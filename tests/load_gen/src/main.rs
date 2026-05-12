//! M9 #51: 10k synthetic-identity load generator.
//!
//! Usage:
//!   cargo run --release --bin load_gen -- \
//!     --server https://rust-message-box.dev-a3e.workers.dev \
//!     --ws wss://rust-message-box.dev-a3e.workers.dev/ws \
//!     --n 10 --soak-secs 30 \
//!     --concurrent-handshakes 64 --concurrent-upgrades 256
//!
//! Subcommand `analytics` queries CF GraphQL for the MessageHub
//! DurableObject metrics over an explicit window.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod analytics;
mod connect;
mod handshake;
mod identity;
mod load;
mod serialize;

#[derive(Debug, Parser)]
#[command(name = "load_gen", about = "BRC-31 + WS load generator for bsv-messagebox-cloudflare")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run a single load wave: handshake → upgrade → soak → drop.
    Run {
        #[arg(long, default_value = "https://rust-message-box.dev-a3e.workers.dev")]
        server: String,
        #[arg(long, default_value = "wss://rust-message-box.dev-a3e.workers.dev/ws")]
        ws: String,
        #[arg(long, default_value_t = 10)]
        n: usize,
        #[arg(long, default_value_t = 30)]
        soak_secs: u64,
        #[arg(long, default_value_t = 64)]
        concurrent_handshakes: usize,
        #[arg(long, default_value_t = 256)]
        concurrent_upgrades: usize,
        /// Optional path to write a JSON report.
        #[arg(long)]
        report_json: Option<String>,
    },

    /// Query CF Analytics for MessageHub DO metrics during a window.
    Analytics {
        #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
        token: String,
        #[arg(long, default_value = "your-cloudflare-account-id")]
        account_id: String,
        #[arg(long, default_value = "your-message-hub-do-namespace-id")]
        namespace_id: String,
        #[arg(long)]
        start: String,
        #[arg(long)]
        end: String,
    },
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,load_gen=info")))
        .compact()
        .init();
}

fn print_report(r: &load::RunReport) {
    println!();
    println!("=== Run report ===");
    println!("server:               {}", r.server_url);
    println!("ws:                   {}", r.ws_url);
    println!("n:                    {}", r.n);
    println!("started:              {}", r.started);
    println!("ended:                {}", r.ended);
    println!("peak_concurrent:      {}", r.peak_concurrent);
    println!("---- handshake (BRC-31 initialRequest) ----");
    println!(
        "  attempted={} ok={} fail={} p50={:.1}ms p99={:.1}ms max={:.1}ms",
        r.handshake.attempted,
        r.handshake.succeeded,
        r.handshake.failed,
        r.handshake.p50_ms().unwrap_or(0.0),
        r.handshake.p99_ms().unwrap_or(0.0),
        r.handshake.max_ms().unwrap_or(0.0),
    );
    if !r.handshake_errors.is_empty() {
        println!("  errors sample (max 10):");
        for e in &r.handshake_errors {
            println!("    - {e}");
        }
    }
    println!("---- ws upgrade (signed GET /ws) ----");
    println!(
        "  attempted={} ok={} fail={} p50={:.1}ms p99={:.1}ms max={:.1}ms",
        r.upgrade.attempted,
        r.upgrade.succeeded,
        r.upgrade.failed,
        r.upgrade.p50_ms().unwrap_or(0.0),
        r.upgrade.p99_ms().unwrap_or(0.0),
        r.upgrade.max_ms().unwrap_or(0.0),
    );
    if !r.upgrade_errors.is_empty() {
        println!("  errors sample (max 10):");
        for e in &r.upgrade_errors {
            println!("    - {e}");
        }
    }
    println!("---- greeting (server-initiated `connected`) ----");
    println!(
        "  attempted={} ok={} fail={} p50={:.1}ms p99={:.1}ms max={:.1}ms",
        r.greeting.attempted,
        r.greeting.succeeded,
        r.greeting.failed,
        r.greeting.p50_ms().unwrap_or(0.0),
        r.greeting.p99_ms().unwrap_or(0.0),
        r.greeting.max_ms().unwrap_or(0.0),
    );
    if !r.greeting_errors.is_empty() {
        println!("  errors sample (max 10):");
        for e in &r.greeting_errors {
            println!("    - {e}");
        }
    }
    println!("---- soak ----");
    println!("  held_full_duration:  {}", r.soak_held_full_duration);
    println!("  dropped_during:      {}", r.soak_dropped_during);
    println!();
}

fn write_report_json(r: &load::RunReport, path: &str) -> std::io::Result<()> {
    let v = serde_json::json!({
        "n": r.n,
        "server_url": r.server_url,
        "ws_url": r.ws_url,
        "started": r.started,
        "ended": r.ended,
        "peak_concurrent": r.peak_concurrent,
        "handshake": {
            "attempted": r.handshake.attempted,
            "succeeded": r.handshake.succeeded,
            "failed": r.handshake.failed,
            "p50_ms": r.handshake.p50_ms(),
            "p99_ms": r.handshake.p99_ms(),
            "max_ms": r.handshake.max_ms(),
            "errors_sample": r.handshake_errors,
        },
        "upgrade": {
            "attempted": r.upgrade.attempted,
            "succeeded": r.upgrade.succeeded,
            "failed": r.upgrade.failed,
            "p50_ms": r.upgrade.p50_ms(),
            "p99_ms": r.upgrade.p99_ms(),
            "max_ms": r.upgrade.max_ms(),
            "errors_sample": r.upgrade_errors,
        },
        "greeting": {
            "attempted": r.greeting.attempted,
            "succeeded": r.greeting.succeeded,
            "failed": r.greeting.failed,
            "p50_ms": r.greeting.p50_ms(),
            "p99_ms": r.greeting.p99_ms(),
            "max_ms": r.greeting.max_ms(),
            "errors_sample": r.greeting_errors,
        },
        "soak": {
            "held_full_duration": r.soak_held_full_duration,
            "dropped_during": r.soak_dropped_during,
        },
    });
    std::fs::write(path, serde_json::to_string_pretty(&v).unwrap())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run {
            server,
            ws,
            n,
            soak_secs,
            concurrent_handshakes,
            concurrent_upgrades,
            report_json,
        } => {
            let report = load::run_wave(
                &server,
                &ws,
                n,
                concurrent_handshakes,
                concurrent_upgrades,
                soak_secs,
            )
            .await?;
            print_report(&report);
            if let Some(path) = report_json {
                if let Err(e) = write_report_json(&report, &path) {
                    eprintln!("warn: could not write report JSON to {path}: {e}");
                }
            }
        }
        Cmd::Analytics {
            token,
            account_id,
            namespace_id,
            start,
            end,
        } => {
            let v =
                analytics::query_do_metrics(&token, &account_id, &namespace_id, &start, &end)
                    .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
    }
    Ok(())
}
