//! Fan-out N synthetic identities, do BRC-31 handshake + WS upgrade
//! for each, hold the sockets open for `soak_secs`, then drop.
//!
//! Records per-stage histograms (handshake, upgrade) and per-stage
//! error counts. The point is to push enough load that we exercise the
//! Worker fleet, the DurableObject dispatch, and the WS-hibernation
//! paths — and to surface honest numbers if we don't.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bsv_rs::wallet::ProtoWallet;
use futures_util::stream::{FuturesUnordered, StreamExt};
use hdrhistogram::Histogram;
use reqwest::Client;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use tracing::{info, warn};
use url::Url;

use crate::connect::{close_ws, open_ws, wait_for_connected, WsStream};
use crate::handshake::{do_handshake, Session};

#[derive(Debug, Default)]
pub struct StageStats {
    pub attempted: u64,
    pub succeeded: u64,
    pub failed: u64,
    /// Histogram of duration in microseconds.
    pub hist_us: Option<Histogram<u64>>,
}

impl StageStats {
    fn new() -> Self {
        Self {
            attempted: 0,
            succeeded: 0,
            failed: 0,
            hist_us: Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).ok(),
        }
    }

    fn record(&mut self, ok: bool, dur: Duration) {
        self.attempted += 1;
        if ok {
            self.succeeded += 1;
            if let Some(h) = self.hist_us.as_mut() {
                let us = dur.as_micros().min(60_000_000) as u64;
                let _ = h.record(us);
            }
        } else {
            self.failed += 1;
        }
    }

    pub fn p50_ms(&self) -> Option<f64> {
        self.hist_us.as_ref().map(|h| h.value_at_quantile(0.5) as f64 / 1000.0)
    }
    pub fn p99_ms(&self) -> Option<f64> {
        self.hist_us.as_ref().map(|h| h.value_at_quantile(0.99) as f64 / 1000.0)
    }
    pub fn max_ms(&self) -> Option<f64> {
        self.hist_us.as_ref().map(|h| h.max() as f64 / 1000.0)
    }
}

#[derive(Debug, Default)]
pub struct RunReport {
    pub n: usize,
    pub server_url: String,
    pub ws_url: String,
    pub started: String,
    pub ended: String,
    pub peak_concurrent: u64,
    pub handshake: StageStats,
    pub upgrade: StageStats,
    pub greeting: StageStats,
    pub soak_held_full_duration: u64,
    pub soak_dropped_during: u64,
    /// Sample of distinct error reasons (max 10 per stage).
    pub handshake_errors: Vec<String>,
    pub upgrade_errors: Vec<String>,
    pub greeting_errors: Vec<String>,
}

/// Run a single load wave at concurrency `n`, holding sockets idle for `soak_secs`.
///
/// `concurrent_handshakes` caps how many BRC-31 handshakes are in
/// flight at once (the server's KV-backed session store is the
/// throat). `concurrent_upgrades` caps in-flight WS upgrades
/// concurrently. Sockets, once opened, are held until soak ends.
pub async fn run_wave(
    server_url: &str,
    ws_url: &str,
    n: usize,
    concurrent_handshakes: usize,
    concurrent_upgrades: usize,
    soak_secs: u64,
) -> Result<RunReport> {
    let started = chrono::Utc::now().to_rfc3339();
    let mut report = RunReport {
        n,
        server_url: server_url.to_string(),
        ws_url: ws_url.to_string(),
        started: started.clone(),
        handshake: StageStats::new(),
        upgrade: StageStats::new(),
        greeting: StageStats::new(),
        ..Default::default()
    };

    info!(n, server_url, ws_url, soak_secs, "wave start");

    // 1. Generate identities
    let wallets = crate::identity::generate_n(n);
    let ws_url_parsed = Url::parse(ws_url)?;

    // 2. Build a single reqwest client (connection pooling helps
    //    handshake throughput; each ProtoWallet still gets its own
    //    POST + signature).
    let http = Client::builder()
        .pool_max_idle_per_host(64)
        .timeout(Duration::from_secs(30))
        .build()?;

    // 3. Phase 1: drive concurrent handshakes
    let handshake_sem = Arc::new(Semaphore::new(concurrent_handshakes));
    let handshake_stats = Arc::new(Mutex::new(StageStats::new()));
    let handshake_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mut sessions: Vec<(ProtoWallet, Session)> = Vec::with_capacity(n);
    {
        let mut futs = FuturesUnordered::new();
        for wallet in wallets.into_iter() {
            let sem = handshake_sem.clone();
            let http = http.clone();
            let stats = handshake_stats.clone();
            let errors = handshake_errors.clone();
            let server = server_url.to_string();
            futs.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let t0 = Instant::now();
                match do_handshake(&http, &server, &wallet).await {
                    Ok(session) => {
                        let dur = t0.elapsed();
                        stats.lock().await.record(true, dur);
                        Some((wallet, session))
                    }
                    Err(e) => {
                        let dur = t0.elapsed();
                        stats.lock().await.record(false, dur);
                        let mut errs = errors.lock().await;
                        if errs.len() < 10 {
                            errs.push(format!("{e:#}"));
                        }
                        None
                    }
                }
            }));
        }

        while let Some(j) = futs.next().await {
            if let Ok(Some(pair)) = j {
                sessions.push(pair);
            }
        }
    }

    {
        let s = handshake_stats.lock().await;
        report.handshake = StageStats {
            attempted: s.attempted,
            succeeded: s.succeeded,
            failed: s.failed,
            hist_us: s.hist_us.clone(),
        };
    }
    report.handshake_errors = handshake_errors.lock().await.clone();

    info!(
        attempted = report.handshake.attempted,
        succeeded = report.handshake.succeeded,
        failed = report.handshake.failed,
        p50_ms = ?report.handshake.p50_ms(),
        p99_ms = ?report.handshake.p99_ms(),
        "handshake phase done"
    );

    if sessions.is_empty() {
        report.ended = chrono::Utc::now().to_rfc3339();
        return Ok(report);
    }

    // 4. Phase 2: drive concurrent WS upgrades, hold sockets open.
    let upgrade_sem = Arc::new(Semaphore::new(concurrent_upgrades));
    let upgrade_stats = Arc::new(Mutex::new(StageStats::new()));
    let greeting_stats = Arc::new(Mutex::new(StageStats::new()));
    let upgrade_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let greeting_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let active = Arc::new(AtomicU64::new(0));
    let peak = Arc::new(AtomicU64::new(0));
    let dropped_during = Arc::new(AtomicU64::new(0));

    // Hold tasks alive until soak signal fires.
    let (soak_tx, _) = tokio::sync::broadcast::channel::<()>(16);

    let mut hold_handles = Vec::with_capacity(sessions.len());
    for (wallet, session) in sessions.into_iter() {
        let sem = upgrade_sem.clone();
        let upgrade_stats = upgrade_stats.clone();
        let greeting_stats = greeting_stats.clone();
        let upgrade_errors = upgrade_errors.clone();
        let greeting_errors = greeting_errors.clone();
        let active = active.clone();
        let peak = peak.clone();
        let dropped_during = dropped_during.clone();
        let mut soak_rx = soak_tx.subscribe();
        let ws_url = ws_url_parsed.clone();

        hold_handles.push(tokio::spawn(async move {
            // The upgrade-rate semaphore is held ONLY across the
            // upgrade + greeting handshake. After that we drop it so
            // the next batch can upgrade while we hold this socket
            // idle. Otherwise concurrent_upgrades would also cap
            // total concurrent open sockets, which is wrong.
            let permit = match sem.acquire_owned().await {
                Ok(p) => p,
                Err(_) => return,
            };

            let t0 = Instant::now();
            let ws_res = open_ws(&ws_url, &session, &wallet).await;
            let dur = t0.elapsed();
            let mut ws: WsStream = match ws_res {
                Ok(ws) => {
                    upgrade_stats.lock().await.record(true, dur);
                    ws
                }
                Err(e) => {
                    upgrade_stats.lock().await.record(false, dur);
                    let mut errs = upgrade_errors.lock().await;
                    if errs.len() < 10 {
                        errs.push(format!("{e:#}"));
                    }
                    drop(permit);
                    return;
                }
            };

            // Confirm auth via greeting
            let t_g = Instant::now();
            let greeting_ok = match wait_for_connected(&mut ws).await {
                Ok(_id) => {
                    greeting_stats.lock().await.record(true, t_g.elapsed());
                    true
                }
                Err(e) => {
                    greeting_stats.lock().await.record(false, t_g.elapsed());
                    let mut errs = greeting_errors.lock().await;
                    if errs.len() < 10 {
                        errs.push(format!("{e:#}"));
                    }
                    false
                }
            };

            // Release the upgrade-rate slot now that the handshake is
            // complete (or definitively failed).
            drop(permit);

            if !greeting_ok {
                let _ = ws.close(None).await;
                return;
            }

            let now = active.fetch_add(1, Ordering::Relaxed) + 1;
            peak.fetch_max(now, Ordering::Relaxed);

            // Hold the socket open until soak signal. Drain any inbound
            // frames so we don't deadlock the receiver. (Server may
            // send pings or push events.)
            let drop_reason = tokio::select! {
                _ = soak_rx.recv() => "soak_complete",
                msg = drain_until_close(&mut ws) => {
                    dropped_during.fetch_add(1, Ordering::Relaxed);
                    msg
                }
            };
            tracing::trace!(drop_reason, "socket released");

            close_ws(ws).await;
            active.fetch_sub(1, Ordering::Relaxed);
        }));
    }

    // 5. Wait until upgrade phase is fully attempted, then soak.
    //    We can't easily await all upgrades AND start the soak timer
    //    cleanly, so: poll until upgrade_stats.attempted == n_started
    //    OR a 60s upgrade-phase deadline elapses.
    let upgrade_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let attempted = upgrade_stats.lock().await.attempted;
        let target = hold_handles.len() as u64;
        if attempted >= target || Instant::now() >= upgrade_deadline {
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }

    let observed_peak = peak.load(Ordering::Relaxed);
    info!(
        peak_concurrent = observed_peak,
        active_now = active.load(Ordering::Relaxed),
        "upgrade phase settled — beginning soak"
    );

    // Soak window
    sleep(Duration::from_secs(soak_secs)).await;

    let final_active = active.load(Ordering::Relaxed);
    info!(final_active, "soak ended — releasing sockets");

    // 6. Signal release & wait.
    let _ = soak_tx.send(());
    for h in hold_handles {
        let _ = h.await;
    }

    {
        let s = upgrade_stats.lock().await;
        report.upgrade = StageStats {
            attempted: s.attempted,
            succeeded: s.succeeded,
            failed: s.failed,
            hist_us: s.hist_us.clone(),
        };
    }
    {
        let s = greeting_stats.lock().await;
        report.greeting = StageStats {
            attempted: s.attempted,
            succeeded: s.succeeded,
            failed: s.failed,
            hist_us: s.hist_us.clone(),
        };
    }
    report.upgrade_errors = upgrade_errors.lock().await.clone();
    report.greeting_errors = greeting_errors.lock().await.clone();
    report.peak_concurrent = observed_peak;
    report.soak_dropped_during = dropped_during.load(Ordering::Relaxed);
    report.soak_held_full_duration = report
        .greeting
        .succeeded
        .saturating_sub(report.soak_dropped_during);
    report.ended = chrono::Utc::now().to_rfc3339();

    if !report.handshake_errors.is_empty() {
        warn!(?report.handshake_errors, "handshake errors sample");
    }
    if !report.upgrade_errors.is_empty() {
        warn!(?report.upgrade_errors, "upgrade errors sample");
    }
    if !report.greeting_errors.is_empty() {
        warn!(?report.greeting_errors, "greeting errors sample");
    }

    Ok(report)
}

/// Drain frames from the socket until it closes. Returns the close
/// reason as a static str.
async fn drain_until_close(ws: &mut WsStream) -> &'static str {
    use tokio_tungstenite::tungstenite::protocol::Message;
    while let Some(frame) = ws.next().await {
        match frame {
            Ok(Message::Close(_)) => return "server_close",
            Ok(_) => continue,
            Err(_) => return "ws_error",
        }
    }
    "stream_end"
}
