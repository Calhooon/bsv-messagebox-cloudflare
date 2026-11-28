use std::{env, fs, path::PathBuf};

/// The raw text of `key` in wrangler.toml's `[limits]` table, its comment cut.
fn limit<'a>(config: &'a str, key: &str) -> Option<&'a str> {
    config
        .split("\n[limits]\n")
        .nth(1)
        .into_iter()
        .flat_map(|table| {
            table
                .lines()
                .take_while(|line| !line.trim().starts_with('['))
        })
        .find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name.trim() == key).then(|| value.split('#').next().unwrap().trim())
        })
}

fn main() {
    println!("cargo:rerun-if-changed=wrangler.toml");
    let config = fs::read_to_string("wrangler.toml").expect("read relay work budget configuration");
    let work = limit(&config, "work_units").map(|value| {
        value
            .parse::<u64>()
            .expect("[limits] work_units must be a u64")
    });
    let literal = work.map_or_else(|| "None".to_string(), |n| format!("Some({n})"));
    // The payment's byte budget: a present value is a whole number of bytes
    // above zero, or the build stops; an absent key uses the relay's default
    // (`payments::payment_budget_from`).
    let payment = limit(&config, "payment_bytes").map(|value| {
        value
            .parse::<u64>()
            .ok()
            .filter(|bytes| *bytes > 0)
            .expect("[limits] payment_bytes must be a whole number of bytes above zero")
    });
    let payment = payment.map_or_else(|| "None".to_string(), |n| format!("Some(\"{n}\")"));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo build output directory"));
    // Compile only the budgets, never the rest of the deployment configuration.
    fs::write(
        output.join("work_limit.rs"),
        format!(
            "pub const WORK_UNITS: Option<u64> = {literal};\npub const PAYMENT_BYTES: Option<&str> = {payment};\n"
        ),
    )
    .expect("write relay work budget constant");
}
