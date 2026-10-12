use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrangler.toml");
    let config = fs::read_to_string("wrangler.toml").expect("read relay work budget configuration");
    let work = config
        .split("\n[limits]\n")
        .nth(1)
        .into_iter()
        .flat_map(|table| {
            table
                .lines()
                .take_while(|line| !line.trim().starts_with('['))
        })
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "work_units").then(|| {
                value
                    .split('#')
                    .next()
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .expect("[limits] work_units must be a u64")
            })
        });
    let literal = work.map_or_else(|| "None".to_string(), |n| format!("Some({n})"));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo build output directory"));
    // Compile only the budget, never the rest of the deployment configuration.
    fs::write(
        output.join("work_limit.rs"),
        format!("pub const WORK_UNITS: Option<u64> = {literal};\n"),
    )
    .expect("write relay work budget constant");
}
