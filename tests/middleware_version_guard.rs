//! CI guard (#251, born of #249): the relay MUST resolve `bsv-middleware-cloudflare`
//! to the EXPECTED **published** version, from the crates.io registry.
//!
//! Why this exists: for weeks a `[patch.crates-io]` pinned a local middleware
//! path against a `= "0.2"` dep while the local crate had advanced to 0.3.1 —
//! cargo silently marked the patch UNUSED and resolved the PRE-fix registry
//! 0.2.0. The 429→500 session-touch fix was written but never shipped (the
//! dead-patch silent regression that hid #249). This guard runs under the
//! repo's existing gate (`cargo test` / `npm test`) and fails loudly if:
//!   * the lock resolves a different middleware version than expected,
//!   * the resolved copy is NOT the crates.io registry build (path/git/patch),
//!   * more than one middleware version is in the graph, or
//!   * a `[patch` section reappears in Cargo.toml (the exact footgun).
//!
//! A move of the middleware is a move of `EXPECTED_VERSION` here in the same
//! commit as the Cargo.toml bump.

/// The published version the relay is expected to ship with (see Cargo.toml's
/// `bsv-middleware-cloudflare` entry and the 2026-07-23 #249 note beneath it).
const EXPECTED_VERSION: &str = "0.5.0";
const CRATE: &str = "bsv-middleware-cloudflare";
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn manifest_file(name: &str) -> String {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// All `[[package]]` blocks in Cargo.lock for `CRATE`, as (version, source).
fn lock_entries() -> Vec<(String, Option<String>)> {
    let lock = manifest_file("Cargo.lock");
    let mut out = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| -> Option<String> {
            block.lines().find_map(|l| {
                let l = l.trim();
                l.strip_prefix(&format!("{key} = \""))
                    .and_then(|rest| rest.strip_suffix('"'))
                    .map(str::to_string)
            })
        };
        if field("name").as_deref() == Some(CRATE) {
            out.push((field("version").unwrap_or_default(), field("source")));
        }
    }
    out
}

#[test]
fn cargo_lock_resolves_expected_published_middleware() {
    let entries = lock_entries();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one {CRATE} in Cargo.lock, found {}: {entries:?} \
         (duplicate/zero versions mean the dependency graph drifted)",
        entries.len()
    );
    let (version, source) = &entries[0];
    assert_eq!(
        version, EXPECTED_VERSION,
        "{CRATE} resolved to {version}, expected the published {EXPECTED_VERSION} — \
         a silent downgrade/upgrade is exactly how the #249 fix failed to ship. \
         If this bump is intentional, update EXPECTED_VERSION in this guard in the \
         same commit."
    );
    let source = source.as_deref().unwrap_or("<none — path/patch override>");
    assert_eq!(
        source, CRATES_IO,
        "{CRATE} {version} is not the crates.io registry build (source = {source}). \
         Local path/git overrides are banned here: hardening ships as a PUBLISHED \
         version, never a local patch (see Cargo.toml's #249 note)."
    );
}

/// The lock's `dependencies` lines of the one `[[package]]` named `name`.
fn lock_dependencies_of(name: &str) -> Vec<String> {
    let lock = manifest_file("Cargo.lock");
    let block = lock
        .split("[[package]]")
        .skip(1)
        .find(|block| block.contains(&format!("name = \"{name}\"\n")))
        .unwrap_or_else(|| panic!("{name} is not in Cargo.lock"));
    block
        .split("dependencies = [")
        .nth(1)
        .and_then(|deps| deps.split(']').next())
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().trim_end_matches(',').trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The BRC-31 layer is on bsv-rs 0.4 (bsv-middleware-cloudflare 0.5.0): the
/// copy of bsv-rs it is built on is the relay's 0.4.3, so the session, the
/// wallet and the auth message it takes are the types the relay holds, and no
/// value crosses from one copy of the SDK to the other on the BRC-31 path.
#[test]
fn the_brc31_layer_is_built_on_the_relays_bsv_rs_0_4_3() {
    let lock = manifest_file("Cargo.lock");
    let copies = lock.matches("name = \"bsv-rs\"\n").count();
    let deps = lock_dependencies_of(CRATE);
    let sdk: Vec<&String> = deps.iter().filter(|d| d.starts_with("bsv-rs")).collect();
    assert_eq!(sdk.len(), 1, "{CRATE} names one bsv-rs: {deps:?}");
    let named = sdk[0].as_str();
    assert!(
        named == "bsv-rs 0.4.3" || (named == "bsv-rs" && copies == 1),
        "{CRATE} is built on {named}, not the relay's bsv-rs 0.4.3"
    );
}

#[test]
fn cargo_toml_has_no_patch_section() {
    let toml = manifest_file("Cargo.toml");
    let has_patch = toml.lines().any(|l| {
        let t = l.trim();
        !t.starts_with('#') && t.starts_with("[patch")
    });
    assert!(
        !has_patch,
        "Cargo.toml contains a [patch] section — the dead-patch silent regression \
         (#249) started exactly this way (an UNUSED patch resolving stale registry \
         code). Ship fixes as published versions instead."
    );
}

/// The 0.4 line: the payment words are bsv-middleware-rs 0.4.1's, built on
/// the relay's bsv-rs 0.4.3 (a transaction with no output is invalid bytes,
/// #59), and bsv-rs is one copy. The door keeps its own
/// reading (the structure, the scripts, the cursor at rest) and hands the
/// middleware the subject alone, for the output check
/// (`verify_payment_output_only` over a byte source). No bsv-rs 0.3 is in the
/// graph and the manifest names no second copy. A move of either is a move of
/// this test in the same commit.
#[test]
fn the_payment_words_are_bsv_middleware_rs_0_4_1_on_bsv_rs_0_4_3_one_copy() {
    let lock = manifest_file("Cargo.lock");
    let versions = |name: &str| -> Vec<String> {
        lock.split("[[package]]")
            .skip(1)
            .filter(|block| block.contains(&format!("name = \"{name}\"\n")))
            .filter_map(|block| {
                block
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("version = \""))
                    .map(|v| v.trim_end_matches('"').to_string())
            })
            .collect()
    };
    assert_eq!(versions("bsv-middleware-rs"), ["0.4.1"]);
    assert_eq!(versions("bsv-rs"), ["0.4.3"]);
    let toml = manifest_file("Cargo.toml");
    let sdk_lines: Vec<&str> = toml
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && l.contains("package = \"bsv-rs\""))
        .collect();
    assert!(
        sdk_lines.is_empty(),
        "the manifest renames bsv-rs, a second copy: {sdk_lines:?}"
    );
}
