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
//! When middleware 0.3.2 (the bounded KV read-timeout) is published and adopted,
//! bump `EXPECTED_VERSION` here in the same commit as the Cargo.toml bump.

/// The published version the relay is expected to ship with (see Cargo.toml's
/// `bsv-middleware-cloudflare` entry and the 2026-07-23 #249 note beneath it).
const EXPECTED_VERSION: &str = "0.3.2";
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
            out.push((
                field("version").unwrap_or_default(),
                field("source"),
            ));
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
