//! The mint and the revoke over a real SQLite with the real migration and
//! statements, a fake provider that records the ttl it was asked for, and a
//! clock the provider moves.

use super::revoke::revoke;
use super::*;
use std::cell::{Cell, RefCell};

/// The store on SQLite: the charge is the D1 batch's statements in one
/// transaction, as D1 runs a batch.
struct Sqlite(RefCell<rusqlite::Connection>);

impl Sqlite {
    fn new() -> Self {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../migrations/0010_turn_credentials.sql"))
            .unwrap();
        Self(RefCell::new(db))
    }

    fn held(&self, key: &str) -> u64 {
        self.0
            .borrow()
            .query_row(
                "SELECT COALESCE(SUM(n), 0) FROM turn_budget WHERE key = ?",
                [key],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn charged_rows(&self) -> u64 {
        self.0
            .borrow()
            .query_row("SELECT COALESCE(SUM(n), 0) FROM turn_budget", [], |r| {
                r.get(0)
            })
            .unwrap()
    }
}

fn to_sql(v: &crate::d1::QVal) -> rusqlite::types::Value {
    use crate::d1::QVal;
    match v {
        QVal::Int(i) => rusqlite::types::Value::Integer(*i),
        QVal::Text(t) => rusqlite::types::Value::Text(t.clone()),
        QVal::Bool(b) => rusqlite::types::Value::Integer(*b as i64),
        QVal::Float(f) => rusqlite::types::Value::Real(*f),
        QVal::Null => rusqlite::types::Value::Null,
    }
}

#[async_trait::async_trait(?Send)]
impl Store for Sqlite {
    async fn charge(&self, window_start: u64, charges: &[Charge]) -> Result<Option<usize>, String> {
        let mut db = self.0.borrow_mut();
        let tx = db.transaction().map_err(|e| e.to_string())?;
        for c in charges {
            tx.execute(OPEN_SQL, rusqlite::params![c.key, window_start])
                .map_err(|e| e.to_string())?;
        }
        let n = charges.len();
        let binds: Vec<rusqlite::types::Value> = take_binds(window_start, charges)
            .iter()
            .map(to_sql)
            .collect();
        let taken = {
            let mut st = tx.prepare(&take_sql(n)).map_err(|e| e.to_string())?;
            let rows = st
                .query_map(rusqlite::params_from_iter(binds), |r| r.get::<_, String>(0))
                .map_err(|e| e.to_string())?;
            rows.count()
        };
        let mut read: Vec<rusqlite::types::Value> =
            vec![rusqlite::types::Value::Integer(window_start as i64)];
        read.extend(
            charges
                .iter()
                .map(|c| rusqlite::types::Value::Text(c.key.clone())),
        );
        let held: Vec<(String, u64)> = {
            let mut st = tx.prepare(&held_sql(n)).map_err(|e| e.to_string())?;
            let rows = st
                .query_map(rusqlite::params_from_iter(read), |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
                })
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?
        };
        tx.commit().map_err(|e| e.to_string())?;
        if taken == n {
            return Ok(None);
        }
        Ok(Some(first_spent(charges, &held).unwrap_or(n - 1)))
    }

    async fn record(&self, u: &str, id: &str, exp: u64, at: u64) -> Result<(), String> {
        self.0
            .borrow()
            .execute(RECORD_SQL, rusqlite::params![u, id, exp, at])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn owner(&self, u: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        self.0
            .borrow()
            .query_row(OWNER_SQL, [u], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())
    }

    async fn forget(&self, u: &str) -> Result<(), String> {
        self.0
            .borrow()
            .execute(FORGET_SQL, [u])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// The token a deployment's secret would hold; it must appear nowhere.
const TOKEN: &str = "dummy-turn-token-must-never-leave-the-worker";

/// A fake provider: records the ttls asked and the usernames revoked, moves
/// the clock by `lag_ms` while it answers, and fails when told.
struct Fake<'a> {
    clock: &'a Cell<u64>,
    lag_ms: u64,
    fail: Cell<bool>,
    asked: RefCell<Vec<u64>>,
    revoked: RefCell<Vec<String>>,
    minted: Cell<u32>,
}

impl<'a> Fake<'a> {
    fn new(clock: &'a Cell<u64>) -> Self {
        Self {
            clock,
            lag_ms: 2_000,
            fail: Cell::new(false),
            asked: RefCell::new(vec![]),
            revoked: RefCell::new(vec![]),
            minted: Cell::new(0),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Provider for Fake<'_> {
    async fn generate(&self, ttl: u64) -> Result<Value, ProviderError> {
        self.asked.borrow_mut().push(ttl);
        self.clock.set(self.clock.get() + self.lag_ms);
        if self.fail.get() {
            return Err(ProviderError("Cloudflare TURN: HTTP 503".into()));
        }
        let k = self.minted.get() + 1;
        self.minted.set(k);
        // Today's answer: a STUN entry, then the TURN entry (the design
        // page's "What Cloudflare offers"); one url on port 53 is dropped.
        Ok(json!({ "iceServers": [
            { "urls": ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"] },
            { "urls": [
                "turn:turn.cloudflare.com:3478?transport=udp",
                "turn:turn.cloudflare.com:53?transport=udp",
                "turns:turn.cloudflare.com:5349?transport=tcp"
              ],
              "username": format!("user{k}"),
              "credential": format!("cred{k}") }
        ]}))
    }

    async fn revoke(&self, username: &str) -> Result<(), ProviderError> {
        if self.fail.get() {
            return Err(ProviderError("Cloudflare TURN: HTTP 503".into()));
        }
        self.revoked.borrow_mut().push(username.to_string());
        Ok(())
    }
}

const A: &str = "02aa";
const B: &str = "03bb";
/// 12:00:30 of an hour: the window opens at 1_789_999_200.
const NOW_MS: u64 = 1_790_000_030_000;
const WINDOW: u64 = 1_789_999_200;

fn on() -> Config {
    Config::parse(|name| match name {
        "TURN_CREDENTIALS" => Some("on".into()),
        "TURN_KEY_ID" => Some("key_id-1".into()),
        _ => None,
    })
}

fn v4(addr: &str) -> Source {
    source_of(Some(addr))
}

struct Harness<'a> {
    cfg: Config,
    store: Sqlite,
    fake: Fake<'a>,
    clock: &'a Cell<u64>,
    logs: RefCell<Vec<String>>,
}

impl<'a> Harness<'a> {
    fn new(clock: &'a Cell<u64>) -> Self {
        clock.set(NOW_MS);
        Self {
            cfg: on(),
            store: Sqlite::new(),
            fake: Fake::new(clock),
            clock,
            logs: RefCell::new(vec![]),
        }
    }

    async fn mint(&self, identity: &str, source: &Source, body: &[u8]) -> RouteResult {
        let clock = || self.clock.get();
        let log = |line: &str| self.logs.borrow_mut().push(line.to_string());
        let m = Mint {
            cfg: &self.cfg,
            store: &self.store,
            provider: Some(&self.fake),
            clock: &clock,
            log: &log,
        };
        mint(&m, identity, source, body).await
    }

    async fn revoke(&self, identity: &str, body: &[u8]) -> RouteResult {
        let log = |line: &str| self.logs.borrow_mut().push(line.to_string());
        revoke(&self.store, Some(&self.fake), &log, identity, body).await
    }
}

// -- The source group ---------------------------------------------------------

#[test]
fn the_source_group_is_ip_ts_s_ipv4_as_is_ipv6_by_64_and_the_48_above() {
    // `test/relay-limits.test.ts:646-664` and `:630-644` at the pin.
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("203.0.113.7", "203.0.113.7", None),
        ("::ffff:203.0.113.7", "203.0.113.7", None),
        ("::ffff:cb00:7107", "203.0.113.7", None),
        (
            "2001:db8:1:2::1",
            "2001:db8:1:2::/64",
            Some("2001:db8:1::/48"),
        ),
        (
            "2001:DB8:1:2:ffff:ffff:ffff:ffff",
            "2001:db8:1:2::/64",
            Some("2001:db8:1::/48"),
        ),
        ("2001:db8::1", "2001:db8:0:0::/64", Some("2001:db8:0::/48")),
        (
            "[2001:db8:0:1::5]",
            "2001:db8:0:1::/64",
            Some("2001:db8:0::/48"),
        ),
        ("fe80::1%en0", "fe80:0:0:0::/64", Some("fe80:0:0::/48")),
        ("::1", "0:0:0:0::/64", Some("0:0:0::/48")),
        (
            "2001:db8:3:4:5:6:192.0.2.4",
            "2001:db8:3:4::/64",
            Some("2001:db8:3::/48"),
        ),
    ];
    for (header, group, p48) in cases {
        let s = source_of(Some(header));
        assert_eq!(
            (s.group.as_str(), s.prefix48.as_deref()),
            (*group, *p48),
            "{header}"
        );
    }
}

#[test]
fn a_missing_list_or_unreadable_address_is_the_group_none() {
    for header in [
        None,
        Some(""),
        Some("not an address"),
        Some("203.0.113.7, 198.51.100.1"),
    ] {
        assert_eq!(
            source_of(header),
            Source {
                group: NO_SOURCE.into(),
                prefix48: None
            },
            "{header:?}"
        );
    }
}

#[test]
fn the_budgets_are_keyed_identity_source_48_total_in_that_order() {
    let cfg = on();
    let six = charges(&cfg, A, &source_of(Some("2001:db8:1:2::1")));
    let keys: Vec<(&str, &str, u64)> = six
        .iter()
        .map(|c| (c.name, c.key.as_str(), c.cap))
        .collect();
    assert_eq!(
        keys,
        vec![
            ("identity", "turn:id:02aa", 6),
            ("source", "turn:src:2001:db8:1:2::/64", 6),
            ("prefix48", "turn:p48:2001:db8:1::/48", 24),
            ("total", "turn:all", 600),
        ]
    );
    let names: Vec<&str> = charges(&cfg, A, &source_of(None))
        .iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["identity", "source", "total"]);
    assert_eq!(charges(&cfg, A, &source_of(None))[1].key, "turn:src:none");
}

// -- The config ---------------------------------------------------------------

#[test]
fn the_ttl_is_capped_at_cloudflare_s_48_hours_and_defaults_to_an_hour() {
    let with = |ttl: &str| {
        let ttl = ttl.to_string();
        Config::parse(move |n| (n == "TURN_TTL_SECONDS").then(|| ttl.clone())).ttl_secs
    };
    assert_eq!(with("3600"), 3_600);
    assert_eq!(with("172800"), MAX_TTL_SECS);
    assert_eq!(with("999999"), MAX_TTL_SECS);
    assert_eq!(with("0"), TTL_SECS);
    assert_eq!(with("an hour"), TTL_SECS);
    let none = Config::parse(|_| None);
    assert_eq!(
        (
            none.on,
            none.ttl_secs,
            none.identity_hour,
            none.source_hour,
            none.prefix48_hour,
            none.total_hour
        ),
        (false, 3_600, 6, 6, 24, 600)
    );
}

#[test]
fn the_switch_is_on_only_when_it_says_on_and_the_placeholder_is_no_key() {
    for (word, on) in [
        ("on", true),
        (" on ", true),
        ("off", false),
        ("true", false),
        ("ON", false),
    ] {
        let word = word.to_string();
        let cfg = Config::parse(move |n| (n == "TURN_CREDENTIALS").then(|| word.clone()));
        assert_eq!(cfg.on, on);
    }
    let placeholder =
        Config::parse(|n| (n == "TURN_KEY_ID").then(|| "<your-turn-key-id>".to_string()));
    assert!(!placeholder.key_id_ok());
    assert!(on().key_id_ok());
    assert!(token_ok(TOKEN) && !token_ok("") && !token_ok("a b"));
}

// -- The mint -----------------------------------------------------------------

#[tokio::test]
async fn the_switch_off_is_403_and_charges_nothing_nor_asks_the_provider() {
    let clock = Cell::new(0);
    let mut h = Harness::new(&clock);
    h.cfg.on = false;
    let (body, status) = h.mint(A, &v4("203.0.113.7"), b"").await;
    assert_eq!((status, &body["code"]), (403, &json!("ERR_TURN_OFF")));
    assert_eq!(h.store.charged_rows(), 0);
    assert!(h.fake.asked.borrow().is_empty());
}

#[tokio::test]
async fn a_body_naming_another_identity_is_403_and_charges_nothing() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    let named_b = format!(r#"{{"identityKey":"{B}"}}"#);
    let (body, status) = h.mint(A, &v4("203.0.113.7"), named_b.as_bytes()).await;
    assert_eq!(
        (status, &body["code"]),
        (403, &json!("ERR_TURN_NOT_CALLER"))
    );
    assert_eq!(h.store.charged_rows(), 0);
    assert!(h.fake.asked.borrow().is_empty());
    // Empty, `{}` and the caller's own name are minted.
    let named_a = format!(r#"{{"identityKey":"{A}"}}"#);
    for ok in [&b""[..], b"{}", b"  ", named_a.as_bytes()] {
        assert_eq!(h.mint(A, &v4("203.0.113.7"), ok).await.1, 200);
    }
    assert_eq!(h.mint(A, &v4("203.0.113.7"), b"[1]").await.1, 400);
}

#[tokio::test]
async fn a_mint_answers_the_ice_servers_and_expires_the_ttl_after_the_provider_request_started() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    let (body, status) = h.mint(A, &v4("203.0.113.7"), b"{}").await;
    assert_eq!(status, 200, "{body}");
    // The provider took 2 s: `expiresAt` is the start plus the ttl, never
    // the answer plus the ttl (`cloudflare.ts:80`).
    assert_eq!(body["expiresAt"], json!(NOW_MS + 3_600_000));
    assert_eq!(clock.get(), NOW_MS + 2_000);
    assert_eq!(*h.fake.asked.borrow(), vec![3_600]);
    assert_eq!(
        body["iceServers"],
        json!([
            { "urls": ["stun:stun.cloudflare.com:3478"] },
            { "urls": [
                "turn:turn.cloudflare.com:3478?transport=udp",
                "turns:turn.cloudflare.com:5349?transport=tcp"
              ],
              "username": "user1", "credential": "cred1" }
        ])
    );
    assert_eq!(h.store.owner("user1").await, Ok(Some(A.to_string())));
}

#[tokio::test]
async fn the_provider_is_asked_the_capped_ttl() {
    let clock = Cell::new(0);
    let mut h = Harness::new(&clock);
    h.cfg = Config::parse(|n| match n {
        "TURN_CREDENTIALS" => Some("on".into()),
        "TURN_KEY_ID" => Some("k".into()),
        "TURN_TTL_SECONDS" => Some("200000".into()),
        _ => None,
    });
    let (body, _) = h.mint(A, &v4("203.0.113.7"), b"").await;
    assert_eq!(*h.fake.asked.borrow(), vec![MAX_TTL_SECS]);
    assert_eq!(body["expiresAt"], json!(NOW_MS + MAX_TTL_SECS * 1000));
}

#[tokio::test]
async fn the_seventh_of_an_identity_s_hour_is_429_naming_the_identity_before_the_provider() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    // Six sources, so only the identity's budget fills.
    for i in 1..=6 {
        let (_, status) = h.mint(A, &v4(&format!("203.0.113.{i}")), b"").await;
        assert_eq!(status, 200);
    }
    let (body, status) = h.mint(A, &v4("203.0.113.7"), b"").await;
    assert_eq!((status, &body["code"]), (429, &json!("ERR_TURN_BUDGET")));
    assert_eq!(body["budget"], "identity");
    assert_eq!(body["windowStart"], json!(WINDOW));
    assert_eq!(body["retryAt"], json!(WINDOW + 3_600));
    assert_eq!(h.fake.asked.borrow().len(), 6);
    // Refused, nothing taken: the total and the new source still read 6 and 0.
    assert_eq!(h.store.held("turn:all"), 6);
    assert_eq!(h.store.held("turn:src:203.0.113.7"), 0);
    // Another identity, and the next window, are their own.
    assert_eq!(h.mint(B, &v4("198.51.100.1"), b"").await.1, 200);
    clock.set(NOW_MS + 3_600_000);
    assert_eq!(h.mint(A, &v4("198.51.100.2"), b"").await.1, 200);
}

#[tokio::test]
async fn ten_fresh_identities_from_one_address_are_held_at_six_by_the_source() {
    // The scenario's step 4: per identity alone all ten are minted.
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    let mut refused = vec![];
    for i in 0..10 {
        let (body, status) = h.mint(&format!("02c{i}"), &v4("203.0.113.7"), b"").await;
        if status == 429 {
            refused.push(body["budget"].as_str().unwrap().to_string());
        }
    }
    assert_eq!(refused, vec!["source"; 4]);
    assert_eq!(h.fake.asked.borrow().len(), 6);
}

#[tokio::test]
async fn the_48_holds_its_64s_and_the_total_holds_the_worker() {
    let clock = Cell::new(0);
    let mut h = Harness::new(&clock);
    // 24 a /48 across many /64s, one identity each.
    for i in 0..24 {
        let src = source_of(Some(&format!("2001:db8:1:{i:x}::1")));
        assert_eq!(h.mint(&format!("02d{i}"), &src, b"").await.1, 200);
    }
    let (body, status) = h
        .mint("02e0", &source_of(Some("2001:db8:1:ff::1")), b"")
        .await;
    assert_eq!((status, &body["budget"]), (429, &json!("prefix48")));
    // Another /48 is not affected; the total is.
    h.cfg.total_hour = 25;
    assert_eq!(
        h.mint("02e1", &source_of(Some("2001:db8:2::1")), b"")
            .await
            .1,
        200
    );
    let (body, status) = h.mint("02e2", &v4("198.51.100.9"), b"").await;
    assert_eq!((status, &body["budget"]), (429, &json!("total")));
}

#[tokio::test]
async fn the_order_names_the_identity_before_the_source_when_both_are_spent() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    for _ in 0..6 {
        assert_eq!(h.mint(A, &v4("203.0.113.7"), b"").await.1, 200);
    }
    let (body, _) = h.mint(A, &v4("203.0.113.7"), b"").await;
    assert_eq!(body["budget"], "identity");
}

#[tokio::test]
async fn every_budget_one_below_its_bound_is_taken_whole() {
    // The guard reads the window as it stood: a row reaching its
    // bound does not stop the rest of the same take.
    let clock = Cell::new(0);
    let mut h = Harness::new(&clock);
    h.cfg.identity_hour = 2;
    h.cfg.source_hour = 2;
    h.cfg.prefix48_hour = 2;
    h.cfg.total_hour = 2;
    let src = source_of(Some("2001:db8:1:2::1"));
    assert_eq!(h.mint(A, &src, b"").await.1, 200);
    assert_eq!(h.mint(A, &src, b"").await.1, 200);
    for key in [
        "turn:id:02aa",
        "turn:src:2001:db8:1:2::/64",
        "turn:p48:2001:db8:1::/48",
        "turn:all",
    ] {
        assert_eq!(h.store.held(key), 2, "{key}");
    }
    assert_eq!(h.mint(A, &src, b"").await.1, 429);
    assert_eq!(h.store.held("turn:all"), 2);
}

#[tokio::test]
async fn a_provider_failure_is_502_and_costs_one() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    h.fake.fail.set(true);
    let (body, status) = h.mint(A, &v4("203.0.113.7"), b"").await;
    assert_eq!((status, &body["code"]), (502, &json!("ERR_TURN_PROVIDER")));
    for key in ["turn:id:02aa", "turn:src:203.0.113.7", "turn:all"] {
        assert_eq!(h.store.held(key), 1, "{key}");
    }
    assert!(h.logs.borrow().iter().any(|l| l.contains("HTTP 503")));
}

#[tokio::test]
async fn a_store_that_cannot_answer_mints_nothing() {
    struct Down;
    #[async_trait::async_trait(?Send)]
    impl Store for Down {
        async fn charge(&self, _: u64, _: &[Charge]) -> Result<Option<usize>, String> {
            Err("D1_ERROR: unavailable".into())
        }
        async fn record(&self, _: &str, _: &str, _: u64, _: u64) -> Result<(), String> {
            Ok(())
        }
        async fn owner(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        async fn forget(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }
    let clock = Cell::new(NOW_MS);
    let fake = Fake::new(&clock);
    let cfg = on();
    let m = Mint {
        cfg: &cfg,
        store: &Down,
        provider: Some(&fake),
        clock: &|| NOW_MS,
        log: &|_| {},
    };
    assert_eq!(mint(&m, A, &v4("203.0.113.7"), b"").await.1, 503);
    assert!(fake.asked.borrow().is_empty());
}

#[tokio::test]
async fn no_usable_key_is_503_and_charges_nothing() {
    let clock = Cell::new(NOW_MS);
    let store = Sqlite::new();
    let cfg = on();
    let m = Mint {
        cfg: &cfg,
        store: &store,
        provider: None,
        clock: &|| NOW_MS,
        log: &|_| {},
    };
    let (body, status) = mint(&m, A, &v4("203.0.113.7"), b"").await;
    assert_eq!(
        (status, &body["code"]),
        (503, &json!("ERR_SERVER_MISCONFIGURED"))
    );
    assert_eq!(store.charged_rows(), 0);
    let _ = clock;
}

#[tokio::test]
async fn the_token_is_in_no_answer_and_no_log() {
    // `key_never_in_answer`: the fake never sees the token, and nothing the
    // route says carries it; the Cloudflare provider's errors are fixed words.
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    let mut said = vec![];
    said.push(h.mint(A, &v4("203.0.113.7"), b"").await.0.to_string());
    h.fake.fail.set(true);
    said.push(h.mint(A, &v4("203.0.113.7"), b"").await.0.to_string());
    said.push(h.revoke(A, br#"{"username":"user1"}"#).await.0.to_string());
    said.extend(h.logs.borrow().iter().cloned());
    for text in &said {
        assert!(!text.contains(TOKEN), "{text}");
    }
}

// -- The answer's ICE servers -------------------------------------------------

#[test]
fn an_answer_without_a_turn_server_is_a_provider_failure() {
    assert!(ice_servers(&json!({})).is_err());
    assert!(ice_servers(&json!({ "iceServers": [{ "urls": "stun:s:3478" }] })).is_err());
    assert!(
        ice_servers(&json!({ "iceServers": [{ "urls": "turn:t:3478", "username": "u" }] }))
            .is_err()
    );
    // The older single object, urls as one string.
    let (ice, users) = ice_servers(&json!({ "iceServers": {
        "urls": "turn:t:3478", "username": "u", "credential": "c" } }))
    .unwrap();
    assert_eq!(
        ice,
        vec![json!({ "urls": ["turn:t:3478"], "username": "u", "credential": "c" })]
    );
    assert_eq!(users, vec!["u".to_string()]);
}

#[test]
fn at_most_eight_turn_urls_are_forwarded() {
    let urls: Vec<String> = (0..12).map(|i| format!("turn:t{i}:3478")).collect();
    let (ice, _) = ice_servers(&json!({ "iceServers": [
        { "urls": urls, "username": "u", "credential": "c" } ] }))
    .unwrap();
    assert_eq!(ice[0]["urls"].as_array().unwrap().len(), MAX_TURN_URLS);
}

// -- The revoke ---------------------------------------------------------------

#[tokio::test]
async fn only_the_minter_revokes_and_another_identity_reads_404() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    assert_eq!(h.mint(A, &v4("203.0.113.7"), b"").await.1, 200);
    let (body, status) = h.revoke(B, br#"{"username":"user1"}"#).await;
    assert_eq!(
        (status, &body["code"]),
        (404, &json!("ERR_TURN_CREDENTIAL_NOT_FOUND"))
    );
    // One never minted reads the same.
    assert_eq!(h.revoke(A, br#"{"username":"nobody"}"#).await, (body, 404));
    assert!(h.fake.revoked.borrow().is_empty());
    let (body, status) = h.revoke(A, br#"{"username":"user1"}"#).await;
    assert_eq!(
        (status, &body),
        (200, &json!({ "status": "success", "revoked": true }))
    );
    assert_eq!(*h.fake.revoked.borrow(), vec!["user1".to_string()]);
    assert_eq!(h.store.owner("user1").await, Ok(None));
    assert_eq!(h.revoke(A, b"{}").await.1, 400);
}

#[tokio::test]
async fn a_provider_that_does_not_revoke_keeps_the_record_for_the_retry() {
    let clock = Cell::new(0);
    let h = Harness::new(&clock);
    assert_eq!(h.mint(A, &v4("203.0.113.7"), b"").await.1, 200);
    h.fake.fail.set(true);
    assert_eq!(h.revoke(A, br#"{"username":"user1"}"#).await.1, 502);
    assert_eq!(h.store.owner("user1").await, Ok(Some(A.to_string())));
}

#[test]
fn the_sweeps_seek_their_index() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(include_str!("../../migrations/0010_turn_credentials.sql"))
        .unwrap();
    for (sql, table) in [
        (FORGET_WINDOWS_SQL, "turn_budget"),
        (FORGET_EXPIRED_SQL, "turn_credentials"),
    ] {
        let plan: String = db
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map([1u64], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join("\n");
        assert!(plan.contains(&format!("SEARCH {table}")), "{plan}");
    }
}
