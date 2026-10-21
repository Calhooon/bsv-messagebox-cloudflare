//! `POST /turn-credentials`: the ICE servers a WebRTC hand needs, TURN
//! credentials included, minted for the identity the BRC-31 door
//! authenticated, from a TURN key only the Worker holds.
//!
//! The reference is `@bsv/webrtpay`'s relay (`ts-stack@9262cac66`,
//! `packages/messaging/webrtpay/server/`): the mint (`cloudflare.ts`: the
//! generate endpoint, the ttl capped at 172,800 s, `expiresAt` counted from
//! the moment the provider request started, so it can only be early; a
//! failure's words hold no secret), the budget's order (`relay.ts`
//! `vendTurn`: every budget ready, then every one taken, before the provider
//! is asked; a provider failure costs one) and the source group (`ip.ts`: an
//! IPv4 address as is, an IPv6 address by its /64, and the /48 above it).
//!
//! What the relay adds: the caller rule (a body naming an identity other than
//! the door's is refused 403 and charged nothing), a budget per identity
//! beside the reference's per source and in total, the switch
//! (`TURN_CREDENTIALS = "on"`), the record of whose username is whose, and
//! the revoke (`revoke.rs`), which the reference does not have.
//!
//! The TURN key's token is the secret `TURN_KEY_API_TOKEN`, read with
//! `env.secret` when a request needs it; it is sent to the provider and
//! nowhere else: never in an answer, never in a log.

use serde::Deserialize;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv6Addr};

pub mod revoke;

type RouteResult = (Value, u16);

/// The longest lifetime Cloudflare gives TURN credentials: 48 hours, in
/// seconds (`cloudflare.ts:5`).
pub const MAX_TTL_SECS: u64 = 172_800;
/// The ttl asked when the deployment names none: an hour, one hand's length
/// with its margin (the charter's ruling 3).
pub const TTL_SECS: u64 = 3_600;
/// The budgets' window, in seconds.
pub const WINDOW_SECS: u64 = 3_600;
/// Credentials one identity mints in a window (ruling 4).
pub const IDENTITY_HOUR: u64 = 6;
/// Credentials one source group mints in a window (ruling 4; the
/// reference's `turnPerIpPerHour`).
pub const SOURCE_HOUR: u64 = 6;
/// Credentials one IPv6 /48 mints in a window (ruling 4; the reference's
/// `turnPer48PerHour`).
pub const PREFIX48_HOUR: u64 = 24;
/// Credentials the Worker mints in a window (ruling 4; the reference's
/// `turnPerHour`).
pub const TOTAL_HOUR: u64 = 600;
/// The time the provider has to answer, body included (`cloudflare.ts:7`).
pub const PROVIDER_TIMEOUT_MS: u64 = 5_000;
/// The longest answer read from the provider (`cloudflare.ts:9`).
pub const PROVIDER_MAX_BODY_BYTES: usize = 65_536;
/// The most TURN urls forwarded (`cloudflare.ts:11`).
pub const MAX_TURN_URLS: usize = 8;
/// The source group of a request without a usable client address.
pub const NO_SOURCE: &str = "none";

const API_URL: &str = "https://rtc.live.cloudflare.com/v1/turn/keys/";

/// The deployment's word on the route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `TURN_CREDENTIALS = "on"`; anything else is off.
    pub on: bool,
    /// `TURN_KEY_ID`: the TURN key's id, a path segment of the provider url.
    pub key_id: String,
    /// `TURN_TTL_SECONDS`, at most `MAX_TTL_SECS`.
    pub ttl_secs: u64,
    pub identity_hour: u64,
    pub source_hour: u64,
    pub prefix48_hour: u64,
    pub total_hour: u64,
}

impl Config {
    /// The route's config from a reader of the Worker's vars: a number that
    /// is missing, not a number or zero takes the default; the ttl is capped.
    pub fn parse(var: impl Fn(&str) -> Option<String>) -> Self {
        let num = |name: &str, default: u64| {
            var(name)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default)
        };
        Self {
            on: var("TURN_CREDENTIALS").is_some_and(|v| v.trim() == "on"),
            key_id: var("TURN_KEY_ID")
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
            ttl_secs: num("TURN_TTL_SECONDS", TTL_SECS).min(MAX_TTL_SECS),
            identity_hour: num("TURN_BUDGET_IDENTITY_HOUR", IDENTITY_HOUR),
            source_hour: num("TURN_BUDGET_SOURCE_HOUR", SOURCE_HOUR),
            prefix48_hour: num("TURN_BUDGET_PREFIX48_HOUR", PREFIX48_HOUR),
            total_hour: num("TURN_BUDGET_TOTAL_HOUR", TOTAL_HOUR),
        }
    }

    pub fn from_env(env: &worker::Env) -> Self {
        Self::parse(|name| env.var(name).ok().map(|v| v.to_string()))
    }

    /// Whether `TURN_KEY_ID` can be the provider's key id (letters, digits,
    /// `-` and `_`, as `cloudflare.ts:15`); the template's placeholder cannot.
    pub fn key_id_ok(&self) -> bool {
        (1..=256).contains(&self.key_id.len())
            && self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }
}

/// Whether `token` can be a bearer token: visible ASCII, no space
/// (`cloudflare.ts:17`).
pub fn token_ok(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

// -- The source group ---------------------------------------------------------

/// What a request counts under at its source: the group (an IPv4 address, an
/// IPv6 /64, or `none`) and, for IPv6, the /48 above it. `header` is the
/// edge's `CF-Connecting-IP`; one that is missing, a list or not an address
/// is the group `none`, which the per-source budget still counts (one budget
/// for every such request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub group: String,
    pub prefix48: Option<String>,
}

pub fn source_of(header: Option<&str>) -> Source {
    let none = Source {
        group: NO_SOURCE.to_string(),
        prefix48: None,
    };
    let Some(value) = header else { return none };
    // `ip.ts:14-18`: a list is never taken apart.
    if value.contains(',') {
        return none;
    }
    match parse_address(value) {
        Some(IpAddr::V4(v4)) => Source {
            group: v4.to_string(),
            prefix48: None,
        },
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => Source {
                group: v4.to_string(),
                prefix48: None,
            },
            None => Source {
                group: prefix(&v6, 4, "64"),
                prefix48: Some(prefix(&v6, 3, "48")),
            },
        },
        None => none,
    }
}

/// `address` trimmed, without IPv6 brackets or a zone index (`ip.ts:59-64`).
fn parse_address(address: &str) -> Option<IpAddr> {
    let mut a = address.trim();
    if let Some(inner) = a.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        a = inner;
    }
    if let Some(zone) = a.find('%') {
        a = &a[..zone];
    }
    a.parse().ok()
}

/// The first `groups` 16-bit groups of `v6` in lowercase hex without leading
/// zeros, then `::/<bits>`: `ip.ts`'s spelling (`2001:db8:0:1::/64`).
fn prefix(v6: &Ipv6Addr, groups: usize, bits: &str) -> String {
    let head: Vec<String> = v6.segments()[..groups]
        .iter()
        .map(|g| format!("{g:x}"))
        .collect();
    format!("{}::/{}", head.join(":"), bits)
}

// -- The budgets --------------------------------------------------------------

/// One budget a mint counts against: its name (the word a refusal says), its
/// key in `turn_budget` and its bound in a window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    pub name: &'static str,
    pub key: String,
    pub cap: u64,
}

/// The budgets `identity` from `source` counts against, in the order a
/// refusal names them: the identity, the source group, the /48 (IPv6 only)
/// and the total.
pub fn charges(cfg: &Config, identity: &str, source: &Source) -> Vec<Charge> {
    let mut out = vec![
        Charge {
            name: "identity",
            key: format!("turn:id:{identity}"),
            cap: cfg.identity_hour,
        },
        Charge {
            name: "source",
            key: format!("turn:src:{}", source.group),
            cap: cfg.source_hour,
        },
    ];
    if let Some(p48) = &source.prefix48 {
        out.push(Charge {
            name: "prefix48",
            key: format!("turn:p48:{p48}"),
            cap: cfg.prefix48_hour,
        });
    }
    out.push(Charge {
        name: "total",
        key: "turn:all".to_string(),
        cap: cfg.total_hour,
    });
    out
}

/// The window `now` (unix seconds) falls in: its start.
pub fn window_of(now_secs: u64) -> u64 {
    now_secs - now_secs % WINDOW_SECS
}

/// A budget's row, made if the window has none (one statement a budget).
pub const OPEN_SQL: &str = "INSERT INTO turn_budget (key, window_start, n) VALUES (?, ?, 0) \
     ON CONFLICT(key, window_start) DO NOTHING";

fn marks(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// One credential charged to every budget, or to none when any is spent: the
/// rows taken are returned, so a mint is taken when every budget's row is.
/// The guard reads the window as it stood before the statement.
pub fn take_sql(n: usize) -> String {
    let spent = vec!["(b.key = ? AND b.n >= ?)"; n].join(" OR ");
    format!(
        "UPDATE turn_budget SET n = n + 1 WHERE window_start = ? AND key IN ({}) \
         AND NOT EXISTS (SELECT 1 FROM turn_budget AS b WHERE b.window_start = ? AND ({})) \
         RETURNING key, n",
        marks(n),
        spent
    )
}

/// What each budget holds in the window after the charge.
pub fn held_sql(n: usize) -> String {
    format!(
        "SELECT key, n FROM turn_budget WHERE window_start = ? AND key IN ({})",
        marks(n)
    )
}

/// The windows that have closed.
pub const FORGET_WINDOWS_SQL: &str = "DELETE FROM turn_budget WHERE window_start < ?";

/// The values `take_sql(charges.len())` binds, in order.
pub fn take_binds(window_start: u64, charges: &[Charge]) -> Vec<crate::d1::QVal> {
    let mut v: Vec<crate::d1::QVal> = vec![window_start.into()];
    v.extend(charges.iter().map(|c| c.key.as_str().into()));
    v.push(window_start.into());
    for c in charges {
        v.push(c.key.as_str().into());
        v.push(c.cap.into());
    }
    v
}

/// The first budget, in `charges`' order, that `held` (key, count) shows
/// spent; `None` when none is.
pub fn first_spent(charges: &[Charge], held: &[(String, u64)]) -> Option<usize> {
    charges
        .iter()
        .position(|c| held.iter().any(|(key, n)| key == &c.key && *n >= c.cap))
}

/// A credential's record: whose username it is and until when.
pub const RECORD_SQL: &str =
    "INSERT INTO turn_credentials (username, identity_key, expires_at, created_at) \
     VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET \
     identity_key = excluded.identity_key, expires_at = excluded.expires_at, \
     created_at = excluded.created_at";
/// Whose a username is.
pub const OWNER_SQL: &str = "SELECT identity_key FROM turn_credentials WHERE username = ?";
/// A revoked username, forgotten.
pub const FORGET_SQL: &str = "DELETE FROM turn_credentials WHERE username = ?";
/// The credentials past their expiry (ms since the epoch).
pub const FORGET_EXPIRED_SQL: &str = "DELETE FROM turn_credentials WHERE expires_at < ?";

/// Where the budgets and the credentials' records are kept.
#[async_trait::async_trait(?Send)]
pub trait Store {
    /// Charge one to every budget in the window, all or none, and answer
    /// `None` when charged, or the index of the first budget spent.
    async fn charge(&self, window_start: u64, charges: &[Charge]) -> Result<Option<usize>, String>;
    /// Record that `username` is `identity`'s until `expires_at` (ms).
    async fn record(
        &self,
        username: &str,
        identity: &str,
        expires_at: u64,
        created_at: u64,
    ) -> Result<(), String>;
    /// Whose `username` is, if it is recorded.
    async fn owner(&self, username: &str) -> Result<Option<String>, String>;
    /// Forget `username`.
    async fn forget(&self, username: &str) -> Result<(), String>;
}

/// The store over D1. The charge is one batch: D1 runs a batch as one
/// transaction.
pub struct D1Store<'a> {
    pub db: &'a worker::D1Database,
}

#[derive(Debug, Deserialize)]
struct HeldRow {
    key: String,
    n: f64,
}

#[derive(Debug, Deserialize)]
struct OwnerRow {
    identity_key: String,
}

fn stmt(
    db: &worker::D1Database,
    sql: &str,
    binds: &[crate::d1::QVal],
) -> Result<worker::D1PreparedStatement, String> {
    let js: Vec<wasm_bindgen::JsValue> = binds.iter().map(|b| b.to_js()).collect();
    db.prepare(sql).bind(&js).map_err(|e| e.to_string())
}

#[async_trait::async_trait(?Send)]
impl Store for D1Store<'_> {
    async fn charge(&self, window_start: u64, charges: &[Charge]) -> Result<Option<usize>, String> {
        let n = charges.len();
        let mut batch = Vec::with_capacity(n + 2);
        for c in charges {
            batch.push(stmt(
                self.db,
                OPEN_SQL,
                &[c.key.as_str().into(), window_start.into()],
            )?);
        }
        batch.push(stmt(
            self.db,
            &take_sql(n),
            &take_binds(window_start, charges),
        )?);
        let mut read: Vec<crate::d1::QVal> = vec![window_start.into()];
        read.extend(charges.iter().map(|c| c.key.as_str().into()));
        batch.push(stmt(self.db, &held_sql(n), &read)?);
        let results = self.db.batch(batch).await.map_err(|e| e.to_string())?;
        let taken: Vec<HeldRow> = results
            .get(n)
            .ok_or("the charge returned no take")?
            .results()
            .map_err(|e| e.to_string())?;
        if taken.len() == n {
            return Ok(None);
        }
        let held: Vec<HeldRow> = results
            .get(n + 1)
            .ok_or("the charge returned no reading")?
            .results()
            .map_err(|e| e.to_string())?;
        let held: Vec<(String, u64)> = held.into_iter().map(|r| (r.key, r.n as u64)).collect();
        // Refused, and nothing reads spent: the guard saw a row the reading
        // did not, so name the total rather than none.
        Ok(Some(first_spent(charges, &held).unwrap_or(n - 1)))
    }

    async fn record(
        &self,
        username: &str,
        identity: &str,
        expires_at: u64,
        created_at: u64,
    ) -> Result<(), String> {
        crate::d1::Query::new(RECORD_SQL)
            .bind(username)
            .bind(identity)
            .bind(expires_at)
            .bind(created_at)
            .execute(self.db)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn owner(&self, username: &str) -> Result<Option<String>, String> {
        let row: Option<OwnerRow> = crate::d1::Query::new(OWNER_SQL)
            .bind(username)
            .fetch_optional(self.db)
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|r| r.identity_key))
    }

    async fn forget(&self, username: &str) -> Result<(), String> {
        crate::d1::Query::new(FORGET_SQL)
            .bind(username)
            .execute(self.db)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// The closed windows and the expired credentials, gone: the scheduled event.
pub async fn forget_closed(db: &worker::D1Database, now_ms: u64) {
    let windows = crate::d1::Query::new(FORGET_WINDOWS_SQL).bind(window_of(now_ms / 1000));
    if let Err(e) = windows.execute(db).await {
        worker::console_error!("AUDIT turn_budget.forget FAILED: {e}");
    }
    let expired = crate::d1::Query::new(FORGET_EXPIRED_SQL).bind(now_ms);
    if let Err(e) = expired.execute(db).await {
        worker::console_error!("AUDIT turn_credentials.forget FAILED: {e}");
    }
}

// -- The provider -------------------------------------------------------------

/// A provider failure: fixed words, never a url, a token or a credential
/// (`cloudflare.ts:29-35`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError(pub String);

/// The TURN provider. `generate` answers the provider's JSON; `revoke` ends
/// one username's credentials.
#[async_trait::async_trait(?Send)]
pub trait Provider {
    async fn generate(&self, ttl_secs: u64) -> Result<Value, ProviderError>;
    async fn revoke(&self, username: &str) -> Result<(), ProviderError>;
}

/// Cloudflare Realtime TURN: `POST <API_URL><key id>/credentials/
/// generate-ice-servers` with `Authorization: Bearer <token>` and
/// `{"ttl": <ttl>}` (200 or 201), and `POST .../credentials/<username>/revoke`
/// (204).
pub struct Cloudflare {
    key_id: String,
    token: String,
}

impl Cloudflare {
    /// The provider, when the key id and the secret can be used; `None`
    /// otherwise (the route answers 503 and charges nothing).
    pub fn from_env(env: &worker::Env, cfg: &Config) -> Option<Self> {
        if !cfg.key_id_ok() {
            return None;
        }
        let token = env.secret("TURN_KEY_API_TOKEN").ok()?.to_string();
        token_ok(&token).then(|| Self {
            key_id: cfg.key_id.clone(),
            token,
        })
    }

    async fn post(
        &self,
        url: &str,
        body: Option<String>,
    ) -> Result<worker::Response, ProviderError> {
        let failed = |why: &str| ProviderError(format!("Cloudflare TURN: {why}"));
        let headers = worker::Headers::new();
        headers
            .set("Authorization", &format!("Bearer {}", self.token))
            .map_err(|_| failed("request failed"))?;
        headers
            .set("Content-Type", "application/json")
            .map_err(|_| failed("request failed"))?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(headers)
            .with_body(body.map(|b| wasm_bindgen::JsValue::from_str(&b)));
        let request =
            worker::Request::new_with_init(url, &init).map_err(|_| failed("request failed"))?;
        let send = Box::pin(async move { worker::Fetch::Request(request).send().await });
        let deadline = Box::pin(worker::Delay::from(std::time::Duration::from_millis(
            PROVIDER_TIMEOUT_MS,
        )));
        match futures_util::future::select(send, deadline).await {
            futures_util::future::Either::Left((Ok(response), _)) => Ok(response),
            futures_util::future::Either::Left((Err(_), _)) => Err(failed("request failed")),
            futures_util::future::Either::Right(_) => Err(failed(&format!(
                "no answer within {} s",
                PROVIDER_TIMEOUT_MS / 1000
            ))),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl Provider for Cloudflare {
    async fn generate(&self, ttl_secs: u64) -> Result<Value, ProviderError> {
        let failed = |why: &str| ProviderError(format!("Cloudflare TURN: {why}"));
        let url = format!("{API_URL}{}/credentials/generate-ice-servers", self.key_id);
        let body = json!({ "ttl": ttl_secs }).to_string();
        let mut response = self.post(&url, Some(body)).await?;
        let status = response.status_code();
        if status != 200 && status != 201 {
            return Err(failed(&format!("HTTP {status}")));
        }
        let declared = response
            .headers()
            .get("content-length")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<usize>().ok());
        if declared.is_some_and(|n| n > PROVIDER_MAX_BODY_BYTES) {
            return Err(failed("the answer is too large"));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| failed("request failed"))?;
        if bytes.len() > PROVIDER_MAX_BODY_BYTES {
            return Err(failed("the answer is too large"));
        }
        serde_json::from_slice(&bytes).map_err(|_| failed("the answer is not JSON"))
    }

    async fn revoke(&self, username: &str) -> Result<(), ProviderError> {
        let url = format!(
            "{API_URL}{}/credentials/{}/revoke",
            self.key_id,
            path_segment(username)
        );
        let response = self.post(&url, None).await?;
        match response.status_code() {
            200 | 204 => Ok(()),
            status => Err(ProviderError(format!("Cloudflare TURN: HTTP {status}"))),
        }
    }
}

/// `s` percent-encoded as one path segment.
fn path_segment(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// -- The answer's ICE servers -------------------------------------------------

/// Whether `url` names port 53, which browsers block (`cloudflare.ts:24`).
fn on_port_53(url: &str) -> bool {
    url.match_indices(":53")
        .any(|(i, _)| matches!(url.as_bytes().get(i + 3), None | Some(b'?') | Some(b'/')))
}

fn scheme_is(url: &str, schemes: &[&str]) -> bool {
    let lower = url.to_ascii_lowercase();
    schemes.iter().any(|s| lower.starts_with(s))
}

fn non_empty(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty())
}

/// The ICE servers in the provider's answer, as the relay hands them out,
/// and the TURN usernames among them: one entry with every STUN url, then
/// each TURN entry with its urls, username and credential (`cloudflare.ts`
/// `cloudflareIceServers`). Entries are told apart by url scheme; urls on
/// port 53 and of other schemes are dropped, as is a TURN entry without a
/// username and a credential; at most 8 TURN urls are kept. An answer with
/// no TURN server is a failure.
pub fn ice_servers(answer: &Value) -> Result<(Vec<Value>, Vec<String>), ProviderError> {
    let failed = |why: &str| ProviderError(format!("Cloudflare TURN: {why}"));
    let entries: Vec<&Value> = match answer.get("iceServers") {
        Some(Value::Array(list)) => list.iter().collect(),
        Some(one @ Value::Object(_)) => vec![one],
        _ => vec![],
    };
    if entries.is_empty() {
        return Err(failed("the answer lists no ICE servers"));
    }
    let mut stun: Vec<String> = Vec::new();
    let mut turn: Vec<Value> = Vec::new();
    let mut usernames: Vec<String> = Vec::new();
    let mut turn_urls = 0usize;
    for entry in entries.into_iter().filter(|e| e.is_object()) {
        let listed: Vec<&Value> = match entry.get("urls") {
            Some(Value::Array(list)) => list.iter().collect(),
            Some(one) => vec![one],
            None => vec![],
        };
        let urls: Vec<&str> = listed
            .into_iter()
            .filter_map(Value::as_str)
            .filter(|u| !on_port_53(u))
            .collect();
        for u in &urls {
            if scheme_is(u, &["stun:", "stuns:"]) && !stun.iter().any(|s| s == u) {
                stun.push(u.to_string());
            }
        }
        let room = MAX_TURN_URLS - turn_urls;
        let these: Vec<&str> = urls
            .iter()
            .copied()
            .filter(|u| scheme_is(u, &["turn:", "turns:"]))
            .take(room)
            .collect();
        let username = entry.get("username").and_then(non_empty);
        let credential = entry.get("credential").and_then(non_empty);
        if let (false, Some(username), Some(credential)) = (these.is_empty(), username, credential)
        {
            turn_urls += these.len();
            turn.push(json!({ "urls": these, "username": username, "credential": credential }));
            if !usernames.iter().any(|u| u == username) {
                usernames.push(username.to_string());
            }
        }
    }
    if turn.is_empty() {
        return Err(failed("the answer has no TURN server"));
    }
    let mut out = Vec::with_capacity(turn.len() + 1);
    if !stun.is_empty() {
        out.push(json!({ "urls": stun }));
    }
    out.extend(turn);
    Ok((out, usernames))
}

// -- The route ----------------------------------------------------------------

fn error(status: u16, code: &str, description: &str) -> RouteResult {
    (
        json!({ "status": "error", "code": code, "description": description }),
        status,
    )
}

/// The route's word when the switch is off: 403, nothing charged.
pub fn switched_off() -> RouteResult {
    error(
        403,
        "ERR_TURN_OFF",
        "This relay does not mint TURN credentials (TURN_CREDENTIALS is not \"on\").",
    )
}

/// The route's word when the TURN key cannot be used: 503, nothing charged.
pub fn misconfigured() -> RouteResult {
    error(
        503,
        "ERR_SERVER_MISCONFIGURED",
        "The relay's TURN key is not configured.",
    )
}

/// The mint request's body: empty, or a JSON object that names no identity
/// or the caller's own (`identityKey`). `Err` is the refusal.
pub fn caller_rule(body: &[u8], identity: &str) -> Result<(), RouteResult> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(body) else {
        return Err(error(
            400,
            "ERR_INVALID_JSON",
            "The body must be empty or a JSON object.",
        ));
    };
    match fields.get("identityKey") {
        None => Ok(()),
        Some(Value::String(named)) if named == identity => Ok(()),
        Some(_) => Err(error(
            403,
            "ERR_TURN_NOT_CALLER",
            "TURN credentials are minted only for the authenticated identity.",
        )),
    }
}

/// What a mint needs beside the request.
pub struct Mint<'a> {
    pub cfg: &'a Config,
    pub store: &'a dyn Store,
    /// `None` when the TURN key cannot be used.
    pub provider: Option<&'a dyn Provider>,
    /// Milliseconds since the epoch.
    pub clock: &'a dyn Fn() -> u64,
    /// A line for the Worker's log.
    pub log: &'a dyn Fn(&str),
}

/// `POST /turn-credentials`, after the door: the switch, the caller rule,
/// the key, then every budget charged (all or none) before the provider is
/// asked; a provider failure is 502 and its charge stands. The answer is
/// `{iceServers, expiresAt}`, `expiresAt` in milliseconds since the epoch,
/// the provider request's start plus the ttl.
pub async fn mint(m: &Mint<'_>, identity: &str, source: &Source, body: &[u8]) -> RouteResult {
    if !m.cfg.on {
        return switched_off();
    }
    if let Err(refused) = caller_rule(body, identity) {
        return refused;
    }
    let Some(provider) = m.provider else {
        return misconfigured();
    };
    let start = (m.clock)();
    let window_start = window_of(start / 1000);
    let charges = charges(m.cfg, identity, source);
    match m.store.charge(window_start, &charges).await {
        Ok(None) => {}
        Ok(Some(i)) => {
            let spent = &charges[i];
            let next = window_start + WINDOW_SECS;
            return (
                json!({
                    "status": "error",
                    "code": "ERR_TURN_BUDGET",
                    "description": format!(
                        "The {} budget of {} TURN credentials in the window of {} s from {} (unix seconds) is spent; ask again from {}.",
                        spent.name, spent.cap, WINDOW_SECS, window_start, next
                    ),
                    "budget": spent.name,
                    "windowStart": window_start,
                    "windowSecs": WINDOW_SECS,
                    "retryAt": next,
                }),
                429,
            );
        }
        // The budget is what bounds the provider's bill: a store that cannot
        // answer mints nothing.
        Err(e) => {
            (m.log)(&format!("AUDIT turn.charge FAILED: {e}"));
            return error(
                503,
                "ERR_TURN_UNAVAILABLE",
                "The TURN budget could not be read; ask again.",
            );
        }
    }
    let ttl = m.cfg.ttl_secs;
    let started = (m.clock)();
    let answer = match provider.generate(ttl).await {
        Ok(answer) => ice_servers(&answer),
        Err(e) => Err(e),
    };
    let (ice, usernames) = match answer {
        Ok(found) => found,
        Err(ProviderError(why)) => {
            (m.log)(&format!("AUDIT turn.mint provider failed: {why}"));
            return error(
                502,
                "ERR_TURN_PROVIDER",
                "The TURN provider did not mint credentials; the request was charged.",
            );
        }
    };
    let expires_at = started + ttl * 1000;
    for username in &usernames {
        if let Err(e) = m
            .store
            .record(username, identity, expires_at, started)
            .await
        {
            // A credential nobody can revoke is not handed out: it is
            // revoked at once (best effort) and the caller asks again.
            (m.log)(&format!("AUDIT turn.record FAILED: {e}"));
            for u in &usernames {
                let _ = provider.revoke(u).await;
            }
            return error(
                503,
                "ERR_TURN_UNAVAILABLE",
                "The credential could not be recorded; ask again.",
            );
        }
    }
    (
        json!({ "status": "success", "iceServers": ice, "expiresAt": expires_at }),
        200,
    )
}

/// The route over the Worker's env: `source` is the edge's
/// `CF-Connecting-IP`, read before the door.
pub async fn handle_mint(
    body: &[u8],
    identity: &str,
    source: Option<&str>,
    env: &worker::Env,
    db: &worker::D1Database,
) -> RouteResult {
    let cfg = Config::from_env(env);
    if !cfg.on {
        return switched_off();
    }
    let cloudflare = Cloudflare::from_env(env, &cfg);
    let store = D1Store { db };
    let m = Mint {
        cfg: &cfg,
        store: &store,
        provider: cloudflare.as_ref().map(|p| p as &dyn Provider),
        clock: &|| worker::Date::now().as_millis(),
        log: &|line| worker::console_log!("{line}"),
    };
    mint(&m, identity, &source_of(source), body).await
}

#[cfg(test)]
mod tests;
