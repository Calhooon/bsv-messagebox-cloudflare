//! S3b (LOW ARCHITECTURE v2, 2026-08-27) — the broadcast SUBSCRIBER REGISTRY.
//!
//! Per-identity DO sharding means a broadcast cannot enumerate sockets: each
//! client's sockets live on its OWN `MessageHub` DO. This registry records
//! WHICH identities currently subscribe to public `broadcast-*` rooms (their
//! own DO notifies on join), so the worker's `POST /broadcast` can fan out
//! through the EXISTING per-identity `/internal/push` machinery — each DO
//! then delivers to its own sockets filtered by joined room, exactly like a
//! normal message push.
//!
//! Entries are (identity → last-seen ms) with a 30-minute freshness window.
//! An entry is written on every `broadcast-*` room join AND refreshed from
//! the Engine.IO heartbeat while a socket holding such a room stays alive
//! (`REGISTRY_REFRESH_EVERY_MS` ≈ 3 min, judged by time — `session.rs`), so a subscription
//! lives exactly as long as its socket. Before 2026-09-03 the window was 10
//! minutes with NO refresh: it assumed the pre-heartbeat world where every
//! socket died and re-joined every 45 s; once sockets lived for hours, a
//! seat that joined at 02:40 was stale by 02:50 and every block after that
//! fanned out to nobody (LOW run 8). Stale entries prune on read, and a push
//! to a stale identity's DO is a harmless no-op (no matching sockets).
//!
//! SCALE NOTE: the v1 fan-out loops subscribers per event — fine for fleets
//! and early users; at consumer scale this shards (registry partitions +
//! queue-driven fan-out). Documented in bsv-low ARCHITECTURE-V2 doc.
use worker::*;

pub const FRESH_MS: u64 = 30 * 60 * 1000;
/// The heartbeat refreshes a subscriber's entry every this long (0.3.8: by
/// TIME — 7 × 25 s, ≈ 3 min): three missed refreshes still sit inside
/// `FRESH_MS`.
pub const REGISTRY_REFRESH_EVERY_MS: u64 = 175_000;

/// Record (or refresh) `identity` as a broadcast subscriber. Sharded by the
/// identity's first hex nibble (16 shards — never a single-DO bottleneck;
/// `/broadcast` reads the shards in parallel). Fire-and-forget: a lost
/// register only delays delivery until the next join or heartbeat refresh.
pub async fn register_identity(env: &Env, identity: &str) {
    let Ok(ns) = env.durable_object("BROADCAST_REGISTRY") else {
        return;
    };
    let shard = identity.chars().next().unwrap_or('0');
    let Ok(stub) = ns.id_from_name(&format!("v1:{shard}")).and_then(|id| id.get_stub()) else {
        return;
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(serde_json::json!({ "identity": identity }).to_string().into()));
    let Ok(req) = Request::new_with_init("https://registry/register", &init) else {
        return;
    };
    if let Err(e) = stub.fetch_with_request(req).await {
        console_log!("BroadcastRegistry: register {} failed (non-fatal): {e}", &identity[..12.min(identity.len())]);
    }
}

#[durable_object]
pub struct BroadcastRegistry {
    state: State,
}

impl DurableObject for BroadcastRegistry {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        match (req.method(), req.path().as_str()) {
            (Method::Post, "/register") => {
                #[derive(serde::Deserialize)]
                struct Body {
                    identity: String,
                }
                let b: Body = match req.json().await {
                    Ok(b) => b,
                    Err(e) => return Response::error(format!("bad body: {e}"), 400),
                };
                if b.identity.len() != 66 || !b.identity.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Response::error("identity must be 66 hex", 400);
                }
                self.state
                    .storage()
                    .put(&b.identity, Date::now().as_millis())
                    .await?;
                Response::ok("ok")
            }
            (Method::Get, "/list") => {
                let now = Date::now().as_millis();
                let map = self.state.storage().list().await?;
                let mut fresh: Vec<String> = Vec::new();
                let mut stale: Vec<String> = Vec::new();
                for entry in map.entries() {
                    let Ok(pair) = entry else { continue };
                    let (k, v): (String, u64) = match serde_wasm_bindgen::from_value(pair) {
                        Ok(kv) => kv,
                        Err(_) => continue,
                    };
                    if now.saturating_sub(v) <= FRESH_MS {
                        fresh.push(k);
                    } else {
                        stale.push(k);
                    }
                }
                for k in &stale {
                    let _ = self.state.storage().delete(k).await;
                }
                Response::from_json(&serde_json::json!({ "identities": fresh }))
            }
            _ => Response::error("not found", 404),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_heartbeat_refresh_keeps_a_live_subscriber_well_inside_the_window() {
        // Three missed refreshes (a slow DO, a dropped fetch) still leave the
        // entry fresh; the window is the safety net, the refresh the truth.
        let refresh_ms = REGISTRY_REFRESH_EVERY_MS;
        assert_eq!(refresh_ms, 7 * crate::engineio::session::PING_INTERVAL_MS, "seven ticks, as before 0.3.8");
        assert!(refresh_ms * 3 < FRESH_MS, "refresh {refresh_ms} ms × 3 must sit inside {FRESH_MS} ms");
        assert!(refresh_ms >= 60_000, "a refresh per minute or slower — never a chatty write");
    }
}
