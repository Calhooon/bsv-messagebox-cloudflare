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
//! Entries are (identity → last-join ms) with a 10-minute freshness window:
//! clients re-join on every (re)connect, stale entries prune on read, and a
//! push to a stale identity's DO is a harmless no-op (no matching sockets).
//!
//! SCALE NOTE: the v1 fan-out loops subscribers per event — fine for fleets
//! and early users; at consumer scale this shards (registry partitions +
//! queue-driven fan-out). Documented in bsv-low ARCHITECTURE-V2 doc.
use worker::*;

const FRESH_MS: u64 = 10 * 60 * 1000;

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
