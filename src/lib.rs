use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::handle_cors_preflight, process_auth, sign_json_response, AuthMiddlewareOptions,
        AuthResult,
    },
};
use serde_json::json;
use worker::*;

mod broadcast_registry;
pub use broadcast_registry::BroadcastRegistry;
mod api_docs;
mod d1;
mod error;
mod retention;
mod routes;
mod storage;
mod types;
mod validation;

mod beef_upload;
mod devices;
mod fcm;
mod fcm_cache;
mod fcm_jwt;
mod fcm_token;
mod payments;
mod permissions;
mod r2_presign;

// Durable Objects (M9)
mod hub_forward;
mod message_hub;

// Engine.IO + Socket.IO transport layer (M10 Phase A — issue #61).
// `/socket.io/*` traffic lands on the per-sid `EngineIoSession` DO via
// `route_socketio_request`. Phase A is auth-less by design (transport
// proof only); Phase B will add BRC-103 over the `authMessage` event,
// and Phase C bridges into the MessageHub event surface.
mod engineio;

// M11 Phase 2: Worker-side polling-POST/GET that intercepts
// authMessage events to keep them off the per-sid DO cold-start path.
// Everything else falls through to `EngineIoSession`.
mod socketio_worker;

#[event(fetch)]
async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    init_panic_hook();

    // Uniform CORS: never let an `Err` bubble to the worker-macro's fallback
    // `Response::error("INTERNAL SERVER ERROR", 500)` — that response carries NO
    // headers, so a browser reports it as "No 'Access-Control-Allow-Origin'
    // header" + `net::ERR_FAILED` (e.g. a stale-session auth `Err`, a `d1("DB")?`
    // failure, or a `sign_json_response` error on the authenticated
    // `/listMessages` + `/acknowledgeMessage` path). Match the canonical TS
    // server's pre-route CORS middleware: every response, success OR error,
    // leaves here CORS-tagged so the client can always read it.
    Ok(match handle(req, env, ctx).await {
        Ok(resp) => resp,
        Err(e) => {
            console_error!("relay handler returned Err (CORS-tagged 500): {e}");
            cors_error_500()
        }
    })
}

/// Cron entry — the transcript-retention TTL backstop (bsv-low #252 stage E).
/// Deployments without a `[triggers]` cron never invoke this; deployments with
/// a cron but no `RETAIN_BOX_PREFIXES` no-op inside the sweep. Retained rows
/// older than `RETAIN_TTL_DAYS` (default 14) are tombstoned then deleted so
/// abandoned games can not accumulate forever.
#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    init_panic_hook();
    retention::run_scheduled_sweep(&env).await;
}

/// A CORS-bearing 500, built infallibly so the error path can never itself
/// produce a header-less response.
fn cors_error_500() -> Response {
    let body = json!({
        "status": "error",
        "code": "ERR_INTERNAL_ERROR",
        "description": "An internal error has occurred."
    });
    let resp = Response::from_json(&body)
        .map(|r| r.with_status(500))
        .unwrap_or_else(|_| Response::error("Internal Server Error", 500).expect("static 500"));
    add_cors_headers(resp)
}

async fn handle(req: Request, env: Env, ctx: Context) -> Result<Response> {
    // CORS preflight — must respond before auth
    if req.method() == Method::Options {
        return handle_cors_preflight();
    }

    // OpenAPI spec — public endpoint (no auth required)
    if req.path() == "/api-docs" && req.method() == Method::Get {
        let spec = api_docs::openapi_spec();
        let response = Response::from_json(&spec)?;
        return Ok(add_cors_headers(response));
    }

    // --- BRC-31 auth setup (shared with the WS upgrade path below) ---
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| Error::from(format!("SERVER_PRIVATE_KEY not set: {}", e)))?
        .to_string();

    // Session TTL is deployment config, not protocol: the default stays 1h;
    // a long-session deployment (e.g. a game table whose multi-hand sitting
    // outlives an hour) sets SESSION_TTL_SECONDS in its wrangler [vars].
    // Floored at 60 — Cloudflare KV rejects `expiration_ttl < 60`, which
    // would silently break session persistence for a misconfigured instance.
    let session_ttl_seconds = env
        .var("SESSION_TTL_SECONDS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .map(|v: u64| v.max(60))
        .unwrap_or(3600);

    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key,
        allow_unauthenticated: false,
        session_ttl_seconds,
        ..Default::default()
    };

    // --- WebSocket upgrade routing (M9 #38, auth landed in #40) ---
    //
    // Run BRC-31 auth on the upgrade GET, then forward the *verified*
    // request to the per-identity MessageHub DO. The middleware injects
    // the verified `x-bsv-auth-identity-key` header onto the request it
    // hands back, which the DO trusts because DOs are not reachable from
    // the public internet — only from this Worker.
    //
    // No anonymous fallback: anonymous WS would let any caller claim any
    // identity and read mailbox traffic.
    // S3b (LOW) — first-party producer fan-out into public broadcast
    // rooms. Bearer-gated (BROADCAST_TOKEN secret): the producers are OUR
    // workers (the app-layer's BoardView actor), never end users — end
    // users only ever JOIN these rooms. Fan-out rides the EXISTING
    // per-identity /internal/push (each subscriber's DO delivers to its
    // own sockets filtered by joined room). Capped per event.
    // W2-P3/P4 (bsv-low event-driven client, 2026-09-02) — FIRST-PARTY
    // SERVER PUSH: our own workers (the tower, the app-layer) file a DURABLE
    // message into ONE identity's box — stored in D1, live-bridged to the
    // recipient's sockets, acknowledged by the client like any message — so
    // a case snapshot or a money fact reaches the seat as an EVENT and
    // survives a reload (the box replays un-acked rows). Same bearer gate as
    // `/broadcast` (producers are our workers, never end users); the
    // `sender` is the producer's own BRC-103 identity key, trusted under the
    // bearer, and the rest of the body is the exact `/sendMessage` shape
    // (`validate_send_message` + `process_send`: fees, permissions, storage,
    // push and FCM all unchanged). No handshake per event: the bearer IS the
    // producer's credential, exactly as on `/broadcast`.
    if req.method() == Method::Post && req.path() == "/push" {
        let expected = env
            .secret("BROADCAST_TOKEN")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let got = req
            .headers()
            .get("Authorization")?
            .unwrap_or_default()
            .strip_prefix("Bearer ")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if expected.is_empty() || got != expected {
            return Response::error("unauthorized", 401);
        }
        let mut req = req;
        let raw = req.bytes().await?;
        let (sender, send_body) = match split_push_body(&raw, Date::now().as_millis()) {
            Ok(x) => x,
            Err(reason) => return Response::error(reason, 400),
        };
        let db = env.d1("DB")?;
        let store = storage::Storage::new(&db);
        let (body, status) = handle_send_message(&send_body, &sender, &env, &store).await;
        return Response::from_json(&body).map(|r| r.with_status(status));
    }
    if req.method() == Method::Post && req.path() == "/broadcast" {
        let expected = env
            .secret("BROADCAST_TOKEN")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let got = req
            .headers()
            .get("Authorization")?
            .unwrap_or_default()
            .strip_prefix("Bearer ")
            .map(|s| s.to_string())
            .unwrap_or_default();
        if expected.is_empty() || got != expected {
            return Response::error("unauthorized", 401);
        }
        #[derive(serde::Deserialize)]
        struct BroadcastBody {
            #[serde(alias = "room")]
            box_name: String,
            body: serde_json::Value,
        }
        let mut req = req;
        let b: BroadcastBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("bad body: {e}"), 400),
        };
        // The broadcast BOX name (e.g. "broadcast-low-board"): the fan-out
        // targets each subscriber's OWN room `<identity>-<box>` (normal
        // ownership; no public rooms exist).
        if !b.box_name.starts_with("broadcast-") {
            return Response::error("box must be broadcast-*", 400);
        }
        let (subscribers, pushed) = fan_out_broadcast(&env, &b.box_name, &b.body).await;
        return Response::from_json(
            &serde_json::json!({ "subscribers": subscribers, "pushed": pushed }),
        );
    }

    if req.path() == "/ws" && is_websocket_upgrade(&req) {
        return route_websocket_upgrade(req, &env, &auth_options).await;
    }

    // --- Socket.IO transport routing (M10 Phase A — issue #61) ---
    //
    // The `/socket.io/*` path family is owned by the Engine.IO + Socket.IO
    // implementation in `src/engineio/`. Phase A is intentionally auth-less:
    // the entire transport is exposed unauthenticated so an unmodified
    // `socket.io-client@4.x` can complete the handshake. Phase B (M10 #61
    // continued) will layer BRC-103 mutual auth over the `authMessage`
    // Socket.IO event, matching the TS `AuthSocketServer` reference. This
    // routing branch MUST run before `process_auth` since polling requests
    // carry no BRC-31 signed headers.
    if req.path().starts_with("/socket.io") {
        return route_socketio_request(req, &env, &ctx).await;
    }

    // --- Per-stage latency instrumentation (bsv-low#249 diagnostic) ---
    //
    // Emits ONE `TRACE_LAT` line per authenticated request with the wall-clock
    // ms spent in (a) BRC-103/104 `process_auth` — which is the *only* place the
    // published bsv-middleware-cloudflare 0.3.0 does UNBOUNDED KV reads
    // (`get_session` / `try_consume_nonce`, no op-timeout) — and (b) the route
    // handler (D1 read_send_context + get_or_create_message_box + insert_message
    // for /sendMessage). This lets the NEXT run empirically pin which stage, if
    // any, burns time on the relay — versus the client-side WS-ack timeout (the
    // measured cause of the ~10.4s `relay.send fail` events in the
    // twoHandRematch-2026-07-23_16-47-30 bundle). Cheap: two `Date::now()` reads
    // + one log line; no allocation on the hot path beyond the format.
    let t_req_start = Date::now().as_millis();
    let req_method_dbg = req.method();
    let req_path_dbg = req.path();

    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;
    let t_auth_done = Date::now().as_millis();

    let (auth_context, req, session, request_body) = match auth_result {
        AuthResult::Authenticated {
            context,
            request,
            session,
            body,
        } => (context, request, session, body),
        // Pass middleware responses through unchanged. The middleware's 401
        // for unauthenticated requests emits
        // `{status:"error", code:"UNAUTHORIZED", message:"Mutual-authentication failed!"}`
        // which matches the TS reference server at messagebox.babbage.systems
        // byte-for-byte (verified via tests/e2e_live_parity.py).
        AuthResult::Response(response) => return Ok(response),
    };

    let identity_key = &auth_context.identity_key;
    let db = env.d1("DB")?;
    let store = storage::Storage::new(&db);

    // Transcript retention predicate (bsv-low #252 stage E): a per-request
    // env-var string parse — no KV, no D1. Empty on deployments that don't
    // opt in, in which case every path below behaves exactly as before.
    let retention_cfg = retention::RetentionConfig::from_env(&env);

    // Dispatch authenticated routes
    let path = req.path();
    let method = req.method();
    let (body, status) = match (method, path.as_str()) {
        // /health behind auth matches TS and Go ("all routes require auth").
        // Authed GET /health returns 200; unauthed requests are rejected by
        // the BRC-31 middleware with UNAUTHORIZED + "Mutual-authentication failed!".
        (Method::Get, "/") | (Method::Get, "/health") => (
            json!({ "status": "success", "message": "rust-message-box is running" }),
            200,
        ),
        (Method::Post, "/sendMessage") => {
            // 0.3.19 (bsv-low loop-10 promotion, the tower review's HIGH-1,
            // 2026-09-09): the FIRST-PARTY boxes (`low_events`, `broadcast-*`)
            // are written only through the bearer-gated `/push` and
            // `/broadcast` — an authenticated end user could otherwise file a
            // forged tower `case` event into a seat's box. Refused here, at
            // the door, before validation (the reference server has no such
            // box; a divergence by design, recorded in bsv-low's register).
            if let Some((status, code, description)) =
                serde_json::from_slice::<serde_json::Value>(&request_body)
                    .ok()
                    .and_then(|v| first_party_box_refusal(&v))
            {
                (
                    json!({ "status": "error", "code": code, "description": description }),
                    status,
                )
            } else {
                handle_send_message(&request_body, identity_key, &env, &store).await
            }
        }
        (Method::Post, "/listMessages") => {
            handle_list_messages(&request_body, identity_key, &store).await
        }
        (Method::Post, "/acknowledgeMessage") => {
            handle_acknowledge_message(&request_body, identity_key, &retention_cfg, &store).await
        }

        // Transcript retention-until-terminal (bsv-low #252 stage E): a
        // reloaded party of a RETAINED box re-fetches the full ordered
        // envelope chain (its own entitlement only — received + authored), and
        // purges its rows once the game is terminal. Both 403 for boxes
        // outside the deployment's RETAIN_BOX_PREFIXES class.
        (Method::Post, "/listTranscript") => {
            retention::handle_list_transcript(&request_body, identity_key, &retention_cfg, &store)
                .await
        }
        (Method::Post, "/purgeTranscript") => {
            retention::handle_purge_transcript(&request_body, identity_key, &retention_cfg, &store)
                .await
        }

        (Method::Post, "/permissions/set") => {
            permissions::handle_set(&request_body, identity_key, &store).await
        }
        (Method::Get, "/permissions/get") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_get(&url, identity_key, &store).await
        }
        (Method::Get, "/permissions/list") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_list(&url, identity_key, &store).await
        }
        (Method::Get, "/permissions/quote") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            permissions::handle_quote(&url, identity_key, &store).await
        }

        (Method::Post, "/registerDevice") => {
            devices::handle_register_device(&request_body, identity_key, &store).await
        }
        (Method::Get, "/devices") => devices::handle_list_devices(identity_key, &store).await,

        (Method::Post, "/beef/upload-url") => {
            beef_upload::handle_upload_url(identity_key, &env).await
        }

        // #40 peer-presence polling fallback: is the OWNER of `?room=`
        // currently seated in it (any live raw-WS or socket.io session on
        // their per-identity hub joined to that room)? BRC-31-authed like
        // every route; the caller must know the FULL room id — for LOW that
        // embeds the 64-hex gameId, so presence is only readable by someone
        // already in the game. UX-only (a toast fallback when the WS
        // `peerLeft` push was missed) — never gates money or delivery.
        (Method::Get, "/presence") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            handle_presence_route(&url, &env).await
        }

        // Tier-2 rejoin-window signal (UX-only): the STAYING client, once it
        // decides "peer left" and starts its grace ladder, PUBLISHES the
        // deadline it will honor so a crashed/reloaded rejoiner can read the
        // counterparty's REAL running countdown (synchronized) instead of
        // guessing locally. Owner-DO routed + BRC-31 authed exactly like
        // `/presence`. Load-bearing honesty: this number can only ever be
        // CONSERVATIVE (the stayer arms ~30-60s AFTER the true disconnect, so
        // the rejoiner sees AT LEAST the real time) and is NEVER a
        // money/delivery/auth gate — a wrong value can only make the rejoiner
        // hurry or give up (still refunded via the tower case + pre-signed
        // nLockTime refund), or gets overridden by the tower deadline (tier 1).
        (Method::Post, "/rejoin-deadline") => {
            let url = req.url().map_err(|e| Error::from(e.to_string()))?;
            handle_rejoin_deadline_route(&url, &request_body, &env).await
        }

        _ => (
            json!({ "status": "error", "code": "ERR_NOT_FOUND", "description": "Not Found" }),
            404,
        ),
    };

    let t_route_done = Date::now().as_millis();
    // TRACE_LAT auth_ms = time in process_auth (BRC-104 KV: get_session +
    // try_consume_nonce, UNBOUNDED in 0.3.0); route_ms = time in the handler
    // (for /sendMessage: D1 read_send_context + box + insert_message, which have
    // their own per-op timing under TRACE_LAT send.* in routes::send_message).
    console_log!(
        "TRACE_LAT req method={:?} path={} auth_ms={} route_ms={} status={}",
        req_method_dbg,
        req_path_dbg,
        t_auth_done.saturating_sub(t_req_start),
        t_route_done.saturating_sub(t_auth_done),
        status
    );

    // Sign response if session available, otherwise plain CORS
    match session {
        Some(ref s) => {
            sign_json_response(&body, status, &[], s).map_err(|e| Error::from(e.to_string()))
        }
        None => {
            let resp = Response::from_json(&body)?.with_status(status);
            Ok(add_cors_headers(resp))
        }
    }
}

// -- Route handlers --

/// Thin HTTP wrapper around the shared write path (`routes::send_message::process_send`).
///
/// All write logic — fee resolution, payment internalization, R2 BEEF
/// resolution, D1 insertion, FCM fan-out — is centralised in
/// `routes::send_message`. Both this handler and the WebSocket
/// `sendMessage` event in `message_hub.rs` (M9 #44) call into the same
/// function and translate the structured `SendOutcome` into their
/// respective wire formats. The HTTP `(json, status)` shape produced
/// here is byte-identical to the pre-#44 implementation.
async fn handle_send_message(
    raw_body: &[u8],
    sender_key: &str,
    env: &Env,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_send_message(raw_body) {
        Ok(v) => v,
        Err((body, status)) => {
            return routes::send_message::outcome_to_http(
                routes::send_message::SendOutcome::ValidationError { body, status },
            );
        }
    };
    let outcome = routes::send_message::process_send(validated, sender_key, env, store).await;
    routes::send_message::outcome_to_http(outcome)
}

async fn handle_list_messages(
    raw_body: &[u8],
    identity_key: &str,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_list_messages(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let messages = match store
        .list_messages(identity_key, &validated.message_box)
        .await
    {
        Ok(m) => m,
        Err(_e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL_ERROR",
                    "description": "An internal error has occurred while listing messages."
                }),
                500,
            )
        }
    };

    // Format response — camelCase, body as raw string, timestamps as ISO 8601 for Node parity
    let formatted: Vec<serde_json::Value> = messages
        .iter()
        .map(|row| {
            json!({
                "messageId": row.message_id.as_deref().unwrap_or(""),
                "body": row.body.as_deref().unwrap_or(""),
                "sender": row.sender.as_deref().unwrap_or(""),
                "createdAt": storage::to_iso8601(row.created_at.as_deref()),
                "updatedAt": storage::to_iso8601(row.updated_at.as_deref()),
            })
        })
        .collect();

    (json!({ "status": "success", "messages": formatted }), 200)
}

async fn handle_acknowledge_message(
    raw_body: &[u8],
    identity_key: &str,
    retention_cfg: &retention::RetentionConfig,
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_acknowledge(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // For RETAINED boxes (bsv-low #252 stage E) this MARKS delivery instead of
    // deleting — the wire contract (success / 0-affected → 400) is unchanged.
    let deleted = match store
        .acknowledge_messages(identity_key, &validated.message_ids, retention_cfg)
        .await
    {
        Ok(n) => n,
        Err(_e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL_ERROR",
                    "description": "An internal error has occurred while acknowledging the message"
                }),
                500,
            )
        }
    };

    if deleted == 0 {
        return (
            json!({
                "status": "error",
                "code": "ERR_INVALID_ACKNOWLEDGMENT",
                "description": "Message not found!"
            }),
            400,
        );
    }

    (json!({ "status": "success" }), 200)
}

/// The three honest answers `GET /presence` can give — the #313 (H1) shape.
///
/// The middle state is the point: "the owner's hub told us nobody is seated"
/// and "we could not LOOK" are DIFFERENT facts, and the wire must be able to
/// say so. Before #313 the route collapsed the second into the first
/// (`unwrap_or((false, None, None))` → HTTP 200 `present:false`), which was
/// safe only while every consumer latched on `true` alone (#40 leave toast,
/// #206 arrival latch). A consumer that counts `false` as EVIDENCE — the
/// lobby away tag (#309/#313) — would have read one relay-internal blip as
/// "every probed host stepped away at the same instant".
///
/// `HubFault` is therefore a SEPARATE VARIANT, not a flag beside a boolean:
/// its response carries no `present` key at all (and a 503), so the absence
/// is structurally UNREPRESENTABLE as a `false` rather than merely
/// detectable. Existing `true`-only consumers are unaffected — they already
/// degrade a non-2xx to "unknown", which is exactly what a hub fault is.
/// Version of the `GET /presence` ANSWER contract, echoed as `presenceWire`
/// on every HTTP 200. Its presence is the proof that this relay separates a
/// hub fault from an absence (#313 H1); its absence means "an older relay,
/// whose `present:false` may be fabricated".
const PRESENCE_WIRE_VERSION: u64 = 1;

enum PresenceRead {
    /// The owner's hub answered. `present` is its real verdict; the advisory
    /// fields are threaded through only when the DO actually emitted them.
    Answered {
        present: bool,
        last_seen_ms: Option<u64>,
        rejoin_deadline_ms: Option<u64>,
    },
    /// Could not read: DO namespace / stub / fetch / unreadable body / a body
    /// with no usable `present`. NEVER an absence.
    HubFault,
}

/// #40 — `GET /presence?room=<roomId>`: route to the room OWNER's
/// per-identity MessageHub and ask whether any of their live sessions is
/// joined to it. The owner is the room's `<66-hex-identity>-` prefix; a
/// malformed room is a 400. Hub unreachable → 503 with NO `present` field
/// (#313: "could not look" is never spelled like "nobody is there"). Still
/// UX-only — never a money/delivery signal.
async fn handle_presence_route(url: &Url, env: &Env) -> (serde_json::Value, u16) {
    let room = url
        .query_pairs()
        .find(|(k, _)| k == "room")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let owner = room.split_once('-').map(|(id, _)| id).unwrap_or("");
    if owner.len() != 66 || !owner.chars().all(|c| c.is_ascii_hexdigit()) {
        return presence_invalid_room_response();
    }
    // Every `?` below is a hop that FAILED to produce an answer — each one
    // lands on `HubFault`, never on a fabricated `present:false`.
    let read = async {
        let namespace = env.durable_object("MESSAGE_HUB").ok()?;
        let stub = namespace.id_from_name(owner).ok()?.get_stub().ok()?;
        // Url::parse_with_params percent-encodes the room for us.
        let do_url = Url::parse_with_params(
            "https://do.local/internal/presence",
            [("room", room.as_str())],
        )
        .ok()?;
        let mut res = stub.fetch_with_str(do_url.as_str()).await.ok()?;
        let body: serde_json::Value = res.json().await.ok()?;
        let present = body.get("present").and_then(|v| v.as_bool())?;
        // Advisory: absent/non-numeric => None (omit later). The CLIENT, not
        // the relay, decides whether a returned deadline is past or future.
        let last_seen_ms = body.get("lastSeenMs").and_then(|v| v.as_u64());
        let rejoin_deadline_ms = body.get("rejoinDeadlineMs").and_then(|v| v.as_u64());
        Some(PresenceRead::Answered {
            present,
            last_seen_ms,
            rejoin_deadline_ms,
        })
    }
    .await
    .unwrap_or(PresenceRead::HubFault);
    presence_route_response(&room, &read)
}

/// A malformed `?room=` — the caller's bug, not a presence answer. Pure so
/// the cross-repo wire fixture can drive it (a 400 must also read as
/// "unknown" on the client, never as an absence).
fn presence_invalid_room_response() -> (serde_json::Value, u16) {
    (
        json!({
            "status": "error", "code": "ERR_INVALID_ROOM",
            "description": "presence requires ?room=<identity>-<box>"
        }),
        400,
    )
}

/// Build the public `GET /presence` response (body + HTTP status).
///
/// `Answered` ⇒ HTTP 200 with `present` as the primary signal; the advisory
/// `last_seen_ms` (heartbeat) and `rejoin_deadline_ms` (tier-2 stayer
/// deadline) are threaded through ONLY when `Some` — an absent value OMITS
/// its field (never 0/null), so a client can never misread a missing signal
/// as a real one. Both are independent of `present` and of each other.
///
/// `HubFault` ⇒ HTTP 503 and a body that contains NO `present` key. There is
/// no boolean to misread: the third state is unrepresentable as an answer,
/// which is the whole #313 (H1) fix.
fn presence_route_response(room: &str, read: &PresenceRead) -> (serde_json::Value, u16) {
    match read {
        PresenceRead::HubFault => (
            json!({
                "status": "error",
                "code": "ERR_PRESENCE_UNAVAILABLE",
                "room": room,
                "description": "presence could not be read (owner hub unreachable) — this is NOT an absence"
            }),
            503,
        ),
        PresenceRead::Answered {
            present,
            last_seen_ms,
            rejoin_deadline_ms,
        } => {
            // `presenceWire` is this producer SELF-IDENTIFYING (#313): it says
            // "the `present` below is a real read — I would have answered 503
            // if I could not look". It rides only the ANSWER, never the fault
            // body. Relay and client deploy independently, so without it a
            // client cannot tell a pre-#313 build's fabricated `false` from a
            // genuine one; consumers that count `false` as evidence require it
            // and read an unmarked `false` as unknown. Bump only if the
            // meaning of `present` itself changes.
            let mut body = json!({
                "status": "success",
                "room": room,
                "present": present,
                "presenceWire": PRESENCE_WIRE_VERSION,
            });
            if let Some(ms) = last_seen_ms {
                body["lastSeenMs"] = json!(ms);
            }
            if let Some(ms) = rejoin_deadline_ms {
                body["rejoinDeadlineMs"] = json!(ms);
            }
            (body, 200)
        }
    }
}

/// Tier-2 WRITE path — `POST /rejoin-deadline?room=<roomId>` with body
/// `{deadlineMs:<u64>}`. Routes to the room OWNER's per-identity MessageHub
/// and stores the deadline the STAYING player will honor, so a rejoiner's
/// `GET /presence` reads back the counterparty's real running countdown.
/// A malformed room is a 400 (mirrors `/presence`); a missing/invalid
/// `deadlineMs` is a 400. The cross-DO hop is best-effort/fail-quiet (like
/// `remember_room_peer`): a hop failure still returns success — this is a
/// UX signal, never a money/delivery gate, so a lost write only costs the
/// rejoiner tier-1/tier-3/tier-4 fallback, never safety.
async fn handle_rejoin_deadline_route(
    url: &Url,
    raw_body: &[u8],
    env: &Env,
) -> (serde_json::Value, u16) {
    let room = url
        .query_pairs()
        .find(|(k, _)| k == "room")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let owner = room.split_once('-').map(|(id, _)| id).unwrap_or("");
    if owner.len() != 66 || !owner.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            json!({
                "status": "error", "code": "ERR_INVALID_ROOM",
                "description": "rejoin-deadline requires ?room=<identity>-<box>"
            }),
            400,
        );
    }
    let deadline_ms = match serde_json::from_slice::<serde_json::Value>(raw_body)
        .ok()
        .and_then(|v| v.get("deadlineMs").and_then(|d| d.as_u64()))
    {
        Some(ms) => ms,
        None => {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_DEADLINE",
                    "description": "rejoin-deadline requires body {deadlineMs:<u64>}"
                }),
                400,
            )
        }
    };
    // Best-effort cross-DO write. Any hop that fails is swallowed (the
    // client's countdown simply falls back a tier); we never surface it.
    // The hub answers with the room's remembered COUNTERPARTY (the seat that
    // posted into this room) when it has one.
    let peer: Option<String> = async {
        let namespace = env.durable_object("MESSAGE_HUB").ok()?;
        let stub = namespace.id_from_name(owner).ok()?.get_stub().ok()?;
        let do_url = Url::parse_with_params(
            "https://do.local/internal/rejoin-deadline",
            [("room", room.as_str())],
        )
        .ok()?;
        let headers = Headers::new();
        headers.set("content-type", "application/json").ok()?;
        let payload = json!({ "deadlineMs": deadline_ms }).to_string();
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.into()));
        let req = Request::new_with_init(do_url.as_str(), &init).ok()?;
        let mut res = stub.fetch_with_request(req).await.ok()?;
        let body: serde_json::Value = res.json().await.ok()?;
        body.get("peer")
            .and_then(|p| p.as_str())
            .map(|p| p.to_ascii_lowercase())
    }
    .await;
    // Tier-2 as an EVENT (bsv-low 2026-09-05): file a `ladder` event into the
    // counterparty's `low_events` box so a leaver's HOME re-reads this seat's
    // presence now, not at the next list change / block. Stored + live-bridged
    // + replayed like every first-party event; best-effort, never a gate.
    let mut ladder = "no-peer";
    if let Some(peer) = peer.as_deref() {
        let now_ms = Date::now().as_millis();
        match ladder_event_push_body(owner, peer, &room, deadline_ms, now_ms) {
            Some(raw) => {
                ladder = "not-filed";
                if let Ok((sender, send_body)) = split_push_body(&raw, now_ms) {
                    if let Ok(db) = env.d1("DB") {
                        let store = storage::Storage::new(&db);
                        let (_, status) =
                            handle_send_message(&send_body, &sender, env, &store).await;
                        ladder = if (200..300).contains(&status) {
                            "filed"
                        } else {
                            "refused"
                        };
                        if ladder == "refused" {
                            console_log!("/rejoin-deadline: ladder event refused (HTTP {status}) for room {room}");
                        }
                    }
                }
            }
            None => ladder = "not-a-game-room",
        }
    }
    (
        json!({ "status": "success", "room": room, "ladder": ladder }),
        200,
    )
}

// Auth-layer error responses (`{code:"UNAUTHORIZED", message:"..."}`) are
// emitted by bsv-middleware-cloudflare directly, matching the TS reference
// server at messagebox.babbage.systems byte-for-byte. No per-path rewriter
// needed — 11/12 live-parity tests against that server pass identical.

// --- WebSocket upgrade helpers (M9 #38) ---

/// True if the request advertises `Upgrade: websocket`. Matches case-insensitively.
fn is_websocket_upgrade(req: &Request) -> bool {
    req.headers()
        .get("upgrade")
        .ok()
        .flatten()
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Route a WebSocket upgrade to the per-identity MessageHub DO instance.
///
/// Runs BRC-31 mutual auth on the upgrade GET via `process_auth`. On
/// success the verified peer identity drives `idFromName` so the socket
/// lands on that identity's hub. On failure the middleware response is
/// returned unchanged — it already carries the parity wire shape
/// `{code:"UNAUTHORIZED",message:"Mutual-authentication failed!",status:"error"}`.
///
/// The forwarded request includes the BRC-104 `x-bsv-auth-identity-key`
/// header, which the DO reads to populate its per-socket attachment
/// (#41). DOs trust that header because they are only reachable from
/// this Worker — the public internet cannot hit them directly.
async fn route_websocket_upgrade(
    req: Request,
    env: &Env,
    auth_options: &AuthMiddlewareOptions,
) -> Result<Response> {
    let auth_result = process_auth(req, env, auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

    let (identity_key, request) = match auth_result {
        AuthResult::Authenticated {
            context, request, ..
        } => (context.identity_key, request),
        // Pass middleware responses (incl. UNAUTHORIZED 401) straight
        // through — the wire shape is already correct.
        AuthResult::Response(response) => return Ok(response),
    };

    let namespace = env.durable_object("MESSAGE_HUB")?;
    let stub = namespace.id_from_name(&identity_key)?.get_stub()?;
    stub.fetch_with_request(request).await
}

// --- Socket.IO transport routing (M10 Phase A — issue #61) ---

/// Route a `/socket.io/*` request to the appropriate `EngineIoSession`
/// Durable Object.
///
/// There are three relevant request shapes:
///
/// 1. **Handshake** — `GET /socket.io/?EIO=4&transport=polling&t=<rand>`
///    with NO `sid` query parameter. We mint a fresh sid, route to a
///    fresh DO via `idFromName(sid)`, and let the DO produce the
///    Engine.IO `0` open packet.
///
/// 2. **Polling poll/post** — `GET|POST /socket.io/?...&sid=<sid>`. We
///    extract the sid from the query string and route to the same DO.
///
/// 3. **WebSocket upgrade** — `GET /socket.io/?...&transport=websocket
///    &sid=<sid>` with `Upgrade: websocket`. Same routing rule as case 2;
///    the DO accepts the WS pair.
///
/// Phase A is intentionally auth-less. Phase B will wrap the surface in
/// BRC-103 over the `authMessage` event.
async fn route_socketio_request(mut req: Request, env: &Env, ctx: &Context) -> Result<Response> {
    let url = req.url()?;
    let qp: std::collections::HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let namespace = env.durable_object("ENGINEIO_SESSION")?;

    let sid_opt = qp.get("sid").map(String::as_str).filter(|s| !s.is_empty());
    let transport = qp.get("transport").map(String::as_str).unwrap_or("");

    if sid_opt.is_none() {
        // Only a polling GET with no sid is a valid handshake.
        if req.method() != Method::Get || transport != "polling" {
            return Response::error(
                "/socket.io: missing sid (only polling GET handshakes may omit it)",
                400,
            );
        }
        // M11 Phase 1: stateless handshake.
        //
        // The Engine.IO `0{...}` open packet is a static-format reply
        // (sid + heartbeat config + upgrade list); the DO's `handle_init`
        // just constructs it from `open_handshake_packet`. We generate
        // sid in the Worker and build the open packet directly, then
        // fire `ctx.wait_until` on the `__init` fetch so the DO cold-
        // starts in the background WHILE the client is processing the
        // handshake response, firing `'connect'`, emitting `authenticated`,
        // and doing the BRC-103 round-trip. The DO is usually warm by
        // the time the client's polling-POST lands.
        //
        // Net effect: the DO cold-start cost is removed from the
        // critical-path 5s auth budget, recovering ~50-500ms in the
        // median case and up to several seconds on cold edges.
        let sid = engineio::make_session_id();
        let body = engineio::open_handshake_packet(&sid).encode();
        let response = engineio::public_polling_text_response(&body, 200)?;

        // Fire-and-forget warm-up. `wait_until` extends the Worker's
        // event lifetime to cover this future, so it completes even
        // after the response is sent. Errors are swallowed — a
        // warm-up failure will surface as a normal cold-start on the
        // next request to the DO; nothing breaks.
        let warm_sid = sid.clone();
        let namespace = namespace;
        ctx.wait_until(async move {
            let init_url = format!("https://socketio.internal/__init?sid={warm_sid}");
            if let Ok(stub) = namespace
                .id_from_name(&warm_sid)
                .and_then(|id| id.get_stub())
            {
                let _ = stub.fetch_with_str(&init_url).await;
            }
        });
        return Ok(response);
    }

    let sid = sid_opt.expect("sid present");

    // M11 Phase 2 — Worker handles ALL polling traffic. KV is the
    // single source of truth for per-sid polling state (auth, queue,
    // CONNECT/closed flags). The `EngineIoSession` DO is touched only
    // at WS upgrade, where it reads the verified BRC-103 state from
    // KV and accepts the WebSocket.
    if transport == "polling" {
        match req.method() {
            Method::Post => {
                let body = req.text().await.unwrap_or_default();
                return socketio_worker::handle_polling_post(&body, env, sid).await;
            }
            Method::Get => {
                return socketio_worker::handle_polling_get(env, sid).await;
            }
            _ => {}
        }
    }

    // WS upgrade and anything else (transport=websocket Upgrade GET):
    // route to the per-sid DO unchanged.
    let stub = namespace.id_from_name(sid)?.get_stub()?;
    stub.fetch_with_request(req).await
}

/// The LOW lobby-watcher broadcast box (the app-layer's `lobby` producer
/// fans into it; since 2026-09-05 the relay itself does too, for a WAITING
/// host's departure — see `lobby_departure_body`).
pub(crate) const LOBBY_BROADCAST_BOX: &str = "broadcast-low-lobby";
/// The room-suffix prefix a WAITING LOW host occupies for its whole wait
/// (`lobbyPairing.lobbyBox` → `low_lobby_<gameId>`); the felt's game box is
/// `low_game_<gameId>`.
pub(crate) const LOBBY_ROOM_PREFIX: &str = "low_lobby_";
pub(crate) const GAME_ROOM_PREFIX: &str = "low_game_";
/// The seat's first-party SERVER-EVENT box (LOW `lowEvents.ts EVENTS_BOX`):
/// our own workers file snapshots there through `/push`; the relay files the
/// tier-2 `ladder` event there itself (`ladder_event_push_body`).
pub(crate) const EVENTS_BOX: &str = "low_events";

/// `<66-hex owner>-<suffix>` → `(owner, suffix)`; anything else → None.
pub(crate) fn split_owner_room(room: &str) -> Option<(&str, &str)> {
    let (owner, suffix) = room.split_once('-')?;
    (owner.len() == 66 && owner.chars().all(|c| c.is_ascii_hexdigit()) && !suffix.is_empty())
        .then_some((owner, suffix))
}

/// Is this the room a WAITING LOW host occupies (the lobby-liveness probe's
/// target)? Its departure has no counterparty room to push `peerLeft` into —
/// the watchers are the whole lobby, reached through the broadcast box.
pub(crate) fn is_lobby_room(room: &str) -> bool {
    // EXACTLY `low_lobby_<64-hex gameId>` — the joiner's `low_lobby_<gid>_ack`
    // box is not a waiting host's room (full18 run 2: every seat departure
    // fanned a bogus host-left into the whole lobby through the ack box).
    split_owner_room(room).is_some_and(|(_, suffix)| {
        suffix
            .strip_prefix(LOBBY_ROOM_PREFIX)
            .is_some_and(|gid| gid.len() == 64 && gid.chars().all(|c| c.is_ascii_hexdigit()))
    })
}

/// The `lobby` broadcast body for a waiting host's CONFIRMED departure (the
/// hub's debounce already ruled out a flap). Same envelope the app-layer's
/// advert-change producer sends (`{kind:"lobby", at, changes:[…]}`): a SIGNAL
/// to refetch + re-probe, never the truth itself — the watcher's presence
/// read decides, and its confirm window (`AWAY_CONFIRM_MS`) outlasts the
/// host's own room re-join repair. bsv-low 2026-09-05 (full18 re-run,
/// class L): with the probe running only on list changes, a QUIET lobby
/// could never learn a host had died — the 2026-09-03 event-driven client
/// had removed the 15 s cadence and nothing replaced the signal.
pub(crate) fn lobby_departure_body(
    room: &str,
    leaver: &str,
    at_ms: u64,
) -> Option<serde_json::Value> {
    let (owner, suffix) = split_owner_room(room)?;
    let game_id = suffix.strip_prefix(LOBBY_ROOM_PREFIX)?;
    if game_id.is_empty() {
        return None;
    }
    Some(json!({
        "kind": "lobby",
        "at": at_ms,
        "changes": [{
            "kind": "host-left",
            "hostIdentity": owner,
            "leaver": leaver,
            "gameId": game_id,
            "room": room,
        }],
    }))
}

/// The `/push`-shaped body (flat form: `split_push_body` wraps it and mints
/// the message id) filing a tier-2 `ladder` event into the COUNTERPARTY's
/// `low_events` box when the STAYER publishes its rejoin deadline for
/// `<owner>-low_game_<gameId>`. Sender = the stayer (the authed caller — the
/// relay speaks in its name, exactly as the presence read answers in it).
/// The leaver's home re-reads the stayer's presence on the event; the body
/// is a CARRIER (nothing is believed off `deadlineMs` itself). bsv-low
/// 2026-09-05 (full18 run 1 + re-run, class F): the leaver's tier-2 countdown
/// could not arrive inside a 20 s grace because the home re-read presence
/// only on list changes and block events.
pub(crate) fn ladder_event_push_body(
    owner: &str,
    peer: &str,
    room: &str,
    deadline_ms: u64,
    at_ms: u64,
) -> Option<Vec<u8>> {
    let (room_owner, suffix) = split_owner_room(room)?;
    if room_owner != owner {
        return None;
    }
    let game_id = suffix.strip_prefix(GAME_ROOM_PREFIX)?;
    if game_id.len() != 64 || !game_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if !validation::is_valid_pubkey(peer) || peer.eq_ignore_ascii_case(owner) {
        return None;
    }
    Some(
        json!({
            "sender": owner,
            "recipient": peer,
            "messageBox": EVENTS_BOX,
            "body": {
                "v": 1,
                "kind": "ladder",
                "gameId": game_id,
                "stayer": owner,
                "deadlineMs": deadline_ms,
                "at": at_ms,
            },
        })
        .to_string()
        .into_bytes(),
    )
}

/// Fan ONE body into every subscriber's own `<identity>-<box_name>` room
/// (the `/broadcast` route's core, shared with the hub's lobby-departure
/// producer). Returns `(subscribers, pushed)`. Best-effort per hub; a shard
/// read failure is logged as a partial fan-out.
pub(crate) async fn fan_out_broadcast(
    env: &Env,
    box_name: &str,
    body: &serde_json::Value,
) -> (usize, u32) {
    let Ok(reg) = env.durable_object("BROADCAST_REGISTRY") else {
        return (0, 0);
    };
    // 16 nibble-shards, read in parallel (see the join-notify twin).
    let mut shard_futs = Vec::new();
    for shard in "0123456789abcdef".chars() {
        let Ok(stub) = reg
            .id_from_name(&format!("v1:{shard}"))
            .and_then(|i| i.get_stub())
        else {
            continue;
        };
        shard_futs.push(async move { stub.fetch_with_str("https://registry/list").await });
    }
    let mut identities: Vec<String> = Vec::new();
    for fut in shard_futs {
        match fut.await {
            Ok(mut r) => {
                if let Some(list) = r.json::<serde_json::Value>().await.ok().and_then(|v| {
                    serde_json::from_value::<Vec<String>>(v["identities"].clone()).ok()
                }) {
                    identities.extend(list);
                }
            }
            Err(e) => {
                console_log!("broadcast {box_name}: a registry shard failed (partial fan-out): {e}")
            }
        }
    }
    let Ok(namespace) = env.durable_object("MESSAGE_HUB") else {
        return (identities.len(), 0);
    };
    let message_id = format!("bcast-{}", Date::now().as_millis());
    let mut delivered_to = 0u32;
    const BROADCAST_FANOUT_CAP: usize = 500;
    for identity in identities.iter().take(BROADCAST_FANOUT_CAP) {
        let Ok(stub) = namespace.id_from_name(identity).and_then(|i| i.get_stub()) else {
            continue;
        };
        let push = serde_json::json!({
            "roomId": format!("{identity}-{box_name}"),
            "sender": "broadcast-producer",
            "messageId": message_id,
            "body": body,
        })
        .to_string();
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(push.into()));
        let Ok(preq) = Request::new_with_init("https://hub/internal/push", &init) else {
            continue;
        };
        if stub.fetch_with_request(preq).await.is_ok() {
            delivered_to += 1;
        }
    }
    if identities.len() > BROADCAST_FANOUT_CAP {
        console_log!(
            "broadcast {box_name}: fan-out CAPPED at {} of {} subscribers (scale note: shard)",
            BROADCAST_FANOUT_CAP,
            identities.len()
        );
    }
    (identities.len(), delivered_to)
}

/// Split a `/push` body into the producer's identity (`sender`, a compressed
/// pubkey hex) and the remaining `/sendMessage`-shaped JSON (re-serialized
/// without `sender`, so the reference validator sees exactly what an authed
/// client would have sent).
/// The boxes only OUR workers may write (through `/push` / `/broadcast`, bearer-gated):
/// the seat's durable server-event box and every public broadcast room.
pub(crate) fn is_first_party_box(name: &str) -> bool {
    name == EVENTS_BOX || name.starts_with("broadcast-")
}

/// The refusal an ordinary `/sendMessage` earns when its `messageBox` is first-party:
/// `(403, code, description)`; `None` for every other box (or an unparseable body,
/// which `validate_send_message` refuses on its own terms).
/// The refusal text for a first-party box (shared by the HTTP door and the hub's
/// live path); `None` for every other box.
pub(crate) fn first_party_box_reason(name: &str) -> Option<String> {
    is_first_party_box(name)
        .then(|| format!("message box '{name}' is first-party: only the service push may write it"))
}

pub(crate) fn first_party_box_refusal(
    body: &serde_json::Value,
) -> Option<(u16, &'static str, String)> {
    let message = body.get("message").unwrap_or(body);
    let name = message.get("messageBox").and_then(|v| v.as_str())?;
    first_party_box_reason(name).map(|reason| (403, "ERR_FIRST_PARTY_BOX", reason))
}

fn split_push_body(raw: &[u8], now_ms: u64) -> std::result::Result<(String, Vec<u8>), String> {
    let mut v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| format!("push body is not JSON: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "push body must be a JSON object".to_string())?;
    let sender = obj
        .remove("sender")
        .and_then(|s| s.as_str().map(|s| s.to_ascii_lowercase()))
        .ok_or_else(|| "push body needs a `sender` identity key".to_string())?;
    if !validation::is_valid_pubkey(&sender) {
        return Err("push `sender` must be a 33-byte compressed pubkey hex".to_string());
    }
    // `/sendMessage`'s validator wants `{ "message": { recipient, messageBox,
    // body, messageId } }`. A producer may send that exact shape, or the FLAT
    // `{ recipient, messageBox, body }` the first-party producers send — the
    // relay wraps it and mints the `messageId` it did not carry (a sha256 of
    // the sender, recipient, box, body and the millisecond: 64 hex, so the
    // client's acknowledge path accepts it as a stored id). Before this the
    // route answered ERR_MESSAGE_REQUIRED to every first-party push and not
    // one server event was ever stored (LOW, 2026-09-03).
    if obj.get("message").is_none() {
        let recipient = obj.remove("recipient");
        let message_box = obj.remove("messageBox");
        let body = obj.remove("body");
        let mut message = serde_json::Map::new();
        if let Some(r) = recipient {
            message.insert("recipient".into(), r);
        }
        if let Some(b) = message_box {
            message.insert("messageBox".into(), b);
        }
        if let Some(b) = body {
            message.insert("body".into(), b);
        }
        if let Some(id) = obj.remove("messageId") {
            message.insert("messageId".into(), id);
        } else {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(sender.as_bytes());
            h.update(
                serde_json::to_vec(&serde_json::Value::Object(message.clone())).unwrap_or_default(),
            );
            h.update(now_ms.to_string().as_bytes());
            message.insert(
                "messageId".into(),
                serde_json::Value::String(hex::encode(h.finalize())),
            );
        }
        obj.insert("message".into(), serde_json::Value::Object(message));
    }
    let rest = serde_json::to_vec(&v).map_err(|e| format!("re-serialize failed: {e}"))?;
    Ok((sender, rest))
}

#[cfg(test)]
mod push_route_tests {
    use super::*;

    const SENDER: &str = "02aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    #[test]
    fn split_push_body_extracts_the_sender_and_leaves_a_pure_send_message_body() {
        let raw = format!(
            r#"{{"sender":"{}","recipient":"03ff","messageBox":"low_events","body":{{"kind":"case"}}}}"#,
            SENDER.to_ascii_uppercase()
        );
        let (sender, rest) = split_push_body(raw.as_bytes(), 1_700_000_000_000).unwrap();
        assert_eq!(sender, SENDER); // lower-cased
        let v: serde_json::Value = serde_json::from_slice(&rest).unwrap();
        assert!(v.get("sender").is_none());
        // The flat producer shape is wrapped into `/sendMessage`'s `message`
        // object, with a minted 64-hex messageId (a stored-id shape).
        assert_eq!(v["message"]["recipient"], "03ff");
        assert_eq!(v["message"]["messageBox"], "low_events");
        assert_eq!(v["message"]["body"]["kind"], "case");
        let id = v["message"]["messageId"].as_str().unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn a_wrapped_flat_push_passes_the_send_message_validator() {
        let raw = format!(
            r#"{{"sender":"{SENDER}","recipient":"{SENDER}","messageBox":"low_events","body":{{"kind":"pot"}}}}"#
        );
        let (_, rest) = split_push_body(raw.as_bytes(), 1_700_000_000_000).unwrap();
        assert!(
            validation::validate_send_message(&rest).is_ok(),
            "{}",
            String::from_utf8_lossy(&rest)
        );
    }

    #[test]
    fn split_push_body_passes_an_explicit_message_wrapper_through() {
        let raw = format!(
            r#"{{"sender":"{SENDER}","message":{{"recipient":"03ff","messageBox":"low_events","body":"x","messageId":"m1"}}}}"#
        );
        let (_, rest) = split_push_body(raw.as_bytes(), 1_700_000_000_000).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&rest).unwrap();
        assert_eq!(v["message"]["messageId"], "m1");
    }

    #[test]
    fn the_ordinary_send_route_refuses_the_first_party_boxes_and_nothing_else() {
        // the seat's server-event box: refused at the door (403), whatever the sender
        let forged = json!({ "recipient": "02aa", "messageBox": "low_events", "body": { "v": 1, "kind": "case", "status": "finalized_refuse" } });
        let r = first_party_box_refusal(&forged).expect("low_events is first-party");
        assert_eq!(r.0, 403);
        assert_eq!(r.1, "ERR_FIRST_PARTY_BOX");
        // the wrapped shape (`{"message": {...}}`) is judged the same
        let wrapped = json!({ "message": { "recipient": "02aa", "messageBox": "broadcast-low-pots", "body": "x" } });
        assert_eq!(first_party_box_refusal(&wrapped).map(|r| r.0), Some(403));
        // every other box passes to validation untouched
        for name in [
            "low_game_ab",
            "notifications",
            "inbox",
            "low_eventsx",
            "xbroadcast-low-pots",
        ] {
            let ok = json!({ "recipient": "02aa", "messageBox": name, "body": "x" });
            assert!(
                first_party_box_refusal(&ok).is_none(),
                "{name} is not first-party"
            );
        }
        // no box at all: not this gate's call (validation answers ERR_INVALID_MESSAGEBOX)
        assert!(first_party_box_refusal(&json!({ "recipient": "02aa", "body": "x" })).is_none());
        assert!(
            is_first_party_box(EVENTS_BOX)
                && is_first_party_box("broadcast-low-board")
                && !is_first_party_box("low_game_x")
        );
    }

    #[test]
    fn split_push_body_refuses_a_missing_or_malformed_sender_and_non_objects() {
        assert!(split_push_body(br#"{"recipient":"03ff"}"#, 1_700_000_000_000).is_err());
        assert!(split_push_body(
            br#"{"sender":"nothex","recipient":"03ff"}"#,
            1_700_000_000_000
        )
        .is_err());
        assert!(split_push_body(br#"[1,2]"#, 1_700_000_000_000).is_err());
        assert!(split_push_body(b"not json", 1_700_000_000_000).is_err());
    }
}

#[cfg(test)]
mod presence_route_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn answered(
        present: bool,
        last_seen_ms: Option<u64>,
        rejoin_deadline_ms: Option<u64>,
    ) -> PresenceRead {
        PresenceRead::Answered {
            present,
            last_seen_ms,
            rejoin_deadline_ms,
        }
    }

    #[test]
    fn presence_route_omits_last_seen_when_unset() {
        // Advisory contract at the public edge: an absent heartbeat
        // OMITS `lastSeenMs` (never 0/null) and never affects `present`.
        // With no tier-2 deadline either, `rejoinDeadlineMs` is likewise absent.
        let (body, status) = presence_route_response("03aa-inbox", &answered(true, None, None));
        assert_eq!(status, 200);
        assert_eq!(body["status"], "success");
        assert_eq!(body["room"], "03aa-inbox");
        assert_eq!(body["present"], json!(true));
        assert!(
            body.get("lastSeenMs").is_none(),
            "lastSeenMs must be omitted when unset, got: {body}"
        );
        assert!(
            body.get("rejoinDeadlineMs").is_none(),
            "rejoinDeadlineMs must be omitted when unset, got: {body}"
        );
    }

    #[test]
    fn presence_route_threads_last_seen_when_set() {
        let (body, status) = presence_route_response(
            "03aa-inbox",
            &answered(false, Some(1_700_000_000_123), None),
        );
        assert_eq!(status, 200);
        assert_eq!(body["present"], json!(false));
        assert_eq!(body["lastSeenMs"], json!(1_700_000_000_123u64));
        assert!(body.get("rejoinDeadlineMs").is_none());
    }

    #[test]
    fn presence_route_threads_rejoin_deadline_when_set() {
        // Tier-2: the stayer-published deadline is threaded through as a
        // number, independent of the heartbeat and of `present`.
        let (body, _) =
            presence_route_response("03aa-inbox", &answered(true, None, Some(1_700_000_060_000)));
        assert_eq!(body["present"], json!(true));
        assert_eq!(body["rejoinDeadlineMs"], json!(1_700_000_060_000u64));
        assert!(
            body.get("lastSeenMs").is_none(),
            "lastSeenMs stays omitted when only the deadline is set, got: {body}"
        );
    }

    #[test]
    fn presence_route_threads_both_last_seen_and_rejoin_deadline() {
        let (body, _) = presence_route_response(
            "03aa-inbox",
            &answered(false, Some(1_700_000_000_123), Some(1_700_000_060_000)),
        );
        assert_eq!(body["lastSeenMs"], json!(1_700_000_000_123u64));
        assert_eq!(body["rejoinDeadlineMs"], json!(1_700_000_060_000u64));
    }

    /// #313 H1 — the whole point. A hub fault must not be spelled like an
    /// absence: no `present` key exists to be misread, and the status is a
    /// 5xx so even a caller that never parses the body cannot mistake it for
    /// an answer.
    #[test]
    fn hub_fault_carries_no_present_key_and_a_503() {
        let (body, status) = presence_route_response("03aa-inbox", &PresenceRead::HubFault);
        assert_eq!(status, 503, "a hub fault is not a successful read");
        assert!(
            body.get("present").is_none(),
            "a hub fault must carry NO `present` key — an absent field is \
             unrepresentable as `false`, a flag beside one is not. Got: {body}"
        );
        assert_eq!(body["status"], "error");
        assert_eq!(body["code"], "ERR_PRESENCE_UNAVAILABLE");
        assert_eq!(body["room"], "03aa-inbox");
    }

    /// The two states must be DISTINGUISHABLE on the wire — not just
    /// differently-worded. A genuine absence and a hub fault share no
    /// (status, present-key) pair.
    #[test]
    fn genuine_absence_and_hub_fault_are_distinguishable() {
        let (absent_body, absent_status) =
            presence_route_response("03aa-inbox", &answered(false, None, None));
        let (fault_body, fault_status) =
            presence_route_response("03aa-inbox", &PresenceRead::HubFault);
        assert_ne!(absent_status, fault_status);
        assert_eq!(absent_body["present"], json!(false));
        assert!(fault_body.get("present").is_none());
    }

    // ── the CROSS-REPO agreement pin (#313, epoch Rule 16) ─────────────────
    //
    // `tests/fixtures/presence-wire-v1.json` is the shared artifact between
    // this relay and the LOW client (bsv-low `app/src/lib/fixtures/` holds a
    // byte-identical copy). THIS test drives the REAL producer through every
    // case and asserts the emitted (status, body) equals the fixture's; the
    // client's test drives those SAME bytes through its real consumer. The
    // sha256 below is asserted in BOTH repos, so a one-sided edit turns both
    // gates red instead of silently splitting the two beliefs apart.
    const PRESENCE_WIRE_V1_SHA256: &str =
        "471c19a3b347a508b794699c5ff21c621427b06805ca81751bf4f527460937f5";
    const PRESENCE_WIRE_V1: &str = include_str!("../tests/fixtures/presence-wire-v1.json");

    #[test]
    fn presence_wire_fixture_is_the_pinned_bytes() {
        let digest = hex::encode(Sha256::digest(PRESENCE_WIRE_V1.as_bytes()));
        assert_eq!(
            digest, PRESENCE_WIRE_V1_SHA256,
            "presence-wire-v1.json changed. This file is a CROSS-REPO agreement: \
             update bsv-low's copy to the identical bytes and the constant in \
             BOTH repos' tests, or the two sides have silently diverged."
        );
    }

    #[test]
    fn real_producer_emits_the_fixture_bytes_for_every_case() {
        let fixture: serde_json::Value = serde_json::from_str(PRESENCE_WIRE_V1).unwrap();
        let cases = fixture["cases"].as_array().expect("cases[]");
        assert!(cases.len() >= 7, "the fixture lost cases");
        let default_room = fixture["room"].as_str().expect("room");
        let mut saw_hub_fault = false;
        let mut saw_legacy = false;
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let p = &case["producer"];
            let room = p
                .get("room")
                .and_then(|v| v.as_str())
                .unwrap_or(default_room);
            let (body, status) = match p["kind"].as_str().unwrap() {
                "answered" => presence_route_response(
                    room,
                    &answered(
                        p["present"].as_bool().unwrap(),
                        p.get("lastSeenMs").and_then(|v| v.as_u64()),
                        p.get("rejoinDeadlineMs").and_then(|v| v.as_u64()),
                    ),
                ),
                "hub-fault" => {
                    saw_hub_fault = true;
                    presence_route_response(room, &PresenceRead::HubFault)
                }
                "invalid-room" => presence_invalid_room_response(),
                // A shape this relay must NEVER emit again: the pre-#313
                // un-marked `present:false`. The client keeps a case for it
                // (version skew — an old relay is still reachable), so the
                // assertion here is the mirror image: prove we don't emit it.
                "never-emitted-by-this-relay" => {
                    saw_legacy = true;
                    for read in [
                        answered(false, None, None),
                        answered(true, None, None),
                        PresenceRead::HubFault,
                    ] {
                        let (emitted, _) = presence_route_response(room, &read);
                        assert_ne!(
                            emitted, case["body"],
                            "case {name} is supposed to be UNREACHABLE from this producer"
                        );
                    }
                    continue;
                }
                other => panic!("unknown producer kind {other} in case {name}"),
            };
            assert_eq!(
                status,
                case["status"].as_u64().unwrap() as u16,
                "status mismatch for case {name}"
            );
            assert_eq!(body, case["body"], "body mismatch for case {name}");
        }
        assert!(
            saw_hub_fault,
            "the fixture must keep a hub-fault case — it is the #313 H1 pin"
        );
        assert!(
            saw_legacy,
            "the fixture must keep the pre-#313 un-marked absence — it is the \
             version-skew pin the client's away tag depends on"
        );
    }

    /// The marker rides the ANSWER only. A fault body carrying it would let a
    /// client believe a fabricated read was a real one.
    #[test]
    fn the_wire_marker_rides_answers_only() {
        let (answer, _) = presence_route_response("03aa-inbox", &answered(false, None, None));
        assert_eq!(answer["presenceWire"], json!(PRESENCE_WIRE_VERSION));
        let (fault, _) = presence_route_response("03aa-inbox", &PresenceRead::HubFault);
        assert!(
            fault.get("presenceWire").is_none(),
            "the fault body must not claim the answer contract: {fault}"
        );
        let (invalid, _) = presence_invalid_room_response();
        assert!(invalid.get("presenceWire").is_none());
    }
}

#[cfg(test)]
mod low_event_tests {
    use super::*;

    const OWNER: &str = "02d09d2feb33d5a17f426fd3d0c5c1a45c87961ece4c095fd111d37c7b2b0b4090";
    const PEER: &str = "03e2328ddc8372a78e9d8d17e7640e15e0909ee67db07a75ef0b6add2455bf7509";
    const GID: &str = "1a3f5099ce9c7bb1751339a9ff5933f56921278eb3228e0b00992b98b1747a55";

    #[test]
    fn a_waiting_hosts_lobby_room_is_recognised_and_nothing_else_is() {
        assert!(is_lobby_room(&format!("{OWNER}-low_lobby_{GID}")));
        assert!(!is_lobby_room(&format!("{OWNER}-low_game_{GID}")));
        assert!(!is_lobby_room(&format!("{OWNER}-low_lobby_{GID}_ack"))); // the joiner's ack box is not a waiting host
        assert!(!is_lobby_room("not-a-room"));
        assert!(!is_lobby_room(&format!("{OWNER}-")));
        assert!(!is_lobby_room(&format!("deadbeef-low_lobby_{GID}")));
    }

    #[test]
    fn the_lobby_departure_body_is_the_app_layer_lobby_envelope_with_a_host_left_change() {
        let room = format!("{OWNER}-low_lobby_{GID}");
        let body =
            lobby_departure_body(&room, OWNER, 1_700_000_000_000).expect("a lobby room fans out");
        assert_eq!(body["kind"], "lobby");
        assert_eq!(body["at"], 1_700_000_000_000u64);
        assert_eq!(body["changes"][0]["kind"], "host-left");
        assert_eq!(body["changes"][0]["hostIdentity"], OWNER);
        assert_eq!(body["changes"][0]["gameId"], GID);
        assert_eq!(body["changes"][0]["room"], room);
        // a game room never produces a lobby departure
        assert!(lobby_departure_body(&format!("{OWNER}-low_game_{GID}"), OWNER, 1).is_none());
        assert!(lobby_departure_body(&format!("{OWNER}-low_lobby_"), OWNER, 1).is_none());
    }

    #[test]
    fn the_ladder_event_is_a_first_party_push_into_the_peers_low_events_box() {
        let room = format!("{OWNER}-low_game_{GID}");
        let raw = ladder_event_push_body(OWNER, PEER, &room, 1_788_571_413_228, 1_788_571_393_000)
            .expect("a game room files a ladder event");
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["sender"], OWNER);
        assert_eq!(v["recipient"], PEER);
        assert_eq!(v["messageBox"], EVENTS_BOX);
        assert_eq!(v["body"]["v"], 1);
        assert_eq!(v["body"]["kind"], "ladder");
        assert_eq!(v["body"]["gameId"], GID);
        assert_eq!(v["body"]["stayer"], OWNER);
        assert_eq!(v["body"]["deadlineMs"], 1_788_571_413_228u64);
        // …and the /push splitter accepts it exactly as a first-party producer's body
        let (sender, send_body) = split_push_body(&raw, 1_788_571_393_000).expect("push shape");
        assert_eq!(sender, OWNER);
        let sb: serde_json::Value = serde_json::from_slice(&send_body).unwrap();
        assert_eq!(sb["message"]["recipient"], PEER);
        assert_eq!(sb["message"]["messageBox"], EVENTS_BOX);
        assert_eq!(sb["message"]["body"]["kind"], "ladder");
        assert!(sb["message"]["messageId"]
            .as_str()
            .is_some_and(|m| m.len() == 64));
    }

    #[test]
    fn the_ladder_event_refuses_a_lobby_room_a_foreign_owner_a_self_peer_and_a_bad_gid() {
        assert!(
            ladder_event_push_body(OWNER, PEER, &format!("{OWNER}-low_lobby_{GID}"), 1, 1)
                .is_none()
        );
        assert!(
            ladder_event_push_body(PEER, PEER, &format!("{OWNER}-low_game_{GID}"), 1, 1).is_none()
        );
        assert!(
            ladder_event_push_body(OWNER, OWNER, &format!("{OWNER}-low_game_{GID}"), 1, 1)
                .is_none()
        );
        assert!(
            ladder_event_push_body(OWNER, PEER, &format!("{OWNER}-low_game_abcd"), 1, 1).is_none()
        );
        assert!(
            ladder_event_push_body(OWNER, "nope", &format!("{OWNER}-low_game_{GID}"), 1, 1)
                .is_none()
        );
    }
}
