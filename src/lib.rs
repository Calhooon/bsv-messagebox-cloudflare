use bsv_middleware_cloudflare::{
    add_cors_headers, init_panic_hook,
    middleware::{
        auth::handle_cors_preflight, process_auth, sign_json_response, AuthMiddlewareOptions,
        AuthResult,
    },
};
use serde_json::json;
use worker::*;

mod api_docs;
mod d1;
mod error;
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

    let auth_options = AuthMiddlewareOptions {
        server_private_key: server_key,
        allow_unauthenticated: false,
        session_ttl_seconds: 3600,
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

    let auth_result = process_auth(req, &env, &auth_options)
        .await
        .map_err(|e| Error::from(e.to_string()))?;

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

    // Dispatch authenticated routes
    let path = req.path();
    let method = req.method();
    let (body, status) = match (method, path.as_str()) {
        // /health behind auth matches TS and Go ("all routes require auth").
        // Authed GET /health returns 200; unauthed requests are rejected by
        // the BRC-31 middleware with UNAUTHORIZED + "Mutual-authentication failed!".
        (Method::Get, "/") | (Method::Get, "/health") => (
            json!({ "status": "success", "message": "bsv-messagebox-cloudflare is running" }),
            200,
        ),
        (Method::Post, "/sendMessage") => {
            handle_send_message(&request_body, identity_key, &env, &store).await
        }
        (Method::Post, "/listMessages") => {
            handle_list_messages(&request_body, identity_key, &store).await
        }
        (Method::Post, "/acknowledgeMessage") => {
            handle_acknowledge_message(&request_body, identity_key, &store).await
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

        _ => (
            json!({ "status": "error", "code": "ERR_NOT_FOUND", "description": "Not Found" }),
            404,
        ),
    };

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
    store: &storage::Storage<'_>,
) -> (serde_json::Value, u16) {
    let validated = match validation::validate_acknowledge(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let deleted = match store
        .acknowledge_messages(identity_key, &validated.message_ids)
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
