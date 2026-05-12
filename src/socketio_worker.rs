//! Worker-side handlers for `/socket.io/*` polling traffic (M11 Phase 2).
//!
//! ## Why
//!
//! The legacy path routed every `/socket.io/*` request to the per-`sid`
//! `EngineIoSession` Durable Object. Each fresh `sid` (every fresh
//! identity in a test) created a fresh DO instance, paying CF
//! cold-start (100ms–several seconds). The deployed
//! `@bsv/message-box-client` has a hard 5-second budget for the
//! BRC-103 auth handshake, so cold-start outliers cause flaky
//! `"WebSocket authentication timed out!"` failures.
//!
//! Phase 2 eliminates the DO from the entire polling path. The Worker
//! (always warm) handles:
//!   * The Engine.IO `0{...}` handshake (done in Phase 1, in `lib.rs`).
//!   * Engine.IO `2`/`3` Ping/Pong and `1` Close on polling-POST.
//!   * Socket.IO `0` CONNECT (replies CONNACK) and `1` DISCONNECT.
//!   * Socket.IO `2` EVENT — including `authMessage` (full BRC-103 in
//!     Worker, no DO involvement) and post-auth events like
//!     `joinRoom` / `sendMessage` (forwarded to `MessageHub` via the
//!     existing `/internal/socketio-event` endpoint).
//!   * Polling-GET long-poll on the KV queue.
//!
//! The per-sid `EngineIoSession` DO is touched only when the client
//! upgrades to WebSocket. At upgrade time the DO loads the verified
//! BRC-103 state from KV and accepts the WS attachment; from there
//! all WS traffic flows through the DO exactly as before.
//!
//! ## Storage layout
//!
//! All in the existing `AUTH_SESSIONS` KV namespace, prefixed with
//! `sio:` to avoid collisions with BRC-31 session entries:
//!
//! | Key | Type | Meaning |
//! |---|---|---|
//! | `sio:auth:{sid}` | JSON `SessionAuthState` | BRC-103 state |
//! | `sio:identity:{sid}` | string | Verified identity key |
//! | `sio:queue:{sid}` | JSON `Vec<String>` | Encoded Engine.IO packets awaiting polling-GET drain |
//! | `sio:connected:{sid}` | string `"1"` | Whether Socket.IO CONNECT has completed |
//! | `sio:closed:{sid}` | string `"1"` | Whether the session is closed |
//!
//! TTL on all keys: 1 hour (matches the legacy DO session lifetime).
//!
//! ## Wire-protocol compatibility
//!
//! Every byte on the wire is identical to the legacy DO output:
//! same `0{...}` handshake JSON, same Engine.IO record-separated
//! polling batch, same Socket.IO frame shape, same BRC-103
//! `authMessage` envelope. Deployed `@bsv/message-box-client` and
//! `@bsv/authsocket-client` callers see no difference.
//!
//! ## Race safety
//!
//! KV read-modify-write on the polling queue is technically racy if
//! polling-POST and polling-GET run concurrently for the same `sid`.
//! In practice socket.io-client serialises its polling cycle (at most
//! one POST and one GET in flight per sid), and after the handshake
//! the client typically upgrades to WS and stops polling within a few
//! hundred milliseconds. The race window is closed by the protocol,
//! not by KV.

use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use worker::{
    console_log, kv::KvStore, Date, Delay, Env, Headers, Method, Request, RequestInit, Response,
    Result,
};

use crate::engineio::auth::{
    build_outbound_general, decode_event_payload, encode_event_payload, handle_auth_message,
    make_wallet, session_from_initial_response, AuthOutcome, SessionAuthState,
};
use crate::engineio::codec::{
    decode_polling_batch, encode_polling_batch, EngineIoPacket, SocketIoPacket,
};
use crate::engineio::public_polling_text_response;

const KV_AUTH_PREFIX: &str = "sio:auth:";
const KV_IDENTITY_PREFIX: &str = "sio:identity:";
const KV_QUEUE_PREFIX: &str = "sio:queue:";
const KV_CONNECTED_PREFIX: &str = "sio:connected:";
const KV_CLOSED_PREFIX: &str = "sio:closed:";
const KV_TTL_SECONDS: u64 = 3600;

const LONG_POLL_MS: u64 = 25_000;
const LONG_POLL_TICK_MS: u64 = 200;

// ===========================================================================
// KV helpers
// ===========================================================================

fn auth_kv(env: &Env) -> Result<KvStore> {
    env.kv("AUTH_SESSIONS")
}

async fn load_auth_state(kv: &KvStore, sid: &str) -> SessionAuthState {
    let key = format!("{KV_AUTH_PREFIX}{sid}");
    match kv.get(&key).json::<SessionAuthState>().await {
        Ok(Some(s)) => s,
        Ok(None) => SessionAuthState::default(),
        Err(e) => {
            console_log!("SIOW: load_auth_state sid={sid}: {e}");
            SessionAuthState::default()
        }
    }
}

async fn save_auth_state(kv: &KvStore, sid: &str, state: &SessionAuthState) {
    let key = format!("{KV_AUTH_PREFIX}{sid}");
    match kv.put(&key, state) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(KV_TTL_SECONDS).execute().await {
                console_log!("SIOW: save_auth_state sid={sid}: {e}");
            }
        }
        Err(e) => console_log!("SIOW: save_auth_state build sid={sid}: {e}"),
    }
}

async fn save_identity(kv: &KvStore, sid: &str, identity: &str) {
    let key = format!("{KV_IDENTITY_PREFIX}{sid}");
    match kv.put(&key, identity) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(KV_TTL_SECONDS).execute().await {
                console_log!("SIOW: save_identity sid={sid}: {e}");
            }
        }
        Err(e) => console_log!("SIOW: save_identity build sid={sid}: {e}"),
    }
}

async fn mark_connected(kv: &KvStore, sid: &str) {
    let key = format!("{KV_CONNECTED_PREFIX}{sid}");
    match kv.put(&key, "1") {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(KV_TTL_SECONDS).execute().await {
                console_log!("SIOW: mark_connected sid={sid}: {e}");
            }
        }
        Err(e) => console_log!("SIOW: mark_connected build sid={sid}: {e}"),
    }
}

#[allow(dead_code)]
async fn is_connected(kv: &KvStore, sid: &str) -> bool {
    let key = format!("{KV_CONNECTED_PREFIX}{sid}");
    matches!(kv.get(&key).text().await, Ok(Some(_)))
}

async fn mark_closed(kv: &KvStore, sid: &str) {
    let key = format!("{KV_CLOSED_PREFIX}{sid}");
    match kv.put(&key, "1") {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(KV_TTL_SECONDS).execute().await {
                console_log!("SIOW: mark_closed sid={sid}: {e}");
            }
        }
        Err(e) => console_log!("SIOW: mark_closed build sid={sid}: {e}"),
    }
}

async fn is_closed(kv: &KvStore, sid: &str) -> bool {
    let key = format!("{KV_CLOSED_PREFIX}{sid}");
    matches!(kv.get(&key).text().await, Ok(Some(_)))
}

async fn read_queue(kv: &KvStore, sid: &str) -> Vec<String> {
    let key = format!("{KV_QUEUE_PREFIX}{sid}");
    match kv.get(&key).json::<Vec<String>>().await {
        Ok(Some(v)) => v,
        _ => Vec::new(),
    }
}

async fn write_queue(kv: &KvStore, sid: &str, q: &[String]) {
    let key = format!("{KV_QUEUE_PREFIX}{sid}");
    let value = serde_json::to_string(q).unwrap_or_else(|_| "[]".into());
    match kv.put(&key, value) {
        Ok(builder) => {
            if let Err(e) = builder.expiration_ttl(KV_TTL_SECONDS).execute().await {
                console_log!("SIOW: write_queue sid={sid}: {e}");
            }
        }
        Err(e) => console_log!("SIOW: write_queue build sid={sid}: {e}"),
    }
}

async fn append_to_queue(kv: &KvStore, sid: &str, encoded_packet: String) {
    let mut q = read_queue(kv, sid).await;
    q.push(encoded_packet);
    write_queue(kv, sid, &q).await;
}

async fn drain_queue(kv: &KvStore, sid: &str) -> Vec<String> {
    let q = read_queue(kv, sid).await;
    if !q.is_empty() {
        write_queue(kv, sid, &Vec::new()).await;
    }
    q
}

/// Load BRC-103 session state for a sid. Public so `EngineIoSession`
/// can hydrate `inner.auth` on WS upgrade (the DO becomes the
/// authoritative state holder once the WS is attached).
pub async fn load_auth_state_public(env: &Env, sid: &str) -> SessionAuthState {
    let Ok(kv) = auth_kv(env) else {
        return SessionAuthState::default();
    };
    load_auth_state(&kv, sid).await
}

// ===========================================================================
// Polling-POST entry: decodes the polling batch and handles each packet.
// ===========================================================================

pub async fn handle_polling_post(body: &str, env: &Env, sid: &str) -> Result<Response> {
    let kv = auth_kv(env)?;

    if is_closed(&kv, sid).await {
        return public_polling_text_response("ok", 200);
    }

    if body.is_empty() {
        return public_polling_text_response("ok", 200);
    }

    let packets = match decode_polling_batch(body) {
        Ok(p) => p,
        Err(e) => {
            console_log!("SIOW: polling-POST decode error sid={sid}: {e}");
            return Response::error(format!("bad polling body: {e}"), 400);
        }
    };

    for pkt in packets {
        match pkt {
            EngineIoPacket::Open(_) => {
                // Server-only; ignore from client.
            }
            EngineIoPacket::Close => {
                mark_closed(&kv, sid).await;
            }
            EngineIoPacket::Ping(payload) => {
                // Engine.IO 2probe → reply 3probe (or any Ping → Pong).
                let pong = EngineIoPacket::Pong(payload).encode();
                append_to_queue(&kv, sid, pong).await;
            }
            EngineIoPacket::Pong(_) => {
                // Bare heartbeat ack — nothing to do.
            }
            EngineIoPacket::Message(payload) => {
                handle_socketio_in_worker(&payload, env, &kv, sid).await;
            }
            EngineIoPacket::Upgrade | EngineIoPacket::Noop => {
                // Upgrade `5` is sent over the new WS, not via polling.
                // Noop is server-only. Either is a no-op here.
            }
        }
    }

    public_polling_text_response("ok", 200)
}

// ===========================================================================
// Socket.IO packet dispatch (inside an Engine.IO Message).
// ===========================================================================

async fn handle_socketio_in_worker(payload: &str, env: &Env, kv: &KvStore, sid: &str) {
    let pkt = match SocketIoPacket::decode(payload) {
        Ok(p) => p,
        Err(e) => {
            console_log!("SIOW: socket.io decode error sid={sid}: {e}");
            return;
        }
    };
    match pkt {
        SocketIoPacket::Connect { nsp, .. } => {
            // CONNACK: same packet type, payload `{ "sid": "..." }`.
            let ack = SocketIoPacket::Connect {
                nsp: nsp.clone(),
                data: Some(json!({ "sid": sid })),
            };
            let frame = EngineIoPacket::Message(ack.encode()).encode();
            append_to_queue(kv, sid, frame).await;
            mark_connected(kv, sid).await;
        }
        SocketIoPacket::Disconnect { .. } => {
            mark_closed(kv, sid).await;
        }
        SocketIoPacket::Event {
            nsp,
            ack_id: _,
            data,
        } => {
            handle_socketio_event(env, kv, sid, &nsp, &data).await;
        }
        SocketIoPacket::Ack { .. } | SocketIoPacket::ConnectError { .. } => {
            // Server-side ACKs / errors aren't sent by the client in
            // the AuthSocket surface — drop silently.
        }
    }
}

async fn handle_socketio_event(env: &Env, kv: &KvStore, sid: &str, nsp: &str, data: &[Value]) {
    let event_name = match data.first().and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => {
            console_log!("SIOW: empty EVENT data sid={sid}");
            return;
        }
    };

    // `authMessage` is the BRC-103 carrier. Run the auth state machine
    // entirely in the Worker.
    if event_name == "authMessage" {
        let arg = data.get(1).cloned().unwrap_or(Value::Null);
        handle_authmessage(env, kv, sid, nsp, &arg).await;
        return;
    }

    // Non-authMessage events require an authenticated session. The
    // legacy DO drops these silently — we match that behaviour.
    let auth = load_auth_state(kv, sid).await;
    if !auth.is_authenticated() {
        console_log!("SIOW: dropping non-auth event '{event_name}' on unauthenticated sid={sid}");
        return;
    }

    // Forward to MessageHub. Returned outbound events are wrapped as
    // signed Generals and enqueued for polling-GET drain.
    let identity = match auth.verified_identity_key() {
        Some(s) => s.to_string(),
        None => return,
    };
    let event_data = data.get(1).cloned().unwrap_or(Value::Null);
    let outbound =
        forward_event_to_message_hub(env, &identity, sid, &event_name, &event_data).await;

    let server_key = match env.secret("SERVER_PRIVATE_KEY") {
        Ok(s) => s.to_string(),
        Err(e) => {
            console_log!("SIOW: SERVER_PRIVATE_KEY sid={sid}: {e}");
            return;
        }
    };
    let wallet = match make_wallet(&server_key) {
        Ok(w) => w,
        Err(e) => {
            console_log!("SIOW: make_wallet sid={sid}: {e}");
            return;
        }
    };
    for (out_name, out_data) in outbound {
        let final_name = authsocket_event_name(&out_name, &out_data);
        let payload = encode_event_payload(&final_name, &out_data);
        match build_outbound_general(payload, &auth, &wallet) {
            Ok(general) => {
                let frame = encode_outbound_authmessage(&general);
                append_to_queue(kv, sid, frame).await;
            }
            Err(e) => {
                console_log!("SIOW: build General '{out_name}' sid={sid}: {e}");
            }
        }
    }
}

async fn handle_authmessage(env: &Env, kv: &KvStore, sid: &str, nsp: &str, arg: &Value) {
    let server_key = match env.secret("SERVER_PRIVATE_KEY") {
        Ok(s) => s.to_string(),
        Err(e) => {
            console_log!("SIOW: SERVER_PRIVATE_KEY sid={sid}: {e}");
            return;
        }
    };
    let wallet = match make_wallet(&server_key) {
        Ok(w) => w,
        Err(e) => {
            console_log!("SIOW: make_wallet sid={sid}: {e}");
            return;
        }
    };

    let current = load_auth_state(kv, sid).await;
    let outcome = handle_auth_message(arg, &current, &wallet).await;
    match outcome {
        AuthOutcome::Outbound(msgs) => {
            // BRC-103 InitialRequest → InitialResponse. Enqueue the
            // InitialResponse and promote session state to
            // Authenticated.
            for out_msg in &msgs {
                let frame = encode_outbound_authmessage(out_msg);
                append_to_queue(kv, sid, frame).await;
            }
            if let Some(out) = msgs.first() {
                if let Ok(new_state) = session_from_initial_response(arg, out) {
                    if let Some(identity) = new_state.verified_identity_key() {
                        save_identity(kv, sid, identity).await;
                    }
                    save_auth_state(kv, sid, &new_state).await;
                    console_log!(
                        "SIOW: BRC-103 complete sid={sid} identity={}",
                        new_state.verified_identity_key().unwrap_or("<unknown>")
                    );
                }
            }
        }
        AuthOutcome::AuthenticatedGeneral { payload } => {
            // Client sent its first post-auth General. The legacy
            // server's "authenticated" fast-path emits
            // `authenticationSuccess` directly here without
            // round-tripping anywhere; we do the same. Other event
            // names forward to MessageHub.
            let (event_name, event_data) = decode_event_payload(&payload);

            if event_name == "authenticated" {
                let ack_payload =
                    encode_event_payload("authenticationSuccess", &json!({ "status": "success" }));
                match build_outbound_general(ack_payload, &current, &wallet) {
                    Ok(general) => {
                        let frame = encode_outbound_authmessage(&general);
                        append_to_queue(kv, sid, frame).await;
                        console_log!("SIOW: fast-path authenticationSuccess sid={sid}");
                    }
                    Err(e) => console_log!("SIOW: build authSuccess sid={sid}: {e}"),
                }
                return;
            }

            // Phase C bridge — same event names handled in the legacy
            // path's `forward_event_to_message_hub`.
            let identity = match current.verified_identity_key() {
                Some(s) => s.to_string(),
                None => return,
            };
            let outbound =
                forward_event_to_message_hub(env, &identity, sid, &event_name, &event_data).await;
            for (out_name, out_data) in outbound {
                let final_name = authsocket_event_name(&out_name, &out_data);
                let payload = encode_event_payload(&final_name, &out_data);
                match build_outbound_general(payload, &current, &wallet) {
                    Ok(general) => {
                        let frame = encode_outbound_authmessage(&general);
                        append_to_queue(kv, sid, frame).await;
                    }
                    Err(e) => console_log!("SIOW: build General '{out_name}' sid={sid}: {e}"),
                }
            }

            // Register this sid with MessageHub for HTTP→socket.io
            // broadcast fan-out. Best-effort; the WS-upgrade path
            // also reads KV state, so missing this is non-fatal.
            let _ = register_sid_with_hub(env, &identity, sid).await;
        }
        AuthOutcome::Quiet => {}
        AuthOutcome::Error(e) => {
            console_log!("SIOW: BRC-103 auth error sid={sid}: {e}");
        }
    }
    // Suppress unused-nsp warning — we currently only emit to "/".
    let _ = nsp;
}

// ===========================================================================
// Polling-GET: long-poll on the KV queue.
// ===========================================================================

pub async fn handle_polling_get(env: &Env, sid: &str) -> Result<Response> {
    let kv = auth_kv(env)?;

    if is_closed(&kv, sid).await {
        return public_polling_text_response(&EngineIoPacket::Close.encode(), 200);
    }

    let deadline = Date::now().as_millis() + LONG_POLL_MS;
    loop {
        let drained = drain_queue(&kv, sid).await;
        if !drained.is_empty() {
            // Each queue entry is a full Engine.IO packet body; we
            // join them with the protocol's record separator. We
            // pass through `EngineIoPacket::decode` + `encode_polling_batch`
            // to guarantee a well-formed batch even if a queue entry
            // was malformed.
            let pkts: std::result::Result<Vec<EngineIoPacket>, _> =
                drained.iter().map(|s| EngineIoPacket::decode(s)).collect();
            let body = match pkts {
                Ok(v) => encode_polling_batch(&v),
                Err(e) => {
                    console_log!("SIOW: polling-GET queue decode failed sid={sid}: {e:?}");
                    EngineIoPacket::Noop.encode()
                }
            };
            return public_polling_text_response(&body, 200);
        }

        if Date::now().as_millis() >= deadline {
            return public_polling_text_response(&EngineIoPacket::Noop.encode(), 200);
        }
        Delay::from(Duration::from_millis(LONG_POLL_TICK_MS)).await;
    }
}

// ===========================================================================
// MessageHub bridge
// ===========================================================================

#[derive(Debug, Deserialize)]
struct HubEventResponse {
    outbound: Vec<HubOutboundEvent>,
}

#[derive(Debug, Deserialize)]
struct HubOutboundEvent {
    #[serde(rename = "eventName")]
    event_name: String,
    data: Value,
}

async fn forward_event_to_message_hub(
    env: &Env,
    identity_key: &str,
    sid: &str,
    event_name: &str,
    data: &Value,
) -> Vec<(String, Value)> {
    let Ok(namespace) = env.durable_object("MESSAGE_HUB") else {
        return Vec::new();
    };
    let Ok(stub) = namespace
        .id_from_name(identity_key)
        .and_then(|id| id.get_stub())
    else {
        return Vec::new();
    };
    let payload = json!({
        "identityKey": identity_key,
        "sid": sid,
        "eventName": event_name,
        "data": data,
    })
    .to_string();
    let headers = Headers::new();
    if headers.set("content-type", "application/json").is_err() {
        return Vec::new();
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(payload.into()));
    let Ok(req) = Request::new_with_init("https://do.local/internal/socketio-event", &init) else {
        return Vec::new();
    };
    let mut resp = match stub.fetch_with_request(req).await {
        Ok(r) => r,
        Err(e) => {
            console_log!("SIOW: socketio-event fetch sid={sid}: {e}");
            return Vec::new();
        }
    };
    let body: HubEventResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            console_log!("SIOW: socketio-event response sid={sid}: {e}");
            return Vec::new();
        }
    };
    body.outbound
        .into_iter()
        .map(|e| (e.event_name, e.data))
        .collect()
}

async fn register_sid_with_hub(env: &Env, identity_key: &str, sid: &str) -> Result<()> {
    let namespace = env.durable_object("MESSAGE_HUB")?;
    let stub = namespace.id_from_name(identity_key)?.get_stub()?;
    let payload = json!({ "sid": sid }).to_string();
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(payload.into()));
    let req = Request::new_with_init("https://do.local/internal/socketio-register", &init)?;
    let _ = stub.fetch_with_request(req).await?;
    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

fn encode_outbound_authmessage(value: &Value) -> String {
    let evt = SocketIoPacket::Event {
        nsp: "/".to_string(),
        ack_id: None,
        data: vec![Value::String("authMessage".into()), value.clone()],
    };
    EngineIoPacket::Message(evt.encode()).encode()
}

/// Mirror of `engineio::session::authsocket_event_name`: for
/// `sendMessage` and `sendMessageAck` events, suffix the event name
/// with the roomId (TS authsocket convention).
fn authsocket_event_name(name: &str, data: &Value) -> String {
    if name == "sendMessage" || name == "sendMessageAck" {
        if let Some(room) = data.get("roomId").and_then(|v| v.as_str()) {
            return format!("{name}-{room}");
        }
    }
    name.to_string()
}
