//! M9 (#37, #39, #40, #41, #42, #43, #44, #45): MessageHub Durable Object —
//! hibernatable WebSocket host.
//!
//! Per-identity DO instance (routed via `MESSAGE_HUB.idFromName(identity_key)`)
//! hosting the WebSocket connections for that identity's clients.
//!
//! ## BRC compliance / trust model
//!
//! The auth model on this socket is **channel trust**, established once at
//! the upgrade and inherited by every subsequent frame — exactly like the
//! TS `authsocket` reference (`socket.emit(...)` events are NOT individually
//! signed there either). Concretely:
//!
//! * **BRC-31** (HTTP request signing) and **BRC-104** (transport headers)
//!   are enforced *only* at the WS upgrade by `process_auth` in `lib.rs`
//!   (M9 #40). The verified identity is forwarded to the DO as the
//!   `x-bsv-auth-identity-key` header on the upgrade Request.
//! * **BRC-103** (peer-to-peer mutual auth over a bidirectional channel)
//!   is satisfied by that same upgrade handshake — the middleware crate's
//!   `process_auth` internally drives the `Peer` abstraction from
//!   `bsv-rs/src/auth/peer.rs`. The WebSocket *is* the established BRC-103
//!   channel; client→server frames ride on that channel's trust boundary.
//!   Per-frame signing would diverge from TS parity AND from the standard
//!   BRC-103 pattern, so we do not do it.
//! * **BRC-100** (wallet substrate: `createAction`, `internalizeAction`)
//!   is not exercised by the event-channel surface — it lands on the
//!   `sendMessage` *write* path in #44.
//!
//! ## Wire envelope (#42 / #43)
//!
//! Both directions use the same JSON envelope, matching the TS authsocket
//! event shapes byte-for-byte:
//!
//! ```text
//!   { "event": "<name>", "data": { ... } }
//! ```
//!
//! Inbound events handled: `joinRoom`, `leaveRoom`, `sendMessage`,
//! `authenticated`. See `ClientEvent` below for field shapes.
//!
//! Outbound events emitted: `connected`, `authenticationSuccess`,
//! `joinedRoom`, `leftRoom`, `joinFailed`, `leaveFailed`, `messageFailed`,
//! `sendMessageAck`, `paymentFailed` (#44), `sendMessage` (#45 HTTP→WS
//! fan-out from the recipient DO's `/internal/push` route). The
//! `authenticationFailed` helper stays `#[allow(dead_code)]` — auth
//! failures abort the upgrade in `lib.rs` before the socket is accepted.
//!
//! ## Per-socket attachment
//!
//! Right after `accept_web_socket` we serialize a small `SocketAttachment`
//! blob onto the socket. Per the workers-rs 0.8 contract this survives
//! hibernation and is recovered via `deserialize_attachment` in any later
//! event handler. The 2 KB cap is plenty for our baseline (~80 bytes) plus
//! the joined-room list (~70 bytes per room — a 20-room client still fits
//! comfortably).
//!
//! ## Hibernation note
//!
//! Per workers-rs 0.8 source (`durable.rs`), the auto-response pair is
//! stored on the DO `state` and persists across hibernation cycles, so we
//! only need to set it once in `new()`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::*;

use crate::routes::send_message::{process_send, SendOutcome};
use crate::storage::Storage;
use crate::validation::{is_valid_pubkey, ValidatedSendMessage};

/// BRC-104 header carrying the authenticated peer identity. The auth
/// middleware in `lib.rs` injects this onto the request before forwarding.
const IDENTITY_KEY_HEADER: &str = "x-bsv-auth-identity-key";

/// DO-storage key prefix for the Phase C socket.io subscriber registry.
/// Each entry is `socketio_sub:<sid>` → JSON `{ sid, registered_at_ms }`.
/// Used by `handle_internal_push` to fan out broadcasts to socket.io
/// subscribers (whose state lives in a different DO class — `EngineIoSession`).
const SOCKETIO_SUB_PREFIX: &str = "socketio_sub:";

/// Per-socket state stored via `serialize_attachment`. Recovered in
/// every later event handler (message/close/error) via
/// `deserialize_attachment`. Survives hibernation per the workers-rs
/// 0.8 contract; hard cap is 2 KB.
///
/// Baseline payload is ~80 bytes; `joined_rooms` adds ~70 bytes per
/// entry, leaving headroom for ~25 rooms before approaching the cap.
#[derive(Serialize, Deserialize, Default, Debug)]
struct SocketAttachment {
    identity_key: String,
    connected_at_ms: u64,
    /// Rooms this socket has explicitly joined via `joinRoom`. The
    /// `<identity_key>-` prefix is enforced at join time, so every
    /// entry here is owned by `identity_key`.
    #[serde(default)]
    joined_rooms: Vec<String>,
}

/// Inbound event envelope: `{ "event": "<name>", "data": { ... } }`.
///
/// Field shapes mirror the TS `authsocket` reference
/// (`message-box-server/src/index.ts` lines 161–323). Unknown event
/// types fall through to the catch-all branch in `dispatch_event`.
///
/// Note on serde renaming: `rename_all = "camelCase"` on a tagged enum
/// only renames the *variant tags*, not their inner fields. Inner
/// struct-variant fields are renamed explicitly with `#[serde(rename)]`
/// so the wire shape stays `{roomId, messageId, identityKey, ...}`.
#[derive(Deserialize, Debug)]
#[serde(tag = "event", content = "data", rename_all = "camelCase")]
enum ClientEvent {
    JoinRoom {
        #[serde(rename = "roomId")]
        room_id: String,
    },
    LeaveRoom {
        #[serde(rename = "roomId")]
        room_id: String,
    },
    SendMessage {
        #[serde(rename = "roomId")]
        room_id: String,
        message: ClientSendMessage,
        /// Optional `payment` payload (BRC-100 internalize) at the
        /// envelope level, mirroring the HTTP `POST /sendMessage`
        /// shape. Not in the TS authsocket reference because the TS
        /// WS write path predates the paid-delivery fee model — kept
        /// optional so unpaid sends (free boxes) still parse cleanly.
        #[serde(default)]
        payment: Option<Value>,
    },
    Authenticated {
        #[serde(rename = "identityKey")]
        #[allow(dead_code)] // already verified at upgrade — kept for TS parity
        identity_key: String,
    },
}

/// Inner payload for the `sendMessage` event. Matches the TS shape at
/// `message-box-server/src/index.ts:163`. `body` is `serde_json::Value`
/// (not `String`) for parity with the HTTP path, which accepts strings,
/// objects, arrays, numbers, and booleans (see `validation.rs`).
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ClientSendMessage {
    message_id: String,
    recipient: String,
    body: Value,
}

/// Internal push body posted by the HTTP `POST /sendMessage` path
/// (M9 #45) to the recipient DO's `/internal/push` route. Wire shape
/// is camelCase to match the `sendMessage` event envelope it lands in.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PushBody {
    room_id: String,
    sender: String,
    message_id: String,
    /// The original-shape body the sender posted — string, object,
    /// array, number, or bool. Forwarded verbatim into the `sendMessage`
    /// envelope so subscribers see exactly what was sent.
    body: Value,
}

/// Inbound body posted by an `EngineIoSession` DO to the
/// `/internal/socketio-event` route (Phase C bridge). Mirrors the WS
/// `ClientEvent` shape, but the event name is on the outer envelope so
/// the MessageHub can dispatch without forcing the EngineIoSession to
/// know the parsing details.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SocketIoEventBody {
    /// The verified BRC-103 identity_key of the EngineIoSession. Used
    /// for room-ownership checks; same role as `SocketAttachment::identity_key`
    /// on the raw WS path. Trusted because the Engine.IO DO only forwards
    /// events from sessions whose `SessionAuthState::Authenticated`
    /// pinned this key.
    identity_key: String,
    /// Engine.IO sid of the originating session. Forwarded back to the
    /// EngineIoSession via `outbound[i].sid` (for direct emits) and
    /// stored on the broadcast registry entry (for fan-out cleanup).
    #[allow(dead_code)] // currently included for round-trip diagnostics; future uses welcome
    sid: String,
    event_name: String,
    /// Raw `data` payload exactly as encoded by the authsocket client.
    /// For `joinRoom` / `leaveRoom` it's a string (the roomId).
    /// For `sendMessage` it's an object `{ message: {recipient, messageBox, messageId, body}, payment? }`.
    /// Note: `roomId` for sendMessage is derived from the recipient + box
    /// (the authsocket reference doesn't put it on the wire).
    #[serde(default)]
    data: Value,
}

/// One outbound event the EngineIoSession should encode as a signed
/// General + send back to the client. Wire shape on the JSON response
/// from `handle_socketio_event` is `{outbound: [{eventName, data}, ...]}`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OutboundEvent {
    event_name: String,
    data: Value,
}

impl OutboundEvent {
    fn new(name: impl Into<String>, data: Value) -> Self {
        Self {
            event_name: name.into(),
            data,
        }
    }
}

/// Body for `/internal/socketio-register` and `/internal/socketio-unregister`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct SocketIoRegistration {
    sid: String,
}

/// Persistent registry entry for a socket.io subscriber. Stored at
/// `socketio_sub:<sid>` on this MessageHub's DO storage. Survives
/// hibernation since DO storage is durable. `joined_rooms` mirrors
/// the raw-WS `SocketAttachment.joined_rooms` so `handle_internal_push`
/// can filter the fan-out by room (only deliver to subscribers that
/// have explicitly joined the matching `<recipient>-<box>` room).
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
struct SocketIoRegistryEntry {
    sid: String,
    registered_at_ms: u64,
    #[serde(default)]
    joined_rooms: Vec<String>,
}

#[durable_object]
pub struct MessageHub {
    state: State,
    /// Worker bindings (D1, R2, secrets) — passed into the shared
    /// write path via `process_send` for the WS `sendMessage` event
    /// handler (#44).
    env: Env,
}

impl DurableObject for MessageHub {
    fn new(state: State, env: Env) -> Self {
        // Wire ping/pong auto-response so the runtime answers heartbeat
        // frames without un-hibernating the DO. Set once in the
        // constructor; the binding persists across hibernation per the
        // workers-rs 0.8 source contract.
        let pair = worker_sys::WebSocketRequestResponsePair::new("ping", "pong")
            .expect("WebSocketRequestResponsePair::new should not fail for static strings");
        state.set_websocket_auto_response(&pair);

        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        // The DO accepts two distinct kinds of incoming `fetch` calls:
        //
        //   1. WebSocket upgrade (`Upgrade: websocket`) — public-facing,
        //      routed via `lib.rs::route_websocket_upgrade` after BRC-31
        //      auth. Lands a hibernatable socket on this hub.
        //
        //   2. Internal push (`POST /internal/push`) — Worker-to-DO only,
        //      not reachable from the public internet. Used by the HTTP
        //      `POST /sendMessage` path (M9 #45) to fan out a freshly
        //      stored message to any of *this identity's* sockets that
        //      have joined the matching room. Authenticity is not
        //      checked at the DO boundary because DOs aren't externally
        //      addressable — only this Worker can reach them, and that
        //      Worker has already done BRC-31 auth on the originating
        //      send.
        let path = req.url()?.path().to_string();

        let upgrade_hdr = req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .unwrap_or_default();
        if upgrade_hdr.eq_ignore_ascii_case("websocket") {
            return self.handle_ws_upgrade(req).await;
        }

        if req.method() == Method::Post && path == "/internal/push" {
            return self.handle_internal_push(&mut req).await;
        }

        // M10 #61 Phase C — socket.io bridge endpoints. These let an
        // EngineIoSession DO (different DO class, per Engine.IO sid)
        // funnel post-auth events into the SAME identity-keyed
        // MessageHub instance that owns this identity's raw WS sockets,
        // so a single source of truth handles every channel:
        //
        //   * /internal/socketio-event       — process one inbound event
        //   * /internal/socketio-register    — register sid for broadcast push
        //   * /internal/socketio-unregister  — drop sid on disconnect/close
        //
        // Same trust model as `/internal/push`: the public internet
        // can't address DOs directly, and the only way a request lands
        // here is via this Worker, which has already verified the
        // identity (BRC-31 for HTTP, BRC-103 for socket.io).
        if req.method() == Method::Post && path == "/internal/socketio-event" {
            return self.handle_socketio_event(&mut req).await;
        }
        if req.method() == Method::Post && path == "/internal/socketio-register" {
            return self.handle_socketio_register(&mut req).await;
        }
        if req.method() == Method::Post && path == "/internal/socketio-unregister" {
            return self.handle_socketio_unregister(&mut req).await;
        }

        Response::error(
            "MessageHub only accepts WebSocket upgrade requests or POST /internal/{push,socketio-*}",
            400,
        )
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Recover the per-socket attachment. The upgrade path always
        // writes one; if it's somehow missing we treat the socket as
        // unverified and refuse to act on its events.
        let mut attachment: SocketAttachment = match ws.deserialize_attachment()? {
            Some(a) => a,
            None => {
                console_error!(
                    "MessageHub: websocket_message with no attachment — \
                     refusing event dispatch (treat as unverified)."
                );
                let _ = emit_message_failed(
                    &ws,
                    "internal: socket has no verified identity attachment",
                );
                return Ok(());
            }
        };

        match message {
            WebSocketIncomingMessage::String(s) => {
                self.dispatch_event(&ws, &mut attachment, &s).await?;
            }
            WebSocketIncomingMessage::Binary(_) => {
                // The event channel is JSON-only by design: TS
                // authsocket transport carries text frames, and we
                // have no defined binary opcode. Reject explicitly so
                // the client gets a useful diagnostic instead of
                // silent drop.
                let _ = emit_message_failed(&ws, "binary frames not supported on event channel");
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> Result<()> {
        console_log!(
            "MessageHub: WS close (code={}, reason={:?}, clean={})",
            code,
            reason,
            was_clean
        );
        // Complete the close handshake from the server side. For
        // hibernatable websockets the runtime delivers `websocket_close`
        // when the client sends a close frame, but does NOT auto-close
        // the server end — we must do so ourselves or the client's
        // `close()` future hangs waiting for the matching close frame.
        // Code must be in the application range (3000-4999) or
        // 1000/1001/etc.; we mirror the client code when valid and fall
        // back to 1000 ("normal closure") otherwise. Errors here are
        // best-effort: if the socket is already torn down, ignore.
        let mirror_code = u16::try_from(code).ok().filter(|c| *c >= 1000);
        let _ = ws.close(mirror_code.or(Some(1000)), Some(reason.as_str()));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_log!("MessageHub: WS error: {}", error);
        Ok(())
    }
}

impl MessageHub {
    /// WebSocket upgrade path. Runs only after `lib.rs::route_websocket_upgrade`
    /// has done BRC-31 auth and injected the verified
    /// `x-bsv-auth-identity-key` header onto the request.
    async fn handle_ws_upgrade(&self, req: Request) -> Result<Response> {
        // Identity is required: lib.rs only forwards here after `process_auth`
        // succeeds, and the middleware injects the verified
        // `x-bsv-auth-identity-key` onto the request. Missing means a bug
        // upstream — fail loudly so we notice.
        let identity_key = match req.headers().get(IDENTITY_KEY_HEADER) {
            Ok(Some(v)) if !v.is_empty() => v,
            _ => {
                console_error!(
                    "MessageHub: WS upgrade missing/empty {} header — \
                     lib.rs auth path is supposed to inject this. Refusing upgrade.",
                    IDENTITY_KEY_HEADER
                );
                return Response::error(
                    "Internal: WS upgrade arrived without verified identity",
                    500,
                );
            }
        };

        let pair = WebSocketPair::new()?;
        // accept_web_socket registers the server side as a hibernatable
        // socket: the runtime delivers events back via websocket_message
        // / websocket_close / websocket_error rather than as JS events.
        self.state.accept_web_socket(&pair.server);

        // Stamp the verified identity + connect time onto the socket so
        // it survives hibernation. This MUST happen before any
        // server.send() so that if a later message arrives the handler
        // can read the attachment back.
        let attachment = SocketAttachment {
            identity_key: identity_key.clone(),
            connected_at_ms: Date::now().as_millis(),
            joined_rooms: Vec::new(),
        };
        pair.server.serialize_attachment(&attachment)?;

        // Server-initiated greeting (#41/#43): proves end-to-end that
        // (a) auth delivered the verified identity and (b) the
        // attachment-write path is alive. Uses the unified envelope
        // shape from #43 so every event on this socket — server or
        // client — has the same outer shape.
        emit_connected(&pair.server, &identity_key)?;

        console_log!(
            "MessageHub: accepted WS upgrade for identity={} (hibernatable)",
            identity_key
        );
        Response::from_websocket(pair.client)
    }

    /// Internal push endpoint (M9 #45). Worker→DO only; the public
    /// internet cannot reach DOs directly, so the trust boundary is
    /// the originating Worker which has already done BRC-31 auth on
    /// the `POST /sendMessage` that triggered this fan-out.
    ///
    /// Body: `{ "roomId": "<recipient>-<box>", "sender": "<key>",
    ///          "messageId": "...", "body": <string|object|array|number|bool> }`
    ///
    /// Iterates every accepted socket on this DO (one DO per identity,
    /// so all sockets here belong to the recipient) and emits a
    /// `sendMessage` envelope to those that have `joinRoom`'d the
    /// matching `roomId`. Returns `{delivered: <count>}` for diagnostics.
    /// Sockets that aren't connected just won't see the push — they'll
    /// pick the message up on their next `listMessages`. The HTTP send
    /// MUST NOT be failed by anything that happens here.
    async fn handle_internal_push(&self, req: &mut Request) -> Result<Response> {
        let t_in = Date::now().as_millis();
        let body: PushBody = match req.json().await {
            Ok(b) => b,
            Err(e) => {
                console_log!("MessageHub: /internal/push bad JSON: {}", e);
                return Response::error(format!("invalid push body: {e}"), 400);
            }
        };

        let ws_count = self.state.get_websockets().len();
        console_log!(
            "TRACE_PHD broadcast.hub.in room={} msgId={} sender={} t={} ws_attached={}",
            body.room_id,
            body.message_id,
            body.sender,
            t_in,
            ws_count
        );

        let mut delivered = 0u32;
        for ws in self.state.get_websockets() {
            // Hibernated sockets without an attachment are non-conforming
            // (every accept path writes one). Skip rather than fail the
            // whole fan-out.
            let attachment: SocketAttachment = match ws.deserialize_attachment() {
                Ok(Some(a)) => a,
                Ok(None) => continue,
                Err(e) => {
                    console_log!(
                        "MessageHub: /internal/push: deserialize_attachment failed: {}",
                        e
                    );
                    continue;
                }
            };
            if !attachment.joined_rooms.iter().any(|r| r == &body.room_id) {
                continue;
            }
            // Best-effort emit: a single dead socket must not abort the
            // fan-out to the rest. Errors get logged and skipped.
            if let Err(e) = emit_send_message(
                &ws,
                &body.room_id,
                &body.sender,
                &body.message_id,
                &body.body,
            ) {
                console_log!(
                    "MessageHub: /internal/push: emit_send_message failed: {}",
                    e
                );
                continue;
            }
            delivered += 1;
        }

        let t_ws_done = Date::now().as_millis();
        console_log!(
            "TRACE_PHD broadcast.hub.ws_done room={} msgId={} t={} dt_ms={} delivered={}",
            body.room_id,
            body.message_id,
            t_ws_done,
            t_ws_done.saturating_sub(t_in),
            delivered
        );

        // M10 #61 Phase C — fan out to socket.io subscribers registered
        // on this hub. Each entry maps to an EngineIoSession DO via
        // `idFromName(sid)`, which we POST `/internal/socketio-broadcast`.
        // Best-effort: a stale registry entry (DO evicted, sid expired)
        // gets logged and skipped so one dead session doesn't abort the
        // others.
        let entries = self.list_socketio_subscribers().await;
        // M10 #61 race fix: do NOT filter by `joined_rooms` server-side
        // for the socket.io path. Two reasons:
        //
        // 1. Race: Alice's MessageBoxClient.listenForLiveMessages
        //    `await`s `socket.emit('joinRoom', ...)` (which only
        //    awaits the SEND, not the server's joinedRoom reply).
        //    Then the test (or any app) immediately sends a
        //    sendMessage from Bob. Bob's broadcast push and Alice's
        //    joinRoom both arrive cross-DO at Alice's MessageHub —
        //    if the push wins the race, Alice's joined_rooms
        //    doesn't include the room yet and the broadcast is
        //    skipped. Manifested as flaky "alice.onMessage doesn't
        //    fire" in tests/e2e_message_box_client_full.mjs step 6.
        //
        // 2. The server-side filter is REDUNDANT for socket.io
        //    clients because we emit the broadcast as the event name
        //    `sendMessage-${roomId}` (per the TS authsocket
        //    convention; see authsocket_event_name in
        //    src/engineio/session.rs). Client-side
        //    `socket.on('sendMessage-${roomId}', ...)` handlers only
        //    fire for the rooms they explicitly subscribed to. Sending
        //    to extra subscribers does no harm — their socket.io
        //    listener won't trigger.
        //
        // The raw-WS path keeps its `attachment.joined_rooms` filter
        // because raw WS uses the flat `sendMessage` event with
        // roomId in the payload (M9 #43 spec) — there's no
        // event-name-based client filtering there.
        let matching: Vec<SocketIoRegistryEntry> = entries;
        console_log!(
            "TRACE_PHD broadcast.hub.socketio_subs room={} msgId={} count={}",
            body.room_id,
            body.message_id,
            matching.len()
        );
        let mut socketio_delivered = 0u32;
        if !matching.is_empty() {
            let namespace = self.env.durable_object("ENGINEIO_SESSION").ok();
            for entry in matching {
                let sid = entry.sid;
                let Some(ns) = namespace.as_ref() else {
                    break;
                };
                let stub = match ns.id_from_name(&sid).and_then(|id| id.get_stub()) {
                    Ok(s) => s,
                    Err(e) => {
                        console_log!(
                            "MessageHub: socketio fan-out: stub for sid={} failed: {}",
                            sid,
                            e
                        );
                        continue;
                    }
                };
                let payload = json!({
                    "roomId": body.room_id,
                    "sender": body.sender,
                    "messageId": body.message_id,
                    "body": body.body,
                })
                .to_string();
                let headers = Headers::new();
                if let Err(e) = headers.set("content-type", "application/json") {
                    console_log!("MessageHub: socketio fan-out: header setup failed: {e}");
                    continue;
                }
                let mut init = RequestInit::new();
                init.with_method(Method::Post)
                    .with_headers(headers)
                    .with_body(Some(payload.into()));
                let req = match Request::new_with_init(
                    "https://do.local/internal/socketio-broadcast",
                    &init,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        console_log!("MessageHub: socketio fan-out: request build failed: {e}");
                        continue;
                    }
                };
                let t_sio_start = Date::now().as_millis();
                match stub.fetch_with_request(req).await {
                    Ok(_) => {
                        let t_sio_done = Date::now().as_millis();
                        console_log!(
                            "TRACE_PHD broadcast.hub.socketio_ok sid={} msgId={} t={} rtt_ms={}",
                            sid,
                            body.message_id,
                            t_sio_done,
                            t_sio_done.saturating_sub(t_sio_start)
                        );
                        socketio_delivered += 1;
                    }
                    Err(e) => {
                        let t_sio_done = Date::now().as_millis();
                        console_log!(
                            "TRACE_PHD broadcast.hub.socketio_err sid={} msgId={} t={} rtt_ms={} err={}",
                            sid,
                            body.message_id,
                            t_sio_done,
                            t_sio_done.saturating_sub(t_sio_start),
                            e
                        );
                        // Stale registry entry — most likely the EngineIoSession
                        // was evicted without firing close. Drop it now so the
                        // next push doesn't waste another fetch.
                        console_log!(
                            "MessageHub: socketio fan-out failed for sid={}: {} — dropping registry entry",
                            sid,
                            e
                        );
                        let key = format!("{SOCKETIO_SUB_PREFIX}{}", sid);
                        let _ = self.state.storage().delete(&key).await;
                    }
                }
            }
        }

        Response::from_json(&json!({
            "delivered": delivered,
            "socketioDelivered": socketio_delivered,
        }))
    }

    /// Parse an inbound text frame as a `ClientEvent` envelope and
    /// dispatch. All errors emit `messageFailed` with a reason — we
    /// never panic and never silently drop.
    async fn dispatch_event(
        &self,
        ws: &WebSocket,
        attachment: &mut SocketAttachment,
        raw: &str,
    ) -> Result<()> {
        // First-pass parse: tagged-enum failure either means malformed
        // JSON, missing/typo'd "event" tag, or unknown event name.
        // Distinguish unknown-event from generic parse error by
        // re-parsing as a loose Value to peek at the tag.
        let event = match serde_json::from_str::<ClientEvent>(raw) {
            Ok(ev) => ev,
            Err(e) => {
                let reason = match serde_json::from_str::<serde_json::Value>(raw) {
                    Ok(v) => match v.get("event").and_then(|t| t.as_str()) {
                        Some(name) => format!("unknown event type: {name}"),
                        None => format!("invalid event payload: {e}"),
                    },
                    Err(parse_err) => format!("invalid event payload: {parse_err}"),
                };
                let _ = emit_message_failed(ws, &reason);
                return Ok(());
            }
        };

        match event {
            ClientEvent::JoinRoom { room_id } => {
                if let Err(reason) = validate_room_owned(&attachment.identity_key, &room_id) {
                    let _ = emit_join_failed(ws, &reason);
                    return Ok(());
                }
                if !attachment.joined_rooms.iter().any(|r| r == &room_id) {
                    attachment.joined_rooms.push(room_id.clone());
                    ws.serialize_attachment(&*attachment)?;
                }
                emit_joined_room(ws, &room_id)?;
            }
            ClientEvent::LeaveRoom { room_id } => {
                if let Err(reason) = validate_room_owned(&attachment.identity_key, &room_id) {
                    let _ = emit_leave_failed(ws, &reason);
                    return Ok(());
                }
                let before = attachment.joined_rooms.len();
                attachment.joined_rooms.retain(|r| r != &room_id);
                if attachment.joined_rooms.len() != before {
                    ws.serialize_attachment(&*attachment)?;
                }
                emit_left_room(ws, &room_id)?;
            }
            ClientEvent::SendMessage {
                room_id,
                message,
                payment,
            } => {
                self.handle_send_message_event(
                    ws,
                    &attachment.identity_key,
                    room_id,
                    message,
                    payment,
                )
                .await;
            }
            ClientEvent::Authenticated { identity_key: _ } => {
                // Already verified at upgrade. Be polite to TS-shaped
                // clients that always send this immediately.
                emit_authentication_success(ws)?;
            }
        }
        Ok(())
    }

    /// Handle a `sendMessage` event from a verified socket. Funnels into
    /// the shared write path (`routes::send_message::process_send`) so
    /// the row inserted into D1 is byte-identical to one produced by
    /// `POST /sendMessage`. Translates the structured `SendOutcome` into
    /// the corresponding `sendMessageAck` / `messageFailed` /
    /// `paymentFailed` WS event.
    ///
    /// `sender_key` is the verified identity from `SocketAttachment` —
    /// it is the BRC-31 mutual-auth output from the upgrade and not
    /// derivable from the frame.
    async fn handle_send_message_event(
        &self,
        ws: &WebSocket,
        sender_key: &str,
        room_id: String,
        message: ClientSendMessage,
        payment: Option<Value>,
    ) {
        let t_in = Date::now().as_millis();
        let msg_id = message.message_id.clone();
        let recipient = message.recipient.clone();
        console_log!(
            "TRACE_PHD broadcast.send.in sender={} recipient={} msgId={} room={} t={}",
            sender_key,
            recipient,
            msg_id,
            room_id,
            t_in
        );
        let outbound = self
            .process_send_message(sender_key, room_id.clone(), message, payment)
            .await;
        let t_processed = Date::now().as_millis();
        console_log!(
            "TRACE_PHD broadcast.send.processed sender={} msgId={} t={} dt_ms={}",
            sender_key,
            msg_id,
            t_processed,
            t_processed.saturating_sub(t_in)
        );
        for ev in outbound {
            let _ = emit_event_to_ws(ws, &ev);
        }
    }

    /// Transport-agnostic send-path. Used by both the raw WS handler
    /// (`handle_send_message_event`) and the socket.io bridge handler
    /// (`handle_socketio_event`). Returns the list of events the caller
    /// must emit to the client.
    async fn process_send_message(
        &self,
        sender_key: &str,
        room_id: String,
        message: ClientSendMessage,
        payment: Option<Value>,
    ) -> Vec<OutboundEvent> {
        // 1. Room ownership: the socket can only send out of rooms
        // prefixed by its verified identity. Same rule as join/leave.
        if let Err(reason) = validate_room_owned(sender_key, &room_id) {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": reason }),
            )];
        }

        // 2. Derive the message_box from the room suffix. The room is
        // `<identity>-<box>` by convention (matches the TS authsocket
        // reference at `message-box-server/src/index.ts:215`, which
        // splits on `-` and takes element [1]).
        let prefix = format!("{sender_key}-");
        let message_box = room_id
            .strip_prefix(&prefix)
            .map(|s| s.to_string())
            .unwrap_or_default();
        if message_box.is_empty() {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": "Invalid room ID" }),
            )];
        }

        // 3. Per-field validation. Mirrors the HTTP validator's checks
        // (validation::validate_send_message) — same error codes, so
        // the parity contract holds for failure modes too.
        if message.message_id.is_empty() {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": "Each messageId must be a non-empty string." }),
            )];
        }
        if !is_valid_pubkey(&message.recipient) {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": format!("Invalid recipient key: {}", message.recipient) }),
            )];
        }
        if message.body.is_null()
            || (message.body.is_string()
                && message.body.as_str().map(str::is_empty).unwrap_or(false))
        {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": "Invalid message body." }),
            )];
        }

        // 4. Construct the same `ValidatedSendMessage` shape the HTTP
        // path produces, then call into the shared core. One source of
        // truth for fee resolution → payment internalization → D1
        // insert → FCM fan-out.
        let validated = ValidatedSendMessage {
            recipients: vec![(message.recipient.clone(), message.message_id.clone())],
            message_box,
            body: message.body,
            payment,
        };

        let db = match self.env.d1("DB") {
            Ok(d) => d,
            Err(e) => {
                return vec![OutboundEvent::new(
                    "messageFailed",
                    json!({ "reason": format!("internal: D1 binding: {e}") }),
                )];
            }
        };
        let store = Storage::new(&db);

        let outcome = process_send(validated, sender_key, &self.env, &store).await;
        outcome_to_outbound(&room_id, outcome)
    }

    /// `/internal/socketio-event` (Phase C). Dispatch one inbound
    /// socket.io event from an `EngineIoSession`. Body shape is
    /// `SocketIoEventBody`. Returns `{outbound: [{eventName, data}, ...]}`
    /// — the EngineIoSession encodes each as a signed General and ships
    /// over the active transport.
    async fn handle_socketio_event(&self, req: &mut Request) -> Result<Response> {
        let body: SocketIoEventBody = match req.json().await {
            Ok(b) => b,
            Err(e) => {
                return Response::error(format!("invalid socketio-event body: {e}"), 400);
            }
        };

        let outbound = self.dispatch_socketio_event(body).await;
        Response::from_json(&json!({ "outbound": outbound }))
    }

    /// Transport-agnostic dispatch for one decoded socket.io event from
    /// an authenticated EngineIoSession. Mirrors the WS path's
    /// `dispatch_event` exactly, but returns events instead of writing
    /// directly to a WebSocket. The event name + data are matched
    /// against the same set of `joinRoom` / `leaveRoom` / `sendMessage`
    /// / `authenticated` cases so the behaviour stays identical across
    /// channels.
    async fn dispatch_socketio_event(&self, body: SocketIoEventBody) -> Vec<OutboundEvent> {
        let SocketIoEventBody {
            identity_key,
            event_name,
            data,
            sid,
        } = body;
        match event_name.as_str() {
            "joinRoom" => {
                let room_id = match data.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        return vec![OutboundEvent::new(
                            "joinFailed",
                            json!({ "reason": "joinRoom requires a string roomId" }),
                        )];
                    }
                };
                if let Err(reason) = validate_room_owned(&identity_key, &room_id) {
                    return vec![OutboundEvent::new(
                        "joinFailed",
                        json!({ "reason": reason }),
                    )];
                }
                // Persist room membership on the per-sid registry entry
                // so `handle_internal_push` filters fan-out by joined
                // rooms — same semantics as the raw-WS path's
                // `SocketAttachment.joined_rooms`.
                self.update_socketio_rooms(&sid, |rooms| {
                    if !rooms.iter().any(|r| r == &room_id) {
                        rooms.push(room_id.clone());
                    }
                })
                .await;
                vec![OutboundEvent::new(
                    "joinedRoom",
                    json!({ "roomId": room_id }),
                )]
            }
            "leaveRoom" => {
                let room_id = match data.as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        return vec![OutboundEvent::new(
                            "leaveFailed",
                            json!({ "reason": "leaveRoom requires a string roomId" }),
                        )];
                    }
                };
                if let Err(reason) = validate_room_owned(&identity_key, &room_id) {
                    return vec![OutboundEvent::new(
                        "leaveFailed",
                        json!({ "reason": reason }),
                    )];
                }
                self.update_socketio_rooms(&sid, |rooms| {
                    rooms.retain(|r| r != &room_id);
                })
                .await;
                vec![OutboundEvent::new("leftRoom", json!({ "roomId": room_id }))]
            }
            "sendMessage" => {
                // The TS authsocket `sendMessage` data is the same body
                // shape as the HTTP /sendMessage `message` field, plus
                // an optional outer `payment`. Derive `roomId` from
                // `<identity>-<messageBox>` since the wire payload
                // doesn't carry it (matches message-box-server/src/index.ts).
                let obj = match data.as_object() {
                    Some(o) => o,
                    None => {
                        return vec![OutboundEvent::new(
                            "messageFailed",
                            json!({ "reason": "sendMessage data must be an object" }),
                        )];
                    }
                };
                // Allow either `message: {...}` (HTTP-style) or the
                // fields inlined directly.
                let inner = obj
                    .get("message")
                    .cloned()
                    .unwrap_or(Value::Object(obj.clone()));
                let payment = obj.get("payment").cloned();
                let parsed: ClientSendMessage = match serde_json::from_value(inner.clone()) {
                    Ok(m) => m,
                    Err(e) => {
                        return vec![OutboundEvent::new(
                            "messageFailed",
                            json!({ "reason": format!("invalid sendMessage payload: {e}") }),
                        )];
                    }
                };
                // Prefer explicit messageBox in the inner object. Fallback to top-level.
                let message_box = inner
                    .get("messageBox")
                    .and_then(|v| v.as_str())
                    .or_else(|| obj.get("messageBox").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string();
                if message_box.is_empty() {
                    return vec![OutboundEvent::new(
                        "messageFailed",
                        json!({ "reason": "sendMessage requires messageBox" }),
                    )];
                }
                let room_id = format!("{identity_key}-{message_box}");
                self.process_send_message(&identity_key, room_id, parsed, payment)
                    .await
            }
            "authenticated" => {
                // Mirror raw WS: idempotent, just acknowledge for TS-shaped clients.
                vec![OutboundEvent::new(
                    "authenticationSuccess",
                    json!({ "status": "success" }),
                )]
            }
            other => {
                console_log!(
                    "MessageHub: socketio-event: unknown event '{other}' for identity={identity_key}"
                );
                vec![OutboundEvent::new(
                    "messageFailed",
                    json!({ "reason": format!("unknown event: {other}") }),
                )]
            }
        }
    }

    /// `/internal/socketio-register` — record a sid that wants
    /// broadcast push fan-out. Stored under `socketio_sub:<sid>` on
    /// DO storage (durable across hibernation).
    async fn handle_socketio_register(&self, req: &mut Request) -> Result<Response> {
        let body: SocketIoRegistration = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid registration body: {e}"), 400),
        };
        if body.sid.is_empty() {
            return Response::error("registration sid must be non-empty", 400);
        }
        let key = format!("{SOCKETIO_SUB_PREFIX}{}", body.sid);
        // Preserve existing joined_rooms across re-registration so a
        // session that re-emits its `register` post-hibernation doesn't
        // lose membership it previously joined.
        let existing: Option<SocketIoRegistryEntry> =
            self.state.storage().get(&key).await.ok().flatten();
        let entry = SocketIoRegistryEntry {
            sid: body.sid.clone(),
            registered_at_ms: Date::now().as_millis(),
            joined_rooms: existing.map(|e| e.joined_rooms).unwrap_or_default(),
        };
        if let Err(e) = self.state.storage().put(&key, entry).await {
            console_log!(
                "MessageHub: socketio-register storage put failed for sid={}: {}",
                body.sid,
                e
            );
            return Response::error("storage put failed", 500);
        }
        Response::from_json(&json!({ "status": "ok" }))
    }

    /// Apply a mutation to a socket.io subscriber's `joined_rooms`
    /// list. Best-effort: if the entry doesn't exist (sid never
    /// registered, or hub eviction wiped storage between register +
    /// dispatch), we no-op rather than create — joining a room without
    /// being registered is meaningless because broadcasts are only
    /// directed to registered sids.
    async fn update_socketio_rooms<F>(&self, sid: &str, mutate: F)
    where
        F: FnOnce(&mut Vec<String>),
    {
        if sid.is_empty() {
            return;
        }
        let key = format!("{SOCKETIO_SUB_PREFIX}{sid}");
        // Auto-create if missing. The EngineIoSession's
        // `register_with_message_hub` call used to land an explicit
        // `socketio-register` *before* the first joinRoom, but that
        // path was removed from the auth fast-path (it blocked the WS
        // event loop on cold MessageHub DO starts). Since
        // MessageBoxClient always emits `joinRoom` before any
        // broadcast-relevant operation (sendLiveMessage joins the
        // sender's own room for the ack; listenForLiveMessages joins
        // the receiver's room), lazy auto-create here is the same
        // observable behaviour with one fewer cross-DO hop on the
        // critical-path WS message handler.
        let mut entry: SocketIoRegistryEntry = match self.state.storage().get(&key).await {
            Ok(Some(e)) => e,
            Ok(None) => SocketIoRegistryEntry {
                sid: sid.to_string(),
                joined_rooms: Vec::new(),
                registered_at_ms: Date::now().as_millis(),
            },
            Err(e) => {
                console_log!(
                    "MessageHub: update_socketio_rooms: storage get failed for sid={sid}: {e}"
                );
                return;
            }
        };
        mutate(&mut entry.joined_rooms);
        if let Err(e) = self.state.storage().put(&key, entry).await {
            console_log!(
                "MessageHub: update_socketio_rooms: storage put failed for sid={sid}: {e}"
            );
        }
    }

    /// `/internal/socketio-unregister` — remove a sid from the registry
    /// on disconnect / close.
    async fn handle_socketio_unregister(&self, req: &mut Request) -> Result<Response> {
        let body: SocketIoRegistration = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid registration body: {e}"), 400),
        };
        let key = format!("{SOCKETIO_SUB_PREFIX}{}", body.sid);
        let _ = self.state.storage().delete(&key).await;
        Response::from_json(&json!({ "status": "ok" }))
    }

    /// List all currently-registered socket.io subscriber entries on
    /// this MessageHub. Used by `handle_internal_push` to fan out
    /// broadcasts and filter by `joined_rooms` per entry. Best-effort:
    /// any storage error is logged and yields an empty list (the
    /// message is already in D1; offline clients catch up via
    /// `listMessages`).
    async fn list_socketio_subscribers(&self) -> Vec<SocketIoRegistryEntry> {
        let opts = ListOptions::new().prefix(SOCKETIO_SUB_PREFIX);
        let map = match self.state.storage().list_with_options(opts).await {
            Ok(m) => m,
            Err(e) => {
                console_log!("MessageHub: socketio sub list failed: {e}");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        // js_sys::Map iteration: each entry is [key, value].
        let entries = map.entries();
        let iter = js_sys::try_iter(&entries).ok().flatten();
        if let Some(iter) = iter {
            for e in iter.flatten() {
                let arr: js_sys::Array = e.into();
                let v = arr.get(1);
                if let Ok(entry) = serde_wasm_bindgen::from_value::<SocketIoRegistryEntry>(v) {
                    if !entry.sid.is_empty() {
                        out.push(entry);
                    }
                }
            }
        }
        out
    }
}

/// Validate that `room_id` is non-empty and prefixed by
/// `<identity_key>-`. Mirrors the implicit ownership model for
/// per-identity DOs: this socket can only operate on rooms owned by
/// its verified identity. Returns the failure reason on rejection.
fn validate_room_owned(identity_key: &str, room_id: &str) -> std::result::Result<(), String> {
    if room_id.trim().is_empty() {
        return Err("Invalid room ID".to_string());
    }
    let prefix = format!("{identity_key}-");
    if !room_id.starts_with(&prefix) {
        return Err(format!(
            "Room ID must be prefixed with the verified identity key (\"{prefix}\")"
        ));
    }
    Ok(())
}

// ===========================================================================
// Outbound event helpers (#43)
//
// Wire envelope: { "event": "<name>", "data": { ... } }
// Names match the TS `authsocket` reference exactly — these strings ARE
// the parity contract.
// ===========================================================================

/// Serialize and send the `{event,data}` envelope as a text frame.
fn emit<T: Serialize>(ws: &WebSocket, event: &str, data: &T) -> Result<()> {
    let envelope = json!({ "event": event, "data": data });
    ws.send_with_str(envelope.to_string())
}

/// `connected` — sent by the server immediately after accept, carrying
/// the verified identity. Replaces the old flat `{type, identityKey}`
/// shape with the unified envelope from #43.
fn emit_connected(ws: &WebSocket, identity_key: &str) -> Result<()> {
    emit(ws, "connected", &json!({ "identityKey": identity_key }))
}

/// `authenticationSuccess` — sent in response to an `authenticated`
/// inbound event. Idempotent on this server (auth is enforced at the
/// upgrade) but emitted for TS-client politeness.
fn emit_authentication_success(ws: &WebSocket) -> Result<()> {
    emit(ws, "authenticationSuccess", &json!({ "status": "success" }))
}

/// `authenticationFailed` — defined for parity. Not currently
/// triggered: auth failures terminate the upgrade in `lib.rs` before
/// the socket is ever accepted.
#[allow(dead_code)] // kept for TS-parity surface; auth failures abort the upgrade in lib.rs
fn emit_authentication_failed(ws: &WebSocket, reason: &str) -> Result<()> {
    emit(ws, "authenticationFailed", &json!({ "reason": reason }))
}

/// `joinedRoom` — successful joinRoom ack.
fn emit_joined_room(ws: &WebSocket, room_id: &str) -> Result<()> {
    emit(ws, "joinedRoom", &json!({ "roomId": room_id }))
}

/// `leftRoom` — successful leaveRoom ack.
fn emit_left_room(ws: &WebSocket, room_id: &str) -> Result<()> {
    emit(ws, "leftRoom", &json!({ "roomId": room_id }))
}

/// `joinFailed` — joinRoom rejected (validation error).
fn emit_join_failed(ws: &WebSocket, reason: &str) -> Result<()> {
    emit(ws, "joinFailed", &json!({ "reason": reason }))
}

/// `leaveFailed` — leaveRoom rejected (validation error).
fn emit_leave_failed(ws: &WebSocket, reason: &str) -> Result<()> {
    emit(ws, "leaveFailed", &json!({ "reason": reason }))
}

/// `sendMessage` — server→client fan-out of a message into a room
/// (M9 #45 HTTP→WS bridge).
///
/// `body` is `&Value` (not `&str`) for parity with the HTTP write path,
/// which accepts strings, objects, arrays, numbers, and booleans (see
/// `validation.rs`). The original-shape body flows through unchanged —
/// a client that POSTed a JSON object body sees the same object here,
/// a client that POSTed a string sees the same string.
fn emit_send_message(
    ws: &WebSocket,
    room_id: &str,
    sender: &str,
    message_id: &str,
    body: &Value,
) -> Result<()> {
    emit(
        ws,
        "sendMessage",
        &json!({
            "roomId": room_id,
            "sender": sender,
            "messageId": message_id,
            "body": body,
        }),
    )
}

/// `messageFailed` — sendMessage rejected, parse error, or unsupported
/// frame.
fn emit_message_failed(ws: &WebSocket, reason: &str) -> Result<()> {
    emit(ws, "messageFailed", &json!({ "reason": reason }))
}

/// Transport-agnostic translation of a `SendOutcome` into outbound
/// events. Identical fan-out shape as the legacy `emit_send_outcome`,
/// just structured so the same logic can drive both raw WS and the
/// socket.io bridge (Phase C).
fn outcome_to_outbound(room_id: &str, outcome: SendOutcome) -> Vec<OutboundEvent> {
    match outcome {
        SendOutcome::Success { results } => results
            .into_iter()
            .map(|r| {
                OutboundEvent::new(
                    "sendMessageAck",
                    json!({
                        "roomId": room_id,
                        "status": "success",
                        "messageId": r.message_id,
                    }),
                )
            })
            .collect(),
        SendOutcome::ValidationError { body, .. } => vec![OutboundEvent::new(
            "messageFailed",
            json!({ "reason": description_or(&body, "validation error") }),
        )],
        SendOutcome::BlockedRecipients { list } => vec![OutboundEvent::new(
            "messageFailed",
            json!({ "reason": format!("Blocked recipients: {}", list.join(", ")) }),
        )],
        SendOutcome::PaymentFailed { body, .. } => vec![OutboundEvent::new(
            "paymentFailed",
            json!({ "reason": description_or(&body, "payment failed") }),
        )],
        SendOutcome::DuplicateMessage { .. } => vec![OutboundEvent::new(
            "messageFailed",
            json!({ "reason": "Duplicate message." }),
        )],
        SendOutcome::InternalError { detail } => vec![OutboundEvent::new(
            "messageFailed",
            json!({ "reason": format!("An internal error has occurred: {}", detail) }),
        )],
    }
}

/// Send an outbound event over a raw WebSocket using the unified
/// `{event, data}` envelope. Mirrors `emit()` above; defined alongside
/// `outcome_to_outbound` so the two stay in sync.
fn emit_event_to_ws(ws: &WebSocket, ev: &OutboundEvent) -> Result<()> {
    let envelope = json!({ "event": ev.event_name, "data": ev.data });
    ws.send_with_str(envelope.to_string())
}

/// Pull `description` out of an HTTP-style error body, falling back to
/// `default` when the field is absent. Used by `outcome_to_outbound` to
/// re-use the HTTP `description` strings as WS event reasons.
fn description_or(body: &Value, default: &str) -> String {
    body.get("description")
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_room_owned_accepts_owner_prefix() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        assert!(validate_room_owned(key, &format!("{key}-inbox")).is_ok());
        assert!(validate_room_owned(key, &format!("{key}-notifications")).is_ok());
        assert!(validate_room_owned(key, &format!("{key}-payment_inbox")).is_ok());
    }

    #[test]
    fn validate_room_owned_rejects_other_identity() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        let other = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let err = validate_room_owned(key, &format!("{other}-inbox")).unwrap_err();
        assert!(err.contains("prefixed"), "got: {err}");
    }

    #[test]
    fn validate_room_owned_rejects_empty_and_whitespace() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        assert!(validate_room_owned(key, "").is_err());
        assert!(validate_room_owned(key, "   ").is_err());
    }

    #[test]
    fn validate_room_owned_rejects_missing_dash_separator() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        // Without the trailing dash a different identity could be a
        // proper prefix of ours — require the explicit `-` separator.
        let other = format!("{key}suffix");
        assert!(validate_room_owned(key, &other).is_err());
    }

    #[test]
    fn client_event_parses_join_room() {
        let raw = r#"{"event":"joinRoom","data":{"roomId":"abc-inbox"}}"#;
        let ev: ClientEvent = serde_json::from_str(raw).unwrap();
        match ev {
            ClientEvent::JoinRoom { room_id } => assert_eq!(room_id, "abc-inbox"),
            _ => panic!("expected JoinRoom"),
        }
    }

    #[test]
    fn client_event_parses_leave_room() {
        let raw = r#"{"event":"leaveRoom","data":{"roomId":"abc-inbox"}}"#;
        let ev: ClientEvent = serde_json::from_str(raw).unwrap();
        assert!(matches!(ev, ClientEvent::LeaveRoom { .. }));
    }

    #[test]
    fn client_event_parses_send_message() {
        let raw = r#"{
            "event":"sendMessage",
            "data":{
                "roomId":"abc-inbox",
                "message":{"messageId":"m1","recipient":"abc","body":"hi"}
            }
        }"#;
        let ev: ClientEvent = serde_json::from_str(raw).unwrap();
        match ev {
            ClientEvent::SendMessage {
                room_id,
                message,
                payment,
            } => {
                assert_eq!(room_id, "abc-inbox");
                assert_eq!(message.message_id, "m1");
                assert_eq!(message.recipient, "abc");
                assert_eq!(message.body, json!("hi"));
                assert!(payment.is_none());
            }
            _ => panic!("expected SendMessage"),
        }
    }

    #[test]
    fn client_event_parses_send_message_with_object_body_and_payment() {
        // Object bodies and an envelope-level payment must round-trip
        // — both flow into the shared write path the same way the
        // HTTP `POST /sendMessage` does.
        let raw = r#"{
            "event":"sendMessage",
            "data":{
                "roomId":"abc-inbox",
                "message":{
                    "messageId":"m1",
                    "recipient":"abc",
                    "body":{"k":"v"}
                },
                "payment":{"tx":"beef","outputs":[{"outputIndex":0}]}
            }
        }"#;
        let ev: ClientEvent = serde_json::from_str(raw).unwrap();
        match ev {
            ClientEvent::SendMessage {
                message, payment, ..
            } => {
                assert_eq!(message.body["k"], "v");
                let p = payment.expect("payment must parse");
                assert_eq!(p["tx"], "beef");
            }
            _ => panic!("expected SendMessage"),
        }
    }

    #[test]
    fn client_event_parses_authenticated() {
        let raw = r#"{"event":"authenticated","data":{"identityKey":"abc"}}"#;
        let ev: ClientEvent = serde_json::from_str(raw).unwrap();
        assert!(matches!(ev, ClientEvent::Authenticated { .. }));
    }

    #[test]
    fn client_event_rejects_unknown_event() {
        let raw = r#"{"event":"unknownEvent","data":{}}"#;
        assert!(serde_json::from_str::<ClientEvent>(raw).is_err());
    }

    #[test]
    fn client_event_rejects_garbage_json() {
        assert!(serde_json::from_str::<ClientEvent>("not-json-at-all").is_err());
    }

    #[test]
    fn socket_attachment_round_trips_with_rooms() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        let a = SocketAttachment {
            identity_key: key.to_string(),
            connected_at_ms: 1_700_000_000_000,
            joined_rooms: vec![format!("{key}-inbox"), format!("{key}-notifications")],
        };
        let s = serde_json::to_string(&a).unwrap();
        let b: SocketAttachment = serde_json::from_str(&s).unwrap();
        assert_eq!(a.identity_key, b.identity_key);
        assert_eq!(a.connected_at_ms, b.connected_at_ms);
        assert_eq!(a.joined_rooms, b.joined_rooms);
    }

    #[test]
    fn socket_attachment_back_compat_no_rooms_field() {
        // Old attachments (#41) had no joined_rooms field. Ensure they
        // still deserialize cleanly via #[serde(default)]. SocketAttachment
        // uses default snake_case derive — only the wire ClientEvent /
        // ClientSendMessage are camelCased.
        let raw = r#"{"identity_key":"abc","connected_at_ms":1}"#;
        let a: SocketAttachment = serde_json::from_str(raw).unwrap();
        assert_eq!(a.identity_key, "abc");
        assert!(a.joined_rooms.is_empty());
    }

    #[test]
    fn client_event_inner_fields_use_camel_case_wire_shape() {
        // Defensive: snake_case wire input must FAIL to parse (we
        // enforce camelCase to match the TS authsocket envelope).
        let bad = r#"{"event":"joinRoom","data":{"room_id":"abc-x"}}"#;
        assert!(serde_json::from_str::<ClientEvent>(bad).is_err());
    }

    #[test]
    fn push_body_round_trips_camel_case_wire_shape() {
        // Wire-format contract for the HTTP→WS bridge (M9 #45). The
        // sending side in routes::send_message::push_to_recipient_sockets
        // builds this exact shape; if either side drifts, the bridge
        // silently no-ops. Asserts the camelCase keys parse, the
        // original-shape body is preserved (object stays object — the
        // parity contract with the HTTP /sendMessage path), and that
        // snake_case is rejected, mirroring the discipline applied to
        // ClientEvent above.
        let raw = r#"{
            "roomId":"03ab-inbox",
            "sender":"02ff",
            "messageId":"m1",
            "body":{"k":"v","n":1}
        }"#;
        let pb: PushBody = serde_json::from_str(raw).unwrap();
        assert_eq!(pb.room_id, "03ab-inbox");
        assert_eq!(pb.sender, "02ff");
        assert_eq!(pb.message_id, "m1");
        assert!(pb.body.is_object());
        assert_eq!(pb.body["k"], "v");
        assert_eq!(pb.body["n"], 1);

        // snake_case must fail — we depend on camelCase parity with
        // the TS authsocket envelope and the HTTP send shape.
        let bad = r#"{"room_id":"x-y","sender":"s","message_id":"m","body":"b"}"#;
        assert!(serde_json::from_str::<PushBody>(bad).is_err());
    }

    #[test]
    fn description_or_extracts_string_or_falls_back() {
        // Load-bearing helper: it produces the human-facing `reason`
        // string on `messageFailed` / `paymentFailed` events when the
        // SendOutcome carries an HTTP-style error body. Three branches
        // matter: present-and-string returns it; missing returns the
        // default; present-but-not-a-string also returns the default
        // (serde_json::Value::as_str returns None for non-strings).
        let with_desc = json!({"description": "blocked by sender", "code": "X"});
        assert_eq!(description_or(&with_desc, "fallback"), "blocked by sender");

        let no_desc = json!({"code": "X"});
        assert_eq!(description_or(&no_desc, "fallback"), "fallback");

        let wrong_type = json!({"description": 42});
        assert_eq!(description_or(&wrong_type, "fallback"), "fallback");
    }
}
