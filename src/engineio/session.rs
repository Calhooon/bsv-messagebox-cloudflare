//! `EngineIoSession` Durable Object — one DO instance per Engine.IO
//! session id (sid). Hosts both the HTTP polling transport and (after
//! upgrade) the hibernatable WebSocket.
//!
//! ## Phase B scope (current)
//!
//! BRC-103 mutual authentication is layered over the `authMessage`
//! Socket.IO event (see `auth.rs`). Inbound EVENTs are dispatched as:
//!   * `authMessage` → `auth::handle_auth_message`. On a successful
//!     `InitialRequest` the session flips to `Authenticated`. The
//!     follow-up `authenticated` General that populates the client's
//!     `serverIdentityKey` is DEFERRED until we receive (and verify)
//!     the client's first post-auth General — sending it earlier
//!     races the TS `Peer.processInitialResponse` async chain and the
//!     client's verify fails with `counterparty: undefined`. See
//!     `auth.rs` module docs for the full rationale.
//!   * Anything else, while `Unauthenticated`, is dropped. (Phase C
//!     will route post-auth events to `MessageHub` for joinRoom /
//!     leaveRoom / sendMessage / etc.)
//!
//! ## Lifecycle
//!
//! 1. Worker handshake (`GET /socket.io/?EIO=4&transport=polling` with
//!    no `sid`) creates a fresh sid, routes to a fresh DO, calls
//!    `open_handshake_response`. The body is the Engine.IO `0`
//!    open packet with the handshake JSON.
//! 2. Subsequent polling GETs hit `handle_polling_get` which long-polls
//!    the in-memory outbound queue for up to ~25 s.
//! 3. Polling POSTs hit `handle_polling_post` which decodes inbound
//!    Engine.IO packets and dispatches them.
//! 4. WebSocket upgrade GET (`transport=websocket&sid=<sid>`) hits
//!    `handle_ws_upgrade`; from then on inbound traffic flows through
//!    `websocket_message`. The polling buffer is drained to the socket
//!    immediately after the upgrade probe handshake.
//!
//! ## Concurrency model
//!
//! DOs are single-threaded JS event-loop hosts. We use `RefCell` for
//! interior mutability — there is no parallel access to mutate state.
//! In-flight fetches share state through the `RefCell`; the polling
//! GET handler observes pushes from the POST handler by polling the
//! cell with a 25 ms `Delay`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::*;

use crate::engineio::auth::{
    self, build_outbound_general, encode_event_payload, handle_auth_message, make_wallet,
    session_from_initial_response, AuthOutcome, SessionAuthState,
};
use crate::engineio::codec::{
    decode_polling_batch, encode_polling_batch, EngineIoPacket, SocketIoPacket,
};

/// How long a polling GET waits for the queue to fill before returning
/// with whatever (possibly nothing) is buffered. socket.io clients
/// poll on a ~25 s long-poll cadence by default; we mirror that.
const POLLING_LONG_POLL_MS: u64 = 25_000;

/// Internal poll interval inside the long-poll loop.
const POLLING_TICK_MS: u64 = 25;

/// Engine.IO heartbeat parameters. Mirrors the reference socket.io
/// Node server defaults so an unmodified `socket.io-client@4.x` accepts
/// our handshake without tweaks.
const PING_INTERVAL_MS: u64 = 25_000;
const PING_TIMEOUT_MS: u64 = 20_000;
const MAX_PAYLOAD: u64 = 1_000_000;

/// Active transport for this session.
///
/// Serializable so it can be persisted into the WS attachment alongside
/// the rest of the session state — see `PersistedSessionState` (M10 #61
/// Bug 1). Without persistence, a hibernation between the WS upgrade
/// and the next inbound packet drops `Transport::WebSocket` back to the
/// default `Polling`, breaking `send_or_enqueue`'s real-time WS path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
enum Transport {
    /// Engine.IO long-poll. Initial transport for every session — the
    /// client must explicitly upgrade to WebSocket. Default so a
    /// `WsAttachment::default()` is sane.
    #[default]
    Polling,
    /// The session has fully upgraded to WebSocket and the polling
    /// transport is closed.
    WebSocket,
    /// The client has sent the upgrade probe (`2probe`) over the new
    /// WS but has not yet committed with the `5` upgrade packet. Both
    /// transports are still considered live; the next polling GET
    /// returns `noop` to flush.
    UpgradePending,
}

/// Mutable per-session state. All access is synchronous from inside the
/// DO event loop, so a plain `RefCell` is sufficient.
struct SessionState {
    sid: String,
    transport: Transport,
    /// Whether the Socket.IO connect handshake has happened on the
    /// default namespace. Until this flips true we don't dispatch
    /// EVENTs, and the first thing we send back to the client is the
    /// CONNECT ack.
    connected: bool,
    /// Outbound packet queue, drained by long-poll or by the WS path.
    /// NOT persisted across hibernation — packets in flight at the
    /// moment of eviction are lost; the client retries.
    queue: VecDeque<EngineIoPacket>,
    /// Whether the session has been closed (received Close packet or
    /// explicit DISCONNECT). Future polls return immediately.
    closed: bool,
    /// BRC-103 auth state for this session (Phase B). Phase C reads
    /// `verified_identity_key()` to route post-auth events to
    /// `MessageHub`.
    auth: SessionAuthState,
    /// Rooms this session has explicitly joined via `joinRoom`. Mirrors
    /// the raw-WS `SocketAttachment.joined_rooms` so we can persist
    /// across hibernation and (future) filter incoming broadcasts on
    /// the socket.io path. Currently MessageHub does the room-filter
    /// before fan-out, but persisting here keeps state intact through
    /// a wake so future hub wake-side filtering still works.
    joined_rooms: Vec<String>,
    /// Whether we've already sent the Phase B `authenticated` follow-up
    /// General to the client. We send it exactly once: the FIRST time
    /// the client successfully sends us a verified post-auth General.
    /// Sending it earlier (e.g. immediately after the InitialResponse)
    /// races the client's `processInitialResponse` async chain — the
    /// General arrives before the client's `peerSession.peerIdentityKey`
    /// is set, and `processGeneralMessage` fails verify with
    /// `counterparty: undefined`. Waiting for the client's first General
    /// guarantees the client has fully processed our InitialResponse
    /// (otherwise it couldn't have sent the General in the first place).
    authenticated_emitted: bool,
}

impl SessionState {
    fn new(sid: String) -> Self {
        Self {
            sid,
            transport: Transport::Polling,
            connected: false,
            queue: VecDeque::new(),
            closed: false,
            auth: SessionAuthState::default(),
            joined_rooms: Vec::new(),
            authenticated_emitted: false,
        }
    }

    /// Build from a persisted attachment after a hibernation wake.
    /// `queue` and `closed` are intentionally NOT carried over — the
    /// queue holds in-flight bytes the client retries, and `closed`
    /// implies the session is being torn down so persistence isn't
    /// meaningful past that point.
    fn from_attachment(att: &WsAttachment) -> Self {
        Self {
            sid: att.sid.clone(),
            transport: att.transport,
            connected: att.connected,
            queue: VecDeque::new(),
            closed: false,
            auth: att.auth.clone(),
            joined_rooms: att.joined_rooms.clone(),
            authenticated_emitted: att.authenticated_emitted,
        }
    }

    /// Snapshot the persisted slice as a fresh attachment for
    /// `WebSocket::serialize_attachment`. Called after every mutation
    /// of a persisted field.
    fn to_attachment(&self) -> WsAttachment {
        WsAttachment {
            sid: self.sid.clone(),
            connected: self.connected,
            transport: self.transport,
            auth: self.auth.clone(),
            joined_rooms: self.joined_rooms.clone(),
            authenticated_emitted: self.authenticated_emitted,
        }
    }

    fn enqueue(&mut self, p: EngineIoPacket) {
        self.queue.push_back(p);
    }

    fn drain(&mut self) -> Vec<EngineIoPacket> {
        self.queue.drain(..).collect()
    }
}

/// Per-WS attachment. Survives hibernation (workers-rs 0.8 contract,
/// 2 KB cap). Mirrors the critical fields of `SessionState` so we can
/// rebuild the in-memory state on a cold-start wake.
///
/// **What we persist** (all required to keep Socket.IO + BRC-103 alive
/// across hibernation):
///   * `sid` — Engine.IO session id; needed for routing + handshake ack.
///   * `connected` — Whether Socket.IO CONNECT has been ack'd. Without
///     this, `is_connected()` returns false on wake and EVENTs (incl.
///     `authMessage`) are dropped before they can dispatch — the exact
///     bug behind M10 #61 Bug 1.
///   * `transport` — Polling / UpgradePending / WebSocket. Without this,
///     `send_or_enqueue` falls back to polling-queue mode after a wake
///     even though the WS is live, so broadcasts never land.
///   * `auth` — Full BRC-103 `SessionAuthState`. Loses the verified
///     `peer_identity_key` and signing nonces if not persisted, breaking
///     every signed General we emit afterwards.
///   * `joined_rooms` — Used by future broadcast-side filtering; persisted
///     here for parity with the raw-WS path's `SocketAttachment.joined_rooms`.
///   * `authenticated_emitted` — Phase B's deferred-emit flag. Without
///     persistence we'd re-emit `authenticated` after every wake.
///
/// **What we do NOT persist** (and that's correct):
///   * The polling outbound `queue` — real-time data; the client retries.
///   * The closed flag — once closed, the DO is going away anyway.
///
/// Sized check: the attachment payload is ~250 B baseline, +~70 B per
/// joined room. Well below the 2 KB cap.
///
/// Serde defaults make older attachments (from before M10 #61 Bug 1
/// landed) deserialize cleanly into a sensible blank session — they
/// just won't auto-restore mid-session, which is fine since those
/// sessions predate the fix anyway.
#[derive(Serialize, Deserialize, Default, Debug)]
struct WsAttachment {
    sid: String,
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    transport: Transport,
    #[serde(default)]
    auth: SessionAuthState,
    #[serde(default)]
    joined_rooms: Vec<String>,
    #[serde(default)]
    authenticated_emitted: bool,
}

/// Body for `/internal/socketio-broadcast` (Phase C). Posted by the
/// per-identity MessageHub when an HTTP `POST /sendMessage` (or any
/// other write path) needs to fan out to socket.io subscribers.
/// Wire shape mirrors the raw-WS push envelope (`PushBody` in
/// `message_hub.rs`) so the same `body` semantics apply: the
/// original-shape body the sender posted is forwarded verbatim into
/// the `sendMessage` event payload.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BroadcastBody {
    room_id: String,
    sender: String,
    message_id: String,
    body: Value,
}

/// One outbound socket.io event the EngineIoSession should encode as a
/// signed General + send back to the client. Mirrors
/// `message_hub::OutboundEvent`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct OutboundSocketIoEvent {
    event_name: String,
    data: Value,
}

/// Response from `MessageHub::handle_socketio_event`.
#[derive(Deserialize, Debug)]
struct HubEventResponse {
    #[serde(default)]
    outbound: Vec<OutboundSocketIoEvent>,
}

#[durable_object]
pub struct EngineIoSession {
    state: State,
    /// Worker bindings — needed for the BRC-103 driver to read the
    /// `SERVER_PRIVATE_KEY` secret on every authMessage dispatch
    /// (Phase B). Cached on the DO instance; survives across requests
    /// but, like the in-memory session state, is recreated when the DO
    /// is evicted (the secret is re-read on the next constructor run).
    env: Env,
    /// In-memory mutable session state. Never populated from storage in
    /// Phase A/B — sessions are non-persistent (they live only as long
    /// as the DO is in memory). This matches the reference socket.io
    /// Node server behavior: a server restart drops live sessions and
    /// the client reconnects with a fresh sid.
    inner: RefCell<Option<SessionState>>,
}

impl DurableObject for EngineIoSession {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            inner: RefCell::new(None),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        // The DO accepts:
        //   * `GET /socket.io/?...&transport=polling[&sid=...]`
        //   * `POST /socket.io/?...&transport=polling&sid=...`
        //   * `GET /socket.io/?...&transport=websocket&sid=...` (Upgrade)
        //   * `GET /__init?sid=<sid>` — internal initialiser sent by
        //     the Worker the first time we land on a fresh sid, so the
        //     DO knows its sid before any client packet arrives.

        let url = req.url()?;
        let path = url.path().to_string();
        let qp: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        if path == "/__init" {
            return self.handle_init(&qp).await;
        }

        // M10 #61 Phase C — internal broadcast endpoint posted to by the
        // per-identity MessageHub when a fan-out for this socket.io sid
        // is required. Worker→DO only; the public internet cannot
        // address DOs directly.
        if req.method() == Method::Post && path == "/internal/socketio-broadcast" {
            return self.handle_socketio_broadcast(&mut req).await;
        }

        // Initialise from query if the DO doesn't yet know its sid.
        // Either the worker just routed a fresh handshake here (no sid
        // yet) or it routed a follow-up polling/WS request and we're
        // re-hydrating after an eviction.
        self.ensure_inner(&qp);

        let upgrade_hdr = req
            .headers()
            .get("upgrade")
            .ok()
            .flatten()
            .unwrap_or_default();
        let is_upgrade = upgrade_hdr.eq_ignore_ascii_case("websocket");

        let transport = qp.get("transport").map(String::as_str).unwrap_or("");

        if is_upgrade && transport == "websocket" {
            return self.handle_ws_upgrade(req).await;
        }

        match (req.method(), transport) {
            (Method::Get, "polling") => self.handle_polling_get(&qp).await,
            (Method::Post, "polling") => self.handle_polling_post(&mut req).await,
            _ => Response::error(
                "EngineIoSession: only polling/websocket transports are supported",
                400,
            ),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Recover the full persisted session state from the WS
        // attachment so we can re-hydrate after a hibernation wake.
        // M10 #61 Bug 1: previously we only pulled `sid` and rebuilt a
        // blank `SessionState`, dropping `connected`/`auth`/etc. and
        // breaking the EVENT-before-CONNECT guard plus all signed
        // emits.
        let attachment = match ws.deserialize_attachment::<WsAttachment>()? {
            Some(a) if !a.sid.is_empty() => a,
            _ => {
                console_error!("EngineIoSession: ws message with no attachment");
                return Ok(());
            }
        };
        if self.inner.borrow().is_none() {
            *self.inner.borrow_mut() = Some(SessionState::from_attachment(&attachment));
            console_log!(
                "EngineIoSession: rehydrated on ws message sid={} connected={} authenticated={}",
                attachment.sid,
                attachment.connected,
                attachment.auth.is_authenticated()
            );
        }

        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => {
                // Engine.IO binary frames are out of scope for Phase A
                // (the AuthSocket transport is text-only).
                return Ok(());
            }
        };

        // A WS frame carries a single Engine.IO packet (no `\x1e`
        // separation — that's polling-only).
        let pkt = match EngineIoPacket::decode(&text) {
            Ok(p) => p,
            Err(e) => {
                console_log!("EngineIoSession: WS decode error: {e}");
                return Ok(());
            }
        };
        self.handle_engineio_packet(pkt, Some(&ws)).await;
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        // If the DO was hibernated, rehydrate from the WS attachment
        // first so `unregister_with_message_hub` can read the
        // identity_key + sid. Otherwise we'd post a no-op unregister
        // and leak the registry entry on the per-identity MessageHub.
        if self.inner.borrow().is_none() {
            if let Ok(Some(att)) = ws.deserialize_attachment::<WsAttachment>() {
                if !att.sid.is_empty() {
                    *self.inner.borrow_mut() = Some(SessionState::from_attachment(&att));
                }
            }
        }
        if let Some(state) = self.inner.borrow_mut().as_mut() {
            state.closed = true;
        }
        // Drop the registry entry on the per-identity MessageHub so
        // future broadcast fan-outs skip this dead session.
        self.unregister_with_message_hub().await;
        let mirror_code = u16::try_from(code).ok().filter(|c| *c >= 1000);
        let _ = ws.close(mirror_code.or(Some(1000)), Some(reason.as_str()));
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_log!("EngineIoSession: WS error: {error}");
        Ok(())
    }
}

impl EngineIoSession {
    /// Initialise the in-memory state if absent. Sid is taken from
    /// `qp["sid"]` if present, otherwise a fresh uuid is generated and
    /// the caller is expected to fetch a handshake-shape `0{...}` from
    /// `open_handshake_packet`.
    ///
    /// Also tries to rehydrate from a hibernated WebSocket's attachment
    /// first — see `rehydrate_or_init` for the rationale. After a
    /// CF-driven eviction the in-memory `inner` is `None` even though
    /// the WS itself is alive and carries our previously-persisted
    /// state.
    fn ensure_inner(&self, qp: &std::collections::HashMap<String, String>) {
        if self.inner.borrow().is_some() {
            return;
        }
        if self.rehydrate_from_ws_attachment() {
            return;
        }
        let sid = qp.get("sid").cloned().unwrap_or_else(make_session_id);
        *self.inner.borrow_mut() = Some(SessionState::new(sid));
    }

    /// Rehydrate `inner` from any hibernated WebSocket's attachment.
    /// Returns true if a valid attachment was found and `inner` is now
    /// populated.
    ///
    /// **The fix for M10 #61 Bug 1.** Cloudflare aggressively evicts
    /// idle DOs; on wake, `inner` is `None` and every previously-set
    /// field is lost (`connected`, `transport`, `auth`, `joined_rooms`,
    /// `authenticated_emitted`). The hibernatable WebSocket survives
    /// the wake and so does its serialised attachment — that's where
    /// we rebuild from. If multiple sockets are attached (shouldn't
    /// happen on this DO, but be defensive), the first valid one wins;
    /// they'd all carry the same sid + state by construction.
    fn rehydrate_from_ws_attachment(&self) -> bool {
        let sockets = self.state.get_websockets();
        for ws in sockets {
            match ws.deserialize_attachment::<WsAttachment>() {
                Ok(Some(att)) if !att.sid.is_empty() => {
                    *self.inner.borrow_mut() = Some(SessionState::from_attachment(&att));
                    console_log!(
                        "EngineIoSession: rehydrated session sid={} connected={} authenticated={} from WS attachment",
                        att.sid,
                        att.connected,
                        att.auth.is_authenticated()
                    );
                    return true;
                }
                Ok(_) => {
                    // No attachment present yet (pre-upgrade WS, or a
                    // socket attached before this fix shipped). Skip.
                }
                Err(e) => {
                    console_log!("EngineIoSession: rehydrate: deserialize_attachment failed: {e}");
                }
            }
        }
        false
    }

    /// Persist the current `inner` snapshot to every attached
    /// hibernatable WebSocket. Call this after any mutation that
    /// touches `connected`, `transport`, `auth`, `joined_rooms`, or
    /// `authenticated_emitted` — those are the fields that must
    /// survive a hibernation wake (see `WsAttachment` doc comment).
    ///
    /// No-ops cleanly when no WebSocket is attached yet (the polling
    /// transport pre-upgrade has nowhere to persist; that's fine
    /// because the upgrade path re-serialises after attaching).
    fn persist_to_ws_attachment(&self) {
        let snapshot = match self.inner.borrow().as_ref() {
            Some(s) => s.to_attachment(),
            None => return,
        };
        let sockets = self.state.get_websockets();
        for ws in sockets {
            if let Err(e) = ws.serialize_attachment(&snapshot) {
                console_log!("EngineIoSession: persist_to_ws_attachment: serialize failed: {e}");
            }
        }
    }

    /// `GET /__init?sid=...` — explicit hand-off from the Worker on
    /// the very first request to a fresh sid. Returns the Engine.IO
    /// `open` packet body so the Worker can serve it as the handshake
    /// response.
    async fn handle_init(
        &self,
        qp: &std::collections::HashMap<String, String>,
    ) -> Result<Response> {
        let sid = match qp.get("sid") {
            Some(s) if !s.is_empty() => s.clone(),
            _ => return Response::error("missing sid", 400),
        };
        // Reset in case (somehow) this DO was reused; for fresh sids
        // it's just a one-time initialisation.
        *self.inner.borrow_mut() = Some(SessionState::new(sid.clone()));
        let body = open_handshake_packet(&sid).encode();
        polling_text_response(&body, 200)
    }

    /// HTTP polling GET — long-poll for up to `POLLING_LONG_POLL_MS`
    /// for the queue to fill, then drain and return as a polling
    /// batch. Returns immediately if the queue already has content or
    /// the session is closed.
    async fn handle_polling_get(
        &self,
        _qp: &std::collections::HashMap<String, String>,
    ) -> Result<Response> {
        let deadline_ticks = POLLING_LONG_POLL_MS / POLLING_TICK_MS;
        for _ in 0..deadline_ticks {
            {
                let mut guard = self.inner.borrow_mut();
                let state = guard.as_mut().expect("session state");
                if state.closed {
                    return polling_text_response(&EngineIoPacket::Close.encode(), 200);
                }
                // Only return `noop` to close the polling transport
                // once the client has fully committed to WebSocket
                // (transport=WebSocket via the `5` Upgrade packet).
                // During `UpgradePending` the client may still need
                // socket.io packets — CONNECT ack, BRC-103
                // InitialResponse, the deferred `authenticated`
                // follow-up — to land via polling because their WS
                // transport is in "probing" mode and ignores non-
                // `3probe` frames. (M10 #61 Bug 1: returning noop
                // here while a polling-POST-driven response is
                // pending strands the response in the polling queue
                // forever, since the client stops polling when it
                // sees noop.)
                if matches!(state.transport, Transport::WebSocket) && state.queue.is_empty() {
                    return polling_text_response(&EngineIoPacket::Noop.encode(), 200);
                }
                if !state.queue.is_empty() {
                    let pkts = state.drain();
                    return polling_text_response(&encode_polling_batch(&pkts), 200);
                }
            }
            Delay::from(Duration::from_millis(POLLING_TICK_MS)).await;
        }
        // Long-poll deadline elapsed with no traffic — drain (likely
        // empty) and return. Some socket.io-client versions tolerate
        // an empty body; Engine.IO v4 doesn't really specify, but a
        // bare `noop` packet is always safe and keeps the client
        // re-polling.
        let pkts = {
            let mut guard = self.inner.borrow_mut();
            let state = guard.as_mut().expect("session state");
            state.drain()
        };
        let body = if pkts.is_empty() {
            EngineIoPacket::Noop.encode()
        } else {
            encode_polling_batch(&pkts)
        };
        polling_text_response(&body, 200)
    }

    /// HTTP polling POST — decode inbound Engine.IO packets and
    /// dispatch each one. The response body is the literal `"ok"` per
    /// the socket.io reference server.
    async fn handle_polling_post(&self, req: &mut Request) -> Result<Response> {
        let body = req.text().await.unwrap_or_default();
        match decode_polling_batch(&body) {
            Ok(pkts) => {
                for pkt in pkts {
                    self.handle_engineio_packet(pkt, None).await;
                }
            }
            Err(e) => {
                console_log!("EngineIoSession: polling POST decode error: {e}");
                return Response::error(format!("bad polling body: {e}"), 400);
            }
        }
        polling_text_response("ok", 200)
    }

    /// WebSocket upgrade. After the handshake we mark the transport as
    /// upgrade-pending; the actual switch to WS-only happens once the
    /// client sends `5` (Engine.IO upgrade packet).
    async fn handle_ws_upgrade(&self, _req: Request) -> Result<Response> {
        let sid = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| s.sid.clone())
            .unwrap_or_default();
        if sid.is_empty() {
            return Response::error("WS upgrade requires existing session sid", 400);
        }

        // M11 Phase 2: if the BRC-103 handshake happened in the
        // Worker (via `crate::socketio_worker`) the DO's in-memory
        // `inner.auth` is still `NotAuthenticated`. Pull the verified
        // state out of KV here, BEFORE serialising the attachment, so
        // every subsequent WS frame's rehydrate-from-attachment sees
        // the right nonces and verifies signed Generals correctly.
        let kv_auth = crate::socketio_worker::load_auth_state_public(&self.env, &sid).await;
        if kv_auth.is_authenticated() {
            if let Some(state) = self.inner.borrow_mut().as_mut() {
                if !state.auth.is_authenticated() {
                    state.auth = kv_auth;
                    state.connected = true;
                    console_log!("EngineIoSession: hydrated KV auth state on WS upgrade sid={sid}");
                }
            }
        }

        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);

        // Don't flip transport yet — we wait for the `2probe` / `5`
        // sequence so polling stays usable until the client commits.
        if let Some(state) = self.inner.borrow_mut().as_mut() {
            state.transport = Transport::UpgradePending;
        }
        // Persist the full session snapshot (sid + transport + auth +
        // ...) onto the new socket so a hibernation between upgrade and
        // first inbound packet can rehydrate the in-memory state — see
        // `WsAttachment` doc / `rehydrate_from_ws_attachment`. We
        // serialise on the just-accepted server socket directly so the
        // attachment is in place before any packet ships over it.
        let snapshot = self
            .inner
            .borrow()
            .as_ref()
            .map(SessionState::to_attachment)
            .unwrap_or_default();
        pair.server.serialize_attachment(&snapshot)?;
        console_log!(
            "TRACE_PHD upgrade.ws_accepted sid={} t={}",
            sid,
            Date::now().as_millis()
        );
        console_log!("EngineIoSession: accepted WS upgrade for sid={sid}");
        Response::from_websocket(pair.client)
    }

    /// Dispatch one inbound Engine.IO packet. `ws_for_response` is
    /// `Some` when called from the WS path (so the response is sent
    /// over the same socket immediately) and `None` when called from
    /// the polling POST path (so the response is enqueued for the
    /// next polling GET to drain).
    async fn handle_engineio_packet(
        &self,
        pkt: EngineIoPacket,
        ws_for_response: Option<&WebSocket>,
    ) {
        match pkt {
            EngineIoPacket::Open(_) => {
                // Server-only packet; ignore from client.
            }
            EngineIoPacket::Close => {
                if let Some(state) = self.inner.borrow_mut().as_mut() {
                    state.closed = true;
                }
                self.unregister_with_message_hub().await;
            }
            EngineIoPacket::Ping(payload) => {
                // `2probe` arrives over the WS during transport upgrade
                // — respond with `3probe` over the SAME socket.
                let pong = EngineIoPacket::Pong(payload);
                self.send_or_enqueue(pong, ws_for_response);
            }
            EngineIoPacket::Pong(_) => {
                // Bare pong ack — nothing to do. The auto-response pair
                // configured for hibernatable WS handles the heartbeat
                // path normally; this branch covers a manual pong from
                // a non-hibernated WS or polling.
            }
            EngineIoPacket::Message(payload) => {
                self.dispatch_socketio(&payload, ws_for_response).await;
            }
            EngineIoPacket::Upgrade => {
                // Client commits to WS. Flip the transport so future
                // polling GETs return `noop` and we drain through the
                // WS only. Persist the new transport into the WS
                // attachment so a hibernation between now and the next
                // packet keeps `send_or_enqueue` on the WS path.
                let sid_log = self
                    .inner
                    .borrow()
                    .as_ref()
                    .map(|s| s.sid.clone())
                    .unwrap_or_else(|| "<empty>".into());
                console_log!(
                    "TRACE_PHD upgrade.commit sid={} t={}",
                    sid_log,
                    Date::now().as_millis()
                );
                if let Some(state) = self.inner.borrow_mut().as_mut() {
                    state.transport = Transport::WebSocket;
                }
                self.persist_to_ws_attachment();
            }
            EngineIoPacket::Noop => {
                // Server-only; ignore from client.
            }
        }
    }

    /// Dispatch one Socket.IO packet (i.e. the payload of an Engine.IO
    /// `4` message). Phase B surface:
    ///   * CONNECT → CONNECT ack (auth happens AFTER namespace connect,
    ///     just like the TS `AuthSocketServer` reference: `peer` is
    ///     constructed inside the `connection` callback).
    ///   * EVENT `authMessage` → BRC-103 driver in `auth.rs`. On
    ///     successful handshake, follows up with an `authenticated`
    ///     event so unmodified `@bsv/authsocket-client` populates its
    ///     `serverIdentityKey`.
    ///   * EVENT (any other name) → dropped while
    ///     `SessionAuthState::Unauthenticated` (Phase C will route to
    ///     MessageHub once authenticated).
    ///   * DISCONNECT/ACK/CONNECT_ERROR — same as Phase A.
    async fn dispatch_socketio(&self, payload: &str, ws_for_response: Option<&WebSocket>) {
        let pkt = match SocketIoPacket::decode(payload) {
            Ok(p) => p,
            Err(e) => {
                console_log!("EngineIoSession: socket.io decode error: {e}");
                return;
            }
        };
        match pkt {
            SocketIoPacket::Connect { nsp, .. } => {
                // Only the default namespace is supported. Phase A's
                // no-namespace contract carries through Phase B.
                if nsp != "/" {
                    let err = SocketIoPacket::ConnectError {
                        nsp: nsp.clone(),
                        data: Some(json!({"message": "namespace not supported"})),
                    };
                    self.send_or_enqueue(EngineIoPacket::Message(err.encode()), ws_for_response);
                    return;
                }
                let sock_sid = self
                    .inner
                    .borrow()
                    .as_ref()
                    .map(|s| s.sid.clone())
                    .unwrap_or_default();
                if let Some(state) = self.inner.borrow_mut().as_mut() {
                    state.connected = true;
                }
                // Persist the CONNECT-ack flip — without this, a wake
                // between CONNECT and the first authMessage drops
                // `connected` to its `Option::unwrap_or(false)` default
                // and the EVENT-before-CONNECT guard at
                // `dispatch_socketio::Event` discards the auth packet.
                // (M10 #61 Bug 1, the exact failure mode that drove
                // `MessageBoxClient.initializeConnection` timeouts on
                // the second of two simultaneous clients.)
                self.persist_to_ws_attachment();
                let ack = SocketIoPacket::Connect {
                    nsp: "/".into(),
                    data: Some(json!({"sid": sock_sid})),
                };
                self.send_or_enqueue(EngineIoPacket::Message(ack.encode()), ws_for_response);
            }
            SocketIoPacket::Disconnect { .. } => {
                if let Some(state) = self.inner.borrow_mut().as_mut() {
                    state.closed = true;
                }
                self.unregister_with_message_hub().await;
            }
            SocketIoPacket::Event { nsp, ack_id, data } => {
                // Peek at event name BEFORE the connected gate.
                // `authMessage` is the BRC-103 bootstrap protocol — it MUST
                // be processed even when `connected=false`, otherwise we
                // create a chicken-and-egg: a cold session whose CONNECT
                // packet hasn't been seen yet receives an `authMessage`
                // (clients commonly send these in quick succession over
                // WS) and we drop it, BRC-103 never starts, and
                // `MessageBoxClient.initializeConnection` hits its 5s
                // `authenticationTimeout`. (M10 #61 cold-start race —
                // distinct from Bug 1's hibernation race.)
                let mut iter = data.into_iter();
                let name = match iter.next().and_then(|v| v.as_str().map(String::from)) {
                    Some(n) => n,
                    None => {
                        console_log!("EngineIoSession: EVENT with non-string name — dropping");
                        return;
                    }
                };

                if name == "authMessage" {
                    // BRC-103 dispatch — single arg is the AuthMessage
                    // JSON object. Bypasses the connected gate by design
                    // (see comment above).
                    let arg = iter.next().unwrap_or(Value::Null);
                    self.dispatch_auth_message(&arg, &nsp, ack_id, ws_for_response)
                        .await;
                    return;
                }

                // Non-authMessage events still require the session to
                // have been CONNECTed (or to have completed BRC-103 — see
                // is_connected() in this file for the Bug 1 defense).
                if !self.is_connected() {
                    console_log!(
                        "EngineIoSession: EVENT '{name}' before CONNECT — dropping (auth not started)"
                    );
                    return;
                }

                // Any non-`authMessage` Socket.IO EVENT is silently
                // dropped. The `@bsv/authsocket-client` (the only
                // supported client) wraps every `socket.emit(...)` in a
                // signed BRC-103 General that ships as
                // `authMessage` — see SocketClientTransport.send. A
                // raw EVENT here therefore means a non-authsocket
                // client that we have no signed channel with; refusing
                // it (whether before or after auth) is the correct
                // posture and matches the TS `AuthSocketServer`
                // reference, which only wires events through its peer
                // listener.
                let _ = (nsp, ack_id);
                console_log!(
                    "EngineIoSession: raw EVENT '{name}' on socket.io surface — dropping (use authMessage)"
                );
            }
            SocketIoPacket::Ack { .. } => {
                // Nothing to acknowledge yet — ignore.
            }
            SocketIoPacket::ConnectError { .. } => {
                // Server-emitted; ignore from client.
            }
        }
    }

    /// BRC-103 inbound — single inbound `authMessage` arg. On success
    /// the session may flip to `Authenticated`, in which case we also
    /// emit an `authenticated` event so the unmodified TypeScript
    /// `@bsv/authsocket-client` populates its `serverIdentityKey`.
    async fn dispatch_auth_message(
        &self,
        arg: &Value,
        nsp: &str,
        ack_id: Option<u64>,
        ws_for_response: Option<&WebSocket>,
    ) {
        // ack_id on an authMessage event is non-standard — the TS
        // reference doesn't ack — but if a client sends one we'll
        // honor the channel by NOT bouncing one back. Suppress the
        // warning.
        let _ = ack_id;

        let server_key = match self.env.secret("SERVER_PRIVATE_KEY") {
            Ok(s) => s.to_string(),
            Err(e) => {
                console_error!("EngineIoSession: SERVER_PRIVATE_KEY not set: {e}");
                return;
            }
        };
        let wallet = match make_wallet(&server_key) {
            Ok(w) => w,
            Err(e) => {
                console_error!("EngineIoSession: make_wallet: {e}");
                return;
            }
        };

        // Snapshot the current auth state — we never hold the borrow
        // across the await below.
        let current_state = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| s.auth.clone())
            .unwrap_or_default();

        let outcome = handle_auth_message(arg, &current_state, &wallet).await;
        match outcome {
            AuthOutcome::Outbound(msgs) => {
                // Send the InitialResponse back as an authMessage event.
                for out_msg in &msgs {
                    self.emit_auth_message(out_msg, nsp, ws_for_response);
                }
                // If the inbound was an InitialRequest and we replied
                // with an InitialResponse, flip session state to
                // Authenticated. The Phase B `authenticated` General
                // follow-up is DEFERRED until the client's first
                // post-auth General arrives — see the
                // `AuthenticatedGeneral` arm below.
                //
                // Why deferred: the TS `Peer.processInitialResponse` is
                // an async chain that mutates `peerSession.peerIdentityKey`
                // and other fields BEFORE its `await`s resolve. If we
                // emit our `authenticated` General immediately after the
                // InitialResponse, both events land in the client's
                // `socket.io` handler in rapid succession; the second
                // (General) call enters `processGeneralMessage` while
                // the first (InitialResponse) is still mid-flight, so
                // `peerSession.peerIdentityKey` is still `undefined` at
                // verify time and the signature check fails with
                // `counterparty: undefined`. Waiting until the client
                // has sent us a General proves the client's session has
                // fully transitioned to authenticated state.
                if let Some(out) = msgs.first() {
                    if let Ok(new_state) = session_from_initial_response(arg, out) {
                        let identity_key = new_state
                            .verified_identity_key()
                            .map(String::from)
                            .unwrap_or_default();
                        if let Some(state) = self.inner.borrow_mut().as_mut() {
                            state.auth = new_state.clone();
                        }
                        // Persist the verified identity + nonces. If the
                        // DO is evicted before the client's first
                        // post-auth General, we need to be able to
                        // verify that General's signature on wake —
                        // which requires the server_session_nonce we
                        // just minted. Lose this and every signed
                        // General fails verify with a brand-new nonce.
                        self.persist_to_ws_attachment();
                        console_log!(
                            "EngineIoSession: BRC-103 handshake complete for identity={identity_key}; deferring `authenticated` follow-up until client's first General"
                        );
                    }
                }
            }
            AuthOutcome::AuthenticatedGeneral { payload } => {
                // Post-auth General arrived from the client. Decode the
                // wrapped authsocket event (`{eventName, data}`) and
                // route it through the Phase C bridge so the unmodified
                // `@bsv/authsocket-client` can drive joinRoom /
                // leaveRoom / sendMessage exactly the same way it would
                // a TS server. Before any Phase C routing happens, if
                // this is the FIRST post-auth General we've seen, emit
                // the deferred `authenticated` follow-up so the client's
                // `serverIdentityKey` lands. The order matters: Phase B
                // contract is that the `authenticated` event arrives
                // before any other server→client event.
                let (name, data) = auth::decode_event_payload(&payload);
                console_log!(
                    "EngineIoSession: post-auth event '{name}' received from client (verified)"
                );

                // -- 1. (One-time) deferred `authenticated` follow-up --
                let (need_auth_emit, snap_state) = {
                    let mut guard = self.inner.borrow_mut();
                    let s = match guard.as_mut() {
                        Some(s) => s,
                        None => return,
                    };
                    if s.authenticated_emitted {
                        (false, Some(s.auth.clone()))
                    } else {
                        s.authenticated_emitted = true;
                        (true, Some(s.auth.clone()))
                    }
                };
                // Persist the once-only `authenticated_emitted` flag so
                // a wake during this code path doesn't cause us to
                // re-emit the deferred `authenticated` General on the
                // client's NEXT General (which would land out of order
                // and either confuse the upstream MessageBoxClient or
                // duplicate its `authenticationSuccess` handler).
                if need_auth_emit {
                    self.persist_to_ws_attachment();
                }
                let snap_state = match snap_state {
                    Some(s) if s.is_authenticated() => s,
                    _ => return,
                };
                let identity_key = snap_state
                    .verified_identity_key()
                    .map(String::from)
                    .unwrap_or_default();

                // M10 #61 Phase D follow-up — short-circuit the
                // auth-handshake event off the MessageHub critical path.
                //
                // The client's `authenticated` post-auth General is on
                // the 5-second auth handshake timeout (see
                // MessageBoxClient.ts line 433-439: `authenticationSuccess`
                // must arrive within 5s of `authenticated` being emitted,
                // or the client throws). The previous flow forwarded
                // `authenticated` to MessageHub (a separate per-identity
                // DO that for fresh identities does not yet exist) and
                // waited for the round-trip, then emitted
                // `authenticationSuccess`. When MessageHub is cold
                // (first touch of this identity's DO) the wake routinely
                // exceeded the 5s budget on prod, manifesting as flaky
                // "WebSocket authentication timed out!" on whichever
                // identity wasn't pre-warmed by an earlier HTTP send to
                // its own MessageHub (most often Bob, who sends-only).
                //
                // MessageHub::dispatch_socketio_event's handler for
                // "authenticated" is trivial — see
                // src/message_hub.rs:1000-1006, it just returns
                // `{eventName:"authenticationSuccess",
                // data:{"status":"success"}}`. Emit that directly here,
                // skipping the cross-DO round-trip entirely.
                //
                // The previously-deferred `authenticated` follow-up
                // General (which existed to populate `serverIdentityKey`
                // on the @bsv/authsocket-client) is also collapsed into
                // the `authenticationSuccess` General — both are signed
                // BRC-103 Generals, and authsocket-client sets
                // `serverIdentityKey = senderKey` on every General it
                // receives (AuthSocketClient.ts:43). One General
                // suffices.
                //
                // `register_with_message_hub` still runs (broadcast
                // fan-out needs the subscriber entry) but is no longer
                // on the latency budget the client measures.
                if name == "authenticated" {
                    let ack = OutboundSocketIoEvent {
                        event_name: "authenticationSuccess".to_string(),
                        data: json!({ "status": "success" }),
                    };
                    self.emit_signed_general(&ack, &snap_state, &wallet, nsp, ws_for_response);
                    console_log!(
                        "TRACE_PHD auth.fastpath_emitted identity={} sid={}",
                        identity_key,
                        self.inner
                            .borrow()
                            .as_ref()
                            .map(|s| s.sid.clone())
                            .unwrap_or_default()
                    );
                    // Intentionally NOT calling register_with_message_hub
                    // here. Awaiting it blocks this WS handler — when
                    // Bob's MessageHub DO is cold (first touch for this
                    // identity), wake latency can exceed 30s and queues
                    // up bob's subsequent joinRoom / sendMessage frames
                    // behind the await, blowing the test's 30s per-step
                    // timeout. Registration is upserted lazily inside
                    // MessageHub::update_socketio_rooms on the next
                    // joinRoom (always emitted by MessageBoxClient before
                    // any sendLiveMessage / listenForLiveMessages), so
                    // skipping the explicit register call is safe.
                    return;
                }

                if need_auth_emit {
                    let payload_auth = encode_event_payload(
                        "authenticated",
                        &json!({"identityKey": identity_key}),
                    );
                    match build_outbound_general(payload_auth, &snap_state, &wallet) {
                        Ok(general) => {
                            self.emit_auth_message(&general, nsp, ws_for_response);
                            console_log!(
                                "EngineIoSession: emitted deferred `authenticated` follow-up for identity={identity_key}"
                            );
                        }
                        Err(e) => {
                            console_error!("EngineIoSession: build_outbound_general failed: {e}");
                        }
                    }

                    // First successful auth — register this sid with
                    // the per-identity MessageHub so we receive
                    // broadcast pushes (HTTP→socket.io fan-out).
                    self.register_with_message_hub(&identity_key).await;
                }

                // -- 2. Phase C event routing -- (joinRoom / leaveRoom /
                // sendMessage / etc.; the `authenticated` fast-path above
                // returned early.)
                let sid = self
                    .inner
                    .borrow()
                    .as_ref()
                    .map(|s| s.sid.clone())
                    .unwrap_or_default();
                let outbound = self
                    .forward_event_to_message_hub(&identity_key, &sid, &name, &data)
                    .await;
                for ev in outbound {
                    self.emit_signed_general(&ev, &snap_state, &wallet, nsp, ws_for_response);
                }
            }
            AuthOutcome::Quiet => {}
            AuthOutcome::Error(e) => {
                console_log!("EngineIoSession: auth error: {e}");
            }
        }
    }

    /// Wrap an AuthMessage JSON value as a Socket.IO EVENT and ship it
    /// over the active transport (or enqueue for the next polling
    /// drain). Always emitted on the default namespace — namespaces
    /// other than `/` are not supported.
    fn emit_auth_message(&self, value: &Value, nsp: &str, ws_for_response: Option<&WebSocket>) {
        let evt = SocketIoPacket::Event {
            nsp: nsp.to_string(),
            ack_id: None,
            data: vec![Value::String("authMessage".into()), value.clone()],
        };
        self.send_or_enqueue(EngineIoPacket::Message(evt.encode()), ws_for_response);
    }

    /// Encode `ev` (one outbound socket.io event from MessageHub) as a
    /// signed BRC-103 General, wrap as the `authMessage` Socket.IO
    /// event, and ship over the active transport. Mirrors the Phase B
    /// `authenticated` follow-up emit path but for arbitrary post-auth
    /// events (Phase C bridge output).
    fn emit_signed_general(
        &self,
        ev: &OutboundSocketIoEvent,
        state: &SessionAuthState,
        wallet: &bsv_rs::wallet::ProtoWallet,
        nsp: &str,
        ws_for_response: Option<&WebSocket>,
    ) {
        // Transform event name to match TS authsocket / message-box-server
        // convention: `sendMessage` and `sendMessageAck` events get the
        // roomId suffixed onto the event name itself
        // (e.g. `sendMessage-<roomId>`), not just included in the payload.
        // This matches `~/bsv/message-box-server/src/index.ts:208,275` and
        // is what `MessageBoxClient.listenForLiveMessages` subscribes to
        // (`socket.on(\`sendMessage-${roomId}\`)` at MessageBoxClient.ts).
        // Raw WS keeps the flat name + data.roomId form (M9 #43 spec).
        let event_name = authsocket_event_name(&ev.event_name, &ev.data);
        let payload = encode_event_payload(&event_name, &ev.data);
        match build_outbound_general(payload, state, wallet) {
            Ok(general) => self.emit_auth_message(&general, nsp, ws_for_response),
            Err(e) => {
                console_error!(
                    "EngineIoSession: emit_signed_general for '{}' failed: {e}",
                    ev.event_name
                );
            }
        }
    }

    /// Forward a post-auth event from this socket.io session to the
    /// per-identity MessageHub for processing. Returns the list of
    /// outbound events MessageHub wants us to ship back to the client.
    /// On any failure (DO unreachable, JSON parse error, etc.) returns
    /// an empty list and logs — the bridge MUST stay best-effort so a
    /// single failure doesn't take down the channel.
    async fn forward_event_to_message_hub(
        &self,
        identity_key: &str,
        sid: &str,
        event_name: &str,
        data: &Value,
    ) -> Vec<OutboundSocketIoEvent> {
        let namespace = match self.env.durable_object("MESSAGE_HUB") {
            Ok(n) => n,
            Err(e) => {
                console_error!("EngineIoSession: MESSAGE_HUB binding: {e}");
                return Vec::new();
            }
        };
        let stub = match namespace
            .id_from_name(identity_key)
            .and_then(|id| id.get_stub())
        {
            Ok(s) => s,
            Err(e) => {
                console_error!(
                    "EngineIoSession: MESSAGE_HUB stub for identity={identity_key}: {e}"
                );
                return Vec::new();
            }
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
        let req = match Request::new_with_init("https://do.local/internal/socketio-event", &init) {
            Ok(r) => r,
            Err(e) => {
                console_error!("EngineIoSession: request build failed: {e}");
                return Vec::new();
            }
        };

        let mut resp = match stub.fetch_with_request(req).await {
            Ok(r) => r,
            Err(e) => {
                console_log!("EngineIoSession: socketio-event fetch failed: {e}");
                return Vec::new();
            }
        };
        let body: HubEventResponse = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                console_log!("EngineIoSession: socketio-event response JSON: {e}");
                return Vec::new();
            }
        };
        body.outbound
    }

    /// Register this sid with the per-identity MessageHub so that any
    /// future HTTP→socket.io broadcast (originating from another
    /// identity's `POST /sendMessage`, or this identity's own write
    /// via either transport) is fanned out to this session. Idempotent
    /// — calling it multiple times for the same sid just refreshes the
    /// `registered_at_ms` timestamp.
    async fn register_with_message_hub(&self, identity_key: &str) {
        let sid = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| s.sid.clone())
            .unwrap_or_default();
        if sid.is_empty() || identity_key.is_empty() {
            return;
        }
        self.post_registration(identity_key, &sid, /*register=*/ true)
            .await;
    }

    /// Inverse of `register_with_message_hub` — called on close /
    /// disconnect. Drops the entry so the hub stops fanning out to a
    /// torn-down session. Best-effort.
    async fn unregister_with_message_hub(&self) {
        let snapshot = {
            let guard = self.inner.borrow();
            let s = match guard.as_ref() {
                Some(s) => s,
                None => return,
            };
            let identity_key = s
                .auth
                .verified_identity_key()
                .map(String::from)
                .unwrap_or_default();
            (identity_key, s.sid.clone())
        };
        let (identity_key, sid) = snapshot;
        if identity_key.is_empty() || sid.is_empty() {
            return;
        }
        self.post_registration(&identity_key, &sid, /*register=*/ false)
            .await;
    }

    /// Helper: POST to MessageHub `/internal/socketio-(un)register`.
    async fn post_registration(&self, identity_key: &str, sid: &str, register: bool) {
        let namespace = match self.env.durable_object("MESSAGE_HUB") {
            Ok(n) => n,
            Err(e) => {
                console_log!("EngineIoSession: registration: MESSAGE_HUB binding: {e}");
                return;
            }
        };
        let stub = match namespace
            .id_from_name(identity_key)
            .and_then(|id| id.get_stub())
        {
            Ok(s) => s,
            Err(e) => {
                console_log!("EngineIoSession: registration: stub for {identity_key} failed: {e}");
                return;
            }
        };

        let endpoint = if register {
            "https://do.local/internal/socketio-register"
        } else {
            "https://do.local/internal/socketio-unregister"
        };
        let payload = json!({ "sid": sid }).to_string();
        let headers = Headers::new();
        if headers.set("content-type", "application/json").is_err() {
            return;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.into()));
        let req = match Request::new_with_init(endpoint, &init) {
            Ok(r) => r,
            Err(e) => {
                console_log!("EngineIoSession: registration request build failed: {e}");
                return;
            }
        };
        if let Err(e) = stub.fetch_with_request(req).await {
            console_log!(
                "EngineIoSession: registration ({}) fetch failed: {e}",
                if register { "register" } else { "unregister" }
            );
        }
    }

    /// `/internal/socketio-broadcast` — receive a broadcast push from
    /// the per-identity MessageHub and emit it to this session as a
    /// signed `sendMessage` General. The session must be authenticated
    /// (otherwise we can't sign); if not, drop the broadcast and
    /// return 200 so the hub doesn't keep retrying.
    async fn handle_socketio_broadcast(&self, req: &mut Request) -> Result<Response> {
        let t_in = Date::now().as_millis();
        let body: BroadcastBody = match req.json().await {
            Ok(b) => b,
            Err(e) => {
                console_log!("EngineIoSession: broadcast bad JSON: {e}");
                return Response::error(format!("invalid broadcast body: {e}"), 400);
            }
        };
        let sid_for_log = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| s.sid.clone())
            .unwrap_or_else(|| "<empty>".into());
        let transport_for_log = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| match s.transport {
                Transport::Polling => "polling",
                Transport::WebSocket => "websocket",
                Transport::UpgradePending => "upgrade_pending",
            })
            .unwrap_or("none");
        let ws_count = self.state.get_websockets().len();
        console_log!(
            "TRACE_PHD broadcast.engineio.in sid={} room={} msgId={} t={} transport={} ws_attached={}",
            sid_for_log,
            body.room_id,
            body.message_id,
            t_in,
            transport_for_log,
            ws_count
        );

        // Rehydrate from any hibernated WebSocket attachment so we can
        // see the verified `auth` state. Without this, a broadcast that
        // arrives after a hibernation wake (very common — broadcasts are
        // bursty and DOs evict aggressively when idle) would fall into
        // the "no session" branch below and silently drop. The
        // auth-protected fan-out from MessageHub depends on us being
        // able to sign the General; that requires the persisted
        // `SessionAuthState::Authenticated`.
        let was_none_pre_rehydrate = self.inner.borrow().is_none();
        if was_none_pre_rehydrate {
            self.rehydrate_from_ws_attachment();
        }
        let post_rehydrate_transport = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| match s.transport {
                Transport::Polling => "polling",
                Transport::WebSocket => "websocket",
                Transport::UpgradePending => "upgrade_pending",
            })
            .unwrap_or("none");
        let post_rehydrate_sid = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| s.sid.clone())
            .unwrap_or_else(|| "<empty>".into());
        console_log!(
            "TRACE_PHD broadcast.engineio.rehydrated sid={} msgId={} rehydrated={} transport={}",
            post_rehydrate_sid,
            body.message_id,
            was_none_pre_rehydrate,
            post_rehydrate_transport
        );

        // Snapshot auth state for signing. We never hold the borrow
        // across the wallet construction below (which is sync, but the
        // discipline matches the rest of this file).
        let snap_state = {
            let guard = self.inner.borrow();
            let s = match guard.as_ref() {
                Some(s) => s,
                None => {
                    return Response::from_json(&json!({ "delivered": 0, "reason": "no session" }));
                }
            };
            s.auth.clone()
        };
        if !snap_state.is_authenticated() {
            return Response::from_json(&json!({ "delivered": 0, "reason": "unauthenticated" }));
        }

        let server_key = match self.env.secret("SERVER_PRIVATE_KEY") {
            Ok(s) => s.to_string(),
            Err(e) => {
                console_error!("EngineIoSession: broadcast: SERVER_PRIVATE_KEY: {e}");
                return Response::from_json(&json!({ "delivered": 0, "reason": "server key" }));
            }
        };
        let wallet = match make_wallet(&server_key) {
            Ok(w) => w,
            Err(e) => {
                console_error!("EngineIoSession: broadcast: make_wallet: {e}");
                return Response::from_json(&json!({ "delivered": 0, "reason": "wallet" }));
            }
        };

        let ev = OutboundSocketIoEvent {
            event_name: "sendMessage".to_string(),
            data: json!({
                "roomId": body.room_id,
                "sender": body.sender,
                "messageId": body.message_id,
                "body": body.body,
            }),
        };
        self.emit_signed_general(&ev, &snap_state, &wallet, "/", None);
        let t_done = Date::now().as_millis();
        console_log!(
            "TRACE_PHD broadcast.engineio.out sid={} msgId={} t={} dt_ms={}",
            sid_for_log,
            body.message_id,
            t_done,
            t_done.saturating_sub(t_in)
        );
        Response::from_json(&json!({ "delivered": 1 }))
    }

    /// Send `pkt` either directly over `ws` (preferred when present)
    /// or enqueue for the next polling drain. When `ws` is None AND
    /// the session has fully upgraded to `Transport::WebSocket`, fall
    /// back to the hibernated WS so external (non-request-scoped)
    /// emits — i.e. `/internal/socketio-broadcast` — land in real time.
    ///
    /// **Why we exclude `Transport::UpgradePending` from the WS-fallback**
    /// (M10 #61 Bug 1): during the upgrade phase the client has
    /// accepted the new WS but is still polling for socket.io packets
    /// (CONNECT ack, EVENTs). Until the client sends `5` (which flips
    /// us to `Transport::WebSocket`), socket.io-client's WS transport
    /// is in "probing" mode and will discard any non-`3probe` frame.
    /// Sending the polling-POST response over the half-upgraded WS
    /// strands it on a transport the client isn't reading — which is
    /// the precise failure mode behind the dual-`MessageBoxClient`
    /// race when the second client's CONNECT lands after its WS
    /// upgrade has been accepted.
    fn send_or_enqueue(&self, pkt: EngineIoPacket, ws: Option<&WebSocket>) {
        let encoded = pkt.encode();
        if let Some(socket) = ws {
            if let Err(e) = socket.send_with_str(&encoded) {
                console_log!("EngineIoSession: ws send failed ({e}) — enqueueing");
                if let Some(state) = self.inner.borrow_mut().as_mut() {
                    state.enqueue(pkt);
                }
            }
            return;
        }
        let on_websocket = self
            .inner
            .borrow()
            .as_ref()
            .map(|s| matches!(s.transport, Transport::WebSocket))
            .unwrap_or(false);
        if on_websocket {
            let sockets = self.state.get_websockets();
            if !sockets.is_empty() {
                let mut sent_any = false;
                for socket in sockets {
                    if socket.send_with_str(&encoded).is_ok() {
                        sent_any = true;
                    }
                }
                if sent_any {
                    return;
                }
                console_log!(
                    "EngineIoSession: send_or_enqueue: WS transport but every send failed — falling back to polling queue"
                );
            }
        }
        if let Some(state) = self.inner.borrow_mut().as_mut() {
            state.enqueue(pkt);
        }
    }

    fn is_connected(&self) -> bool {
        // M10 #61 Bug 1 (hibernation race): some clients (notably
        // socket.io-client 4 in WS-only mode behind authsocket-client +
        // MessageBoxClient) have an order-of-operations where a wake
        // can arrive with `connected=false` in the rehydrated attachment
        // even after BRC-103 has fully completed earlier in the session
        // lifetime. Mathematically impossible to be authenticated without
        // having CONNECTed first (BRC-103 messages ride on Socket.IO
        // EVENT packets which are gated by this same check upstream),
        // so accept either flag. Defensive but provably safe: a malicious
        // unauthenticated client can never set `auth.is_authenticated()`
        // to true.
        self.inner
            .borrow()
            .as_ref()
            .map(|s| s.connected || s.auth.is_authenticated())
            .unwrap_or(false)
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Build the Engine.IO `0` open handshake packet for a fresh sid.
pub fn open_handshake_packet(sid: &str) -> EngineIoPacket {
    let payload = json!({
        "sid": sid,
        "upgrades": ["websocket"],
        "pingInterval": PING_INTERVAL_MS,
        "pingTimeout": PING_TIMEOUT_MS,
        "maxPayload": MAX_PAYLOAD,
    });
    EngineIoPacket::Open(payload.to_string())
}

/// Build a `text/plain` HTTP response with the given body and status.
/// CORS allow-origin is set to `*` because the polling transport is
/// Apply the TS authsocket convention: `sendMessage` and `sendMessageAck`
/// events get `-${roomId}` suffixed onto the event name itself (per
/// `~/bsv/message-box-server/src/index.ts:208,275`). MessageBoxClient
/// subscribes to `sendMessage-${roomId}` as the literal socket.io event
/// name. Without this transform, the broadcast emit is
/// `sendMessage` (flat) and MessageBoxClient's `socket.on` never fires.
///
/// Raw WS clients keep the flat name + data.roomId convention from the
/// M9 #43 spec — that path doesn't go through this function.
fn authsocket_event_name(name: &str, data: &Value) -> String {
    if matches!(name, "sendMessage" | "sendMessageAck") {
        if let Some(room_id) = data.get("roomId").and_then(|v| v.as_str()) {
            return format!("{name}-{room_id}");
        }
    }
    name.to_string()
}

/// commonly hit cross-origin by browsers; the rest of the app sets
/// CORS via its own helper but the DO doesn't have access to that.
fn polling_text_response(body: &str, status: u16) -> Result<Response> {
    public_polling_text_response(body, status)
}

/// Worker-callable variant of `polling_text_response`. Same body shape +
/// headers; exposed so `lib.rs::route_socketio_request` can serve the
/// Engine.IO `0{...}` handshake response directly without round-tripping
/// to the `EngineIoSession` DO (M11 Phase 1).
pub fn public_polling_text_response(body: &str, status: u16) -> Result<Response> {
    let headers = Headers::new();
    headers.set("content-type", "text/plain; charset=UTF-8")?;
    headers.set("access-control-allow-origin", "*")?;
    headers.set("access-control-allow-credentials", "true")?;
    Ok(Response::ok(body)?
        .with_status(status)
        .with_headers(headers))
}

/// Generate a fresh Engine.IO session id. The reference server uses
/// 20 characters of base64-url; we use a uuid v4 hex (32 chars) for
/// simplicity. Clients only require stability + uniqueness.
pub fn make_session_id() -> String {
    let id = uuid::Uuid::new_v4();
    // base64url-encode the raw bytes for a compact ~22-char id that
    // matches the visual style of socket.io's reference sids.
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_handshake_packet_carries_required_fields() {
        let p = open_handshake_packet("abc");
        let s = p.encode();
        assert!(s.starts_with('0'));
        // Verify all required handshake fields are present and parse.
        let json_str = &s[1..];
        let v: Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(v["sid"], "abc");
        assert_eq!(v["pingInterval"], PING_INTERVAL_MS);
        assert_eq!(v["pingTimeout"], PING_TIMEOUT_MS);
        assert_eq!(v["maxPayload"], MAX_PAYLOAD);
        assert!(v["upgrades"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "websocket"));
    }

    #[test]
    fn make_session_id_is_unique_and_url_safe() {
        let a = make_session_id();
        let b = make_session_id();
        assert_ne!(a, b);
        // base64url alphabet: A-Z, a-z, 0-9, '-', '_'.
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!a.is_empty());
    }
}
