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

/// DO-storage key prefix for the room→peer map (#40 peer-left
/// notification). `peer_by_room:<my_room_id>` → the identity key of the
/// LAST counterparty that pushed a message INTO that room (learned from
/// `/internal/push` — the only path an outside identity's traffic reaches
/// this per-identity hub). When the owner's last live session leaves a
/// room, this is who gets the cross-DO `peerLeft`. Presence-only:
/// nothing here ever gates message delivery or auth.
const PEER_BY_ROOM_PREFIX: &str = "peer_by_room:";
/// DO-storage key prefix for a departure nobody was there to receive
/// (bsv-low 2026-09-05): delivered on the identity's next register / room join.
const PARKED_LEFT_PREFIX: &str = "parkedleft:";
/// A parked departure older than this is not news any more (the felt's own
/// ladder has long since decided) — dropped on delivery.
pub(crate) const PARKED_PEER_LEFT_TTL_MS: u64 = 3 * 60 * 1000;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParkedPeerLeft {
    leaver: String,
    at_ms: u64,
}
/// 0.3.16 (bsv-low 2026-09-05, `dealtLeaveNotifyRejoin`): the ARRIVAL mirror of
/// the parked departure. The stayer's socket died on a heartbeat timeout in the
/// very seconds its opponent rejoined — `peerJoined` was pushed to a dying
/// socket, nobody received it, and the told-state still flipped to Present, so
/// every later arrival push was deduped away. A `peerJoined` that reached NO
/// session is parked under `parkedjoined:<room>` and delivered on this
/// identity's next register / room join, exactly like a parked departure.
const PARKED_JOINED_PREFIX: &str = "parkedjoined:";
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParkedPeerJoined {
    joiner: String,
    at_ms: u64,
}
/// PURE: is a parked presence event (departure or arrival) still worth delivering?
pub(crate) fn parked_peer_left_is_fresh(parked_at_ms: u64, now_ms: u64) -> bool {
    now_ms.saturating_sub(parked_at_ms) <= PARKED_PEER_LEFT_TTL_MS
}
/// Which parked presence event a (re)joining session is owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkedChoice {
    Nothing,
    Left,
    Joined,
}
/// PURE (0.3.16): decide between a parked departure and a parked arrival for one
/// room. The TOLD-STATE is the truth about the peer's LAST observed presence:
/// told=Present drops a parked departure (0.3.15's rule — the peer came back),
/// told=Absent drops a parked arrival (the peer left again; that departure has
/// its own path). A stale event (past the TTL) is never news. When both still
/// stand (no told-state at all), the NEWER one is delivered.
pub(crate) fn parked_presence_choice(
    left_at_ms: Option<u64>,
    joined_at_ms: Option<u64>,
    told: Option<ToldPresence>,
    now_ms: u64,
) -> ParkedChoice {
    let left = left_at_ms
        .filter(|at| parked_peer_left_is_fresh(*at, now_ms))
        .filter(|_| !matches!(told, Some(ToldPresence::Present)));
    let joined = joined_at_ms
        .filter(|at| parked_peer_left_is_fresh(*at, now_ms))
        .filter(|_| !matches!(told, Some(ToldPresence::Absent)));
    match (left, joined) {
        (None, None) => ParkedChoice::Nothing,
        (Some(_), None) => ParkedChoice::Left,
        (None, Some(_)) => ParkedChoice::Joined,
        (Some(l), Some(j)) => {
            if j >= l {
                ParkedChoice::Joined
            } else {
                ParkedChoice::Left
            }
        }
    }
}

/// PURE: should a departure from `room` arm the peer-left machinery? A LOBBY
/// room (`<host>-low_lobby_<gid>`) signals a departure ONLY on a socket CLOSE
/// (a crash — the class-L "quiet lobby learns of a dead host" case). A CLEAN
/// leaveRoom of a lobby room is a match or a cancel: the advert lifecycle
/// (overlay `lobby` event) owns it, and fanning a `host-left` there would be a
/// FALSE "host away" on every normal match — the full18 run 2 P6 over-fan-out.
/// A GAME room always signals (a deliberate leave should tell the peer; the
/// crash-into-empty case is handled by the parked-departure delivery).
pub(crate) fn departure_signals(room: &str, via_close: bool) -> bool {
    // 0.3.15 (bsv-low full18 validation, 2026-09-05): a DEPARTURE IS A SOCKET
    // CLOSE — for EVERY room. A client-initiated `leaveRoom` on a game room is
    // a room HOP (the felt's inbound watchdog leaves + re-joins to recover a
    // dropped envelope); under load the re-join took longer than the 4 s
    // debounce, the occupancy re-check found the room empty, and the peer was
    // told "opponent lost connection" about a seat that never left. Every real
    // departure closes the socket (tab close, crash, heartbeat timeout — the
    // #225/W6 teardown) or is an explicit app-level GOODBYE message, so a room
    // hop never needs to signal. `room` stays in the signature for the pin.
    let _ = room;
    via_close
}

/// DO-storage key prefix for a room's last-seen heartbeat
/// (`lastseen:<room>` → `u64` epoch-millis of the most recent
/// high-signal touch: a send into the room, or a join). ADVISORY ONLY —
/// `present` (a live socket joined right now) stays the primary presence
/// signal; a stale or absent `lastSeenMs` must NEVER latch "left" or a
/// false status. Best-effort like `peer_by_room:`: write failures are
/// swallowed, and the key is simply OMITTED from `/presence` when unset
/// (never emitted as 0/null). Never gates delivery, auth, or money.
const LAST_SEEN_PREFIX: &str = "lastseen:";

/// DO-storage key prefix for the tier-2 rejoin-window signal
/// (`rejoindeadline:<room>` → `u64` epoch-millis). Written by the STAYING
/// player (via `POST /rejoin-deadline`, routed here) once it decides its
/// peer left and starts its grace ladder; read back by a crashed/reloaded
/// rejoiner's `GET /presence` so both sides share ONE synchronized
/// countdown. ADVISORY / UX-ONLY, same fail-quiet discipline as
/// `lastseen:`: the value is stored verbatim and simply OMITTED from
/// `/presence` when absent — the CLIENT decides past-vs-future. It NEVER
/// gates delivery, auth, or money (money-safety rides on the tower case +
/// the pre-signed nLockTime refund); a wrong value can only make a rejoiner
/// hurry or give up (still refunded), or be overridden by the tower
/// deadline. A new key — no migration needed.
const REJOIN_DEADLINE_PREFIX: &str = "rejoindeadline:";

/// DO-storage key prefix for a pending (debounced) peer-left notification
/// (`pendingleft:<room>` → [`PendingPeerLeft`]). Written when the owner's
/// LAST live session departs a room; consumed by the DO alarm ~4s later,
/// which re-checks occupancy and pushes `/internal/peer-left` ONLY if the
/// room is still empty. Exists because the LOW client's inbound watchdog
/// self-heals via leaveRoom+rejoin with a ~1-2s gap — an immediate push
/// turned that flap into a false "opponent lost connection" during a
/// funded hand (bsv-low run bundle prod-dist-2026-07-24_04-06-50). One
/// entry per room (trailing edge: a re-departure overwrites it), so a
/// flap during the window collapses to a single trailing check.
const PENDING_LEFT_PREFIX: &str = "pendingleft:";
/// `presence_told:<room>` — what this hub LAST TOLD ITS OWNER about the
/// room's counterparty (`present` / `absent`). The arrival/departure events
/// (`peerJoined` / `peerLeft`) and the join-time snapshot all flow through
/// `told_transition`, so the owner hears a change exactly once — a second
/// tab joining, a flap the debounce absorbed, or a duplicate cross-DO push
/// emits nothing. Storage, not attachment: it is per ROOM, not per socket.
const PRESENCE_TOLD_PREFIX: &str = "presence_told:";

/// Trailing debounce window for the peer-left push. Must comfortably
/// exceed the watchdog's self-heal gap (~1-2s) while adding only a small
/// worst-case delay to REAL departure detection. The client's presence
/// freshness discriminator rides `lastseen:` (stamped IMMEDIATELY at
/// departure, #225) and is unaffected by this delay.
const PEER_LEFT_DEBOUNCE_MS: u64 = 4_000;

/// The identity-key prefix of an owner-prefixed room id
/// (`<66-hex-identity>-<suffix>`), or `None` when the shape doesn't
/// match. Mirrors `validate_room_owned`'s ownership model without
/// needing the identity in hand.
fn room_identity(room_id: &str) -> Option<&str> {
    let (id, _) = room_id.split_once('-')?;
    (id.len() == 66 && id.chars().all(|c| c.is_ascii_hexdigit())).then_some(id)
}

/// The box suffix of an owner-prefixed room id (everything after the
/// `<identity>-` prefix), or `None` when the shape doesn't match.
fn room_suffix(room_id: &str) -> Option<&str> {
    let (id, suffix) = room_id.split_once('-')?;
    (id.len() == 66 && id.chars().all(|c| c.is_ascii_hexdigit()) && !suffix.is_empty())
        .then_some(suffix)
}

/// The PEER's equivalent room for one of OUR rooms: same box suffix,
/// their identity prefix. `<peer>-<suffix of my_room>`.
fn peer_room(peer_identity: &str, my_room: &str) -> Option<String> {
    Some(format!("{peer_identity}-{}", room_suffix(my_room)?))
}

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
    /// Once-per-instance guard for the pendingleft re-arm recovery scan
    /// (`rearm_pending_departures_once`). `Cell` is fine: a DO instance
    /// is single-threaded. NOT persisted — a fresh isolate re-runs the
    /// scan, which is exactly the point.
    rearm_scan_done: std::cell::Cell<bool>,
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

        Self {
            state,
            env,
            rearm_scan_done: std::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        // Presence-flap debounce recovery net: on the first request of
        // this instance's life, re-arm the alarm for any stored
        // `pendingleft:` entries (see `rearm_pending_departures_once`).
        // DO alarms are durable, so this only matters after a failure
        // path stranded an entry — cheap (one prefix list, usually
        // empty) and guarded to once per isolate, the same
        // once-per-isolate init discipline used elsewhere in this stack.
        self.rearm_pending_departures_once().await;
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
        // #40 peer presence (same worker-internal trust model as the routes
        // above — the public internet never reaches a DO stub directly):
        //   * /internal/peer-left — the counterparty's hub says they left;
        //     fan `peerLeft` out to this owner's live sessions.
        //   * /internal/presence  — polling fallback: is the owner seated
        //     in ?room right now (routed here by lib.rs /presence).
        if req.method() == Method::Post && path == "/internal/peer-left" {
            return self.handle_peer_left(&mut req).await;
        }
        if req.method() == Method::Post && path == "/internal/peer-joined" {
            return self.handle_peer_joined(&mut req).await;
        }
        if req.method() == Method::Get && path == "/internal/presence" {
            return self.handle_presence(&req).await;
        }
        // Tier-2 rejoin-window WRITE (routed here by lib.rs
        // /rejoin-deadline): the stayer publishes the deadline it will honor
        // for this room. Best-effort store; UX-only, never a gate.
        if req.method() == Method::Post && path == "/internal/rejoin-deadline" {
            return self.handle_set_rejoin_deadline(&mut req).await;
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
        // #40: a closed socket (tab close / crash / network drop) departs
        // every room it had joined — if any was the identity's last seat,
        // tell the peer. Best-effort: presence never fails the close path.
        self.teardown_departed_socket(&ws).await;
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: Error) -> Result<()> {
        console_log!("MessageHub: WS error: {}", error);
        // #225: an ABRUPT termination (network death, killed tab, TCP
        // reset) can surface here instead of — or as well as —
        // `websocket_close`. It is a departure all the same: run the
        // identical teardown so the peer still gets its `peerLeft` push
        // and `/presence` flips promptly. `teardown_departed_socket`'s
        // attachment latch makes the close+error double-fire emit at
        // most one notification. Best-effort mirror-close so the
        // runtime fully releases the socket; errors ignored (the socket
        // is usually already gone).
        self.teardown_departed_socket(&ws).await;
        let _ = ws.close(Some(1000), Some("error"));
        Ok(())
    }

    /// THE hub's alarm consumer. Today the ONLY alarm producer on this DO
    /// is the presence-flap departure debounce (`maybe_notify_peer_left`
    /// arms it via `ensure_alarm_no_later_than`); a future second alarm
    /// use MUST multiplex inside this handler — a DO has exactly one
    /// alarm slot, and a naive `set_alarm` elsewhere would silently
    /// cancel the debounce's trailing check (and vice versa).
    async fn alarm(&self) -> Result<Response> {
        self.run_departure_debounce_alarm().await;
        Response::empty()
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
    /// S3b — tell the BroadcastRegistry this identity subscribes to public
    /// rooms (fire-and-forget; a lost register only delays delivery until
    /// the next (re)join, and the client re-joins on every connect).
    async fn notify_broadcast_registry(&self, identity: &str) {
        crate::broadcast_registry::register_identity(&self.env, identity).await
    }

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

        // #40 peer presence: every push into one of this identity's rooms
        // names its counterparty (`sender` is the relay-verified identity of
        // whoever posted). Remember it so a later leave can tell the peer.
        // Read-compare-write: one storage read per push, a write only when
        // the peer changes (i.e. ~once per game).
        self.remember_room_peer(&body.room_id, &body.sender).await;
        // Advisory heartbeat: a push into this room is high-signal activity.
        self.stamp_last_seen(&body.room_id).await;

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
                if room_id.contains(BROADCAST_BOX_MARKER) {
                    self.notify_broadcast_registry(&attachment.identity_key).await;
                }
                if !attachment.joined_rooms.iter().any(|r| r == &room_id) {
                    attachment.joined_rooms.push(room_id.clone());
                    ws.serialize_attachment(&*attachment)?;
                }
                // Advisory heartbeat: a join is a high-signal room touch.
                self.stamp_last_seen(&room_id).await;
                emit_joined_room(ws, &room_id)?;
                // #410 (bsv-low, 2026-08-25) — the JOIN HELLO. LOW's client is
                // HTTP-first until a WS-DELIVERED frame proves the socket
                // (#400); under 16-pair fleet load a seat played a WHOLE HAND
                // http-first because no delivery ever arrived on its socket.
                // Emit one delivery-shaped frame to the JOINING socket the
                // moment it joins: it rides the exact `emit_send_message`
                // envelope real fan-outs use, so the message-box client's
                // `sendMessage-{roomId}` handler surfaces it, the LOW client
                // flips `wsProven` (any surfaced frame is proof of a live
                // duplex socket), and LOW's ingest quarantines the junk body
                // harmlessly. DIVERGENCE from the ts-stack reference (which
                // emits only `joinedRoom` on join): recorded as D4 in
                // bsv-low's register — the hello serves OUR client's
                // http-first design; reference clients ignore an unknown
                // plain-text message by contract (parse-tolerant handler).
                // Best-effort: a failed hello must not fail the join.
                if let Err(e) = emit_send_message(
                    ws,
                    &room_id,
                    "relay-hello",
                    "ws-hello",
                    &serde_json::json!("ws-hello"),
                ) {
                    console_log!("MessageHub: join hello emit failed (non-fatal): {}", e);
                }
                // P2 (bsv-low event-driven client, 2026-09-02): presence is an
                // EVENT, never a poll. The joining socket receives a `presence`
                // snapshot of the counterparty (asked ONCE, hub-to-hub, on this
                // join — a reconnect re-joins and therefore re-syncs by itself),
                // and the counterparty's hub is told we ARRIVED (`peerJoined`,
                // the mirror of `peerLeft`). Both best-effort; never fail the join.
                let snapshot = self.presence_snapshot(&room_id).await;
                if let Err(e) = emit(ws, "presence", &snapshot) {
                    console_log!("MessageHub: presence snapshot emit failed (non-fatal): {}", e);
                }
                self.push_peer_joined(&room_id, &attachment.identity_key).await;
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
                // #40: an explicit leave is a deliberate departure — if this
                // was the identity's last seat in the room, tell the peer.
                self.maybe_notify_peer_left(
                    &attachment.identity_key,
                    std::slice::from_ref(&room_id),
                    Some(ws),
                    None,
                    false, // an explicit leaveRoom is a CLEAN departure (match/cancel)
                )
                .await;
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
        // Advisory heartbeat: a send is the highest-signal room touch.
        self.stamp_last_seen(&room_id).await;
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
        // 1. Basic roomId validity.
        if room_id.trim().is_empty() {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": "Invalid room ID" }),
            )];
        }

        // 2. Validate the recipient identity up front (the room belongs to
        //    either it or the sender — see below).
        if !is_valid_pubkey(&message.recipient) {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": format!("Invalid recipient key: {}", message.recipient) }),
            )];
        }

        // 3. Derive the message_box from whichever room the client addressed:
        //    the RECIPIENT's room (`<recipient>-<box>` — the official
        //    `@bsv/message-box-client` + the canonical message-box-server,
        //    which ack + broadcast on the client-sent roomId) OR the sender's
        //    OWN room (`<sender>-<box>` — the legacy raw-WS convention).
        //    Crucially we ack on the SAME room_id below (`outcome_to_outbound`),
        //    so each client's ack listener matches its own convention; the
        //    message itself is always routed to `message.recipient`. Previously
        //    this accepted ONLY the sender's room, so the official client —
        //    which sends to and awaits `sendMessageAck-<recipient>-<box>` —
        //    never got its ack: every WS send burned the 10s ack timeout and
        //    fell back to HTTP, and the live push was lost (poll only). Read-
        //    side ownership (joinRoom / listMessages) is still enforced, so a
        //    sender can DEPOSIT into the recipient's box but never READ it.
        let recipient_prefix = format!("{}-", message.recipient);
        let sender_prefix = format!("{sender_key}-");
        let message_box = match room_id
            .strip_prefix(&recipient_prefix)
            .or_else(|| room_id.strip_prefix(&sender_prefix))
            .filter(|s| !s.is_empty())
        {
            Some(s) => s.to_string(),
            None => {
                return vec![OutboundEvent::new(
                    "messageFailed",
                    json!({ "reason": "Room ID must be the sender's or recipient's room (\"<id>-<box>\")" }),
                )];
            }
        };

        // 4. Remaining per-field validation. Mirrors the HTTP validator's
        // checks (validation::validate_send_message) — same error codes.
        if message.message_id.is_empty() {
            return vec![OutboundEvent::new(
                "messageFailed",
                json!({ "reason": "Each messageId must be a non-empty string." }),
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

        let t_send_start = worker::Date::now().as_millis();
        let outcome = process_send(validated, sender_key, &self.env, &store).await;
        // bsv-low#249 diagnostic: record the WS send outcome + duration. The
        // measured ~10.4s `relay.send fail` events are NOT this stage — they are
        // the CLIENT's `sendLiveMessage` waiting 10s for a `sendMessageAck` that
        // never comes because a DUPLICATE resolves to `messageFailed` here (see
        // outcome_to_outbound). This log proves the relay emits its WS response
        // fast; the wait is entirely client-side.
        worker::console_log!(
            "TRACE_LAT ws.send room={} outcome={} ms={}",
            room_id,
            match &outcome {
                SendOutcome::Success { .. } => "Success->sendMessageAck",
                SendOutcome::DuplicateMessage { .. } => "Duplicate->sendMessageAck(FIXED #249)",
                SendOutcome::ValidationError { .. } => "ValidationError->messageFailed",
                SendOutcome::BlockedRecipients { .. } => "Blocked->messageFailed",
                SendOutcome::PaymentFailed { .. } => "PaymentFailed->paymentFailed",
                SendOutcome::InternalError { .. } => "InternalError->messageFailed",
                SendOutcome::TransientError { .. } => "TransientError->messageFailed",
            },
            worker::Date::now().as_millis().saturating_sub(t_send_start)
        );
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
                if room_id.contains(BROADCAST_BOX_MARKER) {
                    self.notify_broadcast_registry(&identity_key).await;
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
                // Advisory heartbeat: a join is a high-signal room touch.
                self.stamp_last_seen(&room_id).await;
                // P2 (2026-09-02): the socket.io path gets what the raw path
                // gets — the join hello (#410; it was raw-WS only, so LOW's
                // socket.io seats never received it and played http-first
                // until the opponent's first envelope), the `presence`
                // snapshot, and the counterparty's `peerJoined`.
                let snapshot = self.presence_snapshot(&room_id).await;
                self.push_peer_joined(&room_id, &identity_key).await;
                vec![
                    OutboundEvent::new("joinedRoom", json!({ "roomId": room_id })),
                    OutboundEvent::new(
                        "sendMessage",
                        json!({
                            "roomId": room_id,
                            "sender": "relay-hello",
                            "messageId": "ws-hello",
                            "body": "ws-hello",
                        }),
                    ),
                    OutboundEvent::new("presence", snapshot),
                ]
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
                // #40: explicit leave over the socket.io bridge — if this was
                // the identity's last seat in the room, tell the peer. The
                // registry entry was just updated, so the occupancy scan
                // already excludes this membership; skip the sid anyway.
                self.maybe_notify_peer_left(
                    &identity_key,
                    std::slice::from_ref(&room_id),
                    None,
                    Some(&sid),
                    false, // an explicit leaveRoom is a CLEAN departure (match/cancel)
                )
                .await;
                vec![OutboundEvent::new("leftRoom", json!({ "roomId": room_id }))]
            }
            "sendMessage" => {
                // `sendMessage` data carries a `message` object (same shape as
                // the HTTP /sendMessage `message` field) plus an optional outer
                // `payment`. The room is taken from a top-level `roomId` when
                // present (official `@bsv/message-box-client` + canonical
                // message-box-server), else derived from the inline
                // `message.messageBox` (legacy). See the room_id resolution
                // below.
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
                // Honour a top-level `roomId` when present — that's what the
                // official `@bsv/message-box-client` sends (`{ roomId:
                // "<recipient>-<box>", message: {...} }`) and what the
                // canonical message-box-server reads. Fall back to the legacy
                // inline shape (`message.messageBox`, no roomId) by building
                // the sender's own room. `process_send_message` accepts either
                // the recipient's or the sender's room.
                let room_id = match obj.get("roomId").and_then(|v| v.as_str()) {
                    Some(r) if !r.trim().is_empty() => r.to_string(),
                    _ => {
                        let message_box = inner
                            .get("messageBox")
                            .and_then(|v| v.as_str())
                            .or_else(|| obj.get("messageBox").and_then(|v| v.as_str()))
                            .unwrap_or("");
                        if message_box.is_empty() {
                            return vec![OutboundEvent::new(
                                "messageFailed",
                                json!({ "reason": "sendMessage requires roomId or messageBox" }),
                            )];
                        }
                        format!("{identity_key}-{message_box}")
                    }
                };
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
        let rooms_now: Vec<String> = existing.as_ref().map(|e| e.joined_rooms.clone()).unwrap_or_default();
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
        if !rooms_now.is_empty() {
            self.deliver_parked_presence(&body.sid, &rooms_now).await;
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
        // broadcast-relevant operation (listenForLiveMessages joins the
        // receiver's own room to receive pushes; the sendMessage ack is a
        // direct socket emit, so it needs no room membership), lazy
        // auto-create here is the same
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
        let before: Vec<String> = entry.joined_rooms.clone();
        mutate(&mut entry.joined_rooms);
        let added: Vec<String> = entry.joined_rooms.iter().filter(|r| !before.contains(r)).cloned().collect();
        if let Err(e) = self.state.storage().put(&key, entry).await {
            console_log!(
                "MessageHub: update_socketio_rooms: storage put failed for sid={sid}: {e}"
            );
        }
        if !added.is_empty() {
            self.deliver_parked_presence(sid, &added).await;
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
        // #40: read the departing session's memberships BEFORE deleting the
        // entry — a socket.io disconnect (tab close / crash / transport
        // drop) is the LOW client's real leave signal. The leaver identity
        // is recovered from the room's owner prefix (every joined room on a
        // per-identity hub is owner-prefixed by construction).
        let departing: Option<SocketIoRegistryEntry> =
            self.state.storage().get(&key).await.ok().flatten();
        let _ = self.state.storage().delete(&key).await;
        if let Some(entry) = departing {
            if !entry.joined_rooms.is_empty() {
                if let Some(leaver) = room_identity(&entry.joined_rooms[0]).map(str::to_string) {
                    self.maybe_notify_peer_left(
                        &leaver,
                        &entry.joined_rooms,
                        None,
                        Some(&entry.sid),
                        true, // a socket.io disconnect (tab close / crash) — the class-L signal
                    )
                    .await;
                }
            }
        }
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

    // =======================================================================
    // #40 — opponent-left notification (peer presence)
    //
    // Model: hubs are per-identity, rooms are owner-prefixed, so the two
    // parties of a conversation NEVER share a hub. Each hub learns its
    // room's counterparty from inbound `/internal/push` traffic
    // (`remember_room_peer`), and when the owner's LAST live session
    // departs a room (explicit `leaveRoom`, raw-WS close, or socket.io
    // unregister) it arms a DEBOUNCED notify: `lastseen:` is stamped
    // immediately (#225), but the cross-DO POST to the peer's hub
    // `/internal/peer-left` — which fans a `peerLeft` event out to the
    // peer's sessions — fires from the DO alarm ~4s later, and only if
    // the room is STILL empty (a watchdog self-heal leave+rejoin flap
    // pushes nothing). Presence is UX-only: it never gates delivery,
    // auth, or storage.
    // =======================================================================

    /// Record `sender` as the counterparty of `room_id` (skip self-echo
    /// and malformed rooms; write only on change).
    async fn remember_room_peer(&self, room_id: &str, sender: &str) {
        // A room's owner pushing into its own room teaches nothing.
        if room_identity(room_id).is_none_or(|owner| owner == sender) {
            return;
        }
        if sender.len() != 66 || !sender.chars().all(|c| c.is_ascii_hexdigit()) {
            return;
        }
        let key = format!("{PEER_BY_ROOM_PREFIX}{room_id}");
        let existing: Option<String> = self.state.storage().get(&key).await.ok().flatten();
        if existing.as_deref() == Some(sender) {
            return;
        }
        if let Err(e) = self.state.storage().put(&key, sender.to_string()).await {
            console_log!("MessageHub: peer_by_room put failed for {room_id}: {e}");
        }
    }

    /// Best-effort last-seen heartbeat: stamp `lastseen:<room>` with the
    /// current epoch-millis on a high-signal room touch (send / join).
    /// ADVISORY presence only — same fail-quiet discipline as
    /// `remember_room_peer`: a write failure is logged and ignored, and
    /// never fails the caller's path. It only ever helps the peer render
    /// "last seen N ago"; it can never latch "left" or gate anything.
    async fn stamp_last_seen(&self, room: &str) {
        let key = format!("{LAST_SEEN_PREFIX}{room}");
        if let Err(e) = self.state.storage().put(&key, Date::now().as_millis()).await {
            console_log!("MessageHub: last_seen put failed for {room}: {e}");
        }
    }

    /// Best-effort tier-2 rejoin-deadline store: stamp
    /// `rejoindeadline:<room>` with the epoch-millis the STAYING player
    /// published. Same fail-quiet discipline as `stamp_last_seen` — a write
    /// failure is logged and swallowed, never fails the caller. The value is
    /// stored verbatim (the client decides past-vs-future on read); it can
    /// only ever help a rejoiner render a synchronized countdown and can
    /// never latch a status or gate anything.
    async fn stamp_rejoin_deadline(&self, room: &str, deadline_ms: u64) {
        let key = format!("{REJOIN_DEADLINE_PREFIX}{room}");
        if let Err(e) = self.state.storage().put(&key, deadline_ms).await {
            console_log!("MessageHub: rejoin_deadline put failed for {room}: {e}");
        }
    }

    /// Is any LIVE session of this hub's owner still joined to `room_id`,
    /// other than the departing one? Checks raw-WS attachments (skipping
    /// `departing_ws`) and socket.io registry entries (skipping
    /// `departing_sid`).
    async fn room_still_occupied(
        &self,
        room_id: &str,
        departing_ws: Option<&WebSocket>,
        departing_sid: Option<&str>,
    ) -> bool {
        for ws in self.state.get_websockets() {
            if departing_ws == Some(&ws) {
                continue;
            }
            if let Ok(Some(a)) = ws.deserialize_attachment::<SocketAttachment>() {
                if a.joined_rooms.iter().any(|r| r == room_id) {
                    return true;
                }
            }
        }
        for entry in self.list_socketio_subscribers().await {
            if departing_sid == Some(entry.sid.as_str()) {
                continue;
            }
            if entry.joined_rooms.iter().any(|r| r == room_id) {
                return true;
            }
        }
        false
    }

    /// Shared teardown for a raw-WS socket the runtime is done with —
    /// BOTH lifecycle ends land here: graceful close (`websocket_close`)
    /// and abrupt error (`websocket_error`, #225 — a dropped tab or dead
    /// network can surface as either, or both). Reads the departing
    /// socket's attachment, LATCHES it room-less (so whichever of
    /// close/error fires second finds nothing to do — at most one
    /// `peerLeft` per socket), then runs the #40 departure notify.
    /// Best-effort throughout: presence never fails a lifecycle handler.
    async fn teardown_departed_socket(&self, ws: &WebSocket) {
        let attachment: Option<SocketAttachment> = ws.deserialize_attachment().ok().flatten();
        let Some((latched, rooms, leaver)) = attachment.and_then(split_departure) else {
            return; // no attachment, no rooms, or already latched by the other handler
        };
        // Write the latch BEFORE the async notify. If the write fails
        // (socket already torn down) the worst case is a duplicate
        // peerLeft push — which the LOW client's verify-not-a-flap
        // presence check absorbs by design.
        let _ = ws.serialize_attachment(&latched);
        self.maybe_notify_peer_left(&leaver, &rooms, Some(ws), None, true) // a WS close — the class-L signal
            .await;
    }

    /// A session of `leaver` departed `rooms` (leaveRoom / close /
    /// unregister). For each room whose LAST session this was, arm the
    /// DEBOUNCED peer-left notify (see `PENDING_LEFT_PREFIX`): the push
    /// to the counterparty's hub happens ~4s later from the DO alarm,
    /// and ONLY if the room is still empty then — a watchdog self-heal
    /// flap (leaveRoom + rejoin within ~1-2s) therefore pushes nothing,
    /// on every client version. Best-effort end to end: presence must
    /// never fail the caller's path.
    ///
    /// NOTE: explicit app-level goodbyes are MESSAGES (they ride the
    /// `/internal/push` fan-out) and never pass through here — their
    /// immediacy is untouched by this debounce.
    async fn maybe_notify_peer_left(
        &self,
        leaver: &str,
        rooms: &[String],
        departing_ws: Option<&WebSocket>,
        departing_sid: Option<&str>,
        via_close: bool,
    ) {
        for room in rooms {
            // A CLEAN leave of a lobby room (matched / cancelled) fans nothing —
            // only a socket CLOSE (crash) signals a waiting host's departure.
            if !departure_signals(room, via_close) {
                continue;
            }
            // Final heartbeat (#225): the departing session was verifiably
            // here until NOW — stamp `lastseen:<room>` at departure time so
            // the peer's `/presence` carries an honest "was here until T"
            // even when the socket died without a single further touch.
            // Stamped for EVERY departed room (even multi-tab, where the
            // identity remains present) — a departure is still a true
            // "seen at T". Advisory-only, same fail-quiet discipline as
            // every other lastseen stamp. Stamped IMMEDIATELY — the
            // debounce below delays only the peerLeft PUSH, never this
            // stamp (the client's freshness discriminator rides it).
            self.stamp_last_seen(room).await;
            if self
                .room_still_occupied(room, departing_ws, departing_sid)
                .await
            {
                continue; // another tab/device of the same identity is still seated
            }
            // Presence-flap debounce: arm (or re-arm — trailing edge) the
            // single pending entry for this room and make sure the DO
            // alarm rings no later than its due time. The alarm handler
            // (`run_departure_debounce_alarm`) re-checks occupancy and
            // pushes at most once.
            let entry = arm_departure_debounce(leaver, Date::now().as_millis());
            let due_at_ms = entry.due_at_ms;
            let key = format!("{PENDING_LEFT_PREFIX}{room}");
            if let Err(e) = self.state.storage().put(&key, entry).await {
                // Can't persist the pending entry — the trailing check
                // would never fire and a REAL departure would go silent
                // forever. Fall back to the pre-debounce immediate push:
                // a rare flap false-positive (absorbed by the client's
                // verify) beats a permanently missed departure. Delete
                // any PRIOR pending entry for this room first — the put
                // failed, so a stale earlier-departure entry may still
                // be stored, and left in place it would fire a SECOND
                // push at its original due time on top of this
                // immediate one.
                console_log!(
                    "MessageHub: pendingleft put failed for {room} ({e}) — \
                     falling back to immediate peerLeft push"
                );
                let _ = self.state.storage().delete(&key).await;
                self.push_peer_left(room, leaver).await;
                continue;
            }
            if !self.ensure_alarm_no_later_than(due_at_ms).await {
                // Entry stored but NO wake guaranteed — without an alarm
                // the trailing check never runs and the entry strands
                // (recoverable only by the next departure or the
                // fetch-time re-arm scan, i.e. poll latency for the
                // peer). Same reasoning as the put failure above:
                // un-store and push immediately.
                console_log!(
                    "MessageHub: alarm arm failed for {room} — \
                     falling back to immediate peerLeft push"
                );
                let _ = self.state.storage().delete(&key).await;
                self.push_peer_left(room, leaver).await;
            }
        }
    }

    /// Cross-DO `/internal/peer-left` push to the room's known
    /// counterparty. Single attempt, best-effort, log-only on failure —
    /// identical semantics to the pre-debounce inline push. No-ops
    /// quietly when the room has no learned peer (`peer_by_room:` unset)
    /// or is malformed. Accepted bound (review LOW): a fallback
    /// immediate push can race a concurrently armed/fired trailing
    /// check into at most ONE duplicate peerLeft — absorbed by the
    /// client's verify-not-a-flap presence check, same bound as the
    /// close/error double-fire latch.
    async fn push_peer_left(&self, room: &str, leaver: &str) {
        // bsv-low 2026-09-05 (full18 class L): a WAITING host's lobby room has
        // no counterparty — its watchers are the whole lobby. A confirmed
        // departure (the debounce already ruled out a flap) fans a `lobby`
        // event into every subscriber's `broadcast-low-lobby` box; the
        // watcher re-probes presence and its own confirm window decides.
        if crate::is_lobby_room(room) {
            if let Some(body) = crate::lobby_departure_body(room, leaver, Date::now().as_millis()) {
                let (subscribers, pushed) =
                    crate::fan_out_broadcast(&self.env, crate::LOBBY_BROADCAST_BOX, &body).await;
                console_log!(
                    "MessageHub: lobby host-left {} (room {}) → {} of {} lobby subscribers",
                    leaver,
                    room,
                    pushed,
                    subscribers
                );
            }
            return;
        }
        let key = format!("{PEER_BY_ROOM_PREFIX}{room}");
        let peer: Option<String> = self.state.storage().get(&key).await.ok().flatten();
        let Some(peer) = peer else { return };
        let Some(peer_room) = peer_room(&peer, room) else {
            return;
        };
        let Ok(namespace) = self.env.durable_object("MESSAGE_HUB") else {
            return;
        };
        let Ok(stub) = namespace.id_from_name(&peer).and_then(|id| id.get_stub()) else {
            return;
        };
        let payload = json!({ "roomId": peer_room, "leaver": leaver }).to_string();
        let headers = Headers::new();
        let _ = headers.set("content-type", "application/json");
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.into()));
        let Ok(req) = Request::new_with_init("https://do.local/internal/peer-left", &init) else {
            return;
        };
        match stub.fetch_with_request(req).await {
            Ok(_) => console_log!(
                "MessageHub: peerLeft {} → {} (room {})",
                leaver,
                peer,
                peer_room
            ),
            Err(e) => console_log!("MessageHub: peerLeft notify failed: {e}"),
        }
    }

    /// Make sure the DO alarm rings no later than `due_at_ms`. An
    /// earlier-scheduled alarm is left alone (the handler re-arms for
    /// whatever is still pending); a later, missing, or stale one is
    /// pulled in (`alarm_needs_replacing` is the pure predicate).
    /// Returns whether a wake at/before `due_at_ms` is CONFIRMED —
    /// `false` means the caller must not rely on the trailing check
    /// running (arm-path callers fall back to an immediate push).
    async fn ensure_alarm_no_later_than(&self, due_at_ms: u64) -> bool {
        let storage = self.state.storage();
        let now_ms = Date::now().as_millis();
        let current: Option<i64> = storage.get_alarm().await.ok().flatten();
        let (Ok(due), Ok(now)) = (i64::try_from(due_at_ms), i64::try_from(now_ms)) else {
            return false; // epoch-ms beyond i64 — unreachable in practice
        };
        if !alarm_needs_replacing(current, due, now) {
            return true; // an earlier future alarm already covers us
        }
        let delay_ms = due_at_ms.saturating_sub(now_ms).max(1);
        match storage
            .set_alarm(std::time::Duration::from_millis(delay_ms))
            .await
        {
            Ok(()) => true,
            Err(e) => {
                console_log!("MessageHub: set_alarm failed (due {due_at_ms}): {e}");
                false
            }
        }
    }

    /// All pending (debounced) departure notifications, as
    /// `(room, entry)` pairs. A storage LIST failure is an `Err` — the
    /// caller must distinguish "cannot read" from "genuinely empty"
    /// (consuming a fired alarm on an unreadable list would strand every
    /// stored entry). An UNDECODABLE entry is deleted on sight (logged):
    /// it could never fire, and skipping it would leak it forever.
    async fn list_pending_departures(&self) -> Result<Vec<(String, PendingPeerLeft)>> {
        let opts = ListOptions::new().prefix(PENDING_LEFT_PREFIX);
        let map = self.state.storage().list_with_options(opts).await?;
        let mut out = Vec::new();
        let mut corrupt: Vec<String> = Vec::new();
        let entries = map.entries();
        let iter = js_sys::try_iter(&entries).ok().flatten();
        if let Some(iter) = iter {
            for e in iter.flatten() {
                let arr: js_sys::Array = e.into();
                let Some(key) = arr.get(0).as_string() else {
                    continue;
                };
                let Some(room) = key.strip_prefix(PENDING_LEFT_PREFIX) else {
                    continue;
                };
                let decoded = serde_wasm_bindgen::from_value::<PendingPeerLeft>(arr.get(1)).ok();
                match classify_pending_row(room.to_string(), decoded) {
                    PendingRowAction::Keep(room, entry) => out.push((room, entry)),
                    PendingRowAction::DeleteCorrupt(room) => {
                        console_log!(
                            "MessageHub: undecodable pendingleft entry for {room} — deleting"
                        );
                        corrupt.push(key);
                    }
                }
            }
        }
        for key in corrupt {
            let _ = self.state.storage().delete(&key).await;
        }
        Ok(out)
    }

    /// The DO-alarm consumer for the departure debounce: run every DUE
    /// trailing check (delete the entry, re-check occupancy, push the
    /// peer-left iff the room is STILL empty), then re-arm the alarm for
    /// the earliest still-pending entry, if any. Composes via
    /// `split_due_pending` — the same pure core the unit tests drive.
    async fn run_departure_debounce_alarm(&self) {
        let now_ms = Date::now().as_millis();
        let pending = match self.list_pending_departures().await {
            Ok(p) => p,
            Err(e) => {
                // The fired alarm is consumed either way — if we return
                // without re-arming, every stored entry strands until
                // the next departure or the fetch-time recovery scan.
                // Keep the wake chain alive: retry one window out.
                console_log!(
                    "MessageHub: pendingleft list failed in alarm ({e}) — \
                     re-arming a retry in {PEER_LEFT_DEBOUNCE_MS}ms"
                );
                let _ = self
                    .state
                    .storage()
                    .set_alarm(std::time::Duration::from_millis(PEER_LEFT_DEBOUNCE_MS))
                    .await;
                return;
            }
        };
        let (due, _rest, next) = split_due_pending(pending, now_ms);
        for (room, entry) in due {
            // Delete first: the check is one-shot either way (single
            // best-effort push, same as the pre-debounce semantics).
            // Accepted bound (review LOW): a push failure after this
            // delete is NOT retried — single-attempt best-effort,
            // identical to the pre-debounce inline push; the peer's
            // `/presence` poll is the recovery path.
            let _ = self
                .state
                .storage()
                .delete(&format!("{PENDING_LEFT_PREFIX}{room}"))
                .await;
            let still_occupied = self.room_still_occupied(&room, None, None).await;
            if departure_push_due(still_occupied) {
                self.push_peer_left(&room, &entry.leaver).await;
            } else {
                console_log!(
                    "MessageHub: peerLeft for {room} suppressed — flap rejoined \
                     within the debounce window"
                );
            }
        }
        if let Some(next_due) = next {
            self.ensure_alarm_no_later_than(next_due).await;
        }
    }

    /// MED-1(c) recovery net, run once per isolate from the top of
    /// `fetch`: if any `pendingleft:` entries survived an isolate
    /// restart with no alarm covering them (possible only via the
    /// failure paths — DO alarms are otherwise durable), pull the alarm
    /// in to the earliest due so their trailing checks still run.
    /// Best-effort: on a list error the guard flag is RESET so a later
    /// request retries the scan.
    async fn rearm_pending_departures_once(&self) {
        if self.rearm_scan_done.get() {
            return;
        }
        self.rearm_scan_done.set(true);
        let pending = match self.list_pending_departures().await {
            Ok(p) => p,
            Err(e) => {
                console_log!("MessageHub: rearm scan list failed ({e}) — will retry");
                self.rearm_scan_done.set(false);
                return;
            }
        };
        if let Some(earliest) = pending.iter().map(|(_, e)| e.due_at_ms).min() {
            // Ignore the confirmation bool: this is a recovery net, not
            // an arm path — a failure here leaves the entries no worse
            // off, and the next request retriggers nothing (flag set)
            // but the next departure/alarm re-arms.
            let _ = self.ensure_alarm_no_later_than(earliest).await;
        }
    }

    /// `/internal/peer-left` — the counterparty's hub told us their last
    /// session left the shared conversation. Fan a `peerLeft` event out to
    /// this owner's sessions: raw-WS sockets joined to the room get the
    /// flat `peerLeft` envelope; socket.io sessions get a broadcast with
    /// `event:"peerLeft"` (emitted client-side as `peerLeft-<roomId>`, the
    /// same room-suffixed convention as `sendMessage`). UX-only — never a
    /// message, never stored.
    async fn handle_peer_left(&self, req: &mut Request) -> Result<Response> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PeerLeftBody {
            room_id: String,
            leaver: String,
        }
        let body: PeerLeftBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid peer-left body: {e}"), 400),
        };
        // Told-state dedupe: the owner hears "left" once per departure.
        let (emit_it, next) = told_transition(self.read_told(&body.room_id).await, false);
        if !emit_it {
            return Response::from_json(&json!({ "delivered": 0, "deduped": true }));
        }
        self.write_told(&body.room_id, next).await;
        let mut delivered = 0u32;
        for ws in self.state.get_websockets() {
            let Ok(Some(a)) = ws.deserialize_attachment::<SocketAttachment>() else {
                continue;
            };
            if !a.joined_rooms.iter().any(|r| r == &body.room_id) {
                continue;
            }
            if emit(
                &ws,
                "peerLeft",
                &json!({ "roomId": body.room_id, "identityKey": body.leaver }),
            )
            .is_ok()
            {
                delivered += 1;
            }
        }
        // socket.io fan-out: same no-server-side-room-filter rule as
        // sendMessage (the event name is room-suffixed, so client-side
        // subscription filters; see the race note in handle_internal_push).
        let entries = self.list_socketio_subscribers().await;
        if !entries.is_empty() {
            if let Ok(ns) = self.env.durable_object("ENGINEIO_SESSION") {
                for entry in entries {
                    let Ok(stub) = ns.id_from_name(&entry.sid).and_then(|id| id.get_stub()) else {
                        continue;
                    };
                    let payload = json!({
                        "roomId": body.room_id,
                        "sender": body.leaver,
                        "messageId": format!("peer-left-{}", Date::now().as_millis()),
                        "body": {},
                        "event": "peerLeft",
                    })
                    .to_string();
                    let headers = Headers::new();
                    let _ = headers.set("content-type", "application/json");
                    let mut init = RequestInit::new();
                    init.with_method(Method::Post)
                        .with_headers(headers)
                        .with_body(Some(payload.into()));
                    let Ok(req) = Request::new_with_init(
                        "https://do.local/internal/socketio-broadcast",
                        &init,
                    ) else {
                        continue;
                    };
                    if stub.fetch_with_request(req).await.is_ok() {
                        delivered += 1;
                    }
                }
            }
        }
        if delivered == 0 {
            // bsv-low 2026-09-05 (full18 run 2, survivorLooksOnly): the counterparty's
            // hub pushed the departure while THIS identity's only session was between a
            // leave and a re-join (the felt's inbound watchdog re-listens) — nobody
            // received it, the told-state still flipped to "absent", and every later
            // push was deduped: the open seat never heard the event. PARK it; the next
            // register / room join of this identity delivers it (bounded by
            // PARKED_PEER_LEFT_TTL_MS — a stale departure is not news).
            let parked = ParkedPeerLeft { leaver: body.leaver.clone(), at_ms: Date::now().as_millis() };
            if let Err(e) = self.state.storage().put(&format!("{PARKED_LEFT_PREFIX}{}", body.room_id), parked).await {
                console_log!("MessageHub: parkedleft put failed for {}: {e}", body.room_id);
            } else {
                console_log!("MessageHub: peerLeft for {} PARKED (no session to deliver to)", body.room_id);
            }
        }
        Response::from_json(&json!({ "delivered": delivered }))
    }

    /// Deliver the parked presence event (a departure, 0.3.13 — or an arrival,
    /// 0.3.16) each of `rooms` owes the socket.io session `sid` that just
    /// registered / joined, then clear both parked keys for the room. The choice
    /// is `parked_presence_choice` (pure): the told-state decides which one still
    /// stands, the TTL drops stale news, the newer wins a tie.
    async fn deliver_parked_presence(&self, sid: &str, rooms: &[String]) {
        let now_ms = Date::now().as_millis();
        for room in rooms {
            let left_key = format!("{PARKED_LEFT_PREFIX}{room}");
            let joined_key = format!("{PARKED_JOINED_PREFIX}{room}");
            let left: Option<ParkedPeerLeft> = self.state.storage().get(&left_key).await.ok().flatten();
            let joined: Option<ParkedPeerJoined> = self.state.storage().get(&joined_key).await.ok().flatten();
            if left.is_none() && joined.is_none() {
                continue;
            }
            let _ = self.state.storage().delete(&left_key).await;
            let _ = self.state.storage().delete(&joined_key).await;
            let told = self.read_told(room).await;
            let choice = parked_presence_choice(left.as_ref().map(|p| p.at_ms), joined.as_ref().map(|p| p.at_ms), told, now_ms);
            let (event, sender, at_ms) = match choice {
                ParkedChoice::Nothing => {
                    console_log!(
                        "MessageHub: parked presence for {room} dropped (left={} joined={} told={:?}) — stale or superseded",
                        left.is_some(),
                        joined.is_some(),
                        told
                    );
                    continue;
                }
                ParkedChoice::Left => {
                    let p = left.expect("chosen");
                    ("peerLeft", p.leaver, p.at_ms)
                }
                ParkedChoice::Joined => {
                    let p = joined.expect("chosen");
                    ("peerJoined", p.joiner, p.at_ms)
                }
            };
            let Ok(ns) = self.env.durable_object("ENGINEIO_SESSION") else { continue };
            let Ok(stub) = ns.id_from_name(sid).and_then(|id| id.get_stub()) else { continue };
            let payload = json!({
                "roomId": room,
                "sender": sender,
                "messageId": format!("{}-{}", if event == "peerLeft" { "peer-left" } else { "peer-joined" }, now_ms),
                "body": {},
                "event": event,
            })
            .to_string();
            let headers = Headers::new();
            let _ = headers.set("content-type", "application/json");
            let mut init = RequestInit::new();
            init.with_method(Method::Post).with_headers(headers).with_body(Some(payload.into()));
            let Ok(req) = Request::new_with_init("https://do.local/internal/socketio-broadcast", &init) else { continue };
            match stub.fetch_with_request(req).await {
                Ok(_) => console_log!("MessageHub: parked {event} for {room} delivered to sid={sid} ({}ms late)", now_ms.saturating_sub(at_ms)),
                Err(e) => console_log!("MessageHub: parked {event} delivery failed for {room}: {e}"),
            }
        }
    }

    /// `/internal/rejoin-deadline?room=<roomId>` (body `{deadlineMs:<u64>}`)
    /// — the STAYING player published the rejoin deadline it will honor for
    /// this room. Store it verbatim under `rejoindeadline:<room>` so a
    /// rejoiner's `/presence` reads back the synchronized countdown. An
    /// empty/malformed room or body is a 400; the store itself is fail-quiet.
    /// UX-only — never gates delivery, auth, or money.
    async fn handle_set_rejoin_deadline(&self, req: &mut Request) -> Result<Response> {
        let url = req.url()?;
        let room = url
            .query_pairs()
            .find(|(k, _)| k == "room")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if room.is_empty() {
            return Response::error("rejoin-deadline requires ?room=<roomId>", 400);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RejoinDeadlineBody {
            deadline_ms: u64,
        }
        let body: RejoinDeadlineBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid rejoin-deadline body: {e}"), 400),
        };
        self.stamp_rejoin_deadline(&room, body.deadline_ms).await;
        // bsv-low 2026-09-05: name the room's remembered COUNTERPARTY (the
        // seat that posted into this room) so the worker can file the tier-2
        // `ladder` event into its `low_events` box. Advisory: absent ⇒ null.
        let peer: Option<String> = self
            .state
            .storage()
            .get(&format!("{PEER_BY_ROOM_PREFIX}{room}"))
            .await
            .ok()
            .flatten();
        Response::from_json(&json!({ "status": "success", "peer": peer }))
    }

    /// `/internal/presence?room=<roomId>` — is any live session of this
    /// hub's owner joined to `room` right now? The polling fallback for
    /// clients whose WS dropped (a caller must know the full room id —
    /// for LOW that embeds the 64-hex gameId, so presence is only
    /// readable by someone already in the game). UX-only.
    async fn read_told(&self, room: &str) -> Option<ToldPresence> {
        let v: Option<String> = self
            .state
            .storage()
            .get(&format!("{PRESENCE_TOLD_PREFIX}{room}"))
            .await
            .ok()
            .flatten();
        told_from_str(v.as_deref())
    }

    async fn write_told(&self, room: &str, told: ToldPresence) {
        if let Err(e) = self
            .state
            .storage()
            .put(&format!("{PRESENCE_TOLD_PREFIX}{room}"), told.as_str())
            .await
        {
            console_log!("MessageHub: presence_told put failed for {room}: {e}");
        }
    }

    /// `/internal/peer-joined` — the counterparty's hub says they ARRIVED in
    /// the shared conversation. Mirror of `handle_peer_left`: fan `peerJoined`
    /// to this owner's sessions (raw sockets joined to the room; socket.io
    /// sessions via the broadcast bridge, room-suffixed client-side). Deduped
    /// by the told-state so a second tab / a flap emits nothing. UX-only.
    async fn handle_peer_joined(&self, req: &mut Request) -> Result<Response> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PeerJoinedBody {
            room_id: String,
            joiner: String,
        }
        let body: PeerJoinedBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid peer-joined body: {e}"), 400),
        };
        let (emit_it, next) = told_transition(self.read_told(&body.room_id).await, true);
        if !emit_it {
            return Response::from_json(&json!({ "delivered": 0, "deduped": true }));
        }
        self.write_told(&body.room_id, next).await;
        let mut delivered = 0u32;
        for ws in self.state.get_websockets() {
            let Ok(Some(a)) = ws.deserialize_attachment::<SocketAttachment>() else {
                continue;
            };
            if !a.joined_rooms.iter().any(|r| r == &body.room_id) {
                continue;
            }
            if emit(
                &ws,
                "peerJoined",
                &json!({ "roomId": body.room_id, "identityKey": body.joiner }),
            )
            .is_ok()
            {
                delivered += 1;
            }
        }
        let entries = self.list_socketio_subscribers().await;
        if !entries.is_empty() {
            if let Ok(ns) = self.env.durable_object("ENGINEIO_SESSION") {
                for entry in entries {
                    let Ok(stub) = ns.id_from_name(&entry.sid).and_then(|id| id.get_stub()) else {
                        continue;
                    };
                    let payload = json!({
                        "roomId": body.room_id,
                        "sender": body.joiner,
                        "messageId": format!("peer-joined-{}", Date::now().as_millis()),
                        "body": {},
                        "event": "peerJoined",
                    })
                    .to_string();
                    let headers = Headers::new();
                    let _ = headers.set("content-type", "application/json");
                    let mut init = RequestInit::new();
                    init.with_method(Method::Post)
                        .with_headers(headers)
                        .with_body(Some(payload.into()));
                    let Ok(req) = Request::new_with_init(
                        "https://do.local/internal/socketio-broadcast",
                        &init,
                    ) else {
                        continue;
                    };
                    if stub.fetch_with_request(req).await.is_ok() {
                        delivered += 1;
                    }
                }
            }
        }
        if delivered == 0 {
            // 0.3.16 (bsv-low 2026-09-05, dealtLeaveNotifyRejoin): the counterparty
            // rejoined while THIS identity's only session was dead (a heartbeat
            // timeout, a reconnect in flight) — nobody received the arrival and the
            // told-state already says Present, so it would never be re-pushed. PARK
            // it; the next register / room join of this identity delivers it
            // (bounded by the same TTL; dropped if the peer left again meanwhile).
            let parked = ParkedPeerJoined { joiner: body.joiner.clone(), at_ms: Date::now().as_millis() };
            if let Err(e) = self.state.storage().put(&format!("{PARKED_JOINED_PREFIX}{}", body.room_id), parked).await {
                console_log!("MessageHub: parkedjoined put failed for {}: {e}", body.room_id);
            } else {
                console_log!("MessageHub: peerJoined for {} PARKED (no session to deliver to)", body.room_id);
            }
        }
        Response::from_json(&json!({ "delivered": delivered }))
    }

    /// Cross-DO `/internal/peer-joined` push to the room's known counterparty
    /// (mirror of `push_peer_left`). No-ops when no peer is learned yet — the
    /// first envelope teaches it, and an envelope is itself proof of presence.
    async fn push_peer_joined(&self, room: &str, joiner: &str) {
        let key = format!("{PEER_BY_ROOM_PREFIX}{room}");
        let peer: Option<String> = self.state.storage().get(&key).await.ok().flatten();
        let Some(peer) = peer else { return };
        let Some(peer_room) = peer_room(&peer, room) else {
            return;
        };
        let Ok(namespace) = self.env.durable_object("MESSAGE_HUB") else {
            return;
        };
        let Ok(stub) = namespace.id_from_name(&peer).and_then(|id| id.get_stub()) else {
            return;
        };
        let payload = json!({ "roomId": peer_room, "joiner": joiner }).to_string();
        let headers = Headers::new();
        let _ = headers.set("content-type", "application/json");
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.into()));
        let Ok(req) = Request::new_with_init("https://do.local/internal/peer-joined", &init) else {
            return;
        };
        match stub.fetch_with_request(req).await {
            Ok(_) => console_log!("MessageHub: peerJoined {} → {} (room {})", joiner, peer, peer_room),
            Err(e) => console_log!("MessageHub: peerJoined notify failed: {e}"),
        }
    }

    /// The `presence` snapshot for a JOINING socket: the counterparty's live
    /// occupancy asked ONCE, hub-to-hub, at join time. Unknown peer (no
    /// envelope exchanged yet) ⇒ `identityKey: null, present: null` — an
    /// explicit "nothing learned", never a guessed absence. Records the
    /// told-state so the following `peerJoined`/`peerLeft` dedupe against
    /// what the owner has actually seen.
    async fn presence_snapshot(&self, room: &str) -> Value {
        let key = format!("{PEER_BY_ROOM_PREFIX}{room}");
        let peer: Option<String> = self.state.storage().get(&key).await.ok().flatten();
        let Some(peer) = peer else {
            return presence_snapshot_json(room, None, None, None, None);
        };
        let Some(peer_room) = peer_room(&peer, room) else {
            return presence_snapshot_json(room, None, None, None, None);
        };
        let read = async {
            let ns = self.env.durable_object("MESSAGE_HUB").ok()?;
            let stub = ns.id_from_name(&peer).ok()?.get_stub().ok()?;
            let url = format!("https://do.local/internal/presence?room={peer_room}");
            let mut resp = stub.fetch_with_str(&url).await.ok()?;
            if resp.status_code() != 200 {
                return None;
            }
            resp.json::<Value>().await.ok()
        }
        .await;
        let Some(v) = read else {
            return presence_snapshot_json(room, Some(&peer), None, None, None);
        };
        let present = v.get("present").and_then(Value::as_bool);
        let last_seen = v.get("lastSeenMs").and_then(Value::as_u64);
        let rejoin_deadline = v.get("rejoinDeadlineMs").and_then(Value::as_u64);
        if let Some(p) = present {
            let (_, next) = told_transition(self.read_told(room).await, p);
            self.write_told(room, next).await;
        }
        presence_snapshot_json(room, Some(&peer), present, last_seen, rejoin_deadline)
    }

    async fn handle_presence(&self, req: &Request) -> Result<Response> {
        let url = req.url()?;
        let room = url
            .query_pairs()
            .find(|(k, _)| k == "room")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        if room.is_empty() {
            return Response::error("presence requires ?room=<roomId>", 400);
        }
        let present = self.room_still_occupied(&room, None, None).await;
        // Advisory last-seen: read `lastseen:<room>` (u64 millis) and
        // thread it through ONLY when present. A missing/unreadable key
        // omits the field entirely — never 0/null, never a false claim.
        let last_seen_ms: Option<u64> = self
            .state
            .storage()
            .get(&format!("{LAST_SEEN_PREFIX}{room}"))
            .await
            .ok()
            .flatten();
        // Tier-2 stayer-published rejoin deadline: read `rejoindeadline:<room>`
        // (u64 millis) verbatim and thread it through ONLY when present. The
        // relay does NOT judge past-vs-future — that's the client's call. A
        // missing/unreadable key omits the field (never 0/null).
        let rejoin_deadline_ms: Option<u64> = self
            .state
            .storage()
            .get(&format!("{REJOIN_DEADLINE_PREFIX}{room}"))
            .await
            .ok()
            .flatten();
        Response::from_json(&presence_body_json(
            &room,
            present,
            last_seen_ms,
            rejoin_deadline_ms,
        ))
    }
}

/// Build the `/internal/presence` response body. `present` (live socket)
/// is the primary signal; `last_seen_ms` (heartbeat) and `rejoin_deadline_ms`
/// (tier-2 stayer-published deadline) are advisory and each INCLUDED only
/// when `Some` — an absent value OMITS its field entirely (never serialized
/// as 0/null, so a reader can't misread it as a real value). All three are
/// independent.
/// See `PRESENCE_TOLD_PREFIX`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ToldPresence {
    Present,
    Absent,
}

impl ToldPresence {
    fn as_str(self) -> &'static str {
        match self {
            ToldPresence::Present => "present",
            ToldPresence::Absent => "absent",
        }
    }
}

fn told_from_str(s: Option<&str>) -> Option<ToldPresence> {
    match s {
        Some("present") => Some(ToldPresence::Present),
        Some("absent") => Some(ToldPresence::Absent),
        _ => None,
    }
}

/// The ONE rule for presence events: the owner hears a change when, and only
/// when, the observed state differs from what it was last told. The first
/// observation always counts. Returns `(emit, next_told)`.
fn told_transition(prev: Option<ToldPresence>, observed_present: bool) -> (bool, ToldPresence) {
    let next = if observed_present {
        ToldPresence::Present
    } else {
        ToldPresence::Absent
    };
    (prev != Some(next), next)
}

/// The `presence` event body (join-time snapshot). `present: null` with
/// `identityKey: null` = no counterparty learned; `present: null` with a key =
/// the peer hub could not be read (a fault, not an absence).
fn presence_snapshot_json(
    room: &str,
    peer: Option<&str>,
    present: Option<bool>,
    last_seen_ms: Option<u64>,
    rejoin_deadline_ms: Option<u64>,
) -> Value {
    let mut body = json!({ "roomId": room, "identityKey": peer, "present": present });
    if let Some(ms) = last_seen_ms {
        body["lastSeenMs"] = json!(ms);
    }
    if let Some(ms) = rejoin_deadline_ms {
        body["rejoinDeadlineMs"] = json!(ms);
    }
    body
}

fn presence_body_json(
    room: &str,
    present: bool,
    last_seen_ms: Option<u64>,
    rejoin_deadline_ms: Option<u64>,
) -> Value {
    let mut body = json!({ "room": room, "present": present });
    if let Some(ms) = last_seen_ms {
        body["lastSeenMs"] = json!(ms);
    }
    if let Some(ms) = rejoin_deadline_ms {
        body["rejoinDeadlineMs"] = json!(ms);
    }
    body
}

/// Pure core of the departed-socket teardown latch (#225). Given the
/// attachment recovered from a closing/erroring socket, decide whether a
/// departure notification is due. Returns `None` when there is nothing
/// to do (no joined rooms — including the already-latched case, since
/// the latch IS an empty room list). Otherwise returns the latched
/// (room-less) attachment to write back, the departed rooms, and the
/// leaver identity. The runtime can fire BOTH `websocket_close` and
/// `websocket_error` for one socket; writing the latched attachment
/// after the first makes the second a no-op.
fn split_departure(mut a: SocketAttachment) -> Option<(SocketAttachment, Vec<String>, String)> {
    if a.joined_rooms.is_empty() {
        return None;
    }
    let rooms = std::mem::take(&mut a.joined_rooms);
    let leaver = a.identity_key.clone();
    Some((a, rooms, leaver))
}

/// A pending (debounced) peer-left notification, stored at
/// `pendingleft:<room>` between the last-session departure and the
/// trailing alarm check. See [`PENDING_LEFT_PREFIX`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct PendingPeerLeft {
    /// Identity that departed (the payload of the eventual push).
    leaver: String,
    /// Epoch-ms of the departure that (re)armed this entry. Diagnostic
    /// only — the `lastseen:` stamp (written immediately at departure)
    /// is the client-facing "was here until T" truth.
    departed_at_ms: u64,
    /// Epoch-ms when the trailing occupancy re-check is due.
    due_at_ms: u64,
}

/// Pure core of the departure debounce ARM step: on a last-session
/// departure (occupancy already checked empty), build the pending entry
/// whose trailing check fires one debounce window from NOW. Trailing
/// edge by construction — the caller stores it at `pendingleft:<room>`
/// unconditionally, so a departure during an open window OVERWRITES the
/// entry and re-times the single check from the latest departure.
fn arm_departure_debounce(leaver: &str, now_ms: u64) -> PendingPeerLeft {
    PendingPeerLeft {
        leaver: leaver.to_string(),
        departed_at_ms: now_ms,
        due_at_ms: now_ms + PEER_LEFT_DEBOUNCE_MS,
    }
}

/// Pure core of the debounce ALARM step: partition the pending entries
/// into those whose trailing check is DUE now (re-check occupancy →
/// push or drop, then delete) and those still waiting (stay stored),
/// plus the earliest future due time to re-arm the DO alarm with
/// (`None` when nothing remains).
#[allow(clippy::type_complexity)]
fn split_due_pending(
    pending: Vec<(String, PendingPeerLeft)>,
    now_ms: u64,
) -> (
    Vec<(String, PendingPeerLeft)>,
    Vec<(String, PendingPeerLeft)>,
    Option<u64>,
) {
    let mut due = Vec::new();
    let mut rest = Vec::new();
    let mut next: Option<u64> = None;
    for (room, entry) in pending {
        if entry.due_at_ms <= now_ms {
            due.push((room, entry));
        } else {
            next = Some(next.map_or(entry.due_at_ms, |n| n.min(entry.due_at_ms)));
            rest.push((room, entry));
        }
    }
    (due, rest, next)
}

/// Pure core of the trailing check itself: a due entry pushes iff the
/// room is STILL empty at fire time. A reoccupied room (the flap
/// rejoined) pushes nothing — the entry is simply dropped.
fn departure_push_due(still_occupied: bool) -> bool {
    !still_occupied
}

/// Pure predicate of `ensure_alarm_no_later_than`: replace the DO alarm
/// when there is none, when ours is EARLIER than the scheduled one, or
/// when the scheduled one is already in the PAST (stale reading around a
/// fire — the runtime reports `None` inside the alarm handler, but
/// belt-and-braces). An earlier future alarm is left alone: its handler
/// re-arms for whatever is still pending.
fn alarm_needs_replacing(current: Option<i64>, due_ms: i64, now_ms: i64) -> bool {
    match current {
        None => true,
        Some(t) => t > due_ms || t <= now_ms,
    }
}

/// Per-row decision for a listed `pendingleft:` entry.
#[derive(Debug, PartialEq, Eq)]
enum PendingRowAction {
    /// Decodable — a live pending departure.
    Keep(String, PendingPeerLeft),
    /// Undecodable — delete on sight: it can never fire, and a
    /// skip-only policy would leak it (and its alarm churn) forever.
    DeleteCorrupt(String),
}

/// Pure core of `list_pending_departures`' per-row handling.
fn classify_pending_row(room: String, decoded: Option<PendingPeerLeft>) -> PendingRowAction {
    match decoded {
        Some(entry) => PendingRowAction::Keep(room, entry),
        None => PendingRowAction::DeleteCorrupt(room),
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

/// S3b — the broadcast BOX marker. A client subscribes by listening on its
/// OWN box named `broadcast-low-board` (roomId `<identity>-broadcast-...`,
/// the normal ownership rule — no public-room concept); the worker's
/// /broadcast fan-out delivers per-subscriber into exactly that room.
pub const BROADCAST_BOX_MARKER: &str = "-broadcast-";

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
        // A duplicate `messageId` means the message is ALREADY DELIVERED (stored
        // on a prior send — messageId is a content-addressed HMAC of the body).
        // ACK it as SUCCESS (bsv-low#249): the old `messageFailed` mapping left
        // the client's `sendLiveMessage` waiting out its full 10 000ms WS-ack
        // timeout (it only listens for `sendMessageAck-<room>`), then HTTP-falling-
        // back into the same duplicate — a fixed ~10.4s stall on EVERY duplicate
        // resend (watchdog / reconnect / mutual-wait heal), which cascaded into a
        // spurious dispute escalation + wedge. A duplicate = delivery, not failure
        // (matches the client's own #210 `isDuplicateMessage` semantics); acking
        // it resolves the resend in <1s. Idempotent + honest: we only reach here
        // because the identical-content row is already present.
        SendOutcome::DuplicateMessage { message_id, .. } => vec![OutboundEvent::new(
            "sendMessageAck",
            json!({
                "roomId": room_id,
                "status": "success",
                "messageId": message_id,
                "duplicate": true,
            }),
        )],
        SendOutcome::InternalError { detail } => vec![OutboundEvent::new(
            "messageFailed",
            json!({ "reason": format!("An internal error has occurred: {}", detail) }),
        )],
        SendOutcome::TransientError { detail } => vec![OutboundEvent::new(
            // Same `messageFailed` channel; the reason flags it retryable so the
            // WS client resends rather than treating it as terminal. The send
            // failed FAST (bounded write timeout+retry), not the ~10s hang.
            "messageFailed",
            json!({
                "reason": format!(
                    "The relay is momentarily unavailable; please retry: {}",
                    detail
                ),
                "retryable": true,
            }),
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
    fn told_transition_emits_exactly_on_change_and_always_on_first_observation() {
        use ToldPresence::*;
        assert_eq!(told_transition(None, true), (true, Present));
        assert_eq!(told_transition(None, false), (true, Absent));
        assert_eq!(told_transition(Some(Present), true), (false, Present)); // second tab joins: silent
        assert_eq!(told_transition(Some(Present), false), (true, Absent));
        assert_eq!(told_transition(Some(Absent), false), (false, Absent)); // duplicate peerLeft: silent
        assert_eq!(told_transition(Some(Absent), true), (true, Present));
        assert_eq!(told_from_str(Some("present")), Some(Present));
        assert_eq!(told_from_str(Some("absent")), Some(Absent));
        assert_eq!(told_from_str(Some("garbage")), None);
        assert_eq!(told_from_str(None), None);
        assert_eq!(told_from_str(Some(Present.as_str())), Some(Present));
    }

    #[test]
    fn presence_snapshot_json_distinguishes_unknown_peer_from_unreadable_peer_from_answers() {
        let unknown = presence_snapshot_json("03aa-low_game_1", None, None, None, None);
        assert!(unknown["identityKey"].is_null());
        assert!(unknown["present"].is_null());
        let unreadable = presence_snapshot_json("03aa-low_game_1", Some("02bb"), None, None, None);
        assert_eq!(unreadable["identityKey"], "02bb");
        assert!(unreadable["present"].is_null());
        assert!(unreadable.get("lastSeenMs").is_none());
        let seated = presence_snapshot_json("03aa-low_game_1", Some("02bb"), Some(true), Some(5), None);
        assert_eq!(seated["present"], true);
        assert_eq!(seated["lastSeenMs"], 5);
        let gone = presence_snapshot_json("03aa-low_game_1", Some("02bb"), Some(false), Some(5), Some(9));
        assert_eq!(gone["present"], false);
        assert_eq!(gone["rejoinDeadlineMs"], 9);
    }

    #[test]
    fn broadcast_box_rooms_stay_ownership_gated_and_marker_matches() {
        let key = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0";
        // The broadcast BOX rides the NORMAL ownership rule — own-identity
        // rooms only (no public-room concept exists).
        assert!(validate_room_owned(key, &format!("{key}-broadcast-low-board")).is_ok());
        assert!(validate_room_owned(key, "broadcast-low-board").is_err());
        assert!(format!("{key}-broadcast-low-board").contains(BROADCAST_BOX_MARKER));
    }

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
    fn presence_body_omits_last_seen_when_unset() {
        // Advisory contract: no last-seen key => the field is ABSENT
        // (not 0, not null), so a reader can never misread it. With no
        // tier-2 deadline either, `rejoinDeadlineMs` is likewise absent.
        let body = presence_body_json("03aa-inbox", true, None, None);
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
    fn presence_body_includes_last_seen_when_set() {
        // When a heartbeat exists it is threaded through as a number.
        let body = presence_body_json("03aa-inbox", false, Some(1_700_000_000_123), None);
        assert_eq!(body["present"], json!(false));
        assert_eq!(body["lastSeenMs"], json!(1_700_000_000_123u64));
        assert!(body.get("rejoinDeadlineMs").is_none());
    }

    #[test]
    fn presence_body_includes_rejoin_deadline_when_set() {
        // Tier-2: the stayer-published deadline is threaded through as a
        // number, independent of the heartbeat and of `present`.
        let body = presence_body_json("03aa-inbox", true, None, Some(1_700_000_060_000));
        assert_eq!(body["present"], json!(true));
        assert_eq!(body["rejoinDeadlineMs"], json!(1_700_000_060_000u64));
        assert!(
            body.get("lastSeenMs").is_none(),
            "lastSeenMs stays omitted when only the deadline is set, got: {body}"
        );
    }

    #[test]
    fn presence_body_includes_both_last_seen_and_rejoin_deadline() {
        let body =
            presence_body_json("03aa-inbox", false, Some(1_700_000_000_123), Some(1_700_000_060_000));
        assert_eq!(body["lastSeenMs"], json!(1_700_000_000_123u64));
        assert_eq!(body["rejoinDeadlineMs"], json!(1_700_000_060_000u64));
    }

    #[test]
    fn rejoin_deadline_body_parses_camel_case() {
        // The tier-2 write body is `{deadlineMs:<u64>}` (camelCase on the
        // wire, snake_case in Rust via serde rename_all).
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RejoinDeadlineBody {
            deadline_ms: u64,
        }
        let parsed: RejoinDeadlineBody =
            serde_json::from_str(r#"{"deadlineMs":1700000060000}"#).unwrap();
        assert_eq!(parsed.deadline_ms, 1_700_000_060_000u64);
        // A missing field is a hard parse error (=> the handler 400s).
        assert!(serde_json::from_str::<RejoinDeadlineBody>(r#"{}"#).is_err());
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

    // #40 peer presence — pure helpers.
    const ID_A: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    // #225 — departed-socket teardown latch (`split_departure`). The
    // runtime can fire BOTH websocket_close and websocket_error for a
    // single dropped socket; the latch guarantees at most one peerLeft
    // notification per socket.
    #[test]
    fn split_departure_yields_rooms_and_room_less_latch() {
        let room_a = format!("{ID_A}-low_game_deadbeef");
        let room_b = format!("{ID_A}-inbox");
        let a = SocketAttachment {
            identity_key: ID_A.to_string(),
            connected_at_ms: 1_700_000_000_000,
            joined_rooms: vec![room_a.clone(), room_b.clone()],
        };
        let (latched, rooms, leaver) = split_departure(a).expect("departure due");
        assert_eq!(leaver, ID_A);
        assert_eq!(rooms, vec![room_a, room_b]);
        // The latch is the SAME attachment minus rooms — identity and
        // connect time survive so a later handler still sees a verified
        // socket, just one with nothing left to depart.
        assert_eq!(latched.identity_key, ID_A);
        assert_eq!(latched.connected_at_ms, 1_700_000_000_000);
        assert!(latched.joined_rooms.is_empty());
    }

    #[test]
    fn split_departure_no_ops_on_empty_rooms() {
        // No rooms — nothing to notify. This is ALSO the already-latched
        // case: the second lifecycle event (close after error, or error
        // after close) reads back the latched attachment and stops here.
        let a = SocketAttachment {
            identity_key: ID_A.to_string(),
            connected_at_ms: 1,
            joined_rooms: Vec::new(),
        };
        assert!(split_departure(a).is_none());
    }

    #[test]
    fn split_departure_is_idempotent_through_the_latch() {
        // Round-trip the latch exactly as the teardown does: first pass
        // notifies and writes the latched attachment; feeding the latch
        // back in (the double-fire) must be a no-op.
        let a = SocketAttachment {
            identity_key: ID_A.to_string(),
            connected_at_ms: 2,
            joined_rooms: vec![format!("{ID_A}-low_game_x")],
        };
        let (latched, _, _) = split_departure(a).expect("first pass notifies");
        assert!(
            split_departure(latched).is_none(),
            "second lifecycle event must find nothing to depart"
        );
    }

    #[test]
    fn room_identity_extracts_owner_prefix() {
        let room = format!("{ID_A}-low_game_deadbeef");
        assert_eq!(room_identity(&room), Some(ID_A));
        // malformed: no dash, short prefix, non-hex prefix
        assert_eq!(room_identity("nodash"), None);
        assert_eq!(room_identity("02ab-low_game_x"), None);
        assert_eq!(room_identity(&format!("{}-box", "zz".repeat(33))), None);
    }

    #[test]
    fn room_suffix_and_peer_room_compose() {
        let room = format!("{ID_A}-low_game_deadbeef");
        assert_eq!(room_suffix(&room), Some("low_game_deadbeef"));
        assert_eq!(
            peer_room(ID_B, &room).as_deref(),
            Some(format!("{ID_B}-low_game_deadbeef").as_str())
        );
        // a suffix containing dashes survives intact (split_once)
        let dashed = format!("{ID_A}-my-box-name");
        assert_eq!(room_suffix(&dashed), Some("my-box-name"));
        assert_eq!(
            peer_room(ID_B, &dashed).as_deref(),
            Some(format!("{ID_B}-my-box-name").as_str())
        );
        // malformed rooms compose nothing
        assert_eq!(peer_room(ID_B, "garbage"), None);
        assert_eq!(room_suffix(&format!("{ID_A}-")), None);
    }

    // bsv-low#249: a WS duplicate must ACK as success (already delivered), NOT
    // messageFailed — the old mapping stranded sendLiveMessage for its full 10s
    // WS-ack timeout on every duplicate resend → spurious escalation + wedge.
    #[test]
    fn ws_duplicate_acks_as_success_not_failed() {
        let room = format!("{ID_A}-low_game_dupe");
        let out = outcome_to_outbound(
            &room,
            SendOutcome::DuplicateMessage {
                recipient: ID_B.to_string(),
                message_id: "mid-abc".to_string(),
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_name, "sendMessageAck", "duplicate must ack, not fail");
        assert_eq!(out[0].data["status"], "success");
        assert_eq!(out[0].data["messageId"], "mid-abc");
        assert_eq!(out[0].data["roomId"], room);
        assert_eq!(out[0].data["duplicate"], true);
    }

    // Guard the contract that was the actual bug: sendLiveMessage listens ONLY
    // for `sendMessageAck-<room>`, so a duplicate emitted on any OTHER event name
    // re-introduces the 10s stall. Success and Duplicate must share the ack event.
    #[test]
    fn success_and_duplicate_share_the_ack_event() {
        let room = format!("{ID_A}-low_game_x");
        let success = outcome_to_outbound(
            &room,
            SendOutcome::Success {
                results: vec![crate::routes::send_message::RecipientResult {
                    recipient: ID_B.to_string(),
                    message_id: "m1".to_string(),
                }],
            },
        );
        let dupe = outcome_to_outbound(
            &room,
            SendOutcome::DuplicateMessage {
                recipient: ID_B.to_string(),
                message_id: "m1".to_string(),
            },
        );
        assert_eq!(success[0].event_name, dupe[0].event_name);
        assert_eq!(success[0].data["status"], dupe[0].data["status"]);
    }

    // =======================================================================
    // Presence-flap debounce (bsv-low prod-dist-2026-07-24_04-06-50): the
    // LOW client's inbound watchdog self-heals via leaveRoom+rejoin with a
    // ~1-2s gap. The relay must NOT translate that flap into a peerLeft
    // push about a healthy peer — a last-session departure arms a trailing
    // ~4s check instead, and only a room still empty at fire time pushes.
    //
    // `PresenceSim` mirrors the DO pipeline step-for-step using the SAME
    // pure decision functions the production code calls
    // (`arm_departure_debounce` / `split_due_pending` /
    // `departure_push_due`); only the storage/alarm/cross-DO plumbing is
    // simulated.
    // =======================================================================

    use std::collections::BTreeMap;

    #[derive(Default)]
    struct PresenceSim {
        now: u64,
        /// Live-session count per room for the hub owner. `> 0` models
        /// `room_still_occupied` == true — faithfully, so multi-tab
        /// departure suppression (leave one tab, another still seated)
        /// is exercised, not bypassed.
        sessions: BTreeMap<String, u32>,
        /// Models the `pendingleft:<room>` storage entries.
        pending: BTreeMap<String, PendingPeerLeft>,
        /// Models the single DO alarm.
        alarm_at: Option<u64>,
        /// Cross-DO `/internal/peer-left` pushes: (room, leaver, at_ms).
        pushes: Vec<(String, String, u64)>,
        /// Models `lastseen:<room>` stamps.
        lastseen: BTreeMap<String, u64>,
        /// Fault knob: the NEXT pendingleft put fails (production
        /// fallback: delete stale entry + immediate push). One-shot.
        put_fails_once: bool,
        /// Fault knob: the NEXT ensure_alarm after a successful put
        /// fails (production fallback: delete entry + immediate push).
        /// One-shot.
        alarm_fails_once: bool,
        /// Fault knob: the NEXT alarm-time pendingleft LIST fails
        /// (production: consume nothing, re-arm a retry one window
        /// out). One-shot.
        list_fails_once: bool,
    }

    impl PresenceSim {
        fn occupied(&self, room: &str) -> bool {
            self.sessions.get(room).copied().unwrap_or(0) > 0
        }

        fn join(&mut self, room: &str) {
            // Mirrors ClientEvent::JoinRoom: membership + lastseen stamp.
            *self.sessions.entry(room.to_string()).or_insert(0) += 1;
            self.lastseen.insert(room.to_string(), self.now);
        }

        /// ONE session of `leaver` departs `room`. Mirrors
        /// `maybe_notify_peer_left`: stamp `lastseen` immediately (every
        /// departure, even multi-tab); if another session is still
        /// seated, stop (the `room_still_occupied` gate); otherwise
        /// arm/overwrite the trailing debounce entry and pull the alarm
        /// in (`ensure_alarm_no_later_than`), with the two production
        /// fallback paths modeled via the fault knobs.
        fn depart(&mut self, room: &str, leaver: &str) {
            if let Some(n) = self.sessions.get_mut(room) {
                *n = n.saturating_sub(1);
            }
            // #225 final heartbeat: stamped IMMEDIATELY at departure time.
            self.lastseen.insert(room.to_string(), self.now);
            if self.occupied(room) {
                return; // another tab/device of the same identity is still seated
            }
            let entry = arm_departure_debounce(leaver, self.now);
            let due = entry.due_at_ms;
            if std::mem::take(&mut self.put_fails_once) {
                // Production put-failure fallback: delete any STALE prior
                // entry (it must not fire a second push later), push now.
                self.pending.remove(room);
                self.pushes
                    .push((room.to_string(), leaver.to_string(), self.now));
                return;
            }
            self.pending.insert(room.to_string(), entry);
            if std::mem::take(&mut self.alarm_fails_once) {
                // Production alarm-failure fallback: un-store + push now.
                self.pending.remove(room);
                self.pushes
                    .push((room.to_string(), leaver.to_string(), self.now));
                return;
            }
            if self.alarm_at.is_none_or(|t| t > due) {
                self.alarm_at = Some(due);
            }
        }

        /// Advance the clock, firing the DO alarm whenever due. Mirrors
        /// `MessageHub::alarm` → `run_departure_debounce_alarm`.
        fn advance_to(&mut self, t: u64) {
            while let Some(at) = self.alarm_at {
                if at > t {
                    break;
                }
                self.now = at;
                self.fire_alarm();
            }
            self.now = self.now.max(t);
        }

        fn fire_alarm(&mut self) {
            self.alarm_at = None;
            if std::mem::take(&mut self.list_fails_once) {
                // Production MED-1(b) branch: an unreadable list consumes
                // the wake — re-arm a retry one window out, touch nothing.
                self.alarm_at = Some(self.now + PEER_LEFT_DEBOUNCE_MS);
                return;
            }
            let pending: Vec<(String, PendingPeerLeft)> = std::mem::take(&mut self.pending)
                .into_iter()
                .collect();
            let (due, rest, next) = split_due_pending(pending, self.now);
            self.pending = rest.into_iter().collect();
            for (room, entry) in due {
                let still_occupied = self.occupied(&room);
                if departure_push_due(still_occupied) {
                    self.pushes.push((room, entry.leaver, self.now));
                }
            }
            if let Some(n) = next {
                self.alarm_at = Some(n);
            }
        }
    }

    const ROOM_A_SUFFIX: &str = "low_game_feedface";

    fn sim_room_a() -> String {
        format!("{ID_A}-{ROOM_A_SUFFIX}")
    }

    #[test]
    fn arm_departure_debounce_times_trailing_check_from_now() {
        let e = arm_departure_debounce(ID_A, 10_000);
        assert_eq!(e.leaver, ID_A);
        assert_eq!(e.departed_at_ms, 10_000);
        assert_eq!(e.due_at_ms, 10_000 + PEER_LEFT_DEBOUNCE_MS);
    }

    #[test]
    fn split_due_pending_partitions_and_finds_earliest_next() {
        let mk = |due: u64| PendingPeerLeft {
            leaver: ID_A.to_string(),
            departed_at_ms: due - PEER_LEFT_DEBOUNCE_MS,
            due_at_ms: due,
        };
        let pending = vec![
            ("r1".to_string(), mk(5_000)),  // due
            ("r2".to_string(), mk(9_000)),  // future
            ("r3".to_string(), mk(6_000)),  // due (boundary: <= now)
            ("r4".to_string(), mk(7_500)),  // future (earliest next)
        ];
        let (due, rest, next) = split_due_pending(pending, 6_000);
        let due_rooms: Vec<&str> = due.iter().map(|(r, _)| r.as_str()).collect();
        let rest_rooms: Vec<&str> = rest.iter().map(|(r, _)| r.as_str()).collect();
        assert_eq!(due_rooms, vec!["r1", "r3"]);
        assert_eq!(rest_rooms, vec!["r2", "r4"]);
        assert_eq!(next, Some(7_500), "next alarm = earliest FUTURE due");
        // Nothing pending → no re-arm.
        let (d, r, n) = split_due_pending(Vec::new(), 6_000);
        assert!(d.is_empty() && r.is_empty() && n.is_none());
    }

    #[test]
    fn departure_push_due_only_when_room_still_empty() {
        assert!(departure_push_due(false), "still empty → push");
        assert!(!departure_push_due(true), "reoccupied (flap rejoined) → silent");
    }

    #[test]
    fn alarm_needs_replacing_three_way_predicate() {
        let now = 10_000i64;
        let due = 14_000i64;
        // No alarm at all → set ours.
        assert!(alarm_needs_replacing(None, due, now));
        // A LATER alarm → pull it in to ours.
        assert!(alarm_needs_replacing(Some(20_000), due, now));
        // An EARLIER future alarm covers us → leave it alone.
        assert!(!alarm_needs_replacing(Some(12_000), due, now));
        // An alarm at exactly our due → equally good, leave it.
        assert!(!alarm_needs_replacing(Some(due), due, now));
        // STALE (already in the past, boundary t == now inclusive):
        // belt-and-braces around a fire — replace it.
        assert!(alarm_needs_replacing(Some(9_000), due, now));
        assert!(alarm_needs_replacing(Some(now), due, now));
    }

    #[test]
    fn classify_pending_row_keeps_decodable_deletes_corrupt() {
        let entry = arm_departure_debounce(ID_A, 10_000);
        assert_eq!(
            classify_pending_row("r1".to_string(), Some(entry.clone())),
            PendingRowAction::Keep("r1".to_string(), entry)
        );
        // Undecodable value (LOW-3): deleted on sight, never leaked.
        assert_eq!(
            classify_pending_row("r2".to_string(), None),
            PendingRowAction::DeleteCorrupt("r2".to_string())
        );
    }

    /// (1) A watchdog self-heal flap (leave, rejoin ~1.5s later) inside
    /// the debounce window must produce ZERO peerLeft pushes.
    #[test]
    fn flap_within_debounce_window_pushes_nothing() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.advance_to(1_000);
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A);
        sim.advance_to(11_500); // ~1.5s gap — the real flap profile
        sim.join(&room);
        sim.advance_to(60_000); // let any scheduled trailing check fire
        assert_eq!(
            sim.pushes.len(),
            0,
            "a self-heal flap must not notify the peer, got: {:?}",
            sim.pushes
        );
    }

    /// (2) A sustained departure pushes EXACTLY ONCE, only after the
    /// debounce window, with `lastseen` stamped at the ORIGINAL departure
    /// time (#225 final-heartbeat semantics — never re-stamped at fire).
    #[test]
    fn sustained_departure_pushes_exactly_once_after_window() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.advance_to(1_000);
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A);
        sim.advance_to(120_000);
        assert_eq!(sim.pushes.len(), 1, "exactly one push, got: {:?}", sim.pushes);
        let (p_room, p_leaver, p_at) = &sim.pushes[0];
        assert_eq!(p_room, &room);
        assert_eq!(p_leaver, ID_A);
        assert!(
            *p_at >= 10_000 + PEER_LEFT_DEBOUNCE_MS,
            "push must wait out the debounce window; pushed at {p_at}"
        );
        assert_eq!(
            sim.lastseen[&room], 10_000,
            "lastseen must carry the ORIGINAL departure time, not the fire time"
        );
    }

    /// (3) Two rapid leave/rejoin cycles — still zero pushes.
    #[test]
    fn two_rapid_flap_cycles_push_nothing() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A);
        sim.advance_to(11_000);
        sim.join(&room);
        sim.advance_to(12_000);
        sim.depart(&room, ID_A);
        sim.advance_to(13_000);
        sim.join(&room);
        sim.advance_to(60_000);
        assert_eq!(
            sim.pushes.len(),
            0,
            "rapid flap cycles must stay silent, got: {:?}",
            sim.pushes
        );
    }

    /// (4) Departure → rejoin → FINAL departure: exactly one push, timed
    /// from the LAST departure (trailing edge), not the first.
    #[test]
    fn rejoin_then_final_departure_times_from_last_departure() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A); // first departure (a flap)
        sim.advance_to(11_000);
        sim.join(&room); // flap rejoin
        sim.advance_to(12_000);
        sim.depart(&room, ID_A); // FINAL departure
        sim.advance_to(120_000);
        assert_eq!(sim.pushes.len(), 1, "exactly one push, got: {:?}", sim.pushes);
        let (_, _, p_at) = &sim.pushes[0];
        assert!(
            *p_at >= 12_000 + PEER_LEFT_DEBOUNCE_MS,
            "push must be timed from the LAST departure (>= {}), got {p_at}",
            12_000 + PEER_LEFT_DEBOUNCE_MS
        );
    }

    /// (5) An explicit goodbye is an app-level MESSAGE (rides the
    /// `/internal/push` fan-out), not presence — it must keep full
    /// immediacy. The real claim is REACHABILITY: nothing on the
    /// message path calls into the debounced departure notify. This
    /// pointer test pins the producer set of `maybe_notify_peer_left`
    /// against the actual source, so any new call site (e.g. someone
    /// wiring it into a send/push handler) breaks the build's tests and
    /// forces a review of the goodbye-immediacy claim. Current
    /// producers, all DEPARTURES:
    ///   1. dispatch_event / ClientEvent::LeaveRoom   (raw-WS leaveRoom)
    ///   2. dispatch_socketio_event "leaveRoom"       (socket.io leaveRoom)
    ///   3. handle_socketio_unregister                (socket.io disconnect)
    ///   4. teardown_departed_socket                  (WS close/error)
    #[test]
    fn goodbye_immediacy_no_debounce_on_the_message_path() {
        let src = include_str!("message_hub.rs");
        // Needles are assembled at runtime so these literals don't count
        // themselves as call sites.
        let notify_needle = format!(".{}(", "maybe_notify_peer_left");
        let push_needle = format!(".{}(", "push_peer_left");
        let call_sites = src.matches(notify_needle.as_str()).count();
        assert_eq!(
            call_sites, 4,
            "maybe_notify_peer_left producer set changed (expected the 4 \
             departure producers) — if the new caller is on a message/send \
             path, explicit goodbyes just lost their immediacy; re-review \
             and update this test's producer list"
        );
        // And the debounced push itself must only ever be reachable from
        // the departure pipeline: the arm/alarm fallbacks + the alarm
        // trailing check.
        let push_sites = src.matches(push_needle.as_str()).count();
        assert_eq!(
            push_sites, 3,
            "push_peer_left caller set changed (expected: put-failure \
             fallback, alarm-arm-failure fallback, alarm trailing check)"
        );
    }

    /// Multi-tab: departing ONE of two live sessions is suppressed by
    /// the `room_still_occupied` gate (no pending armed, no push, ever);
    /// only the LAST session's departure arms the debounce. The
    /// `lastseen` stamp still lands on EVERY departure (#225).
    #[test]
    fn multi_session_departure_is_suppressed_until_last() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room); // tab 1
        sim.join(&room); // tab 2
        sim.advance_to(10_000);
        sim.depart(&room, ID_A); // tab 1 leaves — tab 2 still seated
        assert!(sim.pending.is_empty(), "not the last session — nothing armed");
        assert!(sim.alarm_at.is_none());
        assert_eq!(sim.lastseen[&room], 10_000, "departure still stamps lastseen");
        sim.advance_to(60_000);
        assert_eq!(sim.pushes.len(), 0, "no push while a session remains");
        sim.depart(&room, ID_A); // tab 2 — the LAST session
        sim.advance_to(120_000);
        assert_eq!(sim.pushes.len(), 1, "last-session departure pushes once");
        assert!(sim.pushes[0].2 >= 60_000 + PEER_LEFT_DEBOUNCE_MS);
    }

    /// MED-1(a)+LOW-1: a pendingleft PUT failure falls back to the
    /// immediate push AND deletes any stale prior entry — the stale
    /// entry must not fire a SECOND push at its original due time.
    #[test]
    fn put_failure_falls_back_to_one_immediate_push_no_double() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A); // armed ok, due 14_000
        sim.advance_to(11_000);
        sim.join(&room); // flap rejoin — entry left for the trailing check
        sim.advance_to(12_000);
        sim.put_fails_once = true;
        sim.depart(&room, ID_A); // put fails → immediate push + stale delete
        assert_eq!(
            sim.pushes,
            vec![(room.clone(), ID_A.to_string(), 12_000)],
            "fallback pushes immediately"
        );
        sim.advance_to(120_000); // past the stale entry's original due
        assert_eq!(
            sim.pushes.len(),
            1,
            "the stale prior entry must NOT fire a second push, got: {:?}",
            sim.pushes
        );
    }

    /// MED-1(a): entry stored but the alarm cannot be scheduled — the
    /// trailing check would never run, so the fallback un-stores the
    /// entry and pushes immediately (exactly once).
    #[test]
    fn alarm_schedule_failure_falls_back_to_one_immediate_push() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room);
        sim.advance_to(10_000);
        sim.alarm_fails_once = true;
        sim.depart(&room, ID_A);
        assert_eq!(
            sim.pushes,
            vec![(room.clone(), ID_A.to_string(), 10_000)],
            "no wake guaranteed → push now"
        );
        assert!(sim.pending.is_empty(), "entry un-stored — nothing can double-fire");
        sim.advance_to(120_000);
        assert_eq!(sim.pushes.len(), 1);
    }

    /// MED-1(b): an unreadable pendingleft list at alarm time must not
    /// consume the wake — the alarm re-arms one window out and the
    /// stored entry still fires (late, exactly once).
    #[test]
    fn list_failure_rearms_retry_instead_of_stranding_entries() {
        let room = sim_room_a();
        let mut sim = PresenceSim::default();
        sim.join(&room);
        sim.advance_to(10_000);
        sim.depart(&room, ID_A); // due 14_000
        sim.list_fails_once = true; // the 14_000 fire can't read the list
        sim.advance_to(120_000);
        assert_eq!(
            sim.pushes.len(),
            1,
            "entry must survive the failed list and fire on the retry, got: {:?}",
            sim.pushes
        );
        assert_eq!(
            sim.pushes[0].2,
            14_000 + PEER_LEFT_DEBOUNCE_MS,
            "retry fires one window after the failed wake"
        );
    }

    /// (6) Debounce state is keyed per room: a sustained departure in one
    /// room pushes once; a flap in another room stays silent.
    #[test]
    fn debounce_state_is_per_room() {
        let room_a = sim_room_a();
        let room_b = format!("{ID_A}-low_game_0ddba11");
        let mut sim = PresenceSim::default();
        sim.join(&room_a);
        sim.join(&room_b);
        sim.advance_to(10_000);
        sim.depart(&room_a, ID_A); // sustained
        sim.advance_to(10_500);
        sim.depart(&room_b, ID_A); // flap...
        sim.advance_to(11_500);
        sim.join(&room_b); // ...rejoined
        sim.advance_to(120_000);
        assert_eq!(
            sim.pushes.len(),
            1,
            "only the sustained room may push, got: {:?}",
            sim.pushes
        );
        assert_eq!(sim.pushes[0].0, room_a);
    }
}

#[cfg(test)]
mod parked_peer_left_tests {
    use super::*;

    #[test]
    fn a_parked_departure_is_fresh_inside_the_ttl_and_stale_past_it() {
        assert!(parked_peer_left_is_fresh(1_000, 1_000));
        assert!(parked_peer_left_is_fresh(1_000, 1_000 + PARKED_PEER_LEFT_TTL_MS));
        assert!(!parked_peer_left_is_fresh(1_000, 1_000 + PARKED_PEER_LEFT_TTL_MS + 1));
        assert!(parked_peer_left_is_fresh(5_000, 1_000)); // a clock that went backwards never drops news
    }

    #[test]
    fn a_parked_arrival_is_delivered_unless_the_peer_left_again_or_it_went_stale() {
        use ParkedChoice::*;
        use ToldPresence::*;
        let now = 1_000_000; // comfortably past the TTL so the stale case cannot underflow
        // the dealtLeaveNotifyRejoin shape: the arrival parked, told=Present, nothing else parked
        assert_eq!(parked_presence_choice(None, Some(now - 5_000), Some(Present), now), Joined);
        // the peer left AGAIN after arriving: the arrival is not news any more
        assert_eq!(parked_presence_choice(None, Some(now - 5_000), Some(Absent), now), Nothing);
        // stale past the TTL
        assert_eq!(parked_presence_choice(None, Some(now - PARKED_PEER_LEFT_TTL_MS - 1), Some(Present), now), Nothing);
        // 0.3.15's rule kept: a parked departure is dropped once the peer came back
        assert_eq!(parked_presence_choice(Some(now - 5_000), None, Some(Present), now), Nothing);
        assert_eq!(parked_presence_choice(Some(now - 5_000), None, Some(Absent), now), Left);
        // both parked, no told-state at all: the newer one is the news
        assert_eq!(parked_presence_choice(Some(now - 9_000), Some(now - 5_000), None, now), Joined);
        assert_eq!(parked_presence_choice(Some(now - 5_000), Some(now - 9_000), None, now), Left);
        // nothing parked
        assert_eq!(parked_presence_choice(None, None, Some(Present), now), Nothing);
    }
}

#[cfg(test)]
mod departure_signals_tests {
    use super::*;

    const OWNER: &str = "02d09d2feb33d5a17f426fd3d0c5c1a45c87961ece4c095fd111d37c7b2b0b4090";
    const GID: &str = "1a3f5099ce9c7bb1751339a9ff5933f56921278eb3228e0b00992b98b1747a55";

    #[test]
    fn a_clean_leave_of_any_room_signals_nothing_but_a_socket_close_does() {
        let lobby = format!("{OWNER}-low_lobby_{GID}");
        let game = format!("{OWNER}-low_game_{GID}");
        // EVERY room: only a socket CLOSE (crash / heartbeat timeout) signals.
        // A clean leaveRoom is a room HOP (a lobby match/cancel, the felt's
        // watchdog re-listen) and never a departure — 0.3.15.
        assert!(!departure_signals(&lobby, false));
        assert!(departure_signals(&lobby, true));
        assert!(!departure_signals(&game, false));
        assert!(departure_signals(&game, true));
    }
}
