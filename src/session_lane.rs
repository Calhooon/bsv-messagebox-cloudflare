//! THE SESSION LANE (bsv-low W-B, register row D10, 2026-09-09).
//!
//! One BRC-103 handshake per connection, then a SESSION: the relay mints a
//! 32-byte id and a salt when the handshake completes, both sides derive one
//! secret `K` from the salt, the id and the handshake's own nonces (never on
//! the wire), and every later frame carries a counter and an HMAC-SHA256 over
//! `(counter ‖ event ‖ sha256(data))` keyed by `K` — computed in wasm here and
//! in JS there, ZERO wallet calls per frame. A frame whose counter is not
//! strictly greater than the last accepted one is a REPLAY; a frame whose MAC
//! does not verify, whose session is unknown or whose session has expired is
//! refused with its reason. A client that never presents a session is served
//! on the reference lane (every frame a signed BRC-103 General), forever.
//!
//! THE HTTP LANE. An in-session HTTP call (`/listMessages`,
//! `/acknowledgeMessage`, the `/sendMessage` fallback) carries the same proof
//! as headers: `x-low-session` (the id), `x-low-session-identity`,
//! `x-low-session-n` (the client's HTTP counter `h`, its own sequence) and
//! `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖ "METHOD path?query" ‖ 0x00 ‖
//! sha256(body))`. The Worker resolves the id through the identity's hub DO,
//! which holds a MIRROR of the lane (`HubMirror`: registered by the socket DO
//! on the first frame the client sends on the socket lane, refreshed on later
//! ones, revoked when the socket closes) and verifies the counter and the MAC;
//! the answer is sealed with `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖
//! "response" ‖ 0x00 ‖ sha256(body))` under the request's own `h`. A refusal
//! is 401 `ERR_SESSION_REFUSED {reason}`; the client falls back to BRC-104
//! for that call and re-handshakes. The mirror's idle window is refreshed by
//! both lanes; the socket lane's own window only by socket frames (the socket
//! DO never learns of an HTTP call), so an HTTP-only hour ends in one
//! `expired` refusal on the next socket frame and a re-handshake: self-healing.
//!
//! Pure: no I/O, no clock reads — the caller passes `now_ms` — so every rule
//! is unit-pinned here and the wasm host (`engineio/session.rs`) only wires
//! it. The MAC vectors are PRODUCED here (`emit_session_mac_vectors`) and
//! pinned byte-for-byte by the client (`app/src/lib/relaySession.vectors.test.ts`):
//! the artifact is shared, never the convention.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// The domain separator inside `K`'s derivation.
pub const KEY_DERIVATION_LABEL: &[u8] = b"low-relay-session/v1";
/// A session expires this long after its last valid frame (either direction).
pub const SESSION_IDLE_MS: u64 = 60 * 60 * 1000;
/// A lane lives at most this long from its mint however busy it is (D12's
/// posture, matched here for the relay's own lane and its hub mirror: the
/// 2026-09-14 gate's M5). Past it every frame, seal and HTTP call is refused
/// `expired` and the client re-handshakes once. Chaining across socket
/// generations (an attach mints a NEW lane from the hub lane's proof) does
/// not extend the hub lane: the mirror keeps the FIRST handshake's mint time.
pub const LANE_MAX_LIFETIME_MS: u64 = 12 * 60 * 60 * 1000;
/// The socket.io event a session-aware client sends its frames on.
pub const INBOUND_EVENT: &str = "sessionMessage";
/// The socket.io event the relay delivers on once the lane is active.
pub const OUTBOUND_EVENT: &str = "sessionEvent";
/// The socket.io event a refusal rides (a signed General on the reference
/// lane: the client may hold no valid session to verify a MAC with).
pub const REFUSED_EVENT: &str = "sessionRefused";
/// The HTTP lane's headers (request: the four; response: the last two).
pub const SESSION_HEADER: &str = "x-low-session";
pub const SESSION_IDENTITY_HEADER: &str = "x-low-session-identity";
pub const SESSION_COUNTER_HEADER: &str = "x-low-session-n";
/// The largest counter a laned call may carry: `Number.MAX_SAFE_INTEGER`. The
/// ask rides to the hub as a JSON number (`req.json()` = JSON.parse then
/// serde-wasm-bindgen), which faults above 2^53 — a crafted header would turn
/// into a hub fault (`reason=storage`, a lane the client drops) instead of a
/// refusal by name (0.3.26, bsv-low #493's review MED, #496).
pub const MAX_SAFE_COUNTER: u64 = (1u64 << 53) - 1;

/// The `x-low-session-n` header as a counter: decimal digits, at most
/// `MAX_SAFE_COUNTER`; anything else is malformed. PURE.
pub fn parse_counter(v: &str) -> Option<u64> {
    v.trim()
        .parse::<u64>()
        .ok()
        .filter(|h| *h <= MAX_SAFE_COUNTER)
}
pub const SESSION_MAC_HEADER: &str = "x-low-session-mac";
/// The event name inside a response's MAC.
pub const HTTP_RESPONSE_EVENT: &str = "response";
/// The HTTP lane's refusal code (401).
pub const HTTP_REFUSED_CODE: &str = "ERR_SESSION_REFUSED";
/// The hub mirror's idle window is re-written only when the lane's window
/// moved past this much (one storage write per minute per lane at most,
/// instead of one per frame).
pub const MIRROR_REFRESH_SLACK_MS: u64 = 60 * 1000;

/// The session record the socket DO persists (in its attachment) and mirrors
/// into the identity's hub (for the HTTP lane).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLane {
    /// 32 random bytes, hex.
    pub id: String,
    /// The derived secret `K`, hex (never on the wire).
    pub key: String,
    /// The verified BRC-103 identity the lane belongs to.
    pub identity: String,
    /// ms epoch after which every frame is refused (`Expired`); refreshed
    /// on every valid frame.
    pub expires_at_ms: u64,
    /// ms epoch of the mint: the lane is refused past `minted_at_ms +
    /// LANE_MAX_LIFETIME_MS` whatever the idle window says. `0` on a lane
    /// persisted before this field existed = past the lifetime (a deploy
    /// closes every socket anyway; one handshake re-mints).
    #[serde(default)]
    pub minted_at_ms: u64,
    /// The last counter accepted from the client on the socket lane.
    pub last_in: u64,
    /// The next counter the relay stamps on a delivery.
    pub next_out: u64,
    /// Whether the client has sent at least one valid frame: deliveries go
    /// out as `sessionEvent` only from then on (before that the client may
    /// be a reference client that will never read one).
    pub active: bool,
}

/// What the handshake's last message carries to a session-aware client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOffer {
    pub id: String,
    #[serde(rename = "expiresAt")]
    pub expires_at_ms: u64,
    pub salt: String,
    /// The client's ask id (`laneAsk` in its `authenticated` payload), echoed
    /// so the client binds the lane to ITS OWN ask: the SDK's own
    /// `authenticated` never mints, and two offers in flight (the handshake's
    /// Generals are verified asynchronously on the client and can complete
    /// out of order) can never leave the two sides holding different lanes
    /// (the traced hand of 2026-09-09 21:36Z: seven mints, a cascade of
    /// unknown-session refusals).
    pub ask: String,
}

/// A frame on the lane, either direction: `{ s?, n, e, d, m }` where `d` is
/// the event's data as the JSON TEXT the sender transmitted (so both sides
/// hash the same bytes; no canonicalisation) and `m` is the MAC, hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// The session id (inbound only; a delivery rides the socket it belongs to).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    pub n: u64,
    pub e: String,
    pub d: String,
    pub m: String,
}

/// Why a frame was refused. Every reason is said and counted, never silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    /// No session on this socket, or the frame names another session.
    UnknownSession,
    /// The session's idle window elapsed.
    Expired,
    /// The counter is not strictly greater than the last accepted one.
    Replay,
    /// The MAC does not verify under `K`.
    BadMac,
    /// The frame is not the lane's shape.
    Malformed,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::UnknownSession => "unknown-session",
            Refusal::Expired => "expired",
            Refusal::Replay => "replay",
            Refusal::BadMac => "bad-mac",
            Refusal::Malformed => "malformed",
        }
    }
}

/// `K = HMAC-SHA256(key = salt, data = label ‖ id ‖ client_nonce ‖ server_nonce)`.
/// The nonces are the BRC-103 handshake's own (base64 text as exchanged);
/// only the two handshake parties hold both.
pub fn derive_key(
    salt: &[u8; 32],
    id: &[u8; 32],
    client_nonce: &str,
    server_nonce: &str,
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(KEY_DERIVATION_LABEL);
    mac.update(id);
    mac.update(client_nonce.as_bytes());
    mac.update(server_nonce.as_bytes());
    let out = mac.finalize().into_bytes();
    let mut k = [0u8; 32];
    k.copy_from_slice(&out);
    k
}

/// `m = HMAC-SHA256(K, n as 8 bytes little-endian ‖ e ‖ 0x00 ‖ sha256(d))`.
pub fn frame_mac(key: &[u8; 32], n: u64, e: &str, d: &str) -> [u8; 32] {
    let digest: [u8; 32] = Sha256::digest(d.as_bytes()).into();
    frame_mac_over_digest(key, n, e, &digest)
}

/// The same MAC with the data's digest already taken (the Worker hashes the
/// request's raw body bytes once and ships the digest to the hub).
pub fn frame_mac_over_digest(key: &[u8; 32], n: u64, e: &str, digest: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&n.to_le_bytes());
    mac.update(e.as_bytes());
    mac.update(&[0u8]);
    mac.update(digest);
    let out = mac.finalize().into_bytes();
    let mut m = [0u8; 32];
    m.copy_from_slice(&out);
    m
}

/// The event name inside an HTTP request's MAC: `"METHOD path?query"`, the
/// method upper-cased, the path and query exactly as the client sent them.
pub fn http_event(method: &str, path_and_query: &str) -> String {
    format!("{} {}", method.to_ascii_uppercase(), path_and_query)
}

/// What the socket DO tells the identity's hub about a lane (on the first
/// frame the client sends on it, then whenever the window moved): enough to
/// verify the HTTP lane there. `K` travels DO-to-DO only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MirrorUpdate {
    pub id: String,
    pub key: String,
    // bounded: a millisecond stamp
    pub expires_at_ms: u64,
    /// The lane's mint time (see `SessionLane::minted_at_ms`); `0` from an
    /// older socket DO = past the lifetime.
    #[serde(default)]
    // bounded: a millisecond stamp
    pub minted_at_ms: u64,
}

impl From<&SessionLane> for MirrorUpdate {
    fn from(lane: &SessionLane) -> Self {
        MirrorUpdate {
            id: lane.id.clone(),
            key: lane.key.clone(),
            expires_at_ms: lane.expires_at_ms,
            minted_at_ms: lane.minted_at_ms,
        }
    }
}

/// The identity hub's mirror of a lane: what the HTTP lane verifies against.
/// Its own counter `h` (the client's HTTP sequence), its own copy of the
/// window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HubMirror {
    pub id: String,
    pub key: String,
    pub identity: String,
    // bounded: a millisecond stamp (~1.8e12)
    pub expires_at_ms: u64,
    /// The mint time of the lane this mirrors (the FIRST handshake's; an
    /// attach chains a new socket lane from it and never moves it). `0` on a
    /// mirror persisted before this field = past the lifetime, refused, swept.
    #[serde(default)]
    // bounded: a millisecond stamp (~1.8e12)
    pub minted_at_ms: u64,
    /// The HIGHEST HTTP counter accepted. Rides as a DECIMAL STRING since
    /// 0.3.26 like the mask below: the header bound (`MAX_SAFE_COUNTER`) and
    /// the storage serializer's limit were the same constant on both sides,
    /// zero headroom; a mirror persisted as a number still reads.
    #[serde(with = "u64_as_string")]
    pub last_h: u64,
    /// The replay window below `last_h`: bit `i` set = counter `last_h - i`
    /// was accepted (bit 0 = `last_h` itself). Browser fetches run in
    /// parallel and reach the hub in any order (the second traced hand,
    /// 2026-09-09 21:53Z: `h=2` landed before `h=1` and the strict counter
    /// refused a fresh call as a replay); a window accepts each counter
    /// ONCE, in any order, `HTTP_REPLAY_WINDOW` deep. The socket lane keeps
    /// the strict counter: one socket delivers in order.
    /// 0.3.24 (bsv-low loop 12, 2026-09-20): SERIALIZED AS A DECIMAL STRING. The mirror is persisted through the
    /// Durable Object's storage, whose serializer carries a `u64` as a JavaScript number: once the window's high
    /// bits are set (every lane past its ~53rd HTTP call) the value exceeds `Number.MAX_SAFE_INTEGER`, the put
    /// throws ("18446744073709289473 can't be represented as a JavaScript number"), and the hub answered every
    /// later call on that lane with `reason=storage` — a 401 the client keeps the lane through. Seven identities in
    /// three hours on beta, one honest seat's tower ruling never reaching its felt. A string carries all 64 bits; a
    /// mirror persisted before this reads back from its number.
    #[serde(default, with = "u64_as_string")]
    pub seen_mask: u64,
}

/// `u64` ⇄ a decimal string on the wire (see `HubMirror::seen_mask`); a number is still read (the rows persisted
/// before 0.3.24, all below 2^53 by construction — anything larger never persisted).
pub mod u64_as_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        v.to_string().serialize(s)
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        match NumOrStr::deserialize(d)? {
            NumOrStr::Num(n) => Ok(n),
            NumOrStr::Str(t) => t.parse::<u64>().map_err(serde::de::Error::custom),
        }
    }
}

/// How far below the highest accepted HTTP counter a late call may land.
pub const HTTP_REPLAY_WINDOW: u64 = 64;

impl HubMirror {
    /// The identity is stored lower-cased: every comparison against it (the
    /// verify body's, the attach frame's, the attest's) is over lower-cased hex.
    pub fn new(identity: &str, update: MirrorUpdate) -> Self {
        HubMirror {
            id: update.id,
            key: update.key,
            identity: identity.to_ascii_lowercase(),
            expires_at_ms: update.expires_at_ms,
            minted_at_ms: update.minted_at_ms,
            last_h: 0,
            seen_mask: 0,
        }
    }

    /// Whether a socket-lane refresh is worth a storage write: only when the
    /// lane's window moved past the slack (never backwards).
    pub fn refresh_due(&self, expires_at_ms: u64) -> bool {
        expires_at_ms > self.expires_at_ms.saturating_add(MIRROR_REFRESH_SLACK_MS)
    }

    /// Whether the mirror may still be used at `now_ms`: inside the idle
    /// window AND inside the lane's absolute lifetime.
    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms <= self.expires_at_ms && !self.past_lifetime(now_ms)
    }

    /// See `SessionLane::past_lifetime`.
    pub fn past_lifetime(&self, now_ms: u64) -> bool {
        now_ms > self.minted_at_ms.saturating_add(LANE_MAX_LIFETIME_MS)
    }

    /// Verify one HTTP request: the idle window, the counter (each value
    /// accepted ONCE, in any order within `HTTP_REPLAY_WINDOW` of the highest)
    /// and the MAC over `"METHOD path?query"` and the body's digest. On
    /// success the counter state advances and the idle window is refreshed.
    /// On refusal nothing changes.
    pub fn verify_http(
        &mut self,
        h: u64,
        method: &str,
        path_and_query: &str,
        body_digest: &[u8; 32],
        mac_hex: &str,
        now_ms: u64,
    ) -> Result<(), Refusal> {
        if now_ms > self.expires_at_ms || self.past_lifetime(now_ms) {
            return Err(Refusal::Expired);
        }
        if h == 0 || !self.counter_is_fresh(h) {
            return Err(Refusal::Replay);
        }
        let Some(key) = hex32(&self.key) else {
            return Err(Refusal::UnknownSession);
        };
        let Some(m) = hex32(mac_hex) else {
            return Err(Refusal::Malformed);
        };
        let e = http_event(method, path_and_query);
        let expected = frame_mac_over_digest(&key, h, &e, body_digest);
        if !constant_time_eq(&expected, &m) {
            return Err(Refusal::BadMac);
        }
        self.accept_counter(h);
        self.expires_at_ms = now_ms + SESSION_IDLE_MS;
        Ok(())
    }

    /// Whether `h` has not been accepted yet and lies inside the window.
    fn counter_is_fresh(&self, h: u64) -> bool {
        if h > self.last_h {
            return true;
        }
        let back = self.last_h - h;
        if back >= HTTP_REPLAY_WINDOW {
            return false;
        }
        self.seen_mask & (1u64 << back) == 0
    }

    /// Record `h` as accepted (the caller checked `counter_is_fresh`).
    fn accept_counter(&mut self, h: u64) {
        if h > self.last_h {
            let shift = h - self.last_h;
            self.seen_mask = if shift >= 64 {
                0
            } else {
                self.seen_mask << shift
            };
            self.seen_mask |= 1;
            self.last_h = h;
        } else {
            self.seen_mask |= 1u64 << (self.last_h - h);
        }
    }
}

/// Seal an HTTP response under the request's own counter: the client reads
/// `x-low-session-n` back (the same `h`) and `x-low-session-mac` = this.
pub fn response_mac(key_hex: &str, h: u64, body_text: &str) -> Option<String> {
    let key = hex32(key_hex)?;
    Some(hex::encode(frame_mac(
        &key,
        h,
        HTTP_RESPONSE_EVENT,
        body_text,
    )))
}

/// A bearer presented against the configured one: never the shortcut `!=`
/// (a byte-by-byte early exit leaks the matched prefix by timing); an empty
/// expected bearer matches nothing (an unset secret closes the door).
pub(crate) fn bearer_matches(got: &str, expected: &str) -> bool {
    !expected.is_empty() && constant_time_eq(got.as_bytes(), expected.as_bytes())
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex32(h: &str) -> Option<[u8; 32]> {
    let v = hex::decode(h).ok()?;
    if v.len() != 32 {
        return None;
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Some(a)
}

impl SessionLane {
    /// Mint a lane at the end of a verified handshake. `random` supplies the
    /// id and the salt (32 + 32 bytes; the host draws them from the platform
    /// RNG). Returns the lane (persisted server-side) and the offer (sent to
    /// the client inside the handshake's last General).
    pub fn mint(
        identity: &str,
        client_nonce: &str,
        server_nonce: &str,
        random: &[u8; 64],
        now_ms: u64,
        ask: &str,
    ) -> (SessionLane, SessionOffer) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&random[..32]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&random[32..]);
        let key = derive_key(&salt, &id, client_nonce, server_nonce);
        let expires_at_ms = now_ms + SESSION_IDLE_MS;
        let lane = SessionLane {
            id: hex::encode(id),
            key: hex::encode(key),
            identity: identity.to_string(),
            expires_at_ms,
            minted_at_ms: now_ms,
            last_in: 0,
            next_out: 1,
            active: false,
        };
        let offer = SessionOffer {
            id: lane.id.clone(),
            expires_at_ms,
            salt: hex::encode(salt),
            ask: ask.to_string(),
        };
        (lane, offer)
    }

    fn key_bytes(&self) -> Option<[u8; 32]> {
        hex32(&self.key)
    }

    /// Verify an inbound frame: the session id, the idle window, the counter
    /// (strictly increasing) and the MAC. On success the counter advances,
    /// the idle window is refreshed and the lane is ACTIVE; the event name
    /// and its data TEXT are returned for routing. On refusal nothing
    /// changes.
    pub fn verify_inbound(
        &mut self,
        frame: &Frame,
        now_ms: u64,
    ) -> Result<(String, String), Refusal> {
        let Some(s) = frame.s.as_deref() else {
            return Err(Refusal::Malformed);
        };
        if !constant_time_eq(s.as_bytes(), self.id.as_bytes()) {
            return Err(Refusal::UnknownSession);
        }
        if now_ms > self.expires_at_ms || self.past_lifetime(now_ms) {
            return Err(Refusal::Expired);
        }
        if frame.n <= self.last_in {
            return Err(Refusal::Replay);
        }
        let Some(key) = self.key_bytes() else {
            return Err(Refusal::UnknownSession);
        };
        let Some(m) = hex32(&frame.m) else {
            return Err(Refusal::Malformed);
        };
        let expected = frame_mac(&key, frame.n, &frame.e, &frame.d);
        if !constant_time_eq(&expected, &m) {
            return Err(Refusal::BadMac);
        }
        self.last_in = frame.n;
        self.expires_at_ms = now_ms + SESSION_IDLE_MS;
        self.active = true;
        Ok((frame.e.clone(), frame.d.clone()))
    }

    /// Seal an outbound delivery: the relay's own counter (strictly
    /// increasing per lane) and the MAC over the event and its data TEXT.
    pub fn seal_outbound(&mut self, e: &str, d: &str, now_ms: u64) -> Option<Frame> {
        if self.past_lifetime(now_ms) {
            return None;
        }
        let key = self.key_bytes()?;
        let n = self.next_out;
        self.next_out += 1;
        self.expires_at_ms = now_ms + SESSION_IDLE_MS;
        Some(Frame {
            s: None,
            n,
            e: e.to_string(),
            d: d.to_string(),
            m: hex::encode(frame_mac(&key, n, e, d)),
        })
    }

    /// Whether the lane may still be used at `now_ms`: inside the idle window
    /// AND inside the absolute lifetime.
    pub fn is_live(&self, now_ms: u64) -> bool {
        now_ms <= self.expires_at_ms && !self.past_lifetime(now_ms)
    }

    /// Whether the lane's absolute lifetime has elapsed (`LANE_MAX_LIFETIME_MS`
    /// from the mint; a missing mint time is past it).
    pub fn past_lifetime(&self, now_ms: u64) -> bool {
        now_ms > self.minted_at_ms.saturating_add(LANE_MAX_LIFETIME_MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_NONCE: &str = "Y2xpZW50LW5vbmNlLWJhc2U2NA==";
    const SERVER_NONCE: &str = "c2VydmVyLW5vbmNlLWJhc2U2NA==";
    const IDENTITY: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixed_random() -> [u8; 64] {
        let mut r = [0u8; 64];
        for (i, b) in r.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        r
    }

    const ASK: &str = "a1b2c3d4e5f60718";

    fn minted() -> (SessionLane, SessionOffer) {
        SessionLane::mint(
            IDENTITY,
            CLIENT_NONCE,
            SERVER_NONCE,
            &fixed_random(),
            1_000,
            ASK,
        )
    }

    fn client_frame(lane: &SessionLane, n: u64, e: &str, d: &str) -> Frame {
        let key = hex32(&lane.key).unwrap();
        Frame {
            s: Some(lane.id.clone()),
            n,
            e: e.into(),
            d: d.into(),
            m: hex::encode(frame_mac(&key, n, e, d)),
        }
    }

    #[test]
    fn mint_binds_the_identity_and_derives_k_from_the_handshake_nonces_and_the_salt() {
        let (lane, offer) = minted();
        assert_eq!(lane.identity, IDENTITY);
        assert_eq!(lane.id, offer.id);
        assert_eq!(lane.id.len(), 64);
        assert_eq!(offer.salt.len(), 64);
        assert_eq!(offer.expires_at_ms, 1_000 + SESSION_IDLE_MS);
        assert!(!lane.active);
        assert_eq!(lane.last_in, 0);
        assert_eq!(lane.next_out, 1);
        // K is a function of ALL four inputs: change any one and K changes.
        let salt = hex32(&offer.salt).unwrap();
        let id = hex32(&offer.id).unwrap();
        let k = derive_key(&salt, &id, CLIENT_NONCE, SERVER_NONCE);
        assert_eq!(hex::encode(k), lane.key);
        assert_ne!(
            hex::encode(derive_key(&salt, &id, "other", SERVER_NONCE)),
            lane.key
        );
        assert_ne!(
            hex::encode(derive_key(&salt, &id, CLIENT_NONCE, "other")),
            lane.key
        );
        let mut other_salt = salt;
        other_salt[0] ^= 1;
        assert_ne!(
            hex::encode(derive_key(&other_salt, &id, CLIENT_NONCE, SERVER_NONCE)),
            lane.key
        );
        // The offer never carries K; it echoes the ask it answers.
        let offer_json = serde_json::to_string(&offer).unwrap();
        assert!(!offer_json.contains(&lane.key));
        assert_eq!(offer.ask, ASK);
        assert!(offer_json.contains("\"ask\":\"a1b2c3d4e5f60718\""));
    }

    #[test]
    fn a_good_frame_is_accepted_advances_the_counter_refreshes_the_window_and_activates_the_lane() {
        let (mut lane, _) = minted();
        let f = client_frame(&lane, 1, "joinRoom", "\"02aa-low_inbox\"");
        let (e, d) = lane.verify_inbound(&f, 5_000).expect("a good frame passes");
        assert_eq!(e, "joinRoom");
        assert_eq!(d, "\"02aa-low_inbox\"");
        assert_eq!(lane.last_in, 1);
        assert!(lane.active);
        assert_eq!(lane.expires_at_ms, 5_000 + SESSION_IDLE_MS);
        let f2 = client_frame(&lane, 7, "sendMessage", "{\"roomId\":\"r\"}");
        lane.verify_inbound(&f2, 6_000)
            .expect("a later counter passes (gaps are fine)");
        assert_eq!(lane.last_in, 7);
    }

    #[test]
    fn a_replayed_or_older_counter_is_refused_and_changes_nothing() {
        let (mut lane, _) = minted();
        let f = client_frame(&lane, 3, "joinRoom", "\"r\"");
        lane.verify_inbound(&f, 5_000).unwrap();
        let before = lane.clone();
        assert_eq!(
            lane.verify_inbound(&f, 6_000),
            Err(Refusal::Replay),
            "the same frame again"
        );
        let older = client_frame(&lane, 2, "joinRoom", "\"r\"");
        assert_eq!(lane.verify_inbound(&older, 6_000), Err(Refusal::Replay));
        assert_eq!(lane, before, "a refusal leaves the lane untouched");
    }

    #[test]
    fn a_bad_mac_a_tampered_event_or_tampered_data_is_refused() {
        let (mut lane, _) = minted();
        let good = client_frame(&lane, 1, "sendMessage", "{\"roomId\":\"r\"}");
        let mut bad = good.clone();
        bad.m = hex::encode([0u8; 32]);
        assert_eq!(lane.verify_inbound(&bad, 5_000), Err(Refusal::BadMac));
        let mut event_swapped = good.clone();
        event_swapped.e = "leaveRoom".into();
        assert_eq!(
            lane.verify_inbound(&event_swapped, 5_000),
            Err(Refusal::BadMac)
        );
        let mut data_swapped = good.clone();
        data_swapped.d = "{\"roomId\":\"other\"}".into();
        assert_eq!(
            lane.verify_inbound(&data_swapped, 5_000),
            Err(Refusal::BadMac)
        );
        let mut counter_swapped = good.clone();
        counter_swapped.n = 2;
        assert_eq!(
            lane.verify_inbound(&counter_swapped, 5_000),
            Err(Refusal::BadMac),
            "the counter is under the MAC"
        );
        assert!(!lane.active, "no refusal activates the lane");
        lane.verify_inbound(&good, 5_000)
            .expect("the untampered frame still passes after the refusals");
    }

    #[test]
    fn an_unknown_session_id_or_a_malformed_frame_is_refused() {
        let (mut lane, _) = minted();
        let mut foreign = client_frame(&lane, 1, "joinRoom", "\"r\"");
        foreign.s = Some(hex::encode([9u8; 32]));
        assert_eq!(
            lane.verify_inbound(&foreign, 5_000),
            Err(Refusal::UnknownSession)
        );
        let mut nameless = client_frame(&lane, 1, "joinRoom", "\"r\"");
        nameless.s = None;
        assert_eq!(
            lane.verify_inbound(&nameless, 5_000),
            Err(Refusal::Malformed)
        );
        let mut short_mac = client_frame(&lane, 1, "joinRoom", "\"r\"");
        short_mac.m = "abcd".into();
        assert_eq!(
            lane.verify_inbound(&short_mac, 5_000),
            Err(Refusal::Malformed)
        );
    }

    #[test]
    fn an_expired_lane_refuses_and_a_valid_frame_refreshes_the_idle_window() {
        let (mut lane, _) = minted();
        let f = client_frame(&lane, 1, "joinRoom", "\"r\"");
        let late = 1_000 + SESSION_IDLE_MS + 1;
        assert_eq!(lane.verify_inbound(&f, late), Err(Refusal::Expired));
        assert!(!lane.is_live(late));
        // Inside the window: accepted, and the window moves.
        let mut fresh = minted().0;
        let f = client_frame(&fresh, 1, "joinRoom", "\"r\"");
        fresh
            .verify_inbound(&f, 1_000 + SESSION_IDLE_MS - 1)
            .unwrap();
        assert_eq!(
            fresh.expires_at_ms,
            1_000 + SESSION_IDLE_MS - 1 + SESSION_IDLE_MS
        );
    }

    #[test]
    fn outbound_frames_carry_a_strictly_increasing_relay_counter_and_verify_under_k() {
        let (mut lane, _) = minted();
        let a = lane
            .seal_outbound("sendMessage-r", "{\"messageId\":\"m1\"}", 5_000)
            .unwrap();
        let b = lane.seal_outbound("presence", "[]", 5_000).unwrap();
        assert_eq!(a.n, 1);
        assert_eq!(b.n, 2);
        assert!(a.s.is_none(), "a delivery rides the socket it belongs to");
        let key = hex32(&lane.key).unwrap();
        assert_eq!(
            a.m,
            hex::encode(frame_mac(
                &key,
                1,
                "sendMessage-r",
                "{\"messageId\":\"m1\"}"
            ))
        );
        assert_ne!(a.m, b.m);
        // The wire shape the client parses: no `s` key at all on a delivery.
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("\"s\""));
        assert!(json.contains("\"n\":1"));
    }

    #[test]
    fn refusal_reasons_are_stable_wire_words() {
        for (r, w) in [
            (Refusal::UnknownSession, "unknown-session"),
            (Refusal::Expired, "expired"),
            (Refusal::Replay, "replay"),
            (Refusal::BadMac, "bad-mac"),
            (Refusal::Malformed, "malformed"),
        ] {
            assert_eq!(r.as_str(), w);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{w}\""));
        }
    }

    /// The MAC vectors the CLIENT pins byte-for-byte (Rule 16: share the
    /// artifact). Regenerate with
    /// `cargo test session_lane::tests::emit_session_mac_vectors -- --ignored`
    /// and copy `tests/fixtures/session_mac.vectors.json` to
    /// `app/src/lib/fixtures/session_mac.vectors.json` in bsv-low.
    fn mirror() -> HubMirror {
        let (lane, _) = minted();
        HubMirror::new(IDENTITY, MirrorUpdate::from(&lane))
    }

    fn http_mac(m: &HubMirror, h: u64, method: &str, path: &str, body: &str) -> String {
        let key = hex32(&m.key).unwrap();
        hex::encode(frame_mac(&key, h, &http_event(method, path), body))
    }

    fn digest(body: &str) -> [u8; 32] {
        Sha256::digest(body.as_bytes()).into()
    }

    #[test]
    fn a_good_http_request_advances_h_and_refreshes_the_mirrors_window() {
        let mut m = mirror();
        assert!(!m.is_live(m.expires_at_ms + 1));
        let body = "{\"messageBox\":\"low_inbox\"}";
        let mac = http_mac(&m, 1, "post", "/listMessages", body);
        let now = 5_000;
        assert_eq!(
            m.verify_http(1, "POST", "/listMessages", &digest(body), &mac, now),
            Ok(())
        );
        assert_eq!(m.last_h, 1);
        assert_eq!(m.expires_at_ms, now + SESSION_IDLE_MS);
        // The method is case-insensitive on the wire, the path is not.
        let mac7 = http_mac(&m, 7, "POST", "/presence?room=02aa-low_game_1", "");
        assert_eq!(
            m.verify_http(
                7,
                "get",
                "/presence?room=02aa-low_game_1",
                &digest(""),
                &mac7,
                now
            ),
            Err(Refusal::BadMac),
            "the method is bound"
        );
        let mac7 = http_mac(&m, 7, "GET", "/presence?room=02aa-low_game_1", "");
        assert_eq!(
            m.verify_http(
                7,
                "get",
                "/presence?room=02aa-low_game_1",
                &digest(""),
                &mac7,
                now
            ),
            Ok(())
        );
        assert_eq!(m.last_h, 7);
    }

    #[test]
    fn an_http_replay_a_bad_mac_a_wrong_path_a_wrong_body_or_an_expired_mirror_is_refused() {
        let mut m = mirror();
        let body = "{\"messageIds\":[\"m1\"]}";
        let mac = http_mac(&m, 3, "POST", "/acknowledgeMessage", body);
        assert_eq!(
            m.verify_http(3, "POST", "/acknowledgeMessage", &digest(body), &mac, 5_000),
            Ok(())
        );
        let before = m.clone();
        // The same counter twice is a replay (an OLDER counter not yet seen is
        // a late parallel call: the window pin below).
        assert_eq!(
            m.verify_http(3, "POST", "/acknowledgeMessage", &digest(body), &mac, 6_000),
            Err(Refusal::Replay)
        );
        let mac4 = http_mac(&m, 4, "POST", "/acknowledgeMessage", body);
        assert_eq!(
            m.verify_http(4, "POST", "/listMessages", &digest(body), &mac4, 6_000),
            Err(Refusal::BadMac)
        );
        assert_eq!(
            m.verify_http(
                4,
                "POST",
                "/acknowledgeMessage",
                &digest("{}"),
                &mac4,
                6_000
            ),
            Err(Refusal::BadMac)
        );
        let mut flipped = hex::decode(&mac4).unwrap();
        flipped[0] ^= 1;
        assert_eq!(
            m.verify_http(
                4,
                "POST",
                "/acknowledgeMessage",
                &digest(body),
                &hex::encode(flipped),
                6_000
            ),
            Err(Refusal::BadMac)
        );
        assert_eq!(
            m.verify_http(4, "POST", "/acknowledgeMessage", &digest(body), "zz", 6_000),
            Err(Refusal::Malformed)
        );
        assert_eq!(m, before, "a refusal changes nothing");
        assert_eq!(
            m.verify_http(
                4,
                "POST",
                "/acknowledgeMessage",
                &digest(body),
                &mac4,
                m.expires_at_ms + 1
            ),
            Err(Refusal::Expired)
        );
    }

    /// Browser fetches run in parallel: `h=2` may reach the hub before `h=1`.
    /// Each counter is accepted ONCE, in any order inside the window; a
    /// counter that far behind, or seen already, is a replay.
    #[test]
    fn http_counters_are_accepted_once_each_in_any_order_inside_the_window() {
        let mut m = mirror();
        let body = "{}";
        let call = |m: &mut HubMirror, h: u64| {
            let mac = http_mac(m, h, "POST", "/acknowledgeMessage", body);
            m.verify_http(h, "POST", "/acknowledgeMessage", &digest(body), &mac, 5_000)
        };
        assert_eq!(call(&mut m, 2), Ok(()));
        assert_eq!(call(&mut m, 1), Ok(()), "the late h=1 is accepted");
        assert_eq!(call(&mut m, 1), Err(Refusal::Replay), "but only once");
        assert_eq!(call(&mut m, 2), Err(Refusal::Replay));
        assert_eq!(call(&mut m, 5), Ok(()));
        assert_eq!(call(&mut m, 3), Ok(()));
        assert_eq!(call(&mut m, 4), Ok(()));
        assert_eq!(call(&mut m, 3), Err(Refusal::Replay));
        assert_eq!(m.last_h, 5);
        assert_eq!(call(&mut m, 100), Ok(()));
        assert_eq!(
            call(&mut m, 36),
            Err(Refusal::Replay),
            "64 behind is out of the window"
        );
        assert_eq!(call(&mut m, 37), Ok(()), "63 behind is inside it");
        assert_eq!(call(&mut m, 37), Err(Refusal::Replay));
        assert_eq!(
            call(&mut m, 0),
            Err(Refusal::Replay),
            "zero is never a counter"
        );
        let old = "{\"id\":\"a\",\"key\":\"b\",\"identity\":\"c\",\"expiresAtMs\":9,\"lastH\":3}";
        let parsed: HubMirror = serde_json::from_str(old).unwrap();
        assert_eq!(parsed.seen_mask, 0);
        assert_eq!(parsed.last_h, 3);
    }

    #[test]
    fn the_response_mac_binds_the_requests_counter_and_the_body() {
        let m = mirror();
        let key = hex32(&m.key).unwrap();
        let body = "{\"status\":\"success\",\"messages\":[]}";
        let sealed = response_mac(&m.key, 9, body).unwrap();
        assert_eq!(sealed, hex::encode(frame_mac(&key, 9, "response", body)));
        assert_ne!(sealed, response_mac(&m.key, 10, body).unwrap());
        assert_ne!(sealed, response_mac(&m.key, 9, "{}").unwrap());
        assert!(response_mac("not-hex", 9, body).is_none());
    }

    /// 0.3.24 (bsv-low loop 12, 2026-09-20): the replay window's high bits must survive the storage boundary. The
    /// Durable Object's serializer carries a `u64` as a JS number and threw above 2^53 — every lane past its ~53rd
    /// call — so the mask rides as a decimal string; a mirror persisted as a number still reads.
    #[test]
    fn the_seen_mask_rides_as_a_string_so_a_full_window_survives_the_storage_boundary() {
        let mut m = mirror();
        m.last_h = 70;
        m.seen_mask = u64::MAX - 5; // the high bit set: a window every one of whose 64 slots but two is taken
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v["seenMask"],
            serde_json::Value::String((u64::MAX - 5).to_string())
        );
        assert_eq!(
            v["lastH"],
            serde_json::Value::String("70".to_string()),
            "0.3.26: the counter rides as a string too"
        );
        let back: HubMirror = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
        // a row persisted before 0.3.24 / 0.3.26 carried numbers (small by construction)
        let mut old = serde_json::to_value(mirror()).unwrap();
        old["seenMask"] = serde_json::json!(4_503_599_627_370_495u64); // 2^52 - 1
        old["lastH"] = serde_json::json!(52u64);
        let parsed: HubMirror = serde_json::from_value(old).unwrap();
        assert_eq!(parsed.seen_mask, 4_503_599_627_370_495u64);
        assert_eq!(parsed.last_h, 52);
        // 0.3.26: the header's counter is bounded at Number.MAX_SAFE_INTEGER, by name
        assert_eq!(parse_counter(" 9007199254740991 "), Some(MAX_SAFE_COUNTER));
        assert_eq!(parse_counter("9007199254740992"), None);
        assert_eq!(parse_counter("18446744073709551615"), None);
        assert_eq!(parse_counter("-1"), None);
        assert_eq!(parse_counter("x"), None);
        // a missing field is the default (the pre-window rows)
        let mut none = serde_json::to_value(mirror()).unwrap();
        none.as_object_mut().unwrap().remove("seenMask");
        assert_eq!(
            serde_json::from_value::<HubMirror>(none).unwrap().seen_mask,
            0
        );
    }

    #[test]
    fn a_mirror_refresh_is_due_only_past_the_slack_and_never_backwards() {
        let m = mirror();
        assert!(!m.refresh_due(m.expires_at_ms));
        assert!(!m.refresh_due(m.expires_at_ms + MIRROR_REFRESH_SLACK_MS));
        assert!(m.refresh_due(m.expires_at_ms + MIRROR_REFRESH_SLACK_MS + 1));
        assert!(!m.refresh_due(m.expires_at_ms - 1));
        let (lane, offer) = minted();
        let u = MirrorUpdate::from(&lane);
        assert_eq!(u.id, offer.id);
        assert_eq!(u.key, lane.key);
        assert_eq!(HubMirror::new(IDENTITY, u).last_h, 0);
    }

    /// M5 (the 2026-09-14 gate): a lane lives at most `LANE_MAX_LIFETIME_MS`
    /// from its mint however busy it is. The socket lane refuses `expired`
    /// inbound, seals nothing outbound and is not live; the hub mirror (the
    /// FIRST handshake's mint time, carried by the update) refuses its HTTP
    /// call the same way. A lane persisted without the field (`0`) is past it.
    #[test]
    fn a_lane_and_its_mirror_die_at_the_absolute_lifetime_however_busy() {
        let (mut lane, _) = minted();
        assert_eq!(lane.minted_at_ms, 1_000);
        let last_ok = 1_000 + LANE_MAX_LIFETIME_MS;
        // Busy right up to the edge: a lane refreshed by frames all along has
        // its idle window open at the lifetime's last ms.
        lane.expires_at_ms = last_ok;
        let f = client_frame(&lane, 1, "joinRoom", "{}");
        assert!(lane.verify_inbound(&f, last_ok).is_ok());
        assert!(lane.is_live(last_ok));
        assert!(lane.seal_outbound("presence", "[]", last_ok).is_some());
        let f = client_frame(&lane, 2, "joinRoom", "{}");
        assert_eq!(lane.verify_inbound(&f, last_ok + 1), Err(Refusal::Expired));
        assert!(!lane.is_live(last_ok + 1));
        assert!(lane.seal_outbound("presence", "[]", last_ok + 1).is_none());
        let mut m = mirror();
        assert_eq!(m.minted_at_ms, 1_000);
        m.expires_at_ms = last_ok;
        let body = "{}";
        let mac = http_mac(&m, 1, "GET", "/x", body);
        let digest: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        assert!(m
            .verify_http(1, "GET", "/x", &digest, &mac, last_ok)
            .is_ok());
        assert!(m.is_live(last_ok));
        let mac = http_mac(&m, 2, "GET", "/x", body);
        assert_eq!(
            m.verify_http(2, "GET", "/x", &digest, &mac, last_ok + 1),
            Err(Refusal::Expired)
        );
        assert!(!m.is_live(last_ok + 1));
        // A record from before the field: past the lifetime at any real now.
        let old: SessionLane = serde_json::from_str(
            &serde_json::to_string(&lane)
                .unwrap()
                .replace("\"minted_at_ms\":1000,", ""),
        )
        .unwrap();
        assert_eq!(old.minted_at_ms, 0);
        assert!(!old.is_live(LANE_MAX_LIFETIME_MS + 1));
        let old_m: HubMirror = serde_json::from_str(
            &serde_json::to_string(&m)
                .unwrap()
                .replace("\"mintedAtMs\":1000,", ""),
        )
        .unwrap();
        assert_eq!(old_m.minted_at_ms, 0);
        assert!(!old_m.is_live(LANE_MAX_LIFETIME_MS + 1));
        let old_u: MirrorUpdate =
            serde_json::from_str(r#"{"id":"a","key":"b","expiresAtMs":5}"#).unwrap();
        assert_eq!(old_u.minted_at_ms, 0);
    }

    /// L6: the mirror stores its identity lower-cased; N3: a bearer is compared
    /// in constant time and an unset one matches nothing.
    #[test]
    fn the_mirror_lower_cases_its_identity_and_a_bearer_matches_in_constant_time() {
        let (lane, _) = minted();
        let m = HubMirror::new(&IDENTITY.to_ascii_uppercase(), MirrorUpdate::from(&lane));
        assert_eq!(m.identity, IDENTITY);
        assert!(bearer_matches("tok", "tok"));
        assert!(!bearer_matches("tok", "tok2"));
        assert!(!bearer_matches("to", "tok"));
        assert!(!bearer_matches("", ""), "an unset secret closes the door");
        assert!(!bearer_matches("x", ""));
    }

    /// The vectors are a CROSS-REPO agreement: bsv-low's
    /// `app/src/lib/relaySession.vectors.test.ts` re-derives every entry with
    /// the client's code and asserts THIS sha256 of ITS copy. One constant, two
    /// repos: a one-sided edit turns both gates red. Regenerate with the
    /// ignored producer below, copy the file to bsv-low unchanged, update the
    /// constant in BOTH repos.
    const SESSION_MAC_VECTORS_SHA256: &str =
        "32f153675ccdfc704bca895dc239c01fd866b600ee954b396bf76e55c2150d39";
    const SESSION_MAC_VECTORS: &str = include_str!("../tests/fixtures/session_mac.vectors.json");

    #[test]
    fn session_mac_vectors_are_the_pinned_bytes_and_the_real_producer_re_derives_them() {
        let digest = hex::encode(Sha256::digest(SESSION_MAC_VECTORS.as_bytes()));
        assert_eq!(
            digest, SESSION_MAC_VECTORS_SHA256,
            "session_mac.vectors.json changed. It is a CROSS-REPO agreement: copy it to \
             bsv-low unchanged and update the constant in BOTH repos' tests."
        );
        let v: serde_json::Value = serde_json::from_str(SESSION_MAC_VECTORS).unwrap();
        let (lane, offer) = minted();
        assert_eq!(v["key"], lane.key);
        assert_eq!(v["id"], offer.id);
        assert_eq!(v["salt"], offer.salt);
        assert_eq!(
            v["label"],
            std::str::from_utf8(KEY_DERIVATION_LABEL).unwrap()
        );
        assert_eq!(v["idleMs"], SESSION_IDLE_MS);
        let key = hex32(&lane.key).unwrap();
        let frames = v["frames"].as_array().expect("frames[]");
        assert!(frames.len() >= 4);
        for f in frames {
            let n = f["n"].as_u64().expect("n is a u64");
            let e = f["e"].as_str().unwrap();
            let d = f["d"].as_str().unwrap();
            assert_eq!(
                f["m"],
                hex::encode(frame_mac(&key, n, e, d)),
                "frame n={n} e={e}"
            );
        }
        assert!(
            frames.iter().any(|f| f["n"].as_u64() == Some(u64::MAX)),
            "the u64::MAX counter is pinned"
        );
        let http = v["http"].as_array().expect("http[]");
        assert!(http.len() >= 3);
        for c in http {
            let h = c["h"].as_u64().unwrap();
            let method = c["method"].as_str().unwrap();
            let path = c["path"].as_str().unwrap();
            let body = c["body"].as_str().unwrap();
            assert_eq!(
                c["mac"],
                hex::encode(frame_mac(&key, h, &http_event(method, path), body)),
                "{method} {path}"
            );
            assert_eq!(
                c["responseMac"],
                response_mac(&lane.key, h, c["responseBody"].as_str().unwrap()).unwrap(),
                "response to {method} {path}"
            );
        }
    }

    #[test]
    #[ignore = "writes tests/fixtures/session_mac.vectors.json on purpose"]
    fn emit_session_mac_vectors() {
        let (lane, offer) = minted();
        let key = hex32(&lane.key).unwrap();
        let frames: Vec<serde_json::Value> = [
            (1u64, "joinRoom", "\"02aa-low_inbox\""),
            (2, "sendMessage", "{\"roomId\":\"02aa-low_inbox\",\"message\":{\"messageId\":\"m1\",\"recipient\":\"02bb\",\"body\":\"{\\\"encryptedMessage\\\":\\\"AAAA\\\"}\"}}"),
            (3, "leaveRoom", "\"02aa-low_inbox\""),
            (u64::MAX, "presence", "[]"),
        ]
        .iter()
        .map(|(n, e, d)| {
            serde_json::json!({ "n": n, "e": e, "d": d, "m": hex::encode(frame_mac(&key, *n, e, d)) })
        })
        .collect();
        let http: Vec<serde_json::Value> = [
            (
                1u64,
                "POST",
                "/listMessages",
                "{\"messageBox\":\"low_inbox\"}",
                "{\"status\":\"success\",\"messages\":[]}",
            ),
            (
                2,
                "POST",
                "/acknowledgeMessage",
                "{\"messageIds\":[\"m1\"]}",
                "{\"status\":\"success\"}",
            ),
            (
                3,
                "GET",
                "/presence?room=02aa-low_game_1",
                "",
                "{\"present\":true}",
            ),
        ]
        .iter()
        .map(|(h, method, path, body, response)| {
            serde_json::json!({
                "h": h,
                "method": method,
                "path": path,
                "body": body,
                "mac": hex::encode(frame_mac(&key, *h, &http_event(method, path), body)),
                "responseBody": response,
                "responseMac": response_mac(&lane.key, *h, response).unwrap(),
            })
        })
        .collect();
        let v = serde_json::json!({
            "producer": "rust-message-box src/session_lane.rs emit_session_mac_vectors (fixed inputs; regenerate, never retype)",
            "http": http,
            "label": std::str::from_utf8(KEY_DERIVATION_LABEL).unwrap(),
            "idleMs": SESSION_IDLE_MS,
            "clientNonce": CLIENT_NONCE,
            "serverNonce": SERVER_NONCE,
            "identity": IDENTITY,
            "salt": offer.salt,
            "id": offer.id,
            "key": lane.key,
            "frames": frames,
        });
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("session_mac.vectors.json"),
            serde_json::to_string_pretty(&v).unwrap(),
        )
        .unwrap();
    }
}

// ── bsv-low #443 step 4 (2026-09-14): a socket ATTACHES through the hub mirror ──
//
// The tab's FIRST relay socket handshakes (BRC-103) and mints the lane the hub
// MIRRORS. Every later socket of the tab attaches instead: its first frame is
// `sessionAttach { s, identity, n, mac, nonce }` — the hub-lane credentials
// (id, identity, the HTTP counter `n`, the MAC over the pseudo-call
// `ATTACH /socket` with the socket's own fresh `nonce` as the body) — verified
// by the identity's hub exactly like an HTTP-lane call (the counter moves: an
// attach is not replayable); the socket DO then mints the socket's OWN lane
// (`SessionLane::mint(identity, client_nonce = nonce, server_nonce = fresh)`)
// and answers `sessionAttached { d, m }`: `d` the JSON text `{session: offer,
// serverNonce, nonce}` and `m = HMAC-SHA256(K_hub, "sessionAttached" ‖ 0x01 ‖
// sha256(d))` (the domain byte 0x01: a frame MAC's input is `n_le8 ‖ e ‖ 0x00 ‖
// digest`, so no frame under the hub key can share the ack's input) — a one-shot ack the client verifies under its hub lane's key
// and binds to its nonce (no counter: the ack rides socket 2, the hub lane's
// counters are socket 1's). A refusal is a plain `sessionAttachRefused
// {reason}` (nothing to sign under yet); the client falls back to the
// reference handshake. A reference client never attaches.
pub const ATTACH_EVENT: &str = "sessionAttach";
pub const ATTACHED_EVENT: &str = "sessionAttached";
pub const ATTACH_REFUSED_EVENT: &str = "sessionAttachRefused";
/// The pseudo-call the attach MAC covers (the hub verifies method + path + the body's digest).
pub const ATTACH_METHOD: &str = "ATTACH";
pub const ATTACH_PATH: &str = "/socket";
/// The ack MAC's domain byte (never 0x00: that is the frame MAC's separator).
pub const ATTACH_ACK_DOMAIN: u8 = 0x01;
/// How long the socket DO waits for the hub's verdict on an attach. The
/// client gives an attach `ATTACH_WAIT_MS` (1.5 s) inside the SDK's own auth
/// budget before it falls back to the handshake, so the hub ask is bounded
/// BELOW that: a slow hub is a fallback, never a wedged auth (the gate's M1).
pub const ATTACH_HUB_TIMEOUT_MS: u64 = 1_200;

/// The attach frame's shape, bounded. PURE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachFrame {
    /// The hub lane's id.
    pub s: String,
    pub identity: String,
    /// The hub lane's HTTP counter for this attach.
    pub n: u64,
    pub mac: String,
    /// The socket's fresh nonce (32 bytes hex): the attach's body and the socket lane's client nonce.
    pub nonce: String,
}

/// Parse and bound an attach frame; `None` for anything malformed.
pub fn parse_attach_frame(v: &serde_json::Value) -> Option<AttachFrame> {
    let f: AttachFrame = serde_json::from_value(v.clone()).ok()?;
    let hex_ok = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
    (hex_ok(&f.s, 64) && hex_ok(&f.identity, 66) && hex_ok(&f.mac, 64) && hex_ok(&f.nonce, 64))
        .then(|| AttachFrame {
            s: f.s.to_ascii_lowercase(),
            identity: f.identity.to_ascii_lowercase(),
            n: f.n,
            mac: f.mac.to_ascii_lowercase(),
            nonce: f.nonce.to_ascii_lowercase(),
        })
}

/// The hub's verify body for an attach (the HTTP-lane verify body verbatim). PURE.
pub fn attach_verify_body(f: &AttachFrame) -> serde_json::Value {
    let digest = Sha256::digest(f.nonce.as_bytes());
    serde_json::json!({
        "id": f.s,
        "identity": f.identity,
        "h": f.n,
        "method": ATTACH_METHOD,
        "path": ATTACH_PATH,
        "bodySha256": hex::encode(digest),
        "mac": f.mac,
    })
}

/// The one-shot ack MAC: `HMAC-SHA256(K_hub, "sessionAttached" ‖ 0x01 ‖ sha256(d))`, hex. PURE.
pub fn attach_ack_mac(hub_key_hex: &str, d_text: &str) -> Option<String> {
    let key = hex::decode(hub_key_hex).ok()?;
    let mut mac = HmacSha256::new_from_slice(&key).ok()?;
    mac.update(ATTACHED_EVENT.as_bytes());
    mac.update(&[ATTACH_ACK_DOMAIN]);
    mac.update(&Sha256::digest(d_text.as_bytes()));
    Some(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod attach_tests {
    use super::*;

    fn frame() -> serde_json::Value {
        serde_json::json!({ "s": "ab".repeat(32), "identity": format!("02{}", "cd".repeat(32)), "n": 5, "mac": "ef".repeat(32), "nonce": "01".repeat(32) })
    }

    #[test]
    fn the_attach_frame_is_bounded_and_its_verify_body_is_the_http_lane_shape_over_attach_slash_socket(
    ) {
        let f = parse_attach_frame(&frame()).unwrap();
        let body = attach_verify_body(&f);
        assert_eq!(body["method"], ATTACH_METHOD);
        assert_eq!(body["path"], ATTACH_PATH);
        assert_eq!(body["h"], 5);
        assert_eq!(
            body["bodySha256"],
            hex::encode(Sha256::digest("01".repeat(32).as_bytes()))
        );
        for k in ["s", "identity", "mac", "nonce"] {
            let mut bad = frame();
            bad[k] = serde_json::json!("zz");
            assert!(parse_attach_frame(&bad).is_none(), "{k} bounded");
        }
        let mut no_n = frame();
        no_n.as_object_mut().unwrap().remove("n");
        assert!(parse_attach_frame(&no_n).is_none());
    }

    #[test]
    fn the_ack_mac_is_a_domain_separated_hmac_over_the_text_s_digest() {
        let key = "11".repeat(32);
        let d = r#"{"session":{"id":"x"},"serverNonce":"y","nonce":"z"}"#;
        let m = attach_ack_mac(&key, d).unwrap();
        assert_eq!(m.len(), 64);
        // The vector shared with the client (`relaySession.test.ts`): the same key, the same text.
        assert_eq!(
            m,
            "3c96cacbd50b4035a9c4c883cf25faafaae415bdc999a94ae7e81472809f603a"
        );
        assert_ne!(
            m,
            attach_ack_mac(
                &key,
                r#"{"session":{"id":"x"},"serverNonce":"y","nonce":"w"}"#
            )
            .unwrap(),
            "bound to the text"
        );
        assert_ne!(
            m,
            attach_ack_mac(&"22".repeat(32), d).unwrap(),
            "bound to the key"
        );
        assert!(attach_ack_mac("nothex", d).is_none());
    }
}
