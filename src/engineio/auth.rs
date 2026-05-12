//! BRC-103 mutual authentication driver for Socket.IO `authMessage` events
//! (M10 #61 — Phase B).
//!
//! ## Wire shape
//!
//! On the Socket.IO surface, BRC-103 is layered as a single event named
//! `authMessage` whose only argument is the JSON-serialised
//! `bsv_rs::auth::types::AuthMessage`. That matches the TypeScript
//! `SocketServerTransport`/`SocketClientTransport` pair from the
//! `@bsv/authsocket` and `@bsv/authsocket-client` libraries (and is the
//! contract the unmodified `@bsv/authsocket-client@2.0.2` will speak to
//! us).
//!
//! ## Why we don't use `bsv_rs::auth::Peer` directly
//!
//! `Peer` is built around `tokio::sync::{RwLock, oneshot}` and a
//! `Transport` trait whose callbacks return boxed `Send + Sync` futures.
//! Cloudflare Workers WASM does not have a tokio runtime, and our
//! `EngineIoSession` Durable Object is a single-threaded `RefCell`
//! world. Wiring `Peer` into that environment is a non-starter.
//!
//! Instead we drive the protocol manually using the same primitives the
//! middleware crate uses for the HTTP path: `AuthMessage::signing_data`,
//! `ProtoWallet::create_signature` /`verify_signature` (sync), and
//! `auth::utils::create_nonce` (async but cheap). This keeps us
//! byte-for-byte interoperable with `Peer` on the wire.
//!
//! ## Authentication state machine (server side)
//!
//! ```text
//!         ┌─ Unauthenticated (initial)
//!         │
//!         │  client → server: authMessage(InitialRequest)
//!         │      server creates session_nonce
//!         │      server signs InitialResponse over (your_nonce || initial_nonce)
//!         │      server replies authMessage(InitialResponse)
//!         ▼
//!         Authenticated { session_nonce, peer_nonce, peer_identity_key }
//!         │
//!         │  client → server: authMessage(General)   [first post-auth]
//!         │      server verifies signature
//!         │      session.rs sees `AuthOutcome::AuthenticatedGeneral`
//!         │      and (one-time) emits the Phase B `authenticated`
//!         │      follow-up General so the client's
//!         │      `serverIdentityKey` lands. See `session.rs` for the
//!         │      `authenticated_emitted` gate.
//! ```
//!
//! ## Why we wait for the client's first General before emitting
//!
//! The TS `Peer.processInitialResponse` in `@bsv/sdk` is an async
//! chain: it `await`s a signature verify, then mutates
//! `peerSession.peerIdentityKey` / `peerNonce` / `isAuthenticated`. If
//! the server emits both the `InitialResponse` AND a follow-up
//! `General` back-to-back, the socket.io client fires its
//! `authMessage` handler twice in rapid succession; both invocations
//! interleave on the JS event loop. The General handler then enters
//! `processGeneralMessage`, looks up the session via
//! `getSession(message.yourNonce)`, and sees a session with
//! `peerIdentityKey: undefined` — because `processInitialResponse`'s
//! verify step hasn't returned yet. Verify fails with
//! `counterparty: undefined` and the connection dies with
//! `ERR_INVALID_SIGNATURE`. The fix: defer the `authenticated`
//! follow-up until the client's first post-auth General arrives — by
//! then the client's session is fully transitioned (the General
//! couldn't have been built otherwise).
//!
//! Phase C will replace the post-auth handler with the real event
//! routing (joinRoom / sendMessage / etc.) and this module will keep
//! providing the `outbound_general` helper used to push events back
//! over the signed-General channel.

use bsv_rs::auth::types::{AuthMessage, MessageType, AUTH_PROTOCOL_ID, AUTH_VERSION};
use bsv_rs::auth::utils::create_nonce;
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel,
    VerifySignatureArgs,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Originator string used for wallet operations. Matches the middleware's
/// constant so derivation is consistent across HTTP and WS auth paths.
const ORIGINATOR: &str = "bsv-auth-cloudflare";

/// Per-session BRC-103 state held inside `SessionState`.
///
/// Implements `Serialize`/`Deserialize` so the full auth state survives
/// hibernation via `WebSocket::serialize_attachment` (M10 #61 Bug 1).
/// The `Authenticated` payload is small: two 32-byte nonces hex-encoded
/// plus a 33-byte compressed pubkey hex. Well under the 2 KB attachment
/// cap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum SessionAuthState {
    /// No InitialRequest has been received (or it was malformed). Non-
    /// `authMessage` Socket.IO events MUST be dropped while in this
    /// state — anything else risks letting an unauthenticated client
    /// send events.
    #[default]
    Unauthenticated,
    /// Mutual handshake completed. `peer_identity_key` is what Phase C
    /// uses for routing messages.
    Authenticated {
        /// Server-side session nonce we created in `process_initial_request`.
        /// Needed for verifying inbound General signatures (key id is
        /// `"{their_nonce} {our_session_nonce}"`).
        server_session_nonce: String,
        /// Client's nonce from `InitialRequest` (`initial_nonce`). Pinned
        /// for the lifetime of the session — used as `your_nonce` on
        /// every outbound General we sign so the client's `verifyNonce`
        /// step succeeds.
        peer_nonce: String,
        /// Verified BRC-103 identity key of the peer (compressed hex).
        /// This is the value Phase C will use as the routing/identity
        /// key (mirrors `auth_context.identity_key` from BRC-31 HTTP).
        peer_identity_key: String,
    },
}

impl SessionAuthState {
    /// True once the BRC-103 handshake has completed.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, SessionAuthState::Authenticated { .. })
    }

    /// Verified peer identity key, or `None` while unauthenticated.
    pub fn verified_identity_key(&self) -> Option<&str> {
        match self {
            SessionAuthState::Authenticated {
                peer_identity_key, ..
            } => Some(peer_identity_key),
            _ => None,
        }
    }
}

/// Outcome of `handle_auth_message`. The caller (`session.rs`) decides
/// what to do with each variant — typically:
///   * `OutboundFrame(s)` → enqueue/send the JSON as the body of a
///     Socket.IO `authMessage` EVENT.
///   * `Authenticated { .. }` → flip session state, stage post-auth
///     follow-up emit (`authenticated` event for Phase B).
///   * `Drop` / `Error` → no-op or log.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// One or more outbound `authMessage` JSON payloads ready to send.
    /// Each entry is a fully serialised `AuthMessage` JSON object —
    /// callers wrap with `socket.io` EVENT framing (`["authMessage", v]`).
    Outbound(Vec<Value>),
    /// Handshake just completed; payload of the inbound `General` (if
    /// any) is included so the caller can decide whether to forward
    /// it. For Phase B the caller ignores this and instead schedules
    /// an `authenticated` outbound event.
    AuthenticatedGeneral {
        /// Decoded payload bytes of the General message (may be empty).
        payload: Vec<u8>,
    },
    /// Inbound message processed, no immediate outbound, no state change.
    Quiet,
    /// Validation/signature error. Logged at the call site; we do NOT
    /// surface it to the client to avoid signal-mining attacks.
    Error(String),
}

/// Build a `ProtoWallet` from the worker's `SERVER_PRIVATE_KEY` secret.
///
/// We re-create the wallet on every auth-message dispatch instead of
/// caching it. The wallet itself just owns a `PrivateKey` + a
/// `KeyDeriver`, both cheap to construct, and the alternative —
/// caching across the `RefCell` boundary in `SessionState` — would
/// require either `Send` bounds we don't get from `worker::Env::secret`
/// or unsafe sharing across the DO event loop.
pub fn make_wallet(server_private_key_hex: &str) -> Result<ProtoWallet, String> {
    let pk = PrivateKey::from_hex(server_private_key_hex)
        .map_err(|e| format!("invalid SERVER_PRIVATE_KEY: {e}"))?;
    Ok(ProtoWallet::new(Some(pk)))
}

/// Identity key (compressed pubkey hex) of the wallet's owner.
pub fn wallet_identity_key(wallet: &ProtoWallet) -> Result<PublicKey, String> {
    let res = wallet
        .get_public_key(GetPublicKeyArgs {
            identity_key: true,
            protocol_id: None,
            key_id: None,
            counterparty: None,
            for_self: None,
        })
        .map_err(|e| format!("get_public_key failed: {e}"))?;
    PublicKey::from_hex(&res.public_key).map_err(|e| format!("identity key parse: {e}"))
}

/// Dispatch one inbound `authMessage` JSON value (the EVENT arg). The
/// `current_state` is borrowed so callers can decide what to mutate
/// based on the returned `AuthOutcome`.
///
/// This is the sole entry point from `session.rs` for inbound BRC-103
/// traffic. It does not write to `current_state`; the caller updates
/// the session in response to the outcome.
pub async fn handle_auth_message(
    raw: &Value,
    current_state: &SessionAuthState,
    wallet: &ProtoWallet,
) -> AuthOutcome {
    // Deserialise — clients always send the full `AuthMessage` JSON
    // object as the single arg of the EVENT.
    let msg: AuthMessage = match serde_json::from_value(raw.clone()) {
        Ok(m) => m,
        Err(e) => return AuthOutcome::Error(format!("decode authMessage JSON: {e}")),
    };
    if msg.version != AUTH_VERSION {
        return AuthOutcome::Error(format!(
            "auth version mismatch: expected {AUTH_VERSION}, got {}",
            msg.version
        ));
    }

    match msg.message_type {
        MessageType::InitialRequest => match process_initial_request(&msg, wallet).await {
            Ok(out) => AuthOutcome::Outbound(vec![out]),
            Err(e) => AuthOutcome::Error(e),
        },
        MessageType::General => match process_general(&msg, current_state, wallet) {
            Ok(payload) => AuthOutcome::AuthenticatedGeneral { payload },
            Err(e) => AuthOutcome::Error(e),
        },
        // Certificate request/response and InitialResponse are not
        // expected on the server-side authMessage path for the basic
        // `@bsv/authsocket` flow (which doesn't pre-request certs).
        // We don't reject the connection — we just no-op so a future
        // certificate-aware client doesn't crash the session.
        MessageType::InitialResponse
        | MessageType::CertificateRequest
        | MessageType::CertificateResponse => AuthOutcome::Quiet,
    }
}

/// Server-side `process_initial_request`. Mirrors
/// `bsv_rs::auth::Peer::process_initial_request` and the middleware's
/// `handle_initial_request` byte-for-byte so the InitialResponse we
/// emit on the wire is indistinguishable from what `Peer` would send.
async fn process_initial_request(msg: &AuthMessage, wallet: &ProtoWallet) -> Result<Value, String> {
    let my_identity = wallet_identity_key(wallet)?;

    // Server session nonce (counterparty=Self, matching middleware).
    let session_nonce = create_nonce(wallet, None, ORIGINATOR)
        .await
        .map_err(|e| format!("create_nonce: {e}"))?;

    // Build the InitialResponse. Field semantics:
    //   nonce         = our session nonce          (Go SDK only)
    //   initial_nonce = our session nonce          (TS + Go)
    //   your_nonce    = peer's nonce echoed back   (initial_nonce in)
    let peer_nonce = msg
        .initial_nonce
        .clone()
        .or(msg.nonce.clone())
        .ok_or_else(|| "InitialRequest missing initial_nonce/nonce — cannot reply".to_string())?;
    let mut response = AuthMessage::new(MessageType::InitialResponse, my_identity);
    response.nonce = Some(session_nonce.clone());
    response.initial_nonce = Some(session_nonce.clone());
    response.your_nonce = Some(peer_nonce.clone());

    // Sign over (your_nonce || initial_nonce) using key derived for the
    // peer counterparty, key id = "{your_nonce} {initial_nonce}".
    let peer_pk = msg.identity_key.clone();
    let signing_data = response.signing_data();
    let key_id = response.get_key_id(None);
    let sig = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(signing_data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(peer_pk)),
        })
        .map_err(|e| format!("sign InitialResponse: {e}"))?;
    response.signature = Some(sig.signature);

    serde_json::to_value(&response).map_err(|e| format!("serialise InitialResponse: {e}"))
}

/// Server-side `process_general`. We verify the signature against the
/// established session and return the inbound payload bytes for the
/// caller to dispatch. No state mutation here.
fn process_general(
    msg: &AuthMessage,
    state: &SessionAuthState,
    wallet: &ProtoWallet,
) -> Result<Vec<u8>, String> {
    let SessionAuthState::Authenticated {
        server_session_nonce,
        peer_identity_key,
        ..
    } = state
    else {
        return Err("General message before InitialRequest".into());
    };

    // Sender identity must match the session's pinned key — anything
    // else means the client tried to switch identities mid-session,
    // which we treat as an attack.
    let sender_hex = msg.identity_key.to_hex();
    if &sender_hex != peer_identity_key {
        return Err(format!(
            "identity key mismatch: session={peer_identity_key}, msg={sender_hex}"
        ));
    }

    let signature = msg
        .signature
        .as_ref()
        .ok_or_else(|| "General without signature".to_string())?;
    let signing_data = msg.signing_data();
    // Verifier key id mirror: "{their_nonce} {our_session_nonce}"
    let key_id = msg.get_key_id(Some(server_session_nonce.as_str()));
    let result = wallet
        .verify_signature(VerifySignatureArgs {
            data: Some(signing_data),
            hash_to_directly_verify: None,
            signature: signature.clone(),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(msg.identity_key.clone())),
            for_self: None,
        })
        .map_err(|e| format!("verify_signature error: {e}"))?;
    if !result.valid {
        return Err("General signature invalid".to_string());
    }

    Ok(msg.payload.clone().unwrap_or_default())
}

/// Construct the session state we'll record after a successful
/// `process_initial_request` reply. We re-derive the server session
/// nonce by parsing it back out of the response we just signed (passed
/// via `outbound`). This keeps `process_initial_request` pure.
pub fn session_from_initial_response(
    inbound: &Value,
    outbound: &Value,
) -> Result<SessionAuthState, String> {
    let inbound_msg: AuthMessage = serde_json::from_value(inbound.clone())
        .map_err(|e| format!("session_from_initial_response: parse inbound: {e}"))?;
    let outbound_msg: AuthMessage = serde_json::from_value(outbound.clone())
        .map_err(|e| format!("session_from_initial_response: parse outbound: {e}"))?;
    let server_session_nonce = outbound_msg
        .initial_nonce
        .clone()
        .or(outbound_msg.nonce.clone())
        .ok_or_else(|| "outbound InitialResponse missing nonce".to_string())?;
    let peer_nonce = inbound_msg
        .initial_nonce
        .clone()
        .or(inbound_msg.nonce.clone())
        .ok_or_else(|| "inbound InitialRequest missing nonce".to_string())?;
    let peer_identity_key = inbound_msg.identity_key.to_hex();
    Ok(SessionAuthState::Authenticated {
        server_session_nonce,
        peer_nonce,
        peer_identity_key,
    })
}

/// Build a signed `General` `AuthMessage` carrying `payload` for the
/// authenticated peer. The returned JSON is what the caller emits as a
/// Socket.IO `authMessage` EVENT body (`["authMessage", value]`).
///
/// Used for:
///   * Phase B: the `authenticated` follow-up event sent immediately
///     after handshake (proves to the client we own the server
///     identity key it just verified).
///   * Phase C: every server→client emit on a post-auth event.
pub fn build_outbound_general(
    payload: Vec<u8>,
    state: &SessionAuthState,
    wallet: &ProtoWallet,
) -> Result<Value, String> {
    let SessionAuthState::Authenticated {
        peer_nonce,
        peer_identity_key,
        ..
    } = state
    else {
        return Err("build_outbound_general called before auth".into());
    };
    let my_identity = wallet_identity_key(wallet)?;
    let peer_pk =
        PublicKey::from_hex(peer_identity_key).map_err(|e| format!("peer pubkey parse: {e}"))?;

    let mut msg = AuthMessage::new(MessageType::General, my_identity);
    // Per-message random nonce — matches Peer.to_peer behaviour. Use
    // `getrandom` directly (already pulled in via the `js` feature for
    // wasm32) to avoid a rand runtime dep just for this 32 bytes.
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|e| format!("getrandom: {e}"))?;
    msg.nonce = Some(to_base64(&random));
    msg.your_nonce = Some(peer_nonce.clone());
    msg.payload = Some(payload);

    // Sign over the payload, key id = "{nonce} {peer_nonce}".
    let signing_data = msg.signing_data();
    let key_id = msg.get_key_id(Some(peer_nonce.as_str()));
    let sig = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(signing_data),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id,
            counterparty: Some(Counterparty::Other(peer_pk)),
        })
        .map_err(|e| format!("sign General: {e}"))?;
    msg.signature = Some(sig.signature);

    serde_json::to_value(&msg).map_err(|e| format!("serialise General: {e}"))
}

/// AuthSocket-shape payload encoder. The TS `AuthSocketServer` /
/// `AuthSocketClient` implementations encode each event as
/// `JSON.stringify({eventName, data})` UTF-8 bytes wrapped in a
/// `number[]`. We mirror exactly so an unmodified
/// `@bsv/authsocket-client` decodes our `authenticated` follow-up.
pub fn encode_event_payload(event_name: &str, data: &Value) -> Vec<u8> {
    let obj = serde_json::json!({
        "eventName": event_name,
        "data": data,
    });
    obj.to_string().into_bytes()
}

/// Decode an authsocket event payload sent over a General message.
/// Returns `(event_name, data)`. Best-effort: a payload that doesn't
/// parse becomes `("_unknown", null)` — same fallback the TS reference
/// uses.
pub fn decode_event_payload(payload: &[u8]) -> (String, Value) {
    match std::str::from_utf8(payload)
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
    {
        Some(v) => {
            let name = v
                .get("eventName")
                .and_then(|v| v.as_str())
                .unwrap_or("_unknown")
                .to_string();
            let data = v.get("data").cloned().unwrap_or(Value::Null);
            (name, data)
        }
        None => ("_unknown".to_string(), Value::Null),
    }
}

/// Best-effort base64 decode helper exposed for tests; the rest of the
/// module never decodes base64 directly. Re-exported so we don't need a
/// transitive `use base64` in the test below.
#[cfg(test)]
pub(crate) fn decode_b64(s: &str) -> Vec<u8> {
    bsv_rs::primitives::from_base64(s).unwrap_or_default()
}

// ============================================================================
// Tests — pure-Rust round-trips using ProtoWallet (no Worker runtime needed).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_rs::primitives::PrivateKey;

    /// 64-char fixed test key — deterministic so failures are debuggable.
    const TEST_SERVER_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    fn fresh_wallet() -> ProtoWallet {
        make_wallet(TEST_SERVER_KEY).expect("server wallet")
    }

    #[tokio::test]
    async fn initial_request_returns_signed_initial_response() {
        let server_wallet = fresh_wallet();
        // Build a synthetic client InitialRequest using a different key.
        let client_pk = PrivateKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_pk));
        let client_identity = wallet_identity_key(&client_wallet).unwrap();
        let client_nonce = create_nonce(&client_wallet, None, ORIGINATOR)
            .await
            .unwrap();

        let mut req = AuthMessage::new(MessageType::InitialRequest, client_identity);
        req.initial_nonce = Some(client_nonce.clone());
        let raw = serde_json::to_value(&req).unwrap();

        let outcome = handle_auth_message(&raw, &SessionAuthState::default(), &server_wallet).await;
        let outbound = match outcome {
            AuthOutcome::Outbound(v) => v,
            other => panic!("expected Outbound, got {other:?}"),
        };
        assert_eq!(outbound.len(), 1);

        let resp: AuthMessage = serde_json::from_value(outbound[0].clone()).unwrap();
        assert_eq!(resp.message_type, MessageType::InitialResponse);
        assert_eq!(resp.your_nonce.as_deref(), Some(client_nonce.as_str()));
        assert!(
            resp.nonce.is_some(),
            "response carries server session nonce"
        );
        assert!(resp.initial_nonce.is_some());
        assert!(resp.signature.is_some());

        // Signature is over (your_nonce || initial_nonce) — non-empty.
        assert!(!resp.signature.as_ref().unwrap().is_empty());
        // Nonce length is wallet-dependent: bsv-rs ≤ 0.3.5 emits the
        // legacy 32-byte format (16 random + 16 truncated HMAC); 0.3.6+
        // emits 48 bytes (16 random + 32 full HMAC). Accept either so
        // this test isn't pinned to a specific bsv-rs minor.
        let your_len = decode_b64(resp.your_nonce.as_ref().unwrap()).len();
        assert!(
            your_len == 32 || your_len == 48,
            "unexpected nonce length: {your_len}"
        );
    }

    #[tokio::test]
    async fn session_from_initial_response_pins_keys() {
        let server_wallet = fresh_wallet();
        let client_pk = PrivateKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_pk));
        let client_identity = wallet_identity_key(&client_wallet).unwrap();
        let client_nonce = create_nonce(&client_wallet, None, ORIGINATOR)
            .await
            .unwrap();

        let mut req = AuthMessage::new(MessageType::InitialRequest, client_identity.clone());
        req.initial_nonce = Some(client_nonce.clone());
        let inbound = serde_json::to_value(&req).unwrap();
        let outbound = process_initial_request(&req, &server_wallet).await.unwrap();

        let state = session_from_initial_response(&inbound, &outbound).unwrap();
        match state {
            SessionAuthState::Authenticated {
                server_session_nonce,
                peer_nonce,
                peer_identity_key,
            } => {
                assert!(!server_session_nonce.is_empty());
                assert_eq!(peer_nonce, client_nonce);
                assert_eq!(peer_identity_key, client_identity.to_hex());
            }
            _ => panic!("expected Authenticated"),
        }
    }

    #[test]
    fn unauthenticated_rejects_general_messages() {
        let server_wallet = fresh_wallet();
        let client_pk = PrivateKey::from_hex(
            "4444444444444444444444444444444444444444444444444444444444444444",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_pk));
        let client_identity = wallet_identity_key(&client_wallet).unwrap();

        let mut general = AuthMessage::new(MessageType::General, client_identity);
        general.payload = Some(b"hello".to_vec());
        general.signature = Some(vec![1, 2, 3]);
        let r = process_general(&general, &SessionAuthState::Unauthenticated, &server_wallet);
        assert!(r.is_err(), "expected General-before-auth error, got {r:?}");
    }

    /// Round-trip: server `build_outbound_general` produces a General
    /// the *client* (a different ProtoWallet) can verify using the
    /// exact same protocol/keyID convention the TS Peer uses.
    /// If this test fails, the on-the-wire signature is not BRC-103
    /// compatible and `@bsv/authsocket-client` will reject the
    /// `authenticated` follow-up.
    #[tokio::test]
    async fn build_outbound_general_signature_verifies_against_peer_wallet() {
        // server identity
        let server_wallet = fresh_wallet();
        let server_pk = wallet_identity_key(&server_wallet).unwrap();

        // client identity + an InitialRequest from them
        let client_priv = PrivateKey::from_hex(
            "5555555555555555555555555555555555555555555555555555555555555555",
        )
        .unwrap();
        let client_wallet = ProtoWallet::new(Some(client_priv));
        let client_identity = wallet_identity_key(&client_wallet).unwrap();
        let client_session_nonce = create_nonce(&client_wallet, None, ORIGINATOR)
            .await
            .unwrap();

        let mut req = AuthMessage::new(MessageType::InitialRequest, client_identity.clone());
        req.initial_nonce = Some(client_session_nonce.clone());
        let inbound = serde_json::to_value(&req).unwrap();
        let outbound_resp = process_initial_request(&req, &server_wallet).await.unwrap();
        let server_state = session_from_initial_response(&inbound, &outbound_resp).unwrap();
        let server_session_nonce = match &server_state {
            SessionAuthState::Authenticated {
                server_session_nonce,
                ..
            } => server_session_nonce.clone(),
            _ => panic!("authenticated"),
        };

        // Server emits a General to the client.
        let payload = encode_event_payload("authenticated", &serde_json::json!({"x": 1}));
        let general_v = build_outbound_general(payload.clone(), &server_state, &server_wallet)
            .expect("build_outbound_general");
        let general: AuthMessage = serde_json::from_value(general_v).unwrap();
        assert_eq!(general.message_type, MessageType::General);

        // Client-side verification — mirror Peer.processGeneralMessage:
        //   keyID = "{message.nonce} {peerSession.sessionNonce}"
        //   counterparty = peerSession.peerIdentityKey  (= server identity)
        //   data = message.payload
        let key_id = format!(
            "{} {}",
            general.nonce.as_deref().unwrap_or(""),
            client_session_nonce.as_str()
        );
        let result = client_wallet
            .verify_signature(VerifySignatureArgs {
                data: general.payload.clone(),
                hash_to_directly_verify: None,
                signature: general.signature.clone().expect("sig"),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id,
                counterparty: Some(Counterparty::Other(server_pk.clone())),
                for_self: None,
            })
            .expect("verify ok");
        assert!(
            result.valid,
            "client (peer-wallet) failed to verify server's General signature — wire shape is NOT BRC-103 compatible"
        );

        // Also sanity-check: yourNonce on the General must equal the
        // client's session nonce (the one verifyNonce checks).
        let _ = server_session_nonce; // not used directly in this test
        assert_eq!(
            general.your_nonce.as_deref(),
            Some(client_session_nonce.as_str())
        );
    }

    #[test]
    fn build_outbound_general_round_trips_payload_decode() {
        // We don't have the client wallet here to *verify* the signature,
        // but we can at least confirm the General message we build has
        // the right shape and that `decode_event_payload` round-trips
        // the body.
        let server_wallet = fresh_wallet();
        let state = SessionAuthState::Authenticated {
            server_session_nonce:
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            peer_nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(),
            peer_identity_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
        };
        let payload = encode_event_payload(
            "authenticated",
            &serde_json::json!({"identityKey": "deadbeef"}),
        );
        let v = build_outbound_general(payload.clone(), &state, &server_wallet)
            .expect("build_outbound_general");
        let msg: AuthMessage = serde_json::from_value(v).unwrap();
        assert_eq!(msg.message_type, MessageType::General);
        assert_eq!(msg.payload.as_ref().unwrap(), &payload);
        assert!(msg.signature.is_some());

        let (name, data) = decode_event_payload(&payload);
        assert_eq!(name, "authenticated");
        assert_eq!(data["identityKey"], "deadbeef");
    }

    #[test]
    fn decode_event_payload_handles_malformed_input() {
        let (name, data) = decode_event_payload(b"not json");
        assert_eq!(name, "_unknown");
        assert!(data.is_null());
    }

    #[test]
    fn encode_event_payload_round_trips_through_decode() {
        let p = encode_event_payload("hello", &serde_json::json!({"a": 1, "b": "x"}));
        let (n, d) = decode_event_payload(&p);
        assert_eq!(n, "hello");
        assert_eq!(d["a"], 1);
        assert_eq!(d["b"], "x");
    }
}
