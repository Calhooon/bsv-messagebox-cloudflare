//! Sign a `GET /ws` upgrade with the established BRC-31 session and
//! open a WebSocket via tokio-tungstenite.
//!
//! The signed-headers approach mirrors `tests/e2e_ws_lifecycle.py::
//! build_signed_ws_headers`: same protocol id ("auth message
//! signature", level 2), same key_id format ("<msg_nonce_b64>
//! <server_nonce_b64>"), same counterparty (server identity key),
//! same serialize_request body shape with method=GET, body=None.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, Protocol, ProtoWallet, SecurityLevel,
};
use futures_util::StreamExt;
use http::Request;
use rand::RngCore;
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::handshake::client::generate_key,
    tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};
use url::Url;

use crate::handshake::Session;
use crate::serialize::{build_auth_headers, filter_signable_headers, serialize_request};

pub type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Build the signed BRC-31 headers for a bare GET WS upgrade.
fn signed_ws_headers(
    session: &Session,
    wallet: &ProtoWallet,
    ws_url: &Url,
) -> Result<Vec<(String, String)>> {
    let path = if ws_url.path().is_empty() {
        Some("/")
    } else {
        Some(ws_url.path())
    };
    let query_owned = ws_url.query().map(|q| format!("?{q}"));
    let query = query_owned.as_deref();

    // No application headers on a bare GET upgrade.
    let signable: Vec<(String, String)> = filter_signable_headers(&[]);

    let mut msg_nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut msg_nonce_bytes);
    let msg_nonce_b64 = BASE64.encode(msg_nonce_bytes);

    let mut request_id_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut request_id_bytes);
    let request_id_b64 = BASE64.encode(request_id_bytes);

    let serialized = serialize_request(
        &request_id_bytes,
        "GET",
        path,
        query,
        &signable,
        None,
    );

    let key_id = format!("{} {}", msg_nonce_b64, session.server_nonce_b64);
    let counterparty = Counterparty::from_hex(&session.server_identity_key)
        .context("parse server identity_key as Counterparty")?;

    let result = wallet
        .create_signature(CreateSignatureArgs {
            data: Some(serialized),
            hash_to_directly_sign: None,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
            key_id,
            counterparty: Some(counterparty),
        })
        .map_err(|e| anyhow!("create_signature: {e}"))?;
    let signature_hex = hex::encode(&result.signature);

    Ok(build_auth_headers(
        &session.client_identity_key,
        &msg_nonce_b64,
        &session.server_nonce_b64,
        &signature_hex,
        &request_id_b64,
    ))
}

/// Open a WebSocket to `ws_url` carrying signed BRC-31 headers from
/// `session`. Returns the active stream.
pub async fn open_ws(
    ws_url: &Url,
    session: &Session,
    wallet: &ProtoWallet,
) -> Result<WsStream> {
    let auth_headers = signed_ws_headers(session, wallet, ws_url)?;

    // tokio-tungstenite needs a fully-formed http::Request with the
    // standard ws upgrade headers PLUS our auth headers.
    let host = ws_url
        .host_str()
        .ok_or_else(|| anyhow!("ws_url missing host"))?;
    let port_str = match ws_url.port_or_known_default() {
        Some(443) | Some(80) | None => host.to_string(),
        Some(p) => format!("{host}:{p}"),
    };

    let mut builder = Request::builder()
        .method("GET")
        .uri(ws_url.as_str())
        .header("Host", port_str)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key());

    for (k, v) in &auth_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let req = builder
        .body(())
        .map_err(|e| anyhow!("build ws upgrade request: {e}"))?;

    let (ws, _resp) = connect_async(req).await.context("ws connect")?;
    Ok(ws)
}

/// Wait for the server-initiated `connected` envelope so we can confirm
/// the auth handshake actually succeeded (101 alone isn't proof — the
/// server may close immediately on auth-fail post-upgrade).
pub async fn wait_for_connected(ws: &mut WsStream) -> Result<String> {
    let frame = ws
        .next()
        .await
        .ok_or_else(|| anyhow!("ws closed before greeting"))?
        .context("ws recv greeting")?;

    let text = match frame {
        Message::Text(t) => t,
        Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
        Message::Close(c) => return Err(anyhow!("server closed ws on greeting: {c:?}")),
        other => return Err(anyhow!("unexpected ws frame for greeting: {other:?}")),
    };

    let v: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parse greeting JSON: {text}"))?;

    if v.get("event").and_then(|e| e.as_str()) != Some("connected") {
        return Err(anyhow!("greeting event != connected: {text}"));
    }

    let id = v
        .get("data")
        .and_then(|d| d.get("identityKey"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    Ok(id)
}

/// Close the socket cleanly.
pub async fn close_ws(mut ws: WsStream) {
    let _ = ws.close(None).await;
}
