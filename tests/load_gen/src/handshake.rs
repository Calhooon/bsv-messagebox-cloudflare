//! BRC-31 handshake driven directly by HTTP — no Peer machinery.
//!
//! Mirrors the proven flow in rust-bsv-worm::auth::client::do_handshake
//! and the Python lib.handshake. We POST `initialRequest` to
//! `/.well-known/auth` with our identity key + a fresh 32-byte nonce,
//! parse `initialResponse`, and stash the server's nonce + identity key
//! as a `Session` we can sign WS-upgrade requests against.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bsv_rs::wallet::ProtoWallet;
use rand::RngCore;
use reqwest::Client;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
#[allow(dead_code)] // server_url + client_nonce_b64 are kept for diagnostics/Debug.
pub struct Session {
    pub server_url: String,
    pub server_identity_key: String,
    pub server_nonce_b64: String,
    pub client_nonce_b64: String,
    pub client_identity_key: String,
}

/// Run the BRC-31 initialRequest/initialResponse exchange against
/// `<server_url>/.well-known/auth`.
pub async fn do_handshake(
    http: &Client,
    server_url: &str,
    wallet: &ProtoWallet,
) -> Result<Session> {
    let server_url = server_url.trim_end_matches('/').to_string();

    let mut client_nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut client_nonce_bytes);
    let client_nonce_b64 = BASE64.encode(client_nonce_bytes);

    let identity_key = wallet.identity_key_hex();

    let body = json!({
        "version": "0.1",
        "messageType": "initialRequest",
        "identityKey": identity_key,
        "initialNonce": client_nonce_b64,
    });

    let url = format!("{server_url}/.well-known/auth");
    let resp = http
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("handshake HTTP {status}: {}", &text[..text.len().min(400)]));
    }

    let data: Value = resp.json().await.context("parse initialResponse JSON")?;

    let server_identity_key = data
        .get("identityKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("initialResponse missing identityKey"))?
        .to_string();

    // Server's nonce field is `initialNonce` or `nonce` depending on impl.
    let server_nonce_b64 = data
        .get("initialNonce")
        .or_else(|| data.get("nonce"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("initialResponse missing initialNonce/nonce"))?
        .to_string();

    if let Some(your_nonce) = data.get("yourNonce").and_then(|v| v.as_str()) {
        if your_nonce != client_nonce_b64 {
            return Err(anyhow!(
                "yourNonce mismatch: sent {client_nonce_b64}, got {your_nonce}"
            ));
        }
    }

    Ok(Session {
        server_url,
        server_identity_key,
        server_nonce_b64,
        client_nonce_b64,
        client_identity_key: identity_key,
    })
}
