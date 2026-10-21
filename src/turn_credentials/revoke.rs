//! `POST /turn-credentials/revoke` with `{"username"}`: the hand's close. Only
//! the identity that minted a username may revoke it; another identity's
//! username, or one never minted here, is 404 (the username is not disclosed
//! as existing). The provider's revoke answered, the record is forgotten and
//! the answer is `{"revoked": true}`. The reference has no revoke
//! (`webrtpay/README.md:677-678` at `ts-stack@9262cac66`); the provider's is
//! Cloudflare's `POST .../credentials/<username>/revoke` (204).

use super::{misconfigured, switched_off, Cloudflare, Config, D1Store, Provider, Store};
use serde_json::{json, Value};

type RouteResult = (Value, u16);

/// The longest username read: Cloudflare's are far shorter.
pub const MAX_USERNAME_CHARS: usize = 256;

fn error(status: u16, code: &str, description: &str) -> RouteResult {
    (
        json!({ "status": "error", "code": code, "description": description }),
        status,
    )
}

/// The revoke, after the door and the switch.
pub async fn revoke(
    store: &dyn Store,
    provider: Option<&dyn Provider>,
    log: &dyn Fn(&str),
    identity: &str,
    body: &[u8],
) -> RouteResult {
    let username = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| {
            v.get("username")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .filter(|u| !u.is_empty() && u.chars().count() <= MAX_USERNAME_CHARS);
    let Some(username) = username else {
        return error(
            400,
            "ERR_USERNAME_REQUIRED",
            "The body must be {\"username\": <a TURN username this identity minted>}.",
        );
    };
    let Some(provider) = provider else {
        return misconfigured();
    };
    match store.owner(&username).await {
        Ok(Some(owner)) if owner == identity => {}
        Ok(_) => {
            return error(
                404,
                "ERR_TURN_CREDENTIAL_NOT_FOUND",
                "No TURN credential of this identity has that username.",
            )
        }
        Err(e) => {
            log(&format!("AUDIT turn.owner FAILED: {e}"));
            return error(
                503,
                "ERR_TURN_UNAVAILABLE",
                "The credential's record could not be read; ask again.",
            );
        }
    }
    if let Err(super::ProviderError(why)) = provider.revoke(&username).await {
        log(&format!("AUDIT turn.revoke provider failed: {why}"));
        return error(
            502,
            "ERR_TURN_PROVIDER",
            "The TURN provider did not revoke the credential; ask again.",
        );
    }
    if let Err(e) = store.forget(&username).await {
        // Revoked at the provider: the record goes with its expiry.
        log(&format!("AUDIT turn.forget FAILED: {e}"));
    }
    (json!({ "status": "success", "revoked": true }), 200)
}

/// The route over the Worker's env.
pub async fn handle_revoke(
    body: &[u8],
    identity: &str,
    env: &worker::Env,
    db: &worker::D1Database,
) -> RouteResult {
    let cfg = Config::from_env(env);
    if !cfg.on {
        return switched_off();
    }
    let cloudflare = Cloudflare::from_env(env, &cfg);
    revoke(
        &D1Store { db },
        cloudflare.as_ref().map(|p| p as &dyn Provider),
        &|line| worker::console_log!("{line}"),
        identity,
        body,
    )
    .await
}
