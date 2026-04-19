//! FCM push notifications via Firebase Cloud Messaging v1.
//!
//! Silently catches all errors — an FCM failure must never block message
//! delivery. The `/sendMessage` handler fires this as fire-and-forget.
//!
//! Only the `notifications` message box triggers a push (mirrors TS + Go).
//!
//! Authentication path:
//! 1. Require the full Google service-account JSON as a secret
//!    (`FIREBASE_SERVICE_ACCOUNT_JSON`).
//! 2. Sign a JWT in WASM via `fcm_jwt::build_fcm_jwt` (deterministic RS256 +
//!    PKCS#1 v1.5 signing — no RNG, no native crypto dependency).
//! 3. Exchange the JWT for a short-lived access token via Google's OAuth2
//!    endpoint (`fcm_token::exchange_jwt_for_token`).
//! 4. Cache the token in KV (`fcm_cache::get_cached_or_fresh_token`) so
//!    subsequent pushes within ~1 hour skip steps 2–3.
//!
//! Transitional fallback: if `FIREBASE_ACCESS_TOKEN` is set it's used as a
//! static override, skipping the JWT flow. Useful for local smoke tests.
//! Production should rely on the service-account path.

use serde_json::{json, Value};
use worker::Env;

use crate::fcm_cache::get_cached_or_fresh_token;
use crate::fcm_jwt::{parse_service_account, ServiceAccount};
use crate::storage::Storage;

/// Only the `notifications` message box triggers FCM delivery.
pub fn should_use_fcm_delivery(message_box: &str) -> bool {
    message_box == "notifications"
}

/// FCM v1 send URL for a given project ID.
pub fn build_fcm_url(project_id: &str) -> String {
    format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        project_id
    )
}

/// Build the JSON body for a single FCM v1 send request.
pub fn build_fcm_request_body(fcm_token: &str, title: &str, message_id: &str) -> Value {
    json!({
        "message": {
            "token": fcm_token,
            "notification": {
                "title": title,
                "body": "New message",
            },
            "data": {
                "messageId": message_id,
            }
        }
    })
}

/// Current unix timestamp in seconds, read from the Workers runtime clock.
fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// Resolve the (access_token, project_id) pair using the service-account
/// flow. Returns an error if neither the SA JSON nor the transitional
/// FIREBASE_ACCESS_TOKEN is available.
///
/// Primary path: parse FIREBASE_SERVICE_ACCOUNT_JSON, sign a JWT, exchange
/// for an access token (with KV caching). Transitional path: if
/// FIREBASE_ACCESS_TOKEN is set, use it verbatim — the SA JSON is still
/// required to discover project_id.
async fn resolve_access_token(env: &Env) -> Result<(String, String), String> {
    let sa_json = env
        .var("FIREBASE_SERVICE_ACCOUNT_JSON")
        .map(|v| v.to_string())
        .map_err(|e| format!("FIREBASE_SERVICE_ACCOUNT_JSON not set: {}", e))?;

    let sa: ServiceAccount =
        parse_service_account(&sa_json).map_err(|e| format!("service account: {}", e))?;

    // Transitional fallback.
    if let Ok(raw) = env.var("FIREBASE_ACCESS_TOKEN") {
        let tok = raw.to_string();
        if !tok.is_empty() {
            return Ok((tok, sa.project_id));
        }
    }

    // Primary path: in-WASM JWT + cached OAuth2 exchange.
    let token = get_cached_or_fresh_token(&sa, env, now_secs())
        .await
        .map_err(|e| format!("fcm access token: {}", e))?;

    Ok((token, sa.project_id))
}

/// Send FCM push notification to all active devices for a recipient.
///
/// Fire-and-forget: every failure path is mapped to Ok so callers don't
/// block. Logs via `worker::console_error!` in future.
///
/// Gated behind `ENABLE_FIREBASE == "true"` — if not set, returns Ok
/// immediately so paid deployments without Firebase stay cheap.
pub async fn send_fcm_notification(
    recipient_key: &str,
    message_id: &str,
    title: &str,
    env: &Env,
    store: &Storage<'_>,
) -> Result<(), String> {
    let enabled = env
        .var("ENABLE_FIREBASE")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if enabled != "true" {
        return Ok(());
    }

    let (access_token, project_id) = resolve_access_token(env).await?;

    let devices = store
        .get_active_devices(recipient_key)
        .await
        .map_err(|e| format!("Failed to query devices: {}", e))?;

    if devices.is_empty() {
        return Ok(());
    }

    let fcm_url = build_fcm_url(&project_id);

    for device in &devices {
        let fcm_token = match &device.fcm_token {
            Some(t) if !t.is_empty() => t,
            _ => continue,
        };

        let body = build_fcm_request_body(fcm_token, title, message_id);

        match send_single_fcm(&fcm_url, &access_token, &body).await {
            Ok(response_text) => {
                if response_text.contains("registration-token-not-registered")
                    || response_text.contains("UNREGISTERED")
                {
                    let _ = store.deactivate_device(fcm_token).await;
                } else {
                    let _ = store.update_device_last_used(fcm_token).await;
                }
            }
            Err(_) => {
                // Fire-and-forget — swallow.
            }
        }
    }

    Ok(())
}

/// Single HTTP POST to FCM v1.
async fn send_single_fcm(url: &str, access_token: &str, body: &Value) -> Result<String, String> {
    let headers = worker::Headers::new();
    headers
        .set("Authorization", &format!("Bearer {}", access_token))
        .map_err(|e| format!("Header error: {}", e))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|e| format!("Header error: {}", e))?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post);
    init.with_headers(headers);
    init.with_body(Some(wasm_bindgen::JsValue::from_str(&body.to_string())));

    let request =
        worker::Request::new_with_init(url, &init).map_err(|e| format!("Request error: {}", e))?;

    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| format!("Fetch error: {}", e))?;

    response
        .text()
        .await
        .map_err(|e| format!("Response error: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- should_use_fcm_delivery --

    #[test]
    fn fcm_delivery_notifications_box() {
        assert!(should_use_fcm_delivery("notifications"));
    }

    #[test]
    fn fcm_delivery_inbox_box() {
        assert!(!should_use_fcm_delivery("inbox"));
    }

    #[test]
    fn fcm_delivery_payment_inbox_box() {
        assert!(!should_use_fcm_delivery("payment_inbox"));
    }

    #[test]
    fn fcm_delivery_empty_string() {
        assert!(!should_use_fcm_delivery(""));
    }

    #[test]
    fn fcm_delivery_case_sensitive() {
        assert!(!should_use_fcm_delivery("Notifications"));
        assert!(!should_use_fcm_delivery("NOTIFICATIONS"));
    }

    // -- build_fcm_request_body --

    #[test]
    fn fcm_request_body_structure() {
        let body = build_fcm_request_body("device-token-123", "New Message", "msg-abc");
        assert_eq!(body["message"]["token"], "device-token-123");
        assert_eq!(body["message"]["notification"]["title"], "New Message");
        assert_eq!(body["message"]["notification"]["body"], "New message");
        assert_eq!(body["message"]["data"]["messageId"], "msg-abc");
    }

    #[test]
    fn fcm_request_body_custom_title() {
        let body = build_fcm_request_body("token", "Custom Title", "id-1");
        assert_eq!(body["message"]["notification"]["title"], "Custom Title");
        assert_eq!(body["message"]["notification"]["body"], "New message");
    }

    // -- build_fcm_url --

    #[test]
    fn fcm_url_format() {
        let url = build_fcm_url("my-project-123");
        assert_eq!(
            url,
            "https://fcm.googleapis.com/v1/projects/my-project-123/messages:send"
        );
    }
}
