//! `/beef/upload-url` endpoint: hand the caller a presigned R2 PUT URL so
//! they can upload a BEEF larger than the 100 MB Cloudflare Workers body
//! cap directly to R2.
//!
//! The key is scoped to the caller's identity key:
//!     `<identity_key>/<uuid>.beef`
//! so that `sendMessage` can later verify ownership before fetching the
//! object. The URL is valid for 10 minutes — long enough for a slow upload,
//! short enough that leaked URLs self-expire.
//!
//! Flow:
//!   1. Client POSTs `/beef/upload-url` (auth'd via BRC-31).
//!   2. Server returns `{ url, key, expiresAt }`.
//!   3. Client PUTs BEEF bytes to `url` (direct to R2, up to 5 TB).
//!   4. Client POSTs `/sendMessage` with `payment.beefR2Key = key`.
//!   5. Server fetches from R2, internalizes, deletes the object.
//!
//! Step 5 lives in `payments.rs`; this module covers steps 1–2 AND the
//! later fetch/resolve/cleanup helpers used when a `sendMessage` body
//! references an R2-backed BEEF.

use crate::r2_presign::{presign_r2_put, PresignInput};
use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine as _};
use serde_json::{json, Value};
use worker::Env;

/// R2 bucket binding name (matches `[[r2_buckets]] binding` in wrangler.toml).
const R2_BINDING: &str = "BEEF_BLOBS";

/// URL lifetime. 10 minutes is long enough for a ~200 Mbps uploader to push
/// a 5 GB BEEF, short enough that leaked URLs can't be re-used later.
const URL_EXPIRES_SECS: u32 = 600;

/// Format a timestamp as AWS amz-date (YYYYMMDDTHHMMSSZ) — matches the
/// format SigV4 requires.
fn format_amz_date(now_secs: u64) -> String {
    // chrono handles this cleanly. Seconds-precision UTC, no colons.
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(now_secs as i64, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

/// Build the R2 object key for an upload from `identity_key`.
///
/// Format: `<identity_key>/<uuid>.beef` — the identity-key prefix lets
/// `sendMessage` validate ownership by simple string compare, and `.beef`
/// makes the key obvious in R2 console listings.
pub fn build_upload_key(identity_key: &str, uuid: &str) -> String {
    format!("{}/{}.beef", identity_key, uuid)
}

/// Validate that a given R2 key is owned by the given identity key.
///
/// Used by `sendMessage` before fetching an object — a caller can't point at
/// someone else's uploaded blob.
pub fn key_is_owned_by(identity_key: &str, key: &str) -> bool {
    // The key must start with `<identity>/` and have at least one char after.
    let prefix = format!("{}/", identity_key);
    key.starts_with(&prefix) && key.len() > prefix.len()
}

/// Configuration read from Worker secrets + vars.
pub struct UploadConfig {
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket: String,
}

/// Read the R2 S3 credentials + bucket name from the environment.
///
/// All four values must be present. Missing values produce a descriptive
/// error that the handler surfaces as a 500.
pub fn load_upload_config(env: &Env) -> Result<UploadConfig, String> {
    let account_id = env
        .var("R2_ACCOUNT_ID")
        .map_err(|_| "R2_ACCOUNT_ID not set".to_string())?
        .to_string();
    let access_key_id = env
        .var("R2_ACCESS_KEY_ID")
        .map_err(|_| "R2_ACCESS_KEY_ID not set".to_string())?
        .to_string();
    let secret_access_key = env
        .var("R2_SECRET_ACCESS_KEY")
        .map_err(|_| "R2_SECRET_ACCESS_KEY not set".to_string())?
        .to_string();
    let bucket = env
        .var("R2_BUCKET_NAME")
        .map_err(|_| "R2_BUCKET_NAME not set".to_string())?
        .to_string();
    Ok(UploadConfig {
        account_id,
        access_key_id,
        secret_access_key,
        bucket,
    })
}

/// Generate the response JSON for `/beef/upload-url`.
///
/// `now_secs` and `uuid` are passed in (instead of read from the runtime)
/// so this function is unit-testable without a live Worker.
pub fn build_upload_response(
    cfg: &UploadConfig,
    identity_key: &str,
    now_secs: u64,
    uuid: &str,
) -> Value {
    let key = build_upload_key(identity_key, uuid);
    let amz_date = format_amz_date(now_secs);

    let presigned = presign_r2_put(&PresignInput {
        access_key_id: &cfg.access_key_id,
        secret_access_key: &cfg.secret_access_key,
        account_id: &cfg.account_id,
        bucket: &cfg.bucket,
        key: &key,
        amz_date: &amz_date,
        expires_secs: URL_EXPIRES_SECS,
    });

    json!({
        "status": "success",
        "url": presigned.url,
        "key": presigned.key,
        "expiresAt": now_secs + URL_EXPIRES_SECS as u64,
    })
}

/// Fetch an R2 object's bytes by key, using the wrangler R2 binding.
///
/// Returns the raw bytes if the object exists, or an error string suitable
/// for surfacing to the caller as an `ERR_BEEF_KEY_NOT_FOUND` response.
pub async fn fetch_beef_from_r2(env: &Env, key: &str) -> Result<Vec<u8>, String> {
    let bucket = env
        .bucket(R2_BINDING)
        .map_err(|e| format!("R2 binding {}: {}", R2_BINDING, e))?;
    let object = bucket
        .get(key)
        .execute()
        .await
        .map_err(|e| format!("R2 get: {}", e))?
        .ok_or_else(|| "R2 object not found".to_string())?;
    let body = object
        .body()
        .ok_or_else(|| "R2 object body missing".to_string())?;
    body.bytes()
        .await
        .map_err(|e| format!("R2 body read: {}", e))
}

/// Delete an R2 object. Best-effort: failures are logged but do not fail
/// the caller (the upload URL will expire on its own).
pub async fn delete_beef_from_r2(env: &Env, key: &str) -> Result<(), String> {
    let bucket = env
        .bucket(R2_BINDING)
        .map_err(|e| format!("R2 binding: {}", e))?;
    bucket
        .delete(key)
        .await
        .map_err(|e| format!("R2 delete: {}", e))
}

/// Decide whether a payment references an R2-backed BEEF, and if so,
/// validate ownership and return the key to fetch. This is the pure-logic
/// portion of `resolve_r2_backed_payment` — no Env required, so it's fully
/// unit-testable.
///
/// Returns:
///   Ok(None)        — payment has no beefR2Key; caller uses it inline.
///   Ok(Some(key))   — caller should fetch the R2 object at `key`.
///   Err((body, st)) — beefR2Key present but not owned by `identity_key`.
pub fn decide_r2_fetch(
    payment: &Value,
    identity_key: &str,
) -> Result<Option<String>, (Value, u16)> {
    let key_opt = payment
        .get("beefR2Key")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());

    let key = match key_opt {
        Some(k) => k.to_string(),
        None => return Ok(None),
    };

    if !key_is_owned_by(identity_key, &key) {
        return Err((
            json!({
                "status": "error",
                "code": "ERR_BEEF_KEY_FORBIDDEN",
                "description": "beefR2Key does not belong to the caller.",
            }),
            403,
        ));
    }

    Ok(Some(key))
}

/// Rewrite a payment JSON value to inline `tx: { beef: <base64> }` and
/// strip `beefR2Key`. Pure function — separated so unit tests can exercise
/// the rewriting independently of the R2 fetch.
pub fn inline_beef_into_payment(payment: &Value, beef_bytes: &[u8]) -> Value {
    let mut rewritten = payment.clone();
    let beef_b64 = B64_STANDARD.encode(beef_bytes);
    if let Some(obj) = rewritten.as_object_mut() {
        obj.insert("tx".to_string(), json!({ "beef": beef_b64 }));
        obj.remove("beefR2Key");
    }
    rewritten
}

/// Inspect a `payment` JSON value for a `beefR2Key`. If present, validate
/// ownership against `identity_key`, fetch the object from R2, and return a
/// rewritten payment with `tx.beef` populated from the fetched bytes. The
/// second return value is the R2 key the caller should delete on success.
///
/// Returns Ok((payment, None)) if the payment is inline (no beefR2Key) —
/// caller should use `payment` unchanged and skip cleanup.
pub async fn resolve_r2_backed_payment(
    payment: &Value,
    identity_key: &str,
    env: &Env,
) -> Result<(Value, Option<String>), (Value, u16)> {
    let key = match decide_r2_fetch(payment, identity_key)? {
        Some(k) => k,
        None => return Ok((payment.clone(), None)),
    };

    let bytes = fetch_beef_from_r2(env, &key).await.map_err(|e| {
        (
            json!({
                "status": "error",
                "code": "ERR_BEEF_KEY_NOT_FOUND",
                "description": format!("Could not fetch BEEF from R2: {}", e),
            }),
            400,
        )
    })?;

    let rewritten = inline_beef_into_payment(payment, &bytes);
    Ok((rewritten, Some(key)))
}

/// Handle a POST /beef/upload-url request.
///
/// Returns (body, status) so the caller can thread it into the normal
/// `sign_json_response` flow used by every other authenticated endpoint.
pub async fn handle_upload_url(identity_key: &str, env: &Env) -> (Value, u16) {
    let cfg = match load_upload_config(env) {
        Ok(c) => c,
        Err(e) => {
            return (
                json!({
                    "status": "error",
                    "code": "ERR_SERVER_MISCONFIGURED",
                    "description": format!("R2 upload config missing: {}", e),
                }),
                500,
            );
        }
    };

    let now = (js_sys::Date::now() / 1000.0) as u64;
    let uuid = uuid::Uuid::new_v4().simple().to_string();
    let body = build_upload_response(&cfg, identity_key, now, &uuid);
    (body, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> UploadConfig {
        UploadConfig {
            account_id: "abc123".to_string(),
            access_key_id: "AKIAEXAMPLE".to_string(),
            secret_access_key: "secretExample".to_string(),
            bucket: "beef-blobs".to_string(),
        }
    }

    #[test]
    fn amz_date_format() {
        // 2026-04-21T12:00:00Z is 1776772800 unix time. Spot-check the
        // SigV4 date format is correct (YYYYMMDDTHHMMSSZ, no separators).
        assert_eq!(format_amz_date(1_776_772_800), "20260421T120000Z");
        // And the epoch itself is formatted the same way.
        assert_eq!(format_amz_date(0), "19700101T000000Z");
    }

    #[test]
    fn upload_key_shape() {
        let key = build_upload_key("02abc", "deadbeef1234");
        assert_eq!(key, "02abc/deadbeef1234.beef");
    }

    #[test]
    fn key_ownership_same_identity() {
        assert!(key_is_owned_by("02abc", "02abc/uuid.beef"));
        assert!(key_is_owned_by("02abc", "02abc/x"));
    }

    #[test]
    fn key_ownership_different_identity_rejected() {
        assert!(!key_is_owned_by("02abc", "02xyz/uuid.beef"));
    }

    #[test]
    fn key_ownership_rejects_prefix_match_without_separator() {
        // Don't let "02a" claim ownership of "02abcde/..."
        assert!(!key_is_owned_by("02a", "02abcde/uuid"));
    }

    #[test]
    fn key_ownership_rejects_bare_prefix() {
        // "02abc/" alone isn't a real key (no object name after the slash).
        assert!(!key_is_owned_by("02abc", "02abc/"));
    }

    #[test]
    fn upload_response_shape() {
        // 1_776_772_800 is 2026-04-21T12:00:00Z.
        let body = build_upload_response(&test_cfg(), "02abc", 1_776_772_800, "uuid123");

        assert_eq!(body["status"], "success");
        assert_eq!(body["key"], "02abc/uuid123.beef");
        assert_eq!(body["expiresAt"], 1_776_773_400u64);

        let url = body["url"].as_str().expect("url is string");
        assert!(url
            .starts_with("https://abc123.r2.cloudflarestorage.com/beef-blobs/02abc/uuid123.beef?"));
        assert!(url.contains("X-Amz-Date=20260421T120000Z"));
        assert!(url.contains("X-Amz-Expires=600"));
        assert!(url.contains("X-Amz-Signature="));
    }

    #[test]
    fn upload_response_is_deterministic_given_inputs() {
        // Same (cfg, identity, now, uuid) → same signed URL.
        let body_a = build_upload_response(&test_cfg(), "02abc", 1_776_772_800, "uuid");
        let body_b = build_upload_response(&test_cfg(), "02abc", 1_776_772_800, "uuid");
        assert_eq!(body_a["url"], body_b["url"]);
        assert_eq!(body_a["key"], body_b["key"]);
    }

    // -- decide_r2_fetch --

    #[test]
    fn decide_no_fetch_when_beef_r2_key_absent() {
        let payment = json!({ "tx": { "beef": "abc" } });
        assert_eq!(decide_r2_fetch(&payment, "02abc").unwrap(), None);
    }

    #[test]
    fn decide_no_fetch_when_beef_r2_key_empty_string() {
        let payment = json!({ "beefR2Key": "", "tx": { "beef": "abc" } });
        assert_eq!(decide_r2_fetch(&payment, "02abc").unwrap(), None);
    }

    #[test]
    fn decide_fetch_when_owned_key_present() {
        let payment = json!({ "beefR2Key": "02abc/upload-id.beef" });
        assert_eq!(
            decide_r2_fetch(&payment, "02abc").unwrap(),
            Some("02abc/upload-id.beef".to_string())
        );
    }

    #[test]
    fn decide_forbidden_when_key_not_owned_by_caller() {
        let payment = json!({ "beefR2Key": "02xyz/upload-id.beef" });
        let err = decide_r2_fetch(&payment, "02abc").expect_err("must be forbidden");
        assert_eq!(err.1, 403);
        assert_eq!(err.0["code"], "ERR_BEEF_KEY_FORBIDDEN");
    }

    #[test]
    fn decide_forbidden_when_key_tries_prefix_attack() {
        // Make sure "02a" can't claim ownership of "02abcde/..."
        let payment = json!({ "beefR2Key": "02abcde/upload-id.beef" });
        let err = decide_r2_fetch(&payment, "02a").expect_err("must be forbidden");
        assert_eq!(err.0["code"], "ERR_BEEF_KEY_FORBIDDEN");
    }

    // -- inline_beef_into_payment --

    #[test]
    fn inline_beef_replaces_tx_and_drops_key() {
        let payment = json!({
            "beefR2Key": "02abc/u.beef",
            "outputs": [{"outputIndex": 0}],
            "description": "test"
        });
        let bytes = b"raw BEEF bytes here";
        let out = inline_beef_into_payment(&payment, bytes);

        // beefR2Key stripped, outputs/description preserved, tx.beef populated.
        assert!(out.get("beefR2Key").is_none());
        assert_eq!(out["description"], "test");
        assert!(out["outputs"].is_array());
        let beef = out["tx"]["beef"].as_str().expect("beef string");
        assert_eq!(
            beef,
            base64::engine::general_purpose::STANDARD.encode(bytes)
        );
    }

    #[test]
    fn inline_beef_overwrites_existing_inline_tx() {
        // If the caller mistakenly included both an inline tx and a
        // beefR2Key, the R2 fetch wins.
        let payment = json!({
            "beefR2Key": "02abc/u.beef",
            "tx": { "beef": "old-stale-inline" }
        });
        let out = inline_beef_into_payment(&payment, b"new");
        assert_eq!(
            out["tx"]["beef"].as_str().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(b"new")
        );
    }
}
