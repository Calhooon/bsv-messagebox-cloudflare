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
//!   5. Server verifies the object as a stream from R2, internalizes,
//!      deletes the object.
//!
//! Step 5 lives in `payments.rs` and `beef_door.rs` (0.4.0: the object is
//! never refused for its size and never held whole while it is verified; a
//! verification one request cannot finish saves its cursor beside the object
//! and the same request again continues). This module covers steps 1–2 AND
//! the R2 side of step 5: the door's store, the spool and the cleanup.

use crate::beef_door::{BeefStore, Chunks, Stamp};
use crate::handoff::PaymentStore;
use crate::r2_presign::{presign_r2_put, PresignInput};
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

/// The `BEEF_BLOBS` bucket as the door's store (`beef_door::BeefStore`): an
/// uploaded BEEF read as a stream from an offset, and the door's state beside
/// it under `beef_door::state_key`.
pub struct R2Store<'a> {
    env: &'a Env,
}

impl<'a> R2Store<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    fn bucket(&self) -> Result<worker::Bucket, String> {
        self.env
            .bucket(R2_BINDING)
            .map_err(|e| format!("R2 binding {}: {}", R2_BINDING, e))
    }
}

/// An R2 object's body, a chunk at a time as R2 hands them, and the bytes
/// still due. `worker::ByteStream` ends quietly on an aborted read; a body
/// that ends short of the object's size is the store's failure here, never
/// the end of the BEEF.
struct R2Chunks {
    stream: Option<std::pin::Pin<Box<worker::ByteStream>>>,
    due: u64,
}

#[async_trait::async_trait(?Send)]
impl Chunks for R2Chunks {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        use futures_util::StreamExt as _;
        let chunk = match self.stream.as_mut() {
            None => None,
            Some(stream) => stream
                .next()
                .await
                .transpose()
                .map_err(|e| format!("R2 body read: {}", e))?,
        };
        match &chunk {
            Some(chunk) => self.due = self.due.saturating_sub(chunk.len() as u64),
            None if self.due > 0 => {
                return Err(format!("R2 body ended {} bytes short", self.due));
            }
            None => {}
        }
        Ok(chunk)
    }
}

#[async_trait::async_trait(?Send)]
impl BeefStore for R2Store<'_> {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        let object = self
            .bucket()?
            .head(key)
            .await
            .map_err(|e| format!("R2 head: {}", e))?;
        Ok(object.map(|o| Stamp {
            size: o.size(),
            etag: o.etag(),
        }))
    }

    async fn open(&self, key: &str, from: u64, stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        // A range that starts at the object's end has no bytes, and R2 has
        // no such range.
        if from >= stamp.size {
            return Ok(Box::new(R2Chunks {
                stream: None,
                due: 0,
            }));
        }
        let object = self
            .bucket()?
            .get(key)
            .range(worker::Range::OffsetToEnd { offset: from })
            .execute()
            .await
            .map_err(|e| format!("R2 get: {}", e))?
            .ok_or("R2 object not found")?;
        if object.etag() != stamp.etag {
            return Err("the R2 object changed while it was read".to_string());
        }
        let stream = object
            .body()
            .ok_or("R2 object body missing")?
            .stream()
            .map_err(|e| format!("R2 body: {}", e))?;
        Ok(Box::new(R2Chunks {
            stream: Some(Box::pin(stream)),
            due: stamp.size - from,
        }))
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let object = self
            .bucket()?
            .get(key)
            .execute()
            .await
            .map_err(|e| format!("R2 get: {}", e))?;
        match object.as_ref().and_then(|o| o.body()) {
            None => Ok(None),
            Some(body) => body
                .bytes()
                .await
                .map(Some)
                .map_err(|e| format!("R2 body read: {}", e)),
        }
    }

    async fn save(&self, key: &str, state: Vec<u8>) -> Result<(), String> {
        self.bucket()?
            .put(key, state)
            .execute()
            .await
            .map(|_| ())
            .map_err(|e| format!("R2 put: {}", e))
    }

    async fn clear(&self, key: &str) -> Result<(), String> {
        self.bucket()?
            .delete(key)
            .await
            .map_err(|e| format!("R2 delete: {}", e))
    }
}

/// The size of one part of a spooled payment. R2 takes the parts of a
/// multipart upload in one size, the last one aside, of 5 MiB or more; a
/// payment of one part or less is one `put`. A part is what the spool holds
/// at a time, never the payment.
const SPOOL_PART_BYTES: usize = 8 * 1024 * 1024;

#[async_trait::async_trait(?Send)]
impl PaymentStore for R2Store<'_> {
    async fn spool(
        &self,
        key: &str,
        chunks: &mut dyn Chunks,
        size: u64,
        reader: &str,
    ) -> Result<Stamp, String> {
        let bucket = self.bucket()?;
        let metadata = || {
            std::collections::HashMap::from([(
                crate::handoff::READER_METADATA.to_string(),
                reader.to_string(),
            )])
        };
        let stamp = |object: worker::Object| Stamp {
            size: object.size(),
            etag: object.etag(),
        };
        let mut part = Vec::with_capacity(SPOOL_PART_BYTES.min(size as usize));
        if size as usize <= SPOOL_PART_BYTES {
            while let Some(chunk) = chunks.next().await? {
                part.extend_from_slice(&chunk);
            }
            return bucket
                .put(key, part)
                .custom_metadata(metadata())
                .execute()
                .await
                .map_err(|e| format!("R2 put: {}", e))?
                .map(stamp)
                .ok_or_else(|| "R2 put: no object".to_string());
        }
        let upload = bucket
            .create_multipart_upload(key)
            .custom_metadata(metadata())
            .execute()
            .await
            .map_err(|e| format!("R2 multipart: {}", e))?;
        let mut parts = Vec::new();
        let mut ended = false;
        while !ended {
            match chunks.next().await {
                Ok(Some(chunk)) => part.extend_from_slice(&chunk),
                Ok(None) => ended = true,
                Err(e) => {
                    let _ = upload.abort().await;
                    return Err(e);
                }
            }
            while part.len() >= SPOOL_PART_BYTES || (ended && !part.is_empty()) {
                let rest = part.split_off(SPOOL_PART_BYTES.min(part.len()));
                let number = parts.len() as u16 + 1;
                match upload
                    .upload_part(number, std::mem::replace(&mut part, rest))
                    .await
                {
                    Ok(uploaded) => parts.push(uploaded),
                    Err(e) => {
                        let _ = upload.abort().await;
                        return Err(format!("R2 part {}: {}", number, e));
                    }
                }
            }
        }
        upload
            .complete(parts)
            .await
            .map(stamp)
            .map_err(|e| format!("R2 multipart complete: {}", e))
    }

    async fn reader(&self, key: &str) -> Result<Option<String>, String> {
        let object = self
            .bucket()?
            .head(key)
            .await
            .map_err(|e| format!("R2 head: {}", e))?;
        match object {
            None => Ok(None),
            Some(object) => object
                .custom_metadata()
                .map(|mut metadata| metadata.remove(crate::handoff::READER_METADATA))
                .map_err(|e| format!("R2 metadata: {}", e)),
        }
    }

    /// `R2_BUCKET_NAME`, the name the presigned URLs already sign: it is the
    /// `bucket_name` of the `BEEF_BLOBS` binding (`wrangler.toml`).
    fn bucket_name(&self) -> Option<String> {
        self.env
            .var("R2_BUCKET_NAME")
            .ok()
            .map(|name| name.to_string())
            .filter(|name| !name.is_empty())
    }
}

/// Decide whether a payment references an R2-backed BEEF, and if so,
/// validate ownership and return the key to fetch. This is the pure-logic
/// portion of resolving an R2-backed payment: no Env required, so it's fully
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

/// The answer of `/beef/download-url` for a row's body: a presigned GET of
/// the object the row's payment names, with what the row says of it. `None`
/// when the row names no bytes at rest.
pub fn build_download_response(cfg: &UploadConfig, row_body: &str, now_secs: u64) -> Option<Value> {
    let row: Value = serde_json::from_str(row_body).ok()?;
    let payment = row.get("payment")?;
    let (key, stamp, _) = crate::handoff::rest_of(payment)?;
    let presigned = crate::r2_presign::presign_r2_get(&PresignInput {
        access_key_id: &cfg.access_key_id,
        secret_access_key: &cfg.secret_access_key,
        account_id: &cfg.account_id,
        bucket: &cfg.bucket,
        key,
        amz_date: &format_amz_date(now_secs),
        expires_secs: URL_EXPIRES_SECS,
    });
    Some(json!({
        "status": "success",
        "url": presigned.url,
        "key": presigned.key,
        "size": stamp.size,
        "etag": stamp.etag,
        "txid": payment.get("txid"),
        "verdict": payment.get("verdict"),
        "expiresAt": now_secs + URL_EXPIRES_SECS as u64,
    }))
}

/// Handle a POST /beef/download-url request, body `{"messageId": ".."}`: the
/// recipient of a paid message is handed a presigned R2 GET URL for the
/// payment's BEEF, which it reads from the bucket as a stream. Only the
/// row's recipient is answered; the key is never taken from the request.
pub async fn handle_download_url(
    raw_body: &[u8],
    identity_key: &str,
    env: &Env,
    store: &crate::storage::Storage<'_>,
) -> (Value, u16) {
    let error = |status: u16, code: &str, description: &str| {
        (
            json!({ "status": "error", "code": code, "description": description }),
            status,
        )
    };
    let message_id = serde_json::from_slice::<Value>(raw_body)
        .ok()
        .and_then(|body| body.get("messageId")?.as_str().map(String::from))
        .filter(|id| !id.is_empty());
    let Some(message_id) = message_id else {
        return error(
            400,
            "ERR_MESSAGE_ID_REQUIRED",
            "Please provide the messageId of a paid message.",
        );
    };
    let row = match store.message_body(identity_key, &message_id).await {
        Ok(row) => row,
        Err(e) => {
            return error(
                503,
                "ERR_D1_UNAVAILABLE",
                &format!("The relay is momentarily unavailable; please retry: {}", e),
            )
        }
    };
    let cfg = match load_upload_config(env) {
        Ok(cfg) => cfg,
        Err(e) => {
            return error(
                500,
                "ERR_SERVER_MISCONFIGURED",
                &format!("R2 upload config missing: {}", e),
            )
        }
    };
    let now = (js_sys::Date::now() / 1000.0) as u64;
    match row.and_then(|body| build_download_response(&cfg, &body, now)) {
        Some(body) => (body, 200),
        None => error(
            404,
            "ERR_BEEF_KEY_NOT_FOUND",
            "No message of yours with that messageId carries a payment at rest.",
        ),
    }
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

    #[test]
    fn a_download_url_is_for_the_object_the_row_names_and_no_other() {
        let stamp = Stamp {
            size: 6_100_113,
            etag: "e1".into(),
        };
        let payment = crate::handoff::payment_at_rest(
            &json!({}),
            "02abc/u.beef",
            &stamp,
            crate::handoff::TxShape::Base64,
            Some("aa"),
        );
        let row = crate::handoff::stored_body(&json!("m"), Some((&payment, &json!([]))));
        let body = build_download_response(&test_cfg(), &row, 1_776_772_800).unwrap();
        assert_eq!(body["status"], "success");
        assert_eq!(body["key"], "02abc/u.beef");
        assert_eq!(body["size"], 6_100_113);
        assert_eq!(body["txid"], "aa");
        assert_eq!(body["verdict"], "verified");
        assert_eq!(body["expiresAt"], 1_776_773_400u64);
        let url = body["url"].as_str().unwrap();
        assert!(url.starts_with("https://abc123.r2.cloudflarestorage.com/beef-blobs/02abc/u.beef?"));
        // A row with no payment, a payment with no bytes at rest, and a
        // message that only speaks of a key name nothing.
        for row in [
            r#"{"message":"m"}"#,
            r#"{"message":"m","payment":{"tx":"00"}}"#,
            r#"{"message":{"payment":{"beefR2Key":"02abc/u.beef"}}}"#,
            "not json",
        ] {
            assert!(
                build_download_response(&test_cfg(), row, 0).is_none(),
                "{row}"
            );
        }
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
}
