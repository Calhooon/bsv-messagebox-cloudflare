//! AWS Signature Version 4 presigning for Cloudflare R2 PUT uploads.
//!
//! Workers cap request bodies at 100 MB. For larger BEEFs we hand the client
//! a presigned URL pointing directly at R2's S3-compatible endpoint; the
//! client PUTs there (up to 5 TB per object — R2's only ceiling) and sends
//! the resulting key to the Worker in the `sendMessage` body. The Worker
//! then fetches the object from R2 and internalizes the BEEF.
//!
//! Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
//! R2 S3 endpoint: https://<account_id>.r2.cloudflarestorage.com
//!
//! The whole algorithm is:
//!
//! 1. canonical_request = method \n path \n canonical_query \n
//!    canonical_headers \n signed_headers \n payload_hash
//! 2. string_to_sign    = algorithm \n datetime \n credential_scope \n
//!    sha256(canonical_request)
//! 3. signing_key = derive_signing_key(secret, date, region, service)
//! 4. signature   = hex(hmac_sha256(signing_key, string_to_sign))
//! 5. URL = https://host/key?X-Amz-Algorithm=...&X-Amz-Credential=...
//!    &X-Amz-Date=...&X-Amz-Expires=...&X-Amz-SignedHeaders=host
//!    &X-Amz-Signature=<hex>
//!
//! For PUT uploads we use `UNSIGNED-PAYLOAD` as the payload-hash so the
//! client can stream a body without precomputing its SHA-256.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const SERVICE: &str = "s3";
/// R2 uses `auto` for region (it's global but the S3 client still needs a
/// region name in the signature). Matches Cloudflare docs.
pub const REGION: &str = "auto";

/// Inputs to presign a PUT request.
#[derive(Debug, Clone)]
pub struct PresignInput<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    /// Cloudflare R2 account ID (found in dashboard).
    pub account_id: &'a str,
    pub bucket: &'a str,
    /// Object key. Leading slash optional; we normalize.
    pub key: &'a str,
    /// `amz_date` in the format `YYYYMMDDTHHMMSSZ`. Derive from the current
    /// time — tests pass a fixed value for determinism.
    pub amz_date: &'a str,
    /// Expiry window in seconds. Max 7 days (604800). Recommend 10 minutes.
    pub expires_secs: u32,
}

/// A presigned URL plus the raw key (for the caller to echo back to the
/// client alongside the URL).
#[derive(Debug, Clone)]
pub struct PresignedUpload {
    pub url: String,
    pub key: String,
}

/// Presign a PUT URL for Cloudflare R2.
pub fn presign_r2_put(input: &PresignInput) -> PresignedUpload {
    let host = format!("{}.r2.cloudflarestorage.com", input.account_id);
    let canonical_key = normalize_key(input.key);
    let canonical_path = format!("/{}/{}", input.bucket, encode_key_path(&canonical_key));

    // The date portion is the first 8 chars of amz_date: YYYYMMDD.
    let date_stamp = &input.amz_date[..8];
    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, REGION, SERVICE);

    // Ordered query params. Keys must be sorted lexicographically in the
    // canonical query. URL-encode values per RFC 3986.
    let credential = format!("{}/{}", input.access_key_id, credential_scope);
    let expires = input.expires_secs.to_string();

    let mut query_pairs: Vec<(&str, String)> = vec![
        ("X-Amz-Algorithm", ALGORITHM.to_string()),
        ("X-Amz-Credential", credential),
        ("X-Amz-Date", input.amz_date.to_string()),
        ("X-Amz-Expires", expires),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ];
    query_pairs.sort_by(|a, b| a.0.cmp(b.0));

    let canonical_query = query_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // Canonical headers — just `host` since we only signed that header.
    let canonical_headers = format!("host:{}\n", host);
    let signed_headers = "host";
    let payload_hash = "UNSIGNED-PAYLOAD";

    let canonical_request = format!(
        "PUT\n{}\n{}\n{}\n{}\n{}",
        canonical_path, canonical_query, canonical_headers, signed_headers, payload_hash
    );

    let hashed_canonical = hex::encode(Sha256::digest(canonical_request.as_bytes()));

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}",
        ALGORITHM, input.amz_date, credential_scope, hashed_canonical
    );

    let signing_key = derive_signing_key(input.secret_access_key, date_stamp, REGION, SERVICE);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let url = format!(
        "https://{}{}?{}&X-Amz-Signature={}",
        host, canonical_path, canonical_query, signature
    );

    PresignedUpload {
        url,
        key: canonical_key,
    }
}

/// Derive the AWS v4 signing key: HMAC chain over
/// ("AWS4" + secret) → date → region → service → "aws4_request".
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 3986 URI encoding.
///
/// `encode_slash = false` for path segments (preserve `/`); `true` for query
/// strings. All bytes outside A–Z / a–z / 0–9 / `-_.~` are percent-encoded.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Canonicalize a key: strip a leading slash, collapse repeated slashes.
fn normalize_key(k: &str) -> String {
    let trimmed = k.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').filter(|p| !p.is_empty()).collect();
    parts.join("/")
}

/// URI-encode each segment of a path but keep the slashes between them.
fn encode_key_path(k: &str) -> String {
    k.split('/')
        .map(|seg| uri_encode(seg, true))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_encode_matches_rfc_3986() {
        // Unreserved set passes through.
        assert_eq!(uri_encode("abcXYZ0-9._~", true), "abcXYZ0-9._~");
        // Space becomes %20.
        assert_eq!(uri_encode("a b", true), "a%20b");
        // Slash encoded in query mode, preserved in path mode.
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
        // Plus becomes %2B (not space, unlike form encoding).
        assert_eq!(uri_encode("a+b", true), "a%2Bb");
        // Colon + equals escape.
        assert_eq!(uri_encode(":=", true), "%3A%3D");
    }

    #[test]
    fn normalize_key_strips_leading_slash() {
        assert_eq!(normalize_key("/foo/bar"), "foo/bar");
        assert_eq!(normalize_key("foo/bar"), "foo/bar");
        assert_eq!(normalize_key("//foo//bar///"), "foo/bar");
    }

    #[test]
    fn encode_key_path_preserves_slashes() {
        assert_eq!(encode_key_path("a/b"), "a/b");
        assert_eq!(
            encode_key_path("user/id/with space/key"),
            "user/id/with%20space/key"
        );
    }

    #[test]
    fn derive_signing_key_changes_with_each_input() {
        // HMAC chain correctness is proven end-to-end by the live R2 test
        // (task 19 — upload a real object via the presigned URL). Here we
        // just sanity-check that every input dimension actually affects the
        // derived key (i.e. we didn't accidentally hardcode something).
        let base = derive_signing_key("secret", "20260421", "auto", "s3");
        assert_ne!(base, derive_signing_key("other", "20260421", "auto", "s3"));
        assert_ne!(base, derive_signing_key("secret", "20260422", "auto", "s3"));
        assert_ne!(
            base,
            derive_signing_key("secret", "20260421", "us-east-1", "s3")
        );
        assert_ne!(
            base,
            derive_signing_key("secret", "20260421", "auto", "iam")
        );
        // Length is always 32 bytes (SHA-256).
        assert_eq!(base.len(), 32);
    }

    #[test]
    fn presigned_url_has_required_amz_params() {
        let input = PresignInput {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            account_id: "abc123def456",
            bucket: "beef-blobs",
            key: "user/abc/upload-xyz.beef",
            amz_date: "20260421T120000Z",
            expires_secs: 600,
        };
        let presigned = presign_r2_put(&input);

        // Host is the R2 S3 endpoint for the account.
        assert!(presigned.url.starts_with(
            "https://abc123def456.r2.cloudflarestorage.com/beef-blobs/user/abc/upload-xyz.beef?"
        ));
        // Algorithm comes first alphabetically in the canonical query but may
        // appear anywhere in the final URL; just check presence.
        assert!(presigned.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(presigned
            .url
            .contains("X-Amz-Credential=AKIAIOSFODNN7EXAMPLE"));
        assert!(presigned.url.contains("X-Amz-Date=20260421T120000Z"));
        assert!(presigned.url.contains("X-Amz-Expires=600"));
        assert!(presigned.url.contains("X-Amz-SignedHeaders=host"));
        assert!(presigned.url.contains("X-Amz-Signature="));
        // Signature is hex and deterministic — 64 hex chars.
        let sig_start = presigned.url.rfind("X-Amz-Signature=").unwrap() + 16;
        let sig = &presigned.url[sig_start..];
        assert_eq!(sig.len(), 64);
        assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn presigned_url_is_deterministic() {
        // Same inputs → same URL. Critical for anyone caching URLs or
        // deduplicating across retries.
        let input = PresignInput {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            account_id: "abc123",
            bucket: "b",
            key: "k",
            amz_date: "20260421T120000Z",
            expires_secs: 600,
        };
        let a = presign_r2_put(&input);
        let b = presign_r2_put(&input);
        assert_eq!(a.url, b.url);
        assert_eq!(a.key, b.key);
    }

    #[test]
    fn presigned_key_is_normalized() {
        let input = PresignInput {
            access_key_id: "k",
            secret_access_key: "s",
            account_id: "acct",
            bucket: "b",
            key: "/foo//bar/",
            amz_date: "20260421T120000Z",
            expires_secs: 60,
        };
        let presigned = presign_r2_put(&input);
        assert_eq!(presigned.key, "foo/bar");
        assert!(presigned.url.contains("/b/foo/bar?"));
    }

    #[test]
    fn signature_changes_when_key_changes() {
        let base = PresignInput {
            access_key_id: "k",
            secret_access_key: "s",
            account_id: "acct",
            bucket: "b",
            key: "first-key",
            amz_date: "20260421T120000Z",
            expires_secs: 60,
        };
        let mut other = base.clone();
        other.key = "second-key";
        assert_ne!(presign_r2_put(&base).url, presign_r2_put(&other).url);
    }

    #[test]
    fn signature_changes_when_secret_changes() {
        let a = PresignInput {
            access_key_id: "k",
            secret_access_key: "secret-one",
            account_id: "acct",
            bucket: "b",
            key: "same",
            amz_date: "20260421T120000Z",
            expires_secs: 60,
        };
        let mut b = a.clone();
        b.secret_access_key = "secret-two";
        assert_ne!(presign_r2_put(&a).url, presign_r2_put(&b).url);
    }
}
