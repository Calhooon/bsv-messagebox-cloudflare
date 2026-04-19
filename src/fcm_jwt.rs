//! Google service-account JWT signing for FCM v1.
//!
//! Builds a signed JWT that Google's OAuth2 endpoint will exchange for a
//! short-lived access token. All crypto happens in-WASM — no external signing
//! service, no pre-issued tokens. Zero ops surface.
//!
//! The flow:
//!   1. Parse service-account JSON → extract private_key (PEM) + client_email.
//!   2. Build JWT header `{"alg":"RS256","typ":"JWT","kid":<key_id>}`.
//!   3. Build claims `{"iss":<email>,"scope":<fcm_scope>,"aud":<token_uri>,
//!                     "exp":now+3600,"iat":now}`.
//!   4. Base64url-encode both (no padding).
//!   5. SHA-256 over "<header_b64>.<claims_b64>".
//!   6. Sign with RSA PKCS#1 v1.5 — deterministic, no RNG needed.
//!   7. Assemble "<header_b64>.<claims_b64>.<signature_b64>".
//!
//! The caller exchanges this JWT via a POST to https://oauth2.googleapis.com/token
//! (see `fcm_token.rs`), caches the resulting access token, and uses it as the
//! Bearer for FCM v1 send requests.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Google OAuth2 scope for FCM v1 send.
pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Google OAuth2 token exchange endpoint.
pub const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// Fields we care about from a Google service-account JSON.
///
/// The JSON has more fields (`type`, `token_uri`, `auth_uri`, `client_id`,
/// etc.) but we only need these four for JWT signing + FCM URL construction.
/// Extra fields in the source JSON are ignored by serde.
#[derive(Debug, Deserialize)]
pub struct ServiceAccount {
    pub project_id: String,
    pub private_key_id: String,
    /// PEM-encoded PKCS#8 private key. Newlines inside the JSON are escaped
    /// as `\n`; serde_json unescapes them on parse.
    pub private_key: String,
    pub client_email: String,
}

/// Errors from JWT construction. Kept as a flat enum so callers can map
/// 4xx vs 5xx at the HTTP layer.
#[derive(Debug)]
pub enum JwtError {
    ServiceAccountParse(String),
    PrivateKeyParse(String),
    Sign(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::ServiceAccountParse(s) => write!(f, "service-account parse: {}", s),
            JwtError::PrivateKeyParse(s) => write!(f, "private key parse: {}", s),
            JwtError::Sign(s) => write!(f, "RSA sign: {}", s),
        }
    }
}

/// Parse a service-account JSON string.
pub fn parse_service_account(json: &str) -> Result<ServiceAccount, JwtError> {
    serde_json::from_str(json).map_err(|e| JwtError::ServiceAccountParse(e.to_string()))
}

/// Build a signed RS256 JWT that Google's OAuth2 endpoint will accept.
///
/// `now_secs` is the current unix timestamp (seconds). The JWT is valid for
/// 1 hour — Google's recommended max.
///
/// Signing uses RSA PKCS#1 v1.5 which is **deterministic**: no RNG required.
/// Same input, same output. That's why this works cleanly in WASM.
pub fn build_fcm_jwt(sa: &ServiceAccount, now_secs: u64) -> Result<String, JwtError> {
    // Header — RS256, JWT, key id for audit.
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": sa.private_key_id,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());

    // Claims.
    let claims = serde_json::json!({
        "iss": sa.client_email,
        "scope": FCM_SCOPE,
        "aud": TOKEN_URI,
        "exp": now_secs + 3600,
        "iat": now_secs,
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());

    // Signing input — the bytes actually hashed + signed.
    let signing_input = format!("{}.{}", header_b64, claims_b64);

    // Parse PEM. pkcs8 handles "BEGIN PRIVATE KEY" blocks (PKCS#8 PEM), which
    // is what Google issues in service-account JSON. Older PKCS#1 PEM
    // ("BEGIN RSA PRIVATE KEY") isn't what they issue; if we ever see one we
    // should fall back to rsa::pkcs1::DecodeRsaPrivateKey — not needed today.
    let private_key = RsaPrivateKey::from_pkcs8_pem(&sa.private_key)
        .map_err(|e| JwtError::PrivateKeyParse(e.to_string()))?;

    // SHA-256 over the signing input, then RSA PKCS#1 v1.5 sign.
    let mut hasher = Sha256::new();
    hasher.update(signing_input.as_bytes());
    let hashed = hasher.finalize();

    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
        .map_err(|e| JwtError::Sign(e.to_string()))?;

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPublicKey;

    /// Split a compact-serialized JWT into (header, claims, signature).
    /// Test-only helper since the main code only produces JWTs, never splits them.
    fn split_jwt(jwt: &str) -> Option<(&str, &str, &str)> {
        let mut parts = jwt.split('.');
        let h = parts.next()?;
        let c = parts.next()?;
        let s = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        Some((h, c, s))
    }

    /// Generate a throwaway 2048-bit RSA key and wrap it in a ServiceAccount
    /// struct. Used only in tests.
    fn ephemeral_sa() -> (ServiceAccount, RsaPrivateKey) {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test key");
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("serialize to PEM")
            .to_string();
        let sa = ServiceAccount {
            project_id: "parity-test".to_string(),
            private_key_id: "test-kid-abc123".to_string(),
            private_key: pem,
            client_email: "ci@parity-test.iam.gserviceaccount.com".to_string(),
        };
        (sa, key)
    }

    #[test]
    fn jwt_is_compact_serialized_with_three_parts() {
        let (sa, _) = ephemeral_sa();
        let jwt = build_fcm_jwt(&sa, 1_700_000_000).expect("build");
        let parts = split_jwt(&jwt).expect("split");
        assert!(!parts.0.is_empty());
        assert!(!parts.1.is_empty());
        assert!(!parts.2.is_empty());
    }

    #[test]
    fn jwt_header_has_rs256_jwt_kid() {
        let (sa, _) = ephemeral_sa();
        let jwt = build_fcm_jwt(&sa, 1_700_000_000).expect("build");
        let (header_b64, _, _) = split_jwt(&jwt).expect("split");
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).expect("b64 decode");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("json parse");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "test-kid-abc123");
    }

    #[test]
    fn jwt_claims_match_google_shape() {
        let (sa, _) = ephemeral_sa();
        let now = 1_700_000_000u64;
        let jwt = build_fcm_jwt(&sa, now).expect("build");
        let (_, claims_b64, _) = split_jwt(&jwt).expect("split");
        let claims_bytes = URL_SAFE_NO_PAD.decode(claims_b64).expect("b64 decode");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("json parse");
        assert_eq!(claims["iss"], "ci@parity-test.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], FCM_SCOPE);
        assert_eq!(claims["aud"], TOKEN_URI);
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + 3600);
    }

    #[test]
    fn jwt_signature_verifies_against_public_key() {
        let (sa, private_key) = ephemeral_sa();
        let now = 1_700_000_000u64;
        let jwt = build_fcm_jwt(&sa, now).expect("build");
        let (header_b64, claims_b64, signature_b64) = split_jwt(&jwt).expect("split");

        // Recompute the signed bytes.
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let mut hasher = Sha256::new();
        hasher.update(signing_input.as_bytes());
        let hashed = hasher.finalize();

        let signature = URL_SAFE_NO_PAD.decode(signature_b64).expect("sig b64");

        // Verify with the matching public key.
        let public_key = RsaPublicKey::from(&private_key);
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &signature)
            .expect("signature must verify");
    }

    #[test]
    fn jwt_signature_is_deterministic() {
        // PKCS#1 v1.5 is deterministic — same input should produce exactly
        // the same signature bytes. Pin this so we notice if rsa ever
        // silently switches to a randomized scheme.
        let (sa, _) = ephemeral_sa();
        let now = 1_700_000_000u64;
        let jwt1 = build_fcm_jwt(&sa, now).expect("build 1");
        let jwt2 = build_fcm_jwt(&sa, now).expect("build 2");
        assert_eq!(jwt1, jwt2);
    }

    #[test]
    fn parse_service_account_round_trip() {
        let (sa, _) = ephemeral_sa();
        let json = serde_json::json!({
            "type": "service_account",
            "project_id": sa.project_id,
            "private_key_id": sa.private_key_id,
            "private_key": sa.private_key,
            "client_email": sa.client_email,
            "client_id": "ignored-extra-field",
            "token_uri": "ignored-extra-field",
        })
        .to_string();

        let parsed = parse_service_account(&json).expect("parse");
        assert_eq!(parsed.project_id, "parity-test");
        assert_eq!(parsed.client_email, sa.client_email);
        assert_eq!(parsed.private_key_id, "test-kid-abc123");
    }

    #[test]
    fn parse_service_account_rejects_malformed() {
        let err = parse_service_account("not json").expect_err("must fail");
        match err {
            JwtError::ServiceAccountParse(_) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn build_fails_on_bad_pem() {
        let sa = ServiceAccount {
            project_id: "x".to_string(),
            private_key_id: "x".to_string(),
            private_key: "-----BEGIN PRIVATE KEY-----\nnotpem\n-----END PRIVATE KEY-----\n"
                .to_string(),
            client_email: "x@x.iam".to_string(),
        };
        let err = build_fcm_jwt(&sa, 0).expect_err("must fail");
        match err {
            JwtError::PrivateKeyParse(_) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn split_jwt_rejects_too_many_parts() {
        assert!(split_jwt("a.b.c.d").is_none());
        assert!(split_jwt("a.b").is_none());
    }
}
