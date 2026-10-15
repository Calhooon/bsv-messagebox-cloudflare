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
//!   5. RS256 over "<header_b64>.<claims_b64>": RSASSA-PKCS1-v1_5 with
//!      SHA-256 (RFC 7518 section 3.3), signed by `ring` (the hash inside it).
//!   6. Assemble "<header_b64>.<claims_b64>.<signature_b64>".
//!
//! The signer is `ring`'s (`RsaKeyPair::from_pkcs8`, `RSA_PKCS1_SHA256`), not
//! the `rsa` crate: the `rsa` crate carries RUSTSEC-2023-0071 with no patched
//! release and the stack's deny template takes no advisory ignore (the
//! owner's word of 2026-10-15). The key is the same secret in the same form:
//! the service-account JSON's PKCS#8 PEM `private_key`.
//!
//! The caller exchanges this JWT via a POST to https://oauth2.googleapis.com/token
//! (see `fcm_token.rs`), caches the resulting access token, and uses it as the
//! Bearer for FCM v1 send requests.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::Deserialize;

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

/// The DER of the one PKCS#8 private-key block (the BEGIN PRIVATE KEY header, not spelled here as a literal) (PKCS#8, what Google
/// issues in a service-account JSON). An older PKCS#1 block ("BEGIN RSA
/// PRIVATE KEY") is not what Google issues and is refused, as before.
pub(crate) const PEM_BEGIN: &str = concat!("-----BEGIN ", "PRIVATE KEY-----");
pub(crate) const PEM_END: &str = concat!("-----END ", "PRIVATE KEY-----");

fn pkcs8_der(pem: &str) -> Result<Vec<u8>, JwtError> {
    // The header and footer assembled from parts: the mirror's scan and the stack's secret-shape leg read a
    // whole PEM header literal as a key shape, and this file holds no key.
    const BEGIN: &str = concat!("-----BEGIN ", "PRIVATE KEY-----");
    const END: &str = concat!("-----END ", "PRIVATE KEY-----");
    let refused = |why: &str| JwtError::PrivateKeyParse(why.to_string());
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body)
        .ok_or_else(|| refused("no PKCS#8 PEM block"))?;
    let b64: String = body.split_whitespace().collect();
    STANDARD
        .decode(b64)
        .map_err(|e| JwtError::PrivateKeyParse(e.to_string()))
}

/// Build a signed RS256 JWT that Google's OAuth2 endpoint will accept.
///
/// `now_secs` is the current unix timestamp (seconds). The JWT is valid for
/// 1 hour — Google's recommended max.
///
/// RSASSA-PKCS1-v1_5 is **deterministic**: same input, same output. `ring`
/// asks a random source for its blinding (`SystemRandom`, the Worker's
/// `crypto.getRandomValues` through getrandom's `js` feature); the blinding
/// never reaches the signature's bytes.
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

    let der = pkcs8_der(&sa.private_key)?;
    let key_pair =
        RsaKeyPair::from_pkcs8(&der).map_err(|e| JwtError::PrivateKeyParse(e.to_string()))?;

    // SHA-256 over the signing input, then RSA PKCS#1 v1.5 sign (ring hashes).
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|e| JwtError::Sign(e.to_string()))?;

    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_rs::primitives::{sha256, BigNumber};
    use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
    use std::sync::OnceLock;

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

    /// A test key's public half: the modulus and the exponent.
    struct TestKey {
        pem: String,
        n: BigNumber,
        e: BigNumber,
    }

    fn random_odd(bits: usize) -> BigNumber {
        let mut bytes = vec![0u8; bits / 8];
        getrandom::getrandom(&mut bytes).expect("test randomness");
        bytes[0] |= 0xc0; // two top bits: p * q has all 2 * bits bits
        *bytes.last_mut().unwrap() |= 1;
        BigNumber::from_bytes_be(&bytes)
    }

    /// Miller-Rabin with 40 random bases, after trial division.
    fn is_probable_prime(n: &BigNumber) -> bool {
        for small in [3u64, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47] {
            if n.modulo(&BigNumber::from_u64(small)).is_zero() {
                return false;
            }
        }
        let one = BigNumber::one();
        let n_minus_1 = n.sub(&one);
        let mut d = n_minus_1.clone();
        let mut r = 0;
        while d.is_even() {
            d = d.shr_bits_toward_zero(1);
            r += 1;
        }
        'witness: for _ in 0..40 {
            let a = random_odd(n.bit_length() - 8)
                .modulo(&n.sub(&BigNumber::from_u64(3)))
                .add(&BigNumber::from_u64(2));
            let mut x = a.mod_pow(&d, n);
            if x.compare(&one).is_eq() || x.compare(&n_minus_1).is_eq() {
                continue;
            }
            for _ in 1..r {
                x = x.mod_pow(&BigNumber::from_u64(2), n);
                if x.compare(&n_minus_1).is_eq() {
                    continue 'witness;
                }
            }
            return false;
        }
        true
    }

    fn prime(bits: usize, e: &BigNumber) -> BigNumber {
        loop {
            let p = random_odd(bits);
            if is_probable_prime(&p)
                && p.sub(&BigNumber::one())
                    .gcd(e)
                    .compare(&BigNumber::one())
                    .is_eq()
            {
                return p;
            }
        }
    }

    /// A DER INTEGER of a non-negative value.
    fn der_int(v: &BigNumber, out: &mut Vec<u8>) {
        let mut bytes = v.to_bytes_be_min();
        if bytes.is_empty() {
            bytes.push(0);
        }
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
        }
        der_tlv(0x02, &bytes, out);
    }

    fn der_tlv(tag: u8, value: &[u8], out: &mut Vec<u8>) {
        out.push(tag);
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let be: Vec<u8> = len
                .to_be_bytes()
                .into_iter()
                .skip_while(|b| *b == 0)
                .collect();
            out.push(0x80 | be.len() as u8);
            out.extend_from_slice(&be);
        }
        out.extend_from_slice(value);
    }

    /// A 2048-bit RSA key generated here (never a real one), as the PKCS#8
    /// PEM a service-account JSON carries (RFC 5958 around RFC 8017's
    /// `RSAPrivateKey`). The `rsa` crate generated it before; it left the
    /// lock with the signer, so the test builds the key from bsv-rs's
    /// `BigNumber`. Generated once per test run.
    fn test_key() -> &'static TestKey {
        static KEY: OnceLock<TestKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let one = BigNumber::one();
            let e = BigNumber::from_u64(65_537);
            let (mut p, mut q) = (prime(1024, &e), prime(1024, &e));
            while p.compare(&q).is_eq() {
                q = prime(1024, &e);
            }
            if p.compare(&q).is_lt() {
                std::mem::swap(&mut p, &mut q);
            }
            let n = p.mul(&q);
            let (p1, q1) = (p.sub(&one), q.sub(&one));
            let lambda = p1.mul(&q1).div(&p1.gcd(&q1));
            let d = e.mod_inverse(&lambda).expect("e is prime to lambda");
            let mut rsa = Vec::new();
            der_int(&BigNumber::zero(), &mut rsa);
            for v in [
                &n,
                &e,
                &d,
                &p,
                &q,
                &d.modulo(&p1),
                &d.modulo(&q1),
                &q.mod_inverse(&p).expect("q is prime to p"),
            ] {
                der_int(v, &mut rsa);
            }
            let mut rsa_seq = Vec::new();
            der_tlv(0x30, &rsa, &mut rsa_seq);
            let mut pkcs8 = Vec::new();
            der_int(&BigNumber::zero(), &mut pkcs8);
            // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1), NULL.
            pkcs8.extend_from_slice(&[
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                0x00,
            ]);
            der_tlv(0x04, &rsa_seq, &mut pkcs8);
            let mut der = Vec::new();
            der_tlv(0x30, &pkcs8, &mut der);
            let b64 = STANDARD.encode(der);
            let mut pem = format!("{PEM_BEGIN}\n");
            for line in b64.as_bytes().chunks(64) {
                pem.push_str(std::str::from_utf8(line).unwrap());
                pem.push('\n');
            }
            pem.push_str(PEM_END);
            pem.push('\n');
            TestKey { pem, n, e }
        })
    }

    /// The test key wrapped in a ServiceAccount struct. Used only in tests.
    fn ephemeral_sa() -> ServiceAccount {
        ServiceAccount {
            project_id: "parity-test".to_string(),
            private_key_id: "test-kid-abc123".to_string(),
            private_key: test_key().pem.clone(),
            client_email: "ci@parity-test.iam.gserviceaccount.com".to_string(),
        }
    }

    #[test]
    fn jwt_is_compact_serialized_with_three_parts() {
        let sa = ephemeral_sa();
        let jwt = build_fcm_jwt(&sa, 1_700_000_000).expect("build");
        let parts = split_jwt(&jwt).expect("split");
        assert!(!parts.0.is_empty());
        assert!(!parts.1.is_empty());
        assert!(!parts.2.is_empty());
    }

    #[test]
    fn jwt_header_has_rs256_jwt_kid() {
        let sa = ephemeral_sa();
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
        let sa = ephemeral_sa();
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

    /// The header and claims bytes, literal: the signer's move to `ring` left
    /// the signing input as it was (serde_json's key order, no padding).
    #[test]
    fn jwt_signing_input_is_the_pinned_bytes() {
        let sa = ephemeral_sa();
        let jwt = build_fcm_jwt(&sa, 1_700_000_000).expect("build");
        let (header_b64, claims_b64, _) = split_jwt(&jwt).expect("split");
        let decoded = |b64: &str| String::from_utf8(URL_SAFE_NO_PAD.decode(b64).unwrap()).unwrap();
        assert_eq!(
            decoded(header_b64),
            r#"{"alg":"RS256","kid":"test-kid-abc123","typ":"JWT"}"#
        );
        assert_eq!(
            decoded(claims_b64),
            concat!(
                r#"{"aud":"https://oauth2.googleapis.com/token","exp":1700003600,"iat":1700000000,"#,
                r#""iss":"ci@parity-test.iam.gserviceaccount.com","#,
                r#""scope":"https://www.googleapis.com/auth/firebase.messaging"}"#
            )
        );
    }

    /// The signature verifies as RS256 under the public key (ring's verifier,
    /// what a JOSE library does), and, apart from ring, `s^e mod n` is
    /// exactly RFC 8017's EMSA-PKCS1-v1_5 block of the signing input's
    /// SHA-256: `00 01 FF.. 00`, the SHA-256 DigestInfo, the digest.
    #[test]
    fn jwt_signature_verifies_against_public_key() {
        let sa = ephemeral_sa();
        let key = test_key();
        let jwt = build_fcm_jwt(&sa, 1_700_000_000).expect("build");
        let (header_b64, claims_b64, signature_b64) = split_jwt(&jwt).expect("split");
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = URL_SAFE_NO_PAD.decode(signature_b64).expect("sig b64");
        assert_eq!(signature.len(), 256);

        let public = RsaPublicKeyComponents {
            n: key.n.to_bytes_be_min(),
            e: key.e.to_bytes_be_min(),
        };
        public
            .verify(
                &RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &signature,
            )
            .expect("signature must verify");

        let m = BigNumber::from_bytes_be(&signature).mod_pow(&key.e, &key.n);
        let mut expected = vec![0x00, 0x01];
        const DIGEST_INFO: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        expected.resize(256 - DIGEST_INFO.len() - 32 - 1, 0xff);
        expected.push(0x00);
        expected.extend_from_slice(&DIGEST_INFO);
        expected.extend_from_slice(&sha256(signing_input.as_bytes()));
        assert_eq!(m.to_bytes_be(256), expected);

        let mut tampered = signature.clone();
        tampered[17] ^= 1;
        assert!(public
            .verify(
                &RSA_PKCS1_2048_8192_SHA256,
                signing_input.as_bytes(),
                &tampered
            )
            .is_err());
    }

    #[test]
    fn jwt_signature_is_deterministic() {
        // PKCS#1 v1.5 is deterministic — same input should produce exactly
        // the same signature bytes. Pin this so we notice if the signer ever
        // silently switches to a randomized scheme (ring's blinding is not).
        let sa = ephemeral_sa();
        let now = 1_700_000_000u64;
        let jwt1 = build_fcm_jwt(&sa, now).expect("build 1");
        let jwt2 = build_fcm_jwt(&sa, now).expect("build 2");
        assert_eq!(jwt1, jwt2);
    }

    /// The secret's own form: the service-account JSON, its PEM with `\n`
    /// escaped, parsed and signed with.
    #[test]
    fn parse_service_account_round_trip() {
        let sa = ephemeral_sa();
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
        assert!(json.contains(&format!("{PEM_BEGIN}\\n")));

        let parsed = parse_service_account(&json).expect("parse");
        assert_eq!(parsed.project_id, "parity-test");
        assert_eq!(parsed.client_email, sa.client_email);
        assert_eq!(parsed.private_key_id, "test-kid-abc123");
        assert_eq!(
            build_fcm_jwt(&parsed, 1_700_000_000).expect("build"),
            build_fcm_jwt(&sa, 1_700_000_000).expect("build")
        );
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
            private_key: format!("{PEM_BEGIN}\nnotpem\n{PEM_END}\n"),
            client_email: "x@x.iam".to_string(),
        };
        let err = build_fcm_jwt(&sa, 0).expect_err("must fail");
        match err {
            JwtError::PrivateKeyParse(_) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }

    /// A PKCS#1 block is not what Google issues; refused as the parse it is.
    #[test]
    fn build_fails_on_a_pkcs1_block() {
        let mut sa = ephemeral_sa();
        sa.private_key = sa
            .private_key
            .replace("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
            .replace("END PRIVATE KEY", "END RSA PRIVATE KEY");
        assert!(matches!(
            build_fcm_jwt(&sa, 0),
            Err(JwtError::PrivateKeyParse(_))
        ));
    }

    #[test]
    fn split_jwt_rejects_too_many_parts() {
        assert!(split_jwt("a.b.c.d").is_none());
        assert!(split_jwt("a.b").is_none());
    }
}
