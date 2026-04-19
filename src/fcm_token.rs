//! Exchange a signed service-account JWT for a Google OAuth2 access token.
//!
//! Google OAuth2 JWT Bearer flow:
//!   POST https://oauth2.googleapis.com/token
//!   Content-Type: application/x-www-form-urlencoded
//!   Body: grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
//!         &assertion=<signed_jwt>
//!
//! Response (200):
//!   { "access_token": "ya29....", "expires_in": 3599, "token_type": "Bearer" }
//!
//! Response (4xx): JSON with `error` + `error_description`. We surface status
//! + body to the caller so ops can debug without guessing.
//!
//! Parse/serialize logic is split out so it's unit-testable without a
//! live HTTP endpoint. The actual `Fetch` call lives in `exchange_jwt_for_token`.

use crate::fcm_jwt::{build_fcm_jwt, JwtError, ServiceAccount, TOKEN_URI};
use serde::Deserialize;
use worker::{Fetch, Headers, Method, Request, RequestInit};

/// Parsed response from the Google token endpoint.
///
/// Google also returns `token_type: "Bearer"` but we don't bother with it —
/// the access token always comes back as a bearer so the field is noise.
#[derive(Debug, Deserialize, Clone)]
pub struct AccessToken {
    pub access_token: String,
    /// Lifetime in seconds from issue time (typically 3599).
    pub expires_in: u64,
}

#[derive(Debug)]
pub enum TokenError {
    Jwt(JwtError),
    HttpSetup(String),
    HttpSend(String),
    HttpStatus { status: u16, body: String },
    ResponseParse(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Jwt(e) => write!(f, "jwt: {}", e),
            TokenError::HttpSetup(s) => write!(f, "http setup: {}", s),
            TokenError::HttpSend(s) => write!(f, "http send: {}", s),
            TokenError::HttpStatus { status, body } => {
                write!(f, "http {}: {}", status, body)
            }
            TokenError::ResponseParse(s) => write!(f, "response parse: {}", s),
        }
    }
}

/// URL-encode a single form value. We only need minimal escaping — the JWT
/// contains alphanumerics + `.`, `-`, `_` which are all safe, but we escape
/// defensively in case Google ever changes the spec.
fn url_encode_form_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Build the request body for the token exchange.
///
/// Pulled out so it's unit-testable without a network call.
pub fn build_token_request_body(jwt: &str) -> String {
    format!(
        "grant_type={}&assertion={}",
        url_encode_form_value("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        url_encode_form_value(jwt),
    )
}

/// Parse a 200 response body. Also pulled out for unit tests.
pub fn parse_token_response(body: &str) -> Result<AccessToken, TokenError> {
    serde_json::from_str(body).map_err(|e| TokenError::ResponseParse(e.to_string()))
}

/// Exchange a signed JWT for an access token.
///
/// `now_secs` is the current unix timestamp in seconds.
pub async fn exchange_jwt_for_token(
    sa: &ServiceAccount,
    now_secs: u64,
) -> Result<AccessToken, TokenError> {
    let jwt = build_fcm_jwt(sa, now_secs).map_err(TokenError::Jwt)?;
    let body = build_token_request_body(&jwt);

    let headers = Headers::new();
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(|e| TokenError::HttpSetup(e.to_string()))?;
    headers
        .set("Accept", "application/json")
        .map_err(|e| TokenError::HttpSetup(e.to_string()))?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.into()));

    let request = Request::new_with_init(TOKEN_URI, &init)
        .map_err(|e| TokenError::HttpSetup(e.to_string()))?;

    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|e| TokenError::HttpSend(e.to_string()))?;

    let status = response.status_code();
    let body = response
        .text()
        .await
        .map_err(|e| TokenError::HttpSend(e.to_string()))?;

    if status != 200 {
        return Err(TokenError::HttpStatus { status, body });
    }

    parse_token_response(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_value_encodes_reserved_characters() {
        // Alphanumerics + -_.~ pass through unchanged (per RFC 3986 unreserved).
        assert_eq!(url_encode_form_value("abc123-_.~"), "abc123-_.~");
        // Colon must be escaped.
        assert_eq!(url_encode_form_value("urn:ietf"), "urn%3Aietf");
        // Space and slash too.
        assert_eq!(url_encode_form_value("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn token_request_body_shape() {
        let body = build_token_request_body("eyJ.eyJ.sig");
        // The grant_type value is fully encoded (all colons → %3A).
        assert!(
            body.starts_with("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer")
        );
        // JWT goes in the assertion parameter. Dots are unreserved so they
        // stay literal — makes debugging the wire traffic easier.
        assert!(body.contains("&assertion=eyJ.eyJ.sig"));
    }

    #[test]
    fn parse_valid_token_response() {
        let body = r#"{"access_token":"ya29.c.abc","expires_in":3599,"token_type":"Bearer"}"#;
        let token = parse_token_response(body).expect("parse");
        assert_eq!(token.access_token, "ya29.c.abc");
        assert_eq!(token.expires_in, 3599);
        // token_type intentionally not exposed on AccessToken — Google always
        // returns "Bearer" and we don't need to validate it.
    }

    #[test]
    fn parse_token_response_with_extra_fields_ok() {
        // Google sometimes adds fields like `scope`. serde should ignore them.
        let body = r#"{
            "access_token":"ya29.xyz",
            "expires_in":3600,
            "token_type":"Bearer",
            "scope":"https://www.googleapis.com/auth/firebase.messaging"
        }"#;
        let token = parse_token_response(body).expect("parse");
        assert_eq!(token.access_token, "ya29.xyz");
    }

    #[test]
    fn parse_token_response_rejects_missing_fields() {
        let body = r#"{"access_token":"ya29.abc"}"#; // no expires_in
        let err = parse_token_response(body).expect_err("must fail");
        match err {
            TokenError::ResponseParse(_) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn parse_token_response_rejects_malformed_json() {
        let err = parse_token_response("not json").expect_err("must fail");
        match err {
            TokenError::ResponseParse(_) => {}
            other => panic!("wrong variant: {:?}", other),
        }
    }
}
