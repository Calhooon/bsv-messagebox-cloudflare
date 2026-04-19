//! KV cache for FCM access tokens.
//!
//! Without caching, every FCM push would trigger a fresh JWT sign + HTTP
//! round-trip to Google — ~200–500ms per request and unnecessary quota
//! consumption. With caching, at most one token exchange per hour regardless
//! of push volume.
//!
//! Cache key: fixed `fcm:access_token` in the AUTH_SESSIONS KV namespace.
//! One service account per Worker means one cached token; if you rotate the
//! service-account secret, the next call mints a new token on cache miss.
//!
//! Race condition note: if two requests arrive during a cache miss, both
//! will mint a token concurrently. That's acceptable — neither fails, one
//! just wastes an exchange. The writes are idempotent (second one overwrites
//! first) and short-lived tokens from the loser won't outlive the winner by
//! more than a few seconds.

use crate::fcm_jwt::ServiceAccount;
use crate::fcm_token::{exchange_jwt_for_token, AccessToken, TokenError};
use serde::{Deserialize, Serialize};
use worker::Env;

/// KV namespace binding name reused from the BRC-31 middleware.
const KV_BINDING: &str = "AUTH_SESSIONS";
/// Fixed KV key — one service account per Worker.
const CACHE_KEY: &str = "fcm:access_token";
/// Seconds to subtract from expires_in so we refresh a little before expiry.
const SAFETY_BUFFER_SECS: u64 = 60;

/// A cached access token plus the unix timestamp at which it expires.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedToken {
    pub access_token: String,
    /// Unix timestamp (seconds) at which this token expires. Google's
    /// expires_in is relative; we store absolute so cache reads don't need
    /// to know when we stored it.
    pub expires_at: u64,
}

impl CachedToken {
    pub fn from_fresh(token: &AccessToken, now_secs: u64) -> Self {
        Self {
            access_token: token.access_token.clone(),
            expires_at: now_secs + token.expires_in,
        }
    }

    /// True if the token has at least SAFETY_BUFFER_SECS remaining.
    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs + SAFETY_BUFFER_SECS < self.expires_at
    }
}

/// Errors from the token-cache layer.
#[derive(Debug)]
pub enum CacheError {
    Kv(String),
    Token(TokenError),
    Serde(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Kv(s) => write!(f, "kv: {}", s),
            CacheError::Token(e) => write!(f, "token: {}", e),
            CacheError::Serde(s) => write!(f, "serde: {}", s),
        }
    }
}

/// Return a fresh access token — from KV cache if still valid, otherwise
/// mint a new one via the service-account JWT + OAuth2 exchange flow.
pub async fn get_cached_or_fresh_token(
    sa: &ServiceAccount,
    env: &Env,
    now_secs: u64,
) -> Result<String, CacheError> {
    let kv = env
        .kv(KV_BINDING)
        .map_err(|e| CacheError::Kv(e.to_string()))?;

    // Cache read. Malformed or expired entries just fall through to re-mint.
    if let Ok(Some(json)) = kv.get(CACHE_KEY).text().await {
        if let Ok(entry) = serde_json::from_str::<CachedToken>(&json) {
            if entry.is_fresh(now_secs) {
                return Ok(entry.access_token);
            }
        }
    }

    // Cache miss or stale — mint a new token.
    let fresh = exchange_jwt_for_token(sa, now_secs)
        .await
        .map_err(CacheError::Token)?;
    let entry = CachedToken::from_fresh(&fresh, now_secs);
    let serialized = serde_json::to_string(&entry).map_err(|e| CacheError::Serde(e.to_string()))?;

    // Best-effort write. If the put fails we still return the token — worst
    // case we re-mint next request. Using Google's expires_in minus the
    // safety buffer so KV TTL aligns with in-token expiry.
    let ttl = fresh.expires_in.saturating_sub(SAFETY_BUFFER_SECS);
    if let Ok(builder) = kv.put(CACHE_KEY, serialized) {
        let _ = builder.expiration_ttl(ttl).execute().await;
    }

    Ok(fresh.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_token_fresh_with_plenty_of_headroom() {
        let token = CachedToken {
            access_token: "ya29.foo".to_string(),
            expires_at: 1_000_000 + 3600, // 1 hour headroom
        };
        assert!(token.is_fresh(1_000_000));
    }

    #[test]
    fn cached_token_fresh_just_past_buffer() {
        // 61s > 60s buffer — still fresh.
        let token = CachedToken {
            access_token: "ya29.foo".to_string(),
            expires_at: 1_000_061,
        };
        assert!(token.is_fresh(1_000_000));
    }

    #[test]
    fn cached_token_stale_inside_buffer() {
        // 30s < 60s buffer — treated as stale to force re-mint.
        let token = CachedToken {
            access_token: "ya29.foo".to_string(),
            expires_at: 1_000_030,
        };
        assert!(!token.is_fresh(1_000_000));
    }

    #[test]
    fn cached_token_stale_past_deadline() {
        let token = CachedToken {
            access_token: "ya29.foo".to_string(),
            expires_at: 900_000,
        };
        assert!(!token.is_fresh(1_000_000));
    }

    #[test]
    fn cached_token_from_fresh_computes_absolute_expiry() {
        let access = AccessToken {
            access_token: "ya29.bar".to_string(),
            expires_in: 3599,
        };
        let cached = CachedToken::from_fresh(&access, 1_700_000_000);
        assert_eq!(cached.access_token, "ya29.bar");
        assert_eq!(cached.expires_at, 1_700_003_599);
    }

    #[test]
    fn cached_token_serde_round_trip() {
        let token = CachedToken {
            access_token: "ya29.baz".to_string(),
            expires_at: 1_700_003_599,
        };
        let json = serde_json::to_string(&token).expect("serialize");
        let parsed: CachedToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.access_token, token.access_token);
        assert_eq!(parsed.expires_at, token.expires_at);
    }
}
