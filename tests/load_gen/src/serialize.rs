//! BRC-104 binary payload serialization for BRC-31 Authrite.
//!
//! Direct port of the proven implementation in rust-bsv-worm
//! (`src/auth/serialization.rs`). Same wire format the TS SDK and Go
//! clients use against the bsv-middleware-cloudflare server. Pure
//! function, no I/O — safe to call repeatedly under fan-out.

use bsv_rs::primitives::to_var_int;

pub const EMPTY_SENTINEL: [u8; 9] = [0xFF; 9];

fn write_varint_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&to_var_int(data.len() as u64));
    buf.extend_from_slice(data);
}

fn write_optional_string(buf: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(s) if !s.is_empty() => write_varint_bytes(buf, s.as_bytes()),
        _ => buf.extend_from_slice(&EMPTY_SENTINEL),
    }
}

fn write_optional_bytes(buf: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) if !d.is_empty() => write_varint_bytes(buf, d),
        _ => buf.extend_from_slice(&EMPTY_SENTINEL),
    }
}

fn write_headers(buf: &mut Vec<u8>, headers: &[(String, String)]) {
    buf.extend_from_slice(&to_var_int(headers.len() as u64));
    for (key, value) in headers {
        write_varint_bytes(buf, key.as_bytes());
        write_varint_bytes(buf, value.as_bytes());
    }
}

/// Serialize an HTTP request into BRC-104 binary format for signing.
pub fn serialize_request(
    request_id: &[u8; 32],
    method: &str,
    path: Option<&str>,
    query: Option<&str>,
    signable_headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(request_id);
    write_varint_bytes(&mut buf, method.as_bytes());
    write_optional_string(&mut buf, path);
    write_optional_string(&mut buf, query);
    write_headers(&mut buf, signable_headers);
    write_optional_bytes(&mut buf, body);
    buf
}

/// Filter and sort headers for BRC-31 signature.
///
/// Rules:
/// - Include `x-bsv-*` headers EXCEPT `x-bsv-auth-*`
/// - Include `authorization` verbatim
/// - Include `content-type` (media type only — strip `;charset=...`)
/// - Sort alphabetically by lowercase key
pub fn filter_signable_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (key, value) in headers {
        let lower = key.to_lowercase();
        if lower.starts_with("x-bsv-auth-") {
            continue;
        }
        if lower.starts_with("x-bsv-") {
            result.push((lower, value.clone()));
            continue;
        }
        if lower == "authorization" {
            result.push((lower, value.clone()));
            continue;
        }
        if lower == "content-type" {
            let media_type = value.split(';').next().unwrap_or(value).trim().to_string();
            result.push((lower, media_type));
            continue;
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

pub fn build_auth_headers(
    identity_key: &str,
    nonce_b64: &str,
    your_nonce_b64: &str,
    signature_hex: &str,
    request_id_b64: &str,
) -> Vec<(String, String)> {
    vec![
        ("x-bsv-auth-version".into(), "0.1".into()),
        ("x-bsv-auth-identity-key".into(), identity_key.into()),
        ("x-bsv-auth-message-type".into(), "general".into()),
        ("x-bsv-auth-nonce".into(), nonce_b64.into()),
        ("x-bsv-auth-your-nonce".into(), your_nonce_b64.into()),
        ("x-bsv-auth-signature".into(), signature_hex.into()),
        ("x-bsv-auth-request-id".into(), request_id_b64.into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The length prefix at every width boundary, byte for byte as the
    /// hand-rolled writer emitted it before bsv-rs 0.6.0 became its home.
    #[test]
    fn length_prefix_bytes_at_each_width() {
        let rows: [(u64, &[u8]); 8] = [
            (0, &[0x00]),
            (252, &[0xFC]),
            (253, &[0xFD, 0xFD, 0x00]),
            (0xFFFF, &[0xFD, 0xFF, 0xFF]),
            (0x1_0000, &[0xFE, 0x00, 0x00, 0x01, 0x00]),
            (0xFFFF_FFFF, &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
            (0x1_0000_0000, &[0xFF, 0, 0, 0, 0, 1, 0, 0, 0]),
            (u64::MAX, &EMPTY_SENTINEL),
        ];
        for (n, want) in rows {
            assert_eq!(to_var_int(n), want, "length {n}");
        }
    }

    #[test]
    fn request_frame_is_unchanged() {
        let id = [7u8; 32];
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let got = serialize_request(
            &id,
            "POST",
            Some("/sendMessage"),
            None,
            &headers,
            Some(b"{}"),
        );
        let mut want = id.to_vec();
        want.extend_from_slice(b"\x04POST\x0c/sendMessage");
        want.extend_from_slice(&EMPTY_SENTINEL);
        want.extend_from_slice(b"\x01\x0ccontent-type\x10application/json\x02{}");
        assert_eq!(got, want);
    }
}
