//! Engine.IO v4 + Socket.IO v5 packet codec.
//!
//! ## Engine.IO packets
//!
//! Each packet on the wire is `<type-digit>[<payload>]`:
//!
//! | Type | Code | Direction      | Notes                                                |
//! |------|------|----------------|------------------------------------------------------|
//! | open | `0`  | server → client| handshake JSON: `{sid,upgrades,pingInterval,...}`    |
//! | close| `1`  | bidirectional  | terminate transport                                  |
//! | ping | `2`  | bidirectional  | heartbeat (or `2probe` during transport upgrade)     |
//! | pong | `3`  | bidirectional  | heartbeat reply (or `3probe` during upgrade)         |
//! | message | `4`| bidirectional | carries a Socket.IO packet in the payload            |
//! | upgrade | `5`| client → server| client commits to the upgraded transport            |
//! | noop    | `6`| server → client| flushes a pending HTTP poll (used during upgrade)   |
//!
//! Polling format: when an HTTP body carries multiple Engine.IO packets,
//! they are concatenated using the U+001E "record separator" (`\x1e`).
//!
//! ## Socket.IO packets (carried in Engine.IO `4` payloads)
//!
//! Format: `<type-digit>[<nsp>,][<ack-id>][<json-payload>]`
//!
//! | Type           | Code |
//! |----------------|------|
//! | CONNECT        | `0`  |
//! | DISCONNECT     | `1`  |
//! | EVENT          | `2`  |
//! | ACK            | `3`  |
//! | CONNECT_ERROR  | `4`  |
//!
//! The namespace is OMITTED when it is the default `/`. When present it
//! is followed by a single `,` separator. Examples:
//!   - `0`              → CONNECT to default namespace (client → server)
//!   - `0{"sid":"x"}`   → server CONNECT ack to default ns
//!   - `0/admin,`       → CONNECT to /admin
//!   - `2["foo","bar"]` → EVENT [foo, bar] on default ns
//!   - `2/admin,["x"]`  → EVENT [x] on /admin
//!   - `212["foo"]`     → EVENT [foo] on default ns with ack id 12
//!
//! Only the no-namespace and default-`/` namespace cases are exercised
//! by the AuthSocket transport, but the parser handles arbitrary
//! namespaces correctly so non-standard clients still parse.

use serde_json::Value;

/// U+001E record separator used between concatenated Engine.IO
/// packets in HTTP polling bodies.
pub const RECORD_SEP: char = '\x1e';

// ============================================================================
// Engine.IO
// ============================================================================

/// One Engine.IO packet in decoded form. The payload (when present) is
/// kept as `String` because the polling/WS transports always speak text
/// for the AuthSocket use-case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineIoPacket {
    /// Server → client open packet. Payload is the handshake JSON.
    Open(String),
    /// Close (transport teardown). Optional reason text.
    Close,
    /// Engine.IO ping. The probe variant carries `"probe"` as payload
    /// during the WS upgrade dance; bare heartbeats have no payload.
    Ping(String),
    /// Engine.IO pong, mirror of Ping.
    Pong(String),
    /// Engine.IO message packet. Payload is the Socket.IO-encoded packet
    /// as a string (encoded by `SocketIoPacket::encode`).
    Message(String),
    /// Client → server upgrade commit packet. No payload.
    Upgrade,
    /// Server → client noop, used to flush a pending HTTP poll mid-upgrade.
    Noop,
}

impl EngineIoPacket {
    /// Encode this packet to its on-the-wire string form.
    pub fn encode(&self) -> String {
        match self {
            EngineIoPacket::Open(payload) => format!("0{payload}"),
            EngineIoPacket::Close => "1".to_string(),
            EngineIoPacket::Ping(payload) => format!("2{payload}"),
            EngineIoPacket::Pong(payload) => format!("3{payload}"),
            EngineIoPacket::Message(payload) => format!("4{payload}"),
            EngineIoPacket::Upgrade => "5".to_string(),
            EngineIoPacket::Noop => "6".to_string(),
        }
    }

    /// Decode a single Engine.IO packet from a string. Returns an error
    /// for empty input or unknown leading digit.
    pub fn decode(raw: &str) -> Result<Self, CodecError> {
        let mut chars = raw.chars();
        let head = chars.next().ok_or(CodecError::EmptyPacket)?;
        let rest: String = chars.collect();
        Ok(match head {
            '0' => EngineIoPacket::Open(rest),
            '1' => EngineIoPacket::Close,
            '2' => EngineIoPacket::Ping(rest),
            '3' => EngineIoPacket::Pong(rest),
            '4' => EngineIoPacket::Message(rest),
            '5' => {
                if !rest.is_empty() {
                    return Err(CodecError::Malformed(format!(
                        "upgrade packet must have no payload, got {rest:?}"
                    )));
                }
                EngineIoPacket::Upgrade
            }
            '6' => {
                if !rest.is_empty() {
                    return Err(CodecError::Malformed(format!(
                        "noop packet must have no payload, got {rest:?}"
                    )));
                }
                EngineIoPacket::Noop
            }
            other => return Err(CodecError::UnknownType(other)),
        })
    }
}

/// Encode a batch of packets into a single HTTP polling body using
/// the `\x1e` record separator.
pub fn encode_polling_batch(packets: &[EngineIoPacket]) -> String {
    let mut out = String::new();
    for (i, p) in packets.iter().enumerate() {
        if i > 0 {
            out.push(RECORD_SEP);
        }
        out.push_str(&p.encode());
    }
    out
}

/// Decode an HTTP polling body that may contain one or more concatenated
/// Engine.IO packets. Empty input yields an empty Vec, which represents
/// an empty body (treated as "client poll with no inbound data" by
/// callers).
pub fn decode_polling_batch(raw: &str) -> Result<Vec<EngineIoPacket>, CodecError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    raw.split(RECORD_SEP).map(EngineIoPacket::decode).collect()
}

// ============================================================================
// Socket.IO
// ============================================================================

/// Decoded Socket.IO packet. We don't bother with `BINARY_EVENT` /
/// `BINARY_ACK` because the AuthSocket transport never sends binary
/// attachments — the JSON payload carries everything.
#[derive(Debug, Clone, PartialEq)]
pub enum SocketIoPacket {
    /// CONNECT (type 0). Client → server: optional auth payload.
    /// Server → client: `{ sid: <socket-sid> }`.
    Connect { nsp: String, data: Option<Value> },
    /// DISCONNECT (type 1). No payload.
    Disconnect { nsp: String },
    /// EVENT (type 2). Payload is the JSON-array `[event_name, ...args]`.
    Event {
        nsp: String,
        ack_id: Option<u64>,
        data: Vec<Value>,
    },
    /// ACK (type 3). Same shape as EVENT but `ack_id` is mandatory.
    Ack {
        nsp: String,
        ack_id: u64,
        data: Vec<Value>,
    },
    /// CONNECT_ERROR (type 4). Payload is the rejection reason object.
    ConnectError { nsp: String, data: Option<Value> },
}

const DEFAULT_NSP: &str = "/";

impl SocketIoPacket {
    /// Borrow the namespace string for this packet.
    pub fn nsp(&self) -> &str {
        match self {
            SocketIoPacket::Connect { nsp, .. }
            | SocketIoPacket::Disconnect { nsp }
            | SocketIoPacket::Event { nsp, .. }
            | SocketIoPacket::Ack { nsp, .. }
            | SocketIoPacket::ConnectError { nsp, .. } => nsp,
        }
    }

    /// Encode this packet to the on-the-wire string form (without the
    /// surrounding Engine.IO `4` prefix — wrap with
    /// `EngineIoPacket::Message(s.encode())` to send).
    pub fn encode(&self) -> String {
        let mut out = String::new();
        let type_code = match self {
            SocketIoPacket::Connect { .. } => '0',
            SocketIoPacket::Disconnect { .. } => '1',
            SocketIoPacket::Event { .. } => '2',
            SocketIoPacket::Ack { .. } => '3',
            SocketIoPacket::ConnectError { .. } => '4',
        };
        out.push(type_code);

        // Namespace prefix: only present when non-default. Followed by `,`.
        let nsp = self.nsp();
        if nsp != DEFAULT_NSP {
            out.push_str(nsp);
            out.push(',');
        }

        // Ack id (decimal) — encoded between the namespace and the JSON
        // payload, with no separator.
        if let SocketIoPacket::Event {
            ack_id: Some(id), ..
        } = self
        {
            out.push_str(&id.to_string());
        }
        if let SocketIoPacket::Ack { ack_id, .. } = self {
            out.push_str(&ack_id.to_string());
        }

        // JSON payload — only present for some packet types.
        match self {
            SocketIoPacket::Connect { data, .. } | SocketIoPacket::ConnectError { data, .. } => {
                if let Some(v) = data {
                    out.push_str(&serde_json::to_string(v).unwrap_or_default());
                }
            }
            SocketIoPacket::Event { data, .. } | SocketIoPacket::Ack { data, .. } => {
                // Always serialize as a JSON array (mandatory per spec).
                let arr = Value::Array(data.clone());
                out.push_str(&serde_json::to_string(&arr).unwrap_or_default());
            }
            SocketIoPacket::Disconnect { .. } => {}
        }
        out
    }

    /// Decode a Socket.IO packet from the payload of an Engine.IO message
    /// packet (i.e. without the leading `4`).
    pub fn decode(raw: &str) -> Result<Self, CodecError> {
        let mut chars = raw.chars();
        let type_ch = chars.next().ok_or(CodecError::EmptyPacket)?;

        // Optional namespace: if next char is `/`, read up to the first
        // `,` (or end of string for type-only packets like CONNECT to
        // /custom with no payload, where the wire form is `0/custom,`).
        let mut rest: String = chars.collect();
        let nsp = if rest.starts_with('/') {
            // Find the comma that ends the namespace; if there's no
            // comma, the entire remainder is the namespace.
            if let Some(comma_idx) = rest.find(',') {
                let ns = rest[..comma_idx].to_string();
                rest = rest[comma_idx + 1..].to_string();
                ns
            } else {
                let ns = rest.clone();
                rest.clear();
                ns
            }
        } else {
            DEFAULT_NSP.to_string()
        };

        // Optional ack id: leading run of decimal digits.
        let ack_digit_count = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        let ack_id: Option<u64> = if ack_digit_count > 0 {
            rest[..ack_digit_count].parse().ok()
        } else {
            None
        };
        let payload = &rest[ack_digit_count..];

        // Parse JSON payload if present.
        let data: Option<Value> = if payload.is_empty() {
            None
        } else {
            Some(serde_json::from_str(payload).map_err(|e| {
                CodecError::Malformed(format!("invalid JSON in socket.io payload: {e}"))
            })?)
        };

        Ok(match type_ch {
            '0' => SocketIoPacket::Connect { nsp, data },
            '1' => SocketIoPacket::Disconnect { nsp },
            '2' => {
                let arr = match data {
                    Some(Value::Array(a)) if !a.is_empty() => a,
                    Some(_) => {
                        return Err(CodecError::Malformed(
                            "socket.io EVENT payload must be a non-empty array".into(),
                        ))
                    }
                    None => {
                        return Err(CodecError::Malformed(
                            "socket.io EVENT requires a payload".into(),
                        ))
                    }
                };
                SocketIoPacket::Event {
                    nsp,
                    ack_id,
                    data: arr,
                }
            }
            '3' => {
                let arr = match data {
                    Some(Value::Array(a)) => a,
                    Some(_) => {
                        return Err(CodecError::Malformed(
                            "socket.io ACK payload must be an array".into(),
                        ))
                    }
                    None => Vec::new(),
                };
                let id = ack_id.ok_or_else(|| {
                    CodecError::Malformed("socket.io ACK requires an ack id".into())
                })?;
                SocketIoPacket::Ack {
                    nsp,
                    ack_id: id,
                    data: arr,
                }
            }
            '4' => SocketIoPacket::ConnectError { nsp, data },
            other => {
                return Err(CodecError::UnknownType(other));
            }
        })
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    EmptyPacket,
    UnknownType(char),
    Malformed(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::EmptyPacket => write!(f, "empty packet"),
            CodecError::UnknownType(c) => write!(f, "unknown packet type: {c:?}"),
            CodecError::Malformed(s) => write!(f, "malformed packet: {s}"),
        }
    }
}

impl std::error::Error for CodecError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---------- Engine.IO ----------

    #[test]
    fn engineio_open_round_trips() {
        let payload =
            r#"{"sid":"x","upgrades":["websocket"],"pingInterval":25000,"pingTimeout":20000}"#;
        let p = EngineIoPacket::Open(payload.to_string());
        let s = p.encode();
        assert!(s.starts_with('0'));
        assert_eq!(EngineIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn engineio_close_round_trips() {
        let p = EngineIoPacket::Close;
        assert_eq!(p.encode(), "1");
        assert_eq!(EngineIoPacket::decode("1").unwrap(), p);
    }

    #[test]
    fn engineio_ping_pong_no_payload() {
        assert_eq!(EngineIoPacket::Ping("".into()).encode(), "2");
        assert_eq!(EngineIoPacket::Pong("".into()).encode(), "3");
        assert_eq!(
            EngineIoPacket::decode("2").unwrap(),
            EngineIoPacket::Ping("".into())
        );
        assert_eq!(
            EngineIoPacket::decode("3").unwrap(),
            EngineIoPacket::Pong("".into())
        );
    }

    #[test]
    fn engineio_ping_pong_probe() {
        // The transport-upgrade probe sequence sends `2probe` / `3probe`
        // — these MUST round-trip through the codec or upgrade fails.
        assert_eq!(EngineIoPacket::Ping("probe".into()).encode(), "2probe");
        assert_eq!(EngineIoPacket::Pong("probe".into()).encode(), "3probe");
        assert_eq!(
            EngineIoPacket::decode("2probe").unwrap(),
            EngineIoPacket::Ping("probe".into())
        );
        assert_eq!(
            EngineIoPacket::decode("3probe").unwrap(),
            EngineIoPacket::Pong("probe".into())
        );
    }

    #[test]
    fn engineio_message_round_trips() {
        let p = EngineIoPacket::Message("2[\"hello\"]".into());
        assert_eq!(p.encode(), "42[\"hello\"]");
        assert_eq!(EngineIoPacket::decode("42[\"hello\"]").unwrap(), p);
    }

    #[test]
    fn engineio_upgrade_and_noop() {
        assert_eq!(EngineIoPacket::Upgrade.encode(), "5");
        assert_eq!(EngineIoPacket::Noop.encode(), "6");
        assert_eq!(
            EngineIoPacket::decode("5").unwrap(),
            EngineIoPacket::Upgrade
        );
        assert_eq!(EngineIoPacket::decode("6").unwrap(), EngineIoPacket::Noop);
    }

    #[test]
    fn engineio_decode_rejects_empty() {
        assert_eq!(EngineIoPacket::decode(""), Err(CodecError::EmptyPacket));
    }

    #[test]
    fn engineio_decode_rejects_unknown() {
        assert!(matches!(
            EngineIoPacket::decode("9foo"),
            Err(CodecError::UnknownType('9'))
        ));
    }

    #[test]
    fn polling_batch_single_packet() {
        let pkts = vec![EngineIoPacket::Message("2[\"a\"]".into())];
        let s = encode_polling_batch(&pkts);
        assert_eq!(s, "42[\"a\"]");
        assert_eq!(decode_polling_batch(&s).unwrap(), pkts);
    }

    #[test]
    fn polling_batch_multi_packet_uses_record_separator() {
        // Spec sample from the protocol README: `42["hello"]\x1e42["world"]`.
        let pkts = vec![
            EngineIoPacket::Message("2[\"hello\"]".into()),
            EngineIoPacket::Message("2[\"world\"]".into()),
        ];
        let s = encode_polling_batch(&pkts);
        assert_eq!(s, "42[\"hello\"]\u{1e}42[\"world\"]");
        assert_eq!(decode_polling_batch(&s).unwrap(), pkts);
    }

    #[test]
    fn polling_batch_empty_string_yields_empty_vec() {
        assert!(decode_polling_batch("").unwrap().is_empty());
    }

    // ---------- Socket.IO ----------

    #[test]
    fn socketio_connect_default_namespace_no_payload() {
        // Client→server CONNECT: bare `0` (default namespace, no auth).
        let p = SocketIoPacket::Connect {
            nsp: "/".into(),
            data: None,
        };
        assert_eq!(p.encode(), "0");
        assert_eq!(SocketIoPacket::decode("0").unwrap(), p);
    }

    #[test]
    fn socketio_connect_default_namespace_with_sid() {
        // Server→client CONNECT ack: `0{"sid":"..."}`.
        let p = SocketIoPacket::Connect {
            nsp: "/".into(),
            data: Some(json!({"sid":"wZX3oN0bSVIhsaknAAAI"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"0{"sid":"wZX3oN0bSVIhsaknAAAI"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_connect_custom_namespace_with_payload() {
        let p = SocketIoPacket::Connect {
            nsp: "/admin".into(),
            data: Some(json!({"token":"123"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"0/admin,{"token":"123"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_disconnect_default_namespace() {
        let p = SocketIoPacket::Disconnect { nsp: "/".into() };
        assert_eq!(p.encode(), "1");
        assert_eq!(SocketIoPacket::decode("1").unwrap(), p);
    }

    #[test]
    fn socketio_disconnect_custom_namespace_round_trips() {
        let p = SocketIoPacket::Disconnect {
            nsp: "/admin".into(),
        };
        // Wire form per spec sample: `1/admin,`
        assert_eq!(p.encode(), "1/admin,");
        assert_eq!(SocketIoPacket::decode("1/admin,").unwrap(), p);
    }

    #[test]
    fn socketio_event_default_namespace_round_trips() {
        let p = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: None,
            data: vec![json!("foo"), json!("bar")],
        };
        let s = p.encode();
        assert_eq!(s, r#"2["foo","bar"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_custom_namespace_with_ack() {
        let p = SocketIoPacket::Event {
            nsp: "/admin".into(),
            ack_id: Some(13),
            data: vec![json!("foo")],
        };
        let s = p.encode();
        assert_eq!(s, r#"2/admin,13["foo"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_with_ack_id_default_namespace() {
        // Spec example: `212["foo"]` with ack id 12.
        let p = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: Some(12),
            data: vec![json!("foo")],
        };
        let s = p.encode();
        assert_eq!(s, r#"212["foo"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_ack_round_trips() {
        let p = SocketIoPacket::Ack {
            nsp: "/".into(),
            ack_id: 12,
            data: vec![json!("ok")],
        };
        let s = p.encode();
        assert_eq!(s, r#"312["ok"]"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_connect_error_round_trips() {
        let p = SocketIoPacket::ConnectError {
            nsp: "/".into(),
            data: Some(json!({"message":"Not authorized"})),
        };
        let s = p.encode();
        assert_eq!(s, r#"4{"message":"Not authorized"}"#);
        assert_eq!(SocketIoPacket::decode(&s).unwrap(), p);
    }

    #[test]
    fn socketio_event_rejects_non_array_payload() {
        // Per spec: EVENT payload MUST be a non-empty array.
        assert!(SocketIoPacket::decode("2{\"foo\":1}").is_err());
        assert!(SocketIoPacket::decode("2[]").is_err());
    }

    #[test]
    fn socketio_full_engineio_wrapped_event_decodes() {
        // The full wire form a client sends for `socket.emit("test","hi")`
        // on the default namespace: `42["test","hi"]`.
        let eio = EngineIoPacket::decode("42[\"test\",\"hi\"]").unwrap();
        let payload = match eio {
            EngineIoPacket::Message(p) => p,
            _ => panic!("expected message"),
        };
        let sio = SocketIoPacket::decode(&payload).unwrap();
        match sio {
            SocketIoPacket::Event { nsp, ack_id, data } => {
                assert_eq!(nsp, "/");
                assert_eq!(ack_id, None);
                assert_eq!(data, vec![json!("test"), json!("hi")]);
            }
            _ => panic!("expected event"),
        }
    }
}
