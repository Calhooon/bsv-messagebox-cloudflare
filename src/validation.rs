// Pure validation functions for request payloads.
// These are extracted so they can be unit tested without D1/WASM.

use serde_json::{json, Value};

/// Error result: (json_body, http_status_code)
pub type ValErr = (Value, u16);
pub type ValResult<T> = Result<T, ValErr>;

fn err(status: u16, code: &str, description: &str) -> ValErr {
    (
        json!({ "status": "error", "code": code, "description": description }),
        status,
    )
}

/// Parsed + validated sendMessage input (multi-recipient, optional payment).
#[derive(Debug)]
pub struct ValidatedSendMessage {
    pub recipients: Vec<(String, String)>, // (recipient_key, message_id) pairs
    pub message_box: String,
    pub body: Value, // Raw body value (wrapping happens per-recipient in handler)
    pub payment: Option<Value>, // Raw payment object if present
}

/// Validate sendMessage request body. Exact validation order from Node.js.
pub fn validate_send_message(raw: &[u8]) -> ValResult<ValidatedSendMessage> {
    // Parse JSON — matches go-messagebox-server's explicit ERR_INVALID_JSON path
    let body: Value = serde_json::from_slice(raw)
        .map_err(|_| err(400, "ERR_INVALID_JSON", "Invalid JSON body"))?;

    // 1. message object must exist
    let message = body.get("message").ok_or_else(|| {
        err(
            400,
            "ERR_MESSAGE_REQUIRED",
            "Please provide a valid message to send!",
        )
    })?;

    if !message.is_object() {
        return Err(err(400, "ERR_INVALID_MESSAGEBOX", "Invalid message box."));
    }

    // 2. messageBox must be non-empty string
    let message_box = message
        .get("messageBox")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err(400, "ERR_INVALID_MESSAGEBOX", "Invalid message box."))?;

    // 3. body must be present, not null, and not an empty string.
    // Matches go-messagebox-server: accepts strings, objects, arrays, numbers, and
    // booleans. TS is stricter (rejects numbers/booleans); we follow Go for parity.
    let msg_body = message
        .get("body")
        .ok_or_else(|| err(400, "ERR_INVALID_MESSAGE_BODY", "Invalid message body."))?;
    if msg_body.is_null() || (msg_body.is_string() && msg_body.as_str().unwrap().is_empty()) {
        return Err(err(
            400,
            "ERR_INVALID_MESSAGE_BODY",
            "Invalid message body.",
        ));
    }

    // 4. Recipient(s) — support `recipients` array or `recipient` string/array
    let recipients_val = message
        .get("recipients")
        .or_else(|| message.get("recipient"));
    let recipients: Vec<String> = match recipients_val {
        None => {
            return Err(err(
                400,
                "ERR_RECIPIENT_REQUIRED",
                "Missing recipient(s). Provide \"recipient\" or \"recipients\".",
            ))
        }
        Some(v) if v.is_string() => vec![v.as_str().unwrap().to_string()],
        Some(v) if v.is_array() => v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        Some(v) => {
            let key_str = match v {
                _ if v.is_number() => v.to_string(),
                _ if v.is_boolean() => v.to_string(),
                _ => v.as_str().unwrap_or("").to_string(),
            };
            return Err(err(
                400,
                "ERR_INVALID_RECIPIENT_KEY",
                &format!("Invalid recipient key: {}", key_str),
            ));
        }
    };
    if recipients.is_empty() {
        return Err(err(
            400,
            "ERR_RECIPIENT_REQUIRED",
            "Missing recipient(s). Provide \"recipient\" or \"recipients\".",
        ));
    }

    // 5. messageId(s)
    let message_id_val = message.get("messageId");
    let message_ids: Vec<String> = match message_id_val {
        None => return Err(err(400, "ERR_MESSAGEID_REQUIRED", "Missing messageId.")),
        Some(v) if v.is_string() => vec![v.as_str().unwrap().to_string()],
        Some(v) if v.is_array() => v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item.as_str().map(String::from))
            .collect(),
        Some(_) => return Err(err(400, "ERR_MESSAGEID_REQUIRED", "Missing messageId.")),
    };

    // 6. Count must match
    if recipients.len() > 1 && message_ids.len() == 1 {
        return Err(err(400, "ERR_MESSAGEID_COUNT_MISMATCH",
            &format!("Provided 1 messageId for {} recipients. Provide one messageId per recipient (same order).", recipients.len())));
    }
    if recipients.len() != message_ids.len() {
        return Err(err(
            400,
            "ERR_MESSAGEID_COUNT_MISMATCH",
            &format!(
                "Recipients ({}) and messageId count ({}) must match.",
                recipients.len(),
                message_ids.len()
            ),
        ));
    }

    // 7. Validate each messageId is non-empty
    for mid in &message_ids {
        if mid.is_empty() {
            return Err(err(
                400,
                "ERR_INVALID_MESSAGEID",
                "Each messageId must be a non-empty string.",
            ));
        }
    }

    // 8. Validate each recipient is a valid compressed public key (66 hex chars)
    for r in &recipients {
        if !is_valid_pubkey(r) {
            return Err(err(
                400,
                "ERR_INVALID_RECIPIENT_KEY",
                &format!("Invalid recipient key: {}", r),
            ));
        }
    }

    // Build (recipient, messageId) pairs
    let pairs: Vec<(String, String)> = recipients.into_iter().zip(message_ids).collect();

    // Extract payment if present
    let payment = body.get("payment").cloned();

    Ok(ValidatedSendMessage {
        recipients: pairs,
        message_box: message_box.to_string(),
        body: msg_body.clone(),
        payment,
    })
}

/// Validated listMessages input.
#[derive(Debug)]
pub struct ValidatedListMessages {
    pub message_box: String,
}

/// Validate listMessages request body.
pub fn validate_list_messages(raw: &[u8]) -> ValResult<ValidatedListMessages> {
    let body: Value = serde_json::from_slice(raw)
        .map_err(|_| err(400, "ERR_INVALID_JSON", "Invalid JSON body"))?;

    let message_box = body.get("messageBox").ok_or_else(|| {
        err(
            400,
            "ERR_MESSAGEBOX_REQUIRED",
            "Please provide the name of a valid MessageBox!",
        )
    })?;

    if !message_box.is_string() {
        return Err(err(
            400,
            "ERR_INVALID_MESSAGEBOX",
            "MessageBox name must be a string!",
        ));
    }

    let s = message_box.as_str().unwrap();
    if s.is_empty() {
        return Err(err(
            400,
            "ERR_MESSAGEBOX_REQUIRED",
            "Please provide the name of a valid MessageBox!",
        ));
    }

    Ok(ValidatedListMessages {
        message_box: s.to_string(),
    })
}

/// Validated acknowledgeMessage input.
#[derive(Debug)]
pub struct ValidatedAcknowledge {
    pub message_ids: Vec<String>,
}

/// Validate acknowledgeMessage request body.
pub fn validate_acknowledge(raw: &[u8]) -> ValResult<ValidatedAcknowledge> {
    let body: Value = serde_json::from_slice(raw)
        .map_err(|_| err(400, "ERR_INVALID_JSON", "Invalid JSON body"))?;

    let ids_val = body.get("messageIds").ok_or_else(|| {
        err(
            400,
            "ERR_MESSAGE_ID_REQUIRED",
            "Please provide the IDs of messages to acknowledge.",
        )
    })?;

    if !ids_val.is_array() {
        return Err(err(
            400,
            "ERR_INVALID_MESSAGE_ID",
            "Message IDs must be formatted as an array of strings!",
        ));
    }

    let arr = ids_val.as_array().unwrap();
    if arr.is_empty() {
        return Err(err(
            400,
            "ERR_MESSAGE_ID_REQUIRED",
            "Please provide the IDs of messages to acknowledge.",
        ));
    }

    let mut ids = Vec::with_capacity(arr.len());
    for item in arr {
        match item.as_str() {
            Some(s) if !s.is_empty() => ids.push(s.to_string()),
            _ => {
                return Err(err(
                    400,
                    "ERR_INVALID_MESSAGE_ID",
                    "Message IDs must be formatted as an array of strings!",
                ))
            }
        }
    }

    Ok(ValidatedAcknowledge { message_ids: ids })
}

/// Check if a string is a valid compressed secp256k1 public key (02/03 + 64 hex).
pub fn is_valid_pubkey(s: &str) -> bool {
    s.len() == 66
        && (s.starts_with("02") || s.starts_with("03"))
        && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID_PUBKEY: &str = "028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1";

    // ---- sendMessage validation tests (mirrors Node.js test vectors) ----

    #[test]
    fn send_missing_message() {
        let raw = b"{}";
        let err = validate_send_message(raw).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGE_REQUIRED");
    }

    #[test]
    fn send_message_not_object() {
        let raw = json!({ "message": "string" }).to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
    }

    #[test]
    fn send_missing_recipient() {
        let raw = json!({
            "message": { "messageBox": "inbox", "body": "{}", "messageId": "id1" }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_RECIPIENT_REQUIRED");
    }

    #[test]
    fn send_recipient_not_string() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": "{}", "messageId": "id1",
                "recipient": 123
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_RECIPIENT_KEY");
    }

    #[test]
    fn send_missing_message_box() {
        let raw = json!({
            "message": {
                "body": "{}", "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
    }

    #[test]
    fn send_message_box_not_string() {
        let raw = json!({
            "message": {
                "messageBox": 123, "body": "{}", "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
    }

    #[test]
    fn send_body_null_rejected() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": null, "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGE_BODY");
    }

    #[test]
    fn send_body_empty_string_rejected() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": "", "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGE_BODY");
    }

    // Go-parity tests: numeric/boolean/array bodies are ACCEPTED (Rust matches
    // go-messagebox-server, which is more permissive than TS on this one point).
    #[test]
    fn send_body_number_accepted() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": 42, "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        assert!(
            validate_send_message(raw.as_bytes()).is_ok(),
            "numeric body should be accepted (Go parity)"
        );
    }

    #[test]
    fn send_body_boolean_accepted() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": true, "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        assert!(
            validate_send_message(raw.as_bytes()).is_ok(),
            "boolean body should be accepted (Go parity)"
        );
    }

    #[test]
    fn send_body_array_accepted() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": [1, 2, 3], "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        assert!(
            validate_send_message(raw.as_bytes()).is_ok(),
            "array body should be accepted (Go parity)"
        );
    }

    #[test]
    fn send_missing_body() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGE_BODY");
    }

    #[test]
    fn send_missing_message_id() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": "{}",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGEID_REQUIRED");
    }

    #[test]
    fn send_invalid_recipient_key() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": "{}", "messageId": "id1",
                "recipient": "not-a-valid-key"
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_RECIPIENT_KEY");
    }

    #[test]
    fn send_valid_request() {
        let raw = json!({
            "message": {
                "messageBox": "payment_inbox",
                "body": "{}",
                "messageId": "mock-message-id",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let result = validate_send_message(raw.as_bytes()).unwrap();
        assert_eq!(result.recipients.len(), 1);
        assert_eq!(result.recipients[0].0, VALID_PUBKEY);
        assert_eq!(result.recipients[0].1, "mock-message-id");
        assert_eq!(result.message_box, "payment_inbox");
        assert_eq!(result.body, "{}");
        assert!(result.payment.is_none());
    }

    #[test]
    fn send_body_as_object() {
        let raw = json!({
            "message": {
                "messageBox": "inbox",
                "body": { "key": "value" },
                "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let result = validate_send_message(raw.as_bytes()).unwrap();
        assert_eq!(result.body["key"], "value");
    }

    #[test]
    fn send_multi_recipient() {
        let key2 = "038d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1";
        let raw = json!({
            "message": {
                "messageBox": "inbox",
                "body": "hello",
                "recipient": [VALID_PUBKEY, key2],
                "messageId": ["id1", "id2"]
            }
        })
        .to_string();
        let result = validate_send_message(raw.as_bytes()).unwrap();
        assert_eq!(result.recipients.len(), 2);
        assert_eq!(
            result.recipients[0],
            (VALID_PUBKEY.to_string(), "id1".to_string())
        );
        assert_eq!(result.recipients[1], (key2.to_string(), "id2".to_string()));
    }

    #[test]
    fn send_with_payment() {
        let raw = json!({
            "message": {
                "messageBox": "inbox",
                "body": "hello",
                "recipient": VALID_PUBKEY,
                "messageId": "id1"
            },
            "payment": {
                "tx": "beef001234",
                "outputs": [{"outputIndex": 0, "protocol": "wallet payment"}]
            }
        })
        .to_string();
        let result = validate_send_message(raw.as_bytes()).unwrap();
        assert!(result.payment.is_some());
        assert!(result.payment.unwrap()["tx"].is_string());
    }

    #[test]
    fn send_messageid_count_mismatch() {
        let raw = json!({
            "message": {
                "messageBox": "inbox", "body": "{}",
                "recipient": [VALID_PUBKEY, VALID_PUBKEY],
                "messageId": "single-id"
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.0["code"], "ERR_MESSAGEID_COUNT_MISMATCH");
        assert_eq!(
            err.0["description"],
            "Provided 1 messageId for 2 recipients. Provide one messageId per recipient (same order)."
        );
    }

    // ---- listMessages validation tests ----

    #[test]
    fn list_missing_message_box() {
        let err = validate_list_messages(b"{}").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGEBOX_REQUIRED");
    }

    #[test]
    fn list_message_box_not_string() {
        let raw = json!({ "messageBox": 123 }).to_string();
        let err = validate_list_messages(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
    }

    #[test]
    fn list_valid() {
        let raw = json!({ "messageBox": "payment_inbox" }).to_string();
        let result = validate_list_messages(raw.as_bytes()).unwrap();
        assert_eq!(result.message_box, "payment_inbox");
    }

    // ---- acknowledgeMessage validation tests ----

    #[test]
    fn ack_missing_message_ids() {
        let err = validate_acknowledge(b"{}").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGE_ID_REQUIRED");
    }

    #[test]
    fn ack_message_ids_not_array() {
        let raw = json!({ "messageIds": "24" }).to_string();
        let err = validate_acknowledge(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGE_ID");
    }

    #[test]
    fn ack_empty_array() {
        let raw = json!({ "messageIds": [] }).to_string();
        let err = validate_acknowledge(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGE_ID_REQUIRED");
    }

    #[test]
    fn ack_valid() {
        let raw = json!({ "messageIds": ["msg-1", "msg-2"] }).to_string();
        let result = validate_acknowledge(raw.as_bytes()).unwrap();
        assert_eq!(result.message_ids, vec!["msg-1", "msg-2"]);
    }

    // ---- ERR_INVALID_JSON parity tests (matches go-messagebox-server) ----
    // A malformed request body must return ERR_INVALID_JSON (400), NOT the
    // field-missing code. {} and valid-JSON-with-missing-fields return the
    // field-specific code; truly invalid JSON bytes return ERR_INVALID_JSON.

    #[test]
    fn send_invalid_json_returns_err_invalid_json() {
        let err = validate_send_message(b"not json at all").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_JSON");
    }

    #[test]
    fn list_invalid_json_returns_err_invalid_json() {
        let err = validate_list_messages(b"{broken").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_JSON");
    }

    #[test]
    fn ack_invalid_json_returns_err_invalid_json() {
        let err = validate_acknowledge(b"]]]").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_JSON");
    }

    // Confirm the "valid JSON, missing field" path still returns the
    // field-specific code, not ERR_INVALID_JSON.
    #[test]
    fn send_empty_object_returns_err_message_required() {
        let err = validate_send_message(b"{}").unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGE_REQUIRED");
    }

    // ---- pubkey validation ----

    #[test]
    fn valid_pubkey() {
        assert!(is_valid_pubkey(VALID_PUBKEY));
        assert!(is_valid_pubkey(
            "038d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1"
        ));
    }

    #[test]
    fn invalid_pubkeys() {
        assert!(!is_valid_pubkey(""));
        assert!(!is_valid_pubkey("not-a-key"));
        assert!(!is_valid_pubkey("04abcd")); // wrong prefix
        assert!(!is_valid_pubkey(&format!("02{}", "g".repeat(64)))); // non-hex
        assert!(!is_valid_pubkey(&format!("02{}", "a".repeat(63)))); // too short
    }

    // ---- Node.js test vectors ----

    #[test]
    fn nodejs_send_message_string_not_object() {
        let raw = json!({
            "message": "My message to send"
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
        assert_eq!(err.0["description"], "Invalid message box.");
    }

    #[test]
    fn nodejs_send_recipient_is_number() {
        let raw = json!({
            "message": {
                "messageBox": "inbox",
                "body": "{}",
                "messageId": "id1",
                "recipient": 123
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_RECIPIENT_KEY");
        assert_eq!(err.0["description"], "Invalid recipient key: 123");
    }

    #[test]
    fn nodejs_send_messagebox_is_number() {
        let raw = json!({
            "message": {
                "messageBox": 123,
                "body": "{}",
                "messageId": "id1",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGEBOX");
        assert_eq!(err.0["description"], "Invalid message box.");
    }

    // Note: the Node.js reference rejects numeric bodies with
    // ERR_INVALID_MESSAGE_BODY; go-messagebox-server accepts them. We follow Go
    // (see send_body_number_accepted above), so the nodejs_send_body_is_number
    // vector is intentionally not reproduced. Acceptance is pinned above.

    #[test]
    fn nodejs_send_missing_messageid() {
        let raw = json!({
            "message": {
                "messageBox": "inbox",
                "body": "{}",
                "recipient": VALID_PUBKEY
            }
        })
        .to_string();
        let err = validate_send_message(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_MESSAGEID_REQUIRED");
        assert_eq!(err.0["description"], "Missing messageId.");
    }

    #[test]
    fn nodejs_list_empty_box_returns_200() {
        let raw = json!({ "messageBox": "pay_inbox" }).to_string();
        let result = validate_list_messages(raw.as_bytes()).unwrap();
        assert_eq!(result.message_box, "pay_inbox");
    }

    #[test]
    fn nodejs_ack_string_instead_of_array() {
        let raw = json!({ "messageIds": "24" }).to_string();
        let err = validate_acknowledge(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_MESSAGE_ID");
        assert_eq!(
            err.0["description"],
            "Message IDs must be formatted as an array of strings!"
        );
    }

    #[test]
    fn nodejs_ack_successful_delete() {
        let raw = json!({ "messageIds": ["123"] }).to_string();
        let result = validate_acknowledge(raw.as_bytes()).unwrap();
        assert_eq!(result.message_ids, vec!["123"]);
    }
}
