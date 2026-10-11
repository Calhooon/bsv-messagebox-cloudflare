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

/// The largest `/sendMessage` body the relay reads (0.4.4, bsv-low #591
/// NOTE-4): 12 MiB, in every shape of `payment.tx`. The isolate is 128 MiB;
/// the body is held whole by the BRC-31 layer (it signs over it), and the
/// relay holds at most two more of its size while it reads it (the text it
/// parses, and the payment's hex beside it), so three bodies stay under 40
/// MiB and the rest of the isolate is the Worker's and the reading's. An
/// estimate on the host, not measured in wasm32. Through 0.4.3 the bound was
/// the platform's 100 MB, and a byte array of about 15 MB exhausted the
/// isolate in parsing alone. A larger payment goes by upload
/// (`/beef/upload-url`), which has no bound.
pub const SEND_BODY_BYTES: usize = 12 * 1024 * 1024;

/// The `/sendMessage` body as a `Value`, read so that no `payment.tx` is
/// ever a `Value` a byte (0.4.4, bsv-low #591 NOTE-4): the body is held to
/// `SEND_BODY_BYTES` before a byte of it is parsed (413
/// `ERR_BODY_TOO_LARGE`), and a `payment.tx` sent as a byte array is read
/// from the text as bytes and handed on as hex, with `payment.txShape:
/// "array"` beside it so its rows hand it back as it came. An array that is
/// not bytes (a number above 255, anything not a number) is no payment and
/// is read as `false`, which the payment door refuses as such. A
/// `txShape` the sender wrote is the relay's field and is dropped.
pub fn read_send_body(raw: &[u8]) -> ValResult<Value> {
    if raw.len() > SEND_BODY_BYTES {
        return Err(err(
            413,
            "ERR_BODY_TOO_LARGE",
            &format!(
                "The send is {} bytes and the relay reads at most {} in one request. Upload the payment's BEEF (/beef/upload-url) and send its key (payment.beefR2Key): an upload has no bound.",
                raw.len(),
                SEND_BODY_BYTES
            ),
        ));
    }
    let invalid = || err(400, "ERR_INVALID_JSON", "Invalid JSON body");
    let spans = tx_spans(raw);
    let mut sent_as_array = false;
    let mut body: Value = if spans.iter().any(|(from, _)| raw[*from] == b'[') {
        let mut text = Vec::with_capacity(raw.len());
        let mut at = 0;
        for (from, to) in &spans {
            text.extend_from_slice(&raw[at..*from]);
            sent_as_array = raw[*from] == b'[';
            if sent_as_array {
                match array_bytes(&raw[*from..*to]) {
                    Some(bytes) => {
                        text.push(b'"');
                        text.extend_from_slice(hex::encode(bytes).as_bytes());
                        text.push(b'"');
                    }
                    None => text.extend_from_slice(b"false"),
                }
            } else {
                text.extend_from_slice(&raw[*from..*to]);
            }
            at = *to;
        }
        text.extend_from_slice(&raw[at..]);
        serde_json::from_slice(&text).map_err(|_| invalid())?
    } else {
        serde_json::from_slice(raw).map_err(|_| invalid())?
    };
    if let Some(payment) = body.get_mut("payment").and_then(Value::as_object_mut) {
        payment.remove("txShape");
        if sent_as_array && payment.get("tx").is_some_and(Value::is_string) {
            payment.insert("txShape".to_string(), json!("array"));
        }
    }
    Ok(body)
}

/// The byte ranges of every value of a `tx` member of a `payment` member of
/// the top-level object, in the order they come; nothing when the text is
/// not an object as far as the scan reads (the parse then says why).
fn tx_spans(raw: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let _ = members(raw, skip_ws(raw, 0), &mut |raw, key, from, to| {
        if key == "payment" && raw.get(from) == Some(&b'{') {
            let _ = members(raw, from, &mut |_, key, from, to| {
                if key == "tx" {
                    spans.push((from, to));
                }
            });
        }
        let _ = to;
    });
    spans
}

/// What `members` hands each member: the text, the key (decoded), and the
/// value's range.
type Member<'a> = dyn FnMut(&[u8], String, usize, usize) + 'a;

/// Each member of the object at `at`: its key (decoded) and its value's
/// range. `None` when the bytes are not an object.
fn members(raw: &[u8], at: usize, each: &mut Member<'_>) -> Option<usize> {
    if raw.get(at) != Some(&b'{') {
        return None;
    }
    let mut at = skip_ws(raw, at + 1);
    if raw.get(at) == Some(&b'}') {
        return Some(at + 1);
    }
    loop {
        let key_end = skip_string(raw, at)?;
        let key: String = serde_json::from_slice(&raw[at..key_end]).ok()?;
        at = skip_ws(raw, key_end);
        if raw.get(at) != Some(&b':') {
            return None;
        }
        let from = skip_ws(raw, at + 1);
        let to = skip_value(raw, from)?;
        each(raw, key, from, to);
        at = skip_ws(raw, to);
        match raw.get(at) {
            Some(b',') => at = skip_ws(raw, at + 1),
            Some(b'}') => return Some(at + 1),
            _ => return None,
        }
    }
}

fn skip_ws(raw: &[u8], mut at: usize) -> usize {
    while matches!(raw.get(at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        at += 1;
    }
    at
}

/// The end of the string at `at` (one past its closing quote).
fn skip_string(raw: &[u8], at: usize) -> Option<usize> {
    if raw.get(at) != Some(&b'"') {
        return None;
    }
    let mut at = at + 1;
    loop {
        match raw.get(at)? {
            b'\\' => at += 2,
            b'"' => return Some(at + 1),
            _ => at += 1,
        }
    }
}

/// The end of the value at `at`, nesting counted without recursion.
fn skip_value(raw: &[u8], at: usize) -> Option<usize> {
    match raw.get(at)? {
        b'"' => skip_string(raw, at),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut at = at;
            loop {
                match raw.get(at)? {
                    b'"' => {
                        at = skip_string(raw, at)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(at + 1);
                        }
                    }
                    _ => {}
                }
                at += 1;
            }
        }
        _ => {
            // A scalar: to the next delimiter.
            let from = at;
            let mut at = at;
            while !matches!(
                raw.get(at),
                None | Some(b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            ) {
                at += 1;
            }
            (at > from).then_some(at)
        }
    }
}

/// The bytes of a JSON array of integers 0 to 255, read from its text; `None`
/// when it is anything else.
fn array_bytes(text: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() / 3);
    let mut at = skip_ws(text, 1);
    if text.get(at) == Some(&b']') {
        return (skip_ws(text, at + 1) == text.len()).then_some(bytes);
    }
    loop {
        let from = at;
        let mut n: u32 = 0;
        while let Some(d @ b'0'..=b'9') = text.get(at) {
            n = n * 10 + u32::from(d - b'0');
            at += 1;
            if at - from > 3 {
                return None;
            }
        }
        if at == from || (text[from] == b'0' && at - from > 1) || n > 255 {
            return None;
        }
        bytes.push(n as u8);
        at = skip_ws(text, at);
        match text.get(at)? {
            b',' => at = skip_ws(text, at + 1),
            b']' => return (skip_ws(text, at + 1) == text.len()).then_some(bytes),
            _ => return None,
        }
    }
}

/// Validate sendMessage request body. Exact validation order from Node.js.
pub fn validate_send_message(raw: &[u8]) -> ValResult<ValidatedSendMessage> {
    validate_send_value(read_send_body(raw)?)
}

/// `validate_send_message` on a body already read (`read_send_body`).
pub fn validate_send_value(body: Value) -> ValResult<ValidatedSendMessage> {
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

    // ---- NOTE-4 (0.4.4): the body read so that no tx is a Value a byte ----

    const KEY66: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn a_send_paying(payment: &str) -> String {
        format!(
            r#"{{"message":{{"messageBox":"inbox","recipient":"{KEY66}","messageId":"m","body":"hi"}},"payment":{payment}}}"#
        )
    }

    #[test]
    fn an_array_tx_is_read_as_bytes_and_handed_on_as_hex_with_its_shape() {
        let body =
            read_send_body(a_send_paying(r#"{ "tx" : [ 0 , 1,255 ] ,"outputs":[]}"#).as_bytes())
                .unwrap();
        assert_eq!(body["payment"]["tx"], "0001ff");
        assert_eq!(body["payment"]["txShape"], "array");
        // An escaped key is the same key.
        let body = read_send_body(
            a_send_paying(r#"{"\u0074x":[7]}"#)
                .replace("\"payment\"", "\"pay\\u006dent\"")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(body["payment"]["tx"], "07");
        // The empty array is no bytes, as before.
        let body = read_send_body(a_send_paying(r#"{"tx":[]}"#).as_bytes()).unwrap();
        assert_eq!(body["payment"]["tx"], "");
    }

    #[test]
    fn an_array_that_is_not_bytes_is_no_payment_and_a_sent_shape_is_dropped() {
        for tx in [
            "[256]", "[1.0]", "[-1]", "[01]", r#"["a"]"#, "[1,]", "[[1]]",
        ] {
            let body = read_send_body(a_send_paying(&format!(r#"{{"tx":{tx}}}"#)).as_bytes())
                .unwrap_or_else(|e| panic!("{tx}: {e:?}"));
            assert_eq!(body["payment"]["tx"], false, "{tx}");
            assert!(body["payment"].get("txShape").is_none(), "{tx}");
        }
        // The sender's txShape is the relay's field.
        let body =
            read_send_body(a_send_paying(r#"{"tx":"00","txShape":"array"}"#).as_bytes()).unwrap();
        assert!(body["payment"].get("txShape").is_none());
        // A tx anywhere but the top-level payment is untouched.
        let text = format!(
            r#"{{"message":{{"messageBox":"inbox","recipient":"{KEY66}","messageId":"m","body":{{"payment":{{"tx":[1]}}}}}}}}"#
        );
        let body = read_send_body(text.as_bytes()).unwrap();
        assert_eq!(body["message"]["body"]["payment"]["tx"], json!([1]));
        // What is not JSON is still not JSON.
        let (body, status) = read_send_body(b"{\"payment\":{\"tx\":[1,2").unwrap_err();
        assert_eq!((status, &body["code"]), (400, &json!("ERR_INVALID_JSON")));
    }

    #[test]
    fn a_body_past_the_bound_is_refused_before_it_is_read() {
        let mut text = a_send_paying(r#"{"tx":"00"}"#);
        text.push_str(&" ".repeat(SEND_BODY_BYTES));
        let (body, status) = read_send_body(text.as_bytes()).unwrap_err();
        assert_eq!((status, &body["code"]), (413, &json!("ERR_BODY_TOO_LARGE")));
        assert!(body["description"].as_str().unwrap().contains("12582912"));
    }
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
