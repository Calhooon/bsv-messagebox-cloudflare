// Route helpers — public endpoints and utilities.
// Authenticated route dispatch lives in lib.rs (after process_auth).
//
// `send_message` is the shared write-path core used by BOTH the HTTP
// `POST /sendMessage` handler in `lib.rs` AND the WebSocket
// `sendMessage` event handler in `message_hub.rs` (M9 #44). Each
// caller is a thin translator from a `SendOutcome` into its native
// response shape — there is exactly one source of truth for the
// validation → permission → payment → D1-insert pipeline.

use serde_json::json;
use worker::*;

pub mod send_message;

/// JSON success response helper.
#[allow(dead_code)]
pub fn ok_json(value: &serde_json::Value) -> Result<Response> {
    Response::from_json(value)
}

/// JSON error response helper.
#[allow(dead_code)]
pub fn error_json(status: u16, code: &str, description: &str) -> Result<Response> {
    let body = json!({
        "status": "error",
        "code": code,
        "description": description,
    });
    Ok(Response::from_json(&body)?.with_status(status))
}
