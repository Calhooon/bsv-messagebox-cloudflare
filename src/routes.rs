// Route helpers — public endpoints and utilities.
// Authenticated route dispatch lives in lib.rs (after process_auth).

use serde_json::json;
use worker::*;

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
