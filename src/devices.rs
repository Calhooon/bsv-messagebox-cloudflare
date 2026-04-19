// Device CRUD endpoints — /registerDevice, /devices.
// 1:1 parity with Node.js message-box-server device registration endpoints.

use serde_json::{json, Value};

use crate::storage::{to_iso8601, Storage};

type RouteResult = (Value, u16);

/// Validate and parse a registerDevice request body.
/// Returns (fcm_token, device_id, platform) or an error tuple.
fn validate_register_device(
    raw: &[u8],
) -> Result<(String, Option<String>, Option<String>), RouteResult> {
    let body: Value = serde_json::from_slice(raw).map_err(|_| {
        (
            json!({
                "status": "error",
                "code": "ERR_INVALID_FCM_TOKEN",
                "description": "fcmToken must be a non-empty string."
            }),
            400u16,
        )
    })?;

    // fcmToken is required and must be a non-empty string
    let fcm_token = match body.get("fcmToken").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return Err((
                json!({
                    "status": "error",
                    "code": "ERR_INVALID_FCM_TOKEN",
                    "description": "fcmToken must be a non-empty string."
                }),
                400,
            ))
        }
    };

    // deviceId is optional string
    let device_id = body
        .get("deviceId")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    // platform is optional but must be one of "ios", "android", "web" if provided
    let platform = match body.get("platform") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => {
            let p = v.as_str().ok_or_else(|| {
                (
                    json!({
                        "status": "error",
                        "code": "ERR_INVALID_PLATFORM",
                        "description": "platform must be one of: ios, android, web"
                    }),
                    400u16,
                )
            })?;
            if p.is_empty() {
                None
            } else {
                match p {
                    "ios" | "android" | "web" => Some(p.to_string()),
                    _ => {
                        return Err((
                            json!({
                                "status": "error",
                                "code": "ERR_INVALID_PLATFORM",
                                "description": "platform must be one of: ios, android, web"
                            }),
                            400,
                        ))
                    }
                }
            }
        }
    };

    Ok((fcm_token, device_id, platform))
}

/// Truncate an FCM token for display: show only last 10 characters with "..." prefix.
fn truncate_fcm_token(token: &str) -> String {
    if token.len() <= 10 {
        token.to_string()
    } else {
        format!("...{}", &token[token.len() - 10..])
    }
}

/// POST /registerDevice — register a device for push notifications.
pub async fn handle_register_device(
    raw_body: &[u8],
    identity_key: &str,
    store: &Storage<'_>,
) -> RouteResult {
    let (fcm_token, device_id, platform) = match validate_register_device(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };

    match store
        .upsert_device(
            identity_key,
            &fcm_token,
            device_id.as_deref(),
            platform.as_deref(),
        )
        .await
    {
        Ok(row_id) => (
            json!({
                "status": "success",
                "message": "Device registered successfully for push notifications",
                "deviceId": row_id
            }),
            200,
        ),
        Err(_) => (
            json!({
                "status": "error",
                "code": "ERR_DATABASE_ERROR",
                "description": "Failed to register device."
            }),
            500,
        ),
    }
}

/// GET /devices — list all devices for the authenticated user.
pub async fn handle_list_devices(identity_key: &str, store: &Storage<'_>) -> RouteResult {
    let rows = match store.list_devices(identity_key).await {
        Ok(r) => r,
        Err(_) => {
            return (
                json!({
                    "status": "error",
                    "code": "ERR_DATABASE_ERROR",
                    "description": "Failed to list devices."
                }),
                500,
            )
        }
    };

    let devices: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id.map(|v| v as i64).unwrap_or(0),
                "deviceId": row.device_id,
                "platform": row.platform,
                "fcmToken": truncate_fcm_token(row.fcm_token.as_deref().unwrap_or("")),
                "active": row.active.map(|v| v as i64 == 1).unwrap_or(false),
                "createdAt": to_iso8601(row.created_at.as_deref()),
                "updatedAt": to_iso8601(row.updated_at.as_deref()),
                "lastUsed": match row.last_used.as_deref() {
                    Some(s) => Value::String(to_iso8601(Some(s))),
                    None => Value::Null,
                },
            })
        })
        .collect();

    (json!({ "status": "success", "devices": devices }), 200)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- validate_register_device --

    #[test]
    fn register_missing_fcm_token() {
        let raw = json!({}).to_string();
        let err = validate_register_device(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_FCM_TOKEN");
    }

    #[test]
    fn register_empty_fcm_token() {
        let raw = json!({ "fcmToken": "" }).to_string();
        let err = validate_register_device(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_FCM_TOKEN");
    }

    #[test]
    fn register_fcm_token_not_string() {
        let raw = json!({ "fcmToken": 123 }).to_string();
        let err = validate_register_device(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_FCM_TOKEN");
    }

    #[test]
    fn register_invalid_platform() {
        let raw = json!({
            "fcmToken": "valid-token-12345",
            "platform": "windows"
        })
        .to_string();
        let err = validate_register_device(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_PLATFORM");
    }

    #[test]
    fn register_platform_not_string() {
        let raw = json!({
            "fcmToken": "valid-token-12345",
            "platform": 42
        })
        .to_string();
        let err = validate_register_device(raw.as_bytes()).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_PLATFORM");
    }

    #[test]
    fn register_valid_minimal() {
        let raw = json!({ "fcmToken": "abc123xyz" }).to_string();
        let (token, device_id, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert_eq!(token, "abc123xyz");
        assert!(device_id.is_none());
        assert!(platform.is_none());
    }

    #[test]
    fn register_valid_full() {
        let raw = json!({
            "fcmToken": "abc123xyz-long-token",
            "deviceId": "my-device-001",
            "platform": "ios"
        })
        .to_string();
        let (token, device_id, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert_eq!(token, "abc123xyz-long-token");
        assert_eq!(device_id.as_deref(), Some("my-device-001"));
        assert_eq!(platform.as_deref(), Some("ios"));
    }

    #[test]
    fn register_valid_android() {
        let raw = json!({
            "fcmToken": "android-token",
            "platform": "android"
        })
        .to_string();
        let (_, _, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert_eq!(platform.as_deref(), Some("android"));
    }

    #[test]
    fn register_valid_web() {
        let raw = json!({
            "fcmToken": "web-token",
            "platform": "web"
        })
        .to_string();
        let (_, _, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert_eq!(platform.as_deref(), Some("web"));
    }

    #[test]
    fn register_null_platform_ok() {
        let raw = json!({
            "fcmToken": "token123",
            "platform": null
        })
        .to_string();
        let (token, _, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert_eq!(token, "token123");
        assert!(platform.is_none());
    }

    #[test]
    fn register_empty_platform_ok() {
        let raw = json!({
            "fcmToken": "token123",
            "platform": ""
        })
        .to_string();
        let (_, _, platform) = validate_register_device(raw.as_bytes()).unwrap();
        assert!(platform.is_none());
    }

    #[test]
    fn register_invalid_json() {
        let raw = b"not json";
        let err = validate_register_device(raw).unwrap_err();
        assert_eq!(err.1, 400);
        assert_eq!(err.0["code"], "ERR_INVALID_FCM_TOKEN");
    }

    // -- truncate_fcm_token --

    #[test]
    fn truncate_long_token() {
        let token = "abcdefghijklmnopqrstuvwxyz1234567890";
        let truncated = truncate_fcm_token(token);
        // Last 10 chars of token are "z1234567890"... wait, let's compute:
        // token = "abcdefghijklmnopqrstuvwxyz1234567890" (36 chars)
        // last 10 = "1234567890" (indices 26..36)
        assert_eq!(truncated, "...1234567890");
        assert!(truncated.starts_with("..."));
        assert_eq!(truncated.len(), 13); // "..." + 10 chars
    }

    #[test]
    fn truncate_short_token() {
        assert_eq!(truncate_fcm_token("short"), "short");
        assert_eq!(truncate_fcm_token("1234567890"), "1234567890");
    }

    #[test]
    fn truncate_exactly_10_chars() {
        assert_eq!(truncate_fcm_token("0123456789"), "0123456789");
    }

    #[test]
    fn truncate_11_chars() {
        assert_eq!(truncate_fcm_token("a0123456789"), "...0123456789");
    }

    #[test]
    fn truncate_empty_token() {
        assert_eq!(truncate_fcm_token(""), "");
    }

    // -- Device list response formatting --

    #[test]
    fn device_list_formats_fcm_token_truncation() {
        use crate::storage::DeviceDbRow;

        let row = DeviceDbRow {
            id: Some(1.0),
            device_id: Some("device-001".into()),
            platform: Some("ios".into()),
            fcm_token: Some("abcdefghijklmnopqrstuvwxyz1234567890".into()),
            active: Some(1.0),
            created_at: Some("2026-01-01 00:00:00".into()),
            updated_at: Some("2026-01-02 00:00:00".into()),
            last_used: Some("2026-01-02 12:00:00".into()),
        };

        let formatted = json!({
            "id": row.id.map(|v| v as i64).unwrap_or(0),
            "deviceId": row.device_id,
            "platform": row.platform,
            "fcmToken": truncate_fcm_token(row.fcm_token.as_deref().unwrap_or("")),
            "active": row.active.map(|v| v as i64 == 1).unwrap_or(false),
            "createdAt": to_iso8601(row.created_at.as_deref()),
            "updatedAt": to_iso8601(row.updated_at.as_deref()),
            "lastUsed": match row.last_used.as_deref() {
                Some(s) => Value::String(to_iso8601(Some(s))),
                None => Value::Null,
            },
        });

        assert_eq!(formatted["id"], 1);
        assert_eq!(formatted["deviceId"], "device-001");
        assert_eq!(formatted["platform"], "ios");
        assert!(formatted["fcmToken"].as_str().unwrap().starts_with("..."));
        assert_eq!(formatted["fcmToken"].as_str().unwrap().len(), 13);
        assert_eq!(formatted["active"], true);
        // ISO 8601 conversion from SQLite datetime format (Node parity)
        assert_eq!(formatted["createdAt"], "2026-01-01T00:00:00.000Z");
        assert_eq!(formatted["updatedAt"], "2026-01-02T00:00:00.000Z");
        assert_eq!(formatted["lastUsed"], "2026-01-02T12:00:00.000Z");
    }

    #[test]
    fn device_list_inactive_device() {
        use crate::storage::DeviceDbRow;

        let row = DeviceDbRow {
            id: Some(2.0),
            device_id: None,
            platform: None,
            fcm_token: Some("shorttoken".into()),
            active: Some(0.0),
            created_at: Some("2026-01-01 00:00:00".into()),
            updated_at: Some("2026-01-01 00:00:00".into()),
            last_used: None,
        };

        let formatted = json!({
            "id": row.id.map(|v| v as i64).unwrap_or(0),
            "deviceId": row.device_id,
            "platform": row.platform,
            "fcmToken": truncate_fcm_token(row.fcm_token.as_deref().unwrap_or("")),
            "active": row.active.map(|v| v as i64 == 1).unwrap_or(false),
            "createdAt": to_iso8601(row.created_at.as_deref()),
            "updatedAt": to_iso8601(row.updated_at.as_deref()),
            "lastUsed": match row.last_used.as_deref() {
                Some(s) => Value::String(to_iso8601(Some(s))),
                None => Value::Null,
            },
        });

        assert_eq!(formatted["id"], 2);
        assert!(formatted["deviceId"].is_null());
        assert!(formatted["platform"].is_null());
        assert_eq!(formatted["fcmToken"], "shorttoken");
        assert_eq!(formatted["active"], false);
        assert_eq!(formatted["createdAt"], "2026-01-01T00:00:00.000Z");
        // lastUsed must preserve null when None, not become empty string
        assert!(formatted["lastUsed"].is_null());
    }
}
