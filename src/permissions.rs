// Permission route handlers — /permissions/set, get, list, quote.
// 1:1 parity with Node.js message-box-server permissions endpoints.

use serde_json::{json, Value};
use worker::Url;

use crate::storage::{to_iso8601, PermissionDbRow, Storage};
use crate::validation::is_valid_pubkey;

type RouteResult = (Value, u16);

/// Map fee value to status string (matches Node.js exactly).
pub fn fee_to_status(fee: i32) -> &'static str {
    match fee {
        -1 => "blocked",
        0 => "always_allow",
        _ => "payment_required",
    }
}

/// Format a permission row for JSON response.
fn format_permission(row: &PermissionDbRow) -> Value {
    let fee = row.recipient_fee.map(|v| v as i32).unwrap_or(0);
    json!({
        "sender": row.sender,
        "messageBox": row.message_box.as_deref().unwrap_or(""),
        "recipientFee": fee,
        "status": fee_to_status(fee),
        "createdAt": to_iso8601(row.created_at.as_deref()),
        "updatedAt": to_iso8601(row.updated_at.as_deref()),
    })
}

/// Build the human-readable description for set permission (matches Node.js exactly).
fn set_description(sender: Option<&str>, message_box: &str, fee: i32) -> String {
    match (sender, fee) {
        (None, -1) => format!(
            "Box-wide default for all senders to {} is now blocked.",
            message_box
        ),
        (None, 0) => format!(
            "Box-wide default for all senders to {} is now always allowed.",
            message_box
        ),
        (None, f) => format!(
            "Box-wide default for all senders to {} now requires {} satoshis.",
            message_box, f
        ),
        (Some(s), -1) => format!("Messages from {} to {} are now blocked.", s, message_box),
        (Some(s), 0) => format!(
            "Messages from {} to {} are now always allowed.",
            s, message_box
        ),
        (Some(s), f) => format!(
            "Messages from {} to {} now require {} satoshis.",
            s, message_box, f
        ),
    }
}

// -- POST /permissions/set --

pub async fn handle_set(raw_body: &[u8], identity_key: &str, store: &Storage<'_>) -> RouteResult {
    // Parse body
    let body: Value = match serde_json::from_slice(raw_body) {
        Ok(v) => v,
        Err(_) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_REQUEST",
                    "description": "messageBox (string) and recipientFee (number) are required. sender (string) is optional for box-wide settings."
                }),
                400,
            )
        }
    };

    // Validate messageBox + recipientFee present
    let message_box_val = body.get("messageBox");
    let fee_val = body.get("recipientFee");
    if message_box_val.is_none() || fee_val.is_none() || !fee_val.unwrap().is_number() {
        return (
            json!({
                "status": "error", "code": "ERR_INVALID_REQUEST",
                "description": "messageBox (string) and recipientFee (number) are required. sender (string) is optional for box-wide settings."
            }),
            400,
        );
    }

    // Validate sender pubkey if provided
    let sender = body.get("sender").and_then(|v| v.as_str());
    if let Some(s) = sender {
        if !is_valid_pubkey(s) {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_PUBLIC_KEY",
                    "description": "Invalid sender public key format."
                }),
                400,
            );
        }
    }

    // Validate recipientFee is integer
    let fee_f64 = fee_val.unwrap().as_f64().unwrap_or(f64::NAN);
    if fee_f64.fract() != 0.0 || fee_f64.is_nan() {
        return (
            json!({
                "status": "error", "code": "ERR_INVALID_FEE_VALUE",
                "description": "recipientFee must be an integer (-1, 0, or positive number)."
            }),
            400,
        );
    }
    let fee = fee_f64 as i32;

    // Validate messageBox is non-empty string
    let message_box = match message_box_val.unwrap().as_str() {
        Some(s) if !s.trim().is_empty() => s,
        _ => {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_MESSAGE_BOX",
                    "description": "messageBox must be a non-empty string."
                }),
                400,
            )
        }
    };

    // Upsert
    match store
        .set_permission(identity_key, sender, message_box, fee)
        .await
    {
        Ok(true) => {}
        Ok(false) | Err(_) => {
            return (
                json!({
                    "status": "error", "code": "ERR_DATABASE_ERROR",
                    "description": "Failed to update message permission."
                }),
                500,
            )
        }
    }

    let desc = set_description(sender, message_box, fee);
    (json!({ "status": "success", "description": desc }), 200)
}

// -- GET /permissions/get --

pub async fn handle_get(url: &Url, identity_key: &str, store: &Storage<'_>) -> RouteResult {
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    let message_box = params
        .iter()
        .find(|(k, _)| k == "messageBox")
        .map(|(_, v)| v.as_str());
    let sender = params
        .iter()
        .find(|(k, _)| k == "sender")
        .map(|(_, v)| v.as_str());

    // messageBox required
    let message_box = match message_box {
        Some(mb) if !mb.is_empty() => mb,
        _ => {
            return (
                json!({
                    "status": "error", "code": "ERR_MISSING_PARAMETERS",
                    "description": "messageBox parameter is required."
                }),
                400,
            )
        }
    };

    // Validate sender pubkey if provided
    if let Some(s) = sender {
        if !s.is_empty() && !is_valid_pubkey(s) {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_PUBLIC_KEY",
                    "description": "Invalid sender public key format."
                }),
                400,
            );
        }
    }

    let sender_for_query = sender.filter(|s| !s.is_empty());

    let row = match store
        .get_permission(identity_key, sender_for_query, message_box)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL",
                    "description": format!("Internal error: {}", e)
                }),
                500,
            )
        }
    };

    match row {
        Some(ref perm) => {
            let desc = match sender_for_query {
                Some(s) => format!(
                    "Permission setting found for sender {} to {}.",
                    s, message_box
                ),
                None => format!("Box-wide permission setting found for {}.", message_box),
            };
            (
                json!({
                    "status": "success",
                    "description": desc,
                    "permission": format_permission(perm)
                }),
                200,
            )
        }
        None => {
            let desc = match sender_for_query {
                Some(s) => format!(
                    "No permission setting found for sender {} to {}.",
                    s, message_box
                ),
                None => format!("No box-wide permission setting found for {}.", message_box),
            };
            (
                json!({ "status": "success", "description": desc, "permission": serde_json::Value::Null }),
                200,
            )
        }
    }
}

// -- GET /permissions/list --

pub async fn handle_list(url: &Url, identity_key: &str, store: &Storage<'_>) -> RouteResult {
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    let message_box = params
        .iter()
        .find(|(k, _)| k == "messageBox")
        .map(|(_, v)| v.as_str());
    let limit_str = params
        .iter()
        .find(|(k, _)| k == "limit")
        .map(|(_, v)| v.as_str());
    let offset_str = params
        .iter()
        .find(|(k, _)| k == "offset")
        .map(|(_, v)| v.as_str());
    let order_str = params
        .iter()
        .find(|(k, _)| k == "createdAtOrder")
        .map(|(_, v)| v.as_str());

    // Parse and validate pagination
    let limit: u32 = limit_str.and_then(|s| s.parse().ok()).unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return (
            json!({
                "status": "error", "code": "ERR_INVALID_LIMIT",
                "description": "Limit must be a number between 1 and 1000"
            }),
            400,
        );
    }

    let offset: u32 = offset_str.and_then(|s| s.parse().ok()).unwrap_or(0);
    // Validate offset_str is valid if provided
    if let Some(s) = offset_str {
        if s.parse::<u32>().is_err() {
            return (
                json!({
                    "status": "error", "code": "ERR_INVALID_OFFSET",
                    "description": "Offset must be a non-negative number"
                }),
                400,
            );
        }
    }

    let sort_order = match order_str {
        Some("asc") => "asc",
        _ => "desc",
    };

    let mb_filter = message_box.filter(|s| !s.is_empty());

    let (rows, total) = match store
        .list_permissions(identity_key, mb_filter, limit, offset, sort_order)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_LIST_PERMISSIONS_FAILED",
                    "description": format!("Failed to list permissions: {}", e)
                }),
                500,
            )
        }
    };

    let formatted: Vec<Value> = rows
        .iter()
        .map(|row| {
            let fee = row.recipient_fee.map(|v| v as i32).unwrap_or(0);
            json!({
                "sender": row.sender,
                "messageBox": row.message_box.as_deref().unwrap_or(""),
                "recipientFee": fee,
                "createdAt": to_iso8601(row.created_at.as_deref()),
                "updatedAt": to_iso8601(row.updated_at.as_deref()),
            })
        })
        .collect();

    (
        json!({
            "status": "success",
            "permissions": formatted,
            "totalCount": total
        }),
        200,
    )
}

// -- GET /permissions/quote --

pub async fn handle_quote(
    url: &Url,
    identity_key: &str, // the sender (authenticated user checking prices)
    store: &Storage<'_>,
) -> RouteResult {
    let params: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    let message_box = params
        .iter()
        .find(|(k, _)| k == "messageBox")
        .map(|(_, v)| v.as_str());
    let recipients: Vec<&str> = params
        .iter()
        .filter(|(k, _)| k == "recipient")
        .map(|(_, v)| v.as_str())
        .collect();

    // Validate required params
    let message_box = match message_box {
        Some(mb) if !mb.is_empty() => mb,
        _ => {
            return (
                json!({
                    "status": "error", "code": "ERR_MISSING_PARAMETERS",
                    "description": "recipient and messageBox parameters are required."
                }),
                400,
            )
        }
    };

    if recipients.is_empty() {
        return (
            json!({
                "status": "error", "code": "ERR_MISSING_PARAMETERS",
                "description": "recipient and messageBox parameters are required."
            }),
            400,
        );
    }

    // Validate all pubkeys
    let mut invalid_indices = Vec::new();
    for (i, r) in recipients.iter().enumerate() {
        if !is_valid_pubkey(r) {
            invalid_indices.push(i);
        }
    }
    if !invalid_indices.is_empty() {
        let indices_str: Vec<String> = invalid_indices.iter().map(|i| i.to_string()).collect();
        return (
            json!({
                "status": "error", "code": "ERR_INVALID_PUBLIC_KEY",
                "description": format!("Invalid recipient public key at index(es): {}.", indices_str.join(", "))
            }),
            400,
        );
    }

    // Get server delivery fee
    let delivery_fee = match store.get_server_delivery_fee(message_box).await {
        Ok(f) => f,
        Err(e) => {
            return (
                json!({
                    "status": "error", "code": "ERR_INTERNAL",
                    "description": format!("Internal error: {}", e)
                }),
                500,
            )
        }
    };

    // Single recipient — legacy response shape
    if recipients.len() == 1 {
        let recipient_fee = match store
            .get_recipient_fee(recipients[0], identity_key, message_box)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                return (
                    json!({
                        "status": "error", "code": "ERR_INTERNAL",
                        "description": format!("Internal error: {}", e)
                    }),
                    500,
                )
            }
        };

        return (
            json!({
                "status": "success",
                "description": "Message delivery quote generated.",
                "quote": {
                    "deliveryFee": delivery_fee,
                    "recipientFee": recipient_fee
                }
            }),
            200,
        );
    }

    // Multi-recipient — detailed response
    let mut quotes_by_recipient = Vec::new();
    let mut blocked_recipients = Vec::new();
    let mut total_recipient_fees: i32 = 0;

    for r in &recipients {
        let recipient_fee = match store.get_recipient_fee(r, identity_key, message_box).await {
            Ok(f) => f,
            Err(e) => {
                return (
                    json!({
                        "status": "error", "code": "ERR_INTERNAL",
                        "description": format!("Internal error: {}", e)
                    }),
                    500,
                )
            }
        };

        let status = fee_to_status(recipient_fee);

        if recipient_fee == -1 {
            blocked_recipients.push(*r);
        } else if recipient_fee > 0 {
            total_recipient_fees += recipient_fee;
        }

        quotes_by_recipient.push(json!({
            "recipient": r,
            "messageBox": message_box,
            "deliveryFee": delivery_fee,
            "recipientFee": recipient_fee,
            "status": status,
        }));
    }

    let total_delivery_fees = delivery_fee * recipients.len() as i32;
    let total_for_payable = total_delivery_fees + total_recipient_fees;

    (
        json!({
            "status": "success",
            "description": format!("Message delivery quotes generated for {} recipients.", recipients.len()),
            "quotesByRecipient": quotes_by_recipient,
            "totals": {
                "deliveryFees": total_delivery_fees,
                "recipientFees": total_recipient_fees,
                "totalForPayableRecipients": total_for_payable
            },
            "blockedRecipients": blocked_recipients
        }),
        200,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- fee_to_status --

    #[test]
    fn test_fee_to_status() {
        assert_eq!(fee_to_status(-1), "blocked");
        assert_eq!(fee_to_status(0), "always_allow");
        assert_eq!(fee_to_status(1), "payment_required");
        assert_eq!(fee_to_status(10), "payment_required");
        assert_eq!(fee_to_status(100), "payment_required");
    }

    // -- set_description --

    #[test]
    fn test_set_description_blocked_boxwide() {
        let d = set_description(None, "inbox", -1);
        assert_eq!(
            d,
            "Box-wide default for all senders to inbox is now blocked."
        );
    }

    #[test]
    fn test_set_description_allow_boxwide() {
        let d = set_description(None, "inbox", 0);
        assert_eq!(
            d,
            "Box-wide default for all senders to inbox is now always allowed."
        );
    }

    #[test]
    fn test_set_description_fee_boxwide() {
        let d = set_description(None, "notifications", 10);
        assert_eq!(
            d,
            "Box-wide default for all senders to notifications now requires 10 satoshis."
        );
    }

    #[test]
    fn test_set_description_blocked_sender() {
        let d = set_description(Some("02abc123"), "inbox", -1);
        assert_eq!(d, "Messages from 02abc123 to inbox are now blocked.");
    }

    #[test]
    fn test_set_description_allow_sender() {
        let d = set_description(Some("02abc123"), "inbox", 0);
        assert_eq!(d, "Messages from 02abc123 to inbox are now always allowed.");
    }

    #[test]
    fn test_set_description_fee_sender() {
        let d = set_description(Some("02abc123"), "inbox", 5);
        assert_eq!(d, "Messages from 02abc123 to inbox now require 5 satoshis.");
    }

    // -- format_permission --

    #[test]
    fn test_format_permission_blocked() {
        let row = PermissionDbRow {
            sender: Some("02abc".into()),
            message_box: Some("inbox".into()),
            recipient_fee: Some(-1.0),
            created_at: Some("2026-01-01 00:00:00".into()),
            updated_at: Some("2026-01-02 00:00:00".into()),
        };
        let p = format_permission(&row);
        assert_eq!(p["status"], "blocked");
        assert_eq!(p["recipientFee"], -1);
        assert_eq!(p["sender"], "02abc");
        // Timestamps normalized to ISO 8601 for Node parity
        assert_eq!(p["createdAt"], "2026-01-01T00:00:00.000Z");
        assert_eq!(p["updatedAt"], "2026-01-02T00:00:00.000Z");
    }

    #[test]
    fn test_format_permission_null_sender() {
        let row = PermissionDbRow {
            sender: None,
            message_box: Some("inbox".into()),
            recipient_fee: Some(0.0),
            created_at: Some("2026-01-01 12:34:56".into()),
            updated_at: Some("2026-01-01 12:34:56".into()),
        };
        let p = format_permission(&row);
        assert_eq!(p["status"], "always_allow");
        assert!(p["sender"].is_null());
        assert_eq!(p["createdAt"], "2026-01-01T12:34:56.000Z");
        assert_eq!(p["updatedAt"], "2026-01-01T12:34:56.000Z");
    }
}
