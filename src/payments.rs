// Payment processing — server delivery fee internalization + per-recipient output routing.
// 1:1 parity with Node.js message-box-server sendMessage.ts payment logic.

use std::collections::{HashMap, HashSet};

use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use worker::Env;

type RouteResult = (Value, u16);

/// Process payment for sendMessage. Returns per-recipient output mappings.
///
/// fee_map: Vec of (recipient, messageId, fee) for non-blocked recipients.
/// delivery_fee: server delivery fee (output[0] if > 0).
pub async fn process_payment(
    payment: &Value,
    fee_map: &[(String, String, i32)],
    delivery_fee: i32,
    _sender_key: &str,
    env: &Env,
) -> Result<HashMap<String, Value>, RouteResult> {
    // Validate payment structure
    let tx = payment.get("tx").ok_or_else(|| {
        err(
            400,
            "ERR_MISSING_PAYMENT_TX",
            "Payment transaction data is required for payable delivery.",
        )
    })?;
    let outputs = payment
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            err(
                400,
                "ERR_MISSING_PAYMENT_TX",
                "Payment transaction data is required for payable delivery.",
            )
        })?;

    // Server delivery fee — output[0]
    if delivery_fee > 0 {
        if outputs.is_empty() {
            return Err(err(
                400,
                "ERR_MISSING_DELIVERY_OUTPUT",
                "Delivery fee required but no outputs were provided.",
            ));
        }

        // Internalize server delivery output via wallet-infra
        let server_output = &outputs[0];
        match internalize_server_fee(tx, server_output, payment, env).await {
            Ok(accepted) => {
                if !accepted {
                    return Err(err(
                        400,
                        "ERR_INSUFFICIENT_PAYMENT",
                        "Payment was not accepted by the server.",
                    ));
                }
            }
            Err(e) => {
                return Err(err(
                    500,
                    "ERR_INTERNALIZE_FAILED",
                    &format!("Failed to internalize payment: {}", e),
                ));
            }
        }
    }

    // Per-recipient output routing
    let fee_recipients: Vec<&str> = fee_map
        .iter()
        .filter(|(_, _, f)| *f > 0)
        .map(|(r, _, _)| r.as_str())
        .collect();

    if fee_recipients.is_empty() {
        return Ok(HashMap::new());
    }

    // Slice off server delivery output if present
    let recipient_outputs = if delivery_fee > 0 {
        &outputs[1..]
    } else {
        &outputs[..]
    };

    route_outputs_to_recipients(recipient_outputs, &fee_recipients)
}

/// Route payment outputs to fee-requiring recipients.
/// 1:1 parity with Node.js: explicit mapping via customInstructions.recipientIdentityKey,
/// then positional fallback for unmapped recipients.
fn route_outputs_to_recipients(
    outputs: &[Value],
    fee_recipients: &[&str],
) -> Result<HashMap<String, Value>, RouteResult> {
    let mut by_key: HashMap<String, Vec<Value>> = HashMap::new();
    let mut used_indices: HashSet<u64> = HashSet::new();

    // Step 1: Try explicit mapping via customInstructions.recipientIdentityKey
    for out in outputs {
        let raw = out
            .get("insertionRemittance")
            .and_then(|r| r.get("customInstructions"))
            .or_else(|| {
                out.get("paymentRemittance")
                    .and_then(|r| r.get("customInstructions"))
            })
            .or_else(|| out.get("customInstructions"));

        let key = match raw {
            Some(Value::String(s)) => {
                // Try parsing as JSON
                serde_json::from_str::<Value>(s).ok().and_then(|v| {
                    v.get("recipientIdentityKey")
                        .and_then(|k| k.as_str())
                        .map(String::from)
                })
            }
            Some(v) if v.is_object() => v
                .get("recipientIdentityKey")
                .and_then(|k| k.as_str())
                .map(String::from),
            _ => None,
        };

        if let Some(k) = key {
            if !k.trim().is_empty() {
                by_key.entry(k).or_default().push(out.clone());
                if let Some(idx) = out.get("outputIndex").and_then(|v| v.as_u64()) {
                    used_indices.insert(idx);
                }
            }
        }
    }

    let mut result: HashMap<String, Value> = HashMap::new();

    if by_key.is_empty() {
        // No explicit tags — pure positional mapping
        if outputs.len() < fee_recipients.len() {
            return Err(err(
                400,
                "ERR_INSUFFICIENT_OUTPUTS",
                &format!(
                    "Expected at least {} recipient output(s) but received {}",
                    fee_recipients.len(),
                    outputs.len()
                ),
            ));
        }

        for (i, &r) in fee_recipients.iter().enumerate() {
            result.insert(r.to_string(), json!([outputs[i]]));
        }
    } else {
        // Mixed: explicit + positional fallback
        // Assign tagged outputs
        for &r in fee_recipients {
            if let Some(tagged) = by_key.get(r) {
                result.insert(r.to_string(), json!(tagged));
            }
        }

        // Find unmapped recipients
        let unmapped: Vec<&str> = fee_recipients
            .iter()
            .filter(|r| !result.contains_key(**r))
            .copied()
            .collect();

        if !unmapped.is_empty() {
            // Filter remaining outputs
            let remaining: Vec<&Value> = outputs
                .iter()
                .filter(|o| match o.get("outputIndex").and_then(|v| v.as_u64()) {
                    Some(idx) => !used_indices.contains(&idx),
                    None => true,
                })
                .collect();

            if remaining.len() < unmapped.len() {
                return Err(err(
                    400,
                    "ERR_INSUFFICIENT_OUTPUTS",
                    &format!(
                        "Expected at least {} additional recipient output(s) but only {} remain",
                        unmapped.len(),
                        remaining.len()
                    ),
                ));
            }

            for (i, &r) in unmapped.iter().enumerate() {
                result.insert(r.to_string(), json!([remaining[i]]));
            }
        }

        // Final check: all fee recipients must have outputs
        for &r in fee_recipients {
            if !result.contains_key(r) {
                return Err(err(
                    400,
                    "ERR_MISSING_RECIPIENT_OUTPUTS",
                    &format!(
                        "Recipient fee required but no outputs were provided for {}",
                        r
                    ),
                ));
            }
        }
    }

    Ok(result)
}

/// Internalize the server delivery fee via WorkerStorageClient → wallet-infra.
async fn internalize_server_fee(
    tx: &Value,
    server_output: &Value,
    payment: &Value,
    env: &Env,
) -> Result<bool, String> {
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| format!("SERVER_PRIVATE_KEY: {}", e))?
        .to_string();
    let storage_url = env
        .var("WALLET_STORAGE_URL")
        .map_err(|e| format!("WALLET_STORAGE_URL: {}", e))?
        .to_string();

    let private_key =
        PrivateKey::from_hex(&server_key).map_err(|e| format!("Invalid key: {}", e))?;

    // Derive identity key before moving private_key into wallet
    let identity_key = private_key.public_key().to_hex();

    let wallet = ProtoWallet::new(Some(private_key));
    let mut client = WorkerStorageClient::new(wallet, &storage_url);
    client
        .make_available()
        .await
        .map_err(|e| format!("Storage handshake failed: {}", e))?;

    // Build internalization args
    let args = json!({
        "tx": tx,
        "outputs": [server_output],
        "description": payment.get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("MessageBox delivery payment"),
        "labels": payment.get("labels").unwrap_or(&json!([])),
        "seekPermission": false
    });
    let auth = json!({
        "identityKey": identity_key
    });

    let result = client
        .internalize_action(auth, args)
        .await
        .map_err(|e| format!("Internalize failed: {}", e))?;

    Ok(result
        .get("accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

fn err(status: u16, code: &str, description: &str) -> RouteResult {
    (
        json!({ "status": "error", "code": code, "description": description }),
        status,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY1: &str = "028d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1";
    const KEY2: &str = "038d37b941208cd6b8a4c28288eda5f2f16c2b3ab0fcb6d13c18b47fe37b971fc1";

    #[test]
    fn route_positional_single() {
        let outputs = vec![json!({"outputIndex": 0, "protocol": "wallet payment"})];
        let recipients = vec![KEY1];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.contains_key(KEY1));
    }

    #[test]
    fn route_positional_multi() {
        let outputs = vec![json!({"outputIndex": 0}), json!({"outputIndex": 1})];
        let recipients = vec![KEY1, KEY2];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.contains_key(KEY1));
        assert!(result.contains_key(KEY2));
    }

    #[test]
    fn route_insufficient_outputs() {
        let outputs = vec![json!({"outputIndex": 0})];
        let recipients = vec![KEY1, KEY2];
        let err = route_outputs_to_recipients(&outputs, &recipients).unwrap_err();
        assert_eq!(err.0["code"], "ERR_INSUFFICIENT_OUTPUTS");
    }

    #[test]
    fn route_explicit_custom_instructions() {
        let outputs = vec![
            json!({
                "outputIndex": 0,
                "customInstructions": { "recipientIdentityKey": KEY1 }
            }),
            json!({
                "outputIndex": 1,
                "customInstructions": { "recipientIdentityKey": KEY2 }
            }),
        ];
        let recipients = vec![KEY1, KEY2];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.contains_key(KEY1));
        assert!(result.contains_key(KEY2));
    }

    #[test]
    fn route_explicit_json_string_instructions() {
        // customInstructions as JSON string (common in real payloads)
        let instr = json!({"recipientIdentityKey": KEY1}).to_string();
        let outputs = vec![json!({
            "outputIndex": 0,
            "paymentRemittance": { "customInstructions": instr }
        })];
        let recipients = vec![KEY1];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.contains_key(KEY1));
    }

    #[test]
    fn route_mixed_explicit_and_positional() {
        let outputs = vec![
            json!({
                "outputIndex": 0,
                "customInstructions": { "recipientIdentityKey": KEY1 }
            }),
            json!({"outputIndex": 1}), // positional fallback for KEY2
        ];
        let recipients = vec![KEY1, KEY2];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.contains_key(KEY1));
        assert!(result.contains_key(KEY2));
    }

    #[test]
    fn route_mixed_insufficient_remaining() {
        // KEY1 tagged explicitly, but no remaining for KEY2
        let outputs = vec![json!({
            "outputIndex": 0,
            "customInstructions": { "recipientIdentityKey": KEY1 }
        })];
        let recipients = vec![KEY1, KEY2];
        let err = route_outputs_to_recipients(&outputs, &recipients).unwrap_err();
        assert_eq!(err.0["code"], "ERR_INSUFFICIENT_OUTPUTS");
    }

    #[test]
    fn route_no_fee_recipients() {
        let outputs: Vec<Value> = vec![];
        let recipients: Vec<&str> = vec![];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.is_empty());
    }
}
