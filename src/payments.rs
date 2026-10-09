// Payment processing — server delivery fee internalization + per-recipient output routing.
// 1:1 parity with Node.js message-box-server sendMessage.ts payment logic.

use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_middleware_rs::{brc29_locking_script, verify_payment_output, PaymentOutputError};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use worker::Env;

type RouteResult = (Value, u16);

/// Process payment for sendMessage. Returns per-recipient output mappings.
///
/// fee_map: Vec of (recipient, messageId, fee) for non-blocked recipients.
/// delivery_fee: the box's server delivery fee per recipient; output[0] must
/// carry it once for every entry of `fee_map` (P0-5b) when it is > 0.
/// A payment transaction above `MAX_PAYMENT_BODY_BYTES` is refused 413
/// before anything reads it.
pub async fn process_payment(
    payment: &Value,
    fee_map: &[(String, String, i32)],
    delivery_fee: i32,
    sender_key: &str,
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
    check_payment_size(tx)?;
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

        let server_output = &outputs[0];

        // P0-3: read the delivery output and compare it with the fee before
        // wallet-infra is asked to record it; wallet-infra checks neither the
        // amount nor the script.
        let server_wallet = server_private_key(env)
            .map(|key| ProtoWallet::new(Some(key)))
            .map_err(|e| {
                err(
                    500,
                    "ERR_INTERNALIZE_FAILED",
                    &format!("Failed to internalize payment: {}", e),
                )
            })?;
        check_delivery_output(
            tx,
            server_output,
            delivery_fee_due(delivery_fee, fee_map.len())?,
            sender_key,
            &server_wallet,
        )?;

        // Internalize server delivery output via wallet-infra
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

/// The delivery fee the server output must carry for a send to `recipients`
/// recipients: the box's fee once per recipient, as the reference charges it
/// (message-box-server at ts-stack@fb1b2da, `sendMessage.ts:710-722`, applied
/// at `:1707-1713` and checked against output 0 at `:1061-1067`; its client
/// pays the same sum, `MessageBoxClient.ts:4283-4299`). A fee that cannot be
/// formed (no recipient, a negative fee, an overflow) is the reference's
/// thrown `TypeError`, a 500.
fn delivery_fee_due(delivery_fee: i32, recipients: usize) -> Result<u64, RouteResult> {
    u64::try_from(delivery_fee)
        .ok()
        .filter(|_| recipients > 0)
        .zip(u64::try_from(recipients).ok())
        .and_then(|(fee, n)| fee.checked_mul(n))
        .ok_or_else(|| err(500, "ERR_INTERNAL", "Invalid aggregate delivery fee."))
}

/// The largest payment transaction the payment path reads, in bytes: 4 MiB,
/// the reference message box's request body limit at its default profile
/// (ts-stack@fb1b2da `infra/message-box-server/src/app.ts:171,195-208`, the
/// `standard` value; `src/security/edgePolicy.ts:135-156`). Every payment the
/// reference accepts arrives in a body of at most that size, so its
/// transaction is no larger: this bound refuses nothing the reference serves.
/// Above it the payment is refused 413 before it is decoded or parsed.
pub const MAX_PAYMENT_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The 413 for a payment transaction of `len` bytes above the bound, in the
/// reference's code (`edgePolicy.ts:613-633`, `ERR_BODY_TOO_LARGE`).
pub(crate) fn payment_size_refusal(len: u64) -> Option<RouteResult> {
    (len > MAX_PAYMENT_BODY_BYTES as u64).then(|| {
        err(
            413,
            "ERR_BODY_TOO_LARGE",
            &format!(
                "The payment transaction exceeds {} bytes.",
                MAX_PAYMENT_BODY_BYTES
            ),
        )
    })
}

/// The bound, read from the length of the encoded transaction before any
/// decode: a byte array's length, half a hex string's, three quarters of a
/// base64 string's less its padding. A shape that is none of these is left
/// to `payment_tx_bytes`, which refuses it.
fn check_payment_size(tx: &Value) -> Result<(), RouteResult> {
    let len = match tx {
        Value::Array(items) => items.len(),
        Value::String(h) => h.len().div_ceil(2),
        Value::Object(o) => match o.get("beef").and_then(|b| b.as_str()) {
            Some(b) => (b.len() / 4 * 3 + b.len() % 4 * 3 / 4)
                .saturating_sub(b.bytes().rev().take(2).filter(|c| *c == b'=').count()),
            None => 0,
        },
        _ => 0,
    };
    match payment_size_refusal(len as u64) {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// The server delivery output, read before it is internalized (P0-3).
///
/// The remittance must be a `wallet payment` from the authenticated sender;
/// the output it names must be locked to the server's BRC-29 key for that
/// remittance and carry at least `delivery_fee`. Returns the satoshis paid.
/// Matches the reference's checks before internalizing
/// (message-box-server sendMessage.ts:693-708, 764-786, 1054-1067), plus the
/// script, which the reference leaves to its wallet's signer.
pub fn check_delivery_output(
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
) -> Result<u64, RouteResult> {
    let invalid = |description: &str| err(400, "ERR_INVALID_PAYMENT", description);
    if server_output.get("protocol").and_then(|v| v.as_str()) != Some("wallet payment") {
        return Err(invalid(
            "The server delivery output must be a wallet payment.",
        ));
    }
    let output_index = server_output
        .get("outputIndex")
        .and_then(|v| v.as_u64())
        .and_then(|i| u32::try_from(i).ok())
        .ok_or_else(|| invalid("The server delivery output index is invalid."))?;
    let remittance = |key: &str| {
        server_output
            .get("paymentRemittance")
            .and_then(|r| r.get(key))
            .and_then(|v| v.as_str())
    };
    let (Some(prefix), Some(suffix), Some(sender)) = (
        remittance("derivationPrefix"),
        remittance("derivationSuffix"),
        remittance("senderIdentityKey"),
    ) else {
        return Err(invalid("The delivery payment remittance is incomplete."));
    };
    if sender != sender_key {
        return Err(invalid(
            "The delivery payment remittance is invalid for the authenticated sender.",
        ));
    }
    let tx_bytes =
        payment_tx_bytes(tx).ok_or_else(|| invalid("Payment must contain a valid Atomic BEEF."))?;
    let expected_script =
        brc29_locking_script(server_wallet, prefix, suffix, sender_key).map_err(|e| {
            invalid(&format!(
                "The delivery payment remittance is invalid: {}",
                e
            ))
        })?;
    match verify_payment_output(&tx_bytes, output_index, &expected_script, delivery_fee) {
        Ok(paid) => Ok(paid),
        Err(PaymentOutputError::Underpaid { .. }) => Err(err(
            400,
            "ERR_INSUFFICIENT_PAYMENT",
            "The server delivery output does not pay the required amount.",
        )),
        Err(e) => Err(invalid(&format!(
            "The server delivery output is invalid: {}",
            e
        ))),
    }
}

/// The payment transaction's bytes, in the shapes this server receives:
/// a JSON byte array (BRC-100), a hex string (both of which wallet-infra
/// accepts), or `{ "beef": <base64> }` (an R2 upload inlined by
/// `beef_upload`). Anything else, or a byte above 255, is `None`.
fn payment_tx_bytes(tx: &Value) -> Option<Vec<u8>> {
    match tx {
        Value::Array(items) => items
            .iter()
            .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        Value::String(h) => hex::decode(h).ok(),
        Value::Object(o) => o
            .get("beef")?
            .as_str()
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()),
        _ => None,
    }
}

/// The SERVER_PRIVATE_KEY secret, parsed.
fn server_private_key(env: &Env) -> Result<PrivateKey, String> {
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| format!("SERVER_PRIVATE_KEY: {}", e))?
        .to_string();
    PrivateKey::from_hex(&server_key).map_err(|e| format!("Invalid key: {}", e))
}

/// Internalize the server delivery fee via WorkerStorageClient → wallet-infra.
async fn internalize_server_fee(
    tx: &Value,
    server_output: &Value,
    payment: &Value,
    env: &Env,
) -> Result<bool, String> {
    let private_key = server_private_key(env)?;
    let storage_url = env
        .var("WALLET_STORAGE_URL")
        .map_err(|e| format!("WALLET_STORAGE_URL: {}", e))?
        .to_string();

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

    // ---- P0-3: the delivery output is compared with the fee ----
    //
    // Crafted payments only: one input from a crafted parent, never signed,
    // never broadcast, no wallet-infra.

    use bsv_rs::primitives::PublicKey;
    use bsv_rs::script::LockingScript;
    use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
    use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, Protocol, SecurityLevel};

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PREFIX: &str = "cHJlZml4";
    const SUFFIX: &str = "c3VmZml4";
    const FEE: u64 = 100;

    fn wallet(hex: &str) -> ProtoWallet {
        ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
    }

    fn sender_identity() -> String {
        wallet(SENDER_KEY).identity_key().to_hex()
    }

    fn p2pkh(hash: &[u8; 20]) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// The payer's side of BRC-29: the server's key for the counterparty
    /// server, derived by the sender, independent of the code under test.
    fn payer_script() -> Vec<u8> {
        let derived = wallet(SENDER_KEY)
            .get_public_key(GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, "3241645161d8")),
                key_id: Some(format!("{PREFIX} {SUFFIX}")),
                counterparty: Some(Counterparty::Other(wallet(SERVER_KEY).identity_key())),
                for_self: Some(false),
            })
            .unwrap();
        p2pkh(&PublicKey::from_hex(&derived.public_key).unwrap().hash160())
    }

    fn atomic_beef(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut parent = Transaction::new();
        parent
            .add_output(TransactionOutput::new(
                10_000,
                LockingScript::from_binary(&p2pkh(&[7u8; 20])).unwrap(),
            ))
            .unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::with_source_transaction(parent, 0))
            .unwrap();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        tx.to_atomic_beef(true).unwrap()
    }

    /// `tx` the way BRC-100 clients send it: a JSON array of bytes.
    fn tx_json(outputs: &[(u64, Vec<u8>)]) -> Value {
        json!(atomic_beef(outputs))
    }

    fn remittance(output_index: u32, sender: &str) -> Value {
        json!({
            "outputIndex": output_index,
            "protocol": "wallet payment",
            "paymentRemittance": {
                "derivationPrefix": PREFIX,
                "derivationSuffix": SUFFIX,
                "senderIdentityKey": sender
            }
        })
    }

    fn check(tx: &Value, output: &Value) -> Result<u64, RouteResult> {
        check_delivery_output(tx, output, FEE, &sender_identity(), &wallet(SERVER_KEY))
    }

    fn refusal_code(r: Result<u64, RouteResult>) -> (u16, String) {
        let (body, status) = r.expect_err("expected a refusal");
        (status, body["code"].as_str().unwrap().to_string())
    }

    #[test]
    fn p0_3_delivery_fee_exact_is_accepted() {
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(check(&tx, &remittance(0, &sender_identity())), Ok(FEE));
    }

    #[test]
    fn p0_3_delivery_fee_one_under_is_refused() {
        let tx = tx_json(&[(FEE - 1, payer_script())]);
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity()))),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_3_delivery_fee_one_over_returns_the_real_amount() {
        let tx = tx_json(&[(FEE + 1, payer_script())]);
        assert_eq!(check(&tx, &remittance(0, &sender_identity())), Ok(FEE + 1));
    }

    #[test]
    fn p0_3_delivery_output_at_another_script_is_refused() {
        let tx = tx_json(&[(FEE, p2pkh(&[9u8; 20]))]);
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity()))),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_3_remittance_sender_other_than_the_authenticated_one_is_refused() {
        let tx = tx_json(&[(FEE, payer_script())]);
        let other = wallet(SERVER_KEY).identity_key().to_hex();
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &other))),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_3_a_remittance_that_is_not_a_wallet_payment_is_refused() {
        let tx = tx_json(&[(FEE, payer_script())]);
        let mut output = remittance(0, &sender_identity());
        output["protocol"] = json!("basket insertion");
        assert_eq!(
            refusal_code(check(&tx, &output)),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_3_the_named_output_index_is_the_one_read() {
        // Output 0 pays someone else; the remittance names output 1, which
        // pays the server: that is the output internalized, so it is read.
        let tx = tx_json(&[(FEE, p2pkh(&[9u8; 20])), (FEE, payer_script())]);
        assert_eq!(check(&tx, &remittance(1, &sender_identity())), Ok(FEE));
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity()))),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_3_tx_as_hex_or_inlined_beef_is_read_like_the_byte_array() {
        let bytes = atomic_beef(&[(FEE - 1, payer_script())]);
        for tx in [
            json!(hex::encode(&bytes)),
            json!({ "beef": base64::engine::general_purpose::STANDARD.encode(&bytes) }),
        ] {
            assert_eq!(
                refusal_code(check(&tx, &remittance(0, &sender_identity()))),
                (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
            );
        }
    }

    #[test]
    fn p0_3_an_unreadable_tx_is_refused() {
        for tx in [
            json!("not hex"),
            json!([1, 2, 300]),
            json!({ "other": 1 }),
            json!(7),
        ] {
            assert_eq!(
                refusal_code(check(&tx, &remittance(0, &sender_identity()))),
                (400, "ERR_INVALID_PAYMENT".to_string())
            );
        }
    }

    // ---- P0-5b: the fee per recipient (M1) and the body bound (H1a) ----

    #[test]
    fn p0_5b_two_recipients_paying_one_fee_is_refused() {
        // The reference charges the delivery fee once per recipient
        // (ts-stack@fb1b2da infra/message-box-server/src/routes/sendMessage.ts:710-722,1707-1713).
        let tx = tx_json(&[(FEE, payer_script())]);
        let due = delivery_fee_due(FEE as i32, 2).expect("a fee is due");
        assert_eq!(
            refusal_code(check_delivery_output(
                &tx,
                &remittance(0, &sender_identity()),
                due,
                &sender_identity(),
                &wallet(SERVER_KEY),
            )),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
    }

    #[test]
    fn p0_5b_two_recipients_paying_two_fees_is_accepted() {
        let tx = tx_json(&[(2 * FEE, payer_script())]);
        let due = delivery_fee_due(FEE as i32, 2).expect("a fee is due");
        assert_eq!(
            check_delivery_output(
                &tx,
                &remittance(0, &sender_identity()),
                due,
                &sender_identity(),
                &wallet(SERVER_KEY),
            ),
            Ok(2 * FEE)
        );
    }

    #[test]
    fn p0_5b_the_fee_due_is_the_fee_times_the_recipients() {
        assert_eq!(delivery_fee_due(100, 1), Ok(100));
        assert_eq!(delivery_fee_due(100, 3), Ok(300));
        assert_eq!(delivery_fee_due(i32::MAX, 2), Ok(2 * i32::MAX as u64));
    }

    #[test]
    fn p0_5b_a_fee_due_that_cannot_be_formed_is_refused() {
        // As the reference's aggregateDeliveryFee throws (sendMessage.ts:710-722).
        for (fee, recipients) in [(100, 0), (-1, 1), (i32::MAX, usize::MAX)] {
            assert_eq!(
                refusal_code(delivery_fee_due(fee, recipients)),
                (500, "ERR_INTERNAL".to_string())
            );
        }
    }

    #[test]
    fn p0_5b_a_payment_one_byte_over_the_bound_is_refused_413_in_every_shape() {
        let over = MAX_PAYMENT_BODY_BYTES + 1;
        // Not hex and not base64: the bound is read before any decode.
        for tx in [
            json!(vec![0u8; over]),
            json!("z".repeat(2 * over)),
            json!({ "beef": "!".repeat(4 * over.div_ceil(3)) }),
        ] {
            assert_eq!(
                refusal_code(check_payment_size(&tx).map(|_| 0)),
                (413, "ERR_BODY_TOO_LARGE".to_string())
            );
        }
    }

    #[test]
    fn p0_5b_a_payment_at_the_bound_is_read() {
        let at = MAX_PAYMENT_BODY_BYTES;
        for tx in [
            json!(vec![0u8; at]),
            json!("0".repeat(2 * at)),
            json!({ "beef": base64::engine::general_purpose::STANDARD.encode(vec![0u8; at]) }),
        ] {
            assert_eq!(check_payment_size(&tx), Ok(()));
        }
    }

    #[test]
    fn p0_5b_an_r2_object_over_the_bound_is_refused_before_it_is_read() {
        assert_eq!(payment_size_refusal(MAX_PAYMENT_BODY_BYTES as u64), None);
        let (body, status) =
            payment_size_refusal(MAX_PAYMENT_BODY_BYTES as u64 + 1).expect("a refusal");
        assert_eq!(
            (status, body["code"].as_str()),
            (413, Some("ERR_BODY_TOO_LARGE"))
        );
    }

    #[test]
    fn route_no_fee_recipients() {
        let outputs: Vec<Value> = vec![];
        let recipients: Vec<&str> = vec![];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.is_empty());
    }
}
