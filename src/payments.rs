// Payment processing — server delivery fee internalization + per-recipient output routing.
// 1:1 parity with Node.js message-box-server sendMessage.ts payment logic.

use std::collections::{HashMap, HashSet};

use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_middleware_rs::{
    brc29_locking_script, header_service_url, HeaderLookupError, HeaderService, PaymentVerdict,
    UnverifiableReason,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::ScriptResource;
use bsv_rs::transaction::beef_stream::SpendRefusal;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use worker::Env;

use crate::beef_door::{
    inline_spool_key, judge_output_inline, structure_inline, verify_inline, AtRest, BeefStore,
    Carrier, DoorError, DoorVerdict, Pending, Slice, Slices, Terms, Within, ROOT_LOOKUPS_PER_PASS,
    SCRIPT_INPUTS_PER_PASS, SCRIPT_WEIGHT_PER_PASS, STACK_MEMORY_BYTES, VERIFY_SLICE_MILLIS,
};

use crate::handoff::{
    drain_fees, hand_off, reask_announces, reclaim, reclaim_released, Announcer, FeeWallet,
    HandedOff, Hint, Paid, PaymentStore, Seams, Subject, DRAIN_BATCH, RECLAIM_BATCH,
};

type RouteResult = (Value, u16);

/// A payment the route has settled: each paid recipient's outputs, and what
/// the hand-off made of the payment.
pub struct Settled {
    pub outputs: HashMap<String, Value>,
    pub handed: HandedOff,
}

/// The door's verdict on a verified payment: what the delivery output pays
/// and the subject's txid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    pub satoshis: u64,
    pub txid: String,
    /// The stamp of the object the door read, when it read one at rest
    /// (0.4.4, bsv-low #591 L1): the hand-off holds what it records to it.
    pub stamp: Option<crate::beef_door::Stamp>,
}

/// Process payment for sendMessage. Returns per-recipient output mappings
/// and the payment as the hand-off left it (`handoff::hand_off`).
///
/// fee_map: Vec of (recipient, messageId, fee) for non-blocked recipients.
/// delivery_fee: the box's server delivery fee per recipient; output[0] must
/// carry it once for every entry of `fee_map` (P0-5b) when it is > 0.
/// r2_key: the object `payment.beefR2Key` names, when it names one the sender
/// owns (`beef_upload::decide_r2_fetch`); the payment's BEEF is then read
/// from R2 and `payment.tx` is not looked at.
///
/// A payment's bytes are held to `PAYMENT_BUDGET_BYTES` (0.8.9) before any of
/// them is read: an inline `payment.tx` by its encoding's length
/// (`check_payment_size`), an object at rest by its stored length
/// (`judge_payment_at_rest`, `check_unjudged_at_rest`); over it the answer is
/// 413 `ERR_PAYMENT_SIZE`. Within it no payment is refused for its counts: the
/// BEEF is read as a stream, one element in hand (`beef_door`), and a refusal
/// names the offset and the kind of the bytes that are wrong. The delivery output is
/// verified against the header service the `HEADER_SERVICE` binding or
/// `HEADER_SERVICE_URL` names (0.3.29, 0.3.30); a deployment that names none
/// refuses every payment that owes a delivery fee. An object at rest that one
/// request cannot finish reading is answered 503 `ERR_PAYMENT_PENDING` with
/// its cursor saved; the same request again continues.
pub async fn process_payment(
    payment: &Value,
    r2_key: Option<&str>,
    fee_map: &[(String, String, i32)],
    delivery_fee: i32,
    sender_key: &str,
    env: &Env,
) -> Result<Settled, RouteResult> {
    // Validate payment structure
    let missing_tx = || {
        err(
            400,
            "ERR_MISSING_PAYMENT_TX",
            "Payment transaction data is required for payable delivery.",
        )
    };
    if r2_key.is_none() && payment.get("tx").is_none() {
        return Err(missing_tx());
    }
    let outputs = payment
        .get("outputs")
        .and_then(|v| v.as_array())
        .ok_or_else(missing_tx)?;

    // A payment the door did not judge leaves one line for the operator.
    let counted = |refused: RouteResult| {
        if let Some(line) = not_judged_line(&refused.0, sender_key) {
            worker::console_log!("{line}");
        }
        refused
    };
    // The inline payment's bytes, held to the budget by their encoding's
    // length before any of them is decoded: every inline path below (spooled,
    // read in the request, or kept unjudged) reads only what passed here.
    if r2_key.is_none() {
        if let Some(tx) = payment.get("tx") {
            check_payment_size(tx).map_err(counted)?;
        }
    }

    // The reader every object of the payment names: the relay, the recipient
    // of the delivery fee (`handoff::READER_METADATA`).
    let reader = server_private_key(env)
        .map(|key| key.public_key().to_hex())
        .map_err(|e| err(500, "ERR_INTERNAL", &e))?;
    // Where the relay put an inline payment's bytes at rest before its
    // scripts ran, when it did.
    let mut spooled: Option<String> = None;

    // Server delivery fee — output[0]
    let judged = if delivery_fee > 0 {
        let server_output = outputs.first().ok_or_else(|| {
            err(
                400,
                "ERR_MISSING_DELIVERY_OUTPUT",
                "Delivery fee required but no outputs were provided.",
            )
        })?;

        // P0-3: read the delivery output and compare it with the fee before
        // wallet-infra is asked to record it; wallet-infra checks neither the
        // amount nor the script. 0.3.29: and every merkle root of the payment
        // with the header service, before it is recorded.
        let server_wallet = server_private_key(env)
            .map(|key| ProtoWallet::new(Some(key)))
            .map_err(|e| {
                err(
                    500,
                    "ERR_INTERNALIZE_FAILED",
                    &format!("Failed to internalize payment: {}", e),
                )
            })?;
        let headers = WorkerHeaderService::from_env(env);
        let headers = headers.as_ref().map(|h| h as &dyn HeaderService);
        let due = delivery_fee_due(delivery_fee, fee_map.len())?;
        let store = crate::beef_upload::R2Store::new(env);
        let clock = || worker::Date::now().as_millis();
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis: VERIFY_SLICE_MILLIS,
            },
            lookups: ROOT_LOOKUPS_PER_PASS,
            inputs: SCRIPT_INPUTS_PER_PASS,
            weight: SCRIPT_WEIGHT_PER_PASS,
            work_units: crate::beef_door::work_units_per_input(),
        };
        let judged = match r2_key {
            Some(key) => judge_payment_at_rest(
                &store,
                key,
                server_output,
                due,
                sender_key,
                &server_wallet,
                headers,
                &slices,
            )
            .await
            .map_err(counted)?,
            // An inline payment is spooled after its output and before its
            // scripts (0.4.4, bsv-low #591 H1), so the slice and the 503
            // resume cover it as they cover an upload. Where no bucket is
            // bound it is read in the request, the output still first.
            None if store.bound() => {
                let tx = payment.get("tx").ok_or_else(missing_tx)?;
                let db = env
                    .d1("DB")
                    .map_err(|e| err(503, "ERR_D1_UNAVAILABLE", &format!("D1 binding: {}", e)))?;
                let minted = crate::storage::D1Rows { db: &db };
                let (judged, key) = judge_delivery_inline_at_rest(
                    &store,
                    tx,
                    server_output,
                    due,
                    sender_key,
                    &server_wallet,
                    headers,
                    &slices,
                    &reader,
                    Some((&minted, worker::Date::now().as_millis() / 1000)),
                )
                .await;
                match judged {
                    Ok(judged) => {
                        spooled = key;
                        judged
                    }
                    Err(refused) => {
                        // A refusal ends the spool; a pending reading keeps
                        // it for the same request again.
                        if let (Some(key), false) = (&key, is_pending(&refused)) {
                            forget_spool(env, &store, key).await;
                        }
                        return Err(counted(refused));
                    }
                }
            }
            None => {
                let tx = payment.get("tx").ok_or_else(missing_tx)?;
                judge_delivery_output(tx, server_output, due, sender_key, &server_wallet, headers)
                    .await
                    .map_err(counted)?
            }
        };
        Some((server_output, judged))
    } else {
        None
    };

    // A body no delivery fee judges is kept in its row, never spooled (0.4.4,
    // bsv-low #591 M3): its structure is read and the row's bound holds it.
    if let (None, None, Some(_)) = (&judged, r2_key, payment.get("tx")) {
        check_unjudged(payment).await.map_err(counted)?;
    }

    // Per-recipient output routing, before the hand-off: a payment whose
    // outputs do not cover its recipients is refused with nothing put at
    // rest and no fee recorded for a message that is not delivered.
    let fee_recipients: Vec<&str> = fee_map
        .iter()
        .filter(|(_, _, f)| *f > 0)
        .map(|(r, _, _)| r.as_str())
        .collect();
    let routed = if fee_recipients.is_empty() {
        HashMap::new()
    } else {
        // Slice off server delivery output if present
        let recipient_outputs = if delivery_fee > 0 {
            &outputs[1..]
        } else {
            &outputs[..]
        };
        route_outputs_to_recipients(recipient_outputs, &fee_recipients)?
    };

    // An upload no delivery fee judges is named in its row and never read:
    // its stored length is held to the budget all the same, and the hand-off
    // names the object it measured and no other.
    let measured = match (&judged, r2_key) {
        (None, Some(key)) => check_unjudged_at_rest(&crate::beef_upload::R2Store::new(env), key)
            .await
            .map_err(counted)?,
        _ => None,
    };

    // The hand-off (`handoff`). The verdict is in.
    let blobs = crate::beef_upload::R2Store::new(env);
    let wallet = WalletInfra { env };
    let db = env
        .d1("DB")
        .map_err(|e| err(503, "ERR_D1_UNAVAILABLE", &format!("D1 binding: {}", e)))?;
    let ledger = crate::storage::D1Ledger { db: &db };
    let rows = crate::storage::D1Rows { db: &db };
    let spool_key = crate::beef_upload::build_upload_key(
        sender_key,
        &uuid::Uuid::new_v4().simple().to_string(),
    );
    let arc = ArcAnnouncer::from_env(env);
    let handed = hand_off(
        &Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
            announcer: arc.as_ref().map(|arc| arc as &dyn Announcer),
        },
        &Paid {
            payment,
            r2_key,
            spooled: spooled.as_deref(),
            spool_key: &spool_key,
            server_output: judged.as_ref().map(|(output, _)| *output),
            stamp: judged
                .as_ref()
                .and_then(|(_, judged)| judged.stamp.as_ref())
                .or(measured.as_ref()),
            txid: judged.as_ref().map(|(_, judged)| judged.txid.as_str()),
            rows: !fee_recipients.is_empty(),
            reader: &reader,
            now: worker::Date::now().as_millis() / 1000,
        },
    )
    .await?;

    Ok(Settled {
        outputs: routed,
        handed,
    })
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

/// The server delivery output, read before it is internalized (P0-3), and
/// the payment's merkle roots checked with the header service (0.3.29).
///
/// The remittance must be a `wallet payment` from the authenticated sender;
/// the output it names must be locked to the server's BRC-29 key for that
/// remittance and carry at least `delivery_fee`; the payment must be a BEEF
/// whose every merkle root is the header service's root at that height.
/// Returns the satoshis paid. Matches the reference's checks before
/// internalizing (message-box-server sendMessage.ts:693-708, 764-786,
/// 1054-1067), plus the script, which the reference leaves to its wallet's
/// signer, and the roots, which it leaves to its wallet's chain tracker.
///
/// The BEEF is read as a stream of its elements (0.4.0): of any size and any
/// counts, and a refusal of its bytes carries their offset and their kind.
pub async fn check_delivery_output(
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
) -> Result<u64, RouteResult> {
    judge_delivery_output(
        tx,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
    )
    .await
    .map(|judged| judged.satoshis)
}

/// `check_delivery_output`, with the subject's txid beside the satoshis: what
/// the hand-off keeps of the verdict.
pub async fn judge_delivery_output(
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
) -> Result<Judged, RouteResult> {
    door_judged(
        delivery_reading(
            tx,
            server_output,
            delivery_fee,
            sender_key,
            server_wallet,
            header_service,
        )
        .await?,
    )
}

/// The verdict on the server delivery output, in the six words of
/// bsv-middleware-rs 0.4.1 (`None` for the header service is
/// `NoHeaderService`, a lookup that cannot answer is `Unverifiable`, fail
/// closed). A remittance that is not this sender's wallet payment, or a
/// transaction that is not bytes, is refused here before any verdict, as
/// before.
pub async fn delivery_verdict(
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
) -> Result<PaymentVerdict, RouteResult> {
    delivery_reading(
        tx,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
    )
    .await
    .map(|verdict| verdict.word)
}

fn invalid(description: &str) -> RouteResult {
    err(400, "ERR_INVALID_PAYMENT", description)
}

/// The output the remittance names and the sender's two derivation strings,
/// or the refusal of a remittance that is not this sender's wallet payment.
fn delivery_remittance<'a>(
    server_output: &'a Value,
    sender_key: &str,
) -> Result<(u32, &'a str, &'a str), RouteResult> {
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
    Ok((output_index, prefix, suffix))
}

/// The script the delivery output must carry: the server's BRC-29 key for
/// this remittance.
fn delivery_script(
    server_wallet: &ProtoWallet,
    prefix: &str,
    suffix: &str,
    sender_key: &str,
) -> Result<Vec<u8>, RouteResult> {
    brc29_locking_script(server_wallet, prefix, suffix, sender_key).map_err(|e| {
        invalid(&format!(
            "The delivery payment remittance is invalid: {}",
            e
        ))
    })
}

/// The door could not answer: the server's side, never a word about the
/// payment. A source that failed is retried by the same request.
fn door_error(error: DoorError) -> RouteResult {
    match error {
        DoorError::Source(e) => err(
            503,
            "ERR_PAYMENT_UNAVAILABLE",
            &format!("The payment's BEEF could not be read: {}", e),
        ),
        DoorError::Internal(e) => err(500, "ERR_INTERNAL", &e),
    }
}

/// The inline payment through the door (`beef_door::verify_inline`): the
/// verdict with the bytes it names, when it names any.
async fn delivery_reading(
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
) -> Result<DoorVerdict, RouteResult> {
    let (output_index, prefix, suffix) = delivery_remittance(server_output, sender_key)?;
    let carrier =
        Carrier::of(tx).ok_or_else(|| invalid("Payment must contain a valid Atomic BEEF."))?;
    let expected_script = delivery_script(server_wallet, prefix, suffix, sender_key)?;
    let terms = Terms {
        output_index,
        expected_script: &expected_script,
        required_satoshis: delivery_fee,
    };
    verify_inline(&carrier, &terms, header_service)
        .await
        .map_err(door_error)
}

/// The delivery check on a payment whose BEEF is an object at rest
/// (`payment.beefR2Key`), for one request's slices
/// (`beef_door::verify_at_rest`): the satoshis paid, a refusal, or 503
/// `ERR_PAYMENT_PENDING` with how far the reading has come; the same request
/// again continues from the saved cursor. No object at the key is 400
/// `ERR_BEEF_KEY_NOT_FOUND`, as before.
#[allow(clippy::too_many_arguments)]
pub async fn check_delivery_at_rest(
    store: &dyn BeefStore,
    key: &str,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
) -> Result<u64, RouteResult> {
    judge_delivery_at_rest(
        store,
        key,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
        slices,
    )
    .await
    .map(|judged| judged.satoshis)
}

/// `check_delivery_at_rest`, with the subject's txid beside the satoshis: the
/// reading itself, which names no size. The route reads an upload through
/// `judge_payment_at_rest`.
#[allow(clippy::too_many_arguments)]
pub async fn judge_delivery_at_rest(
    store: &dyn BeefStore,
    key: &str,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
) -> Result<Judged, RouteResult> {
    judge_at_rest_within(
        store,
        key,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
        slices,
        u64::MAX,
    )
    .await
}

/// The door on a payment uploaded to the relay's store (0.8.9): its stored
/// length, from the stamp the reading uses, is held to
/// `PAYMENT_BUDGET_BYTES` before the saved state is loaded or a byte of it is
/// opened (`beef_door::verify_at_rest_within`), so an object stored before
/// this release is bounded too; over it the answer is 413 `ERR_PAYMENT_SIZE`,
/// and nothing of the reading is kept. Within it, `judge_delivery_at_rest`.
#[allow(clippy::too_many_arguments)]
pub async fn judge_payment_at_rest(
    store: &dyn BeefStore,
    key: &str,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
) -> Result<Judged, RouteResult> {
    judge_at_rest_within(
        store,
        key,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
        slices,
        PAYMENT_BUDGET_BYTES,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn judge_at_rest_within(
    store: &dyn BeefStore,
    key: &str,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
    budget: u64,
) -> Result<Judged, RouteResult> {
    let (output_index, prefix, suffix) = delivery_remittance(server_output, sender_key)?;
    let expected_script = delivery_script(server_wallet, prefix, suffix, sender_key)?;
    let terms = Terms {
        output_index,
        expected_script: &expected_script,
        required_satoshis: delivery_fee,
    };
    let read = match crate::beef_door::verify_at_rest_within(
        store,
        key,
        &terms,
        header_service,
        slices,
        budget,
    )
    .await
    .map_err(door_error)?
    {
        Within::Over(size) => return Err(payment_size_refusal(Some(size))),
        Within::Read(answer, stamp) => (answer, stamp),
    };
    match read {
        (AtRest::Done(verdict), stamp) => {
            door_judged(verdict).map(|judged| Judged { stamp, ..judged })
        }
        (AtRest::Pending(pending), _) => Err(pending_answer(&pending)),
        (AtRest::NotFound, _) => Err(beef_key_not_found("R2 object not found")),
    }
}

fn beef_key_not_found(why: &str) -> RouteResult {
    err(
        400,
        "ERR_BEEF_KEY_NOT_FOUND",
        &format!("Could not fetch BEEF from R2: {}", why),
    )
}

/// The most of a payment's bytes the relay reads (0.8.9): 1,048,576 bytes of
/// the payment itself, its BEEF as bytes, whatever encoding carried it. A
/// payment over it is refused 413 `ERR_PAYMENT_SIZE` before any of it is
/// decoded, parsed or verified, before anything is put at rest for it and
/// before it is handed to a wallet; the door reads and keeps nothing of it,
/// and the same sender may present another payment at once. A request's
/// other content keeps its own bounds (`validation::SEND_BODY_BYTES` for a
/// `/sendMessage` body). A Worker's isolate is memory-limited, and a door
/// bounds what it reads. The figure is provisional: it is read again at this crate's next bsv-rs pin and raised to the door's natural figure then.
pub const PAYMENT_BUDGET_BYTES: u64 = 1_048_576;

/// The refusal of a payment over `PAYMENT_BUDGET_BYTES`, the same at every
/// door: 413 `ERR_PAYMENT_SIZE`, the budget, the payment's size where the door
/// knows it, and one sentence that says the payment is not judged.
pub fn payment_size_refusal(size: Option<u64>) -> RouteResult {
    let budget = PAYMENT_BUDGET_BYTES;
    let description = match size {
        Some(size) => format!(
            "Not judged: this payment is {size} bytes, and this host reads at most {budget} bytes of a payment: a bound of this host, not a rule of the chain, and no verdict on the payment. Pay with other coins. If this payment's size is unconfirmed ancestry, it will be smaller after the next block."
        ),
        None => format!(
            "Not judged: this payment is more than {budget} bytes, the most this host reads of a payment: a bound of this host, not a rule of the chain, and no verdict on the payment. Pay with other coins. If this payment's size is unconfirmed ancestry, it will be smaller after the next block."
        ),
    };
    let mut body = json!({
        "status": "error",
        "code": "ERR_PAYMENT_SIZE",
        "description": description,
        "resource": "Size",
        "budget": budget,
    });
    if let Some(size) = size {
        body["size"] = json!(size);
    }
    (body, 413)
}

/// The bytes an inline `payment.tx` carries, from its encoding's length
/// alone, with no byte decoded: a byte array's length, half a hex string's,
/// three quarters of a base64 text's less its padding. `None` for a value
/// that is none of the three shapes (refused as such by the door).
pub fn sent_payment_bytes(tx: &Value) -> Option<u64> {
    let bytes = match tx {
        Value::Array(items) => items.len(),
        Value::String(hex) => hex.len() / 2,
        Value::Object(o) => {
            let b64 = o.get("beef")?.as_str()?;
            let padding = b64.bytes().rev().take(2).filter(|c| *c == b'=').count();
            (b64.len() / 4 * 3).saturating_sub(padding)
        }
        _ => return None,
    };
    u64::try_from(bytes).ok()
}

/// The door's first word on an inline payment (0.8.9): its bytes held to
/// `PAYMENT_BUDGET_BYTES` by their encoding's length
/// (`sent_payment_bytes`), before any of them is decoded or parsed; 413
/// `ERR_PAYMENT_SIZE` over it.
pub fn check_payment_size(tx: &Value) -> Result<(), RouteResult> {
    match sent_payment_bytes(tx) {
        Some(size) if size > PAYMENT_BUDGET_BYTES => Err(payment_size_refusal(Some(size))),
        _ => Ok(()),
    }
}

/// An upload a box keeps unjudged (no delivery fee), held to
/// `PAYMENT_BUDGET_BYTES` by its stored length (0.8.9): no byte of it is
/// read, here or by the hand-off, which names the object measured here and
/// no other. The stamp measured; 413 `ERR_PAYMENT_SIZE` over the budget; 400
/// `ERR_BEEF_KEY_NOT_FOUND` when the store has no such object or cannot say,
/// the hand-off's answer for the same.
pub async fn check_unjudged_at_rest(
    store: &dyn BeefStore,
    key: &str,
) -> Result<Option<crate::beef_door::Stamp>, RouteResult> {
    let stamp = store
        .stamp(key)
        .await
        .map_err(|e| beef_key_not_found(&e))?
        .ok_or_else(|| beef_key_not_found("R2 object not found"))?;
    if stamp.size > PAYMENT_BUDGET_BYTES {
        return Err(payment_size_refusal(Some(stamp.size)));
    }
    Ok(Some(stamp))
}

/// A payment a box keeps unjudged (no delivery fee), held as 0.3.x held
/// every payment (0.4.4, bsv-low #591 M3): one of the three shapes of bytes;
/// its text no longer than a row holds (`handoff::LIST_INLINE_OBJECT_BYTES`,
/// D1's 2,000,000 bytes), measured before a byte is read, 413
/// `ERR_BODY_TOO_LARGE` beyond it; and its structure a BEEF's (bsv-rs
/// 0.4.3's reader with no script and no root), a refusal naming the offset
/// and the kind otherwise. A box that owes a delivery fee judges the payment
/// whole and refuses nothing for its size; this one judges nothing, so it
/// keeps nothing larger than its row.
pub async fn check_unjudged(payment: &Value) -> Result<(), RouteResult> {
    if let Some(tx) = payment.get("tx") {
        check_payment_size(tx)?;
    }
    let carrier = payment
        .get("tx")
        .and_then(Carrier::of)
        .ok_or_else(|| invalid("Payment must contain a valid Atomic BEEF."))?;
    let shape = crate::handoff::TxShape::sent(payment, &carrier);
    let text = crate::handoff::encoded_len(carrier.len(), shape);
    if text > crate::handoff::LIST_INLINE_OBJECT_BYTES {
        return Err(err(
            413,
            "ERR_BODY_TOO_LARGE",
            &format!(
                "A payment this box does not judge (it owes no delivery fee) is kept in its row, and a row holds {} bytes; this one is {} bytes as sent. Upload it (/beef/upload-url) or send it to a box that judges it.",
                crate::handoff::LIST_INLINE_OBJECT_BYTES,
                text
            ),
        ));
    }
    match structure_inline(&carrier).await.map_err(door_error)? {
        None => Ok(()),
        Some(refused) => door_answer(refused).map(|_| ()),
    }
}

/// Whether a refusal is a reading one request did not finish.
fn is_pending(answer: &RouteResult) -> bool {
    answer.0["code"] == "ERR_PAYMENT_PENDING"
}

/// The spool of a refused inline payment, gone when nothing names it
/// (`handoff::reclaim`: the same bytes sent before may rest under a row).
/// Best-effort: an object left is reclaimed by its deadline.
async fn forget_spool(env: &Env, store: &crate::beef_upload::R2Store<'_>, key: &str) {
    let Ok(db) = env.d1("DB") else {
        return;
    };
    let wallet = WalletInfra { env };
    let ledger = crate::storage::D1Ledger { db: &db };
    let rows = crate::storage::D1Rows { db: &db };
    let seams = Seams {
        blobs: store,
        wallet: &wallet,
        ledger: &ledger,
        rows: &rows,
        announcer: None,
    };
    let _ = reclaim(&seams, key).await;
}

/// The inline payment through the door with its bytes at rest (0.4.4,
/// bsv-low #591 H1): the structure and the paying output are read in the
/// request (no script runs for a body that pays nothing, and nothing is put
/// at rest for it); a payment that pays is spooled to
/// `beef_door::inline_spool_key` with the relay as its reader, and read from
/// there for its scripts and its roots in slices (`judge_delivery_at_rest`).
/// The same request sent again finds its bytes at the same key and resumes
/// from the saved cursor; the verdict is the verdict of the whole.
///
/// The answer, and the key the bytes rest at when they were put there.
#[allow(clippy::too_many_arguments)]
pub async fn judge_delivery_inline_at_rest(
    store: &dyn PaymentStore,
    tx: &Value,
    server_output: &Value,
    delivery_fee: u64,
    sender_key: &str,
    server_wallet: &ProtoWallet,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
    reader: &str,
    minted: Option<(&dyn crate::handoff::RowRefs, u64)>,
) -> (Result<Judged, RouteResult>, Option<String>) {
    let spooled = async || -> Result<String, RouteResult> {
        let (output_index, prefix, suffix) = delivery_remittance(server_output, sender_key)?;
        let carrier =
            Carrier::of(tx).ok_or_else(|| invalid("Payment must contain a valid Atomic BEEF."))?;
        if header_service.is_none() {
            return Err(delivery_answer(PaymentVerdict::NoHeaderService).unwrap_err());
        }
        let expected_script = delivery_script(server_wallet, prefix, suffix, sender_key)?;
        let terms = Terms {
            output_index,
            expected_script: &expected_script,
            required_satoshis: delivery_fee,
        };
        if let Some(refused) = judge_output_inline(&carrier, &terms)
            .await
            .map_err(door_error)?
        {
            door_answer(refused)?;
        }
        let key = inline_spool_key(sender_key, &carrier).await;
        let unavailable = |e: String| {
            err(
                503,
                "ERR_PAYMENT_UNAVAILABLE",
                &format!("The payment's BEEF could not be put at rest: {}", e),
            )
        };
        let at_rest = store.stamp(&key).await.map_err(unavailable)?;
        if at_rest.is_none_or(|stamp| stamp.size != carrier.len()) {
            // Recorded before it is written (0.4.4, bsv-low #591 L3): a spool
            // no send comes back for is reclaimed after its deadline.
            if let Some((rows, now)) = minted {
                rows.mint(&key, now + crate::handoff::MINTED_MARGIN_SECS)
                    .await
                    .map_err(unavailable)?;
            }
            store
                .spool(&key, &mut carrier.chunks(0), carrier.len(), reader)
                .await
                .map_err(unavailable)?;
        }
        Ok(key)
    };
    let key = match spooled().await {
        Ok(key) => key,
        Err(refused) => return (Err(refused), None),
    };
    let judged = judge_delivery_at_rest(
        store,
        &key,
        server_output,
        delivery_fee,
        sender_key,
        server_wallet,
        header_service,
        slices,
    )
    .await;
    (judged, Some(key))
}

/// A verification that one request did not finish: 503, so a client that
/// retries a 503 continues it, with the place the reading has come to.
fn pending_answer(pending: &Pending) -> RouteResult {
    let description = if pending.roots > 0 {
        format!(
            "The payment's BEEF is read ({} elements, {} bytes); {} of its {} merkle roots are checked. Send the same request again to continue.",
            pending.elements, pending.size, pending.roots_asked, pending.roots
        )
    } else if let Some(input) = pending.input {
        format!(
            "The payment's BEEF is being verified ({}): {} elements read, and the scripts of the next, at byte {} of {}, run to its input {}. Send the same request again to continue from that input.",
            pending.phase.name(), pending.elements, pending.offset, pending.size, input
        )
    } else {
        format!(
            "The payment's BEEF is being verified ({}): {} elements and {} of {} bytes read. Send the same request again to continue.",
            pending.phase.name(), pending.elements, pending.offset, pending.size
        )
    };
    (
        json!({
            "status": "error",
            "code": "ERR_PAYMENT_PENDING",
            "description": description,
            "phase": pending.phase.name(),
            "elements": pending.elements,
            "input": pending.input,
            "offset": pending.offset,
            "size": pending.size,
            "rootsChecked": pending.roots_asked,
            "roots": pending.roots,
        }),
        503,
    )
}

/// The door's verdict to the route's answer: `delivery_answer` on the word,
/// and a refusal of the bytes carries the offset and the kind it names as
/// fields, and in the text of every answer but a memory decline's, whose
/// description is its one sentence alone.
pub fn door_answer(verdict: DoorVerdict) -> Result<u64, RouteResult> {
    let DoorVerdict { word, named, .. } = verdict;
    delivery_answer(word).map_err(|(mut body, status)| {
        if let Some(named) = named {
            if body["code"] != "ERR_PAYMENT_MEMORY" {
                let text = body["description"].as_str().unwrap_or_default();
                body["description"] = json!(format!(
                    "{} ({} at offset {})",
                    text, named.kind, named.offset
                ));
            }
            body["offset"] = json!(named.offset);
            body["kind"] = json!(named.kind);
        }
        (body, status)
    })
}

/// `door_answer`, keeping the subject's txid the door names on `Verified`.
pub fn door_judged(verdict: DoorVerdict) -> Result<Judged, RouteResult> {
    let txid = verdict.txid();
    let satoshis = door_answer(verdict)?;
    let txid = txid.ok_or_else(|| {
        err(
            500,
            "ERR_INTERNAL",
            "The door verified a payment and named no subject.",
        )
    })?;
    Ok(Judged {
        satoshis,
        txid,
        stamp: None,
    })
}

/// The six words to the route's answer, in one match with no catch-all arm:
/// the satoshis paid on `Verified`, a refusal on every other word. The
/// statuses are the Axum layer's (bsv-middleware-rs 0.4.1
/// `src/axum_layer.rs:262-290`), with the box's own code for an underpayment:
/// a payment the payer must change is 400; no header service is the server's
/// misconfiguration, 500; a header service that could not answer is 503, so a
/// client retries the same payment and never pays twice.
pub fn delivery_answer(verdict: PaymentVerdict) -> Result<u64, RouteResult> {
    let description = verdict.to_string();
    match verdict {
        PaymentVerdict::Verified { satoshis } => Ok(satoshis),
        PaymentVerdict::Underpaid { .. } => Err(err(
            400,
            "ERR_INSUFFICIENT_PAYMENT",
            "The server delivery output does not pay the required amount.",
        )),
        PaymentVerdict::WrongScript { .. } | PaymentVerdict::RootMismatch { .. } => Err(err(
            400,
            "ERR_INVALID_PAYMENT",
            &format!("The server delivery output is invalid: {}", description),
        )),
        PaymentVerdict::NoHeaderService => Err(err(500, "ERR_SERVER_MISCONFIGURED", &description)),
        PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
            offset,
            txid,
            input,
            why: SpendRefusal::Resource(limit),
        }) if limit.resource == ScriptResource::Work => Err((
            json!({
                "status": "error",
                "code": "ERR_PAYMENT_WORK",
                "description": "The local evaluator declined this input at its work budget; payment validity is undetermined.",
                "resource": "Work",
                "offset": offset,
                "txid": txid,
                "input": input,
                "budget": limit.limit,
                "workSpent": limit.work_spent,
                "attempted": limit.attempted,
            }),
            422,
        )),
        // Every other resource decline: the memory budget
        // (`beef_door::STACK_MEMORY_BYTES`) reached, or memory for a script's
        // step declined. The same road as the work budget: a 422 naming the
        // resource, the relay's own budget (always the constant) and the bytes
        // the input asked for. The payment is not judged: `txid` and `input`
        // name the unproven transaction of the payment's BEEF, the payment
        // itself or one of its ancestors, whose input's script was running
        // (bsv-rs `Verdict::SpendRefused`), and the description gives the
        // way out.
        PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
            offset,
            txid,
            input,
            why: SpendRefusal::Resource(limit),
        }) => Err((
            json!({
                "status": "error",
                "code": "ERR_PAYMENT_MEMORY",
                "description": memory_description(&txid, input),
                "resource": format!("{:?}", limit.resource),
                "offset": offset,
                "txid": txid,
                "input": input,
                "budget": STACK_MEMORY_BYTES,
                "attempted": limit.attempted,
            }),
            422,
        )),
        PaymentVerdict::Unverifiable(reason) if reason.is_server_side() => {
            Err(err(503, "ERR_PAYMENT_UNAVAILABLE", &description))
        }
        PaymentVerdict::Unverifiable(_) => Err(err(
            400,
            "ERR_INVALID_PAYMENT",
            &format!("The server delivery output is invalid: {}", description),
        )),
    }
}

/// The sentence of a memory decline, the same at every door: the host
/// declined memory for a script of an unproven transaction in the payment's
/// BEEF (the payment itself or one of its ancestors); the bound is this
/// host's, not a rule of the chain, and no verdict on the payment; and the
/// way out, the free one first. bsv-rs runs the scripts of a transaction
/// only when it carries no proof of its own, so once that transaction has
/// its proof they are not run.
pub fn memory_description(txid: &str, input: Option<u32>) -> String {
    let script = match input {
        Some(input) => format!("for the script of input {input} of transaction {txid}"),
        None => format!("for a script of transaction {txid}"),
    };
    format!(
        "Not judged: this host declined memory {script}, an unproven transaction in this payment's BEEF (the payment itself or one of its ancestors). This host's memory bound is {STACK_MEMORY_BYTES} bytes per stack: a bound of this host, not a rule of the chain, and no verdict on the payment. Present this payment again once transaction {txid} has its proof, or pay with other coins."
    )
}

/// The operator's record of a payment the door did not judge (a work or a
/// memory decline, 422 `ERR_PAYMENT_WORK` or `ERR_PAYMENT_MEMORY`, or a
/// payment over the byte budget, 413 `ERR_PAYMENT_SIZE`): one
/// `AUDIT payment.not_judged` line with the code, the resource, the
/// transaction and input whose script the bound stopped (for a size, the
/// payment's bytes and the budget), and the sender's public identity key.
/// `None` for every other answer.
pub fn not_judged_line(body: &Value, sender: &str) -> Option<String> {
    let code = body["code"].as_str()?;
    let word = |field: &str| match &body[field] {
        Value::String(text) => text.clone(),
        Value::Null => "none".to_string(),
        other => other.to_string(),
    };
    if code == "ERR_PAYMENT_SIZE" {
        return Some(format!(
            "AUDIT payment.not_judged code={code} resource={} size={} budget={} sender={sender}",
            word("resource"),
            word("size"),
            word("budget"),
        ));
    }
    if code != "ERR_PAYMENT_MEMORY" && code != "ERR_PAYMENT_WORK" {
        return None;
    }
    Some(format!(
        "AUDIT payment.not_judged code={code} resource={} txid={} input={} sender={sender}",
        word("resource"),
        word("txid"),
        word("input"),
    ))
}

/// The host a lookup over the binding names. A service binding ignores the
/// host and hands the callee the path and the query, so the route is the one
/// the URL mode calls.
const HEADER_BINDING_BASE: &str = "https://header-service";

/// One GET to the header service: the status and the body, or why the request
/// did not complete. The seam between the lookup and the way it leaves the
/// Worker (0.3.30): the service binding, or the Worker fetch of a URL.
#[async_trait::async_trait(?Send)]
pub trait HeaderTransport {
    async fn get(&self, url: &str) -> Result<(u16, String), String>;
}

/// The `HEADER_SERVICE` service binding: `Fetcher::fetch`, the one way one
/// Worker reaches another on the same Cloudflare account.
pub struct BindingTransport(worker::Fetcher);

#[async_trait::async_trait(?Send)]
impl HeaderTransport for BindingTransport {
    async fn get(&self, url: &str) -> Result<(u16, String), String> {
        let response = self.0.fetch(url, None).await.map_err(|e| e.to_string())?;
        status_and_body(response).await
    }
}

/// The Worker fetch of a URL (0.3.29), for a header service on another
/// account.
pub struct UrlTransport;

#[async_trait::async_trait(?Send)]
impl HeaderTransport for UrlTransport {
    async fn get(&self, url: &str) -> Result<(u16, String), String> {
        let response = worker::Fetch::Url(
            url.parse()
                .map_err(|e| format!("header service URL: {}", e))?,
        )
        .send()
        .await
        .map_err(|e| e.to_string())?;
        status_and_body(response).await
    }
}

async fn status_and_body(mut response: worker::Response) -> Result<(u16, String), String> {
    let status = response.status_code();
    let body = response
        .text()
        .await
        .map_err(|e| format!("read response: {}", e))?;
    Ok((status, body))
}

/// The box's header service: the merkle root of the block at a height, through
/// `GET {base}/findHeaderHexForHeight?height={h}` (the lookup of
/// bsv-middleware-cloudflare 0.3.8 `src/payment_verify.rs:96,331-356`), from
/// the Worker behind the `HEADER_SERVICE` service binding or, without one,
/// the service the `HEADER_SERVICE_URL` var names (0.3.30).
/// It only fetches; the comparison and the fail-closed rule are the
/// verifier's.
pub struct WorkerHeaderService {
    base: String,
    // A Worker is single-threaded; the trait asks for `Send + Sync`.
    transport: worker::send::SendWrapper<Box<dyn HeaderTransport>>,
}

impl WorkerHeaderService {
    /// The service a configured value names, or `None` when it names none
    /// (unset, blank, a `.invalid` host, a host that cannot be classified:
    /// `header_service_url`, bsv-middleware-rs 0.4.1). `None` is passed to
    /// the verifier as it is and answered `NoHeaderService`.
    pub fn configured(configured: Option<&str>) -> Option<Self> {
        Self::over(None, configured)
    }

    /// The service a binding and a configured value name between them: the
    /// binding when there is one, whatever the value says; without it, the
    /// service the value names; with neither, none.
    pub fn over(
        binding: Option<Box<dyn HeaderTransport>>,
        configured: Option<&str>,
    ) -> Option<Self> {
        let (base, transport) = match binding {
            Some(binding) => (HEADER_BINDING_BASE, binding),
            None => (
                header_service_url(configured)?,
                Box::new(UrlTransport) as Box<dyn HeaderTransport>,
            ),
        };
        Some(Self {
            base: base.to_string(),
            transport: worker::send::SendWrapper::new(transport),
        })
    }

    fn from_env(env: &Env) -> Option<Self> {
        let binding = env
            .service("HEADER_SERVICE")
            .ok()
            .map(|service| Box::new(BindingTransport(service)) as Box<dyn HeaderTransport>);
        let configured = env.var("HEADER_SERVICE_URL").ok().map(|v| v.to_string());
        Self::over(binding, configured.as_deref())
    }

    async fn fetch_root(&self, height: u32) -> Result<String, String> {
        let url = format!("{}/findHeaderHexForHeight?height={}", self.base, height);
        let (status, body) = self
            .transport
            .get(&url)
            .await
            .map_err(|e| format!("fetch height {}: {}", height, e))?;
        if status >= 400 {
            return Err(format!(
                "header service HTTP {} at height {}",
                status, height
            ));
        }
        header_root_from_response(&body, height)
    }
}

#[async_trait::async_trait]
impl HeaderService for WorkerHeaderService {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        // A Worker is single-threaded and its fetch future is not `Send`;
        // the trait asks for one.
        worker::send::SendFuture::new(self.fetch_root(height))
            .await
            .map_err(HeaderLookupError)
    }
}

/// The merkle root a `findHeaderHexForHeight` reply carries
/// (`{"status":"success","value":{"merkleRoot":...}}`, `merkleroot` also
/// read), or why it carries none: every such reason is a lookup that could
/// not answer (bsv-middleware-cloudflare 0.3.8 `src/payment_verify.rs:296-328`).
fn header_root_from_response(body: &str, height: u32) -> Result<String, String> {
    let reply: Value = serde_json::from_str(body).map_err(|e| format!("parse response: {}", e))?;
    let status = reply.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "success" {
        return Err(format!(
            "header service status '{}' at height {}",
            status, height
        ));
    }
    let header = reply
        .get("value")
        .filter(|v| !v.is_null())
        .ok_or_else(|| format!("no header at height {}", height))?;
    header
        .get("merkleRoot")
        .or_else(|| header.get("merkleroot"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| "response missing merkleRoot".to_string())
}

/// The relay's identity key: the reader every object of a paid message names
/// (`handoff::READER_METADATA`).
pub(crate) fn relay_identity(env: &Env) -> Result<String, String> {
    server_private_key(env).map(|key| key.public_key().to_hex())
}

/// The SERVER_PRIVATE_KEY secret, parsed.
fn server_private_key(env: &Env) -> Result<PrivateKey, String> {
    let server_key = env
        .secret("SERVER_PRIVATE_KEY")
        .map_err(|e| format!("SERVER_PRIVATE_KEY: {}", e))?
        .to_string();
    PrivateKey::from_hex(&server_key).map_err(|e| format!("Invalid key: {}", e))
}

/// Scheduled (cron) entry: the drain of the deferred fees (`fee_internalize`,
/// `handoff::drain_fees`). A deployment with no cron never drains; one whose
/// table is empty reads one indexed row range and returns.
pub async fn run_fee_drain(env: &Env) {
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("AUDIT fee.drain D1 binding unavailable: {e}");
            return;
        }
    };
    let blobs = crate::beef_upload::R2Store::new(env);
    let wallet = WalletInfra { env };
    let ledger = crate::storage::D1Ledger { db: &db };
    let rows = crate::storage::D1Rows { db: &db };
    let arc = ArcAnnouncer::from_env(env);
    let seams = Seams {
        blobs: &blobs,
        wallet: &wallet,
        ledger: &ledger,
        rows: &rows,
        announcer: arc.as_ref().map(|arc| arc as &dyn Announcer),
    };
    let now = worker::Date::now().as_millis() / 1000;
    // The announcements a broadcaster refused, or did not answer, asked
    // again (0.4.4, bsv-low #591 M2).
    match reask_announces(&seams, now, DRAIN_BATCH).await {
        Ok(reasked) if reasked == Default::default() => {}
        Ok(reasked) => worker::console_log!(
            "AUDIT announce.reask accepted={} put_off={}",
            reasked.accepted,
            reasked.put_off
        ),
        Err(e) => worker::console_error!("AUDIT announce.reask FAILED: {e}"),
    }
    match drain_fees(&seams, now, DRAIN_BATCH).await {
        Ok(drained) if drained == Default::default() => {}
        Ok(drained) => worker::console_log!(
            "AUDIT fee.drain settled={} put_off={} ended={}",
            drained.settled,
            drained.put_off,
            drained.ended
        ),
        Err(e) => worker::console_error!("AUDIT fee.drain FAILED: {e}"),
    }
    // The keys the relay minted that no send named by their deadline
    // (`handoff::reclaim_minted`, 0.4.4 bsv-low #591 L3).
    match crate::handoff::reclaim_minted(&seams, now, RECLAIM_BATCH).await {
        Ok(expired) if expired == Default::default() => {}
        Ok(expired) => worker::console_log!(
            "AUDIT beef.minted deleted={} named={} put_off={}",
            expired.deleted,
            expired.named,
            expired.put_off
        ),
        Err(e) => worker::console_error!("AUDIT beef.minted FAILED: {e}"),
    }
    // The objects rows have let go of (`handoff::reclaim_released`): one
    // indexed read when there are none.
    match reclaim_released(&seams, RECLAIM_BATCH).await {
        Ok(reclaimed) if reclaimed == Default::default() => {}
        Ok(reclaimed) => worker::console_log!(
            "AUDIT beef.reclaim deleted={} named={} put_off={}",
            reclaimed.deleted,
            reclaimed.named,
            reclaimed.put_off
        ),
        Err(e) => worker::console_error!("AUDIT beef.reclaim FAILED: {e}"),
    }
}

/// After a send (`handoff::forget_unnamed`), over the Worker's stores:
/// best-effort, and never an answer to the sender.
pub async fn forget_unnamed(
    env: &Env,
    rows_naming: usize,
    handed: &Option<crate::handoff::HandedOff>,
    r2_key: Option<&str>,
    failed: bool,
) {
    let (Some(handed), Ok(db)) = (handed, env.d1("DB")) else {
        return;
    };
    let blobs = crate::beef_upload::R2Store::new(env);
    let wallet = WalletInfra { env };
    let ledger = crate::storage::D1Ledger { db: &db };
    let rows = crate::storage::D1Rows { db: &db };
    let seams = Seams {
        blobs: &blobs,
        wallet: &wallet,
        ledger: &ledger,
        rows: &rows,
        announcer: None,
    };
    // A row written while a reclaim held its key, whose bytes are gone: the
    // one case the claim cannot spare, logged with its key (0.4.4, bsv-low
    // #591 L2).
    if let (false, Some(key)) = (failed, handed.kept.as_deref()) {
        if crate::handoff::orphaned(&seams, key).await {
            worker::console_error!(
                "AUDIT beef.orphan key={key} rows={rows_naming}: a reclaim held the key as the send named it, and its bytes are gone"
            );
        }
    }
    crate::handoff::forget_unnamed(&seams, rows_naming, handed, r2_key, failed).await;
}

/// The broadcaster a verified payment's subject is announced to (0.4.4,
/// bsv-low #591 M2): an ARC named by the `ARC_URL` var, with the
/// `ARC_API_KEY` secret as a bearer token when it is set. A deployment that
/// names none announces nothing and says so on the row.
///
/// The body is the BEEF as bytes, `application/octet-stream`, to `/v1/tx`:
/// ARC tells a BEEF by its bytes (V1 or V2) and has no case for the Atomic
/// prefix, so the 36 bytes of the prefix are left off (`[SRC] arc@e7efc5b
/// internal/api/handler/parsers.go:20-61`, `internal/beef/beef.go:24-34`, read
/// in bsv-stack-lean `docs/readings/broadcast-body-forms.md`; wallet-infra's
/// stream of a BEEF at rest does the same, `src/broadcast_at_rest.rs:32-38`).
/// Bytes at rest are handed to the fetch as R2's own stream, never read into
/// the Worker. The answer is a hint: 2xx is taken, anything else is not, and
/// the word is the status and what ARC said.
pub struct ArcAnnouncer<'a> {
    env: &'a Env,
    url: String,
}

/// The Atomic BEEF prefix (BRC-95): its magic, then the subject's txid.
const ATOMIC_PREFIX: [u8; 4] = [0x01, 0x01, 0x01, 0x01];
const ATOMIC_PREFIX_LEN: u64 = 36;

/// What an ARC word keeps of its body.
const ARC_WORD_CHARS: usize = 300;

impl<'a> ArcAnnouncer<'a> {
    pub fn from_env(env: &'a Env) -> Option<Self> {
        let url = env.var("ARC_URL").ok()?.to_string();
        let url = url.trim().trim_end_matches('/').to_string();
        (!url.is_empty()).then_some(Self { env, url })
    }

    async fn post(&self, body: wasm_bindgen::JsValue) -> Result<Hint, String> {
        let headers = worker::Headers::new();
        headers
            .set("Content-Type", "application/octet-stream")
            .map_err(|e| e.to_string())?;
        if let Ok(key) = self.env.secret("ARC_API_KEY") {
            headers
                .set("Authorization", &format!("Bearer {}", key))
                .map_err(|e| e.to_string())?;
        }
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post)
            .with_headers(headers)
            .with_body(Some(body));
        let request = worker::Request::new_with_init(&format!("{}/v1/tx", self.url), &init)
            .map_err(|e| e.to_string())?;
        let response = worker::Fetch::Request(request)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let (status, text) = status_and_body(response).await?;
        let said: String = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| {
                v.get("txStatus")
                    .or_else(|| v.get("title"))
                    .and_then(|w| w.as_str().map(str::to_string))
            })
            .unwrap_or(text)
            .chars()
            .take(ARC_WORD_CHARS)
            .collect();
        Ok(Hint {
            accepted: (200..300).contains(&status),
            word: format!("ARC {}: {}", status, said),
        })
    }
}

#[async_trait::async_trait(?Send)]
impl Announcer for ArcAnnouncer<'_> {
    async fn announce(&self, subject: Subject<'_>) -> Result<Hint, String> {
        match subject {
            Subject::InHand(carrier) => {
                let mut bytes = carrier.bytes(0, carrier.len() as usize);
                if bytes.starts_with(&ATOMIC_PREFIX) {
                    bytes.drain(..(ATOMIC_PREFIX_LEN as usize).min(bytes.len()));
                }
                self.post(js_sys::Uint8Array::from(&bytes[..]).into()).await
            }
            Subject::AtRest { key, stamp } => {
                let bucket = self
                    .env
                    .bucket("BEEF_BLOBS")
                    .map_err(|e| format!("R2 binding BEEF_BLOBS: {}", e))?;
                let lead = bucket
                    .get(key)
                    .range(worker::Range::OffsetWithLength {
                        offset: 0,
                        length: 4,
                    })
                    .execute()
                    .await
                    .map_err(|e| format!("R2 get: {}", e))?
                    .ok_or("R2 object not found")?;
                let lead = lead
                    .body()
                    .ok_or("R2 object body missing")?
                    .bytes()
                    .await
                    .map_err(|e| format!("R2 body read: {}", e))?;
                let from = if lead.starts_with(&ATOMIC_PREFIX) {
                    ATOMIC_PREFIX_LEN
                } else {
                    0
                };
                let object = bucket
                    .get(key)
                    .range(worker::Range::OffsetToEnd { offset: from })
                    .execute()
                    .await
                    .map_err(|e| format!("R2 get: {}", e))?
                    .ok_or("R2 object not found")?;
                if object.etag() != stamp.etag {
                    return Err("the R2 object changed".to_string());
                }
                let body = object
                    .body()
                    .ok_or("R2 object body missing")?
                    .response_body()
                    .map_err(|e| format!("R2 body: {}", e))?;
                match body {
                    worker::ResponseBody::Stream(stream) => self.post(stream.into()).await,
                    worker::ResponseBody::Body(bytes) => {
                        self.post(js_sys::Uint8Array::from(&bytes[..]).into()).await
                    }
                    worker::ResponseBody::Empty => Err("R2 object body empty".to_string()),
                }
            }
        }
    }
}

/// wallet-infra behind `WALLET_STORAGE_URL`, as the hand-off's `FeeWallet`.
pub struct WalletInfra<'a> {
    pub env: &'a Env,
}

#[async_trait::async_trait(?Send)]
impl FeeWallet for WalletInfra<'_> {
    async fn internalize(&self, args: &Value) -> Result<bool, String> {
        internalize_server_fee(args, self.env).await
    }
}

/// Internalize the server delivery fee via WorkerStorageClient → wallet-infra.
/// `args` is the whole argument, `tx` or `beefAtRest` beside the output, the
/// description and the labels (`handoff::internalize_inline`,
/// `handoff::internalize_at_rest`).
async fn internalize_server_fee(args: &Value, env: &Env) -> Result<bool, String> {
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

    let auth = json!({
        "identityKey": identity_key
    });

    let result = client
        .internalize_action(auth, args.clone())
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
    use base64::Engine as _;
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
    // Crafted payments only: one input from a crafted parent proven by a
    // one-leaf BUMP, never signed, never broadcast, no wallet-infra; the
    // header service is a stub answering from a table.

    use bsv_rs::primitives::PublicKey;
    use bsv_rs::script::LockingScript;
    use bsv_rs::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, Protocol, SecurityLevel};
    use std::sync::Mutex;

    const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PREFIX: &str = "cHJlZml4";
    const SUFFIX: &str = "c3VmZml4";
    const FEE: u64 = 100;
    const HEIGHT: u32 = 850_000;

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

    /// The script the payer pays: the server's BRC-29 key for this
    /// remittance, derived by the sender, independent of the code under test.
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

    /// The crafted parent every payment here spends. It has one input, naming
    /// a transaction the BEEF does not carry (its proof vouches for it), and
    /// one output: a transaction with no input is invalid bytes to bsv-rs's
    /// reader since 0.4.1, and one with no output since 0.4.3.
    fn parent() -> Transaction {
        let mut parent = Transaction::new();
        parent
            .add_input(TransactionInput {
                source_txid: Some("11".repeat(32)),
                source_output_index: 0,
                ..Default::default()
            })
            .unwrap();
        parent
            .add_output(TransactionOutput::new(
                10_000,
                LockingScript::from_binary(&[0x51]).unwrap(),
            ))
            .unwrap();
        parent
    }

    /// The root of the parent's block: a block of one transaction, so the
    /// root is the parent's txid.
    fn parent_root() -> String {
        parent().id()
    }

    /// An Atomic BEEF of a payment with `outputs`, spending the parent; the
    /// parent proven by a one-leaf BUMP at `HEIGHT` when `proven`.
    fn atomic_beef_of(outputs: &[(u64, Vec<u8>)], proven: bool) -> Vec<u8> {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::with_source_transaction(parent(), 0))
            .unwrap();
        for (satoshis, script) in outputs {
            tx.add_output(TransactionOutput::new(
                *satoshis,
                LockingScript::from_binary(script).unwrap(),
            ))
            .unwrap();
        }
        let txid = tx.id();
        let mut beef = Beef::new();
        if proven {
            beef.merge_bump(
                MerklePath::new(
                    HEIGHT,
                    vec![vec![MerklePathLeaf::new_txid(0, parent_root())]],
                )
                .unwrap(),
            );
        }
        beef.merge_transaction(parent());
        beef.merge_transaction(tx);
        beef.to_binary_atomic(&txid).unwrap()
    }

    fn atomic_beef(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        atomic_beef_of(outputs, true)
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

    /// A header service answering one thing at every height; records the
    /// heights asked.
    struct StubHeaders {
        answer: Result<String, HeaderLookupError>,
        asked: Mutex<Vec<u32>>,
    }

    impl StubHeaders {
        fn answering(answer: Result<String, HeaderLookupError>) -> Self {
            Self {
                answer,
                asked: Mutex::new(Vec::new()),
            }
        }

        /// The honest service: the parent's block at `HEIGHT`.
        fn honest() -> Self {
            Self::answering(Ok(parent_root()))
        }

        fn asked(&self) -> Vec<u32> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HeaderService for StubHeaders {
        async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
            self.asked.lock().unwrap().push(height);
            self.answer.clone()
        }
    }

    async fn check_due(tx: &Value, output: &Value, due: u64) -> Result<u64, RouteResult> {
        check_delivery_output(
            tx,
            output,
            due,
            &sender_identity(),
            &wallet(SERVER_KEY),
            Some(&StubHeaders::honest()),
        )
        .await
    }

    async fn check(tx: &Value, output: &Value) -> Result<u64, RouteResult> {
        check_due(tx, output, FEE).await
    }

    fn refusal_code(r: Result<u64, RouteResult>) -> (u16, String) {
        let (body, status) = r.expect_err("expected a refusal");
        (status, body["code"].as_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn p0_3_delivery_fee_exact_is_accepted() {
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(
            check(&tx, &remittance(0, &sender_identity())).await,
            Ok(FEE)
        );
    }

    #[tokio::test]
    async fn p0_3_delivery_fee_one_under_is_refused() {
        let tx = tx_json(&[(FEE - 1, payer_script())]);
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity())).await),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_3_delivery_fee_one_over_returns_the_real_amount() {
        let tx = tx_json(&[(FEE + 1, payer_script())]);
        assert_eq!(
            check(&tx, &remittance(0, &sender_identity())).await,
            Ok(FEE + 1)
        );
    }

    #[tokio::test]
    async fn p0_3_delivery_output_at_another_script_is_refused() {
        let tx = tx_json(&[(FEE, p2pkh(&[9u8; 20]))]);
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity())).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_3_remittance_sender_other_than_the_authenticated_one_is_refused() {
        let tx = tx_json(&[(FEE, payer_script())]);
        let other = wallet(SERVER_KEY).identity_key().to_hex();
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &other)).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_3_a_remittance_that_is_not_a_wallet_payment_is_refused() {
        let tx = tx_json(&[(FEE, payer_script())]);
        let mut output = remittance(0, &sender_identity());
        output["protocol"] = json!("basket insertion");
        assert_eq!(
            refusal_code(check(&tx, &output).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_3_the_named_output_index_is_the_one_read() {
        // Output 0 pays someone else; the remittance names output 1, which
        // pays the server: that is the output internalized, so it is read.
        let tx = tx_json(&[(FEE, p2pkh(&[9u8; 20])), (FEE, payer_script())]);
        assert_eq!(
            check(&tx, &remittance(1, &sender_identity())).await,
            Ok(FEE)
        );
        assert_eq!(
            refusal_code(check(&tx, &remittance(0, &sender_identity())).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_3_tx_as_hex_or_inlined_beef_is_read_like_the_byte_array() {
        let bytes = atomic_beef(&[(FEE - 1, payer_script())]);
        for tx in [
            json!(hex::encode(&bytes)),
            json!({ "beef": base64::engine::general_purpose::STANDARD.encode(&bytes) }),
        ] {
            assert_eq!(
                refusal_code(check(&tx, &remittance(0, &sender_identity())).await),
                (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
            );
        }
    }

    #[tokio::test]
    async fn p0_3_an_unreadable_tx_is_refused() {
        for tx in [
            json!("not hex"),
            json!([1, 2, 300]),
            json!({ "other": 1 }),
            json!(7),
        ] {
            assert_eq!(
                refusal_code(check(&tx, &remittance(0, &sender_identity())).await),
                (400, "ERR_INVALID_PAYMENT".to_string())
            );
        }
    }

    // ---- 0.3.29: the six words, the header service as the trait ----

    async fn check_with(
        tx: &Value,
        headers: Option<&dyn HeaderService>,
    ) -> Result<u64, RouteResult> {
        check_delivery_output(
            tx,
            &remittance(0, &sender_identity()),
            FEE,
            &sender_identity(),
            &wallet(SERVER_KEY),
            headers,
        )
        .await
    }

    #[tokio::test]
    async fn the_root_is_asked_of_the_header_service_at_its_height() {
        let headers = StubHeaders::honest();
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(check_with(&tx, Some(&headers)).await, Ok(FEE));
        assert_eq!(headers.asked(), vec![HEIGHT]);
    }

    #[tokio::test]
    async fn no_header_service_refuses_a_good_payment_500() {
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(
            refusal_code(check_with(&tx, None).await),
            (500, "ERR_SERVER_MISCONFIGURED".to_string())
        );
    }

    #[tokio::test]
    async fn a_header_lookup_that_cannot_answer_refuses_a_good_payment_503() {
        // Fail closed (the ruling of 2026-10-08): never accepted unchecked,
        // and never answered as unpaid.
        let headers = StubHeaders::answering(Err(HeaderLookupError("timeout".into())));
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(
            refusal_code(check_with(&tx, Some(&headers)).await),
            (503, "ERR_PAYMENT_UNAVAILABLE".to_string())
        );
        assert_eq!(headers.asked(), vec![HEIGHT]);
    }

    #[tokio::test]
    async fn a_root_the_header_does_not_carry_is_refused_400() {
        let headers = StubHeaders::answering(Ok("00".repeat(32)));
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(
            refusal_code(check_with(&tx, Some(&headers)).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn a_root_in_another_case_is_the_same_root() {
        let headers = StubHeaders::answering(Ok(parent_root().to_uppercase()));
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(check_with(&tx, Some(&headers)).await, Ok(FEE));
    }

    #[tokio::test]
    async fn a_payment_with_no_proof_is_refused_400_and_nothing_is_asked() {
        let headers = StubHeaders::honest();
        let tx = json!(atomic_beef_of(&[(FEE, payer_script())], false));
        assert_eq!(
            refusal_code(check_with(&tx, Some(&headers)).await),
            (400, "ERR_INVALID_PAYMENT".to_string())
        );
        assert!(headers.asked().is_empty());
    }

    #[tokio::test]
    async fn an_underpayment_is_refused_before_any_lookup() {
        let headers = StubHeaders::honest();
        let tx = tx_json(&[(FEE - 1, payer_script())]);
        assert_eq!(
            refusal_code(check_with(&tx, Some(&headers)).await),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
        assert!(headers.asked().is_empty());
    }

    #[test]
    fn the_configured_value_names_a_header_service_or_none() {
        for none in [
            None,
            Some(""),
            Some("   "),
            Some("https://chaintracks.invalid"),
            Some("not a url"),
        ] {
            assert!(WorkerHeaderService::configured(none).is_none(), "{none:?}");
        }
        let service = WorkerHeaderService::configured(Some(" https://headers.example/ "))
            .expect("a service is named");
        assert_eq!(service.base, "https://headers.example");
    }

    #[test]
    fn the_header_reply_gives_its_root_or_a_reason() {
        let root = "ab".repeat(32);
        for body in [
            json!({ "status": "success", "value": { "merkleRoot": root } }),
            json!({ "status": "success", "value": { "merkleroot": root } }),
        ] {
            assert_eq!(
                header_root_from_response(&body.to_string(), HEIGHT),
                Ok(root.clone())
            );
        }
        for body in [
            "not json".to_string(),
            json!({ "status": "error" }).to_string(),
            json!({ "status": "success" }).to_string(),
            json!({ "status": "success", "value": null }).to_string(),
            json!({ "status": "success", "value": { "height": HEIGHT } }).to_string(),
        ] {
            assert!(header_root_from_response(&body, HEIGHT).is_err(), "{body}");
        }
    }

    // ---- 0.3.30: the header service over a service binding ----

    /// A `HEADER_SERVICE` binding answering one thing; records the URLs asked.
    struct StubBinding {
        answer: Result<(u16, String), String>,
        asked: Asked,
    }

    #[async_trait::async_trait(?Send)]
    impl HeaderTransport for StubBinding {
        async fn get(&self, url: &str) -> Result<(u16, String), String> {
            self.asked.lock().unwrap().push(url.to_string());
            self.answer.clone()
        }
    }

    type Asked = std::sync::Arc<Mutex<Vec<String>>>;

    fn binding(answer: Result<(u16, String), String>) -> (Box<dyn HeaderTransport>, Asked) {
        let asked = Asked::default();
        let stub = StubBinding {
            answer,
            asked: asked.clone(),
        };
        (Box::new(stub), asked)
    }

    fn honest_reply() -> Result<(u16, String), String> {
        let body = json!({ "status": "success", "value": { "merkleRoot": parent_root() } });
        Ok((200, body.to_string()))
    }

    fn the_lookup_at_height() -> Vec<String> {
        vec![format!(
            "https://header-service/findHeaderHexForHeight?height={HEIGHT}"
        )]
    }

    #[tokio::test]
    async fn a_binding_and_no_url_checks_the_root_through_the_binding() {
        let (stub, asked) = binding(honest_reply());
        let headers = WorkerHeaderService::over(Some(stub), None)
            .expect("a HEADER_SERVICE binding names a header service");
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(check_with(&tx, Some(&headers)).await, Ok(FEE));
        assert_eq!(*asked.lock().unwrap(), the_lookup_at_height());
    }

    #[tokio::test]
    async fn the_binding_wins_over_the_url() {
        let (stub, asked) = binding(honest_reply());
        let headers = WorkerHeaderService::over(Some(stub), Some("https://headers.example"))
            .expect("a header service is named");
        let tx = tx_json(&[(FEE, payer_script())]);
        assert_eq!(check_with(&tx, Some(&headers)).await, Ok(FEE));
        assert_eq!(*asked.lock().unwrap(), the_lookup_at_height());
    }

    #[tokio::test]
    async fn a_binding_that_cannot_answer_refuses_a_good_payment_503() {
        for answer in [
            Ok((404, "error code: 1042".to_string())),
            Ok((500, honest_reply().unwrap().1)),
            Ok((200, "not json".to_string())),
            Err("the binding threw".to_string()),
        ] {
            let (stub, asked) = binding(answer.clone());
            let headers = WorkerHeaderService::over(Some(stub), None)
                .expect("a HEADER_SERVICE binding names a header service");
            let tx = tx_json(&[(FEE, payer_script())]);
            assert_eq!(
                refusal_code(check_with(&tx, Some(&headers)).await),
                (503, "ERR_PAYMENT_UNAVAILABLE".to_string()),
                "{answer:?}"
            );
            assert_eq!(*asked.lock().unwrap(), the_lookup_at_height());
        }
    }

    #[test]
    fn no_binding_leaves_the_url_and_neither_names_no_service() {
        assert!(WorkerHeaderService::over(None, None).is_none());
        assert!(WorkerHeaderService::over(None, Some("https://chaintracks.invalid")).is_none());
        let service = WorkerHeaderService::over(None, Some("https://headers.example/"))
            .expect("the URL names a service");
        assert_eq!(service.base, "https://headers.example");
    }

    // ---- P0-5b: the fee per recipient (M1) and the body bound (H1a) ----

    #[tokio::test]
    async fn p0_5b_two_recipients_paying_one_fee_is_refused() {
        // The reference charges the delivery fee once per recipient
        // (ts-stack@fb1b2da infra/message-box-server/src/routes/sendMessage.ts:710-722,1707-1713).
        let tx = tx_json(&[(FEE, payer_script())]);
        let due = delivery_fee_due(FEE as i32, 2).expect("a fee is due");
        assert_eq!(
            refusal_code(check_due(&tx, &remittance(0, &sender_identity()), due).await),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
    }

    #[tokio::test]
    async fn p0_5b_two_recipients_paying_two_fees_is_accepted() {
        let tx = tx_json(&[(2 * FEE, payer_script())]);
        let due = delivery_fee_due(FEE as i32, 2).expect("a fee is due");
        assert_eq!(
            check_due(&tx, &remittance(0, &sender_identity()), due).await,
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

    // ---- NL-4: the reader names no size or count; the route's door holds a
    // payment's bytes to PAYMENT_BUDGET_BYTES before the reader (below) ----

    const THE_OLD_DOOR: usize = 4 * 1024 * 1024;

    /// A payment over the old door: output 0 as given, and a second output
    /// of ballast nothing spends.
    fn over_the_old_door(satoshis: u64) -> Vec<u8> {
        let bytes = atomic_beef(&[(satoshis, payer_script()), (0, vec![0x6a; THE_OLD_DOOR])]);
        assert!(bytes.len() > THE_OLD_DOOR);
        bytes
    }

    fn shapes(bytes: &[u8]) -> [Value; 3] {
        [
            json!(bytes),
            json!(hex::encode(bytes)),
            json!({ "beef": base64::engine::general_purpose::STANDARD.encode(bytes) }),
        ]
    }

    #[tokio::test]
    async fn nl4_a_payment_over_the_old_door_is_judged_like_any_other_in_every_shape() {
        let output = remittance(0, &sender_identity());
        for tx in shapes(&over_the_old_door(FEE)) {
            assert_eq!(check(&tx, &output).await, Ok(FEE));
        }
        for tx in shapes(&over_the_old_door(FEE - 1)) {
            assert_eq!(
                refusal_code(check(&tx, &output).await),
                (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
            );
        }
    }

    #[tokio::test]
    async fn nl4_bytes_over_the_old_door_that_are_no_beef_are_refused_for_the_byte_not_the_size() {
        for tx in shapes(&vec![0u8; THE_OLD_DOOR + 1]) {
            let (body, status) = check(&tx, &remittance(0, &sender_identity()))
                .await
                .expect_err("zeros are no BEEF");
            assert_eq!(
                (status, body["code"].as_str()),
                (400, Some("ERR_INVALID_PAYMENT"))
            );
            assert_eq!(
                (&body["offset"], &body["kind"]),
                (&json!(0), &json!("BadVersion"))
            );
            assert!(
                body["description"]
                    .as_str()
                    .unwrap()
                    .ends_with("(BadVersion at offset 0)"),
                "{body}"
            );
        }
    }

    const R2_KEY: &str = "02abc/upload.beef";

    async fn check_at_rest(
        store: &crate::beef_door::tests::MemStore,
        slice_millis: u64,
    ) -> Result<u64, RouteResult> {
        let clock = || 0u64;
        check_delivery_at_rest(
            store,
            R2_KEY,
            &remittance(0, &sender_identity()),
            FEE,
            &sender_identity(),
            &wallet(SERVER_KEY),
            Some(&StubHeaders::honest()),
            &Slices {
                time: Slice {
                    clock: &clock,
                    millis: slice_millis,
                },
                lookups: ROOT_LOOKUPS_PER_PASS,
                inputs: u64::MAX,
                weight: u64::MAX,
                work_units: crate::beef_door::work_units_per_input(),
            },
        )
        .await
    }

    #[tokio::test]
    async fn nl4_an_object_at_rest_over_the_old_door_is_judged_and_not_refused_for_its_size() {
        use crate::beef_door::tests::MemStore;
        assert_eq!(
            check_at_rest(&MemStore::with(R2_KEY, &over_the_old_door(FEE)), u64::MAX).await,
            Ok(FEE)
        );
        assert_eq!(
            refusal_code(
                check_at_rest(
                    &MemStore::with(R2_KEY, &over_the_old_door(FEE - 1)),
                    u64::MAX
                )
                .await
            ),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
        assert_eq!(
            refusal_code(check_at_rest(&MemStore::default(), u64::MAX).await),
            (400, "ERR_BEEF_KEY_NOT_FOUND".to_string())
        );
    }

    #[tokio::test]
    async fn nl4_an_object_at_rest_is_pending_503_until_its_slices_are_done() {
        use crate::beef_door::tests::MemStore;
        let bytes = over_the_old_door(FEE);
        let store = MemStore::with(R2_KEY, &bytes);
        let mut offsets = Vec::new();
        let mut phases = Vec::new();
        let paid = loop {
            match check_at_rest(&store, 0).await {
                Ok(paid) => break paid,
                Err((body, status)) => {
                    assert_eq!(
                        (status, body["code"].as_str()),
                        (503, Some("ERR_PAYMENT_PENDING")),
                        "{body}"
                    );
                    assert_eq!(body["size"], json!(bytes.len()));
                    assert_eq!(body["elements"], json!(offsets.len() % 3 + 1));
                    offsets.push(body["offset"].as_u64().unwrap());
                    phases.push(body["phase"].as_str().unwrap().to_string());
                }
            }
        };
        assert_eq!(paid, FEE);
        // The BUMP, the parent, the subject, read for the structure and
        // then for the scripts (0.4.4); a last pass reads the end.
        assert_eq!(
            phases,
            ["structure"; 3]
                .iter()
                .chain(&["scripts"; 3])
                .cloned()
                .collect::<Vec<_>>()
        );
        for read in offsets.chunks(3) {
            assert!(read.windows(2).all(|w| w[0] < w[1]));
            assert_eq!(read[2], bytes.len() as u64);
        }
    }

    // ---- 0.8.9: a payment's bytes held to PAYMENT_BUDGET_BYTES at both doors ----

    const BUDGET: usize = PAYMENT_BUDGET_BYTES as usize;

    /// A valid payment of exactly `bytes` bytes: output 0 pays `satoshis`,
    /// and a second output of ballast nothing spends sets the length.
    fn payment_of_exactly(bytes: usize, satoshis: u64) -> Vec<u8> {
        let probe = 100_000;
        let bare = atomic_beef(&[(satoshis, payer_script()), (0, vec![0x6a; probe])]).len() - probe;
        let payment = atomic_beef(&[(satoshis, payer_script()), (0, vec![0x6a; bytes - bare])]);
        assert_eq!(payment.len(), bytes);
        payment
    }

    fn size_body(size: Option<u64>) -> Value {
        let description = match size {
            Some(size) => format!("Not judged: this payment is {size} bytes, and this host reads at most 1048576 bytes of a payment: a bound of this host, not a rule of the chain, and no verdict on the payment. Pay with other coins. If this payment's size is unconfirmed ancestry, it will be smaller after the next block."),
            None => "Not judged: this payment is more than 1048576 bytes, the most this host reads of a payment: a bound of this host, not a rule of the chain, and no verdict on the payment. Pay with other coins. If this payment's size is unconfirmed ancestry, it will be smaller after the next block.".to_string(),
        };
        let mut body = json!({
            "status": "error",
            "code": "ERR_PAYMENT_SIZE",
            "resource": "Size",
            "budget": 1_048_576,
            "description": description,
        });
        if let Some(size) = size {
            body["size"] = json!(size);
        }
        body
    }

    #[test]
    fn the_payment_budget_is_one_mebibyte() {
        assert_eq!(PAYMENT_BUDGET_BYTES, 1_048_576);
    }

    #[test]
    fn the_size_refusal_is_413_with_the_pinned_sentence() {
        let (body, status) = payment_size_refusal(Some(1_048_577));
        assert_eq!(status, 413);
        assert_eq!(body, size_body(Some(1_048_577)));
        assert_eq!(
            body["description"],
            "Not judged: this payment is 1048577 bytes, and this host reads at most 1048576 bytes of a payment: a bound of this host, not a rule of the chain, and no verdict on the payment. Pay with other coins. If this payment's size is unconfirmed ancestry, it will be smaller after the next block."
        );
        let (body, status) = payment_size_refusal(None);
        assert_eq!(status, 413);
        assert_eq!(body, size_body(None));
        assert!(body.get("size").is_none(), "{body}");
    }

    #[test]
    fn a_size_refusal_leaves_one_audit_line() {
        let sender = "02".to_string() + &"11".repeat(32);
        let (body, _) = payment_size_refusal(Some(1_048_577));
        assert_eq!(
            not_judged_line(&body, &sender),
            Some(format!(
                "AUDIT payment.not_judged code=ERR_PAYMENT_SIZE resource=Size size=1048577 budget=1048576 sender={sender}"
            ))
        );
        let (body, _) = payment_size_refusal(None);
        assert_eq!(
            not_judged_line(&body, &sender),
            Some(format!(
                "AUDIT payment.not_judged code=ERR_PAYMENT_SIZE resource=Size size=none budget=1048576 sender={sender}"
            ))
        );
    }

    #[test]
    fn the_inline_size_is_read_from_the_encodings_length_in_every_shape() {
        for bytes in [0usize, 1, 2, 3, 4, 5, 1_000] {
            for tx in shapes(&vec![7u8; bytes]) {
                assert_eq!(sent_payment_bytes(&tx), Some(bytes as u64), "{tx}");
            }
        }
        assert_eq!(sent_payment_bytes(&json!(false)), None);
        assert_eq!(sent_payment_bytes(&json!({ "other": "AA==" })), None);
    }

    #[tokio::test]
    async fn an_inline_payment_of_exactly_the_budget_is_judged_as_before_in_every_shape() {
        let output = remittance(0, &sender_identity());
        for tx in shapes(&payment_of_exactly(BUDGET, FEE)) {
            assert_eq!(sent_payment_bytes(&tx), Some(PAYMENT_BUDGET_BYTES));
            assert_eq!(check_payment_size(&tx), Ok(()));
            assert_eq!(check(&tx, &output).await, Ok(FEE));
        }
        for tx in shapes(&payment_of_exactly(BUDGET, FEE - 1)) {
            assert_eq!(check_payment_size(&tx), Ok(()));
            assert_eq!(
                refusal_code(check(&tx, &output).await),
                (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
            );
        }
    }

    #[tokio::test]
    async fn an_inline_payment_one_byte_over_the_budget_is_refused_413_in_every_shape() {
        let over = Some(PAYMENT_BUDGET_BYTES + 1);
        for tx in shapes(&vec![0u8; BUDGET + 1]) {
            assert_eq!(
                check_payment_size(&tx),
                Err((size_body(over), 413)),
                "{}",
                &tx.to_string()[..16]
            );
            // The door that keeps a payment unjudged answers the same.
            assert_eq!(
                check_unjudged(&json!({ "tx": tx })).await,
                Err((size_body(over), 413))
            );
        }
        // Refused from the length alone: none of these is decoded, and each
        // would be refused as no payment if it were.
        for tx in [
            json!("zz".repeat(BUDGET + 1)),
            json!(vec![999u32; BUDGET + 1]),
            json!({ "beef": "!".repeat((BUDGET + 1) / 3 * 4 + 4) }),
        ] {
            let (body, status) = check_payment_size(&tx).expect_err("over the budget");
            assert_eq!((status, &body["code"]), (413, &json!("ERR_PAYMENT_SIZE")));
        }
    }

    /// A store whose objects have a stamp and nothing else: a door that loads
    /// a state or opens a reader on it is counted, and gets no byte.
    #[derive(Default)]
    struct Sealed {
        size: u64,
        loads: std::cell::Cell<u32>,
        opens: std::cell::Cell<u32>,
        saves: std::cell::Cell<u32>,
    }

    #[async_trait::async_trait(?Send)]
    impl BeefStore for Sealed {
        async fn stamp(&self, _key: &str) -> Result<Option<crate::beef_door::Stamp>, String> {
            Ok(Some(crate::beef_door::Stamp {
                size: self.size,
                etag: "v1".to_string(),
            }))
        }
        async fn open(
            &self,
            _key: &str,
            _from: u64,
            _stamp: &crate::beef_door::Stamp,
        ) -> Result<Box<dyn crate::beef_door::Chunks>, String> {
            self.opens.set(self.opens.get() + 1);
            Err("sealed".to_string())
        }
        async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
            self.loads.set(self.loads.get() + 1);
            Ok(None)
        }
        async fn save(&self, _key: &str, _state: Vec<u8>) -> Result<(), String> {
            self.saves.set(self.saves.get() + 1);
            Ok(())
        }
        async fn clear(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }
    }

    /// The route's door on an upload (`judge_payment_at_rest`), in one pass.
    async fn door_at_rest(store: &dyn BeefStore) -> Result<u64, RouteResult> {
        let clock = || 0u64;
        judge_payment_at_rest(
            store,
            R2_KEY,
            &remittance(0, &sender_identity()),
            FEE,
            &sender_identity(),
            &wallet(SERVER_KEY),
            Some(&StubHeaders::honest()),
            &Slices {
                time: Slice {
                    clock: &clock,
                    millis: u64::MAX,
                },
                lookups: ROOT_LOOKUPS_PER_PASS,
                inputs: u64::MAX,
                weight: u64::MAX,
                work_units: crate::beef_door::work_units_per_input(),
            },
        )
        .await
        .map(|judged| judged.satoshis)
    }

    #[tokio::test]
    async fn an_upload_of_exactly_the_budget_is_judged_as_before() {
        use crate::beef_door::tests::MemStore;
        let paid = MemStore::with(R2_KEY, &payment_of_exactly(BUDGET, FEE));
        assert_eq!(door_at_rest(&paid).await, Ok(FEE));
        let under = MemStore::with(R2_KEY, &payment_of_exactly(BUDGET, FEE - 1));
        assert_eq!(
            refusal_code(door_at_rest(&under).await),
            (400, "ERR_INSUFFICIENT_PAYMENT".to_string())
        );
        assert_eq!(
            refusal_code(door_at_rest(&MemStore::default()).await),
            (400, "ERR_BEEF_KEY_NOT_FOUND".to_string())
        );
    }

    #[tokio::test]
    async fn an_upload_one_byte_over_the_budget_is_refused_from_its_stored_length() {
        let sealed = Sealed {
            size: PAYMENT_BUDGET_BYTES + 1,
            ..Sealed::default()
        };
        assert_eq!(
            door_at_rest(&sealed).await,
            Err((size_body(Some(PAYMENT_BUDGET_BYTES + 1)), 413))
        );
        // No state was loaded or saved, and no reader was constructed.
        assert_eq!(
            (sealed.loads.get(), sealed.opens.get(), sealed.saves.get()),
            (0, 0, 0)
        );
        // At the budget the same store is read.
        let at = Sealed {
            size: PAYMENT_BUDGET_BYTES,
            ..Sealed::default()
        };
        let _ = door_at_rest(&at).await;
        assert!(at.opens.get() > 0, "a payment at the budget is read");
        // The same sender presents another payment at once, and it is read.
        let paid =
            crate::beef_door::tests::MemStore::with(R2_KEY, &payment_of_exactly(BUDGET, FEE));
        assert_eq!(door_at_rest(&paid).await, Ok(FEE));
    }

    #[tokio::test]
    async fn an_unjudged_upload_is_held_to_the_budget_by_its_stored_length() {
        let over = Sealed {
            size: PAYMENT_BUDGET_BYTES + 1,
            ..Sealed::default()
        };
        assert_eq!(
            check_unjudged_at_rest(&over, R2_KEY).await,
            Err((size_body(Some(PAYMENT_BUDGET_BYTES + 1)), 413))
        );
        assert_eq!((over.loads.get(), over.opens.get()), (0, 0));
        let at = Sealed {
            size: PAYMENT_BUDGET_BYTES,
            ..Sealed::default()
        };
        assert_eq!(
            check_unjudged_at_rest(&at, R2_KEY).await,
            Ok(Some(crate::beef_door::Stamp {
                size: PAYMENT_BUDGET_BYTES,
                etag: "v1".to_string(),
            }))
        );
        assert_eq!(
            refusal_code(
                check_unjudged_at_rest(&crate::beef_door::tests::MemStore::default(), R2_KEY)
                    .await
                    .map(|_| 0)
            ),
            (400, "ERR_BEEF_KEY_NOT_FOUND".to_string())
        );
    }

    // ---- M3: a body no delivery fee judges ----

    #[tokio::test]
    async fn an_unjudged_body_is_read_for_its_structure_and_held_to_its_row() {
        let good = atomic_beef(&[(FEE, payer_script())]);
        let tx = |tx: Value| json!({ "tx": tx });
        assert_eq!(check_unjudged(&tx(json!(hex::encode(&good)))).await, Ok(()));
        // Bytes that are no BEEF are refused naming them.
        let (body, status) = check_unjudged(&tx(json!("00010203"))).await.unwrap_err();
        assert_eq!(
            (status, &body["code"]),
            (400, &json!("ERR_INVALID_PAYMENT"))
        );
        assert_eq!(body["offset"], 0, "{body}");
        // A text longer than a row is refused before a byte is read: 2,000,001
        // bytes of hex is no BEEF either, and the answer is the bound's.
        let long = "00".repeat(1_000_000) + "0";
        let (body, status) = check_unjudged(&tx(json!(long + "0"))).await.unwrap_err();
        assert_eq!(
            (status, &body["code"]),
            (413, &json!("ERR_BODY_TOO_LARGE")),
            "{body}"
        );
        let at_bound = "00".repeat(999_999);
        let (_, status) = check_unjudged(&json!(at_bound)).await.unwrap_err();
        assert_eq!(
            status, 400,
            "within the bound the bytes are read, and refused as bytes"
        );
    }

    /// A memory decline names the relay's own budget, `STACK_MEMORY_BYTES`,
    /// for every resource and whatever limit the evaluator reported, and
    /// keeps the resource and the fields from the sender's bytes.
    #[test]
    fn a_memory_decline_names_the_relays_own_budget() {
        for resource in [
            ScriptResource::Stack,
            ScriptResource::AltStack,
            ScriptResource::ElementSize,
        ] {
            for reported in [STACK_MEMORY_BYTES as u64, 4_096] {
                let verdict = PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
                    offset: 77,
                    txid: "ab".repeat(32),
                    input: Some(0),
                    why: SpendRefusal::Resource(bsv_rs::script::ScriptResourceLimit {
                        resource,
                        limit: reported,
                        attempted: 1_200_000,
                        work_spent: None,
                    }),
                });
                let (body, status) = delivery_answer(verdict).expect_err("a memory decline");
                assert_eq!(status, 422, "{body}");
                assert_eq!(body["code"], "ERR_PAYMENT_MEMORY", "{body}");
                assert_eq!(body["resource"], format!("{resource:?}"), "{body}");
                assert_eq!(
                    body["budget"].as_u64(),
                    Some(STACK_MEMORY_BYTES as u64),
                    "{body}"
                );
                assert_eq!(body["attempted"], 1_200_000, "{body}");
                assert_eq!(body["input"], 0, "{body}");
                assert_eq!(body["offset"], 77, "{body}");
                assert_eq!(body["txid"], "ab".repeat(32), "{body}");
                assert_eq!(
                    body["description"],
                    memory_description(&"ab".repeat(32), Some(0)),
                    "{body}"
                );
            }
        }
    }

    /// A memory decline reads "not judged": a host's bound, not a rule of the
    /// chain, the transaction and input whose script was declined memory, and
    /// the way out, the free one first; no word of it reads as a verdict on
    /// the payment.
    #[test]
    fn a_memory_decline_reads_not_judged_and_gives_the_way_out() {
        let txid = "cd".repeat(32);
        let text = memory_description(&txid, Some(3));
        assert_eq!(
            text,
            format!(
                "Not judged: this host declined memory for the script of input 3 of transaction {txid}, an unproven transaction in this payment's BEEF (the payment itself or one of its ancestors). This host's memory bound is 1000000 bytes per stack: a bound of this host, not a rule of the chain, and no verdict on the payment. Present this payment again once transaction {txid} has its proof, or pay with other coins."
            )
        );
        assert_eq!(
            memory_description(&txid, None),
            format!(
                "Not judged: this host declined memory for a script of transaction {txid}, an unproven transaction in this payment's BEEF (the payment itself or one of its ancestors). This host's memory bound is 1000000 bytes per stack: a bound of this host, not a rule of the chain, and no verdict on the payment. Present this payment again once transaction {txid} has its proof, or pay with other coins."
            )
        );
        let lower = text.to_lowercase();
        for word in ["invalid", "bad", "malformed", "rejected"] {
            assert!(!lower.contains(word), "{word}: {text}");
        }
    }

    /// One `AUDIT payment.not_judged` line for each memory or work decline,
    /// with the code, the resource, the transaction and input whose script
    /// the bound stopped, and the sender's public identity key; none for any
    /// other answer.
    #[test]
    fn a_decline_not_judged_leaves_one_audit_line() {
        let sender = "02".to_string() + &"11".repeat(32);
        let txid = "ab".repeat(32);
        let memory = PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
            offset: 77,
            txid: txid.clone(),
            input: Some(1),
            why: SpendRefusal::Resource(bsv_rs::script::ScriptResourceLimit {
                resource: ScriptResource::Stack,
                limit: STACK_MEMORY_BYTES as u64,
                attempted: 1_200_000,
                work_spent: None,
            }),
        });
        let (body, _) = delivery_answer(memory).expect_err("a memory decline");
        assert_eq!(
            not_judged_line(&body, &sender).as_deref(),
            Some(
                format!(
                    "AUDIT payment.not_judged code=ERR_PAYMENT_MEMORY resource=Stack txid={txid} input=1 sender={sender}"
                )
                .as_str()
            )
        );
        let work = PaymentVerdict::Unverifiable(UnverifiableReason::SpendRefused {
            offset: 77,
            txid: txid.clone(),
            input: Some(0),
            why: SpendRefusal::Resource(bsv_rs::script::ScriptResourceLimit {
                resource: ScriptResource::Work,
                limit: 10,
                attempted: 11,
                work_spent: Some(10),
            }),
        });
        let (body, _) = delivery_answer(work).expect_err("a work decline");
        assert_eq!(
            not_judged_line(&body, &sender).as_deref(),
            Some(
                format!(
                    "AUDIT payment.not_judged code=ERR_PAYMENT_WORK resource=Work txid={txid} input=0 sender={sender}"
                )
                .as_str()
            )
        );
        let (body, _) = invalid("Payment must contain a valid Atomic BEEF.");
        assert_eq!(not_judged_line(&body, &sender), None);
    }

    #[test]
    fn route_no_fee_recipients() {
        let outputs: Vec<Value> = vec![];
        let recipients: Vec<&str> = vec![];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.is_empty());
    }
}
