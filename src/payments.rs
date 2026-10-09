// Payment processing — server delivery fee internalization + per-recipient output routing.
// 1:1 parity with Node.js message-box-server sendMessage.ts payment logic.

use std::collections::{HashMap, HashSet};

use bsv_middleware_cloudflare::WorkerStorageClient;
use bsv_middleware_rs::{
    brc29_locking_script, header_service_url, HeaderLookupError, HeaderService, PaymentVerdict,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::ProtoWallet;
use serde_json::{json, Value};
use worker::Env;

use crate::beef_door::{
    verify_at_rest, verify_inline, AtRest, BeefStore, Carrier, DoorError, DoorVerdict, Pending,
    Slice, Slices, Terms, ROOT_LOOKUPS_PER_PASS, VERIFY_SLICE_MILLIS,
};

use crate::handoff::{
    drain_fees, hand_off, reclaim_released, FeeWallet, HandedOff, Paid, Seams, DRAIN_BATCH,
    RECLAIM_BATCH,
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
/// No payment is refused for its size or its counts (0.4.0): the BEEF is read
/// as a stream, one element in hand (`beef_door`), and a refusal names the
/// offset and the kind of the bytes that are wrong. The delivery output is
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
        let judged = match r2_key {
            Some(key) => {
                let store = crate::beef_upload::R2Store::new(env);
                let clock = || worker::Date::now().as_millis();
                let slices = Slices {
                    time: Slice {
                        clock: &clock,
                        millis: VERIFY_SLICE_MILLIS,
                    },
                    lookups: ROOT_LOOKUPS_PER_PASS,
                };
                judge_delivery_at_rest(
                    &store,
                    key,
                    server_output,
                    due,
                    sender_key,
                    &server_wallet,
                    headers,
                    &slices,
                )
                .await?
            }
            None => {
                let tx = payment.get("tx").ok_or_else(missing_tx)?;
                judge_delivery_output(tx, server_output, due, sender_key, &server_wallet, headers)
                    .await?
            }
        };
        Some((server_output, judged))
    } else {
        None
    };

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

    // The hand-off (`handoff`). The verdict is in.
    let blobs = crate::beef_upload::R2Store::new(env);
    let wallet = WalletInfra { env };
    let db = env
        .d1("DB")
        .map_err(|e| err(503, "ERR_D1_UNAVAILABLE", &format!("D1 binding: {}", e)))?;
    let ledger = crate::storage::D1Ledger { db: &db };
    let rows = crate::storage::D1Rows { db: &db };
    // The reader every object of the payment names: the relay, the recipient
    // of the delivery fee (`handoff::READER_METADATA`).
    let reader = server_private_key(env)
        .map(|key| key.public_key().to_hex())
        .map_err(|e| err(500, "ERR_INTERNAL", &e))?;
    let spool_key = crate::beef_upload::build_upload_key(
        sender_key,
        &uuid::Uuid::new_v4().simple().to_string(),
    );
    let handed = hand_off(
        &Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
        },
        &Paid {
            payment,
            r2_key,
            spool_key: &spool_key,
            server_output: judged.as_ref().map(|(output, _)| *output),
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

/// `check_delivery_at_rest`, with the subject's txid beside the satoshis.
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
    let (output_index, prefix, suffix) = delivery_remittance(server_output, sender_key)?;
    let expected_script = delivery_script(server_wallet, prefix, suffix, sender_key)?;
    let terms = Terms {
        output_index,
        expected_script: &expected_script,
        required_satoshis: delivery_fee,
    };
    match verify_at_rest(store, key, &terms, header_service, slices)
        .await
        .map_err(door_error)?
    {
        AtRest::Done(verdict) => door_judged(verdict),
        AtRest::Pending(pending) => Err(pending_answer(&pending)),
        AtRest::NotFound => Err(err(
            400,
            "ERR_BEEF_KEY_NOT_FOUND",
            "Could not fetch BEEF from R2: R2 object not found",
        )),
    }
}

/// A verification that one request did not finish: 503, so a client that
/// retries a 503 continues it, with the place the reading has come to.
fn pending_answer(pending: &Pending) -> RouteResult {
    let description = if pending.roots > 0 {
        format!(
            "The payment's BEEF is read ({} elements, {} bytes); {} of its {} merkle roots are checked. Send the same request again to continue.",
            pending.elements, pending.size, pending.roots_asked, pending.roots
        )
    } else {
        format!(
            "The payment's BEEF is being verified: {} elements and {} of {} bytes read. Send the same request again to continue.",
            pending.elements, pending.offset, pending.size
        )
    };
    (
        json!({
            "status": "error",
            "code": "ERR_PAYMENT_PENDING",
            "description": description,
            "elements": pending.elements,
            "offset": pending.offset,
            "size": pending.size,
            "rootsChecked": pending.roots_asked,
            "roots": pending.roots,
        }),
        503,
    )
}

/// The door's verdict to the route's answer: `delivery_answer` on the word,
/// and a refusal of the bytes carries the offset and the kind it names, in
/// the text and as fields.
pub fn door_answer(verdict: DoorVerdict) -> Result<u64, RouteResult> {
    let DoorVerdict { word, named, .. } = verdict;
    delivery_answer(word).map_err(|(mut body, status)| {
        if let Some(named) = named {
            let text = body["description"].as_str().unwrap_or_default();
            body["description"] = json!(format!(
                "{} ({} at offset {})",
                text, named.kind, named.offset
            ));
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
    Ok(Judged { satoshis, txid })
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
    let seams = Seams {
        blobs: &blobs,
        wallet: &wallet,
        ledger: &ledger,
        rows: &rows,
    };
    let now = worker::Date::now().as_millis() / 1000;
    match drain_fees(&seams, now, DRAIN_BATCH).await {
        Ok(drained) if drained == Default::default() => {}
        Ok(drained) => worker::console_log!(
            "AUDIT fee.drain settled={} put_off={} held={}",
            drained.settled,
            drained.put_off,
            drained.held
        ),
        Err(e) => worker::console_error!("AUDIT fee.drain FAILED: {e}"),
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
    };
    crate::handoff::forget_unnamed(&seams, rows_naming, handed, r2_key, failed).await;
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
    /// a transaction the BEEF does not carry (its proof vouches for it): a
    /// transaction with no input is invalid bytes to bsv-rs 0.4.1's reader.
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

    // ---- NL-4: no door by size or count (0.3.31: 413 ERR_BODY_TOO_LARGE) ----

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
                    assert_eq!(body["elements"], json!(offsets.len() + 1));
                    offsets.push(body["offset"].as_u64().unwrap());
                }
            }
        };
        assert_eq!(paid, FEE);
        // The BUMP, the parent, the subject; a last pass reads the end.
        assert_eq!(offsets.len(), 3);
        assert!(offsets.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(offsets[2], bytes.len() as u64);
    }

    #[test]
    fn route_no_fee_recipients() {
        let outputs: Vec<Value> = vec![];
        let recipients: Vec<&str> = vec![];
        let result = route_outputs_to_recipients(&outputs, &recipients).unwrap();
        assert!(result.is_empty());
    }
}
