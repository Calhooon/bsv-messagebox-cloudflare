//! The hand-off after the door's verdict (NL-4b): what the relay does with a
//! payment once it is `Verified`, behind seams a host test can stand in for.
//!
//! Three things happen to a verified payment: the server's delivery fee is
//! recorded in wallet-infra (`FeeWallet`), each fee-bearing recipient's row
//! stores the payment (`stored_body`), and the bytes of its BEEF live
//! somewhere (`PaymentStore`, the R2 bucket in the Worker). `FeeLedger` is the
//! table of fees whose recording is still owed.
//!
//! The bytes stay at rest. An object the sender uploaded stays at its key; an
//! inline payment is spooled, a chunk at a time, to a key of the same shape.
//! A recipient's row carries the key, the verdict and the subject's txid, and
//! never the BEEF (`payment_at_rest`); a reader of the row streams the bytes
//! back from the store (`serve_body`), or hands out a URL to them.
//!
//! The fee is recorded in the request when the BEEF fits the one JSON-RPC
//! argument wallet-infra takes (`INTERNALIZE_INLINE_BYTES`), as before.
//! Otherwise, and whenever wallet-infra cannot answer, it is deferred: a row
//! of the ledger, drained later (`drain_fees`), retried with a backoff, never
//! dropped. The message is stored and delivered on the verdict either way.
//! Nothing here answers a size or a count: a deferred fee is no error to the
//! sender.

use std::borrow::Cow;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::beef_door::{BeefStore, Carrier, Chunks, Stamp};

type RouteResult = (Value, u16);

pub use crate::storage::{INSERT_MESSAGE_SQL, LIST_MESSAGES_SQL};

/// The statements of object ownership and the two acknowledge statements, as
/// the route runs them: a host test runs the same text on a real SQLite.
pub use crate::retention::{ack_delete_sql, ack_update_sql};
pub use crate::storage::{
    FEE_OWES_KEY_SQL, FORGET_RELEASED_SQL, RELEASED_KEYS_SQL, ROW_NAMES_KEY_SQL,
};

/// The object store of the door, and a way to put a payment's bytes there.
#[async_trait::async_trait(?Send)]
pub trait PaymentStore: BeefStore {
    /// Write the `size` bytes `chunks` yields at `key`, a chunk at a time,
    /// and answer the stamp of what is now at rest there.
    async fn spool(&self, key: &str, chunks: &mut dyn Chunks, size: u64) -> Result<Stamp, String>;
}

/// wallet-infra, as the relay asks it to record the server's delivery fee:
/// BRC-100 `internalizeAction` with `tx` and `args` (`fee_args`). `Ok(false)`
/// is the wallet's refusal of the payment; `Err` is a wallet that could not
/// answer.
#[async_trait::async_trait(?Send)]
pub trait FeeWallet {
    async fn internalize(&self, tx: &Value, args: &Value) -> Result<bool, String>;
}

/// A delivery fee whose recording in wallet-infra is still owed: the object
/// that holds the payment's BEEF, the subject's txid, and what
/// `internalizeAction` is asked beside the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredFee {
    pub key: String,
    /// The etag of the object the door verified: another upload at the key
    /// is not this payment.
    pub etag: String,
    pub txid: String,
    /// `fee_args`, as JSON text.
    pub args: String,
    /// Whether a recipient's row of the same send named the object too: what
    /// was so at the deferral, kept for the operator's reading. The drain
    /// does not delete by it; it asks the rows (`reclaim`).
    pub named: bool,
    pub attempts: u32,
    /// Unix seconds: not before.
    pub next_at: u64,
}

/// The table of deferred fees.
#[async_trait::async_trait(?Send)]
pub trait FeeLedger {
    /// Record a fee as owed. A fee already recorded at the key is left as it
    /// is: the same request sent again defers nothing twice.
    async fn defer(&self, fee: &DeferredFee) -> Result<(), String>;
    /// The fees due at `now`, the longest waiting leading, at most `limit`.
    async fn due(&self, now: u64, limit: u32) -> Result<Vec<DeferredFee>, String>;
    /// The fee at `key` is recorded in wallet-infra: its row goes.
    async fn settle(&self, key: &str) -> Result<(), String>;
    /// The fee at `key` could not be recorded this time: it stays, to be
    /// tried again at `next_at`.
    async fn put_off(
        &self,
        key: &str,
        attempts: u32,
        next_at: u64,
        why: &str,
    ) -> Result<(), String>;
    /// Whether a deferred fee names the object at `key`.
    async fn owes(&self, key: &str) -> Result<bool, String>;
}

/// The stored rows, as what names an object at rest (NL-4c). A row names the
/// object its payment rests in (`beef_key`, written with the row); the
/// reference is released when the row is deleted or its message retired, and
/// the store says so itself (`released`: the keys rows have let go of).
#[async_trait::async_trait(?Send)]
pub trait RowRefs {
    /// Whether a stored row that is not retired names the object at `key`.
    async fn names(&self, key: &str) -> Result<bool, String>;
    /// Keys a row has let go of and nobody has looked at since, at most
    /// `limit`.
    async fn released(&self, limit: u32) -> Result<Vec<String>, String>;
    /// The released key was looked at.
    async fn forget(&self, key: &str) -> Result<(), String>;
}

/// What the hand-off works through.
pub struct Seams<'a> {
    pub blobs: &'a dyn PaymentStore,
    pub wallet: &'a dyn FeeWallet,
    pub ledger: &'a dyn FeeLedger,
    pub rows: &'a dyn RowRefs,
}

/// A verified payment as the route hands it on.
pub struct Paid<'a> {
    /// The request's `payment`.
    pub payment: &'a Value,
    /// The object `payment.beefR2Key` names, when the sender uploaded one.
    pub r2_key: Option<&'a str>,
    /// Where an inline payment's bytes are put at rest: a key of the upload
    /// shape, `<sender's identity key>/<uuid>.beef`, that nothing presigned.
    pub spool_key: &'a str,
    /// The server's delivery output, when the box owes a delivery fee.
    pub server_output: Option<&'a Value>,
    /// The subject's txid, when the door judged the payment (a box with no
    /// delivery fee judges nothing).
    pub txid: Option<&'a str>,
    /// Whether a recipient's row will carry the payment.
    pub rows: bool,
    /// Unix seconds.
    pub now: u64,
}

/// What became of the server's delivery fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fee {
    /// The box owes none.
    NotOwed,
    /// wallet-infra recorded it in this request.
    Internalized,
    /// It is owed: a row of the ledger, drained later.
    Deferred,
}

/// The hand-off's result.
#[derive(Debug, Clone, PartialEq)]
pub struct HandedOff {
    /// The payment as a recipient's row stores it (`stored_body` adds that
    /// recipient's outputs).
    pub payment: Value,
    pub fee: Fee,
    /// The object that must stay at rest: a row or a deferred fee names it.
    pub kept: Option<String>,
}

fn err(status: u16, code: &str, description: &str) -> RouteResult {
    (
        json!({ "status": "error", "code": code, "description": description }),
        status,
    )
}

/// What `internalizeAction` is asked beside the bytes: the delivery output
/// with its remittance, and the payment's description and labels.
pub fn fee_args(server_output: &Value, payment: &Value) -> Value {
    json!({
        "outputs": [server_output],
        "description": payment.get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("MessageBox delivery payment"),
        "labels": payment.get("labels").unwrap_or(&json!([])),
    })
}

/// A recipient's row: `{"message": ..}`, and beside it the payment with that
/// recipient's outputs when the recipient is paid.
pub fn stored_body(message: &Value, payment: Option<(&Value, &Value)>) -> String {
    match payment {
        Some((payment, outputs)) => {
            let mut payment = payment.clone();
            if let Some(obj) = payment.as_object_mut() {
                obj.insert("outputs".to_string(), outputs.clone());
            }
            json!({ "message": message, "payment": payment }).to_string()
        }
        None => json!({ "message": message }).to_string(),
    }
}

/// The shape `payment.tx` arrived in, kept in the row so a reader hands the
/// bytes back as the sender sent them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxShape {
    Array,
    Hex,
    Base64,
}

impl TxShape {
    fn of(carrier: &Carrier<'_>) -> Self {
        match carrier {
            Carrier::Array(_) => TxShape::Array,
            Carrier::Hex(_) => TxShape::Hex,
            Carrier::Base64(_) => TxShape::Base64,
        }
    }

    fn name(self) -> &'static str {
        match self {
            TxShape::Array => "array",
            TxShape::Hex => "hex",
            TxShape::Base64 => "base64",
        }
    }

    fn named(name: &str) -> Option<Self> {
        [TxShape::Array, TxShape::Hex, TxShape::Base64]
            .into_iter()
            .find(|shape| shape.name() == name)
    }
}

/// The fields of a stored payment that are the relay's to write. A request
/// that carries one of them does not put it in a row.
const ROW_FIELDS: [&str; 7] = [
    "tx",
    "beefR2Key",
    "beefSize",
    "beefEtag",
    "txShape",
    "verdict",
    "txid",
];

/// The payment as a recipient's row stores it: the request's `payment`
/// without its `tx`, and in its place where the bytes rest (`beefR2Key`,
/// `beefSize`, `beefEtag`), the shape they arrived in (`txShape`), the door's
/// word (`verdict`: `verified`, or `notJudged` on a box that owes no delivery
/// fee) and the subject's `txid` when the door named it.
pub fn payment_at_rest(
    payment: &Value,
    key: &str,
    stamp: &Stamp,
    shape: TxShape,
    txid: Option<&str>,
) -> Value {
    let mut row: serde_json::Map<String, Value> = payment
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| !ROW_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    row.insert("beefR2Key".into(), json!(key));
    row.insert("beefSize".into(), json!(stamp.size));
    row.insert("beefEtag".into(), json!(stamp.etag));
    row.insert("txShape".into(), json!(shape.name()));
    row.insert(
        "verdict".into(),
        json!(if txid.is_some() {
            "verified"
        } else {
            "notJudged"
        }),
    );
    if let Some(txid) = txid {
        row.insert("txid".into(), json!(txid));
    }
    Value::Object(row)
}

/// An object's bytes, as `payment.tx` in `shape`: read as a stream, a chunk
/// encoded at a time. The caller has decided the object fits what it is
/// building.
async fn tx_from_rest(
    blobs: &dyn BeefStore,
    key: &str,
    stamp: &Stamp,
    shape: TxShape,
) -> Result<Value, String> {
    let mut chunks = blobs.open(key, 0, stamp).await?;
    Ok(match shape {
        TxShape::Array => {
            let mut bytes = Vec::with_capacity(stamp.size as usize);
            while let Some(chunk) = chunks.next().await? {
                bytes.extend(chunk.into_iter().map(Value::from));
            }
            Value::Array(bytes)
        }
        TxShape::Hex => {
            let mut text = String::with_capacity(stamp.size as usize * 2);
            while let Some(chunk) = chunks.next().await? {
                text.push_str(&hex::encode(chunk));
            }
            Value::String(text)
        }
        TxShape::Base64 => {
            // Whole groups of three bytes are encoded as they arrive; what
            // is left over waits for the next chunk.
            let mut text = String::with_capacity(stamp.size as usize / 3 * 4 + 4);
            let mut held: Vec<u8> = Vec::new();
            while let Some(chunk) = chunks.next().await? {
                held.extend_from_slice(&chunk);
                let whole = held.len() / 3 * 3;
                B64.encode_string(&held[..whole], &mut text);
                held.drain(..whole);
            }
            B64.encode_string(&held, &mut text);
            json!({ "beef": text })
        }
    })
}

fn beef_key_not_found(e: String) -> RouteResult {
    err(
        400,
        "ERR_BEEF_KEY_NOT_FOUND",
        &format!("Could not fetch BEEF from R2: {}", e),
    )
}

/// The store could not take or give the bytes: the server's side, and the
/// same request again is safe.
fn store_unavailable(e: String) -> RouteResult {
    err(
        503,
        "ERR_PAYMENT_UNAVAILABLE",
        &format!("The payment's BEEF could not be put at rest: {}", e),
    )
}

/// The largest BEEF whose fee is recorded in the request: what one request
/// hands wallet-infra as one JSON-RPC argument beside its own body. A larger
/// payment's fee is deferred, not refused. A way of recording, never a word
/// to the sender.
pub const INTERNALIZE_INLINE_BYTES: u64 = 1024 * 1024;

/// The largest BEEF the drain hands wallet-infra as one argument. The drain
/// has an isolate to itself, and `internalizeAction` takes the bytes as one
/// JSON value: about four thirds of them as base64, held again as the
/// request's body. A fee over this is held in the ledger (never dropped,
/// never tried) until wallet-infra takes a reference to the bytes at rest.
pub const DRAIN_INLINE_BYTES: u64 = 8 * 1024 * 1024;

/// The fees one drain takes up.
pub const DRAIN_BATCH: u32 = 10;

/// How long a fee that could not be recorded waits before its next try: a
/// minute, doubling with each attempt, a day at most.
pub fn backoff_secs(attempts: u32) -> u64 {
    60u64
        .saturating_mul(1u64 << attempts.saturating_sub(1).min(20))
        .min(86_400)
}

/// The hand-off after `Verified`. The bytes stay at rest (an inline payment
/// is spooled when a row or a deferred fee will name it), the row carries
/// the key, and the fee is recorded in wallet-infra here when the BEEF fits
/// one argument and wallet-infra answers, and is deferred otherwise.
pub async fn hand_off(seams: &Seams<'_>, paid: &Paid<'_>) -> Result<HandedOff, RouteResult> {
    // Where the bytes are, and the shape a reader hands them back in.
    let carrier = match paid.r2_key {
        Some(_) => None,
        None => Some(
            paid.payment
                .get("tx")
                .and_then(Carrier::of)
                .ok_or_else(|| {
                    err(
                        400,
                        "ERR_INVALID_PAYMENT",
                        "Payment must contain a valid Atomic BEEF.",
                    )
                })?,
        ),
    };
    let mut rest: Option<(String, Stamp)> = match paid.r2_key {
        Some(key) => Some((
            key.to_string(),
            seams
                .blobs
                .stamp(key)
                .await
                .map_err(beef_key_not_found)?
                .ok_or_else(|| beef_key_not_found("R2 object not found".to_string()))?,
        )),
        None => None,
    };
    let shape = carrier.as_ref().map_or(TxShape::Base64, TxShape::of);
    let size = match (&carrier, &rest) {
        (Some(carrier), _) => carrier.len(),
        (None, Some((_, stamp))) => stamp.size,
        (None, None) => 0,
    };

    // The bytes at rest before anything names them.
    if let (true, Some(carrier)) = (paid.rows, &carrier) {
        let stamp = seams
            .blobs
            .spool(paid.spool_key, &mut carrier.chunks(0), size)
            .await
            .map_err(store_unavailable)?;
        rest = Some((paid.spool_key.to_string(), stamp));
    }

    let mut fee = Fee::NotOwed;
    if let Some(server_output) = paid.server_output {
        let args = fee_args(server_output, paid.payment);
        // Why the fee is not recorded in this request, when it is not.
        let owed: Option<String> = if size > INTERNALIZE_INLINE_BYTES {
            Some("the BEEF is more than one request hands wallet-infra".to_string())
        } else {
            let from_rest = match (&rest, paid.r2_key) {
                (Some((key, stamp)), Some(_)) => {
                    Some(tx_from_rest(seams.blobs, key, stamp, shape).await)
                }
                _ => None,
            };
            match from_rest.as_ref().map(|tx| tx.as_ref()) {
                Some(Err(e)) => Some(format!("the bytes could not be read back: {}", e)),
                tx => {
                    let tx = match tx {
                        Some(Ok(tx)) => tx,
                        _ => &paid.payment["tx"],
                    };
                    match seams.wallet.internalize(tx, &args).await {
                        Ok(true) => None,
                        // wallet-infra's own word on the payment, as before.
                        Ok(false) => {
                            if paid.r2_key.is_none() && rest.is_some() {
                                let _ = seams.blobs.clear(paid.spool_key).await;
                            }
                            return Err(err(
                                400,
                                "ERR_INSUFFICIENT_PAYMENT",
                                "Payment was not accepted by the server.",
                            ));
                        }
                        // A wallet that could not answer says nothing of the
                        // payment: the fee is owed and the message goes.
                        Err(e) => Some(e),
                    }
                }
            }
        };
        fee = match owed {
            None => Fee::Internalized,
            Some(_) => {
                // The deferred fee names the bytes: at rest before it does.
                if let (None, Some(carrier)) = (&rest, &carrier) {
                    let stamp = seams
                        .blobs
                        .spool(paid.spool_key, &mut carrier.chunks(0), size)
                        .await
                        .map_err(store_unavailable)?;
                    rest = Some((paid.spool_key.to_string(), stamp));
                }
                let (key, stamp) = rest.as_ref().ok_or_else(|| {
                    err(
                        500,
                        "ERR_INTERNAL",
                        "A deferred fee names no bytes at rest.",
                    )
                })?;
                seams
                    .ledger
                    .defer(&DeferredFee {
                        key: key.clone(),
                        etag: stamp.etag.clone(),
                        txid: paid.txid.unwrap_or_default().to_string(),
                        args: args.to_string(),
                        named: paid.rows,
                        attempts: 0,
                        next_at: paid.now,
                    })
                    .await
                    .map_err(|e| {
                        err(
                            503,
                            "ERR_PAYMENT_UNAVAILABLE",
                            &format!(
                                "The delivery fee could not be recorded as owed; send the same request again: {}",
                                e
                            ),
                        )
                    })?;
                Fee::Deferred
            }
        };
    }

    let kept = rest.filter(|_| paid.rows || fee == Fee::Deferred);
    let payment = match &kept {
        Some((key, stamp)) if paid.rows => {
            payment_at_rest(paid.payment, key, stamp, shape, paid.txid)
        }
        _ => Value::Null,
    };
    Ok(HandedOff {
        payment,
        fee,
        kept: kept.map(|(key, _)| key),
    })
}

// ---------------------------------------------------------------------------
// Ownership: an object goes only when nothing names it
// ---------------------------------------------------------------------------

/// Delete the object at `key` when no stored row and no deferred fee names
/// it; `true` when it was deleted. A store that cannot say who names the key
/// deletes nothing (`Err`): the object stays. The one way a payment's object
/// is deleted once it is at rest.
pub async fn reclaim(seams: &Seams<'_>, key: &str) -> Result<bool, String> {
    if seams.rows.names(key).await? || seams.ledger.owes(key).await? {
        return Ok(false);
    }
    seams.blobs.clear(key).await?;
    Ok(true)
}

/// The released keys one pass looks at.
pub const RECLAIM_BATCH: u32 = 25;

/// What one reclaim pass came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reclaimed {
    /// Objects deleted: nothing named them.
    pub deleted: u32,
    /// Keys still named by a row or a deferred fee: the object stays.
    pub named: u32,
    /// Keys the store could not answer for: looked at again next pass.
    pub put_off: u32,
}

/// Look at the keys rows have let go of, at most `limit`: an object nothing
/// names is deleted, an object a row or a deferred fee still names stays (the
/// row's own release, or the drain when the fee is recorded, comes back to
/// it). `Err` is a store that could not list the released keys.
pub async fn reclaim_released(seams: &Seams<'_>, limit: u32) -> Result<Reclaimed, String> {
    let mut reclaimed = Reclaimed::default();
    for key in seams.rows.released(limit).await? {
        match reclaim(seams, &key).await {
            Ok(deleted) => {
                seams.rows.forget(&key).await?;
                if deleted {
                    reclaimed.deleted += 1;
                } else {
                    reclaimed.named += 1;
                }
            }
            Err(_) => reclaimed.put_off += 1,
        }
    }
    Ok(reclaimed)
}

/// After a send: delete, best-effort, the payment's object when this send
/// left nothing naming it (no row of it carries the key and no fee waits on
/// it) and nothing else names it either (`reclaim`: a key the sender sends
/// again cannot take the object from a row that names it); `true` when an
/// object was deleted. A send that failed leaves the sender's own upload
/// where it is (the sender may send again); what the relay spooled for that
/// send goes.
pub async fn forget_unnamed(
    seams: &Seams<'_>,
    rows_naming: usize,
    handed: &HandedOff,
    r2_key: Option<&str>,
    failed: bool,
) -> bool {
    if rows_naming > 0 || handed.fee == Fee::Deferred {
        return false;
    }
    let Some(key) = handed.kept.as_deref().or(r2_key) else {
        return false;
    };
    if failed && Some(key) == r2_key {
        return false;
    }
    // What this send knows is not all there is: an earlier send's row, or a
    // fee deferred for one, may name the same key.
    reclaim(seams, key).await.unwrap_or(false)
}

// ---------------------------------------------------------------------------
// The drain
// ---------------------------------------------------------------------------

/// What one drain came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drained {
    /// Fees recorded in wallet-infra; their rows are gone.
    pub settled: u32,
    /// Fees tried and still owed: wallet-infra or the store could not answer.
    pub put_off: u32,
    /// Fees not tried: the bytes are more than one argument carries, or are
    /// no longer the upload the door verified.
    pub held: u32,
}

/// What became of one fee at the drain.
enum Tried {
    Settled,
    PutOff(String),
    Held(String),
}

/// One deferred fee: the bytes read back from the store as a stream, held
/// to the upload the door verified, and handed to wallet-infra.
async fn try_fee(seams: &Seams<'_>, fee: &DeferredFee) -> Tried {
    let stamp = match seams.blobs.stamp(&fee.key).await {
        Ok(Some(stamp)) => stamp,
        Ok(None) => return Tried::Held("the object is not in the store".to_string()),
        Err(e) => return Tried::PutOff(e),
    };
    if stamp.etag != fee.etag {
        return Tried::Held("another upload is at the key".to_string());
    }
    if stamp.size > DRAIN_INLINE_BYTES {
        return Tried::Held(format!(
            "{} bytes are more than one argument to wallet-infra carries",
            stamp.size
        ));
    }
    let Ok(args) = serde_json::from_str::<Value>(&fee.args) else {
        return Tried::Held("the row's arguments do not parse".to_string());
    };
    let tx = match tx_from_rest(seams.blobs, &fee.key, &stamp, TxShape::Base64).await {
        Ok(tx) => tx,
        Err(e) => return Tried::PutOff(e),
    };
    match seams.wallet.internalize(&tx, &args).await {
        Ok(true) => Tried::Settled,
        Ok(false) => Tried::PutOff("wallet-infra did not accept the payment".to_string()),
        Err(e) => Tried::PutOff(e),
    }
}

/// Record the deferred fees that are due at `now`, at most `limit` of them,
/// the longest waiting leading. A fee recorded has its row cleared, and its
/// object deleted when no stored row names it (`reclaim`). A fee that could not be
/// recorded stays, with one more attempt and a later `next_at`; none is
/// dropped. `Err` is a ledger that could not be read.
pub async fn drain_fees(seams: &Seams<'_>, now: u64, limit: u32) -> Result<Drained, String> {
    let mut drained = Drained::default();
    for fee in seams.ledger.due(now, limit).await? {
        let why = match try_fee(seams, &fee).await {
            Tried::Settled => {
                seams.ledger.settle(&fee.key).await?;
                // The fee no longer names the object. It goes when no row
                // does either: asked of the rows now, not read from what the
                // fee's row said when it was deferred.
                let _ = reclaim(seams, &fee.key).await;
                drained.settled += 1;
                continue;
            }
            Tried::PutOff(why) => {
                drained.put_off += 1;
                why
            }
            Tried::Held(why) => {
                drained.held += 1;
                why
            }
        };
        let attempts = fee.attempts.saturating_add(1);
        seams
            .ledger
            .put_off(&fee.key, attempts, now + backoff_secs(attempts), &why)
            .await?;
    }
    Ok(drained)
}

// ---------------------------------------------------------------------------
// The readers of a row
// ---------------------------------------------------------------------------

/// The largest BEEF a list reader hands back inside the row's `payment.tx`:
/// D1's bound on a row, so every payment a row ever carried is still served
/// the way it was. A larger one is served by its key (`/beef/download-url`).
/// A way of serving, never a refusal.
pub const LIST_INLINE_OBJECT_BYTES: u64 = 2_000_000;

/// The BEEF bytes one list response hands back inline. A row past it waits
/// for the next listing; the isolate that builds the response is what this
/// spares.
pub const LIST_INLINE_BYTES: u64 = 32 * 1024 * 1024;

/// What one list response may still hand back inline.
#[derive(Debug, Clone, Copy)]
pub struct ListBudget {
    pub bytes: u64,
}

impl Default for ListBudget {
    fn default() -> Self {
        Self {
            bytes: LIST_INLINE_BYTES,
        }
    }
}

/// A row's body as a reader serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served<'a> {
    /// The body: as stored, or with `payment.tx` read back from the store.
    Body(Cow<'a, str>),
    /// The response has handed back what it may; the row is in the next
    /// listing, whole.
    NextListing,
}

/// The object a row's payment names: the key and the stamp of the bytes the
/// door verified.
pub fn rest_of(payment: &Value) -> Option<(&str, Stamp, TxShape)> {
    let field = |name: &str| payment.get(name);
    Some((
        field("beefR2Key")?.as_str()?,
        Stamp {
            size: field("beefSize")?.as_u64()?,
            etag: field("beefEtag")?.as_str()?.to_string(),
        },
        TxShape::named(field("txShape")?.as_str()?)?,
    ))
}

/// A stored row's body for a list response. A row whose payment names bytes
/// at rest gets them back as `payment.tx`, in the shape the sender sent,
/// streamed from the store, when they are no larger than
/// `LIST_INLINE_OBJECT_BYTES`; a larger payment, or one whose bytes the store
/// could not give (or are no longer the upload the door verified), is served
/// as stored, by its key. Every other body is served as stored, untouched.
pub async fn serve_body<'a>(
    body: &'a str,
    blobs: &dyn BeefStore,
    budget: &mut ListBudget,
) -> Served<'a> {
    let stored = Served::Body(Cow::Borrowed(body));
    if !body.contains("\"beefR2Key\"") {
        return stored;
    }
    let Ok(mut row) = serde_json::from_str::<Value>(body) else {
        return stored;
    };
    let Some((key, stamp, shape)) = row.get("payment").and_then(rest_of) else {
        return stored;
    };
    if stamp.size > LIST_INLINE_OBJECT_BYTES {
        return stored;
    }
    if stamp.size > budget.bytes {
        return Served::NextListing;
    }
    let Ok(tx) = tx_from_rest(blobs, key, &stamp, shape).await else {
        return stored;
    };
    budget.bytes -= stamp.size;
    row["payment"]["tx"] = tx;
    Served::Body(Cow::Owned(row.to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    /// An object store in memory: objects with an etag, and how many times
    /// each was opened.
    #[derive(Default)]
    pub(crate) struct Mem {
        pub(crate) objects: RefCell<HashMap<String, (Vec<u8>, String)>>,
        pub(crate) opened: Cell<usize>,
        pub(crate) down: Cell<bool>,
    }

    impl Mem {
        pub(crate) fn put(&self, key: &str, bytes: &[u8], etag: &str) -> Stamp {
            self.objects
                .borrow_mut()
                .insert(key.to_string(), (bytes.to_vec(), etag.to_string()));
            Stamp {
                size: bytes.len() as u64,
                etag: etag.to_string(),
            }
        }
    }

    struct MemChunks(std::vec::IntoIter<Vec<u8>>);

    #[async_trait::async_trait(?Send)]
    impl Chunks for MemChunks {
        async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.0.next())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl BeefStore for Mem {
        async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
            if self.down.get() {
                return Err("the store is down".to_string());
            }
            Ok(self.objects.borrow().get(key).map(|(bytes, etag)| Stamp {
                size: bytes.len() as u64,
                etag: etag.clone(),
            }))
        }

        async fn open(
            &self,
            key: &str,
            from: u64,
            stamp: &Stamp,
        ) -> Result<Box<dyn Chunks>, String> {
            if self.down.get() {
                return Err("the store is down".to_string());
            }
            let objects = self.objects.borrow();
            let (bytes, etag) = objects.get(key).ok_or("R2 object not found")?;
            if *etag != stamp.etag {
                return Err("the R2 object changed".to_string());
            }
            self.opened.set(self.opened.get() + 1);
            // Chunks of seven bytes: no multiple of three, so the base64
            // reader carries a remainder across every one.
            let chunks: Vec<Vec<u8>> = bytes[from as usize..]
                .chunks(7)
                .map(<[u8]>::to_vec)
                .collect();
            Ok(Box::new(MemChunks(chunks.into_iter())))
        }

        async fn load(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn save(&self, _key: &str, _state: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
        async fn clear(&self, key: &str) -> Result<(), String> {
            self.objects.borrow_mut().remove(key);
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl PaymentStore for Mem {
        async fn spool(
            &self,
            key: &str,
            chunks: &mut dyn Chunks,
            size: u64,
        ) -> Result<Stamp, String> {
            if self.down.get() {
                return Err("the store is down".to_string());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = chunks.next().await? {
                bytes.extend_from_slice(&chunk);
            }
            assert_eq!(bytes.len() as u64, size);
            Ok(self.put(key, &bytes, "spooled"))
        }
    }

    const KEY: &str = "02abc/5b0c1f6e.beef";

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn row(payment: &Value) -> String {
        stored_body(
            &json!("hello"),
            Some((payment, &json!([{ "outputIndex": 1 }]))),
        )
    }

    // ---- the row ----

    #[test]
    fn the_row_carries_the_key_the_verdict_and_the_txid_and_never_the_beef() {
        let request = json!({
            "tx": [1, 2, 3],
            "beefR2Key": "a key the sender named",
            "description": "a paid message",
            "labels": ["l"],
        });
        let stamp = Stamp {
            size: 3,
            etag: "e1".into(),
        };
        let payment = payment_at_rest(
            &request,
            KEY,
            &stamp,
            TxShape::Array,
            Some("ab".repeat(32).as_str()),
        );
        assert_eq!(
            payment,
            json!({
                "description": "a paid message",
                "labels": ["l"],
                "beefR2Key": KEY,
                "beefSize": 3,
                "beefEtag": "e1",
                "txShape": "array",
                "verdict": "verified",
                "txid": "ab".repeat(32),
            })
        );
        // A box that owes no delivery fee judges nothing, and says so; what
        // the sender wrote in the relay's fields is not in the row.
        let claiming = json!({
            "tx": "00", "verdict": "verified", "txid": "ff", "beefEtag": "x", "beefSize": 9,
            "txShape": "array", "description": "d",
        });
        let unjudged = payment_at_rest(&claiming, KEY, &stamp, TxShape::Hex, None);
        assert_eq!(unjudged["verdict"], "notJudged");
        assert_eq!(unjudged["description"], "d");
        assert!(unjudged.get("txid").is_none() && unjudged.get("tx").is_none());
        assert_eq!(rest_of(&unjudged), Some((KEY, stamp, TxShape::Hex)));
    }

    // ---- the readers ----

    async fn served(body: &str, blobs: &Mem, budget: &mut ListBudget) -> Value {
        match serve_body(body, blobs, budget).await {
            Served::Body(body) => serde_json::from_str(&body).unwrap(),
            Served::NextListing => panic!("left for the next listing"),
        }
    }

    #[tokio::test]
    async fn a_reader_hands_the_bytes_back_in_the_shape_they_were_sent_streamed_from_the_store() {
        let beef = bytes(1_000);
        for (shape, tx) in [
            (TxShape::Array, json!(beef)),
            (TxShape::Hex, json!(hex::encode(&beef))),
            (TxShape::Base64, json!({ "beef": B64.encode(&beef) })),
        ] {
            let blobs = Mem::default();
            let stamp = blobs.put(KEY, &beef, "e1");
            let body = row(&payment_at_rest(&json!({}), KEY, &stamp, shape, Some("aa")));
            assert!(body.len() < 400, "the row holds no BEEF: {}", body.len());
            let mut budget = ListBudget::default();
            let row = served(&body, &blobs, &mut budget).await;
            assert_eq!(row["payment"]["tx"], tx, "{shape:?}");
            assert_eq!(row["payment"]["beefR2Key"], KEY, "the key stays beside it");
            assert_eq!(row["payment"]["txid"], "aa");
            assert_eq!(row["message"], "hello");
            assert_eq!(blobs.opened.get(), 1, "one read of the object");
            assert_eq!(budget.bytes, LIST_INLINE_BYTES - 1_000);
        }
    }

    #[tokio::test]
    async fn a_body_that_names_no_bytes_at_rest_is_served_untouched_and_the_store_is_not_asked() {
        let blobs = Mem::default();
        let mut budget = ListBudget::default();
        for body in [
            r#"{"message":"hello"}"#,
            r#"{"message":{"beefR2Key":"02abc/x.beef","beefSize":1,"beefEtag":"e","txShape":"hex"}}"#,
            "not json, \"beefR2Key\" and all",
            "",
        ] {
            assert_eq!(
                serve_body(body, &blobs, &mut budget).await,
                Served::Body(Cow::Borrowed(body))
            );
        }
        assert_eq!(blobs.opened.get(), 0);
    }

    #[tokio::test]
    async fn a_payment_larger_than_a_row_ever_was_is_served_by_its_key() {
        let blobs = Mem::default();
        let stamp = Stamp {
            size: LIST_INLINE_OBJECT_BYTES + 1,
            etag: "e1".into(),
        };
        let body = row(&payment_at_rest(
            &json!({}),
            KEY,
            &stamp,
            TxShape::Base64,
            Some("aa"),
        ));
        let mut budget = ListBudget::default();
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none());
        assert_eq!(row["payment"]["beefR2Key"], KEY);
        assert_eq!(blobs.opened.get(), 0, "never read into the response");
    }

    #[tokio::test]
    async fn bytes_the_store_cannot_give_or_that_are_another_upload_leave_the_row_served_by_its_key(
    ) {
        let beef = bytes(100);
        let blobs = Mem::default();
        let stamp = blobs.put(KEY, &beef, "e1");
        let body = row(&payment_at_rest(
            &json!({}),
            KEY,
            &stamp,
            TxShape::Hex,
            Some("aa"),
        ));
        let mut budget = ListBudget::default();

        // Another upload at the key is not the payment the door verified.
        blobs.put(KEY, &bytes(100), "e2");
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none(), "{row}");

        blobs.put(KEY, &beef, "e1");
        blobs.down.set(true);
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none(), "{row}");
        assert_eq!(row["message"], "hello", "the message is delivered");

        blobs.objects.borrow_mut().clear();
        blobs.down.set(false);
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none(), "{row}");
        assert_eq!(budget.bytes, LIST_INLINE_BYTES, "nothing was handed back");
    }

    #[tokio::test]
    async fn a_response_that_has_handed_back_its_share_leaves_the_next_row_for_the_next_listing() {
        let beef = bytes(600);
        let blobs = Mem::default();
        let stamp = blobs.put(KEY, &beef, "e1");
        let body = row(&payment_at_rest(
            &json!({}),
            KEY,
            &stamp,
            TxShape::Hex,
            None,
        ));
        let mut budget = ListBudget { bytes: 1_000 };
        assert!(matches!(
            serve_body(&body, &blobs, &mut budget).await,
            Served::Body(_)
        ));
        assert_eq!(
            serve_body(&body, &blobs, &mut budget).await,
            Served::NextListing
        );
        assert_eq!(blobs.opened.get(), 1);
    }

    // ---- the hand-off ----

    /// wallet-infra with a scripted answer; counts what it is asked.
    struct Scripted {
        answer: Result<bool, String>,
        asked: Cell<usize>,
    }

    #[async_trait::async_trait(?Send)]
    impl FeeWallet for Scripted {
        async fn internalize(&self, _tx: &Value, _args: &Value) -> Result<bool, String> {
            self.asked.set(self.asked.get() + 1);
            self.answer.clone()
        }
    }

    /// A ledger in memory, or one that cannot be written.
    #[derive(Default)]
    struct Owed {
        rows: RefCell<Vec<DeferredFee>>,
        down: bool,
    }

    #[async_trait::async_trait(?Send)]
    impl FeeLedger for Owed {
        async fn defer(&self, fee: &DeferredFee) -> Result<(), String> {
            if self.down {
                return Err("D1_ERROR: unavailable".to_string());
            }
            self.rows.borrow_mut().push(fee.clone());
            Ok(())
        }
        async fn due(&self, _now: u64, _limit: u32) -> Result<Vec<DeferredFee>, String> {
            Ok(self.rows.borrow().clone())
        }
        async fn settle(&self, key: &str) -> Result<(), String> {
            self.rows.borrow_mut().retain(|row| row.key != key);
            Ok(())
        }
        async fn put_off(&self, _: &str, _: u32, _: u64, _: &str) -> Result<(), String> {
            Ok(())
        }
        async fn owes(&self, key: &str) -> Result<bool, String> {
            Ok(self.rows.borrow().iter().any(|row| row.key == key))
        }
    }

    /// The stored rows as a list of the keys they name, and the keys let go
    /// of; or rows that cannot be read.
    #[derive(Default)]
    struct Named {
        keys: RefCell<Vec<String>>,
        released: RefCell<Vec<String>>,
        down: Cell<bool>,
    }

    #[async_trait::async_trait(?Send)]
    impl RowRefs for Named {
        async fn names(&self, key: &str) -> Result<bool, String> {
            if self.down.get() {
                return Err("D1_ERROR: unavailable".to_string());
            }
            Ok(self.keys.borrow().iter().any(|named| named == key))
        }
        async fn released(&self, limit: u32) -> Result<Vec<String>, String> {
            let released = self.released.borrow();
            Ok(released.iter().take(limit as usize).cloned().collect())
        }
        async fn forget(&self, key: &str) -> Result<(), String> {
            self.released.borrow_mut().retain(|k| k != key);
            Ok(())
        }
    }

    async fn handed(
        blobs: &Mem,
        wallet: &Scripted,
        ledger: &Owed,
        payment: &Value,
        fee_owed: bool,
        rows: bool,
    ) -> Result<HandedOff, RouteResult> {
        let server_output = json!({ "outputIndex": 0 });
        hand_off(
            &Seams {
                blobs,
                wallet,
                ledger,
                rows: &Named::default(),
            },
            &Paid {
                payment,
                r2_key: None,
                spool_key: KEY,
                server_output: fee_owed.then_some(&server_output),
                txid: fee_owed.then_some("aa"),
                rows,
                now: 1_000,
            },
        )
        .await
    }

    // ---- ownership ----

    #[tokio::test]
    async fn an_object_goes_only_when_no_row_and_no_fee_names_it() {
        let blobs = Mem::default();
        let wallet = accepts();
        let ledger = Owed::default();
        let rows = Named::default();
        let seams = Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
        };
        let fee = DeferredFee {
            key: KEY.to_string(),
            etag: "e1".into(),
            txid: "aa".into(),
            args: "{}".into(),
            named: false,
            attempts: 0,
            next_at: 0,
        };
        let here = || blobs.objects.borrow().contains_key(KEY);
        blobs.put(KEY, &bytes(10), "e1");

        // A row names it.
        rows.keys.borrow_mut().push(KEY.to_string());
        assert_eq!(reclaim(&seams, KEY).await, Ok(false));
        assert!(here());
        // A deferred fee names it.
        rows.keys.borrow_mut().clear();
        ledger.defer(&fee).await.unwrap();
        assert_eq!(reclaim(&seams, KEY).await, Ok(false));
        assert!(here());
        // Rows that cannot be read name it, for all the relay knows.
        ledger.settle(KEY).await.unwrap();
        rows.down.set(true);
        assert!(reclaim(&seams, KEY).await.is_err());
        assert!(here());
        // Nothing names it.
        rows.down.set(false);
        assert_eq!(reclaim(&seams, KEY).await, Ok(true));
        assert!(!here());
    }

    #[tokio::test]
    async fn the_released_keys_are_looked_at_and_one_the_store_cannot_answer_for_waits() {
        let blobs = Mem::default();
        let wallet = accepts();
        let ledger = Owed::default();
        let rows = Named::default();
        let seams = Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
        };
        for key in ["02abc/gone.beef", "02abc/named.beef"] {
            blobs.put(key, &bytes(10), "e1");
            rows.released.borrow_mut().push(key.to_string());
        }
        rows.keys.borrow_mut().push("02abc/named.beef".to_string());

        // The rows cannot be read: nothing is deleted and nothing forgotten.
        rows.down.set(true);
        let pass = reclaim_released(&seams, 10).await.unwrap();
        assert_eq!((pass.deleted, pass.named, pass.put_off), (0, 0, 2));
        assert_eq!(blobs.objects.borrow().len(), 2);
        assert_eq!(rows.released.borrow().len(), 2);

        rows.down.set(false);
        let pass = reclaim_released(&seams, 10).await.unwrap();
        assert_eq!((pass.deleted, pass.named, pass.put_off), (1, 1, 0));
        let objects = blobs.objects.borrow();
        assert!(objects.contains_key("02abc/named.beef"));
        assert!(!objects.contains_key("02abc/gone.beef"));
        assert!(rows.released.borrow().is_empty());
    }

    fn accepts() -> Scripted {
        Scripted {
            answer: Ok(true),
            asked: Cell::new(0),
        }
    }

    #[tokio::test]
    async fn a_box_that_owes_no_delivery_fee_keeps_the_recipients_payment_at_rest_unjudged() {
        let (blobs, wallet, ledger) = (Mem::default(), accepts(), Owed::default());
        let payment = json!({ "tx": hex::encode(bytes(50)), "description": "d" });
        let handed = handed(&blobs, &wallet, &ledger, &payment, false, true)
            .await
            .unwrap();
        assert_eq!(handed.fee, Fee::NotOwed);
        assert_eq!(wallet.asked.get(), 0);
        assert_eq!(handed.kept.as_deref(), Some(KEY));
        assert_eq!(handed.payment["verdict"], "notJudged");
        assert_eq!(handed.payment["txShape"], "hex");
        assert!(handed.payment.get("tx").is_none());
        assert_eq!(blobs.objects.borrow()[KEY].0, bytes(50));
    }

    #[tokio::test]
    async fn a_payment_that_is_no_bytes_is_refused_as_invalid_and_nothing_is_put_at_rest() {
        let (blobs, wallet, ledger) = (Mem::default(), accepts(), Owed::default());
        for payment in [json!({ "tx": "not hex" }), json!({ "tx": 7 }), json!({})] {
            let (body, status) = handed(&blobs, &wallet, &ledger, &payment, false, true)
                .await
                .unwrap_err();
            assert_eq!(
                (status, &body["code"]),
                (400, &json!("ERR_INVALID_PAYMENT"))
            );
        }
        assert!(blobs.objects.borrow().is_empty());
    }

    #[tokio::test]
    async fn the_size_that_routes_a_fee_to_the_ledger_is_never_an_answer_to_the_sender() {
        // At the threshold the fee is recorded in the request; one byte over
        // it is owed. Both sends succeed.
        for (size, fee) in [
            (INTERNALIZE_INLINE_BYTES, Fee::Internalized),
            (INTERNALIZE_INLINE_BYTES + 1, Fee::Deferred),
        ] {
            let (blobs, wallet, ledger) = (Mem::default(), accepts(), Owed::default());
            let payment = json!({ "tx": { "beef": B64.encode(bytes(size as usize)) } });
            let handed = handed(&blobs, &wallet, &ledger, &payment, true, false)
                .await
                .expect("no size is refused after the verdict");
            assert_eq!(handed.fee, fee, "{size} bytes");
            assert_eq!(wallet.asked.get(), usize::from(fee == Fee::Internalized));
            assert_eq!(
                ledger.rows.borrow().len(),
                usize::from(fee == Fee::Deferred)
            );
            // No row names the payment: it is kept only while a fee waits.
            assert_eq!(handed.kept.is_some(), fee == Fee::Deferred);
            assert_eq!(
                blobs.objects.borrow().len(),
                usize::from(fee == Fee::Deferred)
            );
            assert!(ledger.rows.borrow().iter().all(|row| !row.named));
        }
    }

    #[tokio::test]
    async fn a_payment_wallet_infra_does_not_accept_is_refused_as_before_and_its_spool_goes() {
        let (blobs, ledger) = (Mem::default(), Owed::default());
        let wallet = Scripted {
            answer: Ok(false),
            asked: Cell::new(0),
        };
        let payment = json!({ "tx": hex::encode(bytes(50)) });
        let (body, status) = handed(&blobs, &wallet, &ledger, &payment, true, true)
            .await
            .unwrap_err();
        assert_eq!(
            (status, &body["code"]),
            (400, &json!("ERR_INSUFFICIENT_PAYMENT"))
        );
        assert!(blobs.objects.borrow().is_empty());
        assert!(ledger.rows.borrow().is_empty());
    }

    #[tokio::test]
    async fn a_store_or_a_ledger_that_is_down_is_a_503_the_same_request_retries() {
        let payment = json!({ "tx": hex::encode(bytes(50)) });
        let failing = Scripted {
            answer: Err("wallet-infra answered 502".to_string()),
            asked: Cell::new(0),
        };

        // The bytes cannot be put at rest: nothing is asked of the wallet.
        let (blobs, ledger) = (Mem::default(), Owed::default());
        blobs.down.set(true);
        let (body, status) = handed(&blobs, &failing, &ledger, &payment, true, true)
            .await
            .unwrap_err();
        assert_eq!(
            (status, &body["code"]),
            (503, &json!("ERR_PAYMENT_UNAVAILABLE"))
        );
        assert_eq!(failing.asked.get(), 0);

        // The fee cannot be recorded as owed.
        let (blobs, ledger) = (
            Mem::default(),
            Owed {
                down: true,
                ..Owed::default()
            },
        );
        let (body, status) = handed(&blobs, &failing, &ledger, &payment, true, true)
            .await
            .unwrap_err();
        assert_eq!(
            (status, &body["code"]),
            (503, &json!("ERR_PAYMENT_UNAVAILABLE"))
        );
    }

    #[test]
    fn the_backoff_is_a_minute_doubling_to_a_day() {
        let waits: Vec<u64> = (1..=12).map(backoff_secs).collect();
        assert_eq!(
            waits,
            [60, 120, 240, 480, 960, 1_920, 3_840, 7_680, 15_360, 30_720, 61_440, 86_400]
        );
        assert_eq!(backoff_secs(0), 60);
        assert_eq!(backoff_secs(u32::MAX), 86_400);
    }
}
