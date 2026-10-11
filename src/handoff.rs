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
//! argument wallet-infra takes (`INTERNALIZE_INLINE_BYTES`), as `tx` in hex.
//! Otherwise, and whenever wallet-infra cannot answer, it is deferred: a row
//! of the ledger, drained later (`drain_fees`), retried with a backoff, never
//! dropped. The drain hands wallet-infra a reference to the bytes at rest
//! (`beef_at_rest`), never the bytes, so no fee is too large to drain. The
//! message is stored and delivered on the verdict either way. Nothing here
//! answers a size or a count: a deferred fee is no error to the sender.

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
    CLAIMED_SQL, CLAIM_SQL, FEE_OWES_KEY_SQL, FORGET_MINTED_SQL, FORGET_RELEASED_SQL,
    MINTED_DUE_SQL, MINT_SQL, POSTPONE_MINTED_SQL, RELEASED_KEYS_SQL, ROW_NAMES_KEY_SQL,
    UNCLAIM_SQL,
};
pub use crate::storage::{
    CLEAR_WALLET_WORD_SQL, END_FEE_SQL, FEES_FIGURE_SQL, LAST_ENDED_SQL, SET_WALLET_WORD_SQL,
    WALLET_WORD_SQL,
};

/// The custom metadata of an object at rest that names the one caller
/// wallet-infra reads it for by reference (NL-7c): the identity key of the
/// recipient of the payment the reference is internalized for, the delivery
/// fee's, so the relay's own (`Paid::reader`).
pub const READER_METADATA: &str = "recipient-identity-key";

/// The object store of the door, and a way to put a payment's bytes there.
#[async_trait::async_trait(?Send)]
pub trait PaymentStore: BeefStore {
    /// Write the `size` bytes `chunks` yields at `key`, a chunk at a time,
    /// with `reader` as its `READER_METADATA`, and answer the stamp of what
    /// is now at rest there.
    async fn spool(
        &self,
        key: &str,
        chunks: &mut dyn Chunks,
        size: u64,
        reader: &str,
    ) -> Result<Stamp, String>;
    /// The `READER_METADATA` of the object at `key`, `None` when it has none.
    async fn reader(&self, key: &str) -> Result<Option<String>, String>;
    /// The bucket's name, as wallet-infra binds it to read a reference
    /// (`beef_at_rest`); `None` when the deployment does not say it.
    fn bucket_name(&self) -> Option<String>;
}

/// wallet-infra, as the relay asks it to record the server's delivery fee:
/// BRC-100 `internalizeAction` with `args`, the whole argument
/// (`internalize_inline` or `internalize_at_rest`). `Ok(false)` is the
/// wallet's refusal of the payment; `Err` is a wallet that could not answer.
#[async_trait::async_trait(?Send)]
pub trait FeeWallet {
    async fn internalize(&self, args: &Value) -> Result<bool, String>;
}

/// A broadcaster's word on a payment's subject (0.4.4, bsv-low #591 M2): a
/// hint by the tracker's rule (bsv-stack-lean `docs/charters/tracker.md`
/// section 2), never a verdict. An acceptance is not "mined" and a refusal is
/// not "rejected"; the message is delivered on the door's verdict either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// The broadcaster took the subject (a 2xx).
    pub accepted: bool,
    /// Its word, or why no word came.
    pub word: String,
}

/// The bytes of a payment as the announcer posts them.
pub enum Subject<'a> {
    /// At rest: the object at `key`, the bytes `stamp` names.
    AtRest { key: &'a str, stamp: &'a Stamp },
    /// In the request.
    InHand(&'a Carrier<'a>),
}

/// A broadcaster the subject is announced to (`payments::ArcAnnouncer` in the
/// Worker). `Ok` is the broadcaster's answer as a hint; `Err` is no answer.
#[async_trait::async_trait(?Send)]
pub trait Announcer {
    async fn announce(&self, subject: Subject<'_>) -> Result<Hint, String>;
}

/// An announcement still owed: the broadcaster refused, or did not answer,
/// and the drain asks again (`reask_announces`). It names the bytes at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwedAnnounce {
    pub key: String,
    /// The etag of the bytes the door verified.
    pub etag: String,
    pub txid: String,
    pub attempts: u32,
    /// Unix seconds: not before.
    pub next_at: u64,
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
    /// Whether a deferred fee, or an announcement owed, names the object at
    /// `key`. An ended fee names nothing.
    async fn owes(&self, key: &str) -> Result<bool, String>;
    /// The fee at `key` ends (0.4.4, bsv-low #591 R403-L1): `why` is kept on
    /// its row, and the drain never takes it up again.
    async fn end(&self, key: &str, why: &str) -> Result<(), String>;
    /// The fees owed, the fees ended, and the reason of the last one ended.
    async fn figure(&self) -> Result<FeeFigure, String>;
    /// The relay's word that wallet-infra cannot read its bucket, and when it
    /// was recorded.
    async fn wallet_word(&self) -> Result<Option<(String, u64)>, String>;
    /// Record that word (`Some`), or clear it (`None`).
    async fn set_wallet_word(&self, word: Option<&str>, now: u64) -> Result<(), String>;
    /// Record an announcement as owed, with the word that made it so. One
    /// already recorded at the key is left as it is.
    async fn owe_announce(&self, owed: &OwedAnnounce, word: &str) -> Result<(), String>;
    /// The announcements due at `now`, the longest waiting leading.
    async fn due_announces(&self, now: u64, limit: u32) -> Result<Vec<OwedAnnounce>, String>;
    /// The broadcaster took the subject: the row goes.
    async fn announced(&self, key: &str) -> Result<(), String>;
    /// Asked again and not taken: one more attempt, a later `next_at`.
    async fn put_off_announce(
        &self,
        key: &str,
        attempts: u32,
        next_at: u64,
        word: &str,
    ) -> Result<(), String>;
}

/// The fees as the health figure gives them (0.4.4, bsv-low #591 R403-L1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeFigure {
    /// Fees still owed: the drain takes them up.
    pub owed: u64,
    /// Fees ended: each row keeps its reason.
    pub ended: u64,
    /// The reason of the fee ended last.
    pub last_ended: Option<String>,
}

/// The attempts a fee wallet-infra could not record is tried, a minute
/// doubling to a day between them (`backoff_secs`): about three weeks. Then it
/// ends, with the last refusal as its reason.
pub const FEE_ATTEMPTS_CEILING: u32 = 30;

/// How long the relay's word that wallet-infra cannot read its bucket stands
/// before a fee is deferred into it again, to be tried once more: a day.
pub const WALLET_WORD_SECS: u64 = 86_400;

/// Whether wallet-infra's refusal says it cannot read the relay's bucket: the
/// two words its at-rest door has for it (`[SRC] rust-wallet-infra@50a282f
/// src/storage/internalize_action.rs:352-356`, no `BEEF_AT_REST` binding;
/// `src/beef_at_rest.rs:430-434`, another bucket bound).
pub fn cannot_read_bucket(word: &str) -> bool {
    word.contains("no bucket is bound here for bytes at rest")
        || (word.contains("beefAtRest: bucket ") && word.contains("is not bound here"))
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
    /// A reclaim holds `key` while it looks and deletes (0.4.4, bsv-low #591
    /// L2): written before it looks at the rows.
    async fn claim(&self, key: &str) -> Result<(), String>;
    /// The reclaim of `key` is over.
    async fn unclaim(&self, key: &str) -> Result<(), String>;
    /// Whether a reclaim holds `key` now: a send that named it asks after
    /// its row is written.
    async fn claimed(&self, key: &str) -> Result<bool, String>;
    /// The relay minted `key` (an upload URL, or a spool): look at it again
    /// at `deadline` (0.4.4, bsv-low #591 L3). A key minted again keeps its
    /// first record.
    async fn mint(&self, key: &str, deadline: u64) -> Result<(), String>;
    /// The minted keys past their deadline at `now`, at most `limit`.
    async fn minted_due(&self, now: u64, limit: u32) -> Result<Vec<String>, String>;
    /// Look at `key` again at `deadline`.
    async fn postpone_minted(&self, key: &str, deadline: u64) -> Result<(), String>;
    /// The minted key was looked at for the last time.
    async fn forget_minted(&self, key: &str) -> Result<(), String>;
}

/// What the hand-off works through.
pub struct Seams<'a> {
    pub blobs: &'a dyn PaymentStore,
    pub wallet: &'a dyn FeeWallet,
    pub ledger: &'a dyn FeeLedger,
    pub rows: &'a dyn RowRefs,
    /// The broadcaster, when the deployment names one.
    pub announcer: Option<&'a dyn Announcer>,
}

/// A verified payment as the route hands it on.
pub struct Paid<'a> {
    /// The request's `payment`.
    pub payment: &'a Value,
    /// The object `payment.beefR2Key` names, when the sender uploaded one.
    pub r2_key: Option<&'a str>,
    /// Where the relay put an inline payment's bytes at rest before its
    /// scripts ran (`payments::judge_delivery_inline_at_rest`), when it did:
    /// the hand-off keeps them there and spools nothing again.
    pub spooled: Option<&'a str>,
    /// Where an inline payment's bytes are put at rest: a key of the upload
    /// shape, `<sender's identity key>/<uuid>.beef`, that nothing presigned.
    pub spool_key: &'a str,
    /// The server's delivery output, when the box owes a delivery fee.
    pub server_output: Option<&'a Value>,
    /// The stamp of the object the door read at `r2_key` or `spooled`, when
    /// it read one (0.4.4, bsv-low #591 L1). The hand-off records nothing of
    /// bytes that are no longer these.
    pub stamp: Option<&'a Stamp>,
    /// The subject's txid, when the door judged the payment (a box with no
    /// delivery fee judges nothing).
    pub txid: Option<&'a str>,
    /// Whether a recipient's row will carry the payment.
    pub rows: bool,
    /// The identity key every object this payment rests in names as its
    /// reader (`READER_METADATA`): the relay's own, the recipient of the
    /// delivery fee, whose drain is the one caller that hands wallet-infra a
    /// reference to it.
    pub reader: &'a str,
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
    /// It could not be recorded and is not owed (0.4.4, R403-L1): the
    /// wallet-infra it would be deferred into cannot read the relay's bucket.
    /// Its row keeps the reason; the message goes.
    Ended,
}

/// The hand-off's result.
#[derive(Debug, Clone, PartialEq)]
pub struct HandedOff {
    /// The payment as a recipient's row stores it (`stored_body` adds that
    /// recipient's outputs).
    pub payment: Value,
    pub fee: Fee,
    /// The object that must stay at rest: a row, a deferred fee or an
    /// announcement owed names it.
    pub kept: Option<String>,
    /// The broadcaster's word on the subject, when the payment was judged.
    pub hint: Option<Hint>,
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

/// `internalizeAction`'s argument with the BEEF inline: `tx`, the hex string
/// wallet-infra decodes (`[SRC] bsv-rs 0.4.1 src/wallet/types.rs:24-43`), beside
/// `fee` (`fee_args`).
pub fn internalize_inline(tx: &str, fee: &Value) -> Value {
    internalize_with("tx", json!(tx), fee)
}

/// `internalizeAction`'s argument with the BEEF at rest: `beefAtRest` (the
/// reference, `beef_at_rest`) in place of `tx`, beside `fee`. wallet-infra
/// refuses both at once (`[SRC] rust-wallet-infra@50a282f
/// src/beef_at_rest.rs:90-94`).
pub fn internalize_at_rest(reference: Value, fee: &Value) -> Value {
    internalize_with("beefAtRest", reference, fee)
}

fn internalize_with(name: &str, bytes: Value, fee: &Value) -> Value {
    let mut args = json!({
        "outputs": fee.get("outputs").unwrap_or(&json!([])),
        "description": fee.get("description").unwrap_or(&json!("MessageBox delivery payment")),
        "labels": fee.get("labels").unwrap_or(&json!([])),
        "seekPermission": false
    });
    args[name] = bytes;
    args
}

/// The reference to a payment's BEEF at rest, as wallet-infra reads it
/// (`[SRC] rust-wallet-infra@50a282f src/beef_at_rest.rs:46-54`, each field and
/// no other): the object's key, its exact size in bytes, R2's etag unquoted
/// (the etag, not the HTTP etag), and the bucket's name (not the binding's).
pub fn beef_at_rest(key: &str, stamp: &Stamp, bucket: &str) -> Value {
    json!({
        "r2Key": key,
        "size": stamp.size,
        "etag": stamp.etag.trim_matches('"'),
        "bucket": bucket,
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
    /// The shape the sender sent `payment.tx` in: the carrier's, or a byte
    /// array the relay read as hex (`validation::read_send_body`, 0.4.4
    /// NOTE-4, `payment.txShape: "array"`).
    pub fn sent(payment: &Value, carrier: &Carrier<'_>) -> Self {
        match payment.get("txShape").and_then(Value::as_str) {
            Some("array") => TxShape::Array,
            _ => TxShape::of(carrier),
        }
    }

    pub fn of(carrier: &Carrier<'_>) -> Self {
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
const ROW_FIELDS: [&str; 11] = [
    "announced",
    "beefReader",
    "key",
    "words",
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

/// A payment no delivery fee judged, as its row keeps it (0.4.4, bsv-low
/// #591 M3): the request's `payment` with its `tx` as sent, without what is
/// the relay's to write, and `verdict: notJudged`.
pub fn payment_in_row(payment: &Value) -> Value {
    let mut row: serde_json::Map<String, Value> = payment
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| !ROW_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    if let Some(tx) = payment.get("tx") {
        // A byte array the relay read as hex goes back in the row as the
        // array it came as (0.4.4, NOTE-4).
        let tx = match (payment.get("txShape").and_then(Value::as_str), tx.as_str()) {
            (Some("array"), Some(text)) => match hex::decode(text) {
                Ok(bytes) => json!(bytes),
                Err(_) => tx.clone(),
            },
            _ => tx.clone(),
        };
        row.insert("tx".into(), tx);
    }
    row.insert("verdict".into(), json!("notJudged"));
    Value::Object(row)
}

/// An object's bytes as the JSON text of `payment.tx` in `shape`, written
/// straight to text a chunk at a time (0.4.4, bsv-low #591 M1): a byte array
/// is never a `Value::Array` of one `Value` a byte. The caller has decided
/// the text fits what it is building (`encoded_len`).
async fn tx_text(
    blobs: &dyn BeefStore,
    key: &str,
    stamp: &Stamp,
    shape: TxShape,
) -> Result<String, String> {
    use std::fmt::Write as _;
    let mut chunks = blobs.open(key, 0, stamp).await?;
    let mut text = String::with_capacity(encoded_len(stamp.size, shape) as usize);
    match shape {
        TxShape::Array => {
            text.push('[');
            while let Some(chunk) = chunks.next().await? {
                for byte in chunk {
                    let _ = write!(text, "{},", byte);
                }
            }
            if text.ends_with(',') {
                text.pop();
            }
            text.push(']');
        }
        TxShape::Hex => {
            text.push('"');
            while let Some(chunk) = chunks.next().await? {
                text.push_str(&hex::encode(chunk));
            }
            text.push('"');
        }
        TxShape::Base64 => {
            // Whole groups of three bytes are encoded as they arrive; what
            // is left over waits for the next chunk.
            text.push_str("{\"beef\":\"");
            let mut held: Vec<u8> = Vec::new();
            while let Some(chunk) = chunks.next().await? {
                held.extend_from_slice(&chunk);
                let whole = held.len() / 3 * 3;
                B64.encode_string(&held[..whole], &mut text);
                held.drain(..whole);
            }
            B64.encode_string(&held, &mut text);
            text.push_str("\"}");
        }
    }
    Ok(text)
}

/// An object's bytes as one hex string: the fee recorded in the request.
async fn hex_from_rest(blobs: &dyn BeefStore, key: &str, stamp: &Stamp) -> Result<String, String> {
    let text = tx_text(blobs, key, stamp, TxShape::Hex).await?;
    Ok(text[1..text.len() - 1].to_string())
}

/// The most the JSON text of `payment.tx` can be for `size` bytes in
/// `shape`: a byte array four characters a byte (up to three digits and a
/// comma; 3.57 on average over bytes spread evenly, but a budget is held to
/// the most), hex two, base64 four for three (about 1.34), each with its
/// brackets or quotes.
pub fn encoded_len(size: u64, shape: TxShape) -> u64 {
    match shape {
        TxShape::Array => size.saturating_mul(4) + 2,
        TxShape::Hex => size.saturating_mul(2) + 2,
        TxShape::Base64 => size.div_ceil(3).saturating_mul(4) + 12,
    }
}

/// The carrier's bytes as one hex string: the fee recorded in the request,
/// bounded by `INTERNALIZE_INLINE_BYTES`.
fn hex_of(carrier: &Carrier<'_>) -> String {
    match carrier {
        Carrier::Hex(text) => text.to_string(),
        _ => hex::encode(carrier.bytes(0, carrier.len() as usize)),
    }
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
    let mut rest: Option<(String, Stamp)> = match (paid.r2_key, paid.spooled) {
        (Some(key), _) => Some((
            key.to_string(),
            seams
                .blobs
                .stamp(key)
                .await
                .map_err(beef_key_not_found)?
                .ok_or_else(|| beef_key_not_found("R2 object not found".to_string()))?,
        )),
        // The relay's own spool: there, or spooled again below.
        (None, Some(key)) => seams
            .blobs
            .stamp(key)
            .await
            .map_err(store_unavailable)?
            .map(|stamp| (key.to_string(), stamp)),
        (None, None) => None,
    };
    // The bytes the door read, and no others (0.4.4, bsv-low #591 L1): an
    // object replaced between the verdict and here is not the payment the
    // door verified, and nothing of it is recorded. The same request again
    // reads the object as it is now.
    if let (Some(door), Some((key, now))) = (paid.stamp, &rest) {
        if door != now {
            return Err(err(
                503,
                "ERR_PAYMENT_CHANGED",
                &format!(
                    "The payment's BEEF at {} changed after it was verified (etag {} then, {} now); send the same request again.",
                    key, door.etag, now.etag
                ),
            ));
        }
    }
    let shape = carrier.as_ref().map_or(TxShape::Base64, |carrier| {
        TxShape::sent(paid.payment, carrier)
    });
    let size = match (&carrier, &rest) {
        (Some(carrier), _) => carrier.len(),
        (None, Some((_, stamp))) => stamp.size,
        (None, None) => 0,
    };

    // A body nobody judged (a box that owes no delivery fee) is kept in its
    // row, as 0.3.x kept every payment, and never spooled (0.4.4, bsv-low
    // #591 M3): the route has read its structure and held it to the row's
    // bound (`payments::check_unjudged`).
    if let (None, None, Some(_)) = (paid.server_output, paid.r2_key, &carrier) {
        return Ok(HandedOff {
            payment: if paid.rows {
                payment_in_row(paid.payment)
            } else {
                Value::Null
            },
            fee: Fee::NotOwed,
            kept: None,
            hint: None,
        });
    }

    // The bytes at rest before anything names them.
    if let (true, None, Some(carrier)) = (paid.rows, &rest, &carrier) {
        let stamp = seams
            .blobs
            .spool(paid.spool_key, &mut carrier.chunks(0), size, paid.reader)
            .await
            .map_err(store_unavailable)?;
        rest = Some((paid.spool_key.to_string(), stamp));
    }

    // The reader of a sender's upload (0.4.4, bsv-low #591 R403-M1): named
    // at mint time, a signed header of the presigned PUT; an object at rest
    // that does not name it (an upload of an earlier release) has it beside
    // its key in the row. The object is never written again: one head, no
    // byte read, and the etag the door verified is the one recorded.
    let beef_reader = match (paid.r2_key, &rest) {
        (Some(_), Some((key, _))) => match seams.blobs.reader(key).await {
            Ok(Some(reader)) if reader == paid.reader => None,
            _ => Some(paid.reader.to_string()),
        },
        _ => None,
    };

    // The subject announced before delivery (0.4.4, bsv-low #591 M2). The
    // broadcaster's word is a hint, kept on the row; a refusal, or no answer,
    // is owed and asked again by the drain. Nothing here refuses the sender.
    let mut hint = None;
    let mut announce_owed = false;
    if let (Some(_), Some(txid)) = (paid.server_output, paid.txid) {
        let word = match (seams.announcer, &rest, &carrier) {
            (Some(to), Some((key, stamp)), _) => {
                Some(to.announce(Subject::AtRest { key, stamp }).await)
            }
            (Some(to), None, Some(carrier)) => Some(to.announce(Subject::InHand(carrier)).await),
            _ => None,
        };
        let said = match &word {
            None => Hint {
                accepted: false,
                word: "no broadcaster is configured".to_string(),
            },
            Some(Ok(said)) => said.clone(),
            Some(Err(e)) => Hint {
                accepted: false,
                word: format!("no answer: {}", e),
            },
        };
        if word.is_some() && !said.accepted {
            // The re-ask names the bytes: at rest before it does.
            if let (None, Some(carrier)) = (&rest, &carrier) {
                let stamp = seams
                    .blobs
                    .spool(paid.spool_key, &mut carrier.chunks(0), size, paid.reader)
                    .await
                    .map_err(store_unavailable)?;
                rest = Some((paid.spool_key.to_string(), stamp));
            }
            if let Some((key, stamp)) = &rest {
                seams
                    .ledger
                    .owe_announce(
                        &OwedAnnounce {
                            key: key.clone(),
                            etag: stamp.etag.clone(),
                            txid: txid.to_string(),
                            attempts: 0,
                            next_at: paid.now,
                        },
                        &said.word,
                    )
                    .await
                    .map_err(|e| {
                        err(
                            503,
                            "ERR_PAYMENT_UNAVAILABLE",
                            &format!(
                                "The announcement could not be recorded as owed; send the same request again: {}",
                                e
                            ),
                        )
                    })?;
                announce_owed = true;
            }
        }
        hint = Some(said);
    }

    let mut fee = Fee::NotOwed;
    if let Some(server_output) = paid.server_output {
        let args = fee_args(server_output, paid.payment);
        // Why the fee is not recorded in this request, when it is not.
        let owed: Option<String> = if size > INTERNALIZE_INLINE_BYTES {
            Some("the BEEF is more than one request hands wallet-infra".to_string())
        } else {
            // `tx` as hex, the shape wallet-infra decodes, whatever shape
            // the sender sent.
            let tx = match (&rest, paid.r2_key, &carrier) {
                (Some((key, stamp)), Some(_), _) => hex_from_rest(seams.blobs, key, stamp)
                    .await
                    .map(Value::String),
                (_, _, Some(carrier)) => Ok(Value::String(hex_of(carrier))),
                _ => Err("no bytes to hand wallet-infra".to_string()),
            };
            match tx.as_ref().map(|tx| tx.as_str().unwrap_or_default()) {
                Err(e) => Some(format!("the bytes could not be read back: {}", e)),
                Ok(tx) => {
                    match seams
                        .wallet
                        .internalize(&internalize_inline(tx, &args))
                        .await
                    {
                        Ok(true) => None,
                        // wallet-infra's own word on the payment, as before.
                        Ok(false) => {
                            // The relay's own spool goes, unless another
                            // send's row names the same bytes.
                            if let (None, Some((key, _))) = (paid.r2_key, &rest) {
                                let _ = reclaim(seams, key).await;
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
                        .spool(paid.spool_key, &mut carrier.chunks(0), size, paid.reader)
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
                let unavailable = |e: String| {
                    err(
                        503,
                        "ERR_PAYMENT_UNAVAILABLE",
                        &format!(
                            "The delivery fee could not be recorded as owed; send the same request again: {}",
                            e
                        ),
                    )
                };
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
                    .map_err(unavailable)?;
                // No fee is deferred into a wallet-infra that cannot read the
                // relay's bucket (0.4.4, R403-L1): it ends at once, its reason
                // on its row.
                match seams.ledger.wallet_word().await {
                    Ok(Some((word, at))) if paid.now < at + WALLET_WORD_SECS => {
                        seams
                            .ledger
                            .end(
                                key,
                                &format!(
                                    "not deferred: wallet-infra cannot read the relay's bucket ({})",
                                    word
                                ),
                            )
                            .await
                            .map_err(unavailable)?;
                        Fee::Ended
                    }
                    _ => Fee::Deferred,
                }
            }
        };
    }

    let keep = paid.rows || fee == Fee::Deferred || announce_owed;
    // A spool nothing will name goes now (`reclaim`: unless an earlier send
    // names the same bytes).
    if let (false, None, Some((key, _))) = (keep, paid.r2_key, &rest) {
        let _ = reclaim(seams, key).await;
    }
    let kept = rest.filter(|_| keep);
    let payment = match &kept {
        Some((key, stamp)) if paid.rows => {
            let mut payment = payment_at_rest(paid.payment, key, stamp, shape, paid.txid);
            if let Some(hint) = &hint {
                payment["announced"] = json!({ "accepted": hint.accepted, "word": hint.word });
            }
            if let Some(reader) = &beef_reader {
                payment["beefReader"] = json!(reader);
            }
            payment
        }
        _ => Value::Null,
    };
    Ok(HandedOff {
        payment,
        fee,
        kept: kept.map(|(key, _)| key),
        hint,
    })
}

// ---------------------------------------------------------------------------
// Ownership: an object goes only when nothing names it
// ---------------------------------------------------------------------------

/// Delete the object at `key` when no stored row, no deferred fee and no
/// announcement owed names it; `true` when it was deleted (or was already
/// gone). A store that cannot say who names the key deletes nothing (`Err`):
/// the object stays. The one way a payment's object is deleted once it is at
/// rest.
///
/// R2 deletes by key alone (0.4.4, bsv-low #591 L2), so the reclaim claims
/// the key first (`RowRefs::claim`), looks, stamps the object, looks again,
/// and deletes only the bytes it stamped. A send that names the key after the
/// second look reads the claim after its row (`RowRefs::claimed`): one of the
/// two always sees the other.
pub async fn reclaim(seams: &Seams<'_>, key: &str) -> Result<bool, String> {
    seams.rows.claim(key).await?;
    let reclaimed = reclaim_claimed(seams, key).await;
    let _ = seams.rows.unclaim(key).await;
    reclaimed
}

async fn named(seams: &Seams<'_>, key: &str) -> Result<bool, String> {
    Ok(seams.rows.names(key).await? || seams.ledger.owes(key).await?)
}

async fn reclaim_claimed(seams: &Seams<'_>, key: &str) -> Result<bool, String> {
    if named(seams, key).await? {
        return Ok(false);
    }
    let Some(looked) = seams.blobs.stamp(key).await? else {
        return Ok(true);
    };
    // The second look: a send that named the key since the first.
    if named(seams, key).await? {
        return Ok(false);
    }
    // The bytes looked at, and no others.
    if seams.blobs.stamp(key).await?.as_ref() != Some(&looked) {
        return Ok(false);
    }
    seams.blobs.clear(key).await?;
    Ok(true)
}

/// After a send named `key` (0.4.4, bsv-low #591 L2): whether a reclaim held
/// the key as the row was written and the bytes are gone, the one case the
/// claim cannot spare. The route logs it with its key: an orphan, a row that
/// names nothing at rest.
pub async fn orphaned(seams: &Seams<'_>, key: &str) -> bool {
    matches!(seams.rows.claimed(key).await, Ok(true))
        && matches!(seams.blobs.stamp(key).await, Ok(None))
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

/// How long after its URL's life a minted upload waits for a send to name it
/// (0.4.4, bsv-low #591 L3): a day.
pub const MINTED_MARGIN_SECS: u64 = 86_400;

/// How long a minted key whose reading is still pending waits again.
pub const MINTED_PENDING_SECS: u64 = 3_600;

/// What one pass over the minted keys came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Expired {
    /// Objects deleted: nothing named them by their deadline.
    pub deleted: u32,
    /// Keys a row, a fee or an announcement names: theirs now.
    pub named: u32,
    /// Keys whose reading is pending, or the store could not answer for.
    pub put_off: u32,
}

/// Look at the minted keys past their deadline, at most `limit` (0.4.4,
/// bsv-low #591 L3): an object nothing names is deleted with its door state
/// (`reclaim`), one something names is left to what names it, and the record
/// is forgotten either way. A key whose door state is there (a reading
/// pending across requests) waits `MINTED_PENDING_SECS` more; the bucket's
/// lifecycle rule on `door-state/` ends a state nobody comes back to.
pub async fn reclaim_minted(seams: &Seams<'_>, now: u64, limit: u32) -> Result<Expired, String> {
    let mut expired = Expired::default();
    for key in seams.rows.minted_due(now, limit).await? {
        let state = crate::beef_door::state_key(&key);
        if !matches!(seams.blobs.load(&state).await, Ok(None)) {
            seams
                .rows
                .postpone_minted(&key, now + MINTED_PENDING_SECS)
                .await?;
            expired.put_off += 1;
            continue;
        }
        match reclaim(seams, &key).await {
            Ok(deleted) => {
                seams.rows.forget_minted(&key).await?;
                if deleted {
                    expired.deleted += 1;
                } else {
                    expired.named += 1;
                }
            }
            Err(_) => {
                seams
                    .rows
                    .postpone_minted(&key, now + MINTED_PENDING_SECS)
                    .await?;
                expired.put_off += 1;
            }
        }
    }
    Ok(expired)
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
    /// Fees ended (0.4.4, R403-L1): a reason that cannot clear by itself
    /// (the bytes are no longer the upload the door verified or are gone, the
    /// arguments do not parse, the deployment names no bucket, wallet-infra
    /// cannot read the bucket), or the ceiling of attempts reached. 0.4.3
    /// held such a fee and retried it daily without end.
    pub ended: u32,
}

/// What became of one fee at the drain.
enum Tried {
    Settled,
    PutOff(String),
    /// A reason that cannot clear by itself: the fee ends.
    Ends(String),
}

/// One deferred fee: the object held to the upload the door verified (its
/// stamp, one head), and wallet-infra handed the reference to it
/// (`beef_at_rest`), never its bytes: wallet-infra reads them from the bucket
/// as a stream. Every fee is drained so, whatever its size.
async fn try_fee(seams: &Seams<'_>, fee: &DeferredFee) -> Tried {
    let stamp = match seams.blobs.stamp(&fee.key).await {
        Ok(Some(stamp)) => stamp,
        Ok(None) => return Tried::Ends("the object is not in the store".to_string()),
        Err(e) => return Tried::PutOff(e),
    };
    if stamp.etag != fee.etag {
        return Tried::Ends("another upload is at the key".to_string());
    }
    let Some(bucket) = seams.blobs.bucket_name() else {
        return Tried::Ends("the deployment names no bucket for the reference".to_string());
    };
    let Ok(args) = serde_json::from_str::<Value>(&fee.args) else {
        return Tried::Ends("the row's arguments do not parse".to_string());
    };
    let reference = beef_at_rest(&fee.key, &stamp, &bucket);
    match seams
        .wallet
        .internalize(&internalize_at_rest(reference, &args))
        .await
    {
        Ok(true) => Tried::Settled,
        Ok(false) => Tried::PutOff("wallet-infra did not accept the payment".to_string()),
        Err(e) if cannot_read_bucket(&e) => Tried::Ends(format!(
            "wallet-infra cannot read the relay's bucket: {}",
            e
        )),
        Err(e) => Tried::PutOff(e),
    }
}

/// Record the deferred fees that are due at `now`, at most `limit` of them,
/// the longest waiting leading. A fee recorded has its row cleared, and its
/// object deleted when nothing else names it (`reclaim`). A fee that could
/// not be recorded this time stays, with one more attempt and a later
/// `next_at`, up to `FEE_ATTEMPTS_CEILING`; at the ceiling, or for a reason
/// that cannot clear by itself, it ends with its reason (0.4.4, bsv-low #591
/// R403-L1). A refusal that says wallet-infra cannot read the relay's bucket
/// is recorded as the relay's word, and cleared when a fee is recorded.
/// `Err` is a ledger that could not be read.
pub async fn drain_fees(seams: &Seams<'_>, now: u64, limit: u32) -> Result<Drained, String> {
    let mut drained = Drained::default();
    for fee in seams.ledger.due(now, limit).await? {
        match try_fee(seams, &fee).await {
            Tried::Settled => {
                seams.ledger.settle(&fee.key).await?;
                // The fee no longer names the object. It goes when no row
                // does either: asked of the rows now, not read from what the
                // fee's row said when it was deferred.
                let _ = reclaim(seams, &fee.key).await;
                if matches!(seams.ledger.wallet_word().await, Ok(Some(_))) {
                    seams.ledger.set_wallet_word(None, now).await?;
                }
                drained.settled += 1;
            }
            Tried::PutOff(why) => {
                let attempts = fee.attempts.saturating_add(1);
                if attempts >= FEE_ATTEMPTS_CEILING {
                    let why = format!("not recorded after {} attempts: {}", attempts, why);
                    seams.ledger.end(&fee.key, &why).await?;
                    drained.ended += 1;
                } else {
                    seams
                        .ledger
                        .put_off(&fee.key, attempts, now + backoff_secs(attempts), &why)
                        .await?;
                    drained.put_off += 1;
                }
            }
            Tried::Ends(why) => {
                if cannot_read_bucket(&why) {
                    seams.ledger.set_wallet_word(Some(&why), now).await?;
                }
                seams.ledger.end(&fee.key, &why).await?;
                drained.ended += 1;
            }
        }
    }
    Ok(drained)
}

/// The fees on the health figure (0.4.4, bsv-low #591 R403-L1): owed, ended
/// and the last reason, and the relay's word on wallet-infra's reach into its
/// bucket when there is one.
pub async fn health_figure(ledger: &dyn FeeLedger) -> Result<Value, String> {
    let figure = ledger.figure().await?;
    let mut fees = json!({
        "owed": figure.owed,
        "ended": figure.ended,
    });
    if let Some(last) = figure.last_ended {
        fees["lastEnded"] = json!(last);
    }
    if let Some((word, at)) = ledger.wallet_word().await? {
        fees["walletInfra"] = json!({ "readsTheBucket": false, "word": word, "since": at });
    }
    Ok(fees)
}

/// What one re-ask of the owed announcements came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reasked {
    /// Announcements the broadcaster took; their rows are gone.
    pub accepted: u32,
    /// Asked again and not taken, or not asked: one more attempt.
    pub put_off: u32,
}

/// Ask again the announcements due at `now`, at most `limit` (0.4.4,
/// bsv-low #591 M2): the bytes held to the etag the door verified and posted
/// from rest. A broadcaster that takes the subject clears its row, and the
/// object goes when nothing else names it; any other word is a hint, kept
/// with one more attempt and the fees' backoff. With no broadcaster named,
/// nothing is asked. `Err` is a ledger that could not be read.
pub async fn reask_announces(seams: &Seams<'_>, now: u64, limit: u32) -> Result<Reasked, String> {
    let mut reasked = Reasked::default();
    let Some(announcer) = seams.announcer else {
        return Ok(reasked);
    };
    for owed in seams.ledger.due_announces(now, limit).await? {
        let word = match seams.blobs.stamp(&owed.key).await {
            Ok(Some(stamp)) if stamp.etag == owed.etag => {
                match announcer
                    .announce(Subject::AtRest {
                        key: &owed.key,
                        stamp: &stamp,
                    })
                    .await
                {
                    Ok(hint) if hint.accepted => {
                        seams.ledger.announced(&owed.key).await?;
                        let _ = reclaim(seams, &owed.key).await;
                        reasked.accepted += 1;
                        continue;
                    }
                    Ok(hint) => hint.word,
                    Err(e) => format!("no answer: {}", e),
                }
            }
            Ok(Some(_)) => "another upload is at the key".to_string(),
            Ok(None) => "the object is not in the store".to_string(),
            Err(e) => e,
        };
        let attempts = owed.attempts.saturating_add(1);
        seams
            .ledger
            .put_off_announce(&owed.key, attempts, now + backoff_secs(attempts), &word)
            .await?;
        reasked.put_off += 1;
    }
    Ok(reasked)
}

// ---------------------------------------------------------------------------
// The readers of a row
// ---------------------------------------------------------------------------

/// The largest `payment.tx` a list reader hands back inside a row, in bytes
/// of its JSON text (0.4.4, bsv-low #591 M1; 0.4.0 to 0.4.3 counted BEEF
/// bytes): D1's bound on a row, so every payment a row ever carried, whose
/// text was in the row, is still served the way it was. A larger one is
/// served by its key (`/beef/download-url`). A way of serving, never a
/// refusal.
pub const LIST_INLINE_OBJECT_BYTES: u64 = 2_000_000;

/// The text one list response is built to, every body it serves counted in
/// bytes of its JSON text (0.4.4, M1 and NOTE-3; 0.4.0 to 0.4.3 counted 32
/// MiB of BEEF bytes, which a byte array makes about 115 MiB of text): about
/// 16 MB, an eighth of the isolate's 128 MB, so the response, its escaped
/// copy in the reply and the rows read from D1 stay well inside it. A row
/// past it waits for the next listing.
pub const LIST_INLINE_BYTES: u64 = 16 * 1024 * 1024;

/// What one list response may still hand back, in bytes of text.
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

/// A stored row's body for a list response, its text counted against the
/// response's budget. A row whose payment names bytes at rest gets them back
/// as `payment.tx`, in the shape the sender sent, streamed from the store and
/// written straight to text, when that text is no longer than
/// `LIST_INLINE_OBJECT_BYTES`; a larger payment, or one whose bytes the store
/// could not give (or are no longer the upload the door verified), is served
/// as stored, by its key. Every other body is served as stored, untouched. A
/// row whose text the budget no longer covers is left for the next listing,
/// before its bytes are read.
pub async fn serve_body<'a>(
    body: &'a str,
    blobs: &dyn BeefStore,
    budget: &mut ListBudget,
) -> Served<'a> {
    let as_stored = |budget: &mut ListBudget| match budget.bytes.checked_sub(body.len() as u64) {
        Some(left) => {
            budget.bytes = left;
            Served::Body(Cow::Borrowed(body))
        }
        None => Served::NextListing,
    };
    if !body.contains("\"beefR2Key\"") {
        return as_stored(budget);
    }
    let Ok(mut row) = serde_json::from_str::<Value>(body) else {
        return as_stored(budget);
    };
    let Some((key, stamp, shape)) = row.get("payment").and_then(rest_of) else {
        return as_stored(budget);
    };
    // A row served by its key carries the payment's reference and the
    // reader's words (0.4.4, bsv-low #591 NOTE-2): `payment.tx` is absent,
    // and a recipient that reads it (the reference client throws on a
    // missing `tx` and keeps the payment on the message, ts-stack@edf6e03
    // packages/messaging/message-box-client/src/MessageBoxClient.ts:580,
    // 2109-2131, 2155-2166) has the key and what to do with it beside it.
    let by_key = |mut row: Value, words: String, budget: &mut ListBudget| {
        row["payment"]["key"] = json!(key);
        row["payment"]["words"] = json!(words);
        let text = row.to_string();
        match budget.bytes.checked_sub(text.len() as u64) {
            Some(left) => {
                budget.bytes = left;
                Served::Body(Cow::Owned(text))
            }
            None => Served::NextListing,
        }
    };
    let text = encoded_len(stamp.size, shape);
    if text > LIST_INLINE_OBJECT_BYTES {
        let words = format!(
            "This payment's BEEF ({} bytes) is not in the listing: it rests at its key, {}. Ask POST /beef/download-url with this message's messageId for a URL to read it from, and internalize it from there.",
            stamp.size, key
        );
        return by_key(row.clone(), words, budget);
    }
    // The body, the payment's text, and `,"tx":` between them.
    if text + body.len() as u64 + 6 > budget.bytes {
        return Served::NextListing;
    }
    let Ok(tx) = tx_text(blobs, key, &stamp, shape).await else {
        let words = format!(
            "This payment's BEEF could not be read back for this listing: it rests at its key, {}. List again, or ask POST /beef/download-url with this message's messageId.",
            key
        );
        return by_key(row.clone(), words, budget);
    };
    // The text goes in where a mark nobody else can write stands.
    let mark = format!("rmb-tx-{}", uuid::Uuid::new_v4().simple());
    row["payment"]["tx"] = json!(mark);
    let served = row.to_string().replacen(&format!("\"{}\"", mark), &tx, 1);
    budget.bytes = budget.bytes.saturating_sub(served.len() as u64);
    Served::Body(Cow::Owned(served))
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
        /// The deployment names no bucket (`bucket_name`).
        pub(crate) nameless: Cell<bool>,
        /// Each object's `READER_METADATA`.
        pub(crate) readers: RefCell<HashMap<String, String>>,
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
            reader: &str,
        ) -> Result<Stamp, String> {
            if self.down.get() {
                return Err("the store is down".to_string());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = chunks.next().await? {
                bytes.extend_from_slice(&chunk);
            }
            assert_eq!(bytes.len() as u64, size);
            self.readers
                .borrow_mut()
                .insert(key.to_string(), reader.to_string());
            Ok(self.put(key, &bytes, "spooled"))
        }

        async fn reader(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.readers.borrow().get(key).cloned())
        }

        fn bucket_name(&self) -> Option<String> {
            (!self.nameless.get()).then(|| "bsv-messagebox-beefs".to_string())
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
            let Served::Body(text) = serve_body(&body, &blobs, &mut budget).await else {
                panic!("served");
            };
            // The text written straight is the text of the row built as a
            // value, byte for byte (0.4.3's way).
            let mut built: Value = serde_json::from_str(&body).unwrap();
            built["payment"]["tx"] = tx.clone();
            assert_eq!(text, built.to_string(), "{shape:?}");
            assert!(text.len() as u64 <= encoded_len(1_000, shape) + body.len() as u64 + 6);
            let row: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(row["payment"]["tx"], tx, "{shape:?}");
            assert_eq!(row["payment"]["beefR2Key"], KEY, "the key stays beside it");
            assert_eq!(row["payment"]["txid"], "aa");
            assert_eq!(row["message"], "hello");
            assert_eq!(blobs.opened.get(), 1, "one read of the object");
            assert_eq!(budget.bytes, LIST_INLINE_BYTES - text.len() as u64);
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
        // NOTE-2 (bsv-low #591, 0.4.4): the payment's reference and the
        // reader's words, so a recipient that reads `payment.tx` and finds
        // none is handed the key's word with the payment it keeps.
        assert_eq!(row["payment"]["key"], KEY);
        let words = row["payment"]["words"]
            .as_str()
            .expect("the reader's words");
        assert!(
            words.contains("/beef/download-url") && words.contains(KEY),
            "{words}"
        );
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
        assert_eq!(row["payment"]["key"], KEY, "served by key, and it says so");
        assert!(row["payment"]["words"].as_str().is_some(), "{row}");

        blobs.put(KEY, &beef, "e1");
        blobs.down.set(true);
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none(), "{row}");
        assert_eq!(row["message"], "hello", "the message is delivered");

        blobs.objects.borrow_mut().clear();
        blobs.down.set(false);
        let row = served(&body, &blobs, &mut budget).await;
        assert!(row["payment"].get("tx").is_none(), "{row}");
        let spent = LIST_INLINE_BYTES - budget.bytes;
        assert!(
            spent > 3 * body.len() as u64 && spent < 3 * 1_024,
            "three rows served by key, their words beside them, and no BEEF: {spent}"
        );
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
        // Room for one row's text (the body and 1,202 bytes of hex), not
        // two.
        let mut budget = ListBudget {
            bytes: body.len() as u64 + 1_202 + 100,
        };
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

    /// M1 (bsv-low #591): the budget is the response's text, not the BEEF's
    /// bytes. Twelve rows of a 450,000-byte BEEF sent as a byte array fit
    /// 0.4.3's 32 MiB of BEEF whole; as text they are at most 1,800,002
    /// bytes each (under a row's 2,000,000; 1,602,977 as written), so a
    /// response of about 16 MB serves ten inline and leaves the eleventh for
    /// the next listing before it is read or encoded.
    #[tokio::test]
    async fn a_listing_whose_beef_fits_the_old_budget_and_whose_text_does_not_stops_before_encoding(
    ) {
        let beef = bytes(450_000);
        let blobs = Mem::default();
        let stamp = blobs.put(KEY, &beef, "e1");
        let body = row(&payment_at_rest(
            &json!({}),
            KEY,
            &stamp,
            TxShape::Array,
            Some("aa"),
        ));
        let mut budget = ListBudget::default();
        let mut served = Vec::new();
        for _ in 0..12 {
            match serve_body(&body, &blobs, &mut budget).await {
                Served::Body(text) => served.push(text.len()),
                Served::NextListing => break,
            }
        }
        let text: usize = served.iter().sum();
        assert_eq!(served.len(), 10, "ten rows of {served:?}");
        assert!(text as u64 <= 16 * 1024 * 1024, "{text} bytes of text");
        assert_eq!(blobs.opened.get(), 10, "the eleventh is not read");
    }

    // ---- the hand-off ----

    /// wallet-infra with a scripted answer; counts what it is asked.
    struct Scripted {
        answer: Result<bool, String>,
        asked: Cell<usize>,
    }

    #[async_trait::async_trait(?Send)]
    impl FeeWallet for Scripted {
        async fn internalize(&self, _args: &Value) -> Result<bool, String> {
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
        async fn owe_announce(&self, _: &OwedAnnounce, _: &str) -> Result<(), String> {
            Ok(())
        }
        async fn end(&self, key: &str, _why: &str) -> Result<(), String> {
            self.rows.borrow_mut().retain(|row| row.key != key);
            Ok(())
        }
        async fn figure(&self) -> Result<FeeFigure, String> {
            Ok(FeeFigure::default())
        }
        async fn wallet_word(&self) -> Result<Option<(String, u64)>, String> {
            Ok(None)
        }
        async fn set_wallet_word(&self, _: Option<&str>, _: u64) -> Result<(), String> {
            Ok(())
        }
        async fn due_announces(&self, _: u64, _: u32) -> Result<Vec<OwedAnnounce>, String> {
            Ok(Vec::new())
        }
        async fn announced(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        async fn put_off_announce(&self, _: &str, _: u32, _: u64, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    /// The stored rows as a list of the keys they name, and the keys let go
    /// of; or rows that cannot be read.
    #[derive(Default)]
    struct Named {
        keys: RefCell<Vec<String>>,
        released: RefCell<Vec<String>>,
        down: Cell<bool>,
        /// A send that names this key right after a look answers that
        /// nothing names it: the race between the look and the delete.
        renamed_after_look: RefCell<Option<String>>,
    }

    #[async_trait::async_trait(?Send)]
    impl RowRefs for Named {
        async fn names(&self, key: &str) -> Result<bool, String> {
            if self.down.get() {
                return Err("D1_ERROR: unavailable".to_string());
            }
            let named = self.keys.borrow().iter().any(|named| named == key);
            if self.renamed_after_look.borrow().as_deref() == Some(key) {
                self.renamed_after_look.borrow_mut().take();
                self.keys.borrow_mut().push(key.to_string());
            }
            Ok(named)
        }
        async fn released(&self, limit: u32) -> Result<Vec<String>, String> {
            let released = self.released.borrow();
            Ok(released.iter().take(limit as usize).cloned().collect())
        }
        async fn forget(&self, key: &str) -> Result<(), String> {
            self.released.borrow_mut().retain(|k| k != key);
            Ok(())
        }
        async fn claim(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }
        async fn unclaim(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }
        async fn claimed(&self, _key: &str) -> Result<bool, String> {
            Ok(false)
        }
        async fn mint(&self, _key: &str, _deadline: u64) -> Result<(), String> {
            Ok(())
        }
        async fn minted_due(&self, _now: u64, _limit: u32) -> Result<Vec<String>, String> {
            Ok(Vec::new())
        }
        async fn postpone_minted(&self, _key: &str, _deadline: u64) -> Result<(), String> {
            Ok(())
        }
        async fn forget_minted(&self, _key: &str) -> Result<(), String> {
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
                announcer: None,
            },
            &Paid {
                payment,
                r2_key: None,
                spooled: None,
                spool_key: KEY,
                server_output: fee_owed.then_some(&server_output),
                stamp: None,
                txid: fee_owed.then_some("aa"),
                rows,
                reader: "02relay",
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
            announcer: None,
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

    /// L2 (bsv-low #591): the reclaim was a look (`names`, `owes`) and then a
    /// delete, so a send that named the key between the two lost its bytes.
    /// Since 0.4.4 the reclaim looks again after its claim and holds the
    /// delete to the etag it looked at: the re-named object stays.
    #[tokio::test]
    async fn a_concurrent_re_name_between_the_look_and_the_delete_loses_nothing() {
        let blobs = Mem::default();
        let wallet = accepts();
        let ledger = Owed::default();
        let rows = Named::default();
        let seams = Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
            announcer: None,
        };
        blobs.put(KEY, &bytes(10), "e1");
        *rows.renamed_after_look.borrow_mut() = Some(KEY.to_string());
        assert_eq!(reclaim(&seams, KEY).await, Ok(false));
        assert!(
            blobs.objects.borrow().contains_key(KEY),
            "the re-named object stays"
        );
        assert!(
            rows.names(KEY).await.unwrap(),
            "and the send's row names it"
        );
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
            announcer: None,
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
    async fn a_box_that_owes_no_delivery_fee_keeps_the_recipients_payment_in_its_row_and_spools_nothing(
    ) {
        // M3 (bsv-low #591): a body nobody judged is never spooled. 0.4.0 to
        // 0.4.3 put it at rest and named it in the row; 0.3.x's row carried
        // it, bounded by the row, and so does 0.4.4's.
        let (blobs, wallet, ledger) = (Mem::default(), accepts(), Owed::default());
        let payment = json!({ "tx": hex::encode(bytes(50)), "description": "d" });
        let handed = handed(&blobs, &wallet, &ledger, &payment, false, true)
            .await
            .unwrap();
        assert_eq!(handed.fee, Fee::NotOwed);
        assert_eq!(wallet.asked.get(), 0);
        assert_eq!(handed.kept, None, "nothing at rest");
        assert!(blobs.objects.borrow().is_empty(), "nothing spooled");
        assert_eq!(handed.payment["verdict"], "notJudged");
        assert_eq!(handed.payment["tx"], payment["tx"], "the bytes in the row");
        assert_eq!(handed.payment["description"], "d");
        assert!(handed.payment.get("beefR2Key").is_none());
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

    // ---- the reference ----

    /// wallet-infra keeping each argument it is handed.
    #[derive(Default)]
    struct Recording(RefCell<Vec<Value>>);

    #[async_trait::async_trait(?Send)]
    impl FeeWallet for Recording {
        async fn internalize(&self, args: &Value) -> Result<bool, String> {
            self.0.borrow_mut().push(args.clone());
            Ok(true)
        }
    }

    fn owed_at(key: &str, etag: &str) -> Owed {
        Owed {
            rows: RefCell::new(vec![DeferredFee {
                key: key.to_string(),
                etag: etag.to_string(),
                txid: "aa".into(),
                args: fee_args(&json!({ "outputIndex": 0 }), &json!({})).to_string(),
                named: false,
                attempts: 0,
                next_at: 0,
            }]),
            down: false,
        }
    }

    #[test]
    fn the_reference_is_the_four_fields_with_the_etag_unquoted() {
        let stamp = Stamp {
            size: 8_388_636,
            etag: "\"0f343b0931126a20f133d67c2b018a3b\"".into(),
        };
        let reference = beef_at_rest(KEY, &stamp, "bsv-messagebox-beefs");
        assert_eq!(
            reference,
            json!({
                "r2Key": KEY,
                "size": 8_388_636u64,
                "etag": "0f343b0931126a20f133d67c2b018a3b",
                "bucket": "bsv-messagebox-beefs"
            })
        );
        let args = internalize_at_rest(
            reference,
            &fee_args(&json!({ "outputIndex": 0 }), &json!({})),
        );
        assert!(args.get("tx").is_none(), "no tx beside the reference");
        assert_eq!(args["outputs"], json!([{ "outputIndex": 0 }]));
        assert_eq!(args["seekPermission"], false);
        let inline = internalize_inline("0100", &json!({}));
        assert_eq!(inline["tx"], "0100");
        assert!(inline.get("beefAtRest").is_none());
    }

    #[tokio::test]
    async fn the_drain_hands_the_reference_and_never_opens_the_object() {
        let blobs = Mem::default();
        let stamp = blobs.put(KEY, &bytes(9 * 1024 * 1024), "e1");
        let (wallet, ledger, rows) = (Recording::default(), owed_at(KEY, "e1"), Named::default());
        let seams = Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
            announcer: None,
        };
        let drained = drain_fees(&seams, 0, DRAIN_BATCH).await.unwrap();
        assert_eq!(drained.settled, 1);
        assert_eq!(blobs.opened.get(), 0, "the relay reads none of the bytes");
        let handed = wallet.0.borrow();
        assert_eq!(
            handed[0]["beefAtRest"],
            beef_at_rest(KEY, &stamp, "bsv-messagebox-beefs")
        );
    }

    #[tokio::test]
    async fn a_deployment_that_names_no_bucket_holds_the_fee_and_sends_nothing() {
        let blobs = Mem::default();
        blobs.nameless.set(true);
        blobs.put(KEY, &bytes(100), "e1");
        let (wallet, ledger, rows) = (Recording::default(), owed_at(KEY, "e1"), Named::default());
        let seams = Seams {
            blobs: &blobs,
            wallet: &wallet,
            ledger: &ledger,
            rows: &rows,
            announcer: None,
        };
        let drained = drain_fees(&seams, 0, DRAIN_BATCH).await.unwrap();
        assert_eq!((drained.settled, drained.ended), (0, 1));
        assert!(wallet.0.borrow().is_empty(), "never the bytes in its place");
        // 0.4.4 (R403-L1): a reason that cannot clear by itself ends the fee
        // at once; 0.4.3 kept it and retried it daily.
        assert!(ledger.rows.borrow().is_empty(), "ended, never retried");
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
