//! The payment door's reader (0.4.0, the no-limits program): a payment's BEEF
//! read as a stream, one element in hand, never refused for its size or its
//! counts.
//!
//! The reader is bsv-rs 0.4.3's `StreamVerifier`
//! (`src/transaction/beef_stream.rs:2641-2758`): one step per element, a
//! `Cursor` between any two. What it holds is the element in hand and its
//! index (one entry per element); what it refuses is invalid bytes, at an
//! offset, by one of twenty kinds, none of which is a size or a count. The
//! nineteenth is 0.4.1's: a transaction with no input is no transaction
//! (`Kind::NoInputs`, at its leading byte), with or without a BUMP. The
//! twentieth is 0.4.3's (#59): a transaction with an input and no output is
//! no transaction either (`Kind::NoOutputs`, at its leading byte); one with
//! neither is `NoInputs`, the node's order.
//!
//! The reading runs the scripts (NL-4c): every input of an unproven
//! transaction is executed against the parent output the index kept, and an
//! unproven transaction may not pay out more than it spends
//! (`StreamVerifier::new`, `BeefIndex::check_spends_of`, `:2063-2167`). A
//! spend the interpreter refuses is refused here, at the input's offset
//! (`SpendRefused`): a payment whose ancestry nobody signed is no payment.
//! What that costs is said plainly: beside the index the reader keeps each
//! transaction's outputs until an input of the BEEF spends them, so an
//! output nothing in the BEEF spends is held to the end of the reading.
//!
//! The six words are bsv-middleware-rs 0.4.1's. Its `verify_payment` reads
//! the whole payment in one pass (`verify_stream` behind a tee,
//! `src/payment_core.rs:350-364`) and keeps no cursor, so a payment at rest
//! could not be read across requests through it. The door reads the structure
//! and the scripts itself and hands the middleware the one thing its words
//! are about: the subject transaction, for the output check
//! (`verify_payment_output_only`). The order is the middleware's
//! (`src/payment_core.rs:578-652`): no header service; then the bytes and the
//! spends (`InvalidBeef`, `SpendRefused`); then the output (script, then
//! amount); then a proof; then a height no header can carry; then the roots,
//! lowest height first, a root the header does not carry before a lookup that
//! could not answer. No root is asked before the output is judged, so a
//! payment that does not pay costs the header service nothing; no payment is
//! accepted with a root unasked.
//!
//! Two sources: the inline `payment.tx` (`Carrier`, decoded a chunk at a time
//! from the JSON value the request carried; the BRC-31 layer, bsv-middleware-
//! cloudflare 0.5.0, has read that body whole before the route runs, as it
//! signs over it: `src/transport/cloudflare.rs:168-178`) and an object at rest
//! (`BeefStore`, the R2 bucket in the Worker). Only bytes at rest can be
//! resumed: `verify_at_rest` reads for one slice of time, saves the cursor
//! beside the object and answers `Pending`; the next request continues from
//! the cursor's offset.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bsv_middleware_rs::{
    verify_payment_output_only, HeaderLookupError, HeaderService, PaymentToVerify, PaymentVerdict,
    UnverifiableReason,
};
use bsv_rs::transaction::beef_stream::{display_hex, Hash32};
use bsv_rs::transaction::{Cursor, Headers, Progress, StreamVerifier, Verdict};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The bytes the door decodes from an inline payment at a time.
const CHUNK: usize = 64 * 1024;

/// The time one request reads an object at rest before it saves its cursor:
/// a slice of the work, not a bound on it. A Worker's request has 30 s of CPU
/// by default; the clock here is wall time read at each chunk of the object
/// (it only moves at I/O), which is never less than the CPU spent.
pub const VERIFY_SLICE_MILLIS: u64 = 15_000;

/// The header lookups one request makes for an object at rest before it saves
/// its place: each is a subrequest, and a request has a bounded number of
/// those. A slice, not a bound.
pub const ROOT_LOOKUPS_PER_PASS: usize = 500;

// ---------------------------------------------------------------------------
// The sources
// ---------------------------------------------------------------------------

/// A BEEF's bytes, a chunk at a time.
#[async_trait::async_trait(?Send)]
pub trait Chunks {
    /// The next chunk, `None` at the end, or why the source failed.
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String>;
}

/// The inline payment transaction, in the shapes this server receives: a JSON
/// byte array (BRC-100), a hex string, or `{ "beef": <base64> }`. The value is
/// the request's own; nothing is decoded but the chunk being read.
#[derive(Debug, Clone, Copy)]
pub enum Carrier<'a> {
    Array(&'a [Value]),
    Hex(&'a str),
    Base64(&'a str),
}

impl<'a> Carrier<'a> {
    /// The carrier of `tx`, or `None` when it is none of the three shapes or
    /// does not decode (a byte above 255, a character outside the alphabet, a
    /// length no encoding has). The check keeps no decoded byte.
    pub fn of(tx: &'a Value) -> Option<Self> {
        let carrier = match tx {
            Value::Array(items) => {
                let bytes = |v: &Value| v.as_u64().is_some_and(|n| n <= 255);
                items.iter().all(bytes).then_some(Carrier::Array(items))?
            }
            Value::String(h) => {
                let hex = h.len() % 2 == 0 && h.bytes().all(|c| c.is_ascii_hexdigit());
                hex.then_some(Carrier::Hex(h))?
            }
            Value::Object(o) => Carrier::Base64(o.get("beef")?.as_str()?),
            _ => return None,
        };
        if let Carrier::Base64(b) = carrier {
            // The standard alphabet with padding, as before: each chunk but
            // the last is whole groups with no padding in it.
            if b.len() % 4 != 0 {
                return None;
            }
            let mut scratch = Vec::with_capacity(CHUNK);
            let groups = b.as_bytes().chunks(CHUNK / 3 * 4);
            let last = groups.len().saturating_sub(1);
            for (i, group) in groups.enumerate() {
                if i != last && group.contains(&b'=') {
                    return None;
                }
                scratch.clear();
                B64.decode_vec(group, &mut scratch).ok()?;
            }
        }
        Some(carrier)
    }

    /// The decoded length in bytes.
    pub fn len(&self) -> u64 {
        (match self {
            Carrier::Array(items) => items.len(),
            Carrier::Hex(h) => h.len() / 2,
            Carrier::Base64(b) => {
                b.len() / 4 * 3 - b.bytes().rev().take(2).filter(|c| *c == b'=').count()
            }
        }) as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// At most `max` decoded bytes from the decoded offset `from`.
    pub fn bytes(&self, from: u64, max: usize) -> Vec<u8> {
        let from = from.min(self.len()) as usize;
        let take = max.min(self.len() as usize - from);
        match self {
            Carrier::Array(items) => items[from..from + take]
                .iter()
                .map(|v| v.as_u64().unwrap_or(0) as u8)
                .collect(),
            Carrier::Hex(h) => hex::decode(&h[2 * from..2 * (from + take)]).unwrap_or_default(),
            Carrier::Base64(b) => {
                let skip = from % 3;
                let first = from / 3 * 4;
                let groups = (skip + take).div_ceil(3) * 4;
                let end = (first + groups).min(b.len());
                let mut out = B64.decode(&b[first..end]).unwrap_or_default();
                out.drain(..skip.min(out.len()));
                out.truncate(take);
                out
            }
        }
    }

    /// The carrier's bytes from `from`, as chunks.
    pub fn chunks(&self, from: u64) -> CarrierChunks<'a> {
        CarrierChunks {
            carrier: *self,
            at: from,
        }
    }
}

/// An inline payment's bytes, decoded as they are asked for.
pub struct CarrierChunks<'a> {
    carrier: Carrier<'a>,
    at: u64,
}

#[async_trait::async_trait(?Send)]
impl Chunks for CarrierChunks<'_> {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let chunk = self.carrier.bytes(self.at, CHUNK);
        self.at += chunk.len() as u64;
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

/// What the verifier reads from: the one chunk the door has fetched and not
/// yet handed over. Empty and not ended is `WouldBlock`: the door fetches the
/// next chunk and steps again (`BeefStream::next_element` keeps its decoder
/// across a failed read, bsv-rs 0.4.3 `beef_stream.rs:1570-1599`, and
/// `StreamVerifier::step` latches no verdict on one, `:2721-2748`).
#[derive(Clone, Default)]
struct Feed(Rc<RefCell<FeedState>>);

#[derive(Default)]
struct FeedState {
    chunks: VecDeque<Vec<u8>>,
    at: usize,
    ended: bool,
}

impl Feed {
    fn push(&self, chunk: Vec<u8>) {
        self.0.borrow_mut().chunks.push_back(chunk);
    }

    fn end(&self) {
        self.0.borrow_mut().ended = true;
    }
}

impl Read for Feed {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut state = self.0.borrow_mut();
        loop {
            let at = state.at;
            match state.chunks.front() {
                Some(chunk) if at < chunk.len() => {
                    let n = out.len().min(chunk.len() - at);
                    out[..n].copy_from_slice(&chunk[at..at + n]);
                    state.at += n;
                    return Ok(n);
                }
                Some(_) => {
                    state.chunks.pop_front();
                    state.at = 0;
                }
                None if state.ended => return Ok(0),
                None => return Err(ErrorKind::WouldBlock.into()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The reading
// ---------------------------------------------------------------------------

/// The headers of the reading itself: every root is carried here and asked
/// afterwards (`roots_word`), in the six words' order. The reading's verdict
/// is on the structure and the spends; the door accepts nothing on it alone.
struct AskedAfter;

impl Headers for AskedAfter {
    fn carries(&self, _height: u64, _root: &Hash32) -> bool {
        true
    }
}

/// A slice of time for one request: the clock (milliseconds) and how long to
/// read before the cursor is saved.
pub struct Slice<'a> {
    pub clock: &'a dyn Fn() -> u64,
    pub millis: u64,
}

/// What one reading came to.
enum Reading {
    /// The structure is valid and every unproven spend is one its script
    /// allows; the cursor is the state at the stream's end.
    Valid(Cursor),
    /// Invalid bytes, or a spend the interpreter refused.
    Refused(Verdict),
    /// The slice is spent; the cursor is the state between two elements.
    Paused(Cursor),
}

/// Reads `chunks` (positioned at the start, or at the cursor's offset) to a
/// verdict, or until the slice is spent and the element in hand is done. The
/// slice is looked at when a chunk is fetched, so every reading that fetches
/// one finishes at least one element.
async fn read(
    from: Option<Cursor>,
    chunks: &mut dyn Chunks,
    slice: Option<&Slice<'_>>,
) -> Result<Reading, String> {
    let feed = Feed::default();
    let mut verifier = match from {
        Some(cursor) => StreamVerifier::resume(cursor, feed.clone(), AskedAfter),
        None => StreamVerifier::new(feed.clone(), AskedAfter, None),
    };
    let started = slice.map(|s| (s.clock)());
    let mut pause = false;
    loop {
        match verifier.step() {
            Ok(Progress::Stepped) if pause => return Ok(Reading::Paused(verifier.cursor())),
            Ok(Progress::Stepped) => {}
            Ok(Progress::Verdict(Verdict::Valid { .. })) => {
                return Ok(Reading::Valid(verifier.cursor()))
            }
            Ok(Progress::Verdict(refused)) => return Ok(Reading::Refused(refused)),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if let (Some(slice), Some(started)) = (slice, started) {
                    pause |= (slice.clock)().saturating_sub(started) >= slice.millis;
                }
                match chunks.next().await? {
                    Some(chunk) => feed.push(chunk),
                    None => feed.end(),
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// The words
// ---------------------------------------------------------------------------

/// The bytes a refusal names: the stream offset and the kind (one of the
/// reader's twenty, or `SpendRefused` at the offset of the input whose
/// spend the interpreter refused).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub offset: u64,
    pub kind: String,
}

/// The door's verdict: one of the six words; when the bytes are why, the
/// bytes; and on `Verified` the subject's txid (internal byte order), which
/// the hand-off keeps beside the bytes at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoorVerdict {
    pub word: PaymentVerdict,
    pub named: Option<Named>,
    pub subject: Option<Hash32>,
}

impl DoorVerdict {
    /// The subject's txid as it is displayed, when the payment is verified.
    pub fn txid(&self) -> Option<String> {
        self.subject.as_ref().map(display_hex)
    }
}

impl From<PaymentVerdict> for DoorVerdict {
    fn from(word: PaymentVerdict) -> Self {
        Self {
            word,
            named: None,
            subject: None,
        }
    }
}

/// The word on the roots with the subject it is about: named on `Verified`
/// and on no other word.
fn judged(word: PaymentVerdict, subject: Hash32) -> DoorVerdict {
    let subject = matches!(word, PaymentVerdict::Verified { .. }).then_some(subject);
    DoorVerdict {
        word,
        named: None,
        subject,
    }
}

/// The payment as the six words judge it: the output that is paid, the script
/// it must carry and the price.
#[derive(Debug, Clone, Copy)]
pub struct Terms<'a> {
    pub output_index: u32,
    pub expected_script: &'a [u8],
    pub required_satoshis: u64,
}

/// Why the door could not answer: neither says anything about the payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoorError {
    /// The bytes could not be read (the object store failed).
    Source(String),
    /// The door could not read back what it verified.
    Internal(String),
}

/// A refusal of the reading in the middleware's words, bsv-middleware-rs
/// 0.4.1's own (`src/payment_core.rs:122-168`): invalid bytes are
/// `InvalidBeef` with the offset and the kind (a transaction with no input or
/// no output is one), a spend the interpreter refused is `SpendRefused` at its input. Both
/// are the payer's side. The route's body names the offset and the kind.
fn refusal_word(refused: Verdict) -> DoorVerdict {
    let (reason, named) = match refused {
        Verdict::Invalid {
            offset,
            kind,
            reason,
        } => (
            UnverifiableReason::InvalidBeef {
                offset,
                kind,
                reason,
            },
            Named {
                offset,
                kind: format!("{:?}", kind),
            },
        ),
        Verdict::SpendRefused {
            offset,
            txid,
            input,
            why,
        } => (
            UnverifiableReason::SpendRefused {
                offset,
                txid: display_hex(&txid),
                input,
                why,
            },
            Named {
                offset,
                kind: "SpendRefused".to_string(),
            },
        ),
        // A reading that ended valid is no refusal: this cannot come back,
        // and is a refusal if it does.
        Verdict::Valid { .. } => (
            UnverifiableReason::MalformedTransaction("a valid reading refused".to_string()),
            Named {
                offset: 0,
                kind: "Valid".to_string(),
            },
        ),
    };
    DoorVerdict {
        word: PaymentVerdict::Unverifiable(reason),
        named: Some(named),
        subject: None,
    }
}

fn malformed(what: impl Into<String>) -> PaymentVerdict {
    PaymentVerdict::Unverifiable(UnverifiableReason::MalformedTransaction(what.into()))
}

/// The last raw transaction a reading folded and the offset of its leading
/// byte: the subject. bsv-rs 0.4.3's verifier does not hand out the element
/// it stepped, so this is read from the cursor's own bytes
/// (`Cursor::to_binary`, `beef_stream.rs:2322-2362`, byte for byte 0.4.1's:
/// the magic `BSC1`, the frame, then the index's `last_raw`). The door holds the bytes it then
/// fetches to this txid (`subject_raw`), so a cursor laid out otherwise is an
/// error here and never a wrong answer.
fn tip_of(cursor: &Cursor) -> Result<Option<(Hash32, u64)>, DoorError> {
    let bin = cursor.to_binary();
    let short = || DoorError::Internal("the cursor's bytes are not the layout read".to_string());
    let mut at = 0usize;
    let mut take = |n: usize| {
        let slice = bin.get(at..at + n).ok_or_else(short);
        at += n;
        slice
    };
    if take(4)? != b"BSC1" {
        return Err(short());
    }
    take(1)?; // spends checked
    if take(1)?[0] == 1 {
        take(32)?; // the subject the caller named
    }
    take(8 + 8 + 1 + 4)?; // the frame: offset, elements, phase, version
    if take(1)?[0] == 1 {
        take(32)?; // the prefix's subject
    }
    take(8 + 8 + 8 + 8)?; // BUMPs left, transactions left, steps, work
    match take(1)?[0] {
        0 => Ok(None),
        1 => {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(take(32)?);
            let mut le = [0u8; 8];
            le.copy_from_slice(take(8)?);
            Ok(Some((txid, u64::from_le_bytes(le))))
        }
        _ => Err(short()),
    }
}

/// The length of the raw transaction (BRC-12) `bytes` starts with.
fn raw_tx_len(bytes: &[u8]) -> Option<usize> {
    fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
        let lead = *bytes.get(*at)?;
        let n = match lead {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => {
                *at += 1;
                return Some(lead as u64);
            }
        };
        let mut le = [0u8; 8];
        le[..n].copy_from_slice(bytes.get(*at + 1..*at + 1 + n)?);
        *at += 1 + n;
        Some(u64::from_le_bytes(le))
    }
    fn skip(bytes: &[u8], at: &mut usize, n: u64) -> Option<()> {
        let end = at.checked_add(usize::try_from(n).ok()?)?;
        (end <= bytes.len()).then(|| *at = end)
    }
    let mut at = 0usize;
    skip(bytes, &mut at, 4)?;
    for _ in 0..varint(bytes, &mut at)? {
        skip(bytes, &mut at, 36)?;
        let script = varint(bytes, &mut at)?;
        skip(bytes, &mut at, script)?;
        skip(bytes, &mut at, 4)?;
    }
    for _ in 0..varint(bytes, &mut at)? {
        skip(bytes, &mut at, 8)?;
        let script = varint(bytes, &mut at)?;
        skip(bytes, &mut at, script)?;
    }
    skip(bytes, &mut at, 4)?;
    Some(at)
}

/// The subject's raw bytes out of the stream's tail (the bytes from the
/// subject's leading byte on), held to the txid the reading folded.
fn subject_raw(mut tail: Vec<u8>, txid: &Hash32) -> Result<Vec<u8>, DoorError> {
    let wrong = || DoorError::Internal("the subject read back is not the one verified".to_string());
    tail.truncate(raw_tx_len(&tail).ok_or_else(wrong)?);
    let hashed: Hash32 = Sha256::digest(Sha256::digest(&tail)).into();
    (hashed == *txid).then_some(tail).ok_or_else(wrong)
}

/// The middleware's output check on the subject: script first, then amount
/// (`verify_payment_output_only`, bsv-middleware-rs 0.4.1
/// `src/payment_core.rs:404-441`), over the subject's bytes as a byte source.
/// The subject is handed over as a BEEF of that one transaction, so a
/// transaction whose version word is a BEEF's is still read as a transaction.
/// The bytes are in hand, so the source cannot fail; if it did, the word is
/// the payer's: nothing was read.
fn output_word(subject: &[u8], terms: &Terms<'_>) -> PaymentVerdict {
    let mut beef = Vec::with_capacity(subject.len() + 7);
    beef.extend_from_slice(&[0x02, 0x00, 0xBE, 0xEF, 0, 1, 0]);
    beef.extend_from_slice(subject);
    verify_payment_output_only(
        &PaymentToVerify {
            output_index: terms.output_index,
            expected_script: terms.expected_script,
            required_satoshis: terms.required_satoshis,
        },
        &beef[..],
    )
    .unwrap_or_else(|e| malformed(e.to_string()))
}

/// The roots of a reading, each once, lowest height first.
fn roots_of(cursor: &Cursor) -> Vec<(u64, Hash32)> {
    let mut roots = cursor.index().roots().to_vec();
    roots.sort_unstable();
    roots.dedup();
    roots
}

/// What asking the roots came to.
enum Rooted {
    /// A word. `failed_at` is the place of the first root whose lookup could
    /// not answer, when that is the word.
    Word {
        word: PaymentVerdict,
        failed_at: Option<usize>,
    },
    /// The lookups of this request are spent at this root.
    Paused(usize),
}

/// Every root from `from` on asked of the header service (bsv-middleware-rs
/// 0.4.1 `src/payment_core.rs:617-652`): a root the header does not carry is
/// `RootMismatch` at once; a lookup that could not answer is remembered, the
/// rest are still asked, and the first such is the word; with every root
/// carried, `Verified`. One lookup per height.
async fn roots_word(
    roots: &[(u64, Hash32)],
    from: usize,
    lookups: Option<usize>,
    headers: &dyn HeaderService,
    satoshis: u64,
) -> Rooted {
    if roots.is_empty() {
        return Rooted::Word {
            word: PaymentVerdict::Unverifiable(UnverifiableReason::NoProof),
            failed_at: None,
        };
    }
    // A height no header can carry is refused before any root is asked
    // (bsv-middleware-rs 0.4.1 `src/payment_core.rs:620-622`). The roots are
    // sorted, so it is the last.
    if let Some((height, _)) = roots.last().filter(|(h, _)| u32::try_from(*h).is_err()) {
        return Rooted::Word {
            word: malformed(format!("a BUMP claims the block height {}", height)),
            failed_at: None,
        };
    }
    let mut answers: HashMap<u32, Result<String, HeaderLookupError>> = HashMap::new();
    let mut first_failure = None;
    for (place, (height, root)) in roots.iter().enumerate().skip(from) {
        let height = *height as u32;
        if !answers.contains_key(&height) {
            if lookups.is_some_and(|max| answers.len() >= max) {
                return Rooted::Paused(first_failure.map_or(place, |(at, _)| at));
            }
            answers.insert(height, headers.merkle_root_at(height).await);
        }
        let merkle_root = display_hex(root);
        match &answers[&height] {
            Ok(carried) if carried.eq_ignore_ascii_case(&merkle_root) => {}
            Ok(_) => {
                return Rooted::Word {
                    word: PaymentVerdict::RootMismatch {
                        height,
                        merkle_root,
                    },
                    failed_at: None,
                }
            }
            Err(HeaderLookupError(reason)) => {
                first_failure.get_or_insert((
                    place,
                    UnverifiableReason::HeaderLookupFailed {
                        height,
                        reason: reason.clone(),
                    },
                ));
            }
        }
    }
    match first_failure {
        Some((place, reason)) => Rooted::Word {
            word: PaymentVerdict::Unverifiable(reason),
            failed_at: Some(place),
        },
        None => Rooted::Word {
            word: PaymentVerdict::Verified { satoshis },
            failed_at: None,
        },
    }
}

/// The inline payment through the door, in one pass: the bytes are in the
/// request and not at rest, so there is no cursor to come back to.
pub async fn verify_inline(
    carrier: &Carrier<'_>,
    terms: &Terms<'_>,
    header_service: Option<&dyn HeaderService>,
) -> Result<DoorVerdict, DoorError> {
    let Some(headers) = header_service else {
        return Ok(PaymentVerdict::NoHeaderService.into());
    };
    let cursor = match read(None, &mut carrier.chunks(0), None)
        .await
        .map_err(DoorError::Source)?
    {
        Reading::Valid(cursor) => cursor,
        Reading::Refused(refused) => return Ok(refusal_word(refused)),
        Reading::Paused(_) => {
            return Err(DoorError::Internal(
                "a reading with no slice paused".to_string(),
            ))
        }
    };
    let Some((txid, at)) = tip_of(&cursor)? else {
        return Ok(PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction).into());
    };
    let subject = subject_raw(carrier.bytes(at, usize::MAX), &txid)?;
    let satoshis = match output_word(&subject, terms) {
        PaymentVerdict::Verified { satoshis } => satoshis,
        other => return Ok(other.into()),
    };
    match roots_word(&roots_of(&cursor), 0, None, headers, satoshis).await {
        Rooted::Word { word, .. } => Ok(judged(word, txid)),
        Rooted::Paused(_) => Err(DoorError::Internal(
            "the roots with no slice paused".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Bytes at rest
// ---------------------------------------------------------------------------

/// What tells one upload of an object from another: its size and its etag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    pub etag: String,
}

/// An object store holding a BEEF at rest and, beside it, the door's state.
/// The state is the verifier's own and is trusted as such: it lives under a
/// key the uploader of the BEEF cannot write (`state_key`).
#[async_trait::async_trait(?Send)]
pub trait BeefStore {
    /// The object's stamp, or `None` when there is no such object.
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String>;
    /// The object's bytes from `from` to its end, as a stream. An object
    /// that is no longer the one `stamp` names is an error.
    async fn open(&self, key: &str, from: u64, stamp: &Stamp) -> Result<Box<dyn Chunks>, String>;
    /// The state saved under `key`.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    async fn save(&self, key: &str, state: Vec<u8>) -> Result<(), String>;
    async fn clear(&self, key: &str) -> Result<(), String>;
}

/// Where the door keeps its state for the object at `key`. An upload key is
/// `<identity key>/<uuid>.beef` (`beef_upload::build_upload_key`), an identity
/// key is 66 hex characters, and `/beef/upload-url` presigns nothing else: no
/// uploader can write here.
pub fn state_key(key: &str) -> String {
    format!("door-state/{}", key)
}

const STATE_MAGIC: &[u8; 5] = b"RMBD1";

/// The door's state for one object at rest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rest {
    /// The object the state is of.
    stamp: Stamp,
    /// The structure is read to its end and valid; the roots are being asked.
    rooting: bool,
    /// The roots asked and carried (`roots_of`'s order).
    roots_asked: u64,
    cursor: Cursor,
}

impl Rest {
    fn to_binary(&self) -> Vec<u8> {
        let cursor = self.cursor.to_binary();
        let etag = self.stamp.etag.as_bytes();
        let mut out = Vec::with_capacity(32 + etag.len() + cursor.len());
        out.extend_from_slice(STATE_MAGIC);
        out.push(self.rooting as u8);
        out.extend_from_slice(&self.stamp.size.to_le_bytes());
        out.extend_from_slice(&self.roots_asked.to_le_bytes());
        out.extend_from_slice(&(etag.len() as u32).to_le_bytes());
        out.extend_from_slice(etag);
        out.extend_from_slice(&cursor);
        out
    }

    /// The state from its bytes; anything else is no state, and the reading
    /// starts over.
    fn from_binary(bin: &[u8]) -> Option<Self> {
        let rest = bin.strip_prefix(STATE_MAGIC)?;
        let (head, rest) = rest.split_at_checked(1 + 8 + 8 + 4)?;
        let u64_at = |at: usize| u64::from_le_bytes(head[at..at + 8].try_into().unwrap());
        let etag_len = u32::from_le_bytes(head[17..21].try_into().unwrap()) as usize;
        let (etag, cursor) = rest.split_at_checked(etag_len)?;
        Some(Self {
            stamp: Stamp {
                size: u64_at(1),
                etag: String::from_utf8(etag.to_vec()).ok()?,
            },
            rooting: head[0] == 1,
            roots_asked: u64_at(9),
            cursor: Cursor::from_binary(cursor).ok()?,
        })
    }
}

/// How far a pending verification has come.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// The elements read.
    pub elements: u64,
    /// The bytes read, of `size`.
    pub offset: u64,
    pub size: u64,
    /// The roots asked and carried, of `roots` (0 of 0 while the bytes are
    /// still being read).
    pub roots_asked: u64,
    pub roots: u64,
}

/// What one request's work on an object at rest came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtRest {
    /// A verdict; the state is gone, or kept at the roots when the header
    /// service could not answer.
    Done(DoorVerdict),
    /// The slice is spent and the state is saved: the same request again
    /// continues.
    Pending(Pending),
    /// There is no object at the key.
    NotFound,
}

/// One request's slices for an object at rest.
pub struct Slices<'a> {
    pub time: Slice<'a>,
    pub lookups: usize,
}

/// The object at `key` through the door, for one slice: read from the saved
/// cursor (or the start) as a stream, never held whole; on a pause the cursor
/// is saved beside the object. A state of another upload of the object (a
/// different size or etag) is dropped and the reading starts over.
pub async fn verify_at_rest(
    store: &dyn BeefStore,
    key: &str,
    terms: &Terms<'_>,
    header_service: Option<&dyn HeaderService>,
    slices: &Slices<'_>,
) -> Result<AtRest, DoorError> {
    let Some(headers) = header_service else {
        return Ok(AtRest::Done(PaymentVerdict::NoHeaderService.into()));
    };
    let source = DoorError::Source;
    let Some(stamp) = store.stamp(key).await.map_err(source)? else {
        return Ok(AtRest::NotFound);
    };
    let state_key = state_key(key);
    let saved = store
        .load(&state_key)
        .await
        .map_err(source)?
        .and_then(|bin| Rest::from_binary(&bin))
        .filter(|rest| rest.stamp == stamp);
    let (cursor, roots_asked) = match saved {
        Some(rest) if rest.rooting => (rest.cursor, rest.roots_asked as usize),
        saved => {
            let from = saved.map(|rest| rest.cursor);
            let offset = from.as_ref().map_or(0, Cursor::offset);
            let mut chunks = store.open(key, offset, &stamp).await.map_err(source)?;
            match read(from, chunks.as_mut(), Some(&slices.time))
                .await
                .map_err(source)?
            {
                Reading::Valid(cursor) => (cursor, 0),
                Reading::Refused(refused) => {
                    store.clear(&state_key).await.map_err(source)?;
                    return Ok(AtRest::Done(refusal_word(refused)));
                }
                Reading::Paused(cursor) => {
                    let pending = Pending {
                        elements: cursor.elements_read(),
                        offset: cursor.offset(),
                        size: stamp.size,
                        roots_asked: 0,
                        roots: 0,
                    };
                    let rest = Rest {
                        stamp,
                        rooting: false,
                        roots_asked: 0,
                        cursor,
                    };
                    store
                        .save(&state_key, rest.to_binary())
                        .await
                        .map_err(source)?;
                    return Ok(AtRest::Pending(pending));
                }
            }
        }
    };
    let done = |word: PaymentVerdict| Ok(AtRest::Done(word.into()));
    let Some((txid, at)) = tip_of(&cursor)? else {
        store.clear(&state_key).await.map_err(source)?;
        return done(PaymentVerdict::Unverifiable(
            UnverifiableReason::NoTransaction,
        ));
    };
    // The subject alone is read again: one element.
    let mut tail = Vec::new();
    let mut chunks = store.open(key, at, &stamp).await.map_err(source)?;
    while let Some(chunk) = chunks.next().await.map_err(source)? {
        tail.extend_from_slice(&chunk);
    }
    let subject = subject_raw(tail, &txid)?;
    let satoshis = match output_word(&subject, terms) {
        PaymentVerdict::Verified { satoshis } => satoshis,
        other => {
            store.clear(&state_key).await.map_err(source)?;
            return done(other);
        }
    };
    let roots = roots_of(&cursor);
    let rooted = roots_word(&roots, roots_asked, Some(slices.lookups), headers, satoshis).await;
    let (keep_at, answer) = match rooted {
        Rooted::Paused(place) => (
            Some(place),
            AtRest::Pending(Pending {
                elements: cursor.elements_read(),
                offset: cursor.offset(),
                size: stamp.size,
                roots_asked: place as u64,
                roots: roots.len() as u64,
            }),
        ),
        Rooted::Word { word, failed_at } => (failed_at, AtRest::Done(judged(word, txid))),
    };
    match keep_at {
        Some(place) => {
            let rest = Rest {
                stamp,
                rooting: true,
                roots_asked: place as u64,
                cursor,
            };
            store.save(&state_key, rest.to_binary()).await
        }
        None => store.clear(&state_key).await,
    }
    .map_err(source)?;
    Ok(answer)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bsv_rs::transaction::Kind;
    use serde_json::json;
    use std::cell::Cell;
    use std::sync::Mutex;

    pub(crate) fn varint(n: u64, out: &mut Vec<u8>) {
        match n {
            0..=0xfc => out.push(n as u8),
            0xfd..=0xffff => {
                out.push(0xfd);
                out.extend_from_slice(&(n as u16).to_le_bytes());
            }
            _ => {
                out.push(0xfe);
                out.extend_from_slice(&(n as u32).to_le_bytes());
            }
        }
    }

    /// One input spending `prev:0`, one output of `satoshis` at `script`.
    fn raw_tx(prev: &Hash32, satoshis: u64, script: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&1u32.to_le_bytes());
        t.push(1);
        t.extend_from_slice(prev);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.push(0);
        t.extend_from_slice(&u32::MAX.to_le_bytes());
        t.push(1);
        t.extend_from_slice(&satoshis.to_le_bytes());
        varint(script.len() as u64, &mut t);
        t.extend_from_slice(script);
        t.extend_from_slice(&0u32.to_le_bytes());
        t
    }

    fn txid(raw: &[u8]) -> Hash32 {
        Sha256::digest(Sha256::digest(raw)).into()
    }

    const PAID: &[u8] = &[0x51; 25];
    /// The script of an output a later link spends: `OP_TRUE`, which an
    /// empty unlocking script satisfies. The door runs the scripts.
    const SPENT: &[u8] = &[0x51];
    const FEE: u64 = 100;
    const HEIGHT: u32 = 850_000;

    fn terms() -> Terms<'static> {
        Terms {
            output_index: 0,
            expected_script: PAID,
            required_satoshis: FEE,
        }
    }

    /// A BEEF V2: one one-leaf BUMP per `(height, txid)`, then the
    /// transactions, each with the BUMP that proves it or none; the Atomic
    /// prefix when `atomic` names the subject.
    fn beef(
        bumps: &[(u32, Hash32)],
        txs: &[(Option<u8>, Vec<u8>)],
        atomic: Option<Hash32>,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        if let Some(subject) = atomic {
            b.extend_from_slice(&0x0101_0101u32.to_le_bytes());
            b.extend_from_slice(&subject);
        }
        b.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
        varint(bumps.len() as u64, &mut b);
        for (height, leaf) in bumps {
            b.push(0xfe);
            b.extend_from_slice(&height.to_le_bytes());
            b.extend_from_slice(&[1, 1, 0, 2]); // height 1, one leaf, offset 0, a txid
            b.extend_from_slice(leaf);
        }
        varint(txs.len() as u64, &mut b);
        for (bump, raw) in txs {
            match bump {
                Some(index) => b.extend_from_slice(&[1, *index]),
                None => b.push(0),
            }
            b.extend_from_slice(raw);
        }
        b
    }

    /// An Atomic BEEF of `links` transactions, the oldest proven at `HEIGHT`,
    /// the last paying `FEE` to `PAID`; and the oldest's txid (the root).
    fn chain(links: usize) -> (Vec<u8>, Hash32) {
        let mut txs = Vec::new();
        let mut prev = [0x11u8; 32];
        for i in 0..links {
            let raw = if i + 1 == links {
                raw_tx(&prev, FEE, PAID)
            } else {
                raw_tx(&prev, 1_000, SPENT)
            };
            prev = txid(&raw);
            txs.push((if i == 0 { Some(0) } else { None }, raw));
        }
        let oldest = txid(&txs[0].1);
        (beef(&[(HEIGHT, oldest)], &txs, Some(prev)), oldest)
    }

    /// Roots by height; a height with none could not be looked up. Counts
    /// what it is asked.
    struct Roots {
        roots: HashMap<u32, Hash32>,
        asked: Mutex<Vec<u32>>,
    }

    impl Roots {
        fn of(roots: &[(u32, Hash32)]) -> Self {
            Self {
                roots: roots.iter().copied().collect(),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<u32> {
            self.asked.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl HeaderService for Roots {
        async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
            self.asked.lock().unwrap().push(height);
            self.roots
                .get(&height)
                .map(display_hex)
                .ok_or_else(|| HeaderLookupError(format!("no header at {height}")))
        }
    }

    fn shapes(bytes: &[u8]) -> [Value; 3] {
        [
            json!(bytes),
            json!(hex::encode(bytes)),
            json!({ "beef": B64.encode(bytes) }),
        ]
    }

    // ---- the carrier ----

    #[test]
    fn a_carrier_reads_the_same_bytes_from_every_offset_in_each_shape() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(1_000).collect();
        for tx in shapes(&bytes) {
            let carrier = Carrier::of(&tx).expect("a carrier");
            assert_eq!(carrier.len(), 1_000);
            for from in 0..=1_000usize {
                for max in [0, 1, 2, 3, 4, 7, 1_000] {
                    let want = &bytes[from..(from + max).min(1_000)];
                    assert_eq!(carrier.bytes(from as u64, max), want, "{from} {max}");
                }
            }
        }
    }

    #[test]
    fn a_carrier_of_every_padding_decodes() {
        for n in 0..=7usize {
            let bytes = vec![0xabu8; n];
            for tx in shapes(&bytes) {
                let carrier = Carrier::of(&tx).expect("a carrier");
                assert_eq!(carrier.bytes(0, usize::MAX), bytes);
            }
        }
    }

    #[test]
    fn what_does_not_decode_is_no_carrier() {
        let long = "A".repeat(CHUNK / 3 * 4);
        for tx in [
            json!([0, 256]),
            json!([0, -1]),
            json!([0, "1"]),
            json!("abc"),
            json!("zz"),
            json!({ "beef": "AAA" }),
            json!({ "beef": "A!AA" }),
            json!({ "beef": format!("AA=={long}") }),
            json!({ "beef": 7 }),
            json!({ "tx": "00" }),
            json!(7),
            Value::Null,
        ] {
            assert!(Carrier::of(&tx).is_none(), "{tx}");
        }
    }

    #[tokio::test]
    async fn a_carrier_is_handed_out_in_chunks() {
        let bytes = vec![7u8; 3 * CHUNK + 5];
        let tx = json!(hex::encode(&bytes));
        let carrier = Carrier::of(&tx).unwrap();
        let mut chunks = carrier.chunks(0);
        let mut sizes = Vec::new();
        while let Some(chunk) = chunks.next().await.unwrap() {
            sizes.push(chunk.len());
        }
        assert_eq!(sizes, [CHUNK, CHUNK, CHUNK, 5]);
    }

    // ---- the subject ----

    #[test]
    fn the_length_of_a_raw_transaction_is_read_from_its_fields() {
        let raw = raw_tx(&[9; 32], 5, PAID);
        assert_eq!(raw_tx_len(&raw), Some(raw.len()));
        let mut followed = raw.clone();
        followed.extend_from_slice(&[1, 2, 3]);
        assert_eq!(raw_tx_len(&followed), Some(raw.len()));
        for cut in 0..raw.len() {
            assert_eq!(raw_tx_len(&raw[..cut]), None, "cut at {cut}");
        }
        // A count no bytes could fill is no transaction, and reserves nothing.
        let mut huge = 1u32.to_le_bytes().to_vec();
        huge.extend_from_slice(&[0xff; 9]);
        assert_eq!(raw_tx_len(&huge), None);
    }

    #[tokio::test]
    async fn the_tip_of_a_reading_is_the_subject_and_where_it_starts() {
        let (bytes, _) = chain(5);
        let tx = json!(hex::encode(&bytes));
        let carrier = Carrier::of(&tx).unwrap();
        let Reading::Valid(cursor) = read(None, &mut carrier.chunks(0), None).await.unwrap() else {
            panic!("a valid chain");
        };
        let (subject, at) = tip_of(&cursor).unwrap().expect("a tip");
        let raw = raw_tx(&[0; 32], FEE, PAID).len();
        assert_eq!(at as usize, bytes.len() - raw);
        assert_eq!(subject, txid(&bytes[at as usize..]));
        assert_eq!(&subject[..], &bytes[4..36], "the prefix's subject");
        assert_eq!(
            subject_raw(bytes[at as usize..].to_vec(), &subject).unwrap(),
            &bytes[at as usize..]
        );
        // Bytes that are not the subject are an error, never an answer.
        assert!(subject_raw(bytes[at as usize - 1..].to_vec(), &subject).is_err());
    }

    // ---- the inline door ----

    async fn inline(bytes: &[u8], headers: &Roots) -> DoorVerdict {
        let mut answers = Vec::new();
        for tx in shapes(bytes) {
            let carrier = Carrier::of(&tx).unwrap();
            answers.push(
                verify_inline(&carrier, &terms(), Some(headers))
                    .await
                    .unwrap(),
            );
        }
        assert!(answers.iter().all(|a| *a == answers[0]), "{answers:?}");
        answers.remove(0)
    }

    #[tokio::test]
    async fn a_valid_chain_is_verified_and_its_root_asked_once() {
        let (bytes, root) = chain(300);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let verdict = inline(&bytes, &headers).await;
        assert_eq!(verdict.word, PaymentVerdict::Verified { satoshis: FEE });
        // The subject is named: the txid the Atomic prefix carries.
        assert_eq!(
            verdict.subject.as_ref().map(|t| &t[..]),
            Some(&bytes[4..36])
        );
        assert_eq!(headers.asked(), [HEIGHT; 3], "once per shape");
    }

    #[tokio::test]
    async fn the_words_come_in_the_middlewares_order() {
        let (bytes, root) = chain(3);
        // No header service before anything is read.
        let tx = json!("zz00");
        assert!(Carrier::of(&tx).is_none());
        let good = json!(hex::encode(&bytes));
        let carrier = Carrier::of(&good).unwrap();
        assert_eq!(
            verify_inline(&carrier, &terms(), None).await.unwrap(),
            PaymentVerdict::NoHeaderService.into()
        );
        // The output before the roots: a wrong script and an underpayment
        // ask the header service nothing, even with a wrong root.
        let wrong_root = Roots::of(&[(HEIGHT, [0; 32])]);
        for (asked, word) in [
            (
                Terms {
                    expected_script: &[0x52; 25],
                    ..terms()
                },
                "WrongScript",
            ),
            (
                Terms {
                    required_satoshis: FEE + 1,
                    ..terms()
                },
                "Underpaid",
            ),
            (
                Terms {
                    output_index: 1,
                    ..terms()
                },
                "Unverifiable(OutputMissing",
            ),
        ] {
            let verdict = verify_inline(&carrier, &asked, Some(&wrong_root))
                .await
                .unwrap();
            assert!(
                format!("{:?}", verdict.word).starts_with(word),
                "{verdict:?}"
            );
            assert_eq!(verdict.named, None);
        }
        assert!(wrong_root.asked().is_empty());
        // Then the roots: a root the header does not carry, a lookup that
        // could not answer.
        assert_eq!(
            verify_inline(&carrier, &terms(), Some(&wrong_root))
                .await
                .unwrap(),
            PaymentVerdict::RootMismatch {
                height: HEIGHT,
                merkle_root: display_hex(&root)
            }
            .into()
        );
        let no_header = Roots::of(&[]);
        assert_eq!(
            verify_inline(&carrier, &terms(), Some(&no_header))
                .await
                .unwrap(),
            PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed {
                height: HEIGHT,
                reason: format!("no header at {HEIGHT}")
            })
            .into()
        );
    }

    #[tokio::test]
    async fn invalid_bytes_are_refused_naming_the_offset_and_the_kind() {
        let (bytes, root) = chain(4);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let named = |offset: u64, kind: &str| {
            Some(Named {
                offset,
                kind: kind.to_string(),
            })
        };
        // The word is bsv-middleware-rs 0.4.1's `InvalidBeef`, its offset and
        // kind the ones the body names.
        let invalid = |word: &PaymentVerdict, offset: u64, kind: Kind| {
            assert!(
                matches!(
                    word,
                    PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                        offset: at,
                        kind: k,
                        ..
                    }) if *at == offset && *k == kind
                ),
                "{word:?} is not InvalidBeef at {offset}, {kind:?}"
            )
        };
        // A raw transaction is not a BEEF: its version word is the byte named.
        let raw = raw_tx(&[9; 32], FEE, PAID);
        let verdict = inline(&raw, &headers).await;
        assert_eq!(verdict.named, named(0, "BadVersion"));
        invalid(&verdict.word, 0, Kind::BadVersion);
        // Nothing at all.
        assert_eq!(inline(&[], &headers).await.named, named(0, "Truncated"));
        // One byte after the frame.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            inline(&trailing, &headers).await.named,
            named(bytes.len() as u64, "TrailingBytes")
        );
        // A tree height of 65 at the BUMP's height byte.
        let mut tall = bytes.clone();
        let tree_height_at = 4 + 32 + 4 + 1 + 5;
        assert_eq!(tall[tree_height_at], 1);
        tall[tree_height_at] = 65;
        assert_eq!(
            inline(&tall, &headers).await.named,
            named(tree_height_at as u64, "TreeHeightOver64")
        );
        // A subject that is not the prefix's.
        let mut other = bytes.clone();
        other[4] ^= 1;
        let verdict = inline(&other, &headers).await;
        assert_eq!(verdict.named, named(4, "SubjectMissing"));
        invalid(&verdict.word, 4, Kind::SubjectMissing);
        // The payment alone: its input names no element.
        let alone = raw_tx(&[9; 32], FEE, PAID);
        let alone = beef(&[], &[(None, alone.clone())], Some(txid(&alone)));
        let verdict = inline(&alone, &headers).await;
        assert_eq!(
            verdict.named,
            named(4 + 32 + 4 + 2 + 1 + 5, "InputNamesNoElement")
        );
        invalid(
            &verdict.word,
            4 + 32 + 4 + 2 + 1 + 5,
            Kind::InputNamesNoElement,
        );
        assert!(headers.asked().is_empty(), "no refusal asked a root");
    }

    #[tokio::test]
    async fn a_height_beyond_the_headers_is_refused_before_any_root_is_asked() {
        // bsv-middleware-rs 0.4.1 refuses a BUMP whose height no header can
        // carry before it asks any root (`src/payment_core.rs:620-622`), so a
        // lower root the header service does not carry is never the word.
        let beyond = u64::from(u32::MAX) + 1;
        let headers = Roots::of(&[(HEIGHT, [7; 32])]);
        let rooted = roots_word(
            &[(HEIGHT as u64, [8; 32]), (beyond, [9; 32])],
            0,
            None,
            &headers,
            FEE,
        )
        .await;
        let Rooted::Word { word, failed_at } = rooted else {
            panic!("no lookup budget was set, so nothing pauses");
        };
        assert_eq!(
            word,
            malformed(format!("a BUMP claims the block height {}", beyond))
        );
        assert_eq!(failed_at, None);
        assert!(headers.asked().is_empty(), "no root was asked");
    }

    #[tokio::test]
    async fn a_transaction_with_no_input_is_refused_naming_it_and_asks_nothing() {
        let headers = Roots::of(&[]);
        // A transaction with no input names nothing a BEEF would have to
        // carry. Until bsv-rs 0.4.1 its structure was valid with nothing in
        // it proven (`NoProof` here); it is invalid bytes, named at its
        // leading byte: behind the prefix and the version (40), the two
        // counts and its format byte.
        let mut minted = 1u32.to_le_bytes().to_vec();
        minted.extend_from_slice(&[0, 1]);
        minted.extend_from_slice(&FEE.to_le_bytes());
        minted.push(PAID.len() as u8);
        minted.extend_from_slice(PAID);
        minted.extend_from_slice(&0u32.to_le_bytes());
        let unproven = beef(&[], &[(None, minted.clone())], Some(txid(&minted)));
        let verdict = inline(&unproven, &headers).await;
        assert_eq!(
            verdict.named,
            Some(Named {
                offset: 43,
                kind: "NoInputs".to_string()
            })
        );
        assert!(matches!(
            verdict.word,
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                offset: 43,
                kind: Kind::NoInputs,
                ..
            })
        ));
        // No transaction at all.
        let empty = beef(&[], &[], None);
        assert_eq!(
            inline(&empty, &headers).await,
            PaymentVerdict::Unverifiable(UnverifiableReason::NoTransaction).into()
        );
        assert!(headers.asked().is_empty());
    }

    #[tokio::test]
    async fn a_transaction_with_no_output_is_refused_naming_it_and_asks_nothing() {
        let headers = Roots::of(&[]);
        // A transaction with no output is no transaction, as one with no
        // input (bsv-rs 0.4.3, #59; the node's `voutEmpty`). Here it spends
        // a proven parent's `OP_TRUE` with an empty unlock, so its input and
        // its spend are sound and the one thing wrong is the count. Through
        // bsv-rs 0.4.2 the reader read it as valid and the door went on to
        // its words; it is invalid bytes, named at its leading byte.
        let parent = raw_tx(&[0x11; 32], 1_000, SPENT);
        let mut spent = 1u32.to_le_bytes().to_vec();
        spent.push(1);
        spent.extend_from_slice(&txid(&parent));
        spent.extend_from_slice(&0u32.to_le_bytes());
        spent.push(0);
        spent.extend_from_slice(&u32::MAX.to_le_bytes());
        spent.push(0);
        spent.extend_from_slice(&0u32.to_le_bytes());
        let bytes = beef(
            &[(HEIGHT, txid(&parent))],
            &[(Some(0), parent), (None, spent.clone())],
            Some(txid(&spent)),
        );
        let offset = (bytes.len() - spent.len()) as u64;
        let verdict = inline(&bytes, &headers).await;
        assert_eq!(
            verdict.named,
            Some(Named {
                offset,
                kind: "NoOutputs".to_string()
            })
        );
        match verdict.word {
            PaymentVerdict::Unverifiable(UnverifiableReason::InvalidBeef {
                offset: at,
                kind,
                ..
            }) => assert_eq!((at, format!("{kind:?}")), (offset, "NoOutputs".into())),
            word => panic!("invalid bytes expected, got {word:?}"),
        }
        assert!(headers.asked().is_empty(), "no root was asked");
    }

    // ---- bytes at rest ----

    /// An object store in memory. Counts the bytes it hands out and keeps
    /// the largest single run it was asked for from one offset.
    #[derive(Default)]
    pub(crate) struct MemStore {
        objects: RefCell<HashMap<String, (Vec<u8>, String)>>,
        states: RefCell<HashMap<String, Vec<u8>>>,
        opened: RefCell<Vec<u64>>,
        chunk: Cell<usize>,
    }

    impl MemStore {
        pub(crate) fn with(key: &str, bytes: &[u8]) -> Self {
            let store = Self::default();
            store.chunk.set(1_000);
            store.put(key, bytes, "v1");
            store
        }

        fn put(&self, key: &str, bytes: &[u8], etag: &str) {
            self.objects
                .borrow_mut()
                .insert(key.to_string(), (bytes.to_vec(), etag.to_string()));
        }

        fn state(&self, key: &str) -> Option<Vec<u8>> {
            self.states.borrow().get(&state_key(key)).cloned()
        }
    }

    struct MemChunks {
        bytes: Vec<u8>,
        at: usize,
        chunk: usize,
    }

    #[async_trait::async_trait(?Send)]
    impl Chunks for MemChunks {
        async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            let end = (self.at + self.chunk).min(self.bytes.len());
            let chunk = self.bytes[self.at..end].to_vec();
            self.at = end;
            Ok((!chunk.is_empty()).then_some(chunk))
        }
    }

    #[async_trait::async_trait(?Send)]
    impl BeefStore for MemStore {
        async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
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
            let objects = self.objects.borrow();
            let (bytes, etag) = objects.get(key).ok_or("no object")?;
            if *etag != stamp.etag {
                return Err("the object changed".to_string());
            }
            self.opened.borrow_mut().push(from);
            Ok(Box::new(MemChunks {
                bytes: bytes[from as usize..].to_vec(),
                at: 0,
                chunk: self.chunk.get(),
            }))
        }

        async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.states.borrow().get(key).cloned())
        }

        async fn save(&self, key: &str, state: Vec<u8>) -> Result<(), String> {
            self.states.borrow_mut().insert(key.to_string(), state);
            Ok(())
        }

        async fn clear(&self, key: &str) -> Result<(), String> {
            self.states.borrow_mut().remove(key);
            Ok(())
        }
    }

    const KEY: &str = "02abc/upload.beef";

    fn word(answer: AtRest) -> PaymentVerdict {
        match answer {
            AtRest::Done(verdict) => verdict.word,
            other => panic!("no verdict: {other:?}"),
        }
    }

    /// One pass with a slice of no time (every pass pauses at the element it
    /// is on) and `lookups` lookups.
    async fn pass(store: &MemStore, headers: &Roots, lookups: usize) -> AtRest {
        let clock = || 0u64;
        verify_at_rest(
            store,
            KEY,
            &terms(),
            Some(headers),
            &Slices {
                time: Slice {
                    clock: &clock,
                    millis: 0,
                },
                lookups,
            },
        )
        .await
        .unwrap()
    }

    /// One pass with all the time and all the lookups it wants.
    async fn whole(store: &MemStore, headers: &Roots) -> AtRest {
        let clock = || 0u64;
        verify_at_rest(
            store,
            KEY,
            &terms(),
            Some(headers),
            &Slices {
                time: Slice {
                    clock: &clock,
                    millis: u64::MAX,
                },
                lookups: usize::MAX,
            },
        )
        .await
        .unwrap()
    }

    /// Passes until a verdict: the verdict and the passes that were pending.
    async fn passes(
        store: &MemStore,
        headers: &Roots,
        lookups: usize,
    ) -> (DoorVerdict, Vec<Pending>) {
        let mut pending = Vec::new();
        loop {
            match pass(store, headers, lookups).await {
                AtRest::Pending(p) => {
                    assert!(store.state(KEY).is_some(), "a pause saves its state");
                    pending.push(p);
                }
                AtRest::Done(verdict) => return (verdict, pending),
                AtRest::NotFound => panic!("the object is there"),
            }
            assert!(pending.len() < 10_000, "the passes end");
        }
    }

    #[tokio::test]
    async fn an_object_at_rest_in_one_pass_is_the_inline_verdict() {
        let (bytes, root) = chain(50);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let store = MemStore::with(KEY, &bytes);
        assert_eq!(
            whole(&store, &headers).await,
            AtRest::Done(inline(&bytes, &headers).await)
        );
        assert_eq!(store.state(KEY), None, "a verdict leaves no state");
        // Read once from the start, then the subject alone from where it
        // starts: one element.
        let subject = raw_tx(&[0; 32], FEE, PAID).len() as u64;
        assert_eq!(*store.opened.borrow(), [0, bytes.len() as u64 - subject]);
    }

    #[tokio::test]
    async fn a_reading_resumed_at_every_element_comes_to_the_verdict_of_the_whole() {
        let links = 120;
        let (bytes, root) = chain(links);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let store = MemStore::with(KEY, &bytes);
        // Chunks smaller than an element, so every pass fetches.
        store.chunk.set(40);
        let (verdict, pending) = passes(&store, &headers, usize::MAX).await;
        assert_eq!(verdict.word, PaymentVerdict::Verified { satoshis: FEE });
        // One BUMP and the links: a pause after each element, and a last
        // pass that reads the stream's end and the verdict.
        let elements: Vec<u64> = pending.iter().map(|p| p.elements).collect();
        assert_eq!(elements, (1..=links as u64 + 1).collect::<Vec<_>>());
        assert!(pending.windows(2).all(|w| w[0].offset < w[1].offset));
        assert!(pending.iter().all(|p| p.size == bytes.len() as u64));
        assert_eq!(
            headers.asked(),
            [HEIGHT],
            "the root is asked once, at the end"
        );
        assert_eq!(store.state(KEY), None);
        // Each pass read on from its cursor, never from the start again.
        let opened = store.opened.borrow();
        assert_eq!(opened[0], 0);
        assert!(opened[1..].iter().all(|from| *from > 0));
    }

    #[tokio::test]
    async fn invalid_bytes_at_depth_are_named_the_same_across_passes() {
        let (mut bytes, root) = chain(60);
        let headers = Roots::of(&[(HEIGHT, root)]);
        // The link at 40 names a previous txid no element carries. Before
        // it: the prefix and the version (40), the BUMP count and the BUMP
        // (1 + 41), the transaction count (1), link 0 behind its two format
        // bytes and links 1 to 39 behind one each; then its own format byte,
        // its version and its input count.
        let raw = raw_tx(&[0; 32], 1_000, SPENT).len();
        let prev_at = 40 + 42 + 1 + (2 + raw) + 39 * (1 + raw) + 1 + 5;
        bytes[prev_at] ^= 1;
        let one = MemStore::with(KEY, &bytes);
        let AtRest::Done(in_one) = whole(&one, &headers).await else {
            panic!("a verdict");
        };
        assert_eq!(
            in_one.named,
            Some(Named {
                offset: prev_at as u64,
                kind: "InputNamesNoElement".to_string()
            })
        );
        let many = MemStore::with(KEY, &bytes);
        many.chunk.set(40);
        let (in_many, pending) = passes(&many, &headers, usize::MAX).await;
        assert_eq!(in_many, in_one);
        assert_eq!(pending.len(), 41, "the BUMP and the 40 links before it");
        assert_eq!(many.state(KEY), None, "a refusal leaves no state");
        assert!(headers.asked().is_empty());
    }

    #[tokio::test]
    async fn a_state_of_another_upload_is_dropped_and_the_reading_starts_over() {
        let (bytes, root) = chain(30);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let store = MemStore::with(KEY, &bytes);
        store.chunk.set(40);
        for _ in 0..10 {
            assert!(matches!(
                pass(&store, &headers, usize::MAX).await,
                AtRest::Pending(_)
            ));
        }
        // The uploader puts other bytes at the key: a chain whose subject
        // pays one satoshi less.
        let mut other = bytes.clone();
        let amount_at = bytes.len() - raw_tx(&[0; 32], FEE, PAID).len() + 4 + 1 + 36 + 1 + 4 + 1;
        assert_eq!(other[amount_at], FEE as u8);
        other[amount_at] -= 1;
        store.put(KEY, &other, "v2");
        let AtRest::Pending(first) = pass(&store, &headers, usize::MAX).await else {
            panic!("a pause");
        };
        assert_eq!(first.elements, 1, "read from the start");
        let (verdict, _) = passes(&store, &headers, usize::MAX).await;
        // The subject's txid is no longer the prefix's.
        assert_eq!(
            verdict.named,
            Some(Named {
                offset: 4,
                kind: "SubjectMissing".to_string()
            })
        );
        // A state that is not a state is no state.
        store.put(KEY, &bytes, "v3");
        store
            .states
            .borrow_mut()
            .insert(state_key(KEY), b"RMBD1 not a state".to_vec());
        assert_eq!(
            word(whole(&store, &headers).await),
            PaymentVerdict::Verified { satoshis: FEE }
        );
    }

    #[tokio::test]
    async fn the_roots_are_asked_in_slices_and_a_failed_lookup_is_come_back_to() {
        // Three proven parents at three heights, and a subject spending the
        // first: no Atomic prefix, so the others need no spender.
        let parents: Vec<Vec<u8>> = (1..=3u8).map(|i| raw_tx(&[i; 32], 1_000, SPENT)).collect();
        let ids: Vec<Hash32> = parents.iter().map(|p| txid(p)).collect();
        let heights = [850_003u32, 850_001, 850_002];
        let bumps: Vec<(u32, Hash32)> = heights.iter().copied().zip(ids.iter().copied()).collect();
        let mut txs: Vec<(Option<u8>, Vec<u8>)> = parents
            .iter()
            .enumerate()
            .map(|(i, p)| (Some(i as u8), p.clone()))
            .collect();
        txs.push((None, raw_tx(&ids[0], FEE, PAID)));
        let bytes = beef(&bumps, &txs, None);

        let headers = Roots::of(&bumps);
        let store = MemStore::with(KEY, &bytes);
        store.chunk.set(40);
        let (verdict, pending) = passes(&store, &headers, 1).await;
        assert_eq!(verdict.word, PaymentVerdict::Verified { satoshis: FEE });
        assert_eq!(
            headers.asked(),
            [850_001, 850_002, 850_003],
            "each once, lowest first"
        );
        let rooting: Vec<(u64, u64)> = pending
            .iter()
            .filter(|p| p.roots > 0)
            .map(|p| (p.roots_asked, p.roots))
            .collect();
        assert_eq!(rooting, [(1, 3), (2, 3)]);
        assert_eq!(store.state(KEY), None);

        // The header service cannot answer at the middle height: the word is
        // the lookup's, the state stays at that root, and the next request
        // asks from there on.
        let down = Roots::of(&[bumps[0], bumps[1]]);
        let store = MemStore::with(KEY, &bytes);
        let AtRest::Done(verdict) = whole(&store, &down).await else {
            panic!("a verdict");
        };
        assert_eq!(
            verdict.word,
            PaymentVerdict::Unverifiable(UnverifiableReason::HeaderLookupFailed {
                height: 850_002,
                reason: "no header at 850002".to_string()
            })
        );
        assert_eq!(down.asked(), [850_001, 850_002, 850_003]);
        assert_eq!(store.opened.borrow().len(), 2);
        assert_eq!(
            word(whole(&store, &headers).await),
            PaymentVerdict::Verified { satoshis: FEE }
        );
        assert_eq!(headers.asked()[3..], [850_002, 850_003]);
        assert_eq!(
            store.opened.borrow().len(),
            3,
            "the bytes are not read again, only the subject"
        );
        assert_eq!(store.state(KEY), None);

        // A root the header does not carry is the word at once.
        let wrong = Roots::of(&[bumps[0], (850_001, [0; 32]), bumps[2]]);
        let store = MemStore::with(KEY, &bytes);
        assert_eq!(
            whole(&store, &wrong).await,
            AtRest::Done(
                PaymentVerdict::RootMismatch {
                    height: 850_001,
                    merkle_root: display_hex(&ids[1])
                }
                .into()
            )
        );
        assert_eq!(wrong.asked(), [850_001]);
    }

    #[tokio::test]
    async fn no_object_and_no_header_service() {
        let (bytes, root) = chain(3);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let store = MemStore::default();
        assert_eq!(whole(&store, &headers).await, AtRest::NotFound);
        let store = MemStore::with(KEY, &bytes);
        let clock = || 0u64;
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis: 0,
            },
            lookups: 1,
        };
        assert_eq!(
            verify_at_rest(&store, KEY, &terms(), None, &slices)
                .await
                .unwrap(),
            AtRest::Done(PaymentVerdict::NoHeaderService.into())
        );
        assert!(store.opened.borrow().is_empty(), "nothing is read");
    }

    #[test]
    fn the_state_is_kept_where_no_upload_key_reaches() {
        let identity = "02".to_string() + &"ab".repeat(32);
        let key = crate::beef_upload::build_upload_key(&identity, "uuid");
        let state = state_key(&key);
        assert_eq!(state, format!("door-state/{identity}/uuid.beef"));
        assert!(!crate::beef_upload::key_is_owned_by(&identity, &state));
    }

    /// The slice by the clock: a reading pauses at the element in hand once
    /// the time is spent, and not before.
    #[tokio::test]
    async fn the_slice_is_time_read_when_a_chunk_is_fetched() {
        let (bytes, root) = chain(100);
        let headers = Roots::of(&[(HEIGHT, root)]);
        let store = MemStore::with(KEY, &bytes);
        store.chunk.set(40);
        let ticks = Cell::new(0u64);
        let clock = || {
            ticks.set(ticks.get() + 1);
            ticks.get()
        };
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis: 50,
            },
            lookups: usize::MAX,
        };
        let mut pauses = 0;
        loop {
            match verify_at_rest(&store, KEY, &terms(), Some(&headers), &slices)
                .await
                .unwrap()
            {
                AtRest::Pending(_) => pauses += 1,
                AtRest::Done(verdict) => {
                    assert_eq!(verdict.word, PaymentVerdict::Verified { satoshis: FEE });
                    break;
                }
                AtRest::NotFound => panic!("the object is there"),
            }
        }
        // About 6,200 bytes in 40-byte chunks, 50 fetches a slice.
        assert!((2..=5).contains(&pauses), "{pauses} pauses");
    }
}
