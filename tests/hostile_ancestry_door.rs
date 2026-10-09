//! NL-4c (the no-limits program): two payments the message box's door
//! refuses, beside the structure and the roots.
//!
//! The builders are NL-5's (`bsv-middleware-rs` 0.4.0 `src/payment_core.rs`,
//! `a_spend_the_interpreter_refuses_is_unverifiable_and_asks_no_header` and
//! `a_transaction_with_no_input_and_no_proof_anchors_nothing`, its `beside`
//! case), written here byte by byte:
//!
//! - **an unsigned spend**: the subject spends a proven parent's output that
//!   is locked to a key, and offers no signature. The structure is whole and
//!   the root is the header's; no script allows the spend.
//! - **a no-input ancestry beside a proven stranger**: the subject spends a
//!   transaction with no input (nothing is beneath it and nothing proves it),
//!   in a BEEF that also carries a proven transaction nothing spends, so
//!   every root the BEEF names is the header's.
//!
//! Each goes through the door inline (the three shapes of `tx`) and from an
//! object at rest (in one pass, and resumed at every element), and each has a
//! control beside it: the same frame, valid, accepted. A refusal is 400
//! `ERR_INVALID_PAYMENT` naming the offset and the kind, and asks the header
//! service nothing.

mod support;

use rust_message_box::beef_door::{BeefStore, Chunks, Slice, Slices, Stamp};
use rust_message_box::payments::{check_delivery_at_rest, check_delivery_output};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::*;

const OP_TRUE: &[u8] = &[0x51];
const KEY: &str = "02abc/upload.beef";

/// A P2PKH script to a key nobody here holds.
fn locked_to_a_key() -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[7u8; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// A transaction with no input and one output.
fn no_input_tx(satoshis: u64, script: &[u8]) -> Vec<u8> {
    let mut t = 1u32.to_le_bytes().to_vec();
    t.push(0);
    t.push(1);
    t.extend_from_slice(&satoshis.to_le_bytes());
    varint(script.len() as u64, &mut t);
    t.extend_from_slice(script);
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// A BEEF V2 whose one BUMP (a block of one transaction at `HEIGHT`) proves
/// the leading transaction, the rest unproven; behind the Atomic prefix when
/// `atomic`. Returns the bytes, the root as the header service gives it, and
/// where each raw transaction starts.
fn beef(txs: &[Vec<u8>], atomic: bool) -> (Vec<u8>, String, Vec<usize>) {
    let proven = hash(&txs[0]);
    let mut b = Vec::new();
    if atomic {
        b.extend_from_slice(&0x0101_0101u32.to_le_bytes());
        b.extend_from_slice(&hash(txs.last().unwrap()));
    }
    b.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
    b.push(1);
    b.push(0xfe);
    b.extend_from_slice(&HEIGHT.to_le_bytes());
    b.extend_from_slice(&[1, 1, 0, 2]); // tree height 1, one leaf, offset 0, a txid
    b.extend_from_slice(&proven);
    varint(txs.len() as u64, &mut b);
    let mut starts = Vec::new();
    for (i, raw) in txs.iter().enumerate() {
        if i == 0 {
            b.extend_from_slice(&[1, 0]);
        } else {
            b.push(0);
        }
        starts.push(b.len());
        b.extend_from_slice(raw);
    }
    let root = hex::encode(proven.iter().rev().copied().collect::<Vec<u8>>());
    (b, root, starts)
}

/// The unsigned spend: a proven parent paying `parent_script`, and the
/// subject spending it with an empty unlock to pay the server the fee.
fn spend_of(parent_script: &[u8]) -> (Vec<u8>, String, Vec<usize>) {
    let parent = raw_tx(&[0x11; 32], FEE, parent_script, 0);
    let subject = raw_tx(&hash(&parent), FEE, &server_script(), 0);
    beef(&[parent, subject], true)
}

/// The no-input ancestry: a proven stranger, a transaction with no input,
/// and the subject spending the transaction with no input (or the stranger,
/// for the control, with no such transaction in the BEEF).
fn ancestry(no_input: bool) -> (Vec<u8>, String, Vec<usize>) {
    let stranger = raw_tx(&[0x11; 32], FEE, OP_TRUE, 0);
    if no_input {
        let minted = no_input_tx(FEE, OP_TRUE);
        let subject = raw_tx(&hash(&minted), FEE, &server_script(), 0);
        beef(&[stranger, minted, subject], false)
    } else {
        let subject = raw_tx(&hash(&stranger), FEE, &server_script(), 0);
        beef(&[stranger, subject], false)
    }
}

fn sender() -> String {
    wallet(SENDER_KEY).identity_key().to_hex()
}

fn remittance() -> Value {
    json!({
        "outputIndex": 0,
        "protocol": "wallet payment",
        "paymentRemittance": {
            "derivationPrefix": PREFIX,
            "derivationSuffix": SUFFIX,
            "senderIdentityKey": sender()
        }
    })
}

type Answer = Result<u64, (u16, Value)>;

fn on_a_small_stack<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .expect("the door returned")
}

/// The inline door on `beef` in each of the three shapes of `tx`: the one
/// answer they share, and how often the header service was asked in all.
fn inline(beef: &[u8], root: &str) -> (Answer, usize) {
    use base64::Engine as _;
    let shapes = [
        json!(hex::encode(beef)),
        json!(beef),
        json!({ "beef": base64::engine::general_purpose::STANDARD.encode(beef) }),
    ];
    let asked = Arc::new(AtomicUsize::new(0));
    let mut answers: Vec<Answer> = Vec::new();
    for tx in shapes {
        let headers = ChainHeaders {
            root: root.to_string(),
            asked: asked.clone(),
        };
        answers.push(on_a_small_stack(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(check_delivery_output(
                    &tx,
                    &remittance(),
                    FEE,
                    &sender(),
                    &wallet(SERVER_KEY),
                    Some(&headers),
                ))
                .map_err(|(body, status)| (status, body))
        }));
    }
    assert!(
        answers.iter().all(|a| *a == answers[0]),
        "the three shapes agree: {answers:?}"
    );
    (answers.remove(0), asked.load(Ordering::SeqCst))
}

/// An object store in memory: one object, handed out in chunks of `chunk`
/// bytes, and the door's states.
struct Store {
    bytes: Vec<u8>,
    chunk: usize,
    states: RefCell<HashMap<String, Vec<u8>>>,
}

struct Bytes {
    bytes: Vec<u8>,
    at: usize,
    chunk: usize,
}

#[async_trait::async_trait(?Send)]
impl Chunks for Bytes {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let end = (self.at + self.chunk).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

#[async_trait::async_trait(?Send)]
impl BeefStore for Store {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        Ok((key == KEY).then(|| Stamp {
            size: self.bytes.len() as u64,
            etag: "v1".to_string(),
        }))
    }

    async fn open(&self, _key: &str, from: u64, _stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        Ok(Box::new(Bytes {
            bytes: self.bytes[from as usize..].to_vec(),
            at: 0,
            chunk: self.chunk,
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

/// The door on `beef` as an object at rest. `resumed` reads it in chunks
/// smaller than an element with a slice of no time, so every request pauses
/// after one element and the next continues from the saved cursor. The
/// answer, the requests that were pending before it, how often the header
/// service was asked, and whether a state was left behind.
fn at_rest(beef: &[u8], root: &str, resumed: bool) -> (Answer, usize, usize, bool) {
    let beef = beef.to_vec();
    let asked = Arc::new(AtomicUsize::new(0));
    let headers = ChainHeaders {
        root: root.to_string(),
        asked: asked.clone(),
    };
    let (answer, pending, left) = on_a_small_stack(move || {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let store = Store {
                    bytes: beef,
                    chunk: if resumed { 40 } else { 64 * 1024 },
                    states: RefCell::new(HashMap::new()),
                };
                let clock = || 0u64;
                let slices = Slices {
                    time: Slice {
                        clock: &clock,
                        millis: if resumed { 0 } else { u64::MAX },
                    },
                    lookups: usize::MAX,
                };
                let mut pending = 0usize;
                loop {
                    let answer = check_delivery_at_rest(
                        &store,
                        KEY,
                        &remittance(),
                        FEE,
                        &sender(),
                        &wallet(SERVER_KEY),
                        Some(&headers),
                        &slices,
                    )
                    .await
                    .map_err(|(body, status)| (status, body));
                    match &answer {
                        Err((503, body)) if body["code"] == "ERR_PAYMENT_PENDING" => pending += 1,
                        _ => break (answer, pending, !store.states.borrow().is_empty()),
                    }
                    assert!(pending < 1_000, "the requests end");
                }
            })
    });
    (answer, pending, asked.load(Ordering::SeqCst), left)
}

/// A refusal for the payer's bytes: 400, the offset and the kind in the body
/// and in its text.
fn refused_naming(answer: &Answer, offset: usize, kind: &str) {
    let (status, body) = answer.as_ref().expect_err("the payment is refused");
    assert_eq!(*status, 400, "the payer's bytes: {body}");
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT", "{body}");
    assert_eq!(body["offset"], json!(offset), "names the offset: {body}");
    assert_eq!(body["kind"], json!(kind), "names the kind: {body}");
    let text = body["description"].as_str().unwrap();
    eprintln!("hostile_ancestry_door: {status} {text}");
    assert!(
        text.contains(&format!("offset {offset}")) && text.contains(kind),
        "the text names both: {text}"
    );
}

// ---- the unsigned spend ----

/// The control: the same two transactions, the parent's output one any
/// spender may take. Accepted, its one root asked.
#[test]
fn a_spend_a_script_allows_is_accepted_inline_and_at_rest() {
    let (bytes, root, _) = spend_of(OP_TRUE);
    assert_eq!(inline(&bytes, &root), (Ok(FEE), 3));
    assert_eq!(at_rest(&bytes, &root, false), (Ok(FEE), 0, 1, false));
    let (answer, pending, asked, left) = at_rest(&bytes, &root, true);
    assert_eq!((answer, asked, left), (Ok(FEE), 1, false));
    assert_eq!(pending, 3, "the BUMP and the two transactions");
}

/// The parent's output is locked to a key and the subject offers no
/// signature: refused inline, naming the input (the subject's leading byte,
/// its version and its input count come before it).
#[test]
fn an_unsigned_spend_is_refused_inline() {
    let (bytes, root, starts) = spend_of(&locked_to_a_key());
    let (answer, asked) = inline(&bytes, &root);
    refused_naming(&answer, starts[1] + 5, "SpendRefused");
    assert_eq!(asked, 0, "refused before any lookup");
}

/// The same object at rest: the same refusal in one request, and when the
/// reading is resumed at every element; no state is left beside the object.
#[test]
fn an_unsigned_spend_is_refused_at_rest() {
    let (bytes, root, starts) = spend_of(&locked_to_a_key());
    let (inline_answer, _) = inline(&bytes, &root);
    let (answer, pending, asked, left) = at_rest(&bytes, &root, false);
    refused_naming(&answer, starts[1] + 5, "SpendRefused");
    assert_eq!((pending, asked, left), (0, 0, false));
    assert_eq!(answer, inline_answer, "the inline refusal, word for word");
    let (resumed, pending, asked, left) = at_rest(&bytes, &root, true);
    assert_eq!(resumed, answer, "the same refusal across requests");
    assert_eq!(pending, 2, "the BUMP and the parent, then the spend");
    assert_eq!((asked, left), (0, false));
}

// ---- the no-input ancestry ----

/// The control: the subject spends the proven stranger, and no transaction
/// without an input is in the BEEF. Accepted.
#[test]
fn a_payment_standing_on_the_proven_transaction_is_accepted_inline_and_at_rest() {
    let (bytes, root, _) = ancestry(false);
    assert_eq!(inline(&bytes, &root), (Ok(FEE), 3));
    assert_eq!(at_rest(&bytes, &root, false), (Ok(FEE), 0, 1, false));
    assert_eq!(at_rest(&bytes, &root, true), (Ok(FEE), 3, 1, false));
}

/// The subject spends a transaction with no input, beside a proven stranger
/// whose root the header service carries: refused inline, naming the leading
/// byte of the transaction with no input and the reader's kind.
#[test]
fn a_no_input_ancestry_beside_a_proven_stranger_is_refused_inline() {
    let (bytes, root, starts) = ancestry(true);
    let (answer, asked) = inline(&bytes, &root);
    refused_naming(&answer, starts[1], "NoInputs");
    assert_eq!(asked, 0, "refused before any lookup");
}

/// The same object at rest: the same refusal in one request and across
/// requests.
#[test]
fn a_no_input_ancestry_beside_a_proven_stranger_is_refused_at_rest() {
    let (bytes, root, starts) = ancestry(true);
    let (inline_answer, _) = inline(&bytes, &root);
    let (answer, pending, asked, left) = at_rest(&bytes, &root, false);
    refused_naming(&answer, starts[1], "NoInputs");
    assert_eq!((pending, asked, left), (0, 0, false));
    assert_eq!(answer, inline_answer, "the inline refusal, word for word");
    let (resumed, pending, asked, left) = at_rest(&bytes, &root, true);
    assert_eq!(resumed, answer, "the same refusal across requests");
    assert_eq!(pending, 2, "the BUMP and the stranger, then the refusal");
    assert_eq!((asked, left), (0, false));
}
