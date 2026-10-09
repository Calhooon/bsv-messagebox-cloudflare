//! NL-4 (the no-limits program, bsv-stack-lean `docs/charters/beef-of-any-size.md`):
//! a stranger's BEEF of any size at the message box's payment door.
//!
//! The posture: a valid BEEF is never refused for its size or its counts; a
//! refusal is for invalid bytes only, and names them (the offset and the
//! kind). This file is the P0-5b witness of 0.3.28 inverted. Until 0.4.0 the
//! door refused a payment above 4 MiB (413 on the route, `PaymentTooLarge`
//! under the delivery check) and a BEEF of more than 128 transactions
//! (`BeefTransactionsExceeded`, the P0-5d door). Here the same shapes, valid,
//! are accepted, and the same shapes with one wrong byte are refused at that
//! byte.
//!
//! Every run is on a thread with a 1 MiB stack (the order of a WASM stack in
//! a Worker, whose size is not measured here): the reader is the streaming
//! one of bsv-rs 0.4.0, one element in hand, so depth costs neither stack nor
//! a copy of the body.
//!
//! The chain is built byte by byte (no library walk builds it): each link is
//! a transaction spending output 0 of the one before, the oldest proven by a
//! one-leaf BUMP (a block of one transaction, so its root is that txid), and
//! the subject pays the server's BRC-29 key the fee.

mod support;

use rust_message_box::payments::check_delivery_output;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::*;

/// The door of 0.3.28 to 0.3.31, in bytes: gone in 0.4.0, named here so the
/// witness stands one byte over it.
const THE_OLD_DOOR: usize = 4 * 1024 * 1024;
/// The count door of the same releases (bsv-middleware-rs 0.3.0
/// `MAX_PAYMENT_BEEF_TXS`).
const THE_OLD_COUNT: usize = 128;

/// The three shapes of `tx` the route reads.
#[derive(Clone, Copy, Debug)]
enum Shape {
    Hex,
    Array,
    Base64,
}

fn shaped(beef: &[u8], shape: Shape) -> Value {
    use base64::Engine as _;
    match shape {
        Shape::Hex => json!(hex::encode(beef)),
        Shape::Array => json!(beef),
        Shape::Base64 => {
            json!({ "beef": base64::engine::general_purpose::STANDARD.encode(beef) })
        }
    }
}

/// The delivery check on `beef`, on a thread with a 1 MiB stack: the answer
/// (the satoshis, or the status and the body of the refusal) and how many
/// times the header service was asked.
fn delivery_check(beef: &[u8], root: &str, shape: Shape) -> (Result<u64, (u16, Value)>, usize) {
    let tx = shaped(beef, shape);
    let sender = wallet(SENDER_KEY).identity_key().to_hex();
    let remittance = json!({
        "outputIndex": 0,
        "protocol": "wallet payment",
        "paymentRemittance": {
            "derivationPrefix": PREFIX,
            "derivationSuffix": SUFFIX,
            "senderIdentityKey": sender
        }
    });
    let asked = Arc::new(AtomicUsize::new(0));
    let headers = ChainHeaders {
        root: root.to_string(),
        asked: asked.clone(),
    };
    let answer = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(check_delivery_output(
                    &tx,
                    &remittance,
                    FEE,
                    &sender,
                    &wallet(SERVER_KEY),
                    Some(&headers),
                ))
                .map_err(|(body, status)| (status, body))
        })
        .unwrap()
        .join()
        .expect("the delivery check returned");
    (answer, asked.load(Ordering::SeqCst))
}

fn accepted(chain: &Chain, shape: Shape) {
    let (answer, asked) = delivery_check(&chain.beef, &chain.root, shape);
    assert_eq!(answer, Ok(FEE), "{shape:?}: a valid BEEF is accepted");
    assert_eq!(asked, 1, "{shape:?}: its one root is asked once");
}

/// A refusal for invalid bytes: 400, the offset and the kind in the body and
/// in its text.
fn refused_naming(answer: Result<u64, (u16, Value)>, offset: usize, kind: &str) {
    let (status, body) = answer.expect_err("invalid bytes are refused");
    assert_eq!(status, 400, "the payer's bytes: {body}");
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT", "{body}");
    assert_eq!(body["offset"], json!(offset), "names the offset: {body}");
    assert_eq!(body["kind"], json!(kind), "names the kind: {body}");
    let text = body["description"].as_str().unwrap();
    assert!(
        text.contains(&format!("offset {offset}")) && text.contains(kind),
        "the text names both: {text}"
    );
}

/// The control: the shape at a size no door ever minded.
#[test]
fn a_shallow_chain_is_accepted() {
    let chain = chain_atomic_beef(10, 0);
    eprintln!("deep_beef_door: 10 links, {} bytes", chain.beef.len());
    for shape in [Shape::Hex, Shape::Array, Shape::Base64] {
        accepted(&chain, shape);
    }
}

/// A valid payment one byte over the old 4 MiB door is accepted, in each of
/// the three shapes of `tx`. (0.3.31: `PaymentTooLarge` under the delivery
/// check, 413 `ERR_BODY_TOO_LARGE` on the route.)
#[test]
fn a_valid_payment_one_byte_over_the_old_door_is_accepted() {
    let chain = chain_of_exactly(10, THE_OLD_DOOR + 1);
    eprintln!("deep_beef_door: 10 links, {} bytes", chain.beef.len());
    for shape in [Shape::Hex, Shape::Array, Shape::Base64] {
        accepted(&chain, shape);
    }
}

/// A valid chain one transaction over the old count is accepted. (0.3.31:
/// `BeefTransactionsExceeded`, "129 transactions, over max_txs 128".)
#[test]
fn a_valid_chain_one_transaction_over_the_old_count_is_accepted() {
    let chain = chain_atomic_beef(THE_OLD_COUNT + 1, 0);
    eprintln!(
        "deep_beef_door: {} links, {} bytes",
        THE_OLD_COUNT + 1,
        chain.beef.len()
    );
    accepted(&chain, Shape::Hex);
}

/// A valid chain of 100,000 unproven links ending at a proven parent is
/// accepted on the 1 MiB thread: over the old count and over the old door at
/// once.
#[test]
fn a_valid_chain_of_100_000_links_is_accepted() {
    let chain = chain_atomic_beef(100_000, 0);
    eprintln!("deep_beef_door: 100000 links, {} bytes", chain.beef.len());
    assert!(chain.beef.len() > THE_OLD_DOOR);
    accepted(&chain, Shape::Hex);
}

/// The same chain with one byte wrong at depth is refused for that byte: the
/// link at 60,000 names a previous txid no element carries. The refusal names
/// the offset of those 32 bytes and the kind; the header service is asked
/// nothing, since no root is asked before the bytes are read to their end.
#[test]
fn a_deep_chain_with_one_wrong_byte_is_refused_naming_it() {
    let mut chain = chain_atomic_beef(100_000, 0);
    // A link: version (4), input count (1), then the previous txid.
    let prev_at = chain.starts[60_000] + 5;
    chain.beef[prev_at] ^= 0x01;
    let (answer, asked) = delivery_check(&chain.beef, &chain.root, Shape::Hex);
    refused_naming(answer, prev_at, "InputNamesNoElement");
    assert_eq!(asked, 0, "refused before any lookup");
}

/// A body over the old door cut one byte short is refused for the byte that
/// is missing, not for its size: the last field of the subject (its lock
/// time, four bytes) ran out.
#[test]
fn a_body_over_the_old_door_cut_short_is_refused_naming_where() {
    let mut chain = chain_of_exactly(10, THE_OLD_DOOR + 2);
    chain.beef.pop();
    assert_eq!(chain.beef.len(), THE_OLD_DOOR + 1);
    let lock_time_at = chain.beef.len() - 3;
    let (answer, asked) = delivery_check(&chain.beef, &chain.root, Shape::Hex);
    refused_naming(answer, lock_time_at, "Truncated");
    assert_eq!(asked, 0, "refused before any lookup");
}
