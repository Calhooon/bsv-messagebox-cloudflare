//! P0-5b (bsv-stack-lean #57, H1): a stranger's deep BEEF at the message
//! box's payment door.
//!
//! The delivery check hands the payment to `verify_payment_output`
//! (bsv-middleware-rs 0.2.2 `src/payment.rs:306-324`), which parses it with
//! the BEEF counts bounded by `PAYMENT_BEEF_LIMITS` (`src/payment.rs:162-167`
//! there, `max_txs` 128, the P0-5d door). Under bsv-rs 0.3.20 the walk that
//! links the subject's unproven ancestry recursed once per link
//! (`attach_proof_recursive`, bsv-rs 0.3.20 `src/transaction/beef.rs:144-197`)
//! and a 50,000-link chain aborted a 1 MiB stack, the H1 this file was
//! written for. Under bsv-rs 0.3.35, the version this crate links, the walk
//! is iterative (`add_input_proof`, `src/transaction/beef.rs:214-296`: an
//! explicit stack of frames visited in the recursion's order), so a
//! stranger's chain of unproven transactions costs heap, not stack.
//!
//! The witness states the door's rule at 0.2.2, every run on a thread with
//! a 1 MiB stack (the order of a WASM stack in a Worker, whose size is not
//! measured here): a chain one transaction over the bound is refused with an
//! error naming the transaction count and the bound, and a chain exactly at
//! the bound parses through the door and the delivery output is judged as
//! before. Never an abort, never a stack overflow: the refusal and the parse
//! alike come back as the check's answer, so the process exits normally.
//!
//! The chain is built byte by byte (no library walk builds it): each link
//! is a 60-byte transaction spending output 0 of the one before, and the
//! subject pays the server's BRC-29 key the fee. It fits under
//! `MAX_PAYMENT_BODY_BYTES`, so the body bound does not stop it; the BEEF
//! count bound does.

use bsv_middleware_rs::PAYMENT_BEEF_LIMITS;
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use rust_message_box::payments::{check_delivery_output, MAX_PAYMENT_BODY_BYTES};
use serde_json::json;
use sha2::{Digest, Sha256};

const FEE: u64 = 100;
const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const PREFIX: &str = "cHJlZml4";
const SUFFIX: &str = "c3VmZml4";

fn wallet(hex: &str) -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
}

/// The payer's side of BRC-29: the server's derived P2PKH script.
fn server_script() -> Vec<u8> {
    let derived = wallet(SENDER_KEY)
        .get_public_key(GetPublicKeyArgs {
            identity_key: false,
            protocol_id: Some(Protocol::new(SecurityLevel::Counterparty, "3241645161d8")),
            key_id: Some(format!("{PREFIX} {SUFFIX}")),
            counterparty: Some(Counterparty::Other(wallet(SERVER_KEY).identity_key())),
            for_self: Some(false),
        })
        .unwrap();
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&PublicKey::from_hex(&derived.public_key).unwrap().hash160());
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

/// One input spending `prev:0`, one output of `satoshis` at `script`.
fn raw_tx(prev: &[u8; 32], satoshis: u64, script: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(60 + script.len());
    t.extend_from_slice(&1u32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(prev);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(1);
    t.extend_from_slice(&satoshis.to_le_bytes());
    t.push(script.len() as u8);
    t.extend_from_slice(script);
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The txid in internal byte order.
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(raw)).into()
}

/// An Atomic BEEF (BRC-95 over BEEF V2) of `links` unproven transactions,
/// oldest first, the last paying the server `FEE` at output 0.
fn chain_atomic_beef(links: usize) -> Vec<u8> {
    let mut txs = Vec::with_capacity(links);
    let mut prev = [0x11u8; 32]; // the root spends an outpoint not in the BEEF
    for i in 0..links {
        let raw = if i + 1 == links {
            raw_tx(&prev, FEE, &server_script())
        } else {
            raw_tx(&prev, 1_000, &[])
        };
        prev = hash(&raw);
        txs.push(raw);
    }
    let mut beef = Vec::new();
    beef.extend_from_slice(&0x0101_0101u32.to_le_bytes());
    beef.extend_from_slice(&prev);
    beef.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
    beef.push(0); // no bumps
    beef.push(0xfd);
    beef.extend_from_slice(&u16::try_from(links).unwrap().to_le_bytes());
    for raw in txs {
        beef.push(0); // raw transaction, no bump index
        beef.extend_from_slice(&raw);
    }
    beef
}

/// The delivery check on `links` links, on a thread with a 1 MiB stack.
fn delivery_check_on_a_chain(links: usize) -> Result<u64, String> {
    let beef = chain_atomic_beef(links);
    eprintln!("deep_beef_door: {links} links, {} bytes", beef.len());
    assert!(
        beef.len() <= MAX_PAYMENT_BODY_BYTES,
        "the body fits under the door's bound"
    );
    let tx = json!(hex::encode(&beef));
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
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || {
            check_delivery_output(&tx, &remittance, FEE, &sender, &wallet(SERVER_KEY))
                .map_err(|(body, status)| format!("{status} {body}"))
        })
        .unwrap()
        .join()
        .expect("the delivery check returned")
}

/// The control: the same bytes at a count no stack minds are a valid Atomic
/// BEEF the check accepts, so the run over the bound is refused only on its
/// count.
#[test]
fn a_shallow_chain_of_the_same_shape_is_accepted() {
    assert_eq!(delivery_check_on_a_chain(10), Ok(FEE));
}

/// The door's rule at 0.2.2 (P0-5d): a chain one transaction over the bound
/// is refused, the error naming the transaction count and the bound. The run
/// returns the refusal as the check's answer, so the process exits normally;
/// nothing under the door aborts or overflows the 1 MiB stack.
#[test]
fn a_chain_one_transaction_over_the_bound_is_refused_naming_it() {
    let bound = PAYMENT_BEEF_LIMITS.max_txs;
    let refusal =
        delivery_check_on_a_chain(bound + 1).expect_err("a chain over the bound is refused");
    let count = format!("{} transactions", bound + 1);
    let limit = format!("max_txs {bound}");
    assert!(refusal.contains(&count), "names the count: {refusal}");
    assert!(refusal.contains(&limit), "names the bound: {refusal}");
}

/// A chain exactly at the bound parses through the door on the 1 MiB thread
/// (the walk on the heap at bsv-rs 0.3.35), and the delivery output is then
/// judged as before: the fee is paid.
#[test]
fn a_chain_exactly_at_the_bound_parses_through_the_door() {
    assert_eq!(
        delivery_check_on_a_chain(PAYMENT_BEEF_LIMITS.max_txs),
        Ok(FEE)
    );
}
