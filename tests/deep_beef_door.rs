//! P0-5b (bsv-stack-lean #57, H1): a stranger's deep BEEF at the message
//! box's payment door.
//!
//! The delivery check hands the payment to `verify_payment`
//! (bsv-middleware-rs 0.3.0 `src/payment_core.rs:329-398`), which parses it
//! with the BEEF counts bounded by `PAYMENT_BEEF_LIMITS`
//! (`src/payment_core.rs:67-71` there, `max_txs` 128, the P0-5d door,
//! unchanged from 0.2.2). Under bsv-rs 0.3.20 the walk that links the
//! subject's unproven ancestry recursed once per link
//! (`attach_proof_recursive`, bsv-rs 0.3.20 `src/transaction/beef.rs:144-197`)
//! and a 50,000-link chain aborted a 1 MiB stack, the H1 this file was
//! written for. Under bsv-rs 0.3.35, the version this crate links, the walk
//! is iterative (`add_input_proof`, `src/transaction/beef.rs:214-296`: an
//! explicit stack of frames visited in the recursion's order), so a
//! stranger's chain of unproven transactions costs heap, not stack.
//!
//! The witness states the door's rule, every run on a thread with a 1 MiB
//! stack (the order of a WASM stack in a Worker, whose size is not measured
//! here): a chain one transaction over the bound is refused with an error
//! naming the transaction count and the bound, before the header service is
//! asked anything, and a chain exactly at the bound parses through the door,
//! its structure is walked, its one root is asked of the header service and
//! the delivery output is judged as before. Never an abort, never a stack
//! overflow: the refusal and the parse alike come back as the check's
//! answer, so the process exits normally.
//!
//! The chain is built byte by byte (no library walk builds it): each link
//! is a 60-byte transaction spending output 0 of the one before, the oldest
//! proven by a one-leaf BUMP (a block of one transaction, so its root is
//! that txid; since 0.3.29 the check is the full one and a chain with no
//! proof is refused as incomplete), and the subject pays the server's BRC-29
//! key the fee. It fits under `MAX_PAYMENT_BODY_BYTES`, so the body bound
//! does not stop it; the BEEF count bound does.

use bsv_middleware_rs::{HeaderLookupError, HeaderService, PAYMENT_BEEF_LIMITS};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use rust_message_box::payments::{check_delivery_output, MAX_PAYMENT_BODY_BYTES};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

/// The height of the block the oldest link is proven in.
const HEIGHT: u32 = 850_000;

/// An Atomic BEEF (BRC-95 over BEEF V2) of `links` transactions, oldest
/// first, the oldest proven by a one-leaf BUMP at `HEIGHT` and the rest
/// unproven, the last paying the server `FEE` at output 0. Returns the BEEF
/// and the root the BUMP computes (the oldest link's txid, as hex).
fn chain_atomic_beef(links: usize) -> (Vec<u8>, String) {
    let mut txs = Vec::with_capacity(links);
    let mut prev = [0x11u8; 32]; // the oldest spends an outpoint not in the BEEF
    for i in 0..links {
        let raw = if i + 1 == links {
            raw_tx(&prev, FEE, &server_script())
        } else {
            raw_tx(&prev, 1_000, &[])
        };
        prev = hash(&raw);
        txs.push(raw);
    }
    let oldest = hash(&txs[0]);
    let mut beef = Vec::new();
    beef.extend_from_slice(&0x0101_0101u32.to_le_bytes());
    beef.extend_from_slice(&prev);
    beef.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
    beef.push(1); // one BUMP (BRC-74)
    beef.push(0xfe);
    beef.extend_from_slice(&HEIGHT.to_le_bytes());
    beef.push(1); // tree height
    beef.push(1); // one leaf at level 0
    beef.push(0); // offset 0
    beef.push(2); // the leaf is a txid
    beef.extend_from_slice(&oldest);
    beef.push(0xfd);
    beef.extend_from_slice(&u16::try_from(links).unwrap().to_le_bytes());
    for (i, raw) in txs.into_iter().enumerate() {
        if i == 0 {
            beef.extend_from_slice(&[1, 0]); // raw transaction proven by BUMP 0
        } else {
            beef.push(0); // raw transaction, no bump index
        }
        beef.extend_from_slice(&raw);
    }
    let root = hex::encode(oldest.iter().rev().copied().collect::<Vec<u8>>());
    (beef, root)
}

/// The header service of the witness: the chain's root at `HEIGHT`, nothing
/// elsewhere; counts what it is asked.
struct ChainHeaders {
    root: String,
    asked: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl HeaderService for ChainHeaders {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if height == HEIGHT {
            Ok(self.root.clone())
        } else {
            Err(HeaderLookupError(format!("no header at {height}")))
        }
    }
}

/// The delivery check on `links` links, on a thread with a 1 MiB stack: the
/// answer and how many times the header service was asked.
fn delivery_check_on_a_chain(links: usize) -> (Result<u64, String>, usize) {
    let (beef, root) = chain_atomic_beef(links);
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
    let asked = Arc::new(AtomicUsize::new(0));
    let headers = ChainHeaders {
        root,
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
                .map_err(|(body, status)| format!("{status} {body}"))
        })
        .unwrap()
        .join()
        .expect("the delivery check returned");
    (answer, asked.load(Ordering::SeqCst))
}

/// The control: the same bytes at a count no stack minds are a valid Atomic
/// BEEF the check accepts, so the run over the bound is refused only on its
/// count.
#[test]
fn a_shallow_chain_of_the_same_shape_is_accepted() {
    assert_eq!(delivery_check_on_a_chain(10), (Ok(FEE), 1));
}

/// The door's rule (P0-5d, unchanged at 0.3.0): a chain one transaction over
/// the bound is refused, the error naming the transaction count and the
/// bound, and the header service is asked nothing. The run returns the
/// refusal as the check's answer, so the process exits normally; nothing
/// under the door aborts or overflows the 1 MiB stack.
#[test]
fn a_chain_one_transaction_over_the_bound_is_refused_naming_it() {
    let bound = PAYMENT_BEEF_LIMITS.max_txs;
    let (answer, asked) = delivery_check_on_a_chain(bound + 1);
    let refusal = answer.expect_err("a chain over the bound is refused");
    assert!(refusal.starts_with("400 "), "the payer's fault: {refusal}");
    assert_eq!(asked, 0, "refused before any lookup");
    let count = format!("{} transactions", bound + 1);
    let limit = format!("max_txs {bound}");
    assert!(refusal.contains(&count), "names the count: {refusal}");
    assert!(refusal.contains(&limit), "names the bound: {refusal}");
}

/// A chain exactly at the bound parses through the door on the 1 MiB thread
/// (the walk on the heap at bsv-rs 0.3.35), its one root is asked once, and
/// the delivery output is judged as before: the fee is paid.
#[test]
fn a_chain_exactly_at_the_bound_parses_through_the_door() {
    assert_eq!(
        delivery_check_on_a_chain(PAYMENT_BEEF_LIMITS.max_txs),
        (Ok(FEE), 1)
    );
}
