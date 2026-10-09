//! The chain builder of the NL-4 deep-BEEF witness (`tests/deep_beef_door.rs`),
//! shared with the hand-off witness (`tests/handoff_at_rest.rs`, NL-4b).
//!
//! The chain is built byte by byte (no library walk builds it): each link is
//! a transaction spending output 0 of the one before, the oldest proven by a
//! one-leaf BUMP (a block of one transaction, so its root is that txid), and
//! the subject pays the server's BRC-29 key the fee.
#![allow(dead_code)]

use bsv_middleware_rs::{HeaderLookupError, HeaderService};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const FEE: u64 = 100;
pub const SERVER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
pub const SENDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
pub const PREFIX: &str = "cHJlZml4";
pub const SUFFIX: &str = "c3VmZml4";

pub fn wallet(hex: &str) -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_hex(hex).unwrap()))
}

/// The payer's side of BRC-29: the server's derived P2PKH script.
pub fn server_script() -> Vec<u8> {
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

pub fn varint(n: u64, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// One input spending `prev:0`, output 0 of `satoshis` at `script`, and a
/// second output carrying `ballast` bytes when there are any.
pub fn raw_tx(prev: &[u8; 32], satoshis: u64, script: &[u8], ballast: usize) -> Vec<u8> {
    let mut t = Vec::with_capacity(80 + script.len() + ballast);
    t.extend_from_slice(&1u32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(prev);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(if ballast > 0 { 2 } else { 1 });
    t.extend_from_slice(&satoshis.to_le_bytes());
    varint(script.len() as u64, &mut t);
    t.extend_from_slice(script);
    if ballast > 0 {
        t.extend_from_slice(&0u64.to_le_bytes());
        varint(ballast as u64, &mut t);
        t.resize(t.len() + ballast, 0x6a);
    }
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The txid in internal byte order.
pub fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(raw)).into()
}

/// The script of an output the next link spends: `OP_TRUE`, which that
/// link's empty unlocking script satisfies. The door runs the scripts of
/// unproven transactions (NL-4c), so a link is a spend a script allows.
pub const SPENT: &[u8] = &[0x51];

/// The height of the block the oldest link is proven in.
pub const HEIGHT: u32 = 850_000;

/// A chain as the witness reads it: the Atomic BEEF, the root its BUMP
/// computes (the oldest link's txid, as hex), and where each link's raw
/// transaction starts in the BEEF.
pub struct Chain {
    pub beef: Vec<u8>,
    pub root: String,
    pub starts: Vec<usize>,
}

/// An Atomic BEEF (BRC-95 over BEEF V2) of `links` transactions, oldest
/// first, the oldest proven by a one-leaf BUMP at `HEIGHT` and the rest
/// unproven, the last paying the server `FEE` at output 0. The oldest link
/// carries `ballast` bytes in a second output nothing spends.
pub fn chain_atomic_beef(links: usize, ballast: usize) -> Chain {
    let mut txs = Vec::with_capacity(links);
    let mut prev = [0x11u8; 32]; // the oldest spends an outpoint not in the BEEF
    for i in 0..links {
        let raw = if i + 1 == links {
            raw_tx(&prev, FEE, &server_script(), 0)
        } else {
            raw_tx(&prev, 1_000, SPENT, if i == 0 { ballast } else { 0 })
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
    varint(links as u64, &mut beef);
    let mut starts = Vec::with_capacity(links);
    for (i, raw) in txs.into_iter().enumerate() {
        if i == 0 {
            beef.extend_from_slice(&[1, 0]); // raw transaction proven by BUMP 0
        } else {
            beef.push(0); // raw transaction, no bump index
        }
        starts.push(beef.len());
        beef.extend_from_slice(&raw);
    }
    let root = hex::encode(oldest.iter().rev().copied().collect::<Vec<u8>>());
    Chain { beef, root, starts }
}

/// A chain of `links` links whose BEEF is exactly `bytes` long.
pub fn chain_of_exactly(links: usize, bytes: usize) -> Chain {
    let bare = chain_atomic_beef(links, 0).beef.len();
    // The second output costs its 8 satoshi bytes, a 5-byte length and the
    // ballast itself.
    let ballast = bytes - bare - 8 - 5;
    assert!(ballast > 0xffff, "the ballast's length takes five bytes");
    let chain = chain_atomic_beef(links, ballast);
    assert_eq!(chain.beef.len(), bytes);
    chain
}

/// The header service of the witness: the chain's root at `HEIGHT`, nothing
/// elsewhere; counts what it is asked.
pub struct ChainHeaders {
    pub root: String,
    pub asked: Arc<AtomicUsize>,
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
