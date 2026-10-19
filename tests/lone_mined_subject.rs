//! W19: a mined subject alone in its BEEF through the payment door (the six
//! `lone` cells of NL-8, bsv-stack-lean `docs/p0/doors-and-messaging-reading.md`
//! section 3).
//!
//! The rows' bytes are the stack's (`corpus/beef-of-any-size/bytes/`, landed at
//! bsv-stack-lean `2745a8c`), copied under `tests/fixtures/`:
//!
//! - `lone.bin`, 109 bytes, sha256
//!   `38656f4c184e754b42b8a30cfc09c959b971a971744db34456d3da3a741fbb50`: one
//!   BUMP (height 800005, one leaf, the transaction's txid) and one
//!   transaction whose single input is the null outpoint, carrying BUMP index
//!   0: a proven coinbase paying one satoshi to an empty script at output 0.
//! - `lone_atomic.bin`, 145 bytes, sha256
//!   `4fc97f61e5c2598b1971d3724d358cf5216fd64be4e67a770ff30cbd188ce3bc`: the
//!   same behind the Atomic prefix.
//!
//! The Lean row accepts both. Through 0.5.5 the door handed the middleware's
//! output check the subject with no BUMP index, and every entry refused them
//! `InvalidBeef { offset: 7, kind: UnprovenCoinbase }`; since 0.5.6 the check
//! is given the BUMP that proves the subject, and each entry accepts.
//!
//! The entries are the stack's runner's (`corpus/runners/rust-message-box/`):
//! `verify_inline` on a hex carrier, `verify_at_rest` on an object read in
//! 40-byte chunks in one request, and the same resumed with a slice of no
//! time, one element per request.

use std::cell::RefCell;
use std::collections::HashMap;

use async_trait::async_trait;
use bsv_middleware_rs::{HeaderLookupError, HeaderService, PaymentVerdict};
use rust_message_box::beef_door::{
    verify_at_rest, verify_inline, work_units_per_input, AtRest, BeefStore, Carrier, Chunks,
    DoorVerdict, Slice, Slices, Stamp, Terms,
};
use sha2::{Digest, Sha256};

const LONE: &[u8] = include_bytes!("fixtures/lone.bin");
const LONE_SHA256: &str = "38656f4c184e754b42b8a30cfc09c959b971a971744db34456d3da3a741fbb50";
const LONE_ATOMIC: &[u8] = include_bytes!("fixtures/lone_atomic.bin");
const LONE_ATOMIC_SHA256: &str = "4fc97f61e5c2598b1971d3724d358cf5216fd64be4e67a770ff30cbd188ce3bc";

/// The row's chain: the header at 800005 carries the BUMP's root.
const HEIGHT: u32 = 800_005;
const ROOT: &str = "f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f";

const TERMS: Terms<'static> = Terms {
    output_index: 0,
    expected_script: &[],
    required_satoshis: 1,
};

/// Answers the row's root at its height, and `root` there when another is
/// asked for; fails every other height.
struct Headers(&'static str);

#[async_trait]
impl HeaderService for Headers {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        if height == HEIGHT {
            Ok(self.0.to_string())
        } else {
            Err(HeaderLookupError(format!("no header at {height}")))
        }
    }
}

struct Bytes {
    data: Vec<u8>,
    at: usize,
}

#[async_trait(?Send)]
impl Chunks for Bytes {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.at >= self.data.len() {
            return Ok(None);
        }
        let end = (self.at + 40).min(self.data.len());
        let chunk = self.data[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

struct Store {
    object: Vec<u8>,
    state: RefCell<HashMap<String, Vec<u8>>>,
}

const KEY: &str = "02aa/lone.beef";

#[async_trait(?Send)]
impl BeefStore for Store {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        Ok((key == KEY).then(|| Stamp {
            size: self.object.len() as u64,
            etag: "lone".to_string(),
        }))
    }
    async fn open(&self, _key: &str, from: u64, _stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        Ok(Box::new(Bytes {
            data: self.object[from as usize..].to_vec(),
            at: 0,
        }))
    }
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.state.borrow().get(key).cloned())
    }
    async fn save(&self, key: &str, state: Vec<u8>) -> Result<(), String> {
        self.state.borrow_mut().insert(key.to_string(), state);
        Ok(())
    }
    async fn clear(&self, key: &str) -> Result<(), String> {
        self.state.borrow_mut().remove(key);
        Ok(())
    }
}

fn block_on<T>(run: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(run)
}

fn row(bytes: &'static [u8], sha256: &str) -> &'static [u8] {
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        sha256,
        "the row's bytes"
    );
    bytes
}

fn inline(bytes: &[u8], root: &'static str) -> DoorVerdict {
    let hexed = hex::encode(bytes);
    block_on(verify_inline(
        &Carrier::Hex(&hexed),
        &TERMS,
        Some(&Headers(root)),
    ))
    .unwrap()
}

/// The object through the door, request after request; the verdict and the
/// requests it took.
fn at_rest(bytes: &[u8], root: &'static str, millis: u64) -> (DoorVerdict, u64) {
    let store = Store {
        object: bytes.to_vec(),
        state: RefCell::new(HashMap::new()),
    };
    let clock = || 0u64;
    let slices = Slices {
        time: Slice {
            clock: &clock,
            millis,
        },
        lookups: usize::MAX,
        inputs: u64::MAX,
        weight: u64::MAX,
        work_units: work_units_per_input(),
    };
    for requests in 1.. {
        match block_on(verify_at_rest(
            &store,
            KEY,
            &TERMS,
            Some(&Headers(root)),
            &slices,
        ))
        .unwrap()
        {
            AtRest::Done(verdict) => return (verdict, requests),
            AtRest::Pending(_) => continue,
            AtRest::NotFound => panic!("the object is there"),
        }
    }
    unreachable!()
}

fn accepted(verdict: &DoorVerdict, bytes: &[u8]) {
    assert_eq!(
        verdict.word,
        PaymentVerdict::Verified { satoshis: 1 },
        "{verdict:?}"
    );
    assert_eq!(verdict.named, None);
    // The subject named is the coinbase, the BEEF's last 60 bytes before
    // its BUMP index (V1: has-BUMP 01, index 00); a block of one transaction,
    // so its txid is the BUMP's root.
    let raw = &bytes[bytes.len() - 2 - 60..bytes.len() - 2];
    let mut txid: [u8; 32] = Sha256::digest(Sha256::digest(raw)).into();
    assert_eq!(verdict.subject, Some(txid));
    txid.reverse();
    assert_eq!(verdict.txid().as_deref(), Some(ROOT));
    assert_eq!(hex::encode(txid), ROOT);
}

#[test]
fn lone_inline_is_accepted() {
    let bytes = row(LONE, LONE_SHA256);
    accepted(&inline(bytes, ROOT), bytes);
}

#[test]
fn lone_at_rest_is_accepted() {
    let bytes = row(LONE, LONE_SHA256);
    let (verdict, requests) = at_rest(bytes, ROOT, u64::MAX);
    accepted(&verdict, bytes);
    assert_eq!(requests, 1);
}

#[test]
fn lone_at_rest_resumed_is_accepted() {
    let bytes = row(LONE, LONE_SHA256);
    let (verdict, requests) = at_rest(bytes, ROOT, 0);
    accepted(&verdict, bytes);
    assert!(requests > 1, "one element per request: {requests}");
}

#[test]
fn lone_atomic_inline_is_accepted() {
    let bytes = row(LONE_ATOMIC, LONE_ATOMIC_SHA256);
    accepted(&inline(bytes, ROOT), bytes);
}

#[test]
fn lone_atomic_at_rest_is_accepted() {
    let bytes = row(LONE_ATOMIC, LONE_ATOMIC_SHA256);
    let (verdict, requests) = at_rest(bytes, ROOT, u64::MAX);
    accepted(&verdict, bytes);
    assert_eq!(requests, 1);
}

#[test]
fn lone_atomic_at_rest_resumed_is_accepted() {
    let bytes = row(LONE_ATOMIC, LONE_ATOMIC_SHA256);
    let (verdict, requests) = at_rest(bytes, ROOT, 0);
    accepted(&verdict, bytes);
    assert!(requests > 1, "one element per request: {requests}");
}

/// The proof handed to the output check is the payer's BUMP, not a pass: its
/// root is still asked of the header service, and a header carrying another
/// root refuses the payment at every entry.
#[test]
fn a_lone_subject_whose_root_is_not_carried_is_still_refused() {
    const OTHER: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    for bytes in [row(LONE, LONE_SHA256), row(LONE_ATOMIC, LONE_ATOMIC_SHA256)] {
        for verdict in [
            inline(bytes, OTHER),
            at_rest(bytes, OTHER, u64::MAX).0,
            at_rest(bytes, OTHER, 0).0,
        ] {
            assert!(
                matches!(
                    verdict.word,
                    PaymentVerdict::RootMismatch { height: HEIGHT, .. }
                ),
                "{verdict:?}"
            );
        }
    }
}
