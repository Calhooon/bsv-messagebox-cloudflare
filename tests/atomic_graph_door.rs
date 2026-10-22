//! The atomic rule on the subject's graph (bsv-rs 0.8.1, BRC-95; the owner's
//! rulings of 2026-10-22) through the payment door: the stack's W4 rows
//! (bsv-stack-lean `corpus/beef-of-any-size/rows.json`, the words of its
//! `lean/BeefOfAnySize.lean` on the graph).
//!
//! The rows' bytes are the stack's (`corpus/beef-of-any-size/bytes/`, at
//! bsv-stack-lean `1d87346`), copied under `tests/fixtures/`:
//!
//! - `wrong_subject.bin`, 339 bytes: the subject carried and the third link
//!   outside its graph; refused `unrelatedTransaction` at 278.
//! - `unrelated.bin`, 400 bytes: a side transaction nothing in the subject's
//!   graph spends; refused `unrelatedTransaction` at 278.
//! - `example_atomic_parent.bin`, 713 bytes: the BRC-62 example behind an
//!   Atomic prefix naming the parent; the payment is outside the parent's
//!   graph, refused `unrelatedTransaction` at 521.
//! - `subject_proven_first.bin`, 331 bytes: the subject (proven, BUMP 1) the
//!   second raw transaction and its unproven ancestor the third (the TS
//!   writer's order); accepted by the rule, five elements. Through bsv-rs
//!   0.8.0 the rule was positional (the subject the last raw transaction):
//!   0.8.0's structure pass refuses these bytes `SubjectMissing` at 4.
//! - `subject_proven_first_true.bin`, 336 bytes: the row's scripted twin,
//!   every output locked by OP_TRUE; accepted by the rule (0.8.0: the same
//!   refusal).
//!
//! The rule is the door's structure pass (bsv-rs's `structure_only` reading,
//! the Lean's validity), and the two accepted rows pass it. The door then
//! runs every script and holds an unproven transaction to what it spends,
//! which the rows were not written to meet: the plain row's ancestor unlocks
//! an empty script with none (`SpendRefused` at 266, the clean stack), and
//! the twin's ancestor pays out more than it spends (`SpendRefused` at 264,
//! `CreatesValue`). Each is pinned by its name, never `unrelatedTransaction`.
//!
//! The entries are the stack's runner's (`corpus/runners/rust-message-box/`):
//! `verify_inline` on a hex carrier, `verify_at_rest` on an object read in
//! 40-byte chunks in one request, and the same resumed with a slice of no
//! time, one element per request. Every entry answers the same.

use std::cell::RefCell;
use std::collections::HashMap;

use async_trait::async_trait;
use bsv_middleware_rs::{HeaderLookupError, HeaderService, PaymentVerdict};
use bsv_rs::primitives::sha256;
use bsv_rs::transaction::beef_stream::Hash32;
use bsv_rs::transaction::{Headers as Roots, Progress, StreamVerifier};
use rust_message_box::beef_door::{
    verify_at_rest, verify_inline, work_units_per_input, AtRest, BeefStore, Carrier, Chunks,
    DoorVerdict, Named, Slice, Slices, Stamp, Terms,
};

/// One row: its bytes and their sha256, its chain, its payment.
struct Row {
    bytes: &'static [u8],
    sha256: &'static str,
    chain: &'static [(u32, &'static str)],
    satoshis: u64,
    script: &'static [u8],
}

const CHAIN: &[(u32, &str)] = &[(
    800_000,
    "0c1511adca15eabe28c6c6b2d0704df0500a23891071c4f658355a6e30d6aa70",
)];

const WRONG_SUBJECT: Row = Row {
    bytes: include_bytes!("fixtures/wrong_subject.bin"),
    sha256: "21daceb21815c50268ca5d6e2d519624e4644e645fd61d5f98c6e85cabf001f1",
    chain: CHAIN,
    satoshis: 1,
    script: &[],
};

const UNRELATED: Row = Row {
    bytes: include_bytes!("fixtures/unrelated.bin"),
    sha256: "67e0655ebb028993c1283fb3475bea823a5a7524f007ec8f70808612e8cbaad8",
    chain: CHAIN,
    satoshis: 1,
    script: &[],
};

/// The example's payment: 26,174 satoshis to a P2PKH script.
const P2PKH: &[u8] = &[
    0x76, 0xa9, 0x14, 0x6b, 0xfd, 0x5c, 0x7f, 0xbe, 0x21, 0x52, 0x9d, 0x45, 0x80, 0x3d, 0xbc, 0xf0,
    0xc8, 0x7d, 0xd3, 0xc7, 0x1e, 0xfb, 0xc2, 0x88, 0xac,
];

const EXAMPLE_ATOMIC_PARENT: Row = Row {
    bytes: include_bytes!("fixtures/example_atomic_parent.bin"),
    sha256: "4f231f127f854b8290bddf0a8c8df96585d89e9246d87edde004814d393d8158",
    chain: &[(
        814_435,
        "bb6f640cc4ee56bf38eb5a1969ac0c16caa2d3d202b22bf3735d10eec0ca6e00",
    )],
    satoshis: 26_174,
    script: P2PKH,
};

const SUBJECT_PROVEN_FIRST: Row = Row {
    bytes: include_bytes!("fixtures/subject_proven_first.bin"),
    sha256: "33306f928a2c84d72831e0668e5468536d921d0580ac7a0da710f9828a1e3d26",
    chain: &[
        (
            800_000,
            "0c1511adca15eabe28c6c6b2d0704df0500a23891071c4f658355a6e30d6aa70",
        ),
        (
            800_008,
            "970188a11f0f853030f9ecafcf67ce4529152fbc66b74369cb3b5f2b6e1a78b0",
        ),
    ],
    satoshis: 1,
    script: &[],
};

const SUBJECT_PROVEN_FIRST_TRUE: Row = Row {
    bytes: include_bytes!("fixtures/subject_proven_first_true.bin"),
    sha256: "e26a4d4975d4ab179d15714b3849d411b3999aa58458b8cd43d10e46e96c60d2",
    chain: &[
        (
            800_000,
            "de8e67c80efbbb46f1e67cf7189da7ebad7fc4fab9c0cf9e687c1ff7aa6935c6",
        ),
        (
            800_008,
            "ef48bebdf68fa05049ef64635d2e0a64128fb26bff0ad2b4b50ddd3be8d1a842",
        ),
    ],
    satoshis: 1,
    script: &[0x51],
};

/// Answers the row's roots at their heights; fails every other height.
struct Headers(&'static [(u32, &'static str)]);

#[async_trait]
impl HeaderService for Headers {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        self.0
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, root)| root.to_string())
            .ok_or_else(|| HeaderLookupError(format!("no header at {height}")))
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

const KEY: &str = "02aa/atomic.beef";

#[async_trait(?Send)]
impl BeefStore for Store {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        Ok((key == KEY).then(|| Stamp {
            size: self.object.len() as u64,
            etag: "atomic".to_string(),
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

fn terms(row: &Row) -> Terms<'static> {
    Terms {
        output_index: 0,
        expected_script: row.script,
        required_satoshis: row.satoshis,
    }
}

fn inline(row: &Row) -> DoorVerdict {
    let hexed = hex::encode(row.bytes);
    block_on(verify_inline(
        &Carrier::Hex(&hexed),
        &terms(row),
        Some(&Headers(row.chain)),
    ))
    .unwrap()
}

/// The object through the door, request after request; the verdict and the
/// requests it took.
fn at_rest(row: &Row, millis: u64) -> (DoorVerdict, u64) {
    let store = Store {
        object: row.bytes.to_vec(),
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
            &terms(row),
            Some(&Headers(row.chain)),
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

/// The verdict of every entry, each the same; the requests the resumed entry
/// took.
fn door(row: &Row) -> (DoorVerdict, u64) {
    assert_eq!(
        hex::encode(sha256(row.bytes)),
        row.sha256,
        "the row's bytes"
    );
    let verdict = inline(row);
    let (one, requests) = at_rest(row, u64::MAX);
    assert_eq!(requests, 1);
    assert_eq!(one, verdict, "at rest, one request");
    let (resumed, requests) = at_rest(row, 0);
    assert_eq!(resumed, verdict, "at rest, resumed");
    (verdict, requests)
}

/// Refused `unrelatedTransaction` at `offset`: the bytes are why.
fn unrelated_at(verdict: &DoorVerdict, offset: u64) {
    assert!(
        matches!(verdict.word, PaymentVerdict::Unverifiable(_)),
        "{verdict:?}"
    );
    assert_eq!(
        verdict.named,
        Some(Named {
            offset,
            kind: "UnrelatedTransaction".to_string(),
        }),
        "{verdict:?}"
    );
    assert_eq!(verdict.subject, None);
}

#[test]
fn wrong_subject_is_unrelated_at_278() {
    let (verdict, _) = door(&WRONG_SUBJECT);
    unrelated_at(&verdict, 278);
}

#[test]
fn unrelated_is_unrelated_at_278() {
    let (verdict, _) = door(&UNRELATED);
    unrelated_at(&verdict, 278);
}

#[test]
fn example_atomic_parent_is_unrelated_at_521() {
    let (verdict, _) = door(&EXAMPLE_ATOMIC_PARENT);
    unrelated_at(&verdict, 521);
}

/// Every root carried: the door's structure pass asks the roots after it.
struct AnyRoot;

impl Roots for AnyRoot {
    fn carries(&self, _height: u64, _root: &Hash32) -> bool {
        true
    }
}

/// The rule alone: the structure pass's verdict is valid, after `elements`.
fn the_rule_accepts(row: &Row, elements: u64) {
    let mut reader = StreamVerifier::structure_only(row.bytes, AnyRoot, None);
    loop {
        if let Progress::Verdict(verdict) = reader.step().unwrap() {
            assert!(verdict.is_valid(), "{verdict:?}");
            break;
        }
    }
    assert_eq!(reader.cursor().elements_read(), elements);
}

/// The door's word: the spend at `offset` refused, the bytes why.
fn spend_refused_at(verdict: &DoorVerdict, offset: u64) {
    assert_eq!(
        verdict.named,
        Some(Named {
            offset,
            kind: "SpendRefused".to_string(),
        }),
        "{verdict:?}"
    );
    assert_eq!(verdict.subject, None);
}

#[test]
fn subject_proven_first_is_accepted_by_the_rule() {
    the_rule_accepts(&SUBJECT_PROVEN_FIRST, 5);
    let (verdict, _) = door(&SUBJECT_PROVEN_FIRST);
    spend_refused_at(&verdict, 266);
    assert!(
        format!("{verdict:?}").contains("clean stack"),
        "{verdict:?}"
    );
}

#[test]
fn subject_proven_first_true_is_accepted_by_the_rule() {
    the_rule_accepts(&SUBJECT_PROVEN_FIRST_TRUE, 5);
    let (verdict, _) = door(&SUBJECT_PROVEN_FIRST_TRUE);
    spend_refused_at(&verdict, 264);
    assert!(
        format!("{verdict:?}").contains("CreatesValue"),
        "{verdict:?}"
    );
}
