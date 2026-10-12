//! H1 (bsv-low #591, LOW's R400 lens on 0.4.0): the wide transaction at the
//! payment door. A proven parent with `n` outputs any spender may take
//! (`OP_TRUE`), and a subject spending all `n` with empty unlocking scripts:
//! 64,000 inputs is 3.3 MB of BEEF, and through 0.4.3 the door ran every one
//! of those scripts before it read the output that pays the box, so a body
//! carrying no satoshis cost the whole walk (LOW measured 18.5 to 24.9 s of
//! CPU, native, with a wrong root asked after the scripts).
//!
//! The order since 0.4.4: the structure is read first (no script, no root),
//! then the paying output, and a body that pays nothing (or too little) is
//! refused there; only a body that pays is read for its scripts, then its
//! roots. Inline and at rest alike.
//!
//! Two cases, each inline and from an object at rest:
//! - **no sats to the box**: the subject's output 0 is not the box's script.
//!   Refused at the output word, zero elements read with scripts, no root
//!   asked, in milliseconds.
//! - **the price paid**: the same frame paying the fee at the box's script.
//!   Its scripts run (the script pass steps three elements: the BUMP, the
//!   parent and the subject), then its root. The 64,000-input paid case is the walk's measurement and is run
//!   with `--release --ignored`; the default suite carries 1,000 inputs.

mod support;

use rust_message_box::beef_door::{scripted_elements, BeefStore, Chunks, Slice, Slices, Stamp};
use rust_message_box::handoff::PaymentStore;
use rust_message_box::payments::{
    check_delivery_at_rest, check_delivery_output, judge_delivery_inline_at_rest,
};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::*;

const OP_TRUE: &[u8] = &[0x51];
const KEY: &str = "02abc/wide.beef";

/// The parent: one input from outside the BEEF, `n` outputs of one satoshi
/// each at `OP_TRUE`.
fn wide_parent(n: usize) -> Vec<u8> {
    let mut t = 1u32.to_le_bytes().to_vec();
    t.push(1);
    t.extend_from_slice(&[0x11; 32]);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    varint(n as u64, &mut t);
    for _ in 0..n {
        t.extend_from_slice(&1u64.to_le_bytes());
        t.push(1);
        t.extend_from_slice(OP_TRUE);
    }
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The subject: `n` inputs, each spending the parent's output of its index
/// with an empty unlocking script, and one output of `satoshis` at `script`.
fn wide_subject(parent: &[u8; 32], n: usize, satoshis: u64, script: &[u8]) -> Vec<u8> {
    let mut t = 1u32.to_le_bytes().to_vec();
    varint(n as u64, &mut t);
    for i in 0..n {
        t.extend_from_slice(parent);
        t.extend_from_slice(&(i as u32).to_le_bytes());
        t.push(0);
        t.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    t.push(1);
    t.extend_from_slice(&satoshis.to_le_bytes());
    varint(script.len() as u64, &mut t);
    t.extend_from_slice(script);
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The Atomic BEEF of the parent (proven by a one-leaf BUMP at `HEIGHT`) and
/// the subject, and the parent's root as the header service gives it.
fn wide(n: usize, pays: bool) -> (Vec<u8>, String) {
    let parent = wide_parent(n);
    let proven = hash(&parent);
    let subject = if pays {
        wide_subject(&proven, n, FEE, &server_script())
    } else {
        wide_subject(&proven, n, 1, OP_TRUE)
    };
    frame(&parent, &subject)
}

/// The Atomic BEEF of `parent` (proven by a one-leaf BUMP at `HEIGHT`) and
/// `subject`, and the parent's root as the header service gives it.
fn frame(parent: &[u8], subject: &[u8]) -> (Vec<u8>, String) {
    let proven = hash(parent);
    let mut b = 0x0101_0101u32.to_le_bytes().to_vec();
    b.extend_from_slice(&hash(subject));
    b.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
    b.push(1);
    b.push(0xfe);
    b.extend_from_slice(&HEIGHT.to_le_bytes());
    b.extend_from_slice(&[1, 1, 0, 2]);
    b.extend_from_slice(&proven);
    b.push(2);
    b.extend_from_slice(&[1, 0]);
    b.extend_from_slice(parent);
    b.push(0);
    b.extend_from_slice(subject);
    let root = hex::encode(proven.iter().rev().copied().collect::<Vec<u8>>());
    (b, root)
}

/// A root no header carries: LOW's body asked one after the scripts.
const WRONG_ROOT: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

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

/// What one door run came to: the answer, the elements read with scripts,
/// the header lookups, the wall time and the requests that were pending.
#[derive(Debug)]
struct Run {
    answer: Answer,
    scripted: u64,
    asked: usize,
    took: Duration,
    pending: usize,
}

fn on_a_thread<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .expect("the door returned")
}

/// The inline door, `tx` in hex.
fn inline(beef: &[u8], root: &str) -> Run {
    let tx = json!(hex::encode(beef));
    let root = root.to_string();
    on_a_thread(move || {
        let asked = Arc::new(AtomicUsize::new(0));
        let headers = ChainHeaders {
            root,
            asked: asked.clone(),
        };
        let before = scripted_elements();
        let started = Instant::now();
        let answer = tokio::runtime::Builder::new_current_thread()
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
            .map_err(|(body, status)| (status, body));
        Run {
            answer,
            took: started.elapsed(),
            scripted: scripted_elements() - before,
            asked: asked.load(Ordering::SeqCst),
            pending: 0,
        }
    })
}

/// Objects in memory, handed out in chunks of 64 KiB, and the door's
/// states.
struct Store {
    objects: RefCell<HashMap<String, Vec<u8>>>,
    states: RefCell<HashMap<String, Vec<u8>>>,
}

impl Store {
    fn with(key: &str, bytes: Vec<u8>) -> Self {
        Self {
            objects: RefCell::new(HashMap::from([(key.to_string(), bytes)])),
            states: RefCell::new(HashMap::new()),
        }
    }
}

struct Bytes {
    bytes: Vec<u8>,
    at: usize,
}

#[async_trait::async_trait(?Send)]
impl Chunks for Bytes {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        let end = (self.at + 64 * 1024).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

#[async_trait::async_trait(?Send)]
impl BeefStore for Store {
    async fn stamp(&self, key: &str) -> Result<Option<Stamp>, String> {
        Ok(self.objects.borrow().get(key).map(|bytes| Stamp {
            size: bytes.len() as u64,
            etag: "v1".to_string(),
        }))
    }
    async fn open(&self, key: &str, from: u64, _stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        let objects = self.objects.borrow();
        let bytes = objects.get(key).ok_or("no object")?;
        Ok(Box::new(Bytes {
            bytes: bytes[from as usize..].to_vec(),
            at: 0,
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

#[async_trait::async_trait(?Send)]
impl PaymentStore for Store {
    async fn spool(
        &self,
        key: &str,
        chunks: &mut dyn Chunks,
        size: u64,
        _reader: &str,
    ) -> Result<Stamp, String> {
        let mut bytes = Vec::new();
        while let Some(chunk) = chunks.next().await? {
            bytes.extend_from_slice(&chunk);
        }
        self.objects.borrow_mut().insert(key.to_string(), bytes);
        Ok(Stamp {
            size,
            etag: "v1".to_string(),
        })
    }
    async fn reader(&self, _key: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn bucket_name(&self) -> Option<String> {
        Some("beef".to_string())
    }
}

/// The door on the object at rest, with a slice of `millis` of wall time a
/// request, every request sent again until a verdict.
fn at_rest(beef: &[u8], root: &str, millis: u64) -> Run {
    at_rest_with_work(
        beef,
        root,
        millis,
        rust_message_box::beef_door::work_units_per_input(),
    )
}

fn at_rest_with_work(beef: &[u8], root: &str, millis: u64, work_units: u64) -> Run {
    let beef = beef.to_vec();
    let root = root.to_string();
    on_a_thread(move || {
        let asked = Arc::new(AtomicUsize::new(0));
        let headers = ChainHeaders {
            root,
            asked: asked.clone(),
        };
        let store = Store::with(KEY, beef);
        let epoch = Instant::now();
        let clock = move || epoch.elapsed().as_millis() as u64;
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis,
            },
            lookups: usize::MAX,
            inputs: u64::MAX,
            weight: u64::MAX,
            work_units,
        };
        let before = scripted_elements();
        let started = Instant::now();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut pending = 0usize;
        let answer = loop {
            let answer = runtime
                .block_on(check_delivery_at_rest(
                    &store,
                    KEY,
                    &remittance(),
                    FEE,
                    &sender(),
                    &wallet(SERVER_KEY),
                    Some(&headers),
                    &slices,
                ))
                .map_err(|(body, status)| (status, body));
            match &answer {
                Err((503, body)) if body["code"] == "ERR_PAYMENT_PENDING" => pending += 1,
                _ => break answer,
            }
            assert!(pending < 100_000, "the requests end");
        };
        assert!(store.states.borrow().is_empty(), "no state left behind");
        Run {
            answer,
            took: started.elapsed(),
            scripted: scripted_elements() - before,
            asked: asked.load(Ordering::SeqCst),
            pending,
        }
    })
}

/// Refused at the output word: 400 `ERR_INVALID_PAYMENT`, the output's
/// script named, no script run and no root asked.
fn refused_at_the_output(run: &Run, path: &str) {
    eprintln!(
        "hostile_wide_door {path}: no sats: {:?} in {} ms, {} elements scripted, {} roots asked",
        run.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
        run.took.as_millis(),
        run.scripted,
        run.asked
    );
    let (status, body) = run.answer.as_ref().expect_err("refused");
    assert_eq!(*status, 400, "{body}");
    assert_eq!(body["code"], "ERR_INVALID_PAYMENT", "{body}");
    let text = body["description"].as_str().unwrap();
    assert!(
        text.contains("not locked to the server"),
        "the output's script: {text}"
    );
    assert_eq!(
        run.scripted, 0,
        "no script runs for a body that pays nothing"
    );
    assert_eq!(run.asked, 0, "no root is asked");
    assert!(
        run.took < Duration::from_secs(10),
        "milliseconds, not the walk: {:?}",
        run.took
    );
}

const WIDE: usize = 64_000;

#[test]
fn a_wide_body_that_pays_nothing_is_refused_at_the_output_with_no_script_run_inline() {
    let (beef, _) = wide(WIDE, false);
    assert!(beef.len() > 3_250_000, "LOW's 3.3 MB: {}", beef.len());
    refused_at_the_output(&inline(&beef, WRONG_ROOT), "inline");
}

#[test]
fn a_wide_body_that_pays_nothing_is_refused_at_the_output_with_no_script_run_at_rest() {
    let (beef, _) = wide(WIDE, false);
    let run = at_rest(&beef, WRONG_ROOT, u64::MAX);
    refused_at_the_output(&run, "at rest");
    assert_eq!(run.pending, 0);
}

/// The paid frame: its scripts run (the BUMP, the parent, the subject), then its
/// root; accepted inline and at rest, in one request and in slices.
fn paid(n: usize) {
    let (beef, root) = wide(n, true);
    for (path, run) in [
        ("inline", inline(&beef, &root)),
        ("at rest", at_rest(&beef, &root, u64::MAX)),
    ] {
        eprintln!(
            "hostile_wide_door {path}: paid, {n} inputs, {} bytes: {:?} in {} ms, {} elements scripted, {} roots asked",
            beef.len(),
            run.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
            run.took.as_millis(),
            run.scripted,
            run.asked
        );
        assert_eq!(run.answer, Ok(FEE), "{path}");
        assert_eq!(
            run.scripted, 3,
            "{path}: the BUMP, the parent and the subject"
        );
        assert_eq!(run.asked, 1, "{path}: the one root, after the scripts");
        assert_eq!(
            run.pending, 0,
            "{path}: a reading with no slice never pauses"
        );
    }
}

#[test]
fn the_same_frame_paying_the_price_runs_its_scripts_then_its_root() {
    paid(1_000);
}

/// The walk at LOW's size, measured: `cargo test --release --test
/// hostile_wide_door -- --ignored --nocapture`.
#[test]
#[ignore = "the walk's measurement: run with --release --ignored"]
fn the_wide_frame_paying_the_price_at_64000_inputs() {
    paid(WIDE);
}

/// The CPU setting derives from the measured budget boundary, scaled by
/// the 0.4.4 V8 factor, plus the 15 s slice and half again. The largest
/// observed single-input door run was 1,127.292 ms (V8 estimate 1,353 ms).
/// The retained between-input slice reached 9,811 ms in the lane's run and
/// 11,193 ms in the keeper's verification at the tip under a loaded host
/// (V8 estimate 13,432 ms), so use the largest stretch measured and round
/// the final CPU up to a whole second.
#[test]
fn the_deployment_states_the_cpu_a_request_may_spend() {
    let toml = include_str!("../wrangler.toml");
    let limits = toml
        .split("\n[limits]\n")
        .nth(1)
        .expect("wrangler.toml has a [limits] table");
    let cpu_ms: u64 = limits
        .lines()
        .find_map(|line| line.strip_prefix("cpu_ms = "))
        .expect("[limits] states cpu_ms")
        .trim()
        .parse()
        .expect("cpu_ms is a number");
    let widest_stretch_wasm_ms = 13_432;
    let need = rust_message_box::beef_door::VERIFY_SLICE_MILLIS + widest_stretch_wasm_ms;
    let measured_cpu_ms = (need * 3).div_ceil(2).div_ceil(1_000) * 1_000;
    assert_eq!(
        cpu_ms, measured_cpu_ms,
        "CPU is the measured need plus half again, rounded up"
    );
    assert!(cpu_ms <= 300_000, "within the platform's ceiling");
}

/// Where a paced door reads the payment from: an upload at rest, or the
/// inline `tx` spooled before its scripts (`judge_delivery_inline_at_rest`).
#[derive(Debug, Clone, Copy)]
enum Path {
    AtRest,
    Inline,
}

/// How a paced door's clock moves.
#[derive(Debug, Clone, Copy)]
enum Clock {
    /// One millisecond each time it is read: the time a request spends is
    /// the times it looked at the clock.
    Ticking,
    /// Never between two reads of one request: a Worker's clock, which moves
    /// only at I/O, over a transaction in hand.
    Frozen,
}

/// The paid frame through the door on `path`, every request sent again until
/// a verdict, with a slice of `millis` on `clock` and of `inputs` inputs. The
/// run and every pending answer.
fn paced(
    beef: &[u8],
    root: &str,
    path: Path,
    clock: Clock,
    millis: u64,
    inputs: u64,
    weight: u64,
) -> (Run, Vec<Value>, Duration) {
    let beef = beef.to_vec();
    let root = root.to_string();
    on_a_thread(move || {
        let asked = Arc::new(AtomicUsize::new(0));
        let headers = ChainHeaders {
            root,
            asked: asked.clone(),
        };
        let store = match path {
            Path::AtRest => Store::with(KEY, beef.clone()),
            Path::Inline => Store {
                objects: RefCell::new(HashMap::new()),
                states: RefCell::new(HashMap::new()),
            },
        };
        let tx = json!(hex::encode(&beef));
        let ticks = Cell::new(0u64);
        let clock = || match clock {
            Clock::Ticking => {
                ticks.set(ticks.get() + 1);
                ticks.get()
            }
            Clock::Frozen => 0,
        };
        let slices = Slices {
            time: Slice {
                clock: &clock,
                millis,
            },
            lookups: usize::MAX,
            inputs,
            weight,
            work_units: rust_message_box::beef_door::work_units_per_input(),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let before = scripted_elements();
        let started = Instant::now();
        let mut pending = Vec::new();
        let mut slowest = Duration::ZERO;
        let answer = loop {
            let request = Instant::now();
            let answer = match path {
                Path::AtRest => runtime.block_on(check_delivery_at_rest(
                    &store,
                    KEY,
                    &remittance(),
                    FEE,
                    &sender(),
                    &wallet(SERVER_KEY),
                    Some(&headers),
                    &slices,
                )),
                Path::Inline => runtime
                    .block_on(judge_delivery_inline_at_rest(
                        &store,
                        &tx,
                        &remittance(),
                        FEE,
                        &sender(),
                        &wallet(SERVER_KEY),
                        Some(&headers),
                        &slices,
                        &wallet(SERVER_KEY).identity_key().to_hex(),
                        None,
                    ))
                    .0
                    .map(|judged| judged.satoshis),
            }
            .map_err(|(body, status)| (status, body));
            slowest = slowest.max(request.elapsed());
            match answer {
                Err((503, body)) if body["code"] == "ERR_PAYMENT_PENDING" => pending.push(body),
                _ => break answer,
            }
            assert!(pending.len() < 100_000, "the requests end");
        };
        assert!(store.states.borrow().is_empty(), "no state left behind");
        let run = Run {
            answer,
            took: started.elapsed(),
            scripted: scripted_elements() - before,
            asked: asked.load(Ordering::SeqCst),
            pending: pending.len(),
        };
        (run, pending, slowest)
    })
}

/// The inputs a paced reading paused at inside the subject, in the order the
/// pending answers named them.
fn paused_inside(pending: &[Value]) -> Vec<u64> {
    pending
        .iter()
        .filter(|body| body["phase"] == "scripts")
        .filter_map(|body| body["input"].as_u64())
        .collect()
}

const PACED: usize = 20_000;

/// The clock between inputs (bsv-rs 0.4.4's `step_until`): a paid subject
/// wider than the slice pauses inside itself, between two of its inputs, on
/// the inline path and the at-rest path alike. The pending answer names the
/// input reached (the BUMP and the parent read, the subject in hand); the
/// next request resumes at that input, never at the subject's first, and
/// the verdict is the verdict of one request. Through 0.4.3 the clock was
/// looked at between elements only, so the subject was one unbroken walk.
#[test]
fn a_paid_subject_wider_than_the_slice_pauses_between_its_inputs_and_resumes_there() {
    let (beef, root) = wide(PACED, true);
    for path in [Path::AtRest, Path::Inline] {
        let (run, pending, _) = paced(
            &beef,
            &root,
            path,
            Clock::Ticking,
            5_000,
            u64::MAX,
            u64::MAX,
        );
        let inputs = paused_inside(&pending);
        eprintln!(
            "hostile_wide_door {path:?}: paid, {PACED} inputs, a slice of 5,000 clock reads: {:?}, {} pending, paused inside the subject at inputs {inputs:?}, {} elements scripted, {} roots asked",
            run.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
            run.pending,
            run.scripted,
            run.asked
        );
        assert_eq!(run.answer, Ok(FEE), "{path:?}: the verdict of one request");
        assert!(
            inputs.len() >= 3,
            "{path:?}: paused inside the subject: {pending:?}"
        );
        assert!(
            inputs.windows(2).all(|w| w[0] < w[1]),
            "{path:?}: each request resumes at the input reached, never at the first: {inputs:?}"
        );
        assert!(
            inputs.iter().all(|&i| 0 < i && i < PACED as u64),
            "{path:?}: between two inputs: {inputs:?}"
        );
        for body in pending.iter().filter(|b| b["input"].is_u64()) {
            assert_eq!(body["elements"], 2, "{path:?}: the subject in hand: {body}");
        }
        assert_eq!(
            run.scripted, 3,
            "{path:?}: the subject is stepped once, however many requests it spans"
        );
        assert_eq!(run.asked, 1, "{path:?}: the one root, after the scripts");
    }
}

/// The slice in work (`Slices::inputs`, `SCRIPT_INPUTS_PER_PASS` in the
/// Worker): a Worker's clock moves only at I/O, and between two inputs of a
/// transaction in hand there is none, so under its clock the time slice
/// alone never pauses inside the subject (the first run here: no input
/// named). The input count does, at the inputs it names, and the resume
/// reaches the same verdict.
#[test]
fn under_a_clock_that_moves_only_at_io_the_input_count_pauses_the_subject() {
    let (beef, root) = wide(PACED, true);
    let millis = rust_message_box::beef_door::VERIFY_SLICE_MILLIS;
    let (run, pending, _) = paced(
        &beef,
        &root,
        Path::AtRest,
        Clock::Frozen,
        millis,
        u64::MAX,
        u64::MAX,
    );
    assert_eq!(run.answer, Ok(FEE));
    assert_eq!(
        paused_inside(&pending),
        Vec::<u64>::new(),
        "the time slice alone, under a frozen clock"
    );
    for path in [Path::AtRest, Path::Inline] {
        let (run, pending, _) = paced(&beef, &root, path, Clock::Frozen, millis, 6_000, u64::MAX);
        let inputs = paused_inside(&pending);
        eprintln!(
            "hostile_wide_door {path:?}: paid, {PACED} inputs, a frozen clock and 6,000 inputs a request: {:?}, {} pending, paused inside the subject at inputs {inputs:?}",
            run.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
            run.pending,
        );
        assert_eq!(run.answer, Ok(FEE), "{path:?}");
        assert_eq!(inputs, [6_000, 12_000, 18_000], "{path:?}: {pending:?}");
        assert_eq!(run.scripted, 3, "{path:?}");
        assert_eq!(run.asked, 1, "{path:?}");
    }
}

// ---- the widest element at 0.4.4 (`cpu_ms`, bsv-low #591 H1) ----

use bsv_rs::primitives::bsv::sighash::{
    TxInput, TxOutput, TxSighashCache, SIGHASH_ALL, SIGHASH_CHRONICLE, SIGHASH_FORKID,
};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::ec::PrivateKey;

fn push(data: &[u8], out: &mut Vec<u8>) {
    assert!(data.len() < 0x4c);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

/// A raw transaction of `inputs` (outpoint, unlocking script) and `outputs`.
fn raw(inputs: &[([u8; 32], u32, Vec<u8>)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut t = 1u32.to_le_bytes().to_vec();
    varint(inputs.len() as u64, &mut t);
    for (txid, vout, unlock) in inputs {
        t.extend_from_slice(txid);
        t.extend_from_slice(&vout.to_le_bytes());
        varint(unlock.len() as u64, &mut t);
        t.extend_from_slice(unlock);
        t.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    varint(outputs.len() as u64, &mut t);
    for (satoshis, script) in outputs {
        t.extend_from_slice(&satoshis.to_le_bytes());
        varint(script.len() as u64, &mut t);
        t.extend_from_slice(script);
    }
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// The paid frame with `n` P2PKH inputs, each signed under `scope`: a parent
/// with `n` P2PKH outputs, a subject spending all of them and paying the
/// box. Under `ALL | FORKID` a signature's digest is BIP-143's, from the
/// transaction's midstates (one set per transaction at 0.4.4); with the
/// CHRONICLE bit it is the original digest, which serializes every input
/// for every signature (bsv-rs 0.4.4's named risk).
fn signed_wide(n: usize, scope: u32) -> (Vec<u8>, String) {
    let key = PrivateKey::from_bytes(&[0x11; 32]).unwrap();
    let mut lock = vec![0x76, 0xa9, 0x14];
    lock.extend_from_slice(&key.public_key().hash160());
    lock.extend_from_slice(&[0x88, 0xac]);
    let parent = raw(&[([0x11; 32], 0, vec![])], &vec![(1_000, lock.clone()); n]);
    let prev = hash(&parent);
    let cache = TxSighashCache::new(
        1,
        (0..n as u32)
            .map(|vout| TxInput {
                txid: prev,
                output_index: vout,
                script: vec![],
                sequence: u32::MAX,
            })
            .collect(),
        vec![TxOutput {
            satoshis: FEE,
            script: server_script(),
        }],
        0,
    );
    let inputs: Vec<_> = (0..n)
        .map(|i| {
            let digest = cache.sighash_dispatched_for_signing(i, &lock, 1_000, scope);
            let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_low_s();
            let mut unlock = Vec::new();
            push(&sig.to_checksig_format(), &mut unlock);
            push(&key.public_key().to_compressed(), &mut unlock);
            (prev, i as u32, unlock)
        })
        .collect();
    let subject = raw(&inputs, &[(FEE, server_script())]);
    frame(&parent, &subject)
}

/// The widest element at 0.4.4, measured: `cargo test --release --test
/// hostile_wide_door -- --ignored --nocapture`. Each frame is read at rest
/// with no slice (the element's whole walk) and again as the Worker reads it
/// (a clock that moves only at I/O, `SCRIPT_INPUTS_PER_PASS` inputs a
/// request), the slowest request named.
#[test]
#[ignore = "the widest element's measurement: run with --release --ignored"]
fn the_widest_element_at_0_4_4() {
    use rust_message_box::beef_door::{
        SCRIPT_INPUTS_PER_PASS, SCRIPT_WEIGHT_PER_PASS, VERIFY_SLICE_MILLIS,
    };
    let forkid = SIGHASH_ALL | SIGHASH_FORKID;
    let original = forkid | SIGHASH_CHRONICLE;
    let mut frames = vec![
        ("OP_TRUE", WIDE, wide(WIDE, true)),
        ("P2PKH ALL|FORKID", WIDE, signed_wide(WIDE, forkid)),
    ];
    for n in [1_000, 2_000, 4_000, 12_000] {
        frames.push(("P2PKH ALL|FORKID|CHRONICLE", n, signed_wide(n, original)));
    }
    for (shape, n, (beef, root)) in frames {
        let whole = at_rest(&beef, &root, u64::MAX);
        let (sliced, pending, slowest) = paced(
            &beef,
            &root,
            Path::AtRest,
            Clock::Frozen,
            VERIFY_SLICE_MILLIS,
            SCRIPT_INPUTS_PER_PASS,
            SCRIPT_WEIGHT_PER_PASS,
        );
        eprintln!(
            "hostile_wide_door widest: {shape}, {n} inputs, {} bytes: whole {:?} in {} ms ({:.1} us an input); the Worker's slices: {} pending, slowest request {} ms, paused at inputs {:?}",
            beef.len(),
            whole.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
            whole.took.as_millis(),
            whole.took.as_secs_f64() * 1e6 / n as f64,
            pending.len(),
            slowest.as_millis(),
            paused_inside(&pending),
        );
        assert_eq!(whole.answer, Ok(FEE), "{shape}");
        assert_eq!(sliced.answer, Ok(FEE), "{shape}");
    }
}

/// The slice in weight (`Slices::weight`, `SCRIPT_WEIGHT_PER_PASS` in the
/// Worker): a signature over the original digest (the CHRONICLE bit)
/// serializes its whole transaction, so each input weighs the transaction's
/// bytes and a request pauses when their sum passes the weight, though its
/// count of inputs is far from spent. 300 signed inputs, a subject of about
/// 44 KB: a weight of 2,000,000 pauses each resumed request after about 46
/// of them, and the resume reaches the verdict of one request.
#[test]
fn an_input_over_the_original_digest_weighs_its_transaction() {
    let (beef, root) = signed_wide(300, SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE);
    let millis = rust_message_box::beef_door::VERIFY_SLICE_MILLIS;
    let (run, pending, _) = paced(
        &beef,
        &root,
        Path::AtRest,
        Clock::Frozen,
        millis,
        u64::MAX,
        2_000_000,
    );
    let inputs = paused_inside(&pending);
    eprintln!(
        "hostile_wide_door weight: 300 signed inputs over the original digest, {} bytes, a weight of 2,000,000: {:?}, paused at inputs {inputs:?}",
        beef.len(),
        run.answer.as_ref().map_err(|(s, b)| (s, &b["description"])),
    );
    assert_eq!(run.answer, Ok(FEE));
    assert!(inputs.len() >= 5, "{inputs:?}");
    assert!(inputs.windows(2).all(|w| w[0] < w[1]), "{inputs:?}");
    // A resumed request reads the subject first: each input weighs its bytes.
    let subject = pending[0]["size"].as_u64().unwrap() - pending[0]["offset"].as_u64().unwrap();
    let per_request = 2_000_000u64.div_ceil(subject);
    for w in inputs.windows(2) {
        assert_eq!(
            w[1] - w[0],
            per_request,
            "a resumed request runs the inputs a weight of 2,000,000 holds, of a {subject}-byte subject: {inputs:?}"
        );
    }
    assert_eq!(run.scripted, 3);
    assert_eq!(run.asked, 1);
}

// LOW R404-H1: phantom source P, one paying input S and a fabricated BUMP.
// One signature is duplicated for k successful checks over the original digest.
fn single_input_work(k: usize, padding: usize) -> (Vec<u8>, String) {
    let (beef, root, _) = single_input_work_measured(k, padding);
    (beef, root)
}

fn single_input_work_measured(k: usize, padding: usize) -> (Vec<u8>, String, u64) {
    let key = PrivateKey::from_bytes(&[0x11; 32]).unwrap();
    let mut lock = Vec::new();
    for _ in 0..k {
        lock.push(0x76); // DUP
        push(&key.public_key().to_compressed(), &mut lock);
        lock.push(0xad); // CHECKSIGVERIFY
    }
    lock.extend_from_slice(&[0x75, 0x51]); // DROP TRUE
    let parent = raw(&[([0x11; 32], 0, vec![])], &[(1_000, lock.clone())]);
    let prev = hash(&parent);
    // Output zero pays the exact BRC-29 script. A zero-value data output
    // widens the original preimage without changing that delivery output.
    let mut data = vec![0x6a];
    data.resize(padding + 1, 0);
    let outputs = vec![(FEE, server_script()), (0, data)];
    let scope = SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_CHRONICLE;
    let cache = TxSighashCache::new(
        1,
        vec![TxInput {
            txid: prev,
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        }],
        outputs
            .iter()
            .map(|(satoshis, script)| TxOutput {
                satoshis: *satoshis,
                script: script.clone(),
            })
            .collect(),
        0,
    );
    // With no code separators, the original preimage is this serialization
    // with the locking script substituted, plus the four-byte scope.
    let per_check = raw(&[(prev, 0, lock.clone())], &outputs).len() as u64 + 4 + 32;
    let work = k as u64 * (per_check + 3) + 3; // 3 opcodes/check, push + DROP TRUE
    let digest = cache.sighash_dispatched_for_signing(0, &lock, 1_000, scope);
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_low_s();
    let mut unlock = Vec::new();
    push(&sig.to_checksig_format(), &mut unlock);
    let (beef, root) = frame(&parent, &raw(&[(prev, 0, unlock)], &outputs));
    (beef, root, work)
}

#[test]
fn r404_h1_one_paying_input_is_declined_by_work_before_the_slice() {
    let (beef, _) = single_input_work(10_000, 1_000_000);
    for (path, run) in [
        ("at rest", at_rest(&beef, WRONG_ROOT, u64::MAX)),
        ("inline", inline(&beef, WRONG_ROOT)),
    ] {
        eprintln!(
            "R404-H1 {path}: {} bytes, {:?}, {:.3} ms, roots {}, pending {}",
            beef.len(),
            run.answer.as_ref().map_err(|(status, body)| (
                status,
                &body["code"],
                &body["resource"],
                &body["budget"],
                &body["workSpent"]
            )),
            run.took.as_secs_f64() * 1e3,
            run.asked,
            run.pending
        );
        let (status, body) = run.answer.expect_err("local work decline");
        assert_eq!(status, 422, "{body}");
        assert_eq!(body["code"], "ERR_PAYMENT_WORK", "{body}");
        assert_eq!(body["resource"], "Work", "{body}");
        assert_eq!(body["kind"], "Work", "{body}");
        assert_eq!(body["input"], 0, "{body}");
        assert!(body["workSpent"].as_u64().unwrap() <= body["budget"].as_u64().unwrap());
        assert_eq!(run.asked, 0, "declined before the fabricated root");
        assert_eq!(
            run.pending, 0,
            "one input is declined, not resumed inside its script"
        );
        assert!(run.took < Duration::from_millis(rust_message_box::beef_door::VERIFY_SLICE_MILLIS));
    }
}

#[test]
fn r404_h1_work_is_reapplied_after_resume_on_both_spooled_paths() {
    let (beef, _) = single_input_work(10_000, 1_000_000);
    for path in [Path::AtRest, Path::Inline] {
        let (run, pending, _) = paced(
            &beef,
            WRONG_ROOT,
            path,
            Clock::Frozen,
            0,
            u64::MAX,
            u64::MAX,
        );
        eprintln!(
            "R404-H1 resumed {path:?}: {:.3} ms, pending {}, {:?}",
            run.took.as_secs_f64() * 1e3,
            pending.len(),
            run.answer
        );
        assert!(pending.iter().any(|p| p["phase"] == "scripts"));
        let (status, body) = run.answer.unwrap_err();
        assert_eq!(status, 422, "{body}");
        assert_eq!(body["code"], "ERR_PAYMENT_WORK", "{body}");
        assert_eq!(
            body["budget"],
            rust_message_box::beef_door::work_units_per_input()
        );
        assert_eq!(body["input"], 0);
        assert_eq!(run.asked, 0);
    }
}

#[test]
fn r404_h1_exact_budget_keeps_the_valid_payment_and_one_less_declines() {
    let (beef, root, work) = single_input_work_measured(9, 1_100_000);
    assert!(work <= rust_message_box::beef_door::work_units_per_input());
    assert_eq!(at_rest_with_work(&beef, &root, 0, work).answer, Ok(FEE));
    let declined = at_rest_with_work(&beef, &root, 0, work - 1);
    let (status, body) = declined.answer.unwrap_err();
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["budget"], work - 1);
    assert_eq!(body["workSpent"], work - 1);
    assert_eq!(body["attempted"], work);
    assert_eq!(declined.asked, 0);
}

#[test]
#[ignore = "native budget calibration: run --release --ignored --nocapture --test-threads=1"]
fn r404_h1_widest_single_input_at_the_budget() {
    let budget = rust_message_box::beef_door::work_units_per_input();
    for k in [1usize, 7, 9, 100, 500] {
        // Each extra padding byte costs k units. Account for a varint
        // width change, then fill the budget to within k-1 units.
        let probe = 1_000;
        let (_, _, work) = single_input_work_measured(k, probe);
        let mut padding = probe + ((budget - work) / k as u64) as usize;
        let (_, _, filled) = single_input_work_measured(k, padding);
        if filled > budget {
            padding -= (filled - budget).div_ceil(k as u64) as usize;
        }
        let (beef, root, work) = single_input_work_measured(k, padding);
        assert!(work <= budget && budget - work < k as u64);
        // At exactly the measured work it is valid; one less must decline.
        let below = at_rest_with_work(&beef, &root, u64::MAX, work - 1);
        assert_eq!(below.answer.unwrap_err().0, 422);
        for sample in 1..=3 {
            for (path, run) in [
                ("at rest", at_rest(&beef, &root, u64::MAX)),
                ("inline", inline(&beef, &root)),
            ] {
                eprintln!("R404-H1 budget calibration: k={k}, padding={padding}, bytes={}, work={work}/{budget}, sample={sample}, {path}: {:.3} ms, {:?}", beef.len(), run.took.as_secs_f64()*1e3, run.answer);
                assert_eq!(run.answer, Ok(FEE));
                assert_eq!(run.asked, 1);
                assert_eq!(run.pending, 0);
            }
        }
    }
}
