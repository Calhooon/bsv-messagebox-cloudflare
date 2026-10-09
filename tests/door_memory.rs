//! NL-4: what the payment door holds while it reads an object at rest.
//!
//! The object is never in memory here: the store writes it link by link as
//! the door asks for chunks, so the heap this test measures is the door's
//! own (a counting allocator over the whole process; one test, so nothing
//! else allocates beside it). Three shapes:
//!
//! - an object over 100 MB of large elements (a chain of links carrying a
//!   megabyte each, in the output the next link spends): the door's peak is
//!   the order of one element, far under the object;
//! - a chain of 100,000 small links: the door's peak is its index, bytes per
//!   element, the number the one-pass ceiling of an isolate is read from;
//! - the megabytes in outputs nothing in the BEEF spends: the door runs the
//!   scripts (NL-4c), so the reader keeps every output until an input spends
//!   it, and these are held to the end of the reading. The peak is the order
//!   of the unspent bytes, twice (the reader's state and the cursor taken
//!   from it at the end). Named here, not hidden: it is the cost of refusing
//!   a spend no script allows in one pass.

use bsv_middleware_rs::{HeaderLookupError, HeaderService, PaymentVerdict};
use rust_message_box::beef_door::{
    verify_at_rest, AtRest, BeefStore, Chunks, Slice, Slices, Stamp, Terms,
};
use sha2::{Digest, Sha256};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            let grown = new_size - layout.size();
            let live = LIVE.fetch_add(grown, Ordering::Relaxed) + grown;
            PEAK.fetch_max(live, Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

const FEE: u64 = 100;
const HEIGHT: u32 = 850_000;
const PAID: &[u8] = &[0x51; 25];
const KEY: &str = "02abc/upload.beef";

fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(raw)).into()
}

/// Where a link carries its megabyte.
#[derive(Clone, Copy, PartialEq)]
enum Ballast {
    None,
    /// In output 0, the one the next link spends: a push of that many bytes,
    /// dropped, then `OP_TRUE`.
    Spent(usize),
    /// In a second output nothing spends.
    Unspent(usize),
}

fn script_len(len: usize, t: &mut Vec<u8>) {
    if len < 0xfd {
        t.push(len as u8);
    } else {
        t.push(0xfe);
        t.extend_from_slice(&(len as u32).to_le_bytes());
    }
}

/// One input spending `prev:0` with an empty unlock, output 0 of `satoshis`
/// at `script`, and the ballast where `ballast` puts it.
fn raw_tx(prev: &[u8; 32], satoshis: u64, script: &[u8], ballast: Ballast) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&1u32.to_le_bytes());
    t.push(1);
    t.extend_from_slice(prev);
    t.extend_from_slice(&0u32.to_le_bytes());
    t.push(0);
    t.extend_from_slice(&u32::MAX.to_le_bytes());
    t.push(if matches!(ballast, Ballast::Unspent(_)) {
        2
    } else {
        1
    });
    t.extend_from_slice(&satoshis.to_le_bytes());
    match ballast {
        Ballast::Spent(bytes) => {
            // OP_PUSHDATA4 <bytes> OP_DROP, then the script.
            script_len(5 + bytes + 1 + script.len(), &mut t);
            t.push(0x4e);
            t.extend_from_slice(&(bytes as u32).to_le_bytes());
            t.resize(t.len() + bytes, 0x6a);
            t.push(0x75);
            t.extend_from_slice(script);
        }
        _ => {
            script_len(script.len(), &mut t);
            t.extend_from_slice(script);
        }
    }
    if let Ballast::Unspent(bytes) = ballast {
        t.extend_from_slice(&0u64.to_le_bytes());
        script_len(bytes, &mut t);
        t.resize(t.len() + bytes, 0x6a);
    }
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// A chain of `links` links, each carrying `ballast` but the last, as an
/// Atomic BEEF written a piece at a time: the header and the BUMP, then one
/// link per call. Each link's output 0 is `OP_TRUE` (behind the ballast when
/// it rides there), which the next link's empty unlock satisfies.
struct Writer {
    links: usize,
    ballast: Ballast,
    next: usize,
    prev: [u8; 32],
    subject: [u8; 32],
    oldest: [u8; 32],
}

impl Writer {
    fn link(&self, i: usize, prev: &[u8; 32]) -> Vec<u8> {
        if i + 1 == self.links {
            raw_tx(prev, FEE, PAID, Ballast::None)
        } else {
            raw_tx(prev, 1_000, &[0x51], self.ballast)
        }
    }

    /// The chain's subject and oldest txids: one walk, a link in hand.
    fn new(links: usize, ballast: Ballast) -> Self {
        let mut w = Self {
            links,
            ballast,
            next: 0,
            prev: [0x11; 32],
            subject: [0; 32],
            oldest: [0; 32],
        };
        let mut prev = [0x11u8; 32];
        for i in 0..links {
            prev = hash(&w.link(i, &prev));
            if i == 0 {
                w.oldest = prev;
            }
        }
        w.subject = prev;
        w
    }

    fn head(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0x0101_0101u32.to_le_bytes());
        b.extend_from_slice(&self.subject);
        b.extend_from_slice(&0xEFBE_0002u32.to_le_bytes());
        b.push(1);
        b.push(0xfe);
        b.extend_from_slice(&HEIGHT.to_le_bytes());
        b.extend_from_slice(&[1, 1, 0, 2]);
        b.extend_from_slice(&self.oldest);
        b.push(0xfe);
        b.extend_from_slice(&(self.links as u32).to_le_bytes());
        b
    }

    /// The next piece: the head first, then each link behind its format.
    fn piece(&mut self) -> Option<Vec<u8>> {
        if self.next > self.links {
            return None;
        }
        let piece = if self.next == 0 {
            self.head()
        } else {
            let i = self.next - 1;
            let raw = self.link(i, &self.prev);
            self.prev = hash(&raw);
            let mut piece = if i == 0 { vec![1, 0] } else { vec![0] };
            piece.extend_from_slice(&raw);
            piece
        };
        self.next += 1;
        Some(piece)
    }
}

/// The object's bytes from an offset, written as they are asked for.
struct Written {
    writer: Writer,
    skip: u64,
}

#[async_trait::async_trait(?Send)]
impl Chunks for Written {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        while let Some(mut piece) = self.writer.piece() {
            let len = piece.len() as u64;
            if self.skip >= len {
                self.skip -= len;
                continue;
            }
            piece.drain(..self.skip as usize);
            self.skip = 0;
            return Ok(Some(piece));
        }
        Ok(None)
    }
}

/// A store whose one object is the chain, never held; the door's state is
/// kept as saved.
struct ChainStore {
    links: usize,
    ballast: Ballast,
    size: u64,
    states: RefCell<HashMap<String, Vec<u8>>>,
}

impl ChainStore {
    fn new(links: usize, ballast: Ballast) -> Self {
        let mut writer = Writer::new(links, ballast);
        let mut size = 0u64;
        while let Some(piece) = writer.piece() {
            size += piece.len() as u64;
        }
        Self {
            links,
            ballast,
            size,
            states: RefCell::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl BeefStore for ChainStore {
    async fn stamp(&self, _key: &str) -> Result<Option<Stamp>, String> {
        Ok(Some(Stamp {
            size: self.size,
            etag: "v1".to_string(),
        }))
    }

    async fn open(&self, _key: &str, from: u64, _stamp: &Stamp) -> Result<Box<dyn Chunks>, String> {
        Ok(Box::new(Written {
            writer: Writer::new(self.links, self.ballast),
            skip: from,
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

struct OneRoot(String);

#[async_trait::async_trait]
impl HeaderService for OneRoot {
    async fn merkle_root_at(&self, height: u32) -> Result<String, HeaderLookupError> {
        if height == HEIGHT {
            Ok(self.0.clone())
        } else {
            Err(HeaderLookupError(format!("no header at {height}")))
        }
    }
}

/// The chain through the door in one pass: its size, the heap the pass added
/// at its peak, and the seconds it took.
fn measure(links: usize, ballast: Ballast) -> (u64, usize, f64) {
    let store = ChainStore::new(links, ballast);
    let oldest = Writer::new(links, ballast).oldest;
    let headers = OneRoot(hex::encode(
        oldest.iter().rev().copied().collect::<Vec<u8>>(),
    ));
    let terms = Terms {
        output_index: 0,
        expected_script: PAID,
        required_satoshis: FEE,
    };
    let clock = || 0u64;
    let slices = Slices {
        time: Slice {
            clock: &clock,
            millis: u64::MAX,
        },
        lookups: usize::MAX,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let answer = runtime
        .block_on(verify_at_rest(&store, KEY, &terms, Some(&headers), &slices))
        .unwrap();
    let seconds = started.elapsed().as_secs_f64();
    let peak = PEAK.load(Ordering::Relaxed) - before;
    match answer {
        AtRest::Done(verdict) => {
            assert_eq!(verdict.word, PaymentVerdict::Verified { satoshis: FEE });
            assert!(verdict.subject.is_some(), "the subject is named");
        }
        other => panic!("no verdict: {other:?}"),
    }
    (store.size, peak, seconds)
}

#[test]
fn the_door_holds_an_element_and_its_index_never_the_object() {
    const MIB: usize = 1024 * 1024;

    // In a release build, 129 links of a megabyte each: over the 100 MB the
    // README names and over an isolate's 128 MiB. A debug build hashes a
    // tenth as fast and reads 16 of them, four times the old door.
    let links = if cfg!(debug_assertions) { 17 } else { 130 };
    let (size, peak, seconds) = measure(links, Ballast::Spent(MIB));
    eprintln!(
        "door_memory: {links} links of 1 MiB, {size} bytes, peak heap {peak} bytes, {seconds:.2} s"
    );
    assert!(size > (links as u64 - 2) * MIB as u64);
    assert!(
        peak < 16 * MIB,
        "the order of one element, not of the object: {peak}"
    );

    // The same megabytes in outputs nothing spends: held until the reading
    // ends, in the reader's state and once more in the cursor taken from it.
    let unspent = 9;
    let (size, peak, seconds) = measure(unspent, Ballast::Unspent(MIB));
    eprintln!(
        "door_memory: {unspent} links of 1 MiB nothing spends, {size} bytes, peak heap {peak} bytes, {seconds:.2} s"
    );
    let held = (unspent - 1) * MIB;
    assert!(
        peak >= held,
        "outputs nothing spends are held to the end: {peak}"
    );
    assert!(
        peak < 2 * held + 4 * MIB,
        "twice the unspent bytes and an element, no more: {peak}"
    );

    // 100,000 small links: the index is the memory.
    for links in [1_000usize, 10_000, 100_000] {
        let (size, peak, seconds) = measure(links, Ballast::None);
        eprintln!(
            "door_memory: {links} links, {size} bytes, peak heap {peak} bytes, {:.1} bytes an element, {seconds:.2} s",
            peak as f64 / (links + 1) as f64
        );
        assert!(
            peak < 512 * (links + 1) + 256 * 1024,
            "linear in the elements: {peak}"
        );
    }
}
