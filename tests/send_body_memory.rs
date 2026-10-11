//! NOTE-4 (bsv-low #591): the inline `payment.tx` read as bytes from the
//! request's body, never parsed into a `serde_json::Value` first.
//!
//! Through 0.4.3 the send's body was parsed whole into a `Value` before any
//! route, and a byte array is one `Value` a byte: LOW's lens measured an
//! Array-shaped body of about 15 MB exhausting the isolate in parsing alone.
//! Since 0.4.4 the body is held to `SEND_BODY_BYTES` before a byte of it is
//! parsed, and below it an array `tx` is read from the text as bytes, handed
//! on as hex with its shape kept beside it.
//!
//! The heap is measured with a counting allocator over the whole process;
//! one test, so nothing else allocates beside it.

use rust_message_box::validation::{validate_send_message, SEND_BODY_BYTES};
use std::alloc::{GlobalAlloc, Layout, System};
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

/// A send whose `payment.tx` is `beef_bytes` bytes as a JSON byte array.
fn array_body(beef_bytes: usize) -> Vec<u8> {
    let mut body = String::from(
        r#"{"message":{"messageBox":"inbox","recipient":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","messageId":"m-1","body":"hi"},"payment":{"outputs":[],"tx":["#,
    );
    for i in 0..beef_bytes {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&((i * 31 % 251) as u8).to_string());
    }
    body.push_str("]}}");
    body.into_bytes()
}

/// The heap a run held above what was live when it began, and its answer.
fn peak_of<T>(run: impl FnOnce() -> T) -> (usize, T) {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    let answer = run();
    (PEAK.load(Ordering::Relaxed) - base, answer)
}

#[test]
fn an_array_body_is_bounded_before_it_is_parsed_and_read_as_bytes_below_the_bound() {
    // About 15 MB: LOW's body. Refused at the bound, nothing parsed.
    let over = array_body(4_300_000);
    assert!(
        over.len() > 15_000_000 && over.len() > SEND_BODY_BYTES,
        "{}",
        over.len()
    );
    let (peak, answer) = peak_of(|| validate_send_message(&over));
    eprintln!(
        "send_body_memory: {} bytes of array body: {:?}, peak {} bytes",
        over.len(),
        answer.as_ref().err().map(|(b, s)| (s, b["code"].clone())),
        peak
    );
    let (body, status) = answer.expect_err("refused at the bound");
    assert_eq!(
        (status, &body["code"]),
        (413, &serde_json::json!("ERR_BODY_TOO_LARGE"))
    );
    assert!(peak < 64 * 1024, "nothing parsed: {peak} bytes");
    drop(over);

    // Under the bound: read as bytes, handed on as hex, its shape kept.
    let beef = 2_800_000;
    let under = array_body(beef);
    assert!(under.len() <= SEND_BODY_BYTES, "{}", under.len());
    let (peak, answer) = peak_of(|| validate_send_message(&under));
    eprintln!(
        "send_body_memory: {} bytes of array body ({} bytes of BEEF): accepted, peak {} bytes",
        under.len(),
        beef,
        peak
    );
    let validated = answer.expect("a valid send");
    let payment = validated.payment.expect("a payment");
    assert_eq!(payment["tx"].as_str().map(str::len), Some(2 * beef), "hex");
    assert_eq!(payment["txShape"], "array", "the shape it was sent in");
    assert!(
        peak < under.len() * 2,
        "about one copy of the body and the hex beside it, never a Value a byte: {peak}"
    );
}
