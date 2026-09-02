//! Bounded, retried EngineIoSession/Worker → per-identity `MessageHub` DO
//! forwarding for the socket.io send path (bsv-low#249, ack-reliability follow-up).
//!
//! ## Why this exists
//!
//! A socket.io `sendMessage` that arrives over the **WebSocket** transport is
//! stored + acked through an extra Durable-Object hop: the `EngineIoSession`
//! DO (or, on the polling transport, the Worker) makes a subrequest to the
//! per-identity `MessageHub` DO at `/internal/socketio-event`, which runs
//! `process_send` (D1 insert) and returns the `sendMessageAck`. The HTTP
//! `POST /sendMessage` fallback the client uses does NOT take this hop — it
//! writes D1 directly in the Worker (`lib.rs::handle_send_message`).
//!
//! That asymmetry is the whole bug. The DO→DO subrequest was **unbounded**:
//! when the target `MessageHub` DO is momentarily cold / evicted / relocating
//! (observed mid-hand during a heavy funding+broadcast burst), the forward
//! stalls past the client's *fixed* 10 000 ms WS-ack timeout — so no
//! `sendMessageAck-<room>` reaches the sender, and `sendLiveMessage` falls back
//! to HTTP, which fast-stores the (never-yet-stored) message fresh. That is the
//! `relay.send ok 10597ms — shuffle_pass #1` evidence: a *fresh* send (`#1`, not
//! a resend) that resolved `ok` via the fast HTTP fallback because the WS hop
//! never landed. Distinct from the duplicate-ack bug (`f09fd2d`), which produced
//! `fail`/duplicate on *resends*; this is a first-send stall on the DO hop.
//!
//! ## The fix
//!
//! Bound each forward attempt with a wall-clock `Delay` race (mirroring
//! `storage::with_d1_op_timeout`) and retry once. A cold/relocating DO that
//! stalls the first attempt is abandoned in `FORWARD_OP_TIMEOUT_MS` and a fresh
//! subrequest is issued — which typically routes to a now-warm instance and acks
//! **sub-second**, well inside the client's 10 s budget, so the WS ack wins and
//! no fallback (and no 10 s move-flow stall) occurs. If both attempts still fail,
//! we return no events and the client's HTTP fallback remains the at-least-once
//! safety net — worst case equals today's behaviour, never worse.
//!
//! ## Why the retry is money-safe (idempotent, at-least-once, ordered)
//!
//! The forwarded write is `insert_message`, an `INSERT OR IGNORE` on a UNIQUE
//! content-addressed `messageId` (see `storage::insert_changes_mean_stored`). A
//! first attempt whose response timed out may still have LANDED on the platform;
//! the retry then sees the row already present and `MessageHub` returns a
//! `DuplicateMessage` → mapped to `sendMessageAck { duplicate: true }`
//! (`message_hub::outcome_to_outbound`, the `f09fd2d` contract). So a retry can
//! never double-deliver and always yields the ack the client listens for. One
//! `sendMessage` frame still produces exactly one ack; retrying does not reorder
//! anything (the client serialises its own resends by messageId).

use std::future::Future;

/// Per-attempt wall-clock bound on the DO→`MessageHub` forward subrequest.
///
/// Sized against the client's fixed 10 000 ms `sendLiveMessage` WS-ack timeout:
/// `FORWARD_ATTEMPTS` attempts × this bound must stay comfortably under 10 s so
/// that a *successful retry's* ack still beats the client's HTTP fallback. At
/// 3 000 ms × 2 = 6 000 ms worst-case-before-giving-up, a retry that succeeds
/// shortly after the first attempt's timeout lands its ack ~3 s in — inside the
/// budget — while a total failure still leaves ~4 s of client margin before the
/// fallback fires.
pub const FORWARD_OP_TIMEOUT_MS: u64 = 3_000;

/// Total forward attempts (initial + retries). One retry: the observed failure
/// is an *intermittent* cold/relocating-DO stall that a fresh subrequest clears;
/// a second retry buys little and eats the client's fallback margin.
pub const FORWARD_ATTEMPTS: u32 = 2;

/// Bound one forward subrequest future by a per-op wall-clock timeout.
///
/// On wasm (the real Worker/DO) the future is raced against a `worker::Delay`;
/// if the delay wins, the subrequest future is DROPPED and a timeout error is
/// returned so the caller retries. A dropped DO subrequest may still land on the
/// platform — which is why the forwarded write is idempotent on a UNIQUE key (a
/// re-attempt can never double-apply; it converges to a duplicate-ack).
///
/// On the host test target there is no JS event loop to drive `Delay`, so the op
/// is awaited directly (host tests exercise the retry/timeout POLICY via injected
/// outcomes in `run_forward_with_retry`, never a real hang).
#[cfg(target_arch = "wasm32")]
pub async fn with_do_op_timeout<T, Fut>(op: Fut, timeout_ms: u64) -> worker::Result<T>
where
    Fut: Future<Output = worker::Result<T>>,
{
    use std::task::Poll;
    let mut op = Box::pin(op);
    let mut timeout = Box::pin(worker::Delay::from(std::time::Duration::from_millis(timeout_ms)));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(r) = op.as_mut().poll(cx) {
            return Poll::Ready(r);
        }
        if timeout.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(worker::Error::RustError(format!(
                "forward: MessageHub subrequest exceeded {timeout_ms}ms bound (transient; retrying)"
            ))));
        }
        Poll::Pending
    })
    .await
}
#[cfg(not(target_arch = "wasm32"))]
pub async fn with_do_op_timeout<T, Fut>(op: Fut, _timeout_ms: u64) -> worker::Result<T>
where
    Fut: Future<Output = worker::Result<T>>,
{
    op.await
}

/// Drive a bounded, retried forward. `attempt(i)` performs one bounded forward
/// subrequest (fetch + parse, already wrapped in `with_do_op_timeout` by the
/// caller) and resolves to:
///   * `Some(events)` — the subrequest succeeded; return these outbound events
///     (the `sendMessageAck` / `messageFailed` the client is waiting for). An
///     empty vec is still a success (a valid response with no events).
///   * `None` — this attempt timed out or errored; try the next one.
///
/// Returns the first successful attempt's events, or an empty vec once
/// `FORWARD_ATTEMPTS` is exhausted (the caller's HTTP fallback is the
/// at-least-once safety net). Pure control flow — no `Delay` — so it runs under
/// `#[tokio::test]` on the host with an injected attempt closure.
pub async fn run_forward_with_retry<T, F, Fut>(mut attempt: F) -> Vec<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Option<Vec<T>>>,
{
    for i in 0..FORWARD_ATTEMPTS {
        if let Some(events) = attempt(i).await {
            return events;
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Succeeds on the first attempt → exactly one subrequest, its events returned,
    // no wasted retry (the common fast path — no regression to the healthy send).
    #[tokio::test]
    async fn returns_first_attempt_events_without_retry() {
        let calls = Cell::new(0u32);
        let out: Vec<&str> = run_forward_with_retry(|_i| {
            calls.set(calls.get() + 1);
            async move { Some(vec!["sendMessageAck"]) }
        })
        .await;
        assert_eq!(out, vec!["sendMessageAck"]);
        assert_eq!(calls.get(), 1, "success on attempt 0 must not retry");
    }

    // The core fix: a first attempt that stalls (the cold/relocating-DO timeout)
    // is retried, and the retry's ack IS delivered — the send no longer silently
    // loses its ack and the client never has to eat the 10 s fallback.
    #[tokio::test]
    async fn retry_recovers_a_stalled_first_attempt() {
        let calls = Cell::new(0u32);
        let out: Vec<&str> = run_forward_with_retry(|i| {
            calls.set(calls.get() + 1);
            async move {
                if i == 0 {
                    None // first attempt: DO-hop stall / timeout
                } else {
                    Some(vec!["sendMessageAck"]) // retry hits a warm instance
                }
            }
        })
        .await;
        assert_eq!(out, vec!["sendMessageAck"], "retry delivered the ack");
        assert_eq!(calls.get(), 2, "stalled once, recovered on the retry");
    }

    // Every attempt fails → return no events (bounded, no unbounded loop). The
    // caller emits nothing and the client's HTTP fallback stores the message:
    // at-least-once preserved, worst case equals pre-fix behaviour.
    #[tokio::test]
    async fn gives_up_empty_after_bound() {
        let calls = Cell::new(0u32);
        let out: Vec<&str> = run_forward_with_retry(|_i| {
            calls.set(calls.get() + 1);
            async move { None }
        })
        .await;
        assert!(out.is_empty(), "exhausted attempts yield no events");
        assert_eq!(
            calls.get(),
            FORWARD_ATTEMPTS,
            "attempts are bounded to FORWARD_ATTEMPTS"
        );
    }

    // A successful-but-EMPTY response (e.g. an outcome that maps to zero events)
    // is honoured as success, NOT mistaken for a retryable failure — otherwise a
    // legitimately empty forward would burn the whole retry budget.
    #[tokio::test]
    async fn empty_success_is_not_retried() {
        let calls = Cell::new(0u32);
        let out: Vec<&str> = run_forward_with_retry(|_i| {
            calls.set(calls.get() + 1);
            async move { Some(Vec::new()) }
        })
        .await;
        assert!(out.is_empty());
        assert_eq!(calls.get(), 1, "Some(empty) is success — do not retry");
    }
}
