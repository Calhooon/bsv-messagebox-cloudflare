//! The presence read's counters, one per reason (0.8.2, message box #20 (e)):
//! numbers the relay's health answer carries, so a loop reads the classes of
//! `GET /presence` (and the session lane's `hub-unavailable`) without the log.

use crate::presence::{HubVerdict, PresenceHop};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};

/// One counted outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresenceReason {
    /// A failed hop of the presence read.
    Hop(PresenceHop),
    /// The hub's undecided 200 (`present: null`), answered as itself.
    Null,
    /// The session lane's door answered 503 `hub-unavailable` (any laned
    /// path, `/presence` among them). Counted outside the door.
    HubUnavailable,
}

/// The counters of the presence read, one per reason, in this isolate.
///
/// Their home is the isolate, not the hub's storage: three of the hops
/// (`namespace`, `stub`, `fetch`) fail before any hub is reached, and the
/// session lane's `hub-unavailable` is the identity hub's, not the room's,
/// so only the relay sees every reason; a count in a hub's storage would also
/// be a write per read. The cost is the scope: a Worker runs many isolates,
/// each counts what it served since it started (`since`), and a restart
/// zeroes it. A loop reads them as rates over its own window, never as
/// totals.
pub(crate) struct PresenceCounters {
    since_ms: AtomicU64,
    hops: [AtomicU64; 6],
    null: AtomicU64,
    hub_unavailable: AtomicU64,
}

impl PresenceCounters {
    pub(crate) const fn new() -> Self {
        Self {
            since_ms: AtomicU64::new(0),
            hops: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            null: AtomicU64::new(0),
            hub_unavailable: AtomicU64::new(0),
        }
    }

    /// Note the isolate's start: the first request it serves.
    pub(crate) fn mark_start(&self, now_ms: u64) {
        let _ = self
            .since_ms
            .compare_exchange(0, now_ms, Ordering::Relaxed, Ordering::Relaxed);
    }

    pub(crate) fn count(&self, reason: PresenceReason) {
        let cell = match reason {
            PresenceReason::Hop(hop) => &self.hops[hop as usize],
            PresenceReason::Null => &self.null,
            PresenceReason::HubUnavailable => &self.hub_unavailable,
        };
        cell.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn get(&self, reason: PresenceReason) -> u64 {
        match reason {
            PresenceReason::Hop(hop) => self.hops[hop as usize].load(Ordering::Relaxed),
            PresenceReason::Null => self.null.load(Ordering::Relaxed),
            PresenceReason::HubUnavailable => self.hub_unavailable.load(Ordering::Relaxed),
        }
    }

    /// The health answer's `presence` figure.
    pub(crate) fn health_json(&self) -> Value {
        let mut counts = serde_json::Map::new();
        for hop in PresenceHop::ALL {
            counts.insert(
                hop.as_str().to_string(),
                json!(self.get(PresenceReason::Hop(hop))),
            );
        }
        counts.insert("null".to_string(), json!(self.get(PresenceReason::Null)));
        counts.insert(
            "hubUnavailable".to_string(),
            json!(self.get(PresenceReason::HubUnavailable)),
        );
        json!({
            "scope": "isolate",
            "sinceMs": self.since_ms.load(Ordering::Relaxed),
            "counts": counts,
        })
    }
}

/// This isolate's counters.
pub(crate) static PRESENCE_COUNTERS: PresenceCounters = PresenceCounters::new();

/// Count one presence read's outcome: a fault's hop, or the hub's `null`; a
/// decided answer is neither.
pub(crate) fn count_presence_verdict(counters: &PresenceCounters, verdict: &HubVerdict) {
    match verdict {
        HubVerdict::Fault { hop, .. } => counters.count(PresenceReason::Hop(*hop)),
        HubVerdict::Answered { present: None, .. } => counters.count(PresenceReason::Null),
        HubVerdict::Answered { .. } => {}
    }
}
