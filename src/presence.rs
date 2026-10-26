//! The presence read's hops (0.8.2, message box #20 (b)).
//!
//! `GET /presence` asks the room owner's hub through five hops: the hub
//! namespace, the object's stub, the fetch, the hub's HTTP status, and the
//! body (whose `present` must be a boolean or `null`). Before 0.8.2 every
//! failed hop folded into one 503 with no log line, and the hub's own
//! `{"present": null}` ("undecided") folded into it too. Here each hop is a
//! reason of its own: on the 503's JSON (`hop`), on one `TRACE_PRESENCE` log
//! line, on the request's `TRACE_LAT` line (`reason=`), and in a counter the
//! relay's health answer carries (`presence_counters`).
//!
//! The hub is reached behind a seam (`PresenceHub`), so the hops are driven
//! by a stub in the tests and by the Worker's namespace in production.

use serde_json::Value;

/// The hop of the presence read that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresenceHop {
    /// The hub namespace could not be bound (`hub_store::hub_namespace`).
    Namespace,
    /// The object's id or stub could not be made.
    Stub,
    /// The fetch to the hub failed (the platform's errors, an overloaded
    /// object among them, arrive here; the log line carries the text).
    Fetch,
    /// The hub answered a status other than 200 (read before the body).
    Status,
    /// The hub's 200 body is not JSON.
    Body,
    /// The hub's JSON has no `present`, or one that is neither a boolean
    /// nor `null`.
    Present,
}

impl PresenceHop {
    pub(crate) const ALL: [PresenceHop; 6] = [
        PresenceHop::Namespace,
        PresenceHop::Stub,
        PresenceHop::Fetch,
        PresenceHop::Status,
        PresenceHop::Body,
        PresenceHop::Present,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PresenceHop::Namespace => "namespace",
            PresenceHop::Stub => "stub",
            PresenceHop::Fetch => "fetch",
            PresenceHop::Status => "status",
            PresenceHop::Body => "body",
            PresenceHop::Present => "present",
        }
    }
}

/// The seconds a client waits before it asks again after a 503
/// `ERR_PRESENCE_UNAVAILABLE` (the `Retry-After` header): five. A failed hop
/// is the platform's (an object resetting or overloaded, a namespace or stub
/// error) and clears in seconds, not in a client's millisecond retry; five
/// seconds also keeps one reader's retries of one room at 0.2 a second, the
/// order of the read rate LOW's beta hour measured (about 0.15 a second),
/// so a fault never multiplies the load on the hub it hit. The hub's own
/// verdicts, `null` included, are 200s and carry no `Retry-After`.
pub(crate) const PRESENCE_RETRY_AFTER_SECS: &str = "5";

/// The code of a presence read that failed.
pub(crate) const PRESENCE_UNAVAILABLE_CODE: &str = "ERR_PRESENCE_UNAVAILABLE";

/// The `Retry-After` value a `/presence` answer carries: every 503
/// `ERR_PRESENCE_UNAVAILABLE`, and nothing else.
pub(crate) fn presence_retry_after(body: &Value, status: u16) -> Option<&'static str> {
    (status == 503 && body["code"] == PRESENCE_UNAVAILABLE_CODE)
        .then_some(PRESENCE_RETRY_AFTER_SECS)
}

/// What the hub's leg of the read hands back: the hub's status and its body
/// (`Err` with the parse error when the body is not JSON), or the hop that
/// failed before the hub answered and its error.
pub(crate) type HubAnswer =
    std::result::Result<(u16, std::result::Result<Value, String>), (PresenceHop, String)>;

/// The owner's hub behind a seam: ask `/internal/presence?room=` of the hub
/// named `owner`.
pub(crate) trait PresenceHub {
    fn ask(&self, owner: &str, room: &str) -> impl std::future::Future<Output = HubAnswer>;
}

/// The hub's verdict, or the hop that kept the relay from reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HubVerdict {
    /// The hub answered: `present` is `Some(true)`, `Some(false)` or `None`
    /// (the hub's own "undecided"); the advisory stamps when it sent them.
    Answered {
        present: Option<bool>,
        last_seen_ms: Option<u64>,
        rejoin_deadline_ms: Option<u64>,
    },
    /// A hop failed: which, the hub's status on the `status` hop, the error.
    Fault {
        hop: PresenceHop,
        hub_status: Option<u16>,
        err: String,
    },
}

/// Pure: classify what the hub's leg handed back. The status is read before
/// the body: a non-200 is the `status` hop whatever its body says.
pub(crate) fn classify_hub_answer(answer: HubAnswer) -> HubVerdict {
    let (status, body) = match answer {
        Ok(a) => a,
        Err((hop, err)) => {
            return HubVerdict::Fault {
                hop,
                hub_status: None,
                err,
            }
        }
    };
    if status != 200 {
        return HubVerdict::Fault {
            hop: PresenceHop::Status,
            hub_status: Some(status),
            err: format!("hub status {status}"),
        };
    }
    let body = match body {
        Ok(b) => b,
        Err(err) => {
            return HubVerdict::Fault {
                hop: PresenceHop::Body,
                hub_status: None,
                err,
            }
        }
    };
    let present = match body.get("present") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::Null) => None,
        Some(other) => {
            return HubVerdict::Fault {
                hop: PresenceHop::Present,
                hub_status: None,
                err: format!("present is {other}"),
            }
        }
        None => {
            return HubVerdict::Fault {
                hop: PresenceHop::Present,
                hub_status: None,
                err: "present missing".to_string(),
            }
        }
    };
    HubVerdict::Answered {
        present,
        // Advisory: absent or non-numeric is None (omitted later). The
        // client, not the relay, decides whether a deadline is past.
        last_seen_ms: body.get("lastSeenMs").and_then(Value::as_u64),
        rejoin_deadline_ms: body.get("rejoinDeadlineMs").and_then(Value::as_u64),
    }
}

/// Ask the owner's hub through `hub` and classify its answer.
pub(crate) async fn read_presence<H: PresenceHub>(hub: &H, owner: &str, room: &str) -> HubVerdict {
    classify_hub_answer(hub.ask(owner, room).await)
}

/// The reason a `/presence` answer names on its `TRACE_LAT` line: the hop of
/// a 503 `ERR_PRESENCE_UNAVAILABLE`, `null` for the hub's undecided 200, and
/// nothing for a decided answer or another route.
pub(crate) fn presence_trace_reason(body: &Value, status: u16) -> Option<&str> {
    if status == 503 && body["code"] == PRESENCE_UNAVAILABLE_CODE {
        return body["hop"].as_str();
    }
    (status == 200 && body.get("present") == Some(&Value::Null)).then_some("null")
}

/// Log one presence read's fault: one `TRACE_PRESENCE` line naming the hop
/// and the error (the room is the only id it carries). An answer, `null`
/// included, logs nothing here (its `TRACE_LAT` line names a `null`).
pub(crate) fn log_presence_verdict(verdict: &HubVerdict, room: &str, log: impl FnOnce(String)) {
    if let HubVerdict::Fault { hop, err, .. } = verdict {
        log(format!(
            "TRACE_PRESENCE hop={} err={} room={room}",
            hop.as_str(),
            err.replace(['\n', '\r'], " ")
        ));
    }
}
