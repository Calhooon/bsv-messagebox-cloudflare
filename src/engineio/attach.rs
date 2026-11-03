//! message box #44: the `sessionAttach` exchange behind a seam.
//!
//! The exchange (`attach_exchange`) and its one line (`run_attach`) take an
//! `AttachPort`: the `EngineIoSession` DO is one (`session.rs`, the hub its own
//! `MESSAGE_HUB`), and the witness below is another, a stubbed hub on a virtual
//! clock. So the same code the DO runs is driven per cause on the host, and a
//! witness reads the outcome, the reason and `ms` each exit writes, never only
//! its type.

use serde_json::{json, Value};

use crate::engineio::auth::SessionAuthState;
use crate::session_lane::{
    attach_line, attach_seat, parse_attach_frame, AttachEnd, LineLevel, Refusal as LaneRefusal,
    SessionLane, SessionOffer,
};

/// Why the hub could not be asked. The wire says `hub-unavailable` for every
/// kind (unchanged); the line says `hub-unavailable.<kind>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HubFault {
    /// No verdict inside `ATTACH_HUB_TIMEOUT_MS`.
    Timeout,
    /// The `MESSAGE_HUB` binding, its id or its stub, or the request could not be built.
    Binding,
    /// The fetch to the hub failed.
    Fetch,
    /// The hub answered a non-2xx status with no verdict in its body.
    Status,
    /// The hub answered 2xx with a body that is not a verdict.
    Decode,
}

impl HubFault {
    pub(crate) fn line_reason(self) -> &'static str {
        match self {
            HubFault::Timeout => "hub-unavailable.timeout",
            HubFault::Binding => "hub-unavailable.binding",
            HubFault::Fetch => "hub-unavailable.fetch",
            HubFault::Status => "hub-unavailable.status",
            HubFault::Decode => "hub-unavailable.decode",
        }
    }
}

/// The one-attach-per-socket gate, judged and spent in one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    NoSession,
    Refuse(&'static str),
    Proceed,
}

/// The compare-and-set after the hub's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    NoSession,
    Lost,
    Won,
}

/// What the exchange needs from its host.
pub(crate) trait AttachPort {
    fn now_ms(&self) -> u64;
    /// Send (or enqueue) one Socket.IO event to this socket.
    fn emit(&self, event: &'static str, data: Value);
    fn gate(&self) -> Gate;
    fn persist(&self);
    async fn ask_hub(&self, identity: &str, verify_body: String) -> Result<Value, HubFault>;
    fn random32(&self) -> Option<[u8; 32]>;
    /// The lane mint (no line of its own: the attach's line names the failure).
    fn mint(
        &self,
        state: &SessionAuthState,
        identity: &str,
        ask: &str,
    ) -> Option<(SessionLane, SessionOffer)>;
    fn commit(&self, state: SessionAuthState, lane: SessionLane) -> Commit;
    fn sid(&self) -> String;
    fn debug(&self, line: &str);
}

/// The attach, timed from `started_ms` (the frame's arrival), and its ONE line.
pub(crate) async fn run_attach<P: AttachPort>(
    p: &P,
    arg: &Value,
    started_ms: u64,
) -> (AttachEnd, LineLevel, String) {
    let seat = attach_seat(arg);
    let end = attach_exchange(p, arg).await;
    let elapsed = p.now_ms().saturating_sub(started_ms);
    let (level, line) = attach_line(&end, seat.as_deref(), &p.sid(), elapsed);
    (end, level, line)
}

/// The attach itself: every exit returns its end (`run_attach` writes it).
pub(crate) async fn attach_exchange<P: AttachPort>(p: &P, arg: &Value) -> AttachEnd {
    let refuse = |wire: &str, line: &str| {
        p.emit(
            crate::session_lane::ATTACH_REFUSED_EVENT,
            json!({ "reason": wire }),
        );
        AttachEnd::Refused(line.to_string())
    };
    let Some(frame) = parse_attach_frame(arg) else {
        let r = LaneRefusal::Malformed.as_str();
        return refuse(r, r);
    };
    // One attach per socket (L1), judged and spent with the authenticated
    // check, before the hub is asked.
    match p.gate() {
        Gate::NoSession => return AttachEnd::Dropped("no-session"),
        Gate::Refuse(r) => return refuse(r, r),
        Gate::Proceed => {}
    }
    p.persist();
    let verify_body = crate::session_lane::attach_verify_body(&frame).to_string();
    let verdict = match p.ask_hub(&frame.identity, verify_body).await {
        Ok(v) => v,
        Err(fault) => return refuse("hub-unavailable", fault.line_reason()),
    };
    if verdict.get("ok").and_then(Value::as_bool) != Some(true) {
        let reason = verdict
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown-session")
            .to_string();
        return refuse(&reason, &reason);
    }
    // The identity the HUB holds the mirror for, and the mirror's key for the ack.
    let identity = verdict
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let hub_key = verdict
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if identity.is_empty() || identity != frame.identity || hub_key.is_empty() {
        let r = LaneRefusal::UnknownSession.as_str();
        return refuse(r, r);
    }
    let Some(random) = p.random32() else {
        return refuse("no-randomness", "no-randomness");
    };
    let server_session_nonce = hex::encode(random);
    let state = SessionAuthState::Authenticated {
        server_session_nonce: server_session_nonce.clone(),
        peer_nonce: frame.nonce.clone(),
        peer_identity_key: identity.clone(),
    };
    let Some((lane, offer)) = p.mint(&state, &identity, &frame.nonce) else {
        return refuse("mint-failed", "mint-failed");
    };
    // Compare-and-set (M2): the hub was asked across an await, and a
    // handshake that completed meanwhile owns this socket. Authenticated
    // and the lane land in one step, or nothing does.
    match p.commit(state, lane) {
        Commit::Won => {}
        Commit::Lost => return refuse("already-authenticated", "already-authenticated"),
        Commit::NoSession => return AttachEnd::Dropped("no-session"),
    }
    p.persist();
    let d = json!({ "session": offer, "serverNonce": server_session_nonce, "nonce": frame.nonce })
        .to_string();
    let Some(m) = crate::session_lane::attach_ack_mac(&hub_key, &d) else {
        return refuse("mint-failed", "mint-failed");
    };
    p.emit(
        crate::session_lane::ATTACHED_EVENT,
        json!({ "d": d, "m": m }),
    );
    p.debug(&format!(
        "TRACE_SESSION attached identity={} hub_lane={}… socket_lane={}…",
        identity,
        &frame.s[..12],
        &offer.id[..12]
    ));
    AttachEnd::Answered
}

/// The witness of #44 on the attach path the DO runs: a stubbed hub per cause,
/// on a virtual clock; each case asserts the end, the wire event, the line's
/// outcome, reason, `ms` and level.
#[cfg(test)]
mod attach_path_witness {
    use super::*;
    use std::cell::{Cell, RefCell};

    const ID: &str = "02cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    const OTHER: &str = "03efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
    const HUB_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    struct Stub {
        clock: Cell<u64>,
        gate: Gate,
        /// The hub's answer and how long it takes on the virtual clock.
        hub: Result<Value, HubFault>,
        hub_ms: u64,
        random: bool,
        commit: Commit,
        sent: RefCell<Vec<(&'static str, Value)>>,
        hub_asked: Cell<bool>,
    }

    impl Stub {
        fn new(hub: Result<Value, HubFault>, hub_ms: u64) -> Self {
            Stub {
                clock: Cell::new(10_000),
                gate: Gate::Proceed,
                hub,
                hub_ms,
                random: true,
                commit: Commit::Won,
                sent: RefCell::new(Vec::new()),
                hub_asked: Cell::new(false),
            }
        }
    }

    impl AttachPort for Stub {
        fn now_ms(&self) -> u64 {
            self.clock.get()
        }
        fn emit(&self, event: &'static str, data: Value) {
            self.sent.borrow_mut().push((event, data));
        }
        fn gate(&self) -> Gate {
            self.gate
        }
        fn persist(&self) {}
        async fn ask_hub(&self, identity: &str, _body: String) -> Result<Value, HubFault> {
            assert_eq!(identity, ID);
            self.hub_asked.set(true);
            self.clock.set(self.clock.get() + self.hub_ms);
            self.hub.clone()
        }
        fn random32(&self) -> Option<[u8; 32]> {
            self.random.then_some([7u8; 32])
        }
        fn mint(
            &self,
            state: &SessionAuthState,
            identity: &str,
            ask: &str,
        ) -> Option<(SessionLane, SessionOffer)> {
            let SessionAuthState::Authenticated {
                server_session_nonce,
                peer_nonce,
                ..
            } = state
            else {
                return None;
            };
            Some(SessionLane::mint(
                identity,
                peer_nonce,
                server_session_nonce,
                &[9u8; 64],
                self.clock.get(),
                ask,
            ))
        }
        fn commit(&self, _state: SessionAuthState, _lane: SessionLane) -> Commit {
            self.commit
        }
        fn sid(&self) -> String {
            "sidW".into()
        }
        fn debug(&self, _line: &str) {}
    }

    fn frame() -> Value {
        json!({ "s": "ab".repeat(32), "identity": ID, "n": 3, "mac": "ef".repeat(32), "nonce": "01".repeat(32) })
    }

    fn ok_verdict(identity: &str) -> Result<Value, HubFault> {
        Ok(json!({ "ok": true, "identity": identity, "key": HUB_KEY }))
    }

    /// Drive the attach the DO runs: the frame arrived `queued_ms` before the
    /// handler ran (the frame's wait at the relay before dispatch).
    fn drive(stub: &Stub, arg: &Value, queued_ms: u64) -> (AttachEnd, LineLevel, String) {
        let started = stub.clock.get();
        stub.clock.set(started + queued_ms);
        let out = futures_executor_lite(run_attach(stub, arg, started));
        println!("{:?} {}", out.1, out.2);
        out
    }

    /// A single-threaded poll to completion (the stub never parks).
    fn futures_executor_lite<F: std::future::Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn wire(stub: &Stub) -> Vec<(&'static str, Value)> {
        stub.sent.borrow().clone()
    }

    fn refused_on_wire(stub: &Stub, reason: &str) {
        assert_eq!(
            wire(stub),
            vec![(
                crate::session_lane::ATTACH_REFUSED_EVENT,
                json!({ "reason": reason })
            )],
            "the wire carries the refusal"
        );
    }

    #[test]
    fn a_bad_token_the_hub_refuses_is_one_warn_line_naming_the_hub_s_reason() {
        let stub = Stub::new(Ok(json!({ "ok": false, "reason": "bad-mac" })), 40);
        let (end, level, line) = drive(&stub, &frame(), 2);
        assert_eq!(end, AttachEnd::Refused("bad-mac".into()));
        assert_eq!(level, LineLevel::Warn);
        assert_eq!(
            line,
            format!("ATTACH_LINE outcome=refused late=false seat={ID} room=- sid=sidW reason=bad-mac ms=42")
        );
        refused_on_wire(&stub, "bad-mac");
    }

    #[test]
    fn a_malformed_token_is_refused_before_the_hub_with_no_seat() {
        let stub = Stub::new(ok_verdict(ID), 0);
        let (end, level, line) = drive(&stub, &json!({ "s": "zz" }), 1);
        assert_eq!(end, AttachEnd::Refused("malformed".into()));
        assert_eq!(level, LineLevel::Warn);
        assert_eq!(
            line,
            "ATTACH_LINE outcome=refused late=false seat=- room=- sid=sidW reason=malformed ms=1"
        );
        assert!(!stub.hub_asked.get());
        refused_on_wire(&stub, "malformed");
    }

    /// The plant Read A ran by hand: the identity-mismatch exit turned into
    /// `Answered` must turn this red (the end, the line and the wire).
    #[test]
    fn a_hub_verdict_for_another_identity_is_refused_unknown_session() {
        let stub = Stub::new(ok_verdict(OTHER), 30);
        let (end, level, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Refused("unknown-session".into()));
        assert_eq!(level, LineLevel::Warn);
        assert!(
            line.starts_with("ATTACH_LINE outcome=refused late=false ")
                && line.ends_with(" reason=unknown-session ms=30"),
            "{line}"
        );
        refused_on_wire(&stub, "unknown-session");
    }

    /// The full room: no room or socket capacity exists in the relay (an attach
    /// names no room; a grep of `src` finds no cap). The nearest exit is the
    /// one-attach-per-socket gate, planted here.
    #[test]
    fn a_spent_attach_or_an_authenticated_socket_is_refused_before_the_hub() {
        for reason in ["attach-exhausted", "already-authenticated"] {
            let mut stub = Stub::new(ok_verdict(ID), 0);
            stub.gate = Gate::Refuse(reason);
            let (end, level, line) = drive(&stub, &frame(), 4);
            assert_eq!(end, AttachEnd::Refused(reason.into()));
            assert_eq!(level, LineLevel::Warn);
            assert!(line.ends_with(&format!(" reason={reason} ms=4")), "{line}");
            assert!(!stub.hub_asked.get());
            refused_on_wire(&stub, reason);
        }
    }

    #[test]
    fn a_hub_unavailable_names_its_kind_on_the_line_and_only_hub_unavailable_on_the_wire() {
        for (fault, ms) in [
            (HubFault::Timeout, 1_200),
            (HubFault::Binding, 0),
            (HubFault::Fetch, 15),
            (HubFault::Status, 22),
            (HubFault::Decode, 9),
        ] {
            let stub = Stub::new(Err(fault), ms);
            let (end, level, line) = drive(&stub, &frame(), 3);
            assert_eq!(end, AttachEnd::Refused(fault.line_reason().into()));
            assert_eq!(level, LineLevel::Warn);
            assert!(
                line.starts_with("ATTACH_LINE outcome=refused late=false ")
                    && line.ends_with(&format!(" reason={} ms={}", fault.line_reason(), ms + 3)),
                "{line}"
            );
            refused_on_wire(&stub, "hub-unavailable");
        }
        // The timeout and a fault no longer read alike at warn.
        assert_ne!(
            HubFault::Timeout.line_reason(),
            HubFault::Fetch.line_reason()
        );
    }

    /// A slow authentication: the hub ask at its bound after a frame that
    /// waited at the relay, so the end lands past the client's 1,500 ms.
    #[test]
    fn a_slow_authentication_past_the_deadline_is_late_at_warn_whatever_the_outcome() {
        let stub = Stub::new(Err(HubFault::Timeout), 1_200);
        let (_, level, line) = drive(&stub, &frame(), 400);
        assert_eq!(level, LineLevel::Warn);
        assert!(
            line.starts_with("ATTACH_LINE outcome=refused late=true ")
                && line.ends_with(" reason=hub-unavailable.timeout ms=1600"),
            "{line}"
        );
        let stub = Stub::new(ok_verdict(ID), 1_100);
        let (end, level, line) = drive(&stub, &frame(), 450);
        assert_eq!(end, AttachEnd::Answered);
        assert_eq!(level, LineLevel::Warn);
        assert!(
            line.starts_with("ATTACH_LINE outcome=answered late=true ")
                && line.ends_with(" reason=ok ms=1550"),
            "{line}"
        );
    }

    #[test]
    fn a_timely_attach_is_answered_at_debug_and_a_slow_timely_one_at_info() {
        let stub = Stub::new(ok_verdict(ID), 35);
        let (end, level, line) = drive(&stub, &frame(), 5);
        assert_eq!(end, AttachEnd::Answered);
        assert_eq!(level, LineLevel::Debug);
        assert_eq!(
            line,
            format!(
                "ATTACH_LINE outcome=answered late=false seat={ID} room=- sid=sidW reason=ok ms=40"
            )
        );
        let sent = wire(&stub);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, crate::session_lane::ATTACHED_EVENT);
        let stub = Stub::new(ok_verdict(ID), 600);
        let (_, level, line) = drive(&stub, &frame(), 0);
        assert_eq!(level, LineLevel::Info, "{line}");
        assert!(line.ends_with(" reason=ok ms=600"));
    }

    #[test]
    fn the_late_exits_after_the_verdict_each_name_their_reason() {
        let mut stub = Stub::new(ok_verdict(ID), 10);
        stub.random = false;
        let (end, _, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Refused("no-randomness".into()));
        assert!(line.ends_with(" reason=no-randomness ms=10"), "{line}");
        refused_on_wire(&stub, "no-randomness");

        let mut stub = Stub::new(ok_verdict(ID), 10);
        stub.commit = Commit::Lost;
        let (end, _, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Refused("already-authenticated".into()));
        assert!(line.contains("outcome=refused "), "{line}");
        refused_on_wire(&stub, "already-authenticated");

        let mut stub = Stub::new(ok_verdict(ID), 10);
        stub.commit = Commit::NoSession;
        let (end, level, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Dropped("no-session"));
        assert_eq!(level, LineLevel::Warn);
        assert!(
            line.starts_with("ATTACH_LINE outcome=dropped ")
                && line.ends_with(" reason=no-session ms=10"),
            "{line}"
        );
        assert!(wire(&stub).is_empty(), "a drop sends nothing");

        let mut stub = Stub::new(ok_verdict(ID), 0);
        stub.gate = Gate::NoSession;
        let (end, _, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Dropped("no-session"));
        assert!(line.contains("outcome=dropped "), "{line}");
        assert!(wire(&stub).is_empty());
    }

    #[test]
    fn a_hub_key_that_is_not_hex_is_refused_mint_failed() {
        let stub = Stub::new(
            Ok(json!({ "ok": true, "identity": ID, "key": "not-hex" })),
            10,
        );
        let (end, _, line) = drive(&stub, &frame(), 0);
        assert_eq!(end, AttachEnd::Refused("mint-failed".into()));
        assert!(line.ends_with(" reason=mint-failed ms=10"), "{line}");
        refused_on_wire(&stub, "mint-failed");
    }
}
