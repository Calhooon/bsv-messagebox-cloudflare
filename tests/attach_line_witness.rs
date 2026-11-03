//! message box #44: a socket attach that is refused, dropped or late leaves one
//! relay-side line; one answered in time writes nothing above debug.
//!
//! This is the source half of the witness: it reads the relay's text only, so it
//! also runs over a tree that predates the fix (copy this file into it and run
//! `cargo test --test attach_line_witness`). The behaviour half, the line itself
//! per plant, is `session_lane::attach_line_tests`.

const SESSION: &str = include_str!("../src/engineio/session.rs");
const WORKER: &str = include_str!("../src/socketio_worker.rs");

/// The attach's handler text, from its entry to the next handler.
fn attach_handler() -> &'static str {
    let a = SESSION
        .find("async fn dispatch_session_attach(")
        .expect("the attach's handler");
    let rest = &SESSION[a..];
    let b = rest
        .find("/// bsv-low W-B (D10): a `sessionMessage` from the client.")
        .expect("the handler after it");
    &rest[..b]
}

#[test]
fn a_refused_attach_writes_one_warn_line_with_its_reason_and_elapsed() {
    let h = attach_handler();
    assert!(
        h.contains("console_warn!(\"{line}\")"),
        "a refused attach writes no warn-level line"
    );
    assert!(
        h.contains("crate::session_lane::attach_line(&end, seat.as_deref(), &sid, elapsed)"),
        "the attach's end is not written through the one line (seat, sid, reason, elapsed)"
    );
    assert!(
        !h.contains("console_log!(\"TRACE_SESSION attach refused"),
        "a refusal still writes its own info line beside the one line"
    );
}

#[test]
fn every_exit_of_the_attach_ends_in_an_attach_end() {
    let h = attach_handler();
    let x = h
        .find("async fn attach_exchange(")
        .expect("the attach's exits are not typed: a bare return leaves no line");
    let body = &h[x..];
    assert!(
        body.contains(") -> AttachEnd {"),
        "the exchange returns its end"
    );
    assert!(
        !body.contains("return;"),
        "an exit of the attach returns without its end"
    );
}

#[test]
fn an_attach_answered_in_time_writes_nothing_above_debug() {
    let h = attach_handler();
    let ok = h
        .find("\"TRACE_SESSION attached identity=")
        .expect("the attached trace");
    let before = &h[..ok];
    let mac = before.rfind('!').expect("the macro");
    let open = before[..mac].rfind(char::is_whitespace).unwrap() + 1;
    assert_eq!(
        &before[open..mac],
        "console_debug",
        "a timely attach writes above debug"
    );
}

#[test]
fn an_attach_that_rides_polling_is_dropped_with_its_line() {
    let a = WORKER
        .find("async fn handle_socketio_event(")
        .expect("the Worker's event handler");
    let h = &WORKER[a..WORKER[a..].find("\nasync fn auth_round_in_do(").unwrap() + a];
    let attach = h
        .find("event_name == crate::session_lane::ATTACH_EVENT")
        .expect("an attach over polling is dropped with no line");
    let gate = h
        .find("if !auth.is_authenticated() {")
        .expect("the Worker's auth gate");
    assert!(attach < gate, "the line is written before the drop");
    assert!(h[attach..gate].contains("console_warn!(\"{line}\")"));
}
