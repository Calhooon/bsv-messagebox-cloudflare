//! message box #44: every exit of the attach reaches the line.
//!
//! The source half of the witness. It holds the rule, not the wording: every
//! exit of the exchange returns its end (`attach_exchange` has no bare return),
//! the DO writes that end through `run_attach` at its level, the frames the DO
//! cannot read and the Worker's attach and entry exits each write a line. It
//! reads the files at run time, so it also runs over a tree that predates the
//! fix (copy this file into it and run `cargo test --test attach_line_witness`;
//! there it fails). The behaviour half, the value at each exit per cause, is
//! `engineio::attach::attach_path_witness` (the exchange the DO runs, a stubbed
//! hub) and `socketio_worker::entry_line_witness` (the Worker's line).

fn src(path: &str) -> String {
    // The tree under test at RUN time (cargo sets it for the test binary), so
    // a binary built over another tree in a shared target never reads that tree.
    let root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let p = format!("{root}/src/{path}");
    std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}: the attach's seam is absent"))
}

/// The text of the fn starting at `head`, to the next line that closes it.
fn body<'a>(text: &'a str, head: &str, close: &str) -> &'a str {
    let a = text
        .find(head)
        .unwrap_or_else(|| panic!("`{head}` is absent"));
    let rest = &text[a..];
    &rest[..rest.find(close).unwrap_or(rest.len())]
}

#[test]
fn every_exit_of_the_exchange_returns_its_end() {
    let attach = src("engineio/attach.rs");
    let x = body(&attach, "pub(crate) async fn attach_exchange<", "\n}\n");
    assert!(
        x.contains(") -> AttachEnd {"),
        "the exchange returns its end"
    );
    assert!(!x.contains("return;"), "an exit returns without its end");
    let returns = x.matches("return ").count();
    let ended = x.matches("return refuse(").count() + x.matches("return AttachEnd::").count();
    assert!(returns >= 10, "the exits enumerated: {returns}");
    assert_eq!(returns, ended, "every return is a refusal or a named end");
    assert!(
        x.trim_end().ends_with("AttachEnd::Answered"),
        "the answered exit"
    );
    let run = body(&attach, "pub(crate) async fn run_attach<", "\n}\n");
    assert!(run.contains("attach_exchange(p, arg).await"));
    assert!(run.contains("attach_line(&end, seat.as_deref(), &p.sid(), elapsed)"));
}

#[test]
fn the_do_writes_the_end_at_its_level() {
    let session = src("engineio/session.rs");
    let d = body(&session, "async fn dispatch_session_attach(", "\n    }\n");
    assert!(d.contains("crate::engineio::attach::run_attach(&port, arg, started).await"));
    for arm in [
        "LineLevel::Warn => console_warn!(\"{line}\")",
        "LineLevel::Info => console_log!(\"{line}\")",
        "LineLevel::Debug => console_debug!(\"{line}\")",
    ] {
        assert!(d.contains(arm), "the level arm `{arm}`");
    }
}

#[test]
fn a_frame_the_do_cannot_read_leaves_the_line() {
    let session = src("engineio/session.rs");
    let ws = body(&session, "    async fn websocket_message(", "\n    }\n");
    for reason in [
        "undecoded.no-attachment",
        "undecoded.attachment-unreadable",
        "undecoded.binary",
        "undecoded.engineio",
    ] {
        assert!(
            ws.contains(&format!("self.undecoded_line(\"{reason}\"")),
            "`{reason}` leaves no line"
        );
    }
    let sio = body(&session, "    async fn dispatch_socketio(", "\n    }\n");
    for reason in ["undecoded.socketio", "undecoded.event-name"] {
        assert!(sio.contains(&format!("self.undecoded_line(\"{reason}\"")));
    }
}

#[test]
fn the_worker_s_attach_and_entry_exits_leave_their_line() {
    let worker = src("socketio_worker.rs");
    let ev = body(&worker, "async fn handle_socketio_event(", "\n}\n");
    let unauth = ev
        .find("if is_attach && !auth.is_authenticated() {")
        .expect("an attach over polling, unauthenticated");
    assert!(
        ev[unauth..].contains("attach_end_line(AttachEnd::Dropped(\"polling-unauthenticated\"));")
    );
    let fwd = ev
        .find("forward_and_enqueue(")
        .expect("the authenticated forward");
    let after = ev
        .find("attach_end_line(polling_attach_end(&enqueued));")
        .expect("the forwarded attach's line");
    assert!(
        fwd < after,
        "the line follows the forward, so `ms` covers it"
    );
    let post = body(&worker, "pub async fn handle_polling_post(", "\n}\n");
    for reason in ["kv-binding", "session-closed", "undecoded.polling-batch"] {
        assert!(
            post.contains(&format!("\"{reason}\")")),
            "`{reason}` leaves no line"
        );
    }
    let fwd = body(&worker, "pub async fn forward_to_session(", "\n}\n");
    assert!(fwd.contains("\"do-binding\""));
    assert!(fwd.contains("watch_entry("));
    let lib = src("lib.rs");
    let route = body(&lib, "async fn route_socketio_request(", "\n}\n");
    assert!(route.contains("socketio_worker::forward_to_session("));
    assert!(route.contains("socketio_worker::entry_binding_fault("));
}
