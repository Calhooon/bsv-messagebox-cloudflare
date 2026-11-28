//! The relay's bounds on every request body it reads.
//!
//! Three doors read a body before the caller is known: the BRC-31 layer
//! (bsv-middleware-cloudflare's `process_auth_do_with_body_bounds`, which
//! signs over the body, so it reads it first), the relay's own HTTP session
//! lane (`session_lane_auth` in `lib.rs`, which hashes the body for the hub's
//! MAC check) and the Socket.IO polling POST (`route_socketio_request` in
//! `lib.rs`, the Engine.IO packets of a session). The BRC-31 layer and the
//! session lane read at most the relay's figure for one send,
//! [`validation::SEND_BODY_BYTES`], and answer a larger body with the relay's
//! own 413 `ERR_BODY_TOO_LARGE` ([`validation::body_too_large`]). The polling
//! POST reads at most [`POLLING_POST_BODY_BYTES`], the `maxPayload` the relay
//! names to the client in its Engine.IO handshake, and answers in the
//! transport's own plain text.
//!
//! The three bearer-gated routes (`/push`, `/session/attest`, `/broadcast`)
//! check the bearer first and then read the body within a figure fit for the
//! route's own message ([`PUSH_BODY_BYTES`], [`ATTEST_BODY_BYTES`],
//! [`BROADCAST_BODY_BYTES`]), answering a larger one 413
//! `ERR_BODY_TOO_LARGE` in the relay's error shape
//! ([`validation::request_body_too_large`]).
//!
//! The figures are this host's. One constant, `SEND_BODY_BYTES`, sets the
//! bound on one send at the BRC-31 door, the session lane, `/push` and the
//! relay's own check after the read (`validation::read_send_body`), so they
//! cannot disagree.
//!
//! The totals. A Worker's isolate is memory-limited and serves several
//! requests at once, so each door also keeps a count of the body bytes it is
//! holding while it reads them, and answers a chunk that would pass its total
//! 503 `ERR_AUTH_BODIES_FULL` with `Retry-After`. Once a door hands a body to
//! the route, the relay holds up to three copies of a send's size while it
//! reads it (the body, the text it parses and a payment's hex beside it:
//! `validation::SEND_BODY_BYTES`'s own estimate), 3 x 12 MiB = 36 MiB for one
//! send at the bound. Beside that one send:
//!
//! - the BRC-31 layer's total, [`AUTH_HELD_BODY_BYTES`] = 2 x 12 MiB = 24 MiB
//!   (two sends at the bound being read at once);
//! - the relay's own total before a caller is known,
//!   [`PRE_AUTH_HELD_BODY_BYTES`] = 12 MiB, ONE count ([`PRE_AUTH_BODIES`])
//!   shared by the session lane and the polling POST (one send at the bound,
//!   or twelve polling POSTs at theirs, being read at once);
//! - the bearer-gated routes' total, [`BEARER_HELD_BODY_BYTES`] = 12 MiB (one
//!   `/push` at the bound being read at once), its own count
//!   ([`BEARER_BODIES`]) so no unauthenticated body takes a first-party
//!   producer's room.
//!
//! 36 + 24 + 12 + 12 = 84 MiB of request bodies at most, of a Workers
//! isolate's 128 MiB; the rest is the Worker's own state and the reading's.
//!
//! The deadline: a body's whole read has the layer's default,
//! `DEFAULT_BODY_DEADLINE` (30 seconds), at every door, and is answered 408
//! `ERR_AUTH_BODY_TIMEOUT` past it. No timeout of the relay's own runs during
//! a body's read (its hub ask, `hub_forward::FORWARD_OP_TIMEOUT_MS`, starts
//! after the body is read), so none is shorter.

use std::future::Future;

use bsv_middleware_cloudflare::core::body_bound::{declared_length, BodyLedger, BoundedBody};
use bsv_middleware_cloudflare::{
    BodyBounds, BodyRefusal, DEFAULT_BODY_DEADLINE, ERR_AUTH_BODY_TOO_LARGE,
};
use futures_util::future::{select, Either};
use futures_util::pin_mut;
use futures_util::stream::{Stream, StreamExt};
use serde_json::Value;

use crate::validation::{self, SEND_BODY_BYTES};

/// The most bytes of one request's body the BRC-31 layer reads:
/// `SEND_BODY_BYTES` (12 MiB), the relay's figure for one send.
pub const AUTH_BODY_BYTES: u64 = SEND_BODY_BYTES as u64;

/// The most request-body bytes the BRC-31 layer holds at once in one isolate:
/// two sends at the bound, 2 x 12 MiB = 24 MiB (the arithmetic is in the
/// module's text).
pub const AUTH_HELD_BODY_BYTES: u64 = 2 * AUTH_BODY_BYTES;

/// The most bytes of one request's body the HTTP session lane reads. The lane
/// carries the same routes as BRC-31 (`/listMessages`, `/acknowledgeMessage`
/// and the `/sendMessage` fallback), so its figure is the send's:
/// `SEND_BODY_BYTES` (12 MiB).
pub const SESSION_LANE_BODY_BYTES: u64 = SEND_BODY_BYTES as u64;

/// The most bytes of one Socket.IO polling POST's body the relay reads:
/// 1,000,000, the `maxPayload` the relay's Engine.IO handshake names to the
/// client (`engineio::session::MAX_PAYLOAD`). A polling POST carries a batch
/// of Engine.IO packets (`authMessage` rounds, Socket.IO events, pings and
/// closes), and a Socket.IO client keeps a batch within the `maxPayload` it
/// was told. It is under `SEND_BODY_BYTES`.
pub const POLLING_POST_BODY_BYTES: u64 = crate::engineio::session::MAX_PAYLOAD;

/// The most request-body bytes the relay itself holds at once in one isolate
/// before a caller is known: one send at the bound, 12 MiB, ONE total for the
/// session lane and the polling POST, counted in [`PRE_AUTH_BODIES`]. The
/// BRC-31 layer's count is the adapter's own and is not one of its public
/// items, so it keeps its own total ([`AUTH_HELD_BODY_BYTES`]).
pub const PRE_AUTH_HELD_BODY_BYTES: u64 = SESSION_LANE_BODY_BYTES;

/// The count of the body bytes the session lane and the polling POST hold at
/// this moment, one per isolate.
pub static PRE_AUTH_BODIES: BodyLedger = BodyLedger::new();

/// The most bytes of a `POST /push` body the relay reads: `SEND_BODY_BYTES`
/// (12 MiB). The body is a `/sendMessage` body (flat or wrapped in
/// `message`) and the producer's `sender`, so its figure is the send's.
pub const PUSH_BODY_BYTES: u64 = SEND_BODY_BYTES as u64;

/// The most bytes of a `POST /session/attest` body the relay reads: 16 KiB.
/// The body is the hub's verify body (`session_attest_body_ok`): `id` (64
/// hex), `identity` (66 hex), `h` (a u64), `method` (at most 8),
/// `path` (at most 2,048), `bodySha256` and `mac` (at most 64 each), under
/// 2.5 KB as plain JSON and under 13 KB with every `path` character written
/// as a six-byte JSON escape.
pub const ATTEST_BODY_BYTES: u64 = 16 * 1024;

/// The most bytes of a `POST /broadcast` body the relay reads: 256 KiB. The
/// body is `{box, body}`; the event `body` is written into one hub push per
/// subscriber with up to `BROADCAST_FANOUT_CONCURRENCY` (32) pushes in flight,
/// so its figure is kept to a carrier event's: 32 x 256 KiB = 8 MiB of
/// pushes in flight at the bound.
pub const BROADCAST_BODY_BYTES: u64 = 256 * 1024;

/// The most request-body bytes the bearer-gated routes hold at once in one
/// isolate: one `/push` at the bound, 12 MiB, counted in [`BEARER_BODIES`].
pub const BEARER_HELD_BODY_BYTES: u64 = PUSH_BODY_BYTES;

/// The count of the body bytes the bearer-gated routes hold at this moment,
/// one per isolate.
pub static BEARER_BODIES: BodyLedger = BodyLedger::new();

const _: () = assert!(POLLING_POST_BODY_BYTES <= SEND_BODY_BYTES as u64);
const _: () = assert!(PRE_AUTH_HELD_BODY_BYTES >= SESSION_LANE_BODY_BYTES);
const _: () = assert!(PRE_AUTH_HELD_BODY_BYTES >= POLLING_POST_BODY_BYTES);
const _: () = assert!(BEARER_HELD_BODY_BYTES >= PUSH_BODY_BYTES);
const _: () = assert!(BEARER_HELD_BODY_BYTES >= ATTEST_BODY_BYTES);
const _: () = assert!(BEARER_HELD_BODY_BYTES >= BROADCAST_BODY_BYTES);
// Every total and one send's three copies together, under a 128 MiB isolate.
const _: () = assert!(
    AUTH_HELD_BODY_BYTES
        + PRE_AUTH_HELD_BODY_BYTES
        + BEARER_HELD_BODY_BYTES
        + 3 * SEND_BODY_BYTES as u64
        <= 84 * 1024 * 1024
);

/// The figures every call of the BRC-31 layer names: [`AUTH_BODY_BYTES`],
/// [`AUTH_HELD_BODY_BYTES`] and the default deadline.
pub const fn auth_body_bounds() -> BodyBounds {
    BodyBounds::new(AUTH_BODY_BYTES, AUTH_HELD_BODY_BYTES)
}

/// The relay's answer for a refusal the BRC-31 layer came back with, where it
/// has one: the layer's 413 `ERR_AUTH_BODY_TOO_LARGE` is answered as the
/// relay's own 413 `ERR_BODY_TOO_LARGE` ([`validation::body_too_large`], with
/// the declared length where the layer names one). `None` for anything else:
/// the layer's answer goes to the sender unchanged (its 503
/// `ERR_AUTH_BODIES_FULL` with `Retry-After`, its 408 `ERR_AUTH_BODY_TIMEOUT`,
/// its 401).
pub fn layer_refusal_answer(status: u16, body: &Value) -> Option<(Value, u16)> {
    if status != 413 || body.get("code").and_then(Value::as_str) != Some(ERR_AUTH_BODY_TOO_LARGE) {
        return None;
    }
    Some(validation::body_too_large(
        body.get("size").and_then(Value::as_u64),
    ))
}

/// The session lane's answer to a body it did not read (or stopped reading):
/// the body, the status and the `Retry-After` seconds. Over the bound, the
/// relay's own 413 `ERR_BODY_TOO_LARGE`, as the BRC-31 door answers it; past
/// the total or the deadline, the same 503 `ERR_AUTH_BODIES_FULL` (with
/// `Retry-After`) and 408 `ERR_AUTH_BODY_TIMEOUT` the BRC-31 layer answers.
pub fn lane_refusal_answer(refusal: &BodyRefusal) -> (Value, u16, Option<u64>) {
    match refusal {
        BodyRefusal::TooLarge { size, .. } => {
            let (body, status) = validation::body_too_large(*size);
            (body, status, None)
        }
        other => (other.to_json(), other.status(), other.retry_after_seconds()),
    }
}

/// The session lane's read of a request's body, under its figures
/// ([`SESSION_LANE_BODY_BYTES`], [`PRE_AUTH_HELD_BODY_BYTES`] and the
/// default deadline, counted in [`PRE_AUTH_BODIES`]).
pub async fn read_session_lane_body<S, E, F, D, C>(
    content_length: Option<&str>,
    open: F,
    deadline: D,
    now_ms: C,
) -> Result<Result<Vec<u8>, BodyRefusal>, String>
where
    F: FnOnce() -> Result<Option<S>, String>,
    S: Stream<Item = Result<Vec<u8>, E>>,
    E: std::fmt::Display,
    D: Future<Output = ()>,
    C: Fn() -> u64,
{
    read_bounded_body(
        &PRE_AUTH_BODIES,
        content_length,
        SESSION_LANE_BODY_BYTES,
        PRE_AUTH_HELD_BODY_BYTES,
        default_deadline_ms(),
        open,
        deadline,
        now_ms,
    )
    .await
}

/// The polling POST's read of a request's body, under its figures
/// ([`POLLING_POST_BODY_BYTES`], [`PRE_AUTH_HELD_BODY_BYTES`] and the
/// default deadline, counted in [`PRE_AUTH_BODIES`] with the session lane's).
pub async fn read_polling_post_body<S, E, F, D, C>(
    content_length: Option<&str>,
    open: F,
    deadline: D,
    now_ms: C,
) -> Result<Result<Vec<u8>, BodyRefusal>, String>
where
    F: FnOnce() -> Result<Option<S>, String>,
    S: Stream<Item = Result<Vec<u8>, E>>,
    E: std::fmt::Display,
    D: Future<Output = ()>,
    C: Fn() -> u64,
{
    read_bounded_body(
        &PRE_AUTH_BODIES,
        content_length,
        POLLING_POST_BODY_BYTES,
        PRE_AUTH_HELD_BODY_BYTES,
        default_deadline_ms(),
        open,
        deadline,
        now_ms,
    )
    .await
}

/// A bearer-gated route's read of its body, after the bearer is checked:
/// at most `budget` bytes (the route's figure), counted in [`BEARER_BODIES`]
/// under [`BEARER_HELD_BODY_BYTES`], within the default deadline.
pub async fn read_bearer_route_body<S, E, F, D, C>(
    content_length: Option<&str>,
    budget: u64,
    open: F,
    deadline: D,
    now_ms: C,
) -> Result<Result<Vec<u8>, BodyRefusal>, String>
where
    F: FnOnce() -> Result<Option<S>, String>,
    S: Stream<Item = Result<Vec<u8>, E>>,
    E: std::fmt::Display,
    D: Future<Output = ()>,
    C: Fn() -> u64,
{
    read_bounded_body(
        &BEARER_BODIES,
        content_length,
        budget,
        BEARER_HELD_BODY_BYTES,
        default_deadline_ms(),
        open,
        deadline,
        now_ms,
    )
    .await
}

fn default_deadline_ms() -> u64 {
    u64::try_from(DEFAULT_BODY_DEADLINE.as_millis()).unwrap_or(u64::MAX)
}

/// The polling POST's answer to a body it did not read (or stopped reading),
/// in the transport's own family (plain text, as its 400 for a batch it
/// cannot decode): the text, the status and the `Retry-After` seconds. 413
/// over [`POLLING_POST_BODY_BYTES`], 503 with `Retry-After` past the total,
/// 408 past the deadline.
pub fn polling_refusal_answer(refusal: &BodyRefusal) -> (String, u16, Option<u64>) {
    (
        refusal.to_string(),
        refusal.status(),
        refusal.retry_after_seconds(),
    )
}

/// A bearer-gated route's answer to a body it did not read (or stopped
/// reading): over the route's figure, 413 `ERR_BODY_TOO_LARGE` in the
/// relay's error shape naming the route and its figure; past the total or
/// the deadline, the same 503 `ERR_AUTH_BODIES_FULL` (with `Retry-After`)
/// and 408 `ERR_AUTH_BODY_TIMEOUT` the session lane answers.
pub fn bearer_refusal_answer(route: &str, refusal: &BodyRefusal) -> (Value, u16, Option<u64>) {
    match refusal {
        BodyRefusal::TooLarge { size, budget } => {
            let (body, status) = validation::request_body_too_large(route, *size, *budget);
            (body, status, None)
        }
        other => (other.to_json(), other.status(), other.retry_after_seconds()),
    }
}

/// A request's body read under a bound, a total and a deadline, in the
/// shape of the BRC-31 layer's reader, through the middleware core's public
/// `BoundedBody`: a declared `Content-Length` over `budget` is refused and
/// `open` is never called; then the body is read as it arrives, each chunk
/// charged to `ledger` under `total` before it is kept, at most `budget` + 1
/// bytes kept, and no chunk pulled after a refusal; the whole read races
/// `deadline`. `open` answers `None` for a request with no body. A stream
/// error is `Err`. Every refusal and error gives the body's charge back; a
/// body read in full is handed over and its charge given back.
#[allow(clippy::too_many_arguments)]
pub async fn read_bounded_body<S, E, F, D, C>(
    ledger: &BodyLedger,
    content_length: Option<&str>,
    budget: u64,
    total: u64,
    deadline_ms: u64,
    open: F,
    deadline: D,
    now_ms: C,
) -> Result<Result<Vec<u8>, BodyRefusal>, String>
where
    F: FnOnce() -> Result<Option<S>, String>,
    S: Stream<Item = Result<Vec<u8>, E>>,
    E: std::fmt::Display,
    D: Future<Output = ()>,
    C: Fn() -> u64,
{
    let mut body = match BoundedBody::admit(ledger, declared_length(content_length), budget, total)
    {
        Ok(body) => body,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(stream) = open()? else {
        return Ok(Ok(body.into_vec()));
    };
    let started = now_ms();
    let ended = {
        let reading = async {
            pin_mut!(stream);
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| e.to_string())?;
                if let Err(refusal) = body.push(&chunk) {
                    return Ok(Some(refusal));
                }
            }
            Ok::<_, String>(None)
        };
        pin_mut!(reading);
        pin_mut!(deadline);
        match select(reading, deadline).await {
            Either::Left((ended, _)) => Some(ended),
            Either::Right(((), _)) => None,
        }
    };
    match ended {
        Some(Ok(None)) => Ok(Ok(body.into_vec())),
        Some(Ok(Some(refusal))) => Ok(Err(refusal)),
        Some(Err(fault)) => Err(fault),
        None => Ok(Err(BodyRefusal::TimedOut {
            held: body.len() as u64,
            waited_ms: now_ms().saturating_sub(started),
            deadline_ms,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use serde_json::json;
    use std::cell::Cell;

    type Chunk = Result<Vec<u8>, String>;

    fn chunks(body: &[u8], size: usize) -> Vec<Chunk> {
        body.chunks(size).map(|c| Ok(c.to_vec())).collect()
    }

    /// The reader at small figures (a bound of 64, a total of 1,024), its
    /// deadline never firing.
    async fn read(
        ledger: &BodyLedger,
        declared: Option<&str>,
        body: Vec<Chunk>,
    ) -> Result<Vec<u8>, BodyRefusal> {
        read_bounded_body(
            ledger,
            declared,
            64,
            1_024,
            250,
            || Ok(Some(stream::iter(body))),
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .expect("no stream error")
    }

    #[test]
    fn the_layers_figure_is_the_relays_send_bound() {
        assert_eq!(AUTH_BODY_BYTES, SEND_BODY_BYTES as u64);
        assert_eq!(AUTH_BODY_BYTES, 12 * 1024 * 1024);
        let bounds = auth_body_bounds();
        assert_eq!(bounds.max_request_body_bytes, SEND_BODY_BYTES as u64);
        assert_eq!(bounds.max_held_body_bytes, AUTH_HELD_BODY_BYTES);
        assert_eq!(AUTH_HELD_BODY_BYTES, 24 * 1024 * 1024);
        assert!(bounds.max_held_body_bytes >= bounds.max_request_body_bytes);
        assert_eq!(bounds.body_deadline, DEFAULT_BODY_DEADLINE);
    }

    #[test]
    fn the_lanes_figure_is_the_relays_send_bound() {
        assert_eq!(SESSION_LANE_BODY_BYTES, SEND_BODY_BYTES as u64);
        assert_eq!(PRE_AUTH_HELD_BODY_BYTES, 12 * 1024 * 1024);
    }

    /// The layer's 413 for a declared length over the bound is answered with
    /// the bytes the relay's own check answers for a body of that length.
    #[test]
    fn an_over_size_send_is_answered_byte_for_byte_as_the_relays_own_413() {
        let size = SEND_BODY_BYTES + 1;
        let layer = BodyRefusal::TooLarge {
            size: Some(size as u64),
            budget: AUTH_BODY_BYTES,
        };
        let (mapped, status) =
            layer_refusal_answer(layer.status(), &layer.to_json()).expect("mapped");
        let (own, own_status) =
            validation::read_send_body(&vec![b' '; size]).expect_err("over the bound");
        assert_eq!(status, own_status);
        assert_eq!(status, 413);
        assert_eq!(
            serde_json::to_vec(&mapped).unwrap(),
            serde_json::to_vec(&own).unwrap(),
            "byte-equal to the relay's own answer"
        );
        assert_eq!(mapped["code"], "ERR_BODY_TOO_LARGE");
    }

    /// Where the read stopped at the bound the length is not known: the same
    /// status, code and fields, the description saying "more than".
    #[test]
    fn a_read_stopped_at_the_bound_is_the_relays_413_more_than_the_bound() {
        let layer = BodyRefusal::TooLarge {
            size: None,
            budget: AUTH_BODY_BYTES,
        };
        let (mapped, status) =
            layer_refusal_answer(layer.status(), &layer.to_json()).expect("mapped");
        assert_eq!(status, 413);
        assert_eq!(
            mapped,
            json!({
                "status": "error",
                "code": "ERR_BODY_TOO_LARGE",
                "description": "The send is more than 12582912 bytes and the relay reads at most 12582912 in one request.",
            })
        );
    }

    #[test]
    fn the_layers_503_408_and_401_pass_through() {
        for refusal in [
            BodyRefusal::BodiesFull {
                held: 1,
                total: AUTH_HELD_BODY_BYTES,
            },
            BodyRefusal::TimedOut {
                held: 1,
                waited_ms: 30_000,
                deadline_ms: 30_000,
            },
        ] {
            assert_eq!(
                layer_refusal_answer(refusal.status(), &refusal.to_json()),
                None
            );
        }
        let unauthorized = json!({"status": "error", "code": "UNAUTHORIZED", "message": "Mutual-authentication failed!"});
        assert_eq!(layer_refusal_answer(401, &unauthorized), None);
        assert_eq!(
            layer_refusal_answer(413, &json!({"code": "SOMETHING_ELSE"})),
            None
        );
    }

    #[test]
    fn the_lanes_answers_are_the_relays_413_and_the_layers_503_and_408() {
        let (body, status, retry) = lane_refusal_answer(&BodyRefusal::TooLarge {
            size: Some(SESSION_LANE_BODY_BYTES + 1),
            budget: SESSION_LANE_BODY_BYTES,
        });
        assert_eq!((body, status, retry), {
            let (b, s) = validation::body_too_large(Some(SESSION_LANE_BODY_BYTES + 1));
            (b, s, None)
        });
        let full = BodyRefusal::BodiesFull {
            held: 5,
            total: PRE_AUTH_HELD_BODY_BYTES,
        };
        assert_eq!(lane_refusal_answer(&full), (full.to_json(), 503, Some(2)));
        assert_eq!(full.to_json()["code"], "ERR_AUTH_BODIES_FULL");
        let late = BodyRefusal::TimedOut {
            held: 5,
            waited_ms: 30_000,
            deadline_ms: 30_000,
        };
        assert_eq!(lane_refusal_answer(&late), (late.to_json(), 408, None));
        assert_eq!(late.to_json()["code"], "ERR_AUTH_BODY_TIMEOUT");
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_figure_is_read_in_chunks_of_every_size() {
        let ledger = BodyLedger::new();
        let body: Vec<u8> = (0..64u8).collect();
        for size in [1, 7, 63, 64] {
            let got = read(&ledger, Some("64"), chunks(&body, size)).await;
            assert_eq!(got, Ok(body.clone()), "chunks of {size}");
            assert_eq!(ledger.held(), 0, "handed over, nothing held");
        }
        assert_eq!(read(&ledger, None, chunks(&body, 5)).await, Ok(body));
    }

    #[tokio::test]
    async fn one_byte_over_the_figure_is_refused_and_no_chunk_pulled_after() {
        let ledger = BodyLedger::new();
        let pulled = Cell::new(0usize);
        let body = [1u8; 65];
        let source = stream::iter(body.chunks(1).map(|c| c.to_vec()).collect::<Vec<_>>())
            .chain(stream::iter(vec![vec![2u8; 10]; 3]))
            .inspect(|_| pulled.set(pulled.get() + 1))
            .map(Ok::<_, String>);
        let got = read_bounded_body(
            &ledger,
            None,
            64,
            1_024,
            250,
            || Ok(Some(source)),
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Err(BodyRefusal::TooLarge {
                size: None,
                budget: 64
            })
        );
        assert_eq!(pulled.get(), 65, "the figure plus one byte, then no more");
        assert_eq!(ledger.held(), 0);
    }

    #[tokio::test]
    async fn a_declared_length_over_the_figure_is_refused_with_the_body_never_opened() {
        let ledger = BodyLedger::new();
        let got = read_bounded_body(
            &ledger,
            Some("65"),
            64,
            1_024,
            250,
            || -> Result<Option<stream::Iter<std::vec::IntoIter<Chunk>>>, String> {
                panic!("the body is never opened")
            },
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Err(BodyRefusal::TooLarge {
                size: Some(65),
                budget: 64
            })
        );
        let (answer, status, _) = lane_refusal_answer(&got.unwrap_err());
        assert_eq!(status, 413);
        assert_eq!(answer["code"], "ERR_BODY_TOO_LARGE");
        assert_eq!(ledger.held(), 0);
    }

    #[tokio::test]
    async fn a_chunk_past_the_total_is_refused_and_its_charge_given_back() {
        let ledger = BodyLedger::new();
        // Another body holds 1,000 of the 1,024.
        let mut other = BoundedBody::admit(&ledger, None, 2_048, 1_024).unwrap();
        other.push(&[0u8; 1_000]).unwrap();
        let got = read(&ledger, None, chunks(&[3u8; 40], 10)).await;
        assert!(
            matches!(got, Err(BodyRefusal::BodiesFull { total: 1_024, .. })),
            "{got:?}"
        );
        assert_eq!(ledger.held(), 1_000, "only the other body's bytes");
        drop(other);
        assert_eq!(ledger.held(), 0);
        assert_eq!(
            read(&ledger, None, chunks(&[3u8; 40], 10)).await,
            Ok(vec![3u8; 40]),
            "read once the other ends"
        );
    }

    #[tokio::test]
    async fn a_body_that_stops_arriving_is_ended_at_the_deadline() {
        let ledger = BodyLedger::new();
        let source = stream::iter(vec![Ok::<_, String>(vec![1u8; 8])]).chain(stream::pending());
        let got = read_bounded_body(
            &ledger,
            None,
            64,
            1_024,
            250,
            || Ok(Some(source)),
            async {
                tokio::task::yield_now().await;
            },
            || 0,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                got,
                Err(BodyRefusal::TimedOut {
                    held: 8,
                    deadline_ms: 250,
                    ..
                })
            ),
            "{got:?}"
        );
        assert_eq!(ledger.held(), 0);
    }

    #[tokio::test]
    async fn a_stream_error_is_an_error_and_gives_its_charge_back() {
        let ledger = BodyLedger::new();
        let got = read_bounded_body(
            &ledger,
            None,
            64,
            1_024,
            250,
            || {
                Ok(Some(stream::iter(vec![
                    Ok(vec![1u8; 8]),
                    Err("gone".to_string()),
                ])))
            },
            std::future::pending::<()>(),
            || 0,
        )
        .await;
        assert_eq!(got, Err("gone".to_string()));
        assert_eq!(ledger.held(), 0);
    }

    #[tokio::test]
    async fn the_lanes_reader_at_and_over_its_figure_by_declared_length() {
        let at = SESSION_LANE_BODY_BYTES.to_string();
        let got = read_session_lane_body(
            Some(&at),
            || Ok(Some(stream::iter(vec![Ok::<_, String>(b"{}".to_vec())]))),
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Ok(b"{}".to_vec()),
            "a declared length at the figure is read"
        );
        let over = (SESSION_LANE_BODY_BYTES + 1).to_string();
        let got = read_session_lane_body(
            Some(&over),
            || -> Result<Option<stream::Iter<std::vec::IntoIter<Chunk>>>, String> {
                panic!("the body is never opened")
            },
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Err(BodyRefusal::TooLarge {
                size: Some(SESSION_LANE_BODY_BYTES + 1),
                budget: SESSION_LANE_BODY_BYTES
            })
        );
        assert_eq!(PRE_AUTH_BODIES.held(), 0);
    }

    type NoBody = stream::Iter<std::vec::IntoIter<Chunk>>;

    /// A body of `len` bytes read in 64 KiB chunks under `budget`, on a ledger
    /// of its own (a total of twice the budget), the deadline never firing.
    async fn read_len(budget: u64, len: usize) -> Result<Vec<u8>, BodyRefusal> {
        let ledger = BodyLedger::new();
        let got = read_bounded_body(
            &ledger,
            None,
            budget,
            2 * budget,
            250,
            || Ok(Some(stream::iter(chunks(&vec![b'4'; len], 64 * 1024)))),
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .expect("no stream error");
        assert_eq!(ledger.held(), 0, "every charge given back");
        got
    }

    #[test]
    fn the_polling_posts_figure_is_the_handshakes_max_payload() {
        assert_eq!(POLLING_POST_BODY_BYTES, 1_000_000);
        assert_eq!(
            POLLING_POST_BODY_BYTES,
            crate::engineio::session::MAX_PAYLOAD
        );
        let open = crate::engineio::open_handshake_packet("sid").encode();
        let named: Value = serde_json::from_str(&open[1..]).expect("the open packet's JSON");
        assert_eq!(named["maxPayload"], POLLING_POST_BODY_BYTES);
        assert_eq!(PRE_AUTH_HELD_BODY_BYTES, SEND_BODY_BYTES as u64);
    }

    #[test]
    fn the_bearer_routes_figures() {
        assert_eq!(PUSH_BODY_BYTES, SEND_BODY_BYTES as u64);
        assert_eq!(ATTEST_BODY_BYTES, 16_384);
        assert_eq!(BROADCAST_BODY_BYTES, 262_144);
        assert_eq!(BEARER_HELD_BODY_BYTES, 12 * 1024 * 1024);
    }

    /// The largest attest body `session_attest_body_ok` accepts, every `path`
    /// character written as a six-byte escape, is within the attest figure.
    #[test]
    fn the_largest_valid_attest_body_is_within_its_figure() {
        let body = json!({
            "id": "ab".repeat(32),
            "identity": format!("02{}", "cd".repeat(32)),
            "h": u64::MAX,
            "method": "OPTIONSX",
            "path": "\u{1}".repeat(2_048),
            "bodySha256": "ef".repeat(32),
            "mac": "01".repeat(32),
        });
        assert!(crate::session_attest_body_ok(&body));
        let bytes = serde_json::to_vec(&body).unwrap();
        assert!(bytes.len() > 2_048 * 6, "every path character escaped");
        assert!(bytes.len() as u64 <= ATTEST_BODY_BYTES, "{}", bytes.len());
    }

    /// The session lane and the polling POST count in the one total.
    #[test]
    fn the_lane_and_the_polling_post_share_one_total() {
        let src: String = include_str!("body_bounds.rs")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        for reader in ["fnread_session_lane_body<", "fnread_polling_post_body<"] {
            let start = src.find(reader).expect(reader);
            let end = src[start..]
                .find("pubasyncfn")
                .map_or(src.len(), |e| e + start);
            let body = &src[start..end];
            assert!(body.contains("&PRE_AUTH_BODIES,"), "{reader}");
            assert!(body.contains("PRE_AUTH_HELD_BODY_BYTES,"), "{reader}");
        }
        let start = src.find("fnread_bearer_route_body<").unwrap();
        assert!(src[start..].contains("&BEARER_BODIES,"));
    }

    #[tokio::test]
    async fn a_polling_post_at_its_figure_is_read_and_one_byte_over_is_refused() {
        let at = POLLING_POST_BODY_BYTES as usize;
        assert_eq!(
            read_len(POLLING_POST_BODY_BYTES, at).await.map(|b| b.len()),
            Ok(at)
        );
        assert_eq!(
            read_len(POLLING_POST_BODY_BYTES, at + 1).await,
            Err(BodyRefusal::TooLarge {
                size: None,
                budget: POLLING_POST_BODY_BYTES
            })
        );
    }

    #[tokio::test]
    async fn a_polling_post_declared_over_its_figure_is_refused_unread() {
        let at = POLLING_POST_BODY_BYTES.to_string();
        let got = read_polling_post_body(
            Some(&at),
            || -> Result<Option<NoBody>, String> { Ok(None) },
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Ok(Vec::new()),
            "a declared length at the figure is read"
        );
        let over = (POLLING_POST_BODY_BYTES + 1).to_string();
        let got = read_polling_post_body(
            Some(&over),
            || -> Result<Option<NoBody>, String> { panic!("the body is never opened") },
            std::future::pending::<()>(),
            || 0,
        )
        .await
        .unwrap();
        assert_eq!(
            got,
            Err(BodyRefusal::TooLarge {
                size: Some(POLLING_POST_BODY_BYTES + 1),
                budget: POLLING_POST_BODY_BYTES
            })
        );
    }

    #[test]
    fn the_polling_posts_answers_are_plain_413_503_and_408() {
        let (text, status, retry) = polling_refusal_answer(&BodyRefusal::TooLarge {
            size: Some(POLLING_POST_BODY_BYTES + 1),
            budget: POLLING_POST_BODY_BYTES,
        });
        assert_eq!(status, 413);
        assert_eq!(retry, None);
        assert_eq!(
            text,
            "This request's body is 1000001 bytes, and this host reads at most 1000000 bytes of a request: a bound of this host."
        );
        let (text, status, retry) = polling_refusal_answer(&BodyRefusal::BodiesFull {
            held: 5,
            total: PRE_AUTH_HELD_BODY_BYTES,
        });
        assert_eq!((status, retry), (503, Some(2)));
        assert!(text.contains("send the request again shortly"), "{text}");
        let (text, status, retry) = polling_refusal_answer(&BodyRefusal::TimedOut {
            held: 5,
            waited_ms: 30_000,
            deadline_ms: 30_000,
        });
        assert_eq!((status, retry), (408, None));
        assert!(text.contains("within 30 seconds"), "{text}");
    }

    #[tokio::test]
    async fn each_bearer_route_reads_its_figure_and_refuses_one_byte_over() {
        for budget in [ATTEST_BODY_BYTES, BROADCAST_BODY_BYTES] {
            let at = budget as usize;
            assert_eq!(
                read_len(budget, at).await.map(|b| b.len()),
                Ok(at),
                "{budget}"
            );
            assert_eq!(
                read_len(budget, at + 1).await,
                Err(BodyRefusal::TooLarge { size: None, budget }),
                "{budget}"
            );
        }
        // `/push` at its figure by declared length (12 MiB is not built here).
        for budget in [PUSH_BODY_BYTES, ATTEST_BODY_BYTES, BROADCAST_BODY_BYTES] {
            let at = budget.to_string();
            let got = read_bearer_route_body(
                Some(&at),
                budget,
                || -> Result<Option<NoBody>, String> { Ok(None) },
                std::future::pending::<()>(),
                || 0,
            )
            .await
            .unwrap();
            assert_eq!(got, Ok(Vec::new()), "{budget}: at the figure");
            let over = (budget + 1).to_string();
            let got = read_bearer_route_body(
                Some(&over),
                budget,
                || -> Result<Option<NoBody>, String> { panic!("the body is never opened") },
                std::future::pending::<()>(),
                || 0,
            )
            .await
            .unwrap();
            assert_eq!(
                got,
                Err(BodyRefusal::TooLarge {
                    size: Some(budget + 1),
                    budget
                }),
                "{budget}: one byte over"
            );
        }
    }

    #[test]
    fn a_bearer_routes_answers_are_the_relays_413_and_the_layers_503_and_408() {
        let (body, status, retry) = bearer_refusal_answer(
            "/broadcast",
            &BodyRefusal::TooLarge {
                size: Some(BROADCAST_BODY_BYTES + 1),
                budget: BROADCAST_BODY_BYTES,
            },
        );
        assert_eq!((status, retry), (413, None));
        assert_eq!(
            body,
            json!({
                "status": "error",
                "code": "ERR_BODY_TOO_LARGE",
                "description": "The /broadcast body is 262145 bytes and the relay reads at most 262144 of it in one request.",
            })
        );
        let (body, _, _) = bearer_refusal_answer(
            "/session/attest",
            &BodyRefusal::TooLarge {
                size: None,
                budget: ATTEST_BODY_BYTES,
            },
        );
        assert_eq!(
            body["description"],
            "The /session/attest body is more than 16384 bytes and the relay reads at most 16384 of it in one request."
        );
        let full = BodyRefusal::BodiesFull {
            held: 5,
            total: BEARER_HELD_BODY_BYTES,
        };
        assert_eq!(
            bearer_refusal_answer("/push", &full),
            (full.to_json(), 503, Some(2))
        );
        let late = BodyRefusal::TimedOut {
            held: 5,
            waited_ms: 30_000,
            deadline_ms: 30_000,
        };
        assert_eq!(
            bearer_refusal_answer("/push", &late),
            (late.to_json(), 408, None)
        );
    }
}
