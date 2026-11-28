//! The relay's bounds on a request's body before its caller is authenticated.
//!
//! Two doors read a body before the caller is known: the BRC-31 layer
//! (bsv-middleware-cloudflare's `process_auth_do_with_body_bounds`, which
//! signs over the body, so it reads it first) and the relay's own HTTP session
//! lane (`session_lane_auth` in `lib.rs`, which hashes the body for the hub's
//! MAC check). Both read at most the relay's figure for one send,
//! [`validation::SEND_BODY_BYTES`], and answer a larger body with the relay's
//! own 413 `ERR_BODY_TOO_LARGE` ([`validation::body_too_large`]).
//!
//! The figures are this host's. One constant, `SEND_BODY_BYTES`, sets the
//! bound on one request at both doors and at the relay's own check after the
//! read (`validation::read_send_body`), so the three cannot disagree.
//!
//! The totals. A Worker's isolate is memory-limited and serves several
//! requests at once, so each door also keeps a count of the body bytes it is
//! holding for callers not yet authenticated, and answers a chunk that would
//! pass its total 503 `ERR_AUTH_BODIES_FULL` with `Retry-After`. Once a door
//! hands a body to the route, the relay holds up to three copies of a send's
//! size while it reads it (the body, the text it parses and a payment's hex
//! beside it: `validation::SEND_BODY_BYTES`'s own estimate), 3 x 12 MiB =
//! 36 MiB for one send at the bound. Beside that one send:
//!
//! - the BRC-31 layer's total, [`AUTH_HELD_BODY_BYTES`] = 2 x 12 MiB = 24 MiB
//!   (two sends at the bound being read at once);
//! - the session lane's total, [`SESSION_LANE_HELD_BODY_BYTES`] = 12 MiB (one
//!   send at the bound being read at once).
//!
//! 36 + 24 + 12 = 72 MiB of request bodies at most, of a Workers isolate's
//! 128 MiB; the rest is the Worker's own state and the reading's.
//!
//! The deadline: a body's whole read has the layer's default,
//! `DEFAULT_BODY_DEADLINE` (30 seconds), at both doors, and is answered 408
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

/// The most request-body bytes the HTTP session lane holds at once in one
/// isolate: one send at the bound, 12 MiB. The lane keeps its own count
/// ([`SESSION_LANE_BODIES`]): the BRC-31 layer's count is the adapter's own
/// and is not one of its public items.
pub const SESSION_LANE_HELD_BODY_BYTES: u64 = SESSION_LANE_BODY_BYTES;

/// The session lane's count of the body bytes it holds at this moment, one
/// per isolate.
pub static SESSION_LANE_BODIES: BodyLedger = BodyLedger::new();

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
/// ([`SESSION_LANE_BODY_BYTES`], [`SESSION_LANE_HELD_BODY_BYTES`] and the
/// default deadline, counted in [`SESSION_LANE_BODIES`]).
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
        &SESSION_LANE_BODIES,
        content_length,
        SESSION_LANE_BODY_BYTES,
        SESSION_LANE_HELD_BODY_BYTES,
        u64::try_from(DEFAULT_BODY_DEADLINE.as_millis()).unwrap_or(u64::MAX),
        open,
        deadline,
        now_ms,
    )
    .await
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
        assert_eq!(SESSION_LANE_HELD_BODY_BYTES, 12 * 1024 * 1024);
        const { assert!(SESSION_LANE_HELD_BODY_BYTES >= SESSION_LANE_BODY_BYTES) };
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
            total: SESSION_LANE_HELD_BODY_BYTES,
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
        assert_eq!(SESSION_LANE_BODIES.held(), 0);
    }
}
