//! Shared `sendMessage` write-path core (M9 #44).
//!
//! Both transports — HTTP `POST /sendMessage` (in `lib.rs`) and the
//! WebSocket `sendMessage` event (in `message_hub.rs`) — funnel through
//! `process_send` here. That makes the row inserted into D1 byte-for-byte
//! identical regardless of which channel the write came in on:
//!
//! ```text
//!   HTTP POST /sendMessage          ┐
//!                                   │
//!   WS   sendMessage event          ┘ → process_send → storage::insert_message
//! ```
//!
//! The two callers each translate the structured `SendOutcome` into
//! their native response shape:
//!
//! * HTTP: `(serde_json::Value, u16)` returned to the BRC-31 signer.
//! * WS:   `sendMessageAck` / `messageFailed` / `paymentFailed` events
//!   emitted on the existing socket envelope.
//!
//! The validation, fee resolution, payment internalization (BRC-100
//! `internalizeAction` via `payments.rs`), R2-backed BEEF resolution,
//! D1 insertion, and FCM fan-out logic live here once. The wrappers
//! contain only outcome → wire-format translation.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use serde_json::{json, Value};
use worker::{console_log, Date, Delay, Env, Headers, Method, Request, RequestInit};

/// Hard cap on the best-effort WS live-push fan-out to a recipient's Durable
/// Object (`push_to_recipient_sockets`). The push MUST NOT block `POST
/// /sendMessage`: the message is already durable in D1 and offline / slow-DO
/// clients receive it via `listMessages` backfill. Without this cap an
/// unresponsive `/internal/push` DO fetch hangs the whole send for the client's
/// full request timeout (~30s) — which wedged every authed send under load
/// (the relay's `/sendMessage` "canceled" 30s hang, 0 CPU). 2s is far above a
/// healthy DO RTT (single-digit ms) yet returns promptly when a DO is stuck.
const PUSH_FANOUT_TIMEOUT_MS: u64 = 2_000;

use crate::beef_upload;
use crate::fcm;
use crate::payments;
use crate::storage::Storage;
use crate::validation::ValidatedSendMessage;

/// Per-recipient success record (matches the HTTP response `results[]`
/// element shape exactly).
#[derive(Debug, Clone)]
pub struct RecipientResult {
    pub recipient: String,
    pub message_id: String,
}

/// Structured result of running the shared write path.
///
/// Each variant maps cleanly onto one HTTP `(json, status)` pair AND one
/// WebSocket event. Add variants here when a new failure mode needs
/// surfaced — never branch on stringly-typed reasons in callers.
#[derive(Debug)]
pub enum SendOutcome {
    /// All recipients accepted and stored.
    Success { results: Vec<RecipientResult> },

    /// Validation rejected the request before any work began.
    /// Returns the existing `(body, status)` shape produced by
    /// `validation::validate_send_message` so callers can pass it
    /// straight through on HTTP, or unpack the description for WS.
    ValidationError { body: Value, status: u16 },

    /// One or more recipients have a fee of -1 (blocked).
    BlockedRecipients { list: Vec<String> },

    /// Payment was required but missing from the request, or the
    /// payment object failed `payments::process_payment`. The inner
    /// `(body, status)` is whatever `payments` produced — callers can
    /// pass it through (HTTP) or extract the description (WS).
    PaymentFailed { body: Value, status: u16 },

    /// A duplicate `messageId` collided with an already-stored row.
    /// Carries the offending (recipient, messageId) for future
    /// diagnostics — neither the HTTP nor WS wrapper currently
    /// surfaces these in the wire response (they match the legacy
    /// HTTP shape, which only emits the generic "Duplicate message."
    /// description), but having them here means we don't need to
    /// re-thread the values through if the wire format ever changes.
    DuplicateMessage {
        #[allow(dead_code)]
        recipient: String,
        #[allow(dead_code)]
        message_id: String,
    },

    /// Something else went wrong (D1 read/write, R2 fetch, etc.).
    InternalError { detail: String },

    /// A TRANSIENT D1 fault (cold-start blip / momentary storage-DO contention)
    /// that did not clear within the bounded in-request retry. Distinct from
    /// `InternalError` so the caller can return a client-RETRYABLE status (HTTP
    /// 503) rather than a terminal 500 — and, critically, WITHOUT the ~10s hang
    /// the un-bounded write path used to inflict (bsv-low#249): the write path now
    /// fails fast here. The client's own resend then succeeds against a warm
    /// binding, so a momentary blip no longer strands a move → no spurious
    /// escalation.
    TransientError { detail: String },
}

/// Map a `worker::Error` bubbled out of the D1 read/write helpers onto the right
/// send outcome: the bounded retry loops only ever propagate a TRANSIENT error
/// after exhausting their attempts (a genuine error short-circuits without
/// retry), so a transient class here means "D1 momentarily unavailable" →
/// client-retryable, whereas anything else is a real internal fault.
fn classify_store_error(e: worker::Error) -> SendOutcome {
    if crate::storage::is_transient_d1_error(&e) {
        SendOutcome::TransientError {
            detail: e.to_string(),
        }
    } else {
        SendOutcome::InternalError {
            detail: e.to_string(),
        }
    }
}

/// Run the shared write path. Idempotent w.r.t. how the request was
/// validated: the HTTP path validates raw bytes via
/// `validation::validate_send_message`, then hands the `ValidatedSendMessage`
/// here. The WS path constructs an equivalent `ValidatedSendMessage` from
/// its event payload (the inner `message` object plus the box derived
/// from `roomId`) and calls the same function.
///
/// The function MUST stay pure of transport concerns — no `Response`,
/// no `WebSocket`. That is the parity contract.
pub async fn process_send(
    validated: ValidatedSendMessage,
    sender_key: &str,
    env: &Env,
    store: &Storage<'_>,
) -> SendOutcome {
    // -- 1. Resolve per-recipient context (recipient fee + server delivery fee + the
    //       recipient's message-box id) in ONE D1 `batch()` round-trip each — #9: this is
    //       the per-round-message relay hot path (keygen/aux), formerly 3-4 SEQUENTIAL D1
    //       queries. `box_id == None` ⇒ create lazily in the insert loop (only the first
    //       message to a recipient). --
    let mut blocked = Vec::new();
    // (recipient, message_id, recipient_fee, box_id)
    let mut ctx_map: Vec<(String, String, i32, Option<i64>)> = Vec::new();
    let mut delivery_fee: i32 = 0;

    for (recipient, message_id) in &validated.recipients {
        // bsv-low#249 diagnostic: time the D1 read_send_context (find_message_box
        // READ — the review flagged it has read-retry but NO op-timeout, so a
        // read stall would surface here). Paired with the box/insert timers below
        // and the TRACE_LAT route_ms in lib.rs, the next run pins any relay-side
        // stall to an exact D1 op.
        let t_ctx_start = Date::now().as_millis();
        let ctx = match store
            .read_send_context(recipient, sender_key, &validated.message_box)
            .await
        {
            Ok(c) => c,
            Err(e) => return classify_store_error(e),
        };
        console_log!(
            "TRACE_LAT send.read_ctx recipient={} ms={}",
            recipient,
            Date::now().as_millis().saturating_sub(t_ctx_start)
        );
        // server delivery fee is per-message_box — identical for every recipient.
        delivery_fee = ctx.server_fee;

        if ctx.recipient_fee < 0 {
            blocked.push(recipient.clone());
        } else {
            ctx_map.push((
                recipient.clone(),
                message_id.clone(),
                ctx.recipient_fee,
                ctx.box_id,
            ));
        }
    }

    if !blocked.is_empty() {
        return SendOutcome::BlockedRecipients { list: blocked };
    }

    // -- 2. Decide whether payment is required. --
    let fee_map: Vec<(String, String, i32)> = ctx_map
        .iter()
        .map(|(r, m, f, _)| (r.clone(), m.clone(), *f))
        .collect();
    let any_recipient_fee = fee_map.iter().any(|(_, _, f)| *f > 0);
    let requires_payment = delivery_fee > 0 || any_recipient_fee;

    // -- 3. If payment required: resolve R2-backed BEEF (if applicable),
    //       then hand to `payments::process_payment` which calls BRC-100
    //       `internalizeAction` against `WALLET_STORAGE_URL`. --
    let (per_recipient_outputs, r2_cleanup_key, resolved_payment) = if requires_payment {
        match &validated.payment {
            None => {
                return SendOutcome::PaymentFailed {
                    body: json!({
                        "status": "error",
                        "code": "ERR_MISSING_PAYMENT_TX",
                        "description": "Payment transaction data is required for payable delivery."
                    }),
                    status: 400,
                };
            }
            Some(payment) => {
                let (resolved, cleanup) =
                    match beef_upload::resolve_r2_backed_payment(payment, sender_key, env).await {
                        Ok(pair) => pair,
                        Err((body, status)) => return SendOutcome::PaymentFailed { body, status },
                    };

                match payments::process_payment(&resolved, &fee_map, delivery_fee, sender_key, env)
                    .await
                {
                    Ok(outputs) => (outputs, cleanup, Some(resolved)),
                    Err((body, status)) => return SendOutcome::PaymentFailed { body, status },
                }
            }
        }
    } else {
        (HashMap::<String, Value>::new(), None, None)
    };

    // -- 4. Insert per-recipient rows into D1. Same column shape as the
    //       HTTP path — the parity contract. --
    let mut results = Vec::with_capacity(ctx_map.len());
    for (recipient, message_id, _fee, box_id_opt) in &ctx_map {
        // #9: the batched read already fetched the box id; only hit D1 to create the box
        // when it doesn't exist yet (first message to this recipient/box).
        let box_id = match box_id_opt {
            Some(id) => *id,
            None => {
                let t_box_start = Date::now().as_millis();
                let r = store
                    .get_or_create_message_box(recipient, &validated.message_box)
                    .await;
                console_log!(
                    "TRACE_LAT send.get_or_create_box recipient={} ms={}",
                    recipient,
                    Date::now().as_millis().saturating_sub(t_box_start)
                );
                match r {
                    Ok(id) => id,
                    Err(e) => return classify_store_error(e),
                }
            }
        };

        // Stored body shape: {"message": body, "payment": ...} — the
        // resolved payment (post-R2-inline) is what gets durably stored,
        // not the R2 reference, since the object is deleted shortly.
        let per_payment = per_recipient_outputs.get(recipient.as_str());
        let stored_body = match per_payment {
            Some(payment_data) => {
                let mut p = resolved_payment
                    .clone()
                    .or_else(|| validated.payment.clone())
                    .unwrap_or(json!({}));
                if let Some(obj) = p.as_object_mut() {
                    obj.insert("outputs".to_string(), payment_data.clone());
                }
                json!({ "message": validated.body, "payment": p }).to_string()
            }
            None => json!({ "message": validated.body }).to_string(),
        };

        let t_ins_start = Date::now().as_millis();
        let ins = store
            .insert_message(message_id, box_id, sender_key, recipient, &stored_body)
            .await;
        console_log!(
            "TRACE_LAT send.insert_message recipient={} msgId={} ms={} dup={}",
            recipient,
            message_id,
            Date::now().as_millis().saturating_sub(t_ins_start),
            matches!(&ins, Ok(false))
        );
        match ins {
            Ok(true) => {}
            Ok(false) => {
                return SendOutcome::DuplicateMessage {
                    recipient: recipient.clone(),
                    message_id: message_id.clone(),
                };
            }
            Err(e) => return classify_store_error(e),
        }

        results.push(RecipientResult {
            recipient: recipient.clone(),
            message_id: message_id.clone(),
        });

        // -- M9 #45: HTTP→WS push bridge. Fan out the freshly stored
        //    message to any of the recipient's currently-connected
        //    sockets that have joined the matching room. Best-effort:
        //    push failure (DO unreachable, no subscribers, JSON marshal
        //    error) MUST NOT fail the HTTP send. The message is already
        //    in D1; offline clients get it on their next listMessages.
        push_to_recipient_sockets(
            env,
            recipient,
            &validated.message_box,
            sender_key,
            message_id,
            &validated.body,
        )
        .await;

        // Fire-and-forget FCM push — only for the notifications box.
        if fcm::should_use_fcm_delivery(&validated.message_box) {
            let _ =
                fcm::send_fcm_notification(recipient, message_id, "New Message", env, store).await;
        }
    }

    // -- 5. Best-effort cleanup of the R2-uploaded BEEF. R2 lifecycle
    //       rules will sweep any leak. --
    if let Some(key) = r2_cleanup_key {
        let _ = beef_upload::delete_beef_from_r2(env, &key).await;
    }

    SendOutcome::Success { results }
}

/// Translate a `SendOutcome` into the HTTP `(json, status)` pair the
/// existing handler emits. Wire shape is byte-identical to pre-#44.
pub fn outcome_to_http(outcome: SendOutcome) -> (Value, u16) {
    match outcome {
        SendOutcome::Success { results } => {
            let n = results.len();
            let arr: Vec<Value> = results
                .into_iter()
                .map(|r| json!({ "recipient": r.recipient, "messageId": r.message_id }))
                .collect();
            (
                json!({
                    "status": "success",
                    "message": format!("Your message has been sent to {} recipient(s).", n),
                    "results": arr,
                }),
                200,
            )
        }
        SendOutcome::ValidationError { body, status } => (body, status),
        SendOutcome::BlockedRecipients { list } => (
            json!({
                "status": "error",
                "code": "ERR_DELIVERY_BLOCKED",
                "description": format!("Blocked recipients: {}", list.join(", ")),
                "blockedRecipients": list,
            }),
            403,
        ),
        SendOutcome::PaymentFailed { body, status } => (body, status),
        SendOutcome::DuplicateMessage { .. } => (
            json!({
                "status": "error",
                "code": "ERR_DUPLICATE_MESSAGE",
                "description": "Duplicate message.",
            }),
            400,
        ),
        SendOutcome::InternalError { detail } => (
            json!({
                "status": "error",
                "code": "ERR_INTERNAL",
                "description": format!("An internal error has occurred: {}", detail),
            }),
            500,
        ),
        SendOutcome::TransientError { detail } => (
            json!({
                "status": "error",
                "code": "ERR_D1_UNAVAILABLE",
                "description": format!(
                    "The relay is momentarily unavailable; please retry: {}",
                    detail
                ),
            }),
            // 503 = client-retryable. The send failed FAST (bounded write
            // timeout+retry), never the ~10s hang — the client resend lands on a
            // warm binding, so a momentary D1 blip no longer strands a move.
            503,
        ),
    }
}

/// HTTP→WS push bridge (M9 #45). Posts the freshly stored message to
/// the recipient DO's `/internal/push` endpoint so any of that
/// identity's sockets that have joined `<recipient>-<message_box>`
/// receive the `sendMessage` envelope in real time.
///
/// Best-effort: every failure path here logs via `console_log!` and
/// returns. The HTTP `sendMessage` caller MUST NOT see this fail —
/// the durable D1 row is the source of truth, and offline clients
/// pick the message up on their next `listMessages`.
///
/// Why no auth on the internal endpoint: DOs are not addressable
/// from the public internet. The only way a request reaches
/// `MessageHub::handle_internal_push` is via this Worker's stub, and
/// this Worker has already done BRC-31 mutual auth on the originating
/// `POST /sendMessage`. Adding a second auth layer would be theatre.
async fn push_to_recipient_sockets(
    env: &Env,
    recipient: &str,
    message_box: &str,
    sender: &str,
    message_id: &str,
    body: &Value,
) {
    let payload = json!({
        "roomId": format!("{recipient}-{message_box}"),
        "sender": sender,
        "messageId": message_id,
        "body": body,
    })
    .to_string();

    let namespace = match env.durable_object("MESSAGE_HUB") {
        Ok(n) => n,
        Err(e) => {
            console_log!("WS push: MESSAGE_HUB binding lookup failed: {}", e);
            return;
        }
    };

    let stub = match namespace
        .id_from_name(recipient)
        .and_then(|id| id.get_stub())
    {
        Ok(s) => s,
        Err(e) => {
            console_log!("WS push: stub lookup for {} failed: {}", recipient, e);
            return;
        }
    };

    let headers = Headers::new();
    if let Err(e) = headers.set("content-type", "application/json") {
        console_log!("WS push: header setup failed: {}", e);
        return;
    }

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(payload.into()));

    // The URL host is irrelevant for DO stub fetches — the runtime
    // routes purely on the Worker→DO stub. The path IS read by
    // `handle_internal_push` (matches `/internal/push`), so use a
    // synthetic origin and the literal path.
    let req = match Request::new_with_init("https://do.local/internal/push", &init) {
        Ok(r) => r,
        Err(e) => {
            console_log!("WS push: request construction failed: {}", e);
            return;
        }
    };

    let t_fanout_start = Date::now().as_millis();
    console_log!(
        "TRACE_PHD broadcast.fanout.start recipient={} msgId={} t={}",
        recipient,
        message_id,
        t_fanout_start
    );
    // Bound the DO push: race the subrequest against a `PUSH_FANOUT_TIMEOUT_MS`
    // `Delay`. On timeout we ABANDON the push (dropping the fetch future cancels
    // the subrequest) and return — best-effort, exactly as this function's
    // contract documents — so a wedged/slow recipient DO can never hang the send.
    let mut fetch = Box::pin(stub.fetch_with_request(req));
    let mut push_timeout = Box::pin(Delay::from(Duration::from_millis(PUSH_FANOUT_TIMEOUT_MS)));
    let push_result = std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(r) = fetch.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(r));
        }
        if push_timeout.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Pending
    })
    .await;
    let t_done = Date::now().as_millis();
    match push_result {
        Some(Ok(_)) => {
            console_log!(
                "TRACE_PHD broadcast.fanout.ok recipient={} msgId={} t={} rtt_ms={}",
                recipient,
                message_id,
                t_done,
                t_done.saturating_sub(t_fanout_start)
            );
        }
        Some(Err(e)) => {
            console_log!(
                "TRACE_PHD broadcast.fanout.err recipient={} msgId={} t={} rtt_ms={} err={}",
                recipient,
                message_id,
                t_done,
                t_done.saturating_sub(t_fanout_start),
                e
            );
            console_log!(
                "WS push: fan-out to recipient={} room={}-{} failed: {}",
                recipient,
                recipient,
                message_box,
                e
            );
        }
        None => {
            // Timed out — best-effort push abandoned. The D1 row is the source of
            // truth; the recipient gets the message on its next `listMessages`
            // (the MPC ceremonies' reliability-drain backfill covers this).
            console_log!(
                "TRACE_PHD broadcast.fanout.timeout recipient={} msgId={} t={} after_ms={}",
                recipient,
                message_id,
                t_done,
                PUSH_FANOUT_TIMEOUT_MS
            );
            console_log!(
                "WS push: fan-out to recipient={} room={}-{} TIMED OUT after {}ms (best-effort; \
                 message already durable in D1, delivered via listMessages backfill)",
                recipient,
                recipient,
                message_box,
                PUSH_FANOUT_TIMEOUT_MS
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_success_to_http_matches_legacy_shape() {
        let outcome = SendOutcome::Success {
            results: vec![RecipientResult {
                recipient: "abc".into(),
                message_id: "m1".into(),
            }],
        };
        let (body, status) = outcome_to_http(outcome);
        assert_eq!(status, 200);
        assert_eq!(body["status"], "success");
        assert_eq!(
            body["message"],
            "Your message has been sent to 1 recipient(s)."
        );
        assert_eq!(body["results"][0]["recipient"], "abc");
        assert_eq!(body["results"][0]["messageId"], "m1");
    }

    #[test]
    fn outcome_blocked_to_http_matches_legacy_shape() {
        let outcome = SendOutcome::BlockedRecipients {
            list: vec!["abc".into(), "def".into()],
        };
        let (body, status) = outcome_to_http(outcome);
        assert_eq!(status, 403);
        assert_eq!(body["code"], "ERR_DELIVERY_BLOCKED");
        assert_eq!(body["description"], "Blocked recipients: abc, def");
        assert_eq!(body["blockedRecipients"][0], "abc");
        assert_eq!(body["blockedRecipients"][1], "def");
    }

    #[test]
    fn outcome_duplicate_to_http_matches_legacy_shape() {
        let outcome = SendOutcome::DuplicateMessage {
            recipient: "abc".into(),
            message_id: "m1".into(),
        };
        let (body, status) = outcome_to_http(outcome);
        assert_eq!(status, 400);
        assert_eq!(body["code"], "ERR_DUPLICATE_MESSAGE");
        assert_eq!(body["description"], "Duplicate message.");
    }

    #[test]
    fn outcome_internal_to_http_matches_legacy_shape() {
        let outcome = SendOutcome::InternalError {
            detail: "kaboom".into(),
        };
        let (body, status) = outcome_to_http(outcome);
        assert_eq!(status, 500);
        assert_eq!(body["code"], "ERR_INTERNAL");
        assert_eq!(
            body["description"],
            "An internal error has occurred: kaboom"
        );
    }

    #[test]
    fn outcome_transient_to_http_is_retryable_503() {
        let outcome = SendOutcome::TransientError {
            detail: "D1_ERROR: write op exceeded 2000ms bound".into(),
        };
        let (body, status) = outcome_to_http(outcome);
        // 503 (client-retryable) — NOT 500, and NOT the old ~10s hang.
        assert_eq!(status, 503);
        assert_eq!(body["code"], "ERR_D1_UNAVAILABLE");
        assert_eq!(body["status"], "error");
    }

    #[test]
    fn outcome_validation_passes_through_payload() {
        let body = json!({"status":"error","code":"ERR_INVALID_MESSAGEBOX","description":"x"});
        let outcome = SendOutcome::ValidationError {
            body: body.clone(),
            status: 400,
        };
        let (got, status) = outcome_to_http(outcome);
        assert_eq!(status, 400);
        assert_eq!(got, body);
    }

    #[test]
    fn outcome_payment_passes_through_payload() {
        let body =
            json!({"status":"error","code":"ERR_MISSING_PAYMENT_TX","description":"need tx"});
        let outcome = SendOutcome::PaymentFailed {
            body: body.clone(),
            status: 400,
        };
        let (got, status) = outcome_to_http(outcome);
        assert_eq!(status, 400);
        assert_eq!(got, body);
    }
}
