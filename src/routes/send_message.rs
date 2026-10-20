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
//!
//! The live push to each recipient's hub (M9 #45) is NOT part of the answer
//! (0.6.1, bsv-low #787): `process_send` returns it as an `AfterAnswer`, and
//! each caller runs it once the answer is out (`answer_then_defer` on HTTP,
//! `emit_then_defer` in the hub). A send is answered once its rows are
//! durable; delivery is the recipient's socket push or its next
//! `listMessages`. That is the reference's order: message-box-server stores,
//! answers, and emits to the room without waiting on a delivery.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use serde_json::{json, Value};
use worker::{console_log, Date, Delay, Env, Headers, Method, Request, RequestInit};

/// Hard cap on the best-effort WS live-push fan-out to a recipient's Durable
/// Object (`push_one`). The push MUST NOT block `POST /sendMessage`: the
/// message is already durable in D1 and offline / slow-DO clients receive it
/// via `listMessages` backfill. Since 0.6.1 the push runs after the answer
/// (`AfterAnswer`); this bound still caps how long the deferred work holds the
/// Worker (or the hub) open. Without this cap an
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

/// The result of the shared write path: the outcome the caller answers with,
/// and the pushes the stored rows owe their recipients' hubs, which the caller
/// runs only after the answer is out.
#[must_use]
pub struct Sent {
    pub outcome: SendOutcome,
    pub after: AfterAnswer,
}

/// One live push a durable row owes its recipient's hub (M9 #45).
#[derive(Debug, Clone)]
pub struct HubPush {
    pub recipient: String,
    pub message_box: String,
    pub sender: String,
    pub message_id: String,
    pub body: Value,
}

/// What a send leaves for after its answer: one `HubPush` per row that
/// landed, in insert order. A send that stops part way (a duplicate, a D1
/// fault) still owes the pushes of the rows stored before it, as before.
#[derive(Debug, Default)]
#[must_use]
pub struct AfterAnswer {
    pushes: Vec<HubPush>,
}

impl AfterAnswer {
    #[cfg(test)]
    pub(crate) fn of(pushes: Vec<HubPush>) -> Self {
        Self { pushes }
    }

    #[cfg(test)]
    pub(crate) fn pushes(&self) -> &[HubPush] {
        &self.pushes
    }

    pub fn is_empty(&self) -> bool {
        self.pushes.is_empty()
    }

    /// Run the pushes against the real `MESSAGE_HUB`, each one raced against
    /// `PUSH_FANOUT_TIMEOUT_MS`. For `ctx.wait_until` / `state.wait_until`.
    pub async fn run(self, env: Env) {
        self.run_on(&WorkerHub { env }).await
    }

    /// The same over any hub (the pins drive a stub).
    pub(crate) async fn run_on<H: PushHub>(self, hub: &H) {
        for job in &self.pushes {
            push_one(hub, job).await;
        }
    }
}

/// The HTTP leg's order: the answer is formed from the outcome, the fan-out is
/// handed to `defer` (the Worker's `ctx.wait_until`), and the answer returns
/// without waiting on it. The answer means DURABLE, not delivered: the rows are
/// in D1; delivery is the recipient's socket push or its next `listMessages`.
/// This is the reference's order (message-box-server stores, answers, and
/// emits to the room without awaiting a delivery ack).
pub fn answer_then_defer(sent: Sent, defer: impl FnOnce(AfterAnswer)) -> (Value, u16) {
    let answer = outcome_to_http(sent.outcome);
    if !sent.after.is_empty() {
        defer(sent.after);
    }
    answer
}

/// The hub a push goes to: the real one is `WorkerHub`; the pins use stubs.
pub(crate) trait PushHub {
    /// Deliver one push; `Err` carries the transport or setup failure.
    fn push(&self, job: &HubPush) -> impl Future<Output = Result<(), String>>;
    /// A future that resolves after `ms`.
    fn timer(&self, ms: u64) -> impl Future<Output = ()>;
    fn now_ms(&self) -> u64;
    fn log(&self, line: String);
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
///
/// The returned `Sent` carries the hub pushes apart from the outcome: no push
/// runs here, so the caller answers once the rows are durable (0.6.1).
pub async fn process_send(
    validated: ValidatedSendMessage,
    sender_key: &str,
    env: &Env,
    store: &Storage<'_>,
) -> Sent {
    let mut after = AfterAnswer::default();
    let outcome = store_send(validated, sender_key, env, store, &mut after).await;
    Sent { outcome, after }
}

/// `process_send`'s body: every row it stores leaves its push in `after`.
async fn store_send(
    validated: ValidatedSendMessage,
    sender_key: &str,
    env: &Env,
    store: &Storage<'_>,
    after: &mut AfterAnswer,
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

    // -- 1b. The sender's budget for the window (0.4.4, bsv-low #591 M3 and
    //       NOTE-3): one send, and the bytes of text no delivery fee judges
    //       (the message, and the payment when the box owes no delivery fee).
    //       A paid payment's bytes are not counted: it is paid for. --
    if let Ok(db) = env.d1("DB") {
        let payment_text = match (&validated.payment, delivery_fee > 0) {
            (Some(payment), false) => payment.to_string().len(),
            _ => 0,
        };
        let unjudged = (validated.body.to_string().len() + payment_text) as u64;
        if let Err((body, status)) = crate::send_budget::charge(
            &crate::send_budget::D1Windows { db: &db },
            &crate::send_budget::Budget::from_env(env),
            sender_key,
            Date::now().as_millis() / 1000,
            unjudged,
        )
        .await
        {
            return SendOutcome::ValidationError { body, status };
        }
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
    let (per_recipient_outputs, r2_key, handed) = if requires_payment {
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
                // The object `payment.beefR2Key` names, when the sender owns
                // it. It is verified from R2 as a stream and inlined only
                // after the verdict (0.4.0); a verification one request does
                // not finish is a 503 the same request continues.
                let r2_key = match beef_upload::decide_r2_fetch(payment, sender_key) {
                    Ok(key) => key,
                    Err((body, status)) => return SendOutcome::PaymentFailed { body, status },
                };

                match payments::process_payment(
                    payment,
                    r2_key.as_deref(),
                    &fee_map,
                    delivery_fee,
                    sender_key,
                    env,
                )
                .await
                {
                    Ok(settled) => (settled.outputs, r2_key, Some(settled.handed)),
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
    // The rows stored so far whose payment names the bytes at rest.
    let mut rows_naming = 0usize;
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
                    Err(e) => {
                        payments::forget_unnamed(
                            env,
                            rows_naming,
                            &handed,
                            r2_key.as_deref(),
                            true,
                        )
                        .await;
                        return classify_store_error(e);
                    }
                }
            }
        };

        // Stored body shape: {"message": body, "payment": ...}. The payment
        // is the hand-off's (`handoff::payment_at_rest`): the R2 key, the
        // verdict and the subject's txid, never the BEEF.
        let paid = handed.as_ref().and_then(|handed| {
            per_recipient_outputs
                .get(recipient.as_str())
                .map(|outputs| (&handed.payment, outputs))
        });
        // The object the row's payment names: the row's reference to it
        // (`beef_key`), released when the row is deleted or retired.
        let beef_key = paid.and_then(|(payment, _)| payment.get("beefR2Key")?.as_str());
        let stored_body = crate::handoff::stored_body(&validated.body, paid);

        let t_ins_start = Date::now().as_millis();
        let ins = store
            .insert_message(
                message_id,
                box_id,
                sender_key,
                recipient,
                &stored_body,
                beef_key,
            )
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
                payments::forget_unnamed(env, rows_naming, &handed, r2_key.as_deref(), true).await;
                return SendOutcome::DuplicateMessage {
                    recipient: recipient.clone(),
                    message_id: message_id.clone(),
                };
            }
            Err(e) => {
                payments::forget_unnamed(env, rows_naming, &handed, r2_key.as_deref(), true).await;
                return classify_store_error(e);
            }
        }
        rows_naming += usize::from(beef_key.is_some());

        results.push(RecipientResult {
            recipient: recipient.clone(),
            message_id: message_id.clone(),
        });

        // -- M9 #45: HTTP→WS push bridge. The freshly stored message is
        //    owed to any of the recipient's connected sockets that joined
        //    the matching room. Recorded here, run by the caller AFTER the
        //    answer (0.6.1): the row is the source of truth, a push that
        //    fails or times out is backfilled by the next listMessages.
        after.pushes.push(HubPush {
            recipient: recipient.clone(),
            message_box: validated.message_box.clone(),
            sender: sender_key.to_string(),
            message_id: message_id.clone(),
            body: validated.body.clone(),
        });

        // Fire-and-forget FCM push — only for the notifications box.
        if fcm::should_use_fcm_delivery(&validated.message_box) {
            let _ =
                fcm::send_fcm_notification(recipient, message_id, "New Message", env, store).await;
        }
    }

    // -- 5. The bytes stay at rest while a row or a deferred fee names them
    //       (`HandedOff::kept`). An object nothing names goes, best-effort. --
    payments::forget_unnamed(env, rows_naming, &handed, r2_key.as_deref(), false).await;

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
/// Best-effort: every failure path here is logged and returns. The
/// sender MUST NOT see this fail, and since 0.6.1 never waits on it
/// either (it runs after the answer, `AfterAnswer`) — the durable D1
/// row is the source of truth, and offline clients pick the message up
/// on their next `listMessages`.
///
/// Why no auth on the internal endpoint: DOs are not addressable
/// from the public internet. The only way a request reaches
/// `MessageHub::handle_internal_push` is via this Worker's stub, and
/// this Worker has already done BRC-31 mutual auth on the originating
/// `POST /sendMessage`. Adding a second auth layer would be theatre.
struct WorkerHub {
    env: Env,
}

impl PushHub for WorkerHub {
    async fn push(&self, job: &HubPush) -> Result<(), String> {
        let payload = json!({
            "roomId": format!("{}-{}", job.recipient, job.message_box),
            "sender": job.sender,
            "messageId": job.message_id,
            "body": job.body,
        })
        .to_string();

        let namespace = self
            .env
            .durable_object("MESSAGE_HUB")
            .map_err(|e| format!("MESSAGE_HUB binding lookup failed: {e}"))?;
        let stub = namespace
            .id_from_name(&job.recipient)
            .and_then(|id| id.get_stub())
            .map_err(|e| format!("stub lookup for {} failed: {e}", job.recipient))?;

        let headers = Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(|e| format!("header setup failed: {e}"))?;

        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.into()));

        // The URL host is irrelevant for DO stub fetches — the runtime
        // routes purely on the Worker→DO stub. The path IS read by
        // `handle_internal_push` (matches `/internal/push`), so use a
        // synthetic origin and the literal path.
        let req = Request::new_with_init("https://do.local/internal/push", &init)
            .map_err(|e| format!("request construction failed: {e}"))?;
        stub.fetch_with_request(req)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn timer(&self, ms: u64) -> impl Future<Output = ()> {
        Delay::from(Duration::from_millis(ms))
    }

    fn now_ms(&self) -> u64 {
        Date::now().as_millis()
    }

    fn log(&self, line: String) {
        console_log!("{}", line);
    }
}

/// One bounded push: race the hub's answer against `PUSH_FANOUT_TIMEOUT_MS`.
/// On timeout the push is ABANDONED (dropping the fetch future cancels the
/// subrequest) and logged, best-effort, so a wedged/slow recipient DO never
/// holds the deferred work past the bound.
async fn push_one<H: PushHub>(hub: &H, job: &HubPush) {
    let (recipient, message_id, message_box) = (&job.recipient, &job.message_id, &job.message_box);
    let t_fanout_start = hub.now_ms();
    hub.log(format!(
        "TRACE_PHD broadcast.fanout.start recipient={recipient} msgId={message_id} t={t_fanout_start}"
    ));
    let mut fetch = Box::pin(hub.push(job));
    let mut push_timeout = Box::pin(hub.timer(PUSH_FANOUT_TIMEOUT_MS));
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
    let t_done = hub.now_ms();
    let rtt = t_done.saturating_sub(t_fanout_start);
    match push_result {
        Some(Ok(())) => hub.log(format!(
            "TRACE_PHD broadcast.fanout.ok recipient={recipient} msgId={message_id} t={t_done} rtt_ms={rtt}"
        )),
        Some(Err(e)) => {
            hub.log(format!(
                "TRACE_PHD broadcast.fanout.err recipient={recipient} msgId={message_id} t={t_done} rtt_ms={rtt} err={e}"
            ));
            hub.log(format!(
                "WS push: fan-out to recipient={recipient} room={recipient}-{message_box} failed: {e}"
            ));
        }
        None => {
            // Timed out — best-effort push abandoned. The D1 row is the source of
            // truth; the recipient gets the message on its next `listMessages`
            // (the MPC ceremonies' reliability-drain backfill covers this).
            hub.log(format!(
                "TRACE_PHD broadcast.fanout.timeout recipient={recipient} msgId={message_id} t={t_done} after_ms={PUSH_FANOUT_TIMEOUT_MS}"
            ));
            hub.log(format!(
                "WS push: fan-out to recipient={recipient} room={recipient}-{message_box} TIMED OUT after {PUSH_FANOUT_TIMEOUT_MS}ms (best-effort; \
                 message already durable in D1, delivered via listMessages backfill)"
            ));
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

/// Host-drivable hub stubs for the 0.6.1 order pins (bsv-low #787): the real
/// hub fetch and `Delay` are wasm-only, so the pins drive `AfterAnswer::run_on`.
#[cfg(test)]
pub(crate) mod test_hub {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    pub(crate) type Log = Rc<RefCell<Vec<String>>>;

    /// How the stub hub answers a push.
    #[derive(Clone, Copy)]
    pub(crate) enum Answer {
        /// Never answers (a wedged or flooded recipient hub); the timer fires.
        Never,
        /// Answers after this many polls (a slow hub); the timer never fires.
        After(usize),
    }

    pub(crate) struct StubHub {
        pub(crate) log: Log,
        pub(crate) answer: Answer,
        pub(crate) calls: Cell<usize>,
    }

    impl StubHub {
        pub(crate) fn new(log: Log, answer: Answer) -> Self {
            Self {
                log,
                answer,
                calls: Cell::new(0),
            }
        }
    }

    /// Ready after `n` polls, waking itself in between.
    struct Polls(usize);

    impl Future for Polls {
        type Output = ();
        fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 == 0 {
                return Poll::Ready(());
            }
            self.0 -= 1;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    impl PushHub for StubHub {
        async fn push(&self, job: &HubPush) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            match self.answer {
                Answer::Never => std::future::pending::<()>().await,
                Answer::After(n) => Polls(n).await,
            }
            self.log.borrow_mut().push(format!(
                "hub delivered sendMessage room={}-{} msgId={}",
                job.recipient, job.message_box, job.message_id
            ));
            Ok(())
        }

        async fn timer(&self, _ms: u64) {
            match self.answer {
                Answer::Never => {}
                Answer::After(_) => std::future::pending::<()>().await,
            }
        }

        fn now_ms(&self) -> u64 {
            0
        }

        fn log(&self, line: String) {
            self.log.borrow_mut().push(line);
        }
    }

    pub(crate) fn job(recipient: &str, message_id: &str) -> HubPush {
        HubPush {
            recipient: recipient.to_string(),
            message_box: "low_game_x".to_string(),
            sender: "S".to_string(),
            message_id: message_id.to_string(),
            body: json!("hi"),
        }
    }

    pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
        panic!("the future did not resolve");
    }

    pub(crate) fn at(log: &[String], needle: &str) -> usize {
        log.iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no log line contains {needle:?}: {log:#?}"))
    }
}

/// bsv-low #787 (0.6.1): a send is answered once durable; the push follows.
#[cfg(test)]
mod decouple_787_tests {
    use super::test_hub::*;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn write_path_src() -> &'static str {
        let src = include_str!("send_message.rs");
        let a = src
            .find("pub async fn process_send(")
            .expect("process_send");
        let b = src
            .find("pub fn outcome_to_http(")
            .expect("outcome_to_http");
        &src[a..b]
    }

    fn fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
        let a = src.find(sig).unwrap_or_else(|| panic!("{sig} not found"));
        let rest = &src[a..];
        let end = rest
            .find("\n}\n")
            .or_else(|| rest.find("\n    }\n"))
            .unwrap();
        &rest[..end]
    }

    // Pin (a), behaviour: a hub that never answers. The HTTP answer is formed
    // before the hub is touched, and the push's timeout is logged after it.
    #[test]
    fn pin_a_a_send_answers_before_its_push_and_the_timeout_is_logged_after() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let hub = StubHub::new(log.clone(), Answer::Never);
        let sent = Sent {
            outcome: SendOutcome::Success {
                results: vec![RecipientResult {
                    recipient: "R1".into(),
                    message_id: "m1".into(),
                }],
            },
            after: AfterAnswer::of(vec![job("R1", "m1")]),
        };
        let mut deferred = None;
        let (body, status) = answer_then_defer(sent, |a| deferred = Some(a));
        log.borrow_mut().push("send.answered".into());
        assert_eq!(status, 200);
        assert_eq!(body["status"], "success");
        assert_eq!(body["results"][0]["messageId"], "m1");
        assert_eq!(
            hub.calls.get(),
            0,
            "the hub is not touched before the answer"
        );

        let after = deferred.expect("the push is deferred, not dropped");
        assert_eq!(after.pushes().len(), 1);
        block_on(after.run_on(&hub));
        let log = log.borrow();
        let answered = at(&log, "send.answered");
        let timeout = at(
            &log,
            "TRACE_PHD broadcast.fanout.timeout recipient=R1 msgId=m1",
        );
        assert!(answered < timeout, "{log:#?}");
        assert!(
            log[timeout].contains("after_ms=2000"),
            "the 2 s bound holds"
        );
        assert!(!log.iter().any(|l| l.contains("hub delivered")));
    }

    // Pin (a), source: the write path holds no push await; the HTTP leg hands
    // the fan-out to `ctx.wait_until` after forming the answer.
    #[test]
    fn pin_a_source_the_write_path_awaits_no_push() {
        let path = write_path_src();
        assert!(
            !path.contains("push_to_recipient_sockets(") && !path.contains("push_one("),
            "process_send must not await the hub push before it answers"
        );
        let lib = include_str!("../lib.rs");
        let tail = fn_body(lib, "async fn handle_send_body(");
        assert!(
            tail.contains("ctx.wait_until("),
            "the HTTP leg must run the fan-out under ctx.wait_until"
        );
        assert!(lib.contains("TRACE_LAT send.answered ms="));
    }

    // Pin (c), behaviour: a duplicate still answers ERR_DUPLICATE_MESSAGE on
    // HTTP; the pushes owed by the rows stored before it still run.
    #[test]
    fn pin_c_a_duplicate_answers_unchanged_and_the_owed_pushes_still_run() {
        let sent = Sent {
            outcome: SendOutcome::DuplicateMessage {
                recipient: "R2".into(),
                message_id: "m2".into(),
            },
            after: AfterAnswer::of(vec![job("R1", "m1")]),
        };
        let mut deferred = None;
        let (body, status) = answer_then_defer(sent, |a| deferred = Some(a));
        assert_eq!(status, 400);
        assert_eq!(body["code"], "ERR_DUPLICATE_MESSAGE");
        let after = deferred.expect("the stored row's push still runs");
        assert_eq!(after.pushes()[0].message_id, "m1");

        let lone = Sent {
            outcome: SendOutcome::DuplicateMessage {
                recipient: "R1".into(),
                message_id: "m1".into(),
            },
            after: AfterAnswer::default(),
        };
        let mut called = false;
        let (_, status) = answer_then_defer(lone, |_| called = true);
        assert_eq!(status, 400);
        assert!(!called, "a duplicate stored nothing and owes no push");
    }

    // Pin (c), source: the duplicate return no longer waits on the earlier
    // rows' pushes (they were awaited in the insert loop), and the WS trace
    // still names the duplicate an ack (#249).
    #[test]
    fn pin_c_source_the_duplicate_return_waits_on_no_push() {
        let path = write_path_src();
        assert!(path.contains("Ok(false) =>") && path.contains("DuplicateMessage {"));
        assert!(
            !path.contains("push_to_recipient_sockets("),
            "the duplicate return must not wait on the pushes of the rows before it"
        );
        let hub = include_str!("../message_hub.rs");
        assert!(hub.contains("\"Duplicate->sendMessageAck"));
    }
}
