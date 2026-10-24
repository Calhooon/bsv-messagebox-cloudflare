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
pub(crate) const PUSH_FANOUT_TIMEOUT_MS: u64 = 2_000;

use crate::beef_upload;
use crate::fcm;
use crate::handoff::HandedOff;
use crate::payments;
use crate::storage::{SendContext, Storage};
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

/// One FCM notification a durable row in the `notifications` box owes its
/// recipient's devices (0.6.1, R1 M3): run after the answer like `HubPush`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcmPush {
    pub recipient: String,
    pub message_id: String,
}

/// What a send leaves for after its answer: one `HubPush` per row that
/// landed, in insert order, and one `FcmPush` per landed row of the
/// `notifications` box. A send that stops part way (a duplicate, a D1 fault)
/// still owes the pushes of the rows stored before it, as before.
#[derive(Debug, Default)]
#[must_use]
pub struct AfterAnswer {
    pushes: Vec<HubPush>,
    fcm: Vec<FcmPush>,
}

impl AfterAnswer {
    #[cfg(test)]
    pub(crate) fn of(pushes: Vec<HubPush>) -> Self {
        Self {
            pushes,
            fcm: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn pushes(&self) -> &[HubPush] {
        &self.pushes
    }

    #[cfg(test)]
    pub(crate) fn fcm(&self) -> &[FcmPush] {
        &self.fcm
    }

    pub fn is_empty(&self) -> bool {
        self.pushes.is_empty() && self.fcm.is_empty()
    }

    /// Run the pushes against the real `MESSAGE_HUB` (each raced against
    /// `PUSH_FANOUT_TIMEOUT_MS`) beside the FCM notifications (each raced
    /// against `FCM_DEFERRED_TIMEOUT_MS`). For `ctx.wait_until` /
    /// `state.wait_until`.
    pub async fn run(self, env: Env) {
        let Self { pushes, fcm } = self;
        let hub = WorkerHub { env: env.clone() };
        futures_util::future::join(fan_out(&hub, &pushes), notify_fcm(&env, &fcm)).await;
    }

    /// The hub pushes over any hub (the pins drive a stub).
    #[cfg(test)]
    pub(crate) async fn run_on<H: PushHub>(self, hub: &H) {
        fan_out(hub, &self.pushes).await
    }
}

/// The pushes of one send, concurrently (0.6.1, R1 M2): one chain per
/// recipient hub, the chains joined, so N wedged hubs hold the deferred work
/// one `PUSH_FANOUT_TIMEOUT_MS`, not N of them. Within a chain the pushes keep
/// insert order, so two rows to one recipient reach its hub in the order they
/// were stored (R1 L2). `broadcast.fanout.deferred n=<N>` opens the run and
/// `broadcast.fanout.done n=<N>` closes it: a run the Worker's post-response
/// budget cuts leaves the first line without the second (and each push it cut
/// a `broadcast.fanout.start` without its ok/err/timeout).
async fn fan_out<H: PushHub>(hub: &H, pushes: &[HubPush]) {
    if pushes.is_empty() {
        return;
    }
    let mut chains: Vec<Vec<&HubPush>> = Vec::new();
    for job in pushes {
        match chains.iter_mut().find(|c| c[0].recipient == job.recipient) {
            Some(chain) => chain.push(job),
            None => chains.push(vec![job]),
        }
    }
    let (n, hubs, sender) = (pushes.len(), chains.len(), &pushes[0].sender);
    let t_start = hub.now_ms();
    hub.log(format!(
        "TRACE_PHD broadcast.fanout.deferred n={n} hubs={hubs} sender={sender} t={t_start}"
    ));
    futures_util::future::join_all(chains.into_iter().map(|chain| async move {
        for job in chain {
            push_one(hub, job).await;
        }
    }))
    .await;
    let t_done = hub.now_ms();
    hub.log(format!(
        "TRACE_PHD broadcast.fanout.done n={n} hubs={hubs} sender={sender} t={t_done} ms={}",
        t_done.saturating_sub(t_start)
    ));
}

/// Bound on one FCM notification after the answer (0.6.1, R1 M3). In the
/// request it had none of its own (the client's timeout was its bound); after
/// the answer nothing would end it inside the Worker's post-response budget.
const FCM_DEFERRED_TIMEOUT_MS: u64 = 10_000;

/// The FCM notifications of one send, after its answer, each raced against
/// `FCM_DEFERRED_TIMEOUT_MS`; a failure or a timeout is logged
/// (`fcm.deferred.err` / `fcm.deferred.timeout`), never surfaced.
async fn notify_fcm(env: &Env, fcm: &[FcmPush]) {
    if fcm.is_empty() {
        return;
    }
    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            console_log!("fcm.deferred.err n={} err=D1 binding: {}", fcm.len(), e);
            return;
        }
    };
    let store = Storage::new(&db);
    for job in fcm {
        let sent =
            fcm::send_fcm_notification(&job.recipient, &job.message_id, "New Message", env, &store);
        let timer = Delay::from(Duration::from_millis(FCM_DEFERRED_TIMEOUT_MS));
        match race(sent, timer).await {
            Some(Ok(())) => {}
            Some(Err(e)) => console_log!(
                "fcm.deferred.err recipient={} msgId={} err={}",
                job.recipient,
                job.message_id,
                e
            ),
            None => console_log!(
                "fcm.deferred.timeout recipient={} msgId={} after_ms={}",
                job.recipient,
                job.message_id,
                FCM_DEFERRED_TIMEOUT_MS
            ),
        }
    }
}

/// `Some(work's output)` if `work` ends first, `None` if `timer` does (the
/// work is then dropped, which cancels a subrequest).
pub(crate) async fn race<T>(
    work: impl Future<Output = T>,
    timer: impl Future<Output = ()>,
) -> Option<T> {
    let mut work = std::pin::pin!(work);
    let mut timer = std::pin::pin!(timer);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(r) = work.as_mut().poll(cx) {
            return std::task::Poll::Ready(Some(r));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        std::task::Poll::Pending
    })
    .await
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
    /// Deliver one push; `Err` carries the transport or setup failure, or a
    /// hub that answered other than 2xx.
    fn push(&self, job: &HubPush) -> impl Future<Output = Result<(), String>>;
    /// A future that resolves `ms` after this call.
    fn timer(&self, ms: u64) -> impl Future<Output = ()>;
    fn now_ms(&self) -> u64;
    fn log(&self, line: String);
}

/// The store the write path stores through (0.6.1, R1 M1): D1, the send
/// budget, the payment's settlement and the release of bytes nothing names.
/// The real one is `WorkerStore`; the pins drive `store_send` over a stub, so
/// "every stored row leaves its push, a partial send keeps the earlier rows'
/// pushes, no push runs before the answer" is pinned on the write path itself.
pub(crate) trait SendStore {
    async fn read_send_context(
        &self,
        recipient: &str,
        sender: &str,
        message_box: &str,
    ) -> worker::Result<SendContext>;
    /// The sender's budget for the window; `Err` is the refusal's answer.
    async fn charge(&self, sender: &str, unjudged: u64) -> Result<(), (Value, u16)>;
    async fn settle(
        &self,
        payment: &Value,
        r2_key: Option<&str>,
        fee_map: &[(String, String, i32)],
        delivery_fee: i32,
        sender: &str,
    ) -> Result<payments::Settled, (Value, u16)>;
    async fn get_or_create_message_box(
        &self,
        recipient: &str,
        message_box: &str,
    ) -> worker::Result<i64>;
    /// Store one recipient's row: stored, a duplicate `messageId`, or (the
    /// mailbox, 0.8.1) refused at the recipient's bound with its 429 body.
    async fn insert_message(
        &self,
        message_id: &str,
        box_id: i64,
        sender: &str,
        recipient: &str,
        body: &str,
        beef_key: Option<&str>,
    ) -> worker::Result<Insert>;
    async fn forget_unnamed(
        &self,
        rows_naming: usize,
        handed: &Option<HandedOff>,
        r2_key: Option<&str>,
        failed: bool,
    );
    fn now_ms(&self) -> u64;
    fn log(&self, line: String);
    /// The box switch (0.8.1, `BOXES_OFF`): a send into a box switched off is
    /// refused before anything else of the write path runs.
    fn box_off(&self, _message_box: &str) -> bool {
        false
    }
}

/// What `SendStore::insert_message` did with one row.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Insert {
    /// The row is durable (a retried hop that found its own row included).
    Stored,
    /// The `messageId` is held by another send.
    Duplicate,
    /// The recipient's mailbox is at its bound: the 429
    /// `ERR_INBOX_QUOTA_EXCEEDED` body (`mailbox::full_answer`).
    Full(Value),
}

impl Insert {
    /// The D1 path's answer: `true` stored, `false` a duplicate.
    pub(crate) fn of_d1(stored: bool) -> Self {
        if stored {
            Insert::Stored
        } else {
            Insert::Duplicate
        }
    }
}

/// The Worker's `SendStore`: D1 through `Storage`, the rest through `Env`.
pub(crate) struct WorkerStore<'a, 'db> {
    pub(crate) env: &'a Env,
    pub(crate) store: &'a Storage<'db>,
}

/// The sender's budget for the window on D1 (`send_budget`), the D1 path's
/// and the mailbox path's alike in 0.8.1.
pub(crate) async fn charge_on_d1(
    env: &Env,
    sender: &str,
    unjudged: u64,
) -> Result<(), (Value, u16)> {
    let Ok(db) = env.d1("DB") else {
        return Ok(());
    };
    crate::send_budget::charge(
        &crate::send_budget::D1Windows { db: &db },
        &crate::send_budget::Budget::from_env(env),
        sender,
        Date::now().as_millis() / 1000,
        unjudged,
    )
    .await
}

/// Whether `BOXES_OFF` in the Worker's environment switches `message_box` off.
pub(crate) fn box_off_in_env(env: &Env, message_box: &str) -> bool {
    let raw = env
        .var(crate::hub_store::BOXES_OFF_VAR)
        .ok()
        .map(|v| v.to_string());
    crate::hub_store::box_is_off(raw.as_deref(), message_box)
}

impl SendStore for WorkerStore<'_, '_> {
    async fn read_send_context(
        &self,
        recipient: &str,
        sender: &str,
        message_box: &str,
    ) -> worker::Result<SendContext> {
        self.store
            .read_send_context(recipient, sender, message_box)
            .await
    }

    async fn charge(&self, sender: &str, unjudged: u64) -> Result<(), (Value, u16)> {
        charge_on_d1(self.env, sender, unjudged).await
    }

    async fn settle(
        &self,
        payment: &Value,
        r2_key: Option<&str>,
        fee_map: &[(String, String, i32)],
        delivery_fee: i32,
        sender: &str,
    ) -> Result<payments::Settled, (Value, u16)> {
        payments::process_payment(payment, r2_key, fee_map, delivery_fee, sender, self.env).await
    }

    async fn get_or_create_message_box(
        &self,
        recipient: &str,
        message_box: &str,
    ) -> worker::Result<i64> {
        self.store
            .get_or_create_message_box(recipient, message_box)
            .await
    }

    async fn insert_message(
        &self,
        message_id: &str,
        box_id: i64,
        sender: &str,
        recipient: &str,
        body: &str,
        beef_key: Option<&str>,
    ) -> worker::Result<Insert> {
        self.store
            .insert_message(message_id, box_id, sender, recipient, body, beef_key)
            .await
            .map(Insert::of_d1)
    }

    async fn forget_unnamed(
        &self,
        rows_naming: usize,
        handed: &Option<HandedOff>,
        r2_key: Option<&str>,
        failed: bool,
    ) {
        payments::forget_unnamed(self.env, rows_naming, handed, r2_key, failed).await
    }

    fn now_ms(&self) -> u64 {
        Date::now().as_millis()
    }

    fn log(&self, line: String) {
        console_log!("{}", line);
    }

    fn box_off(&self, message_box: &str) -> bool {
        box_off_in_env(self.env, message_box)
    }
}

/// Map a `worker::Error` bubbled out of the D1 read/write helpers onto the right
/// send outcome: the bounded retry loops only ever propagate a TRANSIENT error
/// after exhausting their attempts (a genuine error short-circuits without
/// retry), so a transient class here means "D1 momentarily unavailable" →
/// client-retryable, whereas anything else is a real internal fault.
pub(crate) fn classify_store_error(e: worker::Error) -> SendOutcome {
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

/// The listing's and the acknowledge's answer to a storage error (message box
/// #22 (a)): the send path's own classification and wire words, so a transient
/// D1 failure is 503 `ERR_D1_UNAVAILABLE` there too (`Retry-After` is added
/// where the answer is built, `retry_after`). `None` is a real fault: the
/// route keeps its own 500.
pub(crate) fn transient_store_answer(e: worker::Error) -> Option<(Value, u16)> {
    match classify_store_error(e) {
        outcome @ SendOutcome::TransientError { .. } => Some(outcome_to_http(outcome)),
        _ => None,
    }
}

/// The seconds a client waits before it retries a 503 `ERR_D1_UNAVAILABLE`
/// (the `Retry-After` header): one second, against a bounded failure that
/// already spent up to `storage::stalled_read_worst_ms` (6,150 ms) in the relay.
pub(crate) const D1_UNAVAILABLE_RETRY_AFTER_SECS: &str = "1";

/// The `Retry-After` value an answer carries: every 503 `ERR_D1_UNAVAILABLE`
/// (the send's, the listing's and the acknowledge's), and nothing else.
pub(crate) fn retry_after(body: &Value, status: u16) -> Option<&'static str> {
    (status == 503 && body["code"] == "ERR_D1_UNAVAILABLE")
        .then_some(D1_UNAVAILABLE_RETRY_AFTER_SECS)
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
///
/// The store is the router's (0.8.1, `hub_store`): under `HUB_STORE = "sql"`
/// the rows land in each recipient hub's mailbox (`MailboxSendStore`); under
/// `kv` (the default) and `kv-drain` they land in D1 as before. A refused
/// `HUB_STORE` stores nothing and answers its typed 500.
pub async fn process_send(
    validated: ValidatedSendMessage,
    sender_key: &str,
    env: &Env,
    store: &Storage<'_>,
) -> Sent {
    use crate::hub_store::{refused_boot_answer, HubStore, StorePath};
    match HubStore::from_env(env).map(HubStore::send_path) {
        Err(value) => {
            let (body, status) = refused_boot_answer(&value);
            Sent {
                outcome: SendOutcome::ValidationError { body, status },
                after: AfterAnswer::default(),
            }
        }
        Ok(StorePath::Mailbox) => {
            let mailbox = crate::message_hub_sql::MailboxSendStore {
                worker: WorkerStore { env, store },
                message_box: validated.message_box.clone(),
            };
            store_send(validated, sender_key, &mailbox).await
        }
        Ok(_) => store_send(validated, sender_key, &WorkerStore { env, store }).await,
    }
}

/// `process_send`'s body over any `SendStore`: every row it stores leaves its
/// push (and, in the `notifications` box, its FCM notification) in `after`,
/// and none of them runs here.
pub(crate) async fn store_send<S: SendStore>(
    validated: ValidatedSendMessage,
    sender_key: &str,
    store: &S,
) -> Sent {
    let mut after = AfterAnswer::default();
    let outcome = store_rows(validated, sender_key, store, &mut after).await;
    Sent { outcome, after }
}

async fn store_rows<S: SendStore>(
    validated: ValidatedSendMessage,
    sender_key: &str,
    store: &S,
    after: &mut AfterAnswer,
) -> SendOutcome {
    // -- 0. The box switch (0.8.1; LOW's design 2026-10-23 section 2.4): a
    //       send into a box named in BOXES_OFF is refused here, before the
    //       context read, the budget and any store, on every transport. --
    if store.box_off(&validated.message_box) {
        let (body, status) = crate::hub_store::box_off_answer(&validated.message_box);
        return SendOutcome::ValidationError { body, status };
    }

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
        let t_ctx_start = store.now_ms();
        let ctx = match store
            .read_send_context(recipient, sender_key, &validated.message_box)
            .await
        {
            Ok(c) => c,
            Err(e) => return classify_store_error(e),
        };
        store.log(format!(
            "TRACE_LAT send.read_ctx recipient={} ms={}",
            recipient,
            store.now_ms().saturating_sub(t_ctx_start)
        ));
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
    let payment_text = match (&validated.payment, delivery_fee > 0) {
        (Some(payment), false) => payment.to_string().len(),
        _ => 0,
    };
    let unjudged = (validated.body.to_string().len() + payment_text) as u64;
    if let Err((body, status)) = store.charge(sender_key, unjudged).await {
        return SendOutcome::ValidationError { body, status };
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

                match store
                    .settle(
                        payment,
                        r2_key.as_deref(),
                        &fee_map,
                        delivery_fee,
                        sender_key,
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
                let t_box_start = store.now_ms();
                let r = store
                    .get_or_create_message_box(recipient, &validated.message_box)
                    .await;
                store.log(format!(
                    "TRACE_LAT send.get_or_create_box recipient={} ms={}",
                    recipient,
                    store.now_ms().saturating_sub(t_box_start)
                ));
                match r {
                    Ok(id) => id,
                    Err(e) => {
                        store
                            .forget_unnamed(rows_naming, &handed, r2_key.as_deref(), true)
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

        let t_ins_start = store.now_ms();
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
        store.log(format!(
            "TRACE_LAT send.insert_message recipient={} msgId={} ms={} dup={}",
            recipient,
            message_id,
            store.now_ms().saturating_sub(t_ins_start),
            matches!(&ins, Ok(Insert::Duplicate))
        ));
        match ins {
            Ok(Insert::Stored) => {}
            Ok(Insert::Duplicate) => {
                store
                    .forget_unnamed(rows_naming, &handed, r2_key.as_deref(), true)
                    .await;
                return SendOutcome::DuplicateMessage {
                    recipient: recipient.clone(),
                    message_id: message_id.clone(),
                };
            }
            // The recipient's mailbox is full (0.8.1, the design's section
            // 4): refused at this recipient, the rows before it kept, as a
            // duplicate or a fault keeps them.
            Ok(Insert::Full(body)) => {
                store
                    .forget_unnamed(rows_naming, &handed, r2_key.as_deref(), true)
                    .await;
                return SendOutcome::ValidationError { body, status: 429 };
            }
            Err(e) => {
                store
                    .forget_unnamed(rows_naming, &handed, r2_key.as_deref(), true)
                    .await;
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

        // FCM — only for the notifications box. Recorded here, run after the
        // answer beside the hub pushes (0.6.1, R1 M3), its own bound kept.
        if fcm::should_use_fcm_delivery(&validated.message_box) {
            after.fcm.push(FcmPush {
                recipient: recipient.clone(),
                message_id: message_id.clone(),
            });
        }
    }

    // -- 5. The bytes stay at rest while a row or a deferred fee names them
    //       (`HandedOff::kept`). An object nothing names goes, best-effort. --
    store
        .forget_unnamed(rows_naming, &handed, r2_key.as_deref(), false)
        .await;

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

        let namespace = crate::hub_store::hub_namespace(&self.env)
            .map_err(|e| format!("hub binding lookup failed: {e}"))?;
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
        let resp = stub
            .fetch_with_request(req)
            .await
            .map_err(|e| e.to_string())?;
        hub_reply(resp.status_code())
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

/// A hub's reply to `/internal/push`: 2xx delivered, anything else (the hub's
/// 400 on bad JSON, a 5xx) is a `broadcast.fanout.err`, not an ok (R1 L1).
fn hub_reply(status: u16) -> Result<(), String> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("hub answered {status}"))
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
    let push_result = race(hub.push(job), hub.timer(PUSH_FANOUT_TIMEOUT_MS)).await;
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

    /// A stub hub on a virtual clock: a timer asked for `ms` at virtual time
    /// `t` moves the clock to `t + ms` when it fires (R1 L3), so a timeout
    /// line's `t=` is the virtual time elapsed, and pushes raced together end
    /// at one bound, pushes chained end at the sum (R1 M2).
    pub(crate) struct StubHub {
        pub(crate) log: Log,
        pub(crate) answer: Answer,
        pub(crate) calls: Cell<usize>,
        pub(crate) clock: Rc<Cell<u64>>,
        pub(crate) timers_ms: RefCell<Vec<u64>>,
    }

    impl StubHub {
        pub(crate) fn new(log: Log, answer: Answer) -> Self {
            Self {
                log,
                answer,
                calls: Cell::new(0),
                clock: Rc::new(Cell::new(0)),
                timers_ms: RefCell::new(Vec::new()),
            }
        }
    }

    /// `Answer::Never`'s timer: pending on its first poll (so every push of a
    /// joined run has started before any timer fires), then fires and moves
    /// the clock to its deadline.
    struct VirtualTimer {
        clock: Rc<Cell<u64>>,
        deadline: u64,
        polled: bool,
    }

    impl Future for VirtualTimer {
        type Output = ();
        fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if !self.polled {
                self.polled = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.clock.set(self.clock.get().max(self.deadline));
            Poll::Ready(())
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

        fn timer(&self, ms: u64) -> impl Future<Output = ()> {
            self.timers_ms.borrow_mut().push(ms);
            let fires = matches!(self.answer, Answer::Never);
            let timer = VirtualTimer {
                clock: self.clock.clone(),
                deadline: self.clock.get() + ms,
                polled: false,
            };
            async move {
                if fires {
                    timer.await
                } else {
                    std::future::pending::<()>().await
                }
            }
        }

        fn now_ms(&self) -> u64 {
            self.clock.get()
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
    // before the hub is touched, and the push's timeout is logged after it,
    // at the virtual bound (an ordering pin over a stub clock, R1 L3).
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
        // R1 L3: the race asked for PUSH_FANOUT_TIMEOUT_MS and took the timer
        // arm at the virtual 2,000 ms; a stub cannot show wall time elapse.
        assert_eq!(*hub.timers_ms.borrow(), vec![PUSH_FANOUT_TIMEOUT_MS]);
        assert!(log[timeout].contains("t=2000 "), "{}", log[timeout]);
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
        assert!(path.contains("Ok(Insert::Duplicate) =>") && path.contains("DuplicateMessage {"));
        assert!(
            !path.contains("push_to_recipient_sockets("),
            "the duplicate return must not wait on the pushes of the rows before it"
        );
        let hub = include_str!("../message_hub.rs");
        assert!(hub.contains("\"Duplicate->sendMessageAck"));
    }
}

/// R1 (M28A-DECOUPLE-R1-2026-10-20): the write path driven for real through a
/// `SendStore` stub (M1), the concurrent fan-out (M2), FCM after the answer
/// (M3) and a non-2xx hub reply (L1).
#[cfg(test)]
mod decouple_r1_tests {
    use super::test_hub::*;
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A store whose every row lands but the one named a duplicate (or the
    /// one named a D1 fault); the send owes no fee.
    struct StubStore {
        log: Log,
        dup: Option<&'static str>,
        fault: Option<&'static str>,
        /// 0.8.1: the row whose recipient's mailbox is full.
        full: Option<&'static str>,
        /// 0.8.1: the box `BOXES_OFF` names.
        off: Option<&'static str>,
    }

    impl StubStore {
        fn new(log: Log) -> Self {
            Self {
                log,
                dup: None,
                fault: None,
                full: None,
                off: None,
            }
        }
    }

    impl SendStore for StubStore {
        async fn read_send_context(
            &self,
            _recipient: &str,
            _sender: &str,
            _message_box: &str,
        ) -> worker::Result<SendContext> {
            self.log.borrow_mut().push("context".into());
            Ok(SendContext {
                recipient_fee: 0,
                server_fee: 0,
                box_id: Some(1),
            })
        }

        async fn charge(&self, _sender: &str, _unjudged: u64) -> Result<(), (Value, u16)> {
            self.log.borrow_mut().push("charge".into());
            Ok(())
        }

        async fn settle(
            &self,
            _payment: &Value,
            _r2_key: Option<&str>,
            _fee_map: &[(String, String, i32)],
            _delivery_fee: i32,
            _sender: &str,
        ) -> Result<payments::Settled, (Value, u16)> {
            panic!("a send that owes no fee settles nothing")
        }

        async fn get_or_create_message_box(
            &self,
            _recipient: &str,
            _message_box: &str,
        ) -> worker::Result<i64> {
            Ok(1)
        }

        async fn insert_message(
            &self,
            message_id: &str,
            _box_id: i64,
            _sender: &str,
            _recipient: &str,
            _body: &str,
            _beef_key: Option<&str>,
        ) -> worker::Result<Insert> {
            if self.fault == Some(message_id) {
                return Err(worker::Error::RustError("D1 write failed".into()));
            }
            if self.full == Some(message_id) {
                self.log
                    .borrow_mut()
                    .push(format!("insert {message_id} full"));
                return Ok(Insert::Full(
                    crate::mailbox::full_answer(
                        &crate::mailbox::Full {
                            resource: "messages".into(),
                            limit: 10_000,
                            held: 10_000,
                        },
                        _recipient,
                    )
                    .0,
                ));
            }
            let stored = self.dup != Some(message_id);
            self.log
                .borrow_mut()
                .push(format!("insert {message_id} stored={stored}"));
            Ok(Insert::of_d1(stored))
        }

        async fn forget_unnamed(
            &self,
            _rows_naming: usize,
            _handed: &Option<HandedOff>,
            _r2_key: Option<&str>,
            _failed: bool,
        ) {
        }

        fn now_ms(&self) -> u64 {
            0
        }

        fn log(&self, _line: String) {}

        fn box_off(&self, message_box: &str) -> bool {
            self.off == Some(message_box)
        }
    }

    fn send(message_box: &str, rows: &[(&str, &str)]) -> ValidatedSendMessage {
        ValidatedSendMessage {
            recipients: rows
                .iter()
                .map(|(r, m)| (r.to_string(), m.to_string()))
                .collect(),
            message_box: message_box.into(),
            body: json!("hi"),
            payment: None,
        }
    }

    fn ids(after: &AfterAnswer) -> Vec<&str> {
        after
            .pushes()
            .iter()
            .map(|p| p.message_id.as_str())
            .collect()
    }

    // M1: a real send through the write path, two recipients, the second a
    // duplicate. The answer is ERR_DUPLICATE_MESSAGE, `after` holds exactly
    // the first row's push, and with a hub that never answers the answer is
    // formed before the hub is touched and the push's timeout follows it.
    #[test]
    fn m1_a_partial_send_answers_first_and_keeps_the_earlier_rows_push() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut store = StubStore::new(log.clone());
        store.dup = Some("m2");
        let hub = StubHub::new(log.clone(), Answer::Never);
        let sent = block_on(store_send(
            send("low_game_x", &[("R1", "m1"), ("R2", "m2")]),
            "S",
            &store,
        ));
        assert!(matches!(
            sent.outcome,
            SendOutcome::DuplicateMessage { ref message_id, .. } if message_id == "m2"
        ));
        assert_eq!(ids(&sent.after), vec!["m1"]);
        assert_eq!(sent.after.pushes()[0].recipient, "R1");

        let mut deferred = None;
        let (body, status) = answer_then_defer(sent, |a| deferred = Some(a));
        log.borrow_mut().push("send.answered".into());
        assert_eq!(
            (status, &body["code"]),
            (400, &json!("ERR_DUPLICATE_MESSAGE"))
        );
        assert_eq!(hub.calls.get(), 0, "no push runs inside the write path");

        block_on(
            deferred
                .expect("the stored row's push is owed")
                .run_on(&hub),
        );
        let log = log.borrow();
        assert!(at(&log, "insert m2 stored=false") < at(&log, "send.answered"));
        assert!(
            at(&log, "send.answered") < at(&log, "broadcast.fanout.timeout recipient=R1 msgId=m1"),
            "{log:#?}"
        );
        assert!(!log
            .iter()
            .any(|l| l.contains("msgId=m2") && l.contains("fanout")));
    }

    // M1: a D1 fault part way keeps the earlier rows' pushes too; a full
    // send owes one push per row, in insert order; a lone duplicate none.
    #[test]
    fn m1_every_stored_row_leaves_its_push_and_nothing_else_does() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut store = StubStore::new(log.clone());
        store.fault = Some("m3");
        let sent = block_on(store_send(
            send("low_game_x", &[("R1", "m1"), ("R2", "m2"), ("R3", "m3")]),
            "S",
            &store,
        ));
        assert!(matches!(sent.outcome, SendOutcome::InternalError { .. }));
        assert_eq!(ids(&sent.after), vec!["m1", "m2"]);

        let store = StubStore::new(log.clone());
        let sent = block_on(store_send(
            send("low_game_x", &[("R1", "m1"), ("R2", "m2")]),
            "S",
            &store,
        ));
        assert!(matches!(sent.outcome, SendOutcome::Success { ref results } if results.len() == 2));
        assert_eq!(ids(&sent.after), vec!["m1", "m2"]);
        assert!(sent.after.fcm().is_empty(), "no FCM outside notifications");

        let mut store = StubStore::new(log);
        store.dup = Some("m1");
        let sent = block_on(store_send(send("low_game_x", &[("R1", "m1")]), "S", &store));
        assert!(sent.after.is_empty(), "a lone duplicate owes nothing");
    }

    // M2: the pushes of one send run concurrently under the one deferral: two
    // wedged hubs end at one bound (virtual t=2000), not two (t=4000); the
    // run opens with `broadcast.fanout.deferred n=2` and closes with
    // `broadcast.fanout.done n=2`. L2: two rows to one recipient stay chained
    // in insert order.
    #[test]
    fn m2_the_pushes_of_one_send_are_joined_and_bracketed() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let hub = StubHub::new(log.clone(), Answer::Never);
        block_on(AfterAnswer::of(vec![job("R1", "m1"), job("R2", "m2")]).run_on(&hub));
        {
            let log = log.borrow();
            let opened = at(&log, "broadcast.fanout.deferred n=2 hubs=2");
            let s1 = at(&log, "broadcast.fanout.start recipient=R1");
            let s2 = at(&log, "broadcast.fanout.start recipient=R2");
            let t1 = at(&log, "broadcast.fanout.timeout recipient=R1");
            assert!(
                opened < s1 && s2 < t1,
                "both start before either times out: {log:#?}"
            );
            for r in ["R1", "R2"] {
                let line = &log[at(&log, &format!("broadcast.fanout.timeout recipient={r}"))];
                assert!(line.contains("t=2000 "), "{line}");
            }
            let done = at(&log, "broadcast.fanout.done n=2 hubs=2");
            assert!(log[done].contains("ms=2000"), "{}", log[done]);
        }

        log.borrow_mut().clear();
        let hub = StubHub::new(log.clone(), Answer::Never);
        block_on(AfterAnswer::of(vec![job("R1", "m1"), job("R1", "m2")]).run_on(&hub));
        let log = log.borrow();
        assert!(at(&log, "broadcast.fanout.deferred n=2 hubs=1") == 0);
        let first = at(&log, "broadcast.fanout.timeout recipient=R1 msgId=m1");
        let second = at(&log, "broadcast.fanout.start recipient=R1 msgId=m2");
        assert!(first < second, "one recipient's pushes keep insert order");
        assert!(
            log[at(&log, "broadcast.fanout.timeout recipient=R1 msgId=m2")].contains("t=4000 ")
        );
    }

    // M3: a notifications-box send owes its FCM after the answer; the write
    // path records it beside the hub push and calls no FCM itself.
    #[test]
    fn m3_the_notifications_box_fcm_is_owed_after_the_answer() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut store = StubStore::new(log);
        store.dup = Some("m2");
        let sent = block_on(store_send(
            send("notifications", &[("R1", "m1"), ("R2", "m2")]),
            "S",
            &store,
        ));
        assert_eq!(
            sent.after.fcm(),
            &[FcmPush {
                recipient: "R1".into(),
                message_id: "m1".into(),
            }]
        );
        assert_eq!(ids(&sent.after), vec!["m1"]);
        let mut deferred = None;
        let (_, status) = answer_then_defer(sent, |a| deferred = Some(a));
        assert_eq!(status, 400);
        assert_eq!(deferred.expect("the FCM is deferred").fcm().len(), 1);
        let path = include_str!("send_message.rs");
        let rows = &path[path.find("async fn store_rows<").unwrap()
            ..path.find("pub fn outcome_to_http(").unwrap()];
        assert!(!rows.contains("send_fcm_notification("));
    }

    // L1: only a 2xx from the hub is a delivery; its 400 (bad JSON) or a 5xx
    // is a `broadcast.fanout.err`.
    #[test]
    fn l1_a_non_2xx_hub_reply_is_an_error() {
        assert_eq!(hub_reply(200), Ok(()));
        assert_eq!(hub_reply(204), Ok(()));
        assert_eq!(hub_reply(400), Err("hub answered 400".into()));
        assert_eq!(hub_reply(500), Err("hub answered 500".into()));
    }

    // 0.8.1, the box switch: a send into a box BOXES_OFF names is refused 403
    // ERR_BOX_OFF before the context read, the budget and any store, so a
    // refused send spends no budget; the same send with the box on charges.
    #[test]
    fn a_send_into_a_box_switched_off_is_refused_before_the_budget() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut store = StubStore::new(log.clone());
        store.off = Some("webrtc_signal");
        let sent = block_on(store_send(
            send("webrtc_signal", &[("R1", "m1"), ("R2", "m2")]),
            "S",
            &store,
        ));
        assert!(sent.after.is_empty(), "nothing stored, nothing owed");
        let (body, status) = outcome_to_http(sent.outcome);
        assert_eq!(status, 403);
        assert_eq!(
            body,
            json!({
                "status": "error",
                "code": "ERR_BOX_OFF",
                "description": "box webrtc_signal is off",
            })
        );
        assert!(
            log.borrow().is_empty(),
            "no context read, no charge, no insert: {:?}",
            log.borrow()
        );

        // Another box is served, and charged, as before.
        let sent = block_on(store_send(send("low_game_x", &[("R1", "m1")]), "S", &store));
        assert!(matches!(sent.outcome, SendOutcome::Success { .. }));
        assert_eq!(
            *log.borrow(),
            vec!["context", "charge", "insert m1 stored=true"]
        );
    }

    // 0.8.1, the box switch's absence: no BOXES_OFF switches nothing off.
    #[test]
    fn without_the_var_no_box_is_off() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let store = StubStore::new(log.clone());
        let sent = block_on(store_send(
            send("webrtc_signal", &[("R1", "m1")]),
            "S",
            &store,
        ));
        assert!(matches!(sent.outcome, SendOutcome::Success { .. }));
        assert!(log.borrow().contains(&"charge".to_string()));
        assert!(!crate::hub_store::box_is_off(None, "webrtc_signal"));
    }

    // 0.8.1, the full mailbox: the send is refused at the recipient whose
    // mailbox is full with the reference's 429; the rows before it stay and
    // keep their pushes, as a duplicate's do.
    #[test]
    fn a_full_mailbox_answers_429_at_its_recipient_and_keeps_the_earlier_rows() {
        let log: Log = Rc::new(RefCell::new(Vec::new()));
        let mut store = StubStore::new(log.clone());
        store.full = Some("m2");
        let sent = block_on(store_send(
            send("low_game_x", &[("R1", "m1"), ("R2", "m2"), ("R3", "m3")]),
            "S",
            &store,
        ));
        assert_eq!(ids(&sent.after), vec!["m1"]);
        let (body, status) = outcome_to_http(sent.outcome);
        assert_eq!(status, 429);
        assert_eq!(body["code"], "ERR_INBOX_QUOTA_EXCEEDED");
        assert_eq!(body["recipient"], "R2");
        assert_eq!(body["resource"], "messages");
        assert_eq!(body["freedBy"], "acknowledgeMessage");
        assert!(!log.borrow().iter().any(|l| l.contains("m3")));
    }
}
