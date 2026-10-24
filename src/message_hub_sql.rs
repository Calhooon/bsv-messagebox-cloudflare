//! `MessageHubSql` (0.8.1, R2 of the relay mailbox): the per-identity hub on
//! the SQLite backend, the recipient's mailbox beside everything `MessageHub`
//! does (bsv-stack-lean `docs/p0/mbx-hot-path-m28a.md`, sections 4, 5, 6, 9).
//!
//! A KV-backed class cannot gain SQLite storage in place, so the mailbox is a
//! new class (migration `v5`, `new_sqlite_classes`). It wraps a `MessageHub`
//! over its own state: the sockets, the socket.io registry, the presence and
//! the session mirrors run unchanged (the SQLite backend serves the hub's
//! key-value calls too), and the class adds:
//!
//! - the mailbox (`mailbox`, its statements in `mailbox::schema`): a send's
//!   row, the two counters read on every send, the full mailbox's 429;
//! - the permissions copy a send's context reads;
//! - the archive routes: every change of a row is enqueued to `ARCHIVE_QUEUE`
//!   after the answer (R1's message, read by `archive::consume`), replayed by
//!   the next request past 120 s, read back by `/internal/archive-read` for a
//!   body too long for a queue message, and confirmed by `/internal/archive-done`;
//! - the legacy merge: a listing or an acknowledgment asks D1 for the rows the
//!   old path holds for the box, merged by id, the mailbox's row winning;
//! - the forwarded session read: a lane mirror this hub lacks is taken once
//!   from the identity's `MessageHub` (`/internal/session-take`) and kept.
//!
//! Under `HUB_STORE = "kv"` (the default) no request reaches this class
//! (`hub_store`). Every fetch it serves logs one `hub_sql.fetch` line, the
//! count the zero-fetch proof reads.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{json, Value};
use worker::*;

use crate::hub_forward::{with_do_op_timeout, FORWARD_OP_TIMEOUT_MS};
use crate::mailbox::{self, Bounds, Done, Inserted, MailboxSql, MergeOrder, NewRow, Val};
use crate::message_hub::{MessageHub, SessionVerifyBody};
use crate::routes::send_message::{Insert, SendStore, WorkerStore};
use crate::session_lane::HubMirror;
use crate::storage::{MessageDbRow, SendContext, Storage};

/// The SQLite storage of a Durable Object as the mailbox's `MailboxSql`.
struct DoSql(worker::SqlStorage);

impl MailboxSql for DoSql {
    fn run(&self, sql: &str, params: &[Val]) -> std::result::Result<Vec<Vec<Val>>, String> {
        let binds: Vec<SqlStorageValue> = params
            .iter()
            .map(|v| match v {
                Val::Null => SqlStorageValue::Null,
                Val::Int(i) => SqlStorageValue::Integer(*i),
                Val::Text(s) => SqlStorageValue::String(s.clone()),
            })
            .collect();
        let cursor = self.0.exec(sql, binds).map_err(|e| e.to_string())?;
        cursor
            .raw()
            .map(|row| {
                row.map_err(|e| e.to_string()).map(|cols| {
                    cols.into_iter()
                        .map(|c| match c {
                            SqlStorageValue::Null => Val::Null,
                            SqlStorageValue::Boolean(b) => Val::Int(i64::from(b)),
                            SqlStorageValue::Integer(i) => Val::Int(i),
                            SqlStorageValue::Float(f) => Val::Int(f as i64),
                            SqlStorageValue::String(s) => Val::Text(s),
                            SqlStorageValue::Blob(b) => {
                                Val::Text(String::from_utf8_lossy(&b).into_owned())
                            }
                        })
                        .collect()
                })
            })
            .collect()
    }
}

#[durable_object]
pub struct MessageHubSql {
    /// Everything `MessageHub` does, over this object's state.
    hub: MessageHub,
    sql: DoSql,
    env: Env,
    /// The layout was made on this instance (`mailbox::ensure_schema`).
    schema_ready: std::cell::Cell<bool>,
}

impl DurableObject for MessageHubSql {
    fn new(state: State, env: Env) -> Self {
        let sql = DoSql(state.storage().sql());
        let hub = <MessageHub as DurableObject>::new(state, env.clone());
        Self {
            hub,
            sql,
            env,
            schema_ready: std::cell::Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.url()?.path().to_string();
        console_log!("hub_sql.fetch path={}", path);
        let post = req.method() == Method::Post;
        match path.as_str() {
            "/internal/mailbox/context" if post => self.handle_context(&mut req).await,
            "/internal/mailbox/insert" if post => self.handle_insert(&mut req).await,
            "/internal/mailbox/list" if post => self.handle_list(&mut req).await,
            "/internal/mailbox/ack" if post => self.handle_ack(&mut req).await,
            "/internal/mailbox/permissions-forget" if post => {
                self.handle_permissions_forget(&mut req).await
            }
            "/internal/archive-read" if req.method() == Method::Get => {
                self.handle_archive_read(&req)
            }
            "/internal/archive-done" if post => self.handle_archive_done(&mut req).await,
            "/internal/session-verify" if post => self.handle_session_verify(&mut req).await,
            _ => DurableObject::fetch(&self.hub, req).await,
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        DurableObject::websocket_message(&self.hub, ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> Result<()> {
        DurableObject::websocket_close(&self.hub, ws, code, reason, was_clean).await
    }

    async fn websocket_error(&self, ws: WebSocket, error: Error) -> Result<()> {
        DurableObject::websocket_error(&self.hub, ws, error).await
    }

    async fn alarm(&self) -> Result<Response> {
        DurableObject::alarm(&self.hub).await
    }
}

/// A mailbox route's body: the identity the hub serves rides on every one.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContextBody {
    identity: String,
    sender: String,
    message_box: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InsertBody {
    identity: String,
    row: NewRow,
    #[serde(default)]
    retry: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListBody {
    identity: String,
    message_box: String,
    /// `sql`: merge the D1 rows of the box here. `kv-drain`: the caller holds
    /// the D1 rows and asks which of `against` this mailbox holds.
    legacy: bool,
    #[serde(default)]
    against: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AckBody {
    identity: String,
    message_ids: Vec<String>,
    legacy: bool,
    #[serde(default)]
    retry: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityBody {
    identity: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DoneBody {
    identity: String,
    done: Vec<Done>,
}

fn now_ms() -> u64 {
    Date::now().as_millis()
}

fn answer(v: Value) -> Result<Response> {
    Response::from_json(&v)
}

fn refuse(status: u16, why: impl std::fmt::Display) -> Result<Response> {
    Response::from_json(&json!({ "error": why.to_string() })).map(|r| r.with_status(status))
}

impl MessageHubSql {
    /// The layout, once per instance, and the identity check. `Err` answers.
    fn ready(&self, identity: &str) -> std::result::Result<(), String> {
        if !self.schema_ready.get() {
            mailbox::ensure_schema(&self.sql)?;
            self.schema_ready.set(true);
        }
        // The identity as the hub id names it (`idFromName`), the D1 path's
        // `recipient` column as stored: neither is case-folded.
        mailbox::bind_identity(&self.sql, identity)
    }

    /// Whether this hub ever made its mailbox (a `kv-drain` read of a hub
    /// that never held a row creates nothing).
    fn has_mailbox(&self) -> bool {
        self.schema_ready.get()
            || self
                .sql
                .run(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mailbox_rows'",
                    &[],
                )
                .map(|r| !r.is_empty())
                .unwrap_or(false)
    }

    /// The identity's archive messages for `rows`, handed to the queue after
    /// the answer. A row the queue refuses stays owed (`enqueued_at` already
    /// set): the replay hands it again past `REPLAY_AFTER_MS`.
    fn enqueue_after(&self, identity: &str, rows: Vec<mailbox::ArchiveRow>) {
        if rows.is_empty() {
            return;
        }
        let msgs: Vec<crate::archive::ArchiveMessage> = rows
            .iter()
            .map(|r| mailbox::archive_message(r, identity))
            .collect();
        let env = self.env.clone();
        self.hub.state().wait_until(async move {
            enqueue(&env, &msgs).await;
        });
    }

    /// E12, inside a request the hub is already serving.
    fn replay(&self, identity: &str) {
        match mailbox::take_owed_due(&self.sql, now_ms()) {
            Ok(rows) => {
                if !rows.is_empty() {
                    console_log!("archive.replay n={}", rows.len());
                }
                self.enqueue_after(identity, rows);
            }
            Err(e) => console_log!("archive.replay.err {}", e),
        }
    }

    async fn handle_context(&self, req: &mut Request) -> Result<Response> {
        let b: ContextBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("context body: {e}")),
        };
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        let now = now_ms();
        match mailbox::permissions_copy(&self.sql, &b.sender, &b.message_box, now) {
            Ok(Some((recipient_fee, server_fee))) => {
                return answer(json!({ "recipientFee": recipient_fee, "serverFee": server_fee }))
            }
            Ok(None) => {}
            Err(e) => return refuse(500, e),
        }
        let db = self.env.d1("DB")?;
        let ctx = Storage::new(&db)
            .read_send_context(&b.identity, &b.sender, &b.message_box)
            .await;
        match ctx {
            Ok(ctx) => {
                if let Err(e) = mailbox::keep_permissions(
                    &self.sql,
                    &b.sender,
                    &b.message_box,
                    ctx.recipient_fee,
                    ctx.server_fee,
                    now,
                ) {
                    console_log!("mailbox.permissions.keep.err {}", e);
                }
                answer(json!({ "recipientFee": ctx.recipient_fee, "serverFee": ctx.server_fee }))
            }
            Err(e) => refuse(503, format!("permissions read from D1: {e}")),
        }
    }

    async fn handle_insert(&self, req: &mut Request) -> Result<Response> {
        let b: InsertBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("insert body: {e}")),
        };
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        self.replay(&b.identity);
        let inserted = match mailbox::insert(&self.sql, &b.row, b.retry, now_ms(), Bounds::RULED) {
            Ok(i) => i,
            Err(e) => return refuse(500, format!("mailbox insert: {e}")),
        };
        match inserted {
            Inserted::Stored => {
                match mailbox::archive_rows(&self.sql, std::slice::from_ref(&b.row.message_id)) {
                    Ok(rows) => self.enqueue_after(&b.identity, rows),
                    Err(e) => console_log!("archive.enqueue.read.err {}", e),
                }
                answer(json!({ "result": "stored" }))
            }
            Inserted::Retried => answer(json!({ "result": "stored", "retried": true })),
            Inserted::Duplicate => answer(json!({ "result": "duplicate" })),
            Inserted::Full(full) => {
                console_log!(
                    "mailbox.full recipient={} resource={} held={} limit={}",
                    b.identity,
                    full.resource,
                    full.held,
                    full.limit
                );
                let (body, _) = mailbox::full_answer(&full, &b.identity);
                answer(json!({ "result": "full", "answer": body }))
            }
        }
    }

    async fn handle_list(&self, req: &mut Request) -> Result<Response> {
        let b: ListBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("list body: {e}")),
        };
        if !b.legacy && !self.has_mailbox() {
            return answer(json!({ "messages": [], "held": [] }));
        }
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        self.replay(&b.identity);
        let rows = match mailbox::list(
            &self.sql,
            &b.message_box,
            mailbox::LIST_LIMIT,
            crate::handoff::LIST_INLINE_BYTES,
        ) {
            Ok(r) => r,
            Err(e) => return refuse(500, format!("mailbox list: {e}")),
        };
        if !b.legacy {
            let held = match mailbox::held_ids(&self.sql, &b.against) {
                Ok(h) => h,
                Err(e) => return refuse(500, format!("mailbox held: {e}")),
            };
            return answer(
                json!({ "messages": rows, "held": held.into_iter().collect::<Vec<_>>() }),
            );
        }
        // The legacy merge: the rows the old path stored for this box.
        let db = self.env.d1("DB")?;
        let d1 = match Storage::new(&db)
            .list_messages(&b.identity, &b.message_box)
            .await
        {
            Ok(r) => r,
            Err(e) => return legacy_refusal("list", e),
        };
        let ids: Vec<String> = d1.iter().filter_map(|r| r.message_id.clone()).collect();
        let held = match mailbox::held_ids(&self.sql, &ids) {
            Ok(h) => h,
            Err(e) => return refuse(500, format!("mailbox held: {e}")),
        };
        let merged = mailbox::merge(
            d1,
            rows,
            &held,
            MergeOrder::D1First,
            mailbox::LIST_LIMIT,
            crate::handoff::LIST_INLINE_BYTES,
        );
        answer(json!({ "messages": merged }))
    }

    async fn handle_ack(&self, req: &mut Request) -> Result<Response> {
        let b: AckBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("ack body: {e}")),
        };
        if !b.legacy && !self.has_mailbox() {
            return answer(json!({ "acknowledged": 0, "missing": b.message_ids }));
        }
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        self.replay(&b.identity);
        let acked = match mailbox::acknowledge(&self.sql, &b.message_ids, b.retry, now_ms()) {
            Ok(a) => a,
            Err(e) => return refuse(500, format!("mailbox acknowledge: {e}")),
        };
        match mailbox::archive_rows(&self.sql, &acked.acknowledged) {
            Ok(rows) => self.enqueue_after(&b.identity, rows),
            Err(e) => console_log!("archive.enqueue.read.err {}", e),
        }
        if !b.legacy || acked.missing.is_empty() {
            return answer(json!({
                "acknowledged": acked.acknowledged.len(),
                "missing": acked.missing,
            }));
        }
        // The legacy rule: the ids the mailbox does not hold are acknowledged
        // in D1 as before (a retained box marks, every other box deletes),
        // those D1 holds live only: the archive's acknowledged mark of a row
        // this mailbox held is not a row to acknowledge again.
        let db = self.env.d1("DB")?;
        let retention = crate::retention::RetentionConfig::from_env(&self.env);
        let n =
            match legacy_acknowledge(&Storage::new(&db), &b.identity, &acked.missing, &retention)
                .await
            {
                Ok(n) => n,
                Err(e) => return legacy_refusal("acknowledge", e),
            };
        answer(json!({ "acknowledged": acked.acknowledged.len() + n, "missing": [] }))
    }

    async fn handle_permissions_forget(&self, req: &mut Request) -> Result<Response> {
        let b: IdentityBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("forget body: {e}")),
        };
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        match mailbox::forget_permissions(&self.sql) {
            Ok(()) => answer(json!({ "forgot": true })),
            Err(e) => refuse(500, e),
        }
    }

    /// `/internal/archive-read?identity=<key>&id=<id>&id=...`: the rows the
    /// mailbox holds under those ids, as the archive writes them.
    fn handle_archive_read(&self, req: &Request) -> Result<Response> {
        let url = req.url()?;
        let mut identity = String::new();
        let mut ids = Vec::new();
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "identity" => identity = v.into_owned(),
                "id" => ids.push(v.into_owned()),
                _ => {}
            }
        }
        if !self.has_mailbox() {
            return answer(json!({ "rows": [] }));
        }
        if let Err(e) = self.ready(&identity) {
            return refuse(500, e);
        }
        match mailbox::archive_rows(&self.sql, &ids) {
            Ok(rows) => answer(json!({ "rows": rows })),
            Err(e) => refuse(500, e),
        }
    }

    async fn handle_archive_done(&self, req: &mut Request) -> Result<Response> {
        let b: DoneBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return refuse(400, format!("archive-done body: {e}")),
        };
        if !self.has_mailbox() {
            return answer(json!({ "changed": 0 }));
        }
        if let Err(e) = self.ready(&b.identity) {
            return refuse(500, e);
        }
        match mailbox::archive_done(&self.sql, &b.done) {
            Ok(n) => answer(json!({ "changed": n })),
            Err(e) => refuse(500, e),
        }
    }

    /// The forwarded session read (section 6, R3): a lane this hub holds no
    /// mirror of is asked of the identity's `MessageHub` once; the mirror it
    /// hands over (and deletes there) is kept here, and the verify runs here.
    async fn handle_session_verify(&self, req: &mut Request) -> Result<Response> {
        let body: SessionVerifyBody = match req.json().await {
            Ok(b) => b,
            Err(e) => return Response::error(format!("invalid session-verify body: {e}"), 400),
        };
        if !body.id.is_empty() && !self.hub.has_session_mirror(&body.id).await {
            match take_mirror(&self.env, &body.id, &body.identity).await {
                Ok(Some(mirror)) => {
                    if self.hub.keep_session_mirror(&mirror).await {
                        console_log!(
                            "TRACE_SESSION mirror kept from MessageHub id={}…",
                            &mirror.id[..12.min(mirror.id.len())]
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => console_log!("TRACE_SESSION mirror take failed: {e}"),
            }
        }
        self.hub.verify_session(body).await
    }
}

/// The legacy rule's acknowledgment in D1: of `ids`, those D1 holds live, as
/// `Storage::acknowledge_messages` acknowledges them. `sql`'s hub and
/// `kv-drain`'s Worker both use it.
pub(crate) async fn legacy_acknowledge(
    store: &Storage<'_>,
    identity: &str,
    ids: &[String],
    retention: &crate::retention::RetentionConfig,
) -> Result<usize> {
    let live = store.live_message_ids(identity, ids).await?;
    if live.is_empty() {
        return Ok(0);
    }
    store.acknowledge_messages(identity, &live, retention).await
}

/// A D1 failure on the legacy merge: a transient one is the caller's 503, any
/// other its 500.
fn legacy_refusal(op: &str, e: Error) -> Result<Response> {
    let status = if crate::storage::is_transient_d1_error(&e) {
        503
    } else {
        500
    };
    refuse(status, format!("legacy {op} on D1: {e}"))
}

/// Hand the archive messages to `ARCHIVE_QUEUE`, one at a time, each logged.
async fn enqueue(env: &Env, msgs: &[crate::archive::ArchiveMessage]) {
    let queue = match env.queue("ARCHIVE_QUEUE") {
        Ok(q) => q,
        Err(e) => {
            console_log!("archive.enqueue.err n={} err=binding: {}", msgs.len(), e);
            return;
        }
    };
    for m in msgs {
        let sent = async {
            let text = serde_json::to_string(m).map_err(|e| Error::from(e.to_string()))?;
            let js = js_sys::JSON::parse(&text).map_err(Error::from)?;
            queue
                .send_raw(
                    RawMessageBuilder::new(js).build_with_content_type(QueueContentType::Json),
                )
                .await
        }
        .await;
        match sent {
            Ok(()) => console_log!(
                "archive.enqueue msgId={} version={} change={:?} bodyInHub={}",
                m.message_id,
                m.version,
                m.change,
                m.body_in_hub
            ),
            Err(e) => console_log!(
                "archive.enqueue.err msgId={} version={} err={}",
                m.message_id,
                m.version,
                e
            ),
        }
    }
}

/// Ask the identity's `MessageHub` for a lane's mirror (`/internal/session-take`).
async fn take_mirror(env: &Env, id: &str, identity: &str) -> Result<Option<HubMirror>> {
    let ns = env.durable_object(crate::hub_store::KV_HUB_BINDING)?;
    // The same name the session lane routed this verify by.
    let v = post_json(
        &ns,
        identity,
        "/internal/session-take",
        &json!({ "id": id, "identity": identity }),
    )
    .await?;
    Ok(serde_json::from_value(v["mirror"].clone()).ok())
}

/// POST a JSON body to `path` on the hub named `name`, bounded by
/// `FORWARD_OP_TIMEOUT_MS`; a non-2xx answer is an error carrying its body.
pub(crate) async fn post_json(
    ns: &ObjectNamespace,
    name: &str,
    path: &str,
    body: &Value,
) -> Result<Value> {
    let stub = ns.id_from_name(name)?.get_stub()?;
    let text = body.to_string();
    let call = async {
        let hdrs = Headers::new();
        hdrs.set("content-type", "application/json")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(hdrs)
            .with_body(Some(text.into()));
        let r = Request::new_with_init(&format!("https://do.local{path}"), &init)?;
        let mut res = stub.fetch_with_request(r).await?;
        let status = res.status_code();
        let v: Value = res.json().await.unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            Ok(v)
        } else {
            Err(Error::RustError(format!(
                "mailbox hub answered {status} on {path}: {}",
                v["error"].as_str().unwrap_or("")
            )))
        }
    };
    with_do_op_timeout(call, FORWARD_OP_TIMEOUT_MS).await
}

/// The mailbox hub of `identity`.
fn sql_hub(env: &Env) -> Result<ObjectNamespace> {
    env.durable_object(crate::hub_store::SQL_HUB_BINDING)
}

/// A hop to a mailbox hub that did not answer: a transient error (the send's
/// 503 `ERR_D1_UNAVAILABLE`, the listing's and the acknowledge's too), so the
/// client retries; the hub's own 500 stays a fault.
fn hop_error(e: Error) -> Error {
    let s = e.to_string();
    if s.contains("mailbox hub answered 5") && !s.contains("answered 503") {
        Error::RustError(s)
    } else {
        Error::RustError(format!("mailbox hub connection: {s}"))
    }
}

/// POST with one retry after a failure; `retry` is set on the second attempt
/// (an insert or an acknowledgment that may have landed reads its own row).
async fn post_with_retry(env: &Env, identity: &str, path: &str, mut body: Value) -> Result<Value> {
    let ns = sql_hub(env)?;
    match post_json(&ns, identity, path, &body).await {
        Ok(v) => Ok(v),
        Err(err) => {
            console_log!("mailbox.hop.retry path={} err={}", path, err);
            body["retry"] = json!(true);
            post_json(&ns, identity, path, &body)
                .await
                .map_err(hop_error)
        }
    }
}

/// `sql`: the caller's listing from its own hub, the legacy merge done there.
pub(crate) async fn list_on_hub(
    env: &Env,
    identity: &str,
    message_box: &str,
) -> Result<Vec<MessageDbRow>> {
    let v = post_with_retry(
        env,
        identity,
        "/internal/mailbox/list",
        json!({ "identity": identity, "messageBox": message_box, "legacy": true }),
    )
    .await?;
    serde_json::from_value(v["messages"].clone()).map_err(|e| Error::from(e.to_string()))
}

/// `kv-drain`: the D1 listing merged with the rows the identity's hub still
/// holds, the hub's rows leading (they were stored before the rollback).
pub(crate) async fn drain_list(
    env: &Env,
    identity: &str,
    message_box: &str,
    d1: Vec<MessageDbRow>,
) -> Result<Vec<MessageDbRow>> {
    let against: Vec<String> = d1.iter().filter_map(|r| r.message_id.clone()).collect();
    let v = post_with_retry(
        env,
        identity,
        "/internal/mailbox/list",
        json!({
            "identity": identity, "messageBox": message_box, "legacy": false,
            "against": against,
        }),
    )
    .await?;
    let mailbox: Vec<MessageDbRow> =
        serde_json::from_value(v["messages"].clone()).map_err(|e| Error::from(e.to_string()))?;
    let held: HashSet<String> =
        serde_json::from_value(v["held"].clone()).map_err(|e| Error::from(e.to_string()))?;
    Ok(mailbox::merge(
        d1,
        mailbox,
        &held,
        MergeOrder::MailboxFirst,
        mailbox::LIST_LIMIT,
        crate::handoff::LIST_INLINE_BYTES,
    ))
}

/// The caller's acknowledgment at its own hub: the count acknowledged and the
/// ids the hub does not hold (empty under `sql`, where the hub asks D1).
pub(crate) async fn ack_on_hub(
    env: &Env,
    identity: &str,
    ids: &[String],
    legacy: bool,
) -> Result<(usize, Vec<String>)> {
    let v = post_with_retry(
        env,
        identity,
        "/internal/mailbox/ack",
        json!({ "identity": identity, "messageIds": ids, "legacy": legacy }),
    )
    .await?;
    let n = v["acknowledged"].as_u64().unwrap_or(0) as usize;
    let missing: Vec<String> = serde_json::from_value(v["missing"].clone()).unwrap_or_default();
    Ok((n, missing))
}

/// `sql`: the identity set a permission; its hub's copy goes (best-effort,
/// logged; the copy is read from D1 again past `PERMISSIONS_COPY_TTL_MS`).
pub(crate) async fn forget_permissions(env: &Env, identity: &str) {
    let r = async {
        let ns = sql_hub(env)?;
        post_json(
            &ns,
            identity,
            "/internal/mailbox/permissions-forget",
            &json!({ "identity": identity }),
        )
        .await
    }
    .await;
    if let Err(e) = r {
        console_log!(
            "mailbox.permissions.forget.err identity={} err={}",
            identity,
            e
        );
    }
}

/// The send's store under `HUB_STORE = "sql"`: the context and the row at the
/// recipient's hub; the budget, the payment and the release of bytes as the
/// D1 path does them. A paid row (its payment's bytes at rest in R2, named by
/// `beef_key`) stays a D1 row, as section 8.1 keeps a paid send's D1 steps;
/// the hub's legacy merge lists it.
pub(crate) struct MailboxSendStore<'a, 'db> {
    pub(crate) worker: WorkerStore<'a, 'db>,
    /// The box of the send (one box per send; `insert_message` carries the
    /// D1 box's id, which the mailbox does not use).
    pub(crate) message_box: String,
}

impl SendStore for MailboxSendStore<'_, '_> {
    async fn read_send_context(
        &self,
        recipient: &str,
        sender: &str,
        message_box: &str,
    ) -> Result<SendContext> {
        let v = post_with_retry(
            self.worker.env,
            recipient,
            "/internal/mailbox/context",
            json!({ "identity": recipient, "sender": sender, "messageBox": message_box }),
        )
        .await?;
        Ok(SendContext {
            recipient_fee: v["recipientFee"].as_i64().unwrap_or(0) as i32,
            server_fee: v["serverFee"].as_i64().unwrap_or(0) as i32,
            // The mailbox needs no D1 box; a paid row makes its own.
            box_id: Some(0),
        })
    }

    async fn charge(&self, sender: &str, unjudged: u64) -> std::result::Result<(), (Value, u16)> {
        self.worker.charge(sender, unjudged).await
    }

    async fn settle(
        &self,
        payment: &Value,
        r2_key: Option<&str>,
        fee_map: &[(String, String, i32)],
        delivery_fee: i32,
        sender: &str,
    ) -> std::result::Result<crate::payments::Settled, (Value, u16)> {
        self.worker
            .settle(payment, r2_key, fee_map, delivery_fee, sender)
            .await
    }

    async fn get_or_create_message_box(&self, _recipient: &str, _message_box: &str) -> Result<i64> {
        Ok(0)
    }

    async fn insert_message(
        &self,
        message_id: &str,
        _box_id: i64,
        sender: &str,
        recipient: &str,
        body: &str,
        beef_key: Option<&str>,
    ) -> Result<Insert> {
        let message_box = self.message_box.clone();
        if beef_key.is_some() {
            let box_id = self
                .worker
                .store
                .get_or_create_message_box(recipient, &message_box)
                .await?;
            return self
                .worker
                .insert_message(message_id, box_id, sender, recipient, body, beef_key)
                .await;
        }
        let v = post_with_retry(
            self.worker.env,
            recipient,
            "/internal/mailbox/insert",
            json!({
                "identity": recipient,
                "row": NewRow {
                    message_id: message_id.into(),
                    message_box,
                    sender: sender.into(),
                    body: body.into(),
                },
            }),
        )
        .await?;
        match v["result"].as_str() {
            Some("stored") => Ok(Insert::Stored),
            Some("duplicate") => Ok(Insert::Duplicate),
            Some("full") => Ok(Insert::Full(v["answer"].clone())),
            other => Err(Error::RustError(format!(
                "mailbox insert answered {other:?}"
            ))),
        }
    }

    async fn forget_unnamed(
        &self,
        rows_naming: usize,
        handed: &Option<crate::handoff::HandedOff>,
        r2_key: Option<&str>,
        failed: bool,
    ) {
        self.worker
            .forget_unnamed(rows_naming, handed, r2_key, failed)
            .await
    }

    fn now_ms(&self) -> u64 {
        self.worker.now_ms()
    }

    fn log(&self, line: String) {
        self.worker.log(line)
    }

    fn box_off(&self, message_box: &str) -> bool {
        self.worker.box_off(message_box)
    }
}
