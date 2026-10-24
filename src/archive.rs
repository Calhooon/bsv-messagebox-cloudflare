//! The archive of the relay mailbox (0.8.0, R1: the archive ready; 0.8.1, R2:
//! the hub that feeds it).
//!
//! The recipient's hub holds the live rows and D1 a copy behind the queue
//! `relay-archive` (bsv-stack-lean `docs/p0/mbx-hot-path-m28a.md`, section 5).
//! Since 0.8.1 `MessageHubSql` enqueues every change of a mailbox row (under
//! `HUB_STORE = "sql"`; under `kv` nothing reaches it and nothing enqueues),
//! and after a written batch the consumer tells each recipient's hub which
//! versions the archive holds (`/internal/archive-done`), so the hub stops
//! owing them and deletes an acknowledged row. A message whose body was too
//! long for the queue (`bodyInHub`) has its body read from the hub before the write
//! (`/internal/archive-read`).
//!
//! A message names one change of one row: the insert (version 1) or the
//! acknowledgment (a later version), keyed by the message id and the version
//! the hub counts. The consumer upserts D1 so the queue's at-least-once
//! delivery cannot move a row backwards:
//!
//! - a repeated message (the version D1 holds, or an older one) writes nothing;
//! - a newer version overwrites the row and moves `archive_version` forward;
//! - an acknowledgment sets `acknowledged_at`, so `LIST_MESSAGES_SQL` (which
//!   reads `acknowledged_at IS NULL`) never lists the row again, whichever
//!   order the insert and the acknowledgment arrive in;
//! - a row held under the same id by another recipient (`UNIQUE(message_id)`,
//!   `migrations/0001_initial.sql`) is never touched: `archive.collision`.
//!
//! A message that does not parse, or names no row, is acknowledged and logged
//! once (a redelivery would fail the same way); a batch D1 could not write is
//! retried by the queue (`max_retries`, `retry_delay` in `wrangler.toml`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::d1::QVal;

/// D1's bound parameters per statement: the held read is cut at this many ids
/// (a queue batch is at most 100 messages, `max_batch_size`).
pub const ARCHIVE_READ_CHUNK: usize = 100;

/// Make sure the recipient's box exists before its row is written (the box
/// statement of `Storage::get_or_create_message_box`, `src/storage.rs`).
/// Bind order: recipient, box type.
pub const ARCHIVE_BOX_SQL: &str =
    "INSERT OR IGNORE INTO message_boxes (identity_key, type) VALUES (?, ?)";

/// The upsert. A row the archive never saw is inserted at the message's
/// version; a held row moves only to a higher version and only for its own
/// recipient. An acknowledgment sets `acknowledged_at` and nothing clears it.
/// A body-less change (an acknowledgment whose body the hub already archived)
/// keeps the stored body; one that arrives before its insert stores an empty
/// body, acknowledged, which no listing returns.
///
/// Bind order: message id, sender, recipient, body (NULL for none), created at
/// (NULL for now), acknowledged (1 or 0), version, recipient, box type.
pub const ARCHIVE_UPSERT_SQL: &str =
    "INSERT INTO messages (message_id, message_box_id, sender, recipient, body, created_at, \
                           acknowledged_at, archive_version) \
     SELECT ?, message_box_id, ?, ?, COALESCE(?, ''), COALESCE(?, datetime('now')), \
            CASE WHEN ? = 1 THEN datetime('now') END, ? \
     FROM message_boxes WHERE identity_key = ? AND type = ? \
     ON CONFLICT(message_id) DO UPDATE SET \
       body = CASE WHEN excluded.body <> '' THEN excluded.body ELSE messages.body END, \
       acknowledged_at = COALESCE(messages.acknowledged_at, excluded.acknowledged_at), \
       archive_version = excluded.archive_version, \
       updated_at = datetime('now') \
     WHERE excluded.archive_version > messages.archive_version \
       AND messages.recipient = excluded.recipient";

/// Who holds each of a batch's message ids, at what version: read through
/// `idx_messages_archive` (migration 0011), which covers it, so no row's body
/// is read. Named by `INDEXED BY` because SQLite's planner, with no statistics,
/// takes the `UNIQUE(message_id)` index and then reads each row; on a schema
/// without migration 0011 the statement fails, and the batch is retried.
pub fn archive_held_sql(n_ids: usize) -> String {
    format!(
        "SELECT message_id, recipient, archive_version FROM messages \
         INDEXED BY idx_messages_archive WHERE message_id IN ({})",
        vec!["?"; n_ids].join(", ")
    )
}

/// The two changes of a row the archive receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    Insert,
    Acknowledge,
}

/// One queue message: one change of one row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveMessage {
    pub recipient: String,
    pub message_id: String,
    /// The hub's count of the row's changes: 1 for the insert, one more for
    /// the acknowledgment. Never 0 (0 is a row the archive never wrote).
    pub version: u64,
    pub change: Change,
    pub message_box: String,
    pub sender: String,
    /// The row's body. Required on an insert; on an acknowledgment, present
    /// only while no earlier version of the row was archived.
    #[serde(default)]
    pub body: Option<String>,
    /// The row's creation time as the hub stored it (D1's `datetime('now')`
    /// form or ISO 8601, both listed by `storage::to_iso8601`); none is now.
    #[serde(default)]
    pub created_at: Option<String>,
    /// 0.8.1: the body is too long for a queue message (128 KB) and stays in
    /// the recipient's `MessageHubSql`; the consumer reads it there
    /// (`/internal/archive-read`) before the write. Absent is false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub body_in_hub: bool,
}

/// Read one queue message's body. `Err` is malformed beyond repair: the
/// consumer acknowledges it and logs the reason once.
pub fn parse(value: serde_json::Value) -> Result<ArchiveMessage, String> {
    let m: ArchiveMessage =
        serde_json::from_value(value).map_err(|e| format!("not an archive message: {e}"))?;
    if m.version == 0 {
        return Err("version 0".into());
    }
    for (name, v) in [
        ("recipient", &m.recipient),
        ("messageId", &m.message_id),
        ("messageBox", &m.message_box),
        ("sender", &m.sender),
    ] {
        if v.is_empty() {
            return Err(format!("empty {name}"));
        }
    }
    if m.change == Change::Insert && m.body.is_none() && !m.body_in_hub {
        return Err("an insert without its body".into());
    }
    Ok(m)
}

/// A row D1 holds under a message id (the held read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub recipient: String,
    pub version: u64,
}

/// The held read's row, as D1 answers it (integers as f64, per `storage`).
#[derive(Debug, Deserialize)]
pub struct HeldRow {
    pub message_id: Option<String>,
    pub recipient: Option<String>,
    pub archive_version: Option<f64>,
}

/// The held rows by message id.
pub fn held_map(rows: Vec<HeldRow>) -> HashMap<String, Held> {
    rows.into_iter()
        .filter_map(|r| {
            Some((
                r.message_id?,
                Held {
                    recipient: r.recipient?,
                    version: r.archive_version.unwrap_or(0.0) as u64,
                },
            ))
        })
        .collect()
}

/// What the consumer does with one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Written: D1 holds an older version or no row.
    Apply,
    /// D1 holds this version or a newer one: nothing to write.
    Repeat,
    /// A newer version of the same row is in the same batch: that one is written.
    Superseded,
    /// D1 holds the id for another recipient: nothing written, logged.
    Collision,
}

impl Verdict {
    /// The log line's name.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Apply => "archive.done",
            Verdict::Repeat => "archive.repeat",
            Verdict::Superseded => "archive.superseded",
            Verdict::Collision => "archive.collision",
        }
    }
}

/// The plan of a batch against what D1 holds: one verdict per message, in
/// order. Pure, so the idempotence rule is pinned without a D1. Of the
/// messages naming one id, the highest version (the earliest of equals) is
/// the batch's; the upsert's own guard holds the same rule under a race.
pub fn plan(batch: &[ArchiveMessage], held: &HashMap<String, Held>) -> Vec<Verdict> {
    let mut best: HashMap<&str, usize> = HashMap::new();
    for (i, m) in batch.iter().enumerate() {
        best.entry(m.message_id.as_str())
            .and_modify(|b| {
                if m.version > batch[*b].version {
                    *b = i;
                }
            })
            .or_insert(i);
    }
    batch
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let b = &batch[best[m.message_id.as_str()]];
            let owner = held
                .get(&m.message_id)
                .map(|h| h.recipient.as_str())
                .unwrap_or(b.recipient.as_str());
            if m.recipient != owner {
                return Verdict::Collision;
            }
            if best[m.message_id.as_str()] != i {
                return Verdict::Superseded;
            }
            match held.get(&m.message_id) {
                Some(h) if h.version >= m.version => Verdict::Repeat,
                _ => Verdict::Apply,
            }
        })
        .collect()
}

/// The statements that write one applied message, in order: the box, then
/// the row.
pub fn statements(m: &ArchiveMessage) -> [(&'static str, Vec<QVal>); 2] {
    let acknowledged = i64::from(m.change == Change::Acknowledge);
    [
        (
            ARCHIVE_BOX_SQL,
            vec![
                QVal::from(m.recipient.as_str()),
                QVal::from(m.message_box.as_str()),
            ],
        ),
        (
            ARCHIVE_UPSERT_SQL,
            vec![
                QVal::from(m.message_id.as_str()),
                QVal::from(m.sender.as_str()),
                QVal::from(m.recipient.as_str()),
                QVal::from(m.body.clone()),
                QVal::from(m.created_at.clone()),
                QVal::from(acknowledged),
                QVal::from(m.version),
                QVal::from(m.recipient.as_str()),
                QVal::from(m.message_box.as_str()),
            ],
        ),
    ]
}

/// Read what D1 holds for a batch, plan it, and write the applied messages in
/// one D1 `batch()` (all or none). The read is bounded per operation and
/// retried as `find_message_box`'s; the write as the send's insert. `Err` is a
/// D1 failure: the caller hands the batch back to the queue.
pub async fn archive_batch(
    db: &worker::D1Database,
    batch: &[ArchiveMessage],
) -> worker::Result<Vec<Verdict>> {
    use crate::d1::Query;
    use crate::storage::{with_d1_bounded_read, with_d1_write_retry};

    let mut ids: Vec<&str> = batch.iter().map(|m| m.message_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    let mut rows: Vec<HeldRow> = Vec::new();
    for chunk in ids.chunks(ARCHIVE_READ_CHUNK) {
        let mut q = Query::new(&archive_held_sql(chunk.len()));
        for id in chunk {
            q = q.bind(*id);
        }
        rows.extend(with_d1_bounded_read(|| q.fetch_all::<HeldRow>(db)).await?);
    }
    let verdicts = plan(batch, &held_map(rows));

    let applied: Vec<&ArchiveMessage> = batch
        .iter()
        .zip(&verdicts)
        .filter(|(_, v)| **v == Verdict::Apply)
        .map(|(m, _)| m)
        .collect();
    if !applied.is_empty() {
        with_d1_write_retry(|| async {
            let mut stmts = Vec::with_capacity(applied.len() * 2);
            for m in &applied {
                for (sql, params) in statements(m) {
                    let js: Vec<wasm_bindgen::JsValue> = params.iter().map(QVal::to_js).collect();
                    stmts.push(db.prepare(sql).bind(&js)?);
                }
            }
            db.batch(stmts).await
        })
        .await?;
    }
    Ok(verdicts)
}

/// What each recipient's hub is told after a written batch, in the order the
/// recipients appear: every message D1 now holds at its version or a newer
/// one (written, a repeat, superseded in the batch), and every collision.
pub fn done_by_recipient(
    batch: &[ArchiveMessage],
    verdicts: &[Verdict],
) -> Vec<(String, Vec<crate::mailbox::Done>)> {
    let mut out: Vec<(String, Vec<crate::mailbox::Done>)> = Vec::new();
    for (m, v) in batch.iter().zip(verdicts) {
        let done = crate::mailbox::Done {
            message_id: m.message_id.clone(),
            version: m.version,
            collision: *v == Verdict::Collision,
        };
        match out.iter_mut().find(|(r, _)| *r == m.recipient) {
            Some((_, list)) => list.push(done),
            None => out.push((m.recipient.clone(), vec![done])),
        }
    }
    out
}

/// The messages whose body stayed in the hub, by recipient: `(recipient,
/// indices into the batch)`, in the order the recipients appear.
pub fn bodies_in_hub(batch: &[ArchiveMessage]) -> Vec<(String, Vec<usize>)> {
    let mut out: Vec<(String, Vec<usize>)> = Vec::new();
    for (i, m) in batch.iter().enumerate() {
        if !(m.body_in_hub && m.body.is_none()) {
            continue;
        }
        match out.iter_mut().find(|(r, _)| *r == m.recipient) {
            Some((_, list)) => list.push(i),
            None => out.push((m.recipient.clone(), vec![i])),
        }
    }
    out
}

/// The body of a message from the rows its hub answered: the row under its id
/// with a body (a message id's body never changes). `None`: the hub no longer
/// holds it with a body, so the archive already holds a newer version and the
/// message has nothing to write.
pub fn body_from_hub(m: &ArchiveMessage, rows: &[crate::mailbox::ArchiveRow]) -> Option<String> {
    rows.iter()
        .find(|r| r.message_id == m.message_id)
        .and_then(|r| r.body.clone())
}

/// `/internal/archive-read` on the recipient's `MessageHubSql`.
async fn read_hub_rows(
    env: &worker::Env,
    recipient: &str,
    ids: &[String],
) -> worker::Result<Vec<crate::mailbox::ArchiveRow>> {
    let ns = env.durable_object(crate::hub_store::archive_hub_binding())?;
    let stub = ns.id_from_name(recipient)?.get_stub()?;
    let mut pairs: Vec<(&str, &str)> = vec![("identity", recipient)];
    pairs.extend(ids.iter().map(|id| ("id", id.as_str())));
    let url = worker::Url::parse_with_params("https://do.local/internal/archive-read", pairs)
        .map_err(|e| worker::Error::from(e.to_string()))?;
    let call = async {
        let mut res = stub.fetch_with_str(url.as_str()).await?;
        if res.status_code() != 200 {
            return Err(worker::Error::from(format!(
                "archive-read answered {}",
                res.status_code()
            )));
        }
        let v: serde_json::Value = res.json().await?;
        serde_json::from_value(v["rows"].clone()).map_err(|e| worker::Error::from(e.to_string()))
    };
    crate::hub_forward::with_do_op_timeout(call, crate::hub_forward::FORWARD_OP_TIMEOUT_MS).await
}

/// `/internal/archive-done` on the recipient's `MessageHubSql`.
async fn tell_hub(
    env: &worker::Env,
    recipient: &str,
    done: &[crate::mailbox::Done],
) -> worker::Result<()> {
    let ns = env.durable_object(crate::hub_store::archive_hub_binding())?;
    crate::message_hub_sql::post_json(
        &ns,
        recipient,
        "/internal/archive-done",
        &serde_json::json!({ "identity": recipient, "done": done }),
    )
    .await
    .map(|_| ())
}

/// The queue's handler: each message parsed, the malformed acknowledged and
/// logged once, the rest archived in one pass; a D1 failure retries every
/// message of the pass (a repeat is a no-op, so the retry is safe). After a
/// written pass each recipient's hub is told what the archive holds; a hub
/// that cannot be told keeps the rows owed and hands them again later.
pub async fn consume(batch: &worker::MessageBatch<serde_json::Value>, env: &worker::Env) {
    use worker::{console_log, MessageExt};

    let mut raws = Vec::new();
    let mut msgs = Vec::new();
    for raw in batch.raw_iter() {
        let parsed = serde_wasm_bindgen::from_value::<serde_json::Value>(raw.body())
            .map_err(|e| format!("not JSON: {e}"))
            .and_then(parse);
        match parsed {
            Ok(m) => {
                msgs.push(m);
                raws.push(raw);
            }
            Err(why) => {
                console_log!("archive.malformed queue_id={} why={}", raw.id(), why);
                raw.ack();
            }
        }
    }
    if msgs.is_empty() {
        return;
    }
    // 0.8.1: a body too long for the queue is read from the recipient's hub.
    let mut keep = vec![true; msgs.len()];
    for (recipient, idxs) in bodies_in_hub(&msgs) {
        let ids: Vec<String> = idxs.iter().map(|&i| msgs[i].message_id.clone()).collect();
        match read_hub_rows(env, &recipient, &ids).await {
            Ok(rows) => {
                for i in idxs {
                    match body_from_hub(&msgs[i], &rows) {
                        Some(body) => msgs[i].body = Some(body),
                        None => {
                            console_log!(
                                "archive.gone msgId={} version={}",
                                msgs[i].message_id,
                                msgs[i].version
                            );
                            raws[i].ack();
                            keep[i] = false;
                        }
                    }
                }
            }
            Err(e) => {
                for i in idxs {
                    console_log!(
                        "archive.retry msgId={} version={} err=hub read: {}",
                        msgs[i].message_id,
                        msgs[i].version,
                        e
                    );
                    raws[i].retry();
                    keep[i] = false;
                }
            }
        }
    }
    let (raws, msgs): (Vec<_>, Vec<_>) = raws
        .into_iter()
        .zip(msgs)
        .zip(keep)
        .filter_map(|(pair, k)| k.then_some(pair))
        .unzip();
    if msgs.is_empty() {
        return;
    }
    let outcome = match env.d1("DB") {
        Ok(db) => archive_batch(&db, &msgs).await,
        Err(e) => Err(e),
    };
    match outcome {
        Ok(verdicts) => {
            for ((raw, m), v) in raws.iter().zip(&msgs).zip(&verdicts) {
                console_log!(
                    "{} msgId={} version={} change={:?}",
                    v.as_str(),
                    m.message_id,
                    m.version,
                    m.change
                );
                raw.ack();
            }
            for (recipient, done) in done_by_recipient(&msgs, &verdicts) {
                match tell_hub(env, &recipient, &done).await {
                    Ok(()) => {
                        console_log!("archive.hub_told recipient={} n={}", recipient, done.len())
                    }
                    Err(e) => console_log!(
                        "archive.hub_told.err recipient={} n={} err={}",
                        recipient,
                        done.len(),
                        e
                    ),
                }
            }
        }
        Err(e) => {
            console_log!("archive.retry n={} err={}", raws.len(), e);
            for raw in &raws {
                raw.retry();
            }
        }
    }
}

#[cfg(test)]
mod tests;
