//! The archive of the relay mailbox (0.8.0, R1: the archive ready).
//!
//! The recipient's hub will hold the live rows and D1 a copy behind the queue
//! `relay-archive` (bsv-stack-lean `docs/p0/mbx-hot-path-m28a.md`, section 5).
//! This release ships the consumer alone: nothing enqueues yet (the producer
//! binding `ARCHIVE_QUEUE` exists so the release that feeds it needs no binding
//! change), and D1 stays the store every route reads.
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
    if m.change == Change::Insert && m.body.is_none() {
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

/// The queue's handler: each message parsed, the malformed acknowledged and
/// logged once, the rest archived in one pass; a D1 failure retries every
/// message of the pass (a repeat is a no-op, so the retry is safe).
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
    let outcome = match env.d1("DB") {
        Ok(db) => archive_batch(&db, &msgs).await,
        Err(e) => Err(e),
    };
    match outcome {
        Ok(verdicts) => {
            for ((raw, m), v) in raws.iter().zip(&msgs).zip(verdicts) {
                console_log!(
                    "{} msgId={} version={} change={:?}",
                    v.as_str(),
                    m.message_id,
                    m.version,
                    m.change
                );
                raw.ack();
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
