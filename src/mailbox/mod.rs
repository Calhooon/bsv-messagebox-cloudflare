//! The recipient hub's mailbox (0.8.1, R2 of the relay mailbox): the machine
//! of bsv-stack-lean `docs/p0/mbx-hot-path-m28a.md` section 9, over the
//! statements of `schema`.
//!
//! The machine is synchronous and runs over `MailboxSql`, one method that runs
//! one statement: the Durable Object drives it through `ctx.storage.sql`
//! (`message_hub_sql`), the tests through rusqlite over the same statements.
//! Each operation is a run of statements with no `await` between them, so the
//! Durable Object commits it as one unit before its answer leaves (the
//! platform's output gate; the design's section 3).
//!
//! The events (section 9's numbering):
//!
//! - E1 `insert`, the id not held, under the bound: the row `live`, version 1,
//!   owed; the counters moved.
//! - E2 a retried hop's insert, the id held with the same sender, box and
//!   body: `Retried` (the send's answer is stored; no second row, no push).
//! - E3 a clean insert, the id held: `Duplicate`.
//! - E4 the bound: `Full` (429 `ERR_INBOX_QUOTA_EXCEEDED`), nothing written.
//! - E8 `list`: the box's live rows, insertion order, 100 and 16 MiB.
//! - E9 `acknowledge`: `acknowledged`, version + 1, owed, out of the counters.
//! - E11 `archive_done`: `live` archived, or an acknowledged row deleted.
//! - E12 `owed_due`: at most 16 owed rows last enqueued at least 120 s ago.

pub mod schema;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::archive::{ArchiveMessage, Change};
use crate::storage::MessageDbRow;

/// The bound per identity on the live rows held (the reference's standard
/// profile, `maxInboxMessages`; the owner's ruling of 2026-10-23).
pub const MAILBOX_ROWS_LIMIT: u64 = 10_000;

/// The bound per identity on the bytes of the live rows' stored text
/// (`maxInboxBytes`, 1 GiB).
pub const MAILBOX_BYTES_LIMIT: u64 = 1 << 30;

/// An owed row is handed to the queue again once its last enqueue is this old.
pub const REPLAY_AFTER_MS: u64 = 120_000;

/// At most this many owed rows are re-enqueued per request.
pub const REPLAY_PER_REQUEST: usize = 16;

/// A listing's rows, as `storage::LIST_MESSAGES_LIMIT`.
pub const LIST_LIMIT: usize = 100;

/// The permissions copy is read from D1 again once it is this old.
pub const PERMISSIONS_COPY_TTL_MS: u64 = 600_000;

/// A queue message holds 128 KB (the Queues limits page); an archive message
/// whose JSON is longer than this carries no body and names the hub's
/// `/internal/archive-read` instead (`body_in_hub`).
pub const ARCHIVE_INLINE_MAX: usize = 120_000;

/// One value bound to or read from a statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Text(String),
}

impl Val {
    fn int(&self) -> i64 {
        match self {
            Val::Int(i) => *i,
            Val::Text(s) => s.parse().unwrap_or(0),
            Val::Null => 0,
        }
    }

    fn text(&self) -> Option<String> {
        match self {
            Val::Text(s) => Some(s.clone()),
            Val::Int(i) => Some(i.to_string()),
            Val::Null => None,
        }
    }
}

impl From<&str> for Val {
    fn from(s: &str) -> Self {
        Val::Text(s.to_string())
    }
}

impl From<i64> for Val {
    fn from(i: i64) -> Self {
        Val::Int(i)
    }
}

impl From<u64> for Val {
    fn from(i: u64) -> Self {
        Val::Int(i as i64)
    }
}

/// The store the machine runs on: one statement, its bound values, its rows
/// (each a list of column values in the statement's order).
pub trait MailboxSql {
    fn run(&self, sql: &str, params: &[Val]) -> Result<Vec<Vec<Val>>, String>;
}

/// The bound a hub applies; `Bounds::RULED` in production, smaller in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub rows: u64,
    pub bytes: u64,
}

impl Bounds {
    pub const RULED: Bounds = Bounds {
        rows: MAILBOX_ROWS_LIMIT,
        bytes: MAILBOX_BYTES_LIMIT,
    };
}

/// Make the layout (idempotent).
pub fn ensure_schema<S: MailboxSql>(db: &S) -> Result<(), String> {
    for stmt in schema::SCHEMA {
        db.run(stmt, &[])?;
    }
    Ok(())
}

/// Record the identity the hub serves on its earliest request; a later request
/// naming another identity is refused (a hub id is the identity's name, so
/// this is a routing bug, never a second tenant).
pub fn bind_identity<S: MailboxSql>(db: &S, identity: &str) -> Result<(), String> {
    if identity.is_empty() {
        return Err("no identity".into());
    }
    db.run(
        "INSERT OR IGNORE INTO mailbox_meta (key, value) VALUES ('identity', ?)",
        &[identity.into()],
    )?;
    match identity_of(db)? {
        Some(held) if held == identity => Ok(()),
        Some(held) => Err(format!("hub serves {held}, asked for {identity}")),
        None => Err("identity not recorded".into()),
    }
}

/// The identity the hub serves, once recorded.
pub fn identity_of<S: MailboxSql>(db: &S) -> Result<Option<String>, String> {
    let rows = db.run("SELECT value FROM mailbox_meta WHERE key = 'identity'", &[])?;
    Ok(rows.first().and_then(|r| r[0].text()))
}

/// The counters: (live rows held, their bytes).
pub fn counters<S: MailboxSql>(db: &S) -> Result<(u64, u64), String> {
    let rows = db.run(
        "SELECT rows_held, bytes_held FROM mailbox_counters WHERE id = 1",
        &[],
    )?;
    let r = rows.first().ok_or("no counters row")?;
    Ok((r[0].int().max(0) as u64, r[1].int().max(0) as u64))
}

/// D1's `datetime('now')` form of an epoch-ms instant, the form the listing's
/// `storage::to_iso8601` turns into the wire's ISO 8601.
pub fn sqlite_time(ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// A row a send asks the mailbox to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewRow {
    pub message_id: String,
    pub message_box: String,
    pub sender: String,
    pub body: String,
}

/// Which bound a full mailbox met.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Full {
    /// `messages` or `bytes`, the reference's words.
    pub resource: String,
    pub limit: u64,
    /// The count or the bytes the mailbox holds.
    pub held: u64,
}

/// What an insert did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inserted {
    /// E1: held, `live`, version 1.
    Stored,
    /// E2: a retried hop found its own row: stored, nothing written.
    Retried,
    /// E3: the id is held by another send.
    Duplicate,
    /// E4: refused at the bound, nothing written.
    Full(Full),
}

/// E1 to E4. `retry` is true on a hop the sender repeats after a timeout: a
/// row under the id with the same sender, box and body is then this send's
/// own (the D1 path's read-back rule, `storage::retried_row_is_ours`).
pub fn insert<S: MailboxSql>(
    db: &S,
    row: &NewRow,
    retry: bool,
    now_ms: u64,
    bounds: Bounds,
) -> Result<Inserted, String> {
    let held = db.run(
        "SELECT sender, message_box, body FROM mailbox_rows WHERE message_id = ?",
        &[row.message_id.as_str().into()],
    )?;
    if let Some(h) = held.first() {
        let ours = h[0].text().as_deref() == Some(row.sender.as_str())
            && h[1].text().as_deref() == Some(row.message_box.as_str())
            && h[2].text().as_deref() == Some(row.body.as_str());
        return Ok(if retry && ours {
            Inserted::Retried
        } else {
            Inserted::Duplicate
        });
    }
    let size = row.body.len() as u64;
    let (rows_held, bytes_held) = counters(db)?;
    if rows_held >= bounds.rows {
        return Ok(Inserted::Full(Full {
            resource: "messages".into(),
            limit: bounds.rows,
            held: rows_held,
        }));
    }
    if bytes_held.saturating_add(size) > bounds.bytes {
        return Ok(Inserted::Full(Full {
            resource: "bytes".into(),
            limit: bounds.bytes,
            held: bytes_held,
        }));
    }
    let at = sqlite_time(now_ms);
    db.run(
        "INSERT INTO mailbox_rows (message_id, message_box, sender, body, body_bytes, state, \
                                   version, archived_version, owed, enqueued_at, created_at, \
                                   updated_at) \
         VALUES (?, ?, ?, ?, ?, 'live', 1, 0, 1, ?, ?, ?)",
        &[
            row.message_id.as_str().into(),
            row.message_box.as_str().into(),
            row.sender.as_str().into(),
            row.body.as_str().into(),
            size.into(),
            now_ms.into(),
            at.as_str().into(),
            at.as_str().into(),
        ],
    )?;
    db.run(
        "UPDATE mailbox_counters SET rows_held = rows_held + 1, bytes_held = bytes_held + ? \
         WHERE id = 1",
        &[size.into()],
    )?;
    Ok(Inserted::Stored)
}

/// The full mailbox's answer (section 4): HTTP 429 with the reference's
/// `status`, `code`, `description`, `resource` and `limit`, and `held`,
/// `recipient` and `freedBy`.
pub fn full_answer(full: &Full, recipient: &str) -> (Value, u16) {
    (
        json!({
            "status": "error",
            "code": "ERR_INBOX_QUOTA_EXCEEDED",
            "description": "The recipient inbox storage quota has been reached. Retry after messages are acknowledged or expire.",
            "resource": full.resource,
            "limit": full.limit,
            "held": full.held,
            "recipient": recipient,
            "freedBy": "acknowledgeMessage",
        }),
        429,
    )
}

/// The listing's statement: a box's live rows in insertion order, at most
/// `?` of them, and of those the leading rows whose bodies add up to at most
/// `?` bytes (the shape of `storage::LIST_MESSAGES_SQL`).
pub const MAILBOX_LIST_SQL: &str =
    "SELECT message_id, body, sender, created_at, updated_at FROM ( \
       SELECT seq, message_id, body, sender, created_at, updated_at, \
              SUM(body_bytes) OVER (ORDER BY seq ROWS UNBOUNDED PRECEDING) AS upto FROM ( \
         SELECT seq, message_id, body, sender, created_at, updated_at, body_bytes \
         FROM mailbox_rows INDEXED BY mailbox_rows_listing \
         WHERE message_box = ? AND state = 'live' \
         ORDER BY seq LIMIT ?)) \
     WHERE upto <= ? ORDER BY seq";

/// E8: the box's live rows, as the D1 listing returns them.
pub fn list<S: MailboxSql>(
    db: &S,
    message_box: &str,
    limit: usize,
    inline_bytes: u64,
) -> Result<Vec<MessageDbRow>, String> {
    let rows = db.run(
        MAILBOX_LIST_SQL,
        &[
            message_box.into(),
            (limit as u64).into(),
            inline_bytes.into(),
        ],
    )?;
    Ok(rows
        .into_iter()
        .map(|r| MessageDbRow {
            message_id: r[0].text(),
            body: r[1].text(),
            sender: r[2].text(),
            created_at: r[3].text(),
            updated_at: r[4].text(),
        })
        .collect())
}

/// Of `ids`, those the mailbox holds in any state (a legacy row under one of
/// them is never listed: the mailbox's row wins, and an acknowledged one
/// stays acknowledged).
pub fn held_ids<S: MailboxSql>(db: &S, ids: &[String]) -> Result<HashSet<String>, String> {
    let mut held = HashSet::new();
    for chunk in ids.chunks(90) {
        if chunk.is_empty() {
            continue;
        }
        let sql = format!(
            "SELECT message_id FROM mailbox_rows WHERE message_id IN ({})",
            vec!["?"; chunk.len()].join(", ")
        );
        let params: Vec<Val> = chunk.iter().map(|s| s.as_str().into()).collect();
        for r in db.run(&sql, &params)? {
            if let Some(id) = r[0].text() {
                held.insert(id);
            }
        }
    }
    Ok(held)
}

/// What an acknowledgment did: the ids it moved to `acknowledged`, and the
/// ids the mailbox does not hold live (the legacy rule asks D1 for those).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acked {
    pub acknowledged: Vec<String>,
    pub missing: Vec<String>,
}

/// E9. A row already `acknowledged` counts as acknowledged only on a retried
/// hop (the earlier attempt landed); on a clean request it is missing, as a
/// D1 row already deleted is.
pub fn acknowledge<S: MailboxSql>(
    db: &S,
    ids: &[String],
    retry: bool,
    now_ms: u64,
) -> Result<Acked, String> {
    let mut out = Acked::default();
    let mut seen = HashSet::new();
    let at = sqlite_time(now_ms);
    for id in ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        let rows = db.run(
            "SELECT state, body_bytes FROM mailbox_rows WHERE message_id = ?",
            &[id.as_str().into()],
        )?;
        match rows.first().map(|r| (r[0].text(), r[1].int())) {
            Some((Some(state), bytes)) if state == "live" => {
                db.run(
                    "UPDATE mailbox_rows SET state = 'acknowledged', version = version + 1, \
                       owed = 1, enqueued_at = ?, updated_at = ?, \
                       body = CASE WHEN archived_version > 0 THEN NULL ELSE body END \
                     WHERE message_id = ?",
                    &[now_ms.into(), at.as_str().into(), id.as_str().into()],
                )?;
                db.run(
                    "UPDATE mailbox_counters SET rows_held = rows_held - 1, \
                       bytes_held = bytes_held - ? WHERE id = 1",
                    &[Val::Int(bytes)],
                )?;
                out.acknowledged.push(id.clone());
            }
            Some((Some(_), _)) if retry => out.acknowledged.push(id.clone()),
            _ => out.missing.push(id.clone()),
        }
    }
    Ok(out)
}

/// One row as the archive reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveRow {
    pub message_id: String,
    pub message_box: String,
    pub sender: String,
    pub body: Option<String>,
    pub state: String,
    pub version: u64,
    pub created_at: String,
}

const ARCHIVE_ROW_COLUMNS: &str =
    "message_id, message_box, sender, body, state, version, created_at";

fn archive_row(r: &[Val]) -> ArchiveRow {
    ArchiveRow {
        message_id: r[0].text().unwrap_or_default(),
        message_box: r[1].text().unwrap_or_default(),
        sender: r[2].text().unwrap_or_default(),
        body: r[3].text(),
        state: r[4].text().unwrap_or_default(),
        version: r[5].int().max(0) as u64,
        created_at: r[6].text().unwrap_or_default(),
    }
}

/// The rows under `ids` the mailbox holds, for the archive (the enqueue after
/// an answer, and `/internal/archive-read`).
pub fn archive_rows<S: MailboxSql>(db: &S, ids: &[String]) -> Result<Vec<ArchiveRow>, String> {
    let mut out = Vec::new();
    for chunk in ids.chunks(90) {
        if chunk.is_empty() {
            continue;
        }
        let sql = format!(
            "SELECT {ARCHIVE_ROW_COLUMNS} FROM mailbox_rows WHERE message_id IN ({}) ORDER BY seq",
            vec!["?"; chunk.len()].join(", ")
        );
        let params: Vec<Val> = chunk.iter().map(|s| s.as_str().into()).collect();
        out.extend(db.run(&sql, &params)?.iter().map(|r| archive_row(r)));
    }
    Ok(out)
}

/// E12: at most `REPLAY_PER_REQUEST` owed rows last enqueued at or before
/// `now_ms - REPLAY_AFTER_MS` (or never), the oldest enqueue leading, through the
/// owed index; their `enqueued_at` renewed to `now_ms` in the same run.
pub fn take_owed_due<S: MailboxSql>(db: &S, now_ms: u64) -> Result<Vec<ArchiveRow>, String> {
    let cutoff = now_ms.saturating_sub(REPLAY_AFTER_MS);
    let sql = format!(
        "SELECT {ARCHIVE_ROW_COLUMNS} FROM mailbox_rows INDEXED BY mailbox_rows_owed \
         WHERE owed = 1 AND (enqueued_at IS NULL OR enqueued_at <= ?) \
         ORDER BY enqueued_at LIMIT ?"
    );
    let rows: Vec<ArchiveRow> = db
        .run(&sql, &[cutoff.into(), (REPLAY_PER_REQUEST as u64).into()])?
        .iter()
        .map(|r| archive_row(r))
        .collect();
    for r in &rows {
        db.run(
            "UPDATE mailbox_rows SET enqueued_at = ? WHERE message_id = ?",
            &[now_ms.into(), r.message_id.as_str().into()],
        )?;
    }
    Ok(rows)
}

/// The queue message of one row's current version (R1's shape, read by
/// `archive::consume`): the insert while `live`, the acknowledgment after.
/// A message whose JSON would pass `ARCHIVE_INLINE_MAX` carries no body and
/// sets `bodyInHub`: the consumer reads the body from `/internal/archive-read`.
pub fn archive_message(row: &ArchiveRow, recipient: &str) -> ArchiveMessage {
    let mut m = ArchiveMessage {
        recipient: recipient.to_string(),
        message_id: row.message_id.clone(),
        version: row.version,
        change: if row.state == "live" {
            Change::Insert
        } else {
            Change::Acknowledge
        },
        message_box: row.message_box.clone(),
        sender: row.sender.clone(),
        body: row.body.clone(),
        created_at: Some(row.created_at.clone()),
        body_in_hub: false,
    };
    let len = serde_json::to_string(&m).map(|s| s.len()).unwrap_or(0);
    if len > ARCHIVE_INLINE_MAX && m.body.is_some() {
        m.body = None;
        m.body_in_hub = true;
    }
    m
}

/// One confirmation from the archive: D1 holds the row at `version` or newer,
/// or (`collision`) D1 holds the id for another recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Done {
    pub message_id: String,
    pub version: u64,
    #[serde(default)]
    pub collision: bool,
}

/// E11. At the row's current version: a `live` row is archived (not owed), an
/// acknowledged one is deleted. At an older version: the archived version
/// moves up, and an acknowledged row drops its body (the archive holds it).
/// A collision is never archived: a live row is kept and served, not owed; an
/// acknowledged one is deleted. Returns the rows changed.
pub fn archive_done<S: MailboxSql>(db: &S, done: &[Done]) -> Result<usize, String> {
    let mut changed = 0;
    for d in done {
        let rows = db.run(
            "SELECT state, version FROM mailbox_rows WHERE message_id = ?",
            &[d.message_id.as_str().into()],
        )?;
        let Some((state, version)) = rows
            .first()
            .map(|r| (r[0].text().unwrap_or_default(), r[1].int().max(0) as u64))
        else {
            continue;
        };
        let id: Val = d.message_id.as_str().into();
        if state == "acknowledged" && (d.collision || d.version >= version) {
            db.run("DELETE FROM mailbox_rows WHERE message_id = ?", &[id])?;
        } else if d.collision {
            db.run(
                "UPDATE mailbox_rows SET owed = 0, collision = 1 WHERE message_id = ?",
                &[id],
            )?;
        } else if d.version >= version {
            db.run(
                "UPDATE mailbox_rows SET archived_version = ?, owed = 0 WHERE message_id = ?",
                &[d.version.into(), id],
            )?;
        } else {
            db.run(
                "UPDATE mailbox_rows SET archived_version = MAX(archived_version, ?), \
                   body = CASE WHEN state = 'acknowledged' THEN NULL ELSE body END \
                 WHERE message_id = ?",
                &[d.version.into(), id],
            )?;
        }
        changed += 1;
    }
    Ok(changed)
}

/// The permissions copy for a sender and box, while younger than
/// `PERMISSIONS_COPY_TTL_MS`: (the recipient's fee, the server's delivery fee).
pub fn permissions_copy<S: MailboxSql>(
    db: &S,
    sender: &str,
    message_box: &str,
    now_ms: u64,
) -> Result<Option<(i32, i32)>, String> {
    let rows = db.run(
        "SELECT recipient_fee, server_fee, copied_at FROM permissions_copy \
         WHERE sender = ? AND message_box = ?",
        &[sender.into(), message_box.into()],
    )?;
    Ok(rows.first().and_then(|r| {
        let copied = r[2].int().max(0) as u64;
        (now_ms.saturating_sub(copied) < PERMISSIONS_COPY_TTL_MS)
            .then_some((r[0].int() as i32, r[1].int() as i32))
    }))
}

/// Keep what D1 answered for a sender and box.
pub fn keep_permissions<S: MailboxSql>(
    db: &S,
    sender: &str,
    message_box: &str,
    recipient_fee: i32,
    server_fee: i32,
    now_ms: u64,
) -> Result<(), String> {
    db.run(
        "INSERT OR REPLACE INTO permissions_copy \
           (sender, message_box, recipient_fee, server_fee, copied_at) VALUES (?, ?, ?, ?, ?)",
        &[
            sender.into(),
            message_box.into(),
            Val::Int(i64::from(recipient_fee)),
            Val::Int(i64::from(server_fee)),
            now_ms.into(),
        ],
    )?;
    Ok(())
}

/// The identity changed a permission: every copied answer goes.
pub fn forget_permissions<S: MailboxSql>(db: &S) -> Result<(), String> {
    db.run("DELETE FROM permissions_copy", &[])?;
    Ok(())
}

/// Which side of a merged listing leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOrder {
    /// `sql`: the D1 rows the old path stored before the cutover are older by
    /// construction, so they lead.
    D1First,
    /// `kv-drain`: the rows the mailbox still holds were stored before the
    /// rollback, so they lead the D1 rows stored since.
    MailboxFirst,
}

/// The merge by id: every D1 row whose id the mailbox holds (`held`, any
/// state) is dropped, so the mailbox's row wins and an acknowledged row never
/// comes back from D1; the two sides keep their own order; the result is cut
/// at `limit` rows and at the leading rows whose bodies add up to at most
/// `inline_bytes` (the listing's budget).
pub fn merge(
    d1: Vec<MessageDbRow>,
    mailbox: Vec<MessageDbRow>,
    held: &HashSet<String>,
    order: MergeOrder,
    limit: usize,
    inline_bytes: u64,
) -> Vec<MessageDbRow> {
    let d1: Vec<MessageDbRow> = d1
        .into_iter()
        .filter(|r| r.message_id.as_deref().is_none_or(|id| !held.contains(id)))
        .collect();
    let (lead, rest) = match order {
        MergeOrder::D1First => (d1, mailbox),
        MergeOrder::MailboxFirst => (mailbox, d1),
    };
    let mut out = Vec::new();
    let mut upto = 0u64;
    let mut ids = HashSet::new();
    for r in lead.into_iter().chain(rest) {
        if out.len() >= limit {
            break;
        }
        if let Some(id) = r.message_id.clone() {
            if !ids.insert(id) {
                continue;
            }
        }
        upto += r.body.as_deref().map_or(0, |b| b.len() as u64);
        if upto > inline_bytes {
            break;
        }
        out.push(r);
    }
    out
}

#[cfg(test)]
mod tests;
