// D1 storage operations for message-box.

use serde::Deserialize;
use worker::D1Database;

use crate::d1::Query;

/// Max messages returned by a single `/listMessages` call.
///
/// The canonical TS message-box-server returns the *entire* mailbox (no LIMIT)
/// and relies on clients `acknowledgeMessage`-ing (which DELETEs) to keep boxes
/// small — fine on a Node host with GBs of RAM. This relay is a Cloudflare
/// Worker with a hard **128 MB isolate ceiling**, so an unbounded `SELECT` of a
/// box that accumulated many un-acknowledged messages OOMs the isolate (CF 1102)
/// and fails every request sharing it. This bound is the platform guard that the
/// Node reference doesn't need; the real drain is still the client acknowledging
/// consumed messages. Kept small so even large DKG/Paillier bodies stay well
/// under the ceiling; a draining client (list → acknowledge → repeat) still walks
/// any backlog, and live ceremony messages arrive via WS push regardless.
const LIST_MESSAGES_LIMIT: u32 = 100;

/// Attempts (1 initial + retries) for an idempotent D1 read before giving up.
/// Bounded so a genuinely-down D1 fails fast (≤ ~150ms of added backoff) instead
/// of hanging the request in an unbounded loop.
const D1_READ_ATTEMPTS: u32 = 3;

/// Attempts (1 initial + retries) for an idempotent D1 WRITE before giving up.
/// Mirrors the read path (`D1_READ_ATTEMPTS`): a transient blip clears on the
/// re-attempt against a now-warm binding; a genuinely-down D1 stops after the
/// bound instead of looping.
const D1_WRITE_ATTEMPTS: u32 = 3;

/// Per-op wall-clock bound (ms) for one idempotent D1 WRITE.
///
/// The read path self-heals a transient D1 blip because `with_d1_read_retry`
/// re-issues the query — but a retry only helps when the op *errors*. A D1 write
/// that STALLS under a momentary storage/DO contention blip never errors: the
/// underlying JS promise just stays pending, so `stmt.run().await` hangs until
/// the client gives up (~10s). That was the send-path hang that stranded a
/// `commit_discard` move and let the peer escalate into a wedged tower case
/// (bsv-low#249): four `relay.send` POSTs each hung ~10.4s then client-timed-out,
/// no 500 — a pure write-path stall. Bounding each write turns that hang into a
/// fast transient error that the retry loop re-attempts against a warm binding
/// (~ms), or — if D1 is genuinely down — fails fast with a client-retryable
/// status well under the client's ~10s budget. 2s is orders of magnitude above a
/// healthy write (single-digit ms) yet returns promptly when a write is wedged.
const D1_WRITE_OP_TIMEOUT_MS: u64 = 2_000;

/// Per-op wall-clock bound (ms) for the `find_message_box` READ (#251 residual).
///
/// The read path had `with_d1_read_retry` but no per-op timeout — and a retry
/// only helps when the op *errors*. A read that STALLS (the same pending-promise
/// class as the #249 write hang) would park the request until the client gave
/// up. Bounding it turns the stall into a transient error the read-retry loop
/// re-attempts against a warm binding. Same 2s rationale as the write bound.
const D1_READ_OP_TIMEOUT_MS: u64 = 2_000;

/// Storage handle wrapping the D1 database binding.
pub struct Storage<'a> {
    pub db: &'a D1Database,
}

// -- D1 row types (snake_case, Option<f64> for integers per D1/JS interop) --

#[derive(Debug, Deserialize)]
pub struct MessageBoxRow {
    pub message_box_id: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct MessageDbRow {
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,
    pub body: Option<String>,
    pub sender: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerFeeRow {
    pub delivery_fee: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct RecipientFeeRow {
    pub recipient_fee: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub struct PermissionDbRow {
    pub sender: Option<String>,
    pub message_box: Option<String>,
    pub recipient_fee: Option<f64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceDbRow {
    pub id: Option<f64>,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub fcm_token: Option<String>,
    pub active: Option<f64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_used: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CountRow {
    pub count: Option<f64>,
}

/// #9: the per-send context resolved in ONE D1 batch round-trip (recipient fee +
/// server delivery fee + the recipient's message-box id). `box_id == None` ⇒ the box
/// doesn't exist yet and the caller must create it (only on the first message).
pub struct SendContext {
    pub recipient_fee: i32,
    pub server_fee: i32,
    pub box_id: Option<i64>,
}

impl<'a> Storage<'a> {
    pub fn new(db: &'a D1Database) -> Self {
        Self { db }
    }

    // -- Message box operations --

    /// Find message_box_id for (identity_key, type). Returns None if not found.
    ///
    /// Bounded transient-retry (see `with_d1_read_retry`): this SELECT is the
    /// FIRST D1 touch on the `/listMessages` cold path, and the first D1 read
    /// after the Worker/D1 goes cold intermittently rejects with a transient
    /// `D1_ERROR` before the binding is warm — a live probe reproduced exactly
    /// this (1st `/listMessages` after idle → 500, next 4/4 warm calls green),
    /// stalling a player's first hand. The read is idempotent (a missing box is
    /// `Ok(None)`, never `Err`), so retrying only ever turns a transient blip
    /// into the correct answer; it never changes the not-found / happy path.
    pub async fn find_message_box(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<Option<i64>> {
        let q = Query::new(
            "SELECT message_box_id FROM message_boxes WHERE identity_key = ? AND type = ?",
        )
        .bind(identity_key)
        .bind(box_type);
        // #251: the retry only fires on an *error*, so the read is additionally
        // bounded per-op (`with_d1_op_timeout`) — a stalled (never-erroring) read
        // becomes a transient timeout the retry loop re-attempts, instead of
        // hanging `/listMessages` / `get_or_create_message_box` for the client's
        // whole budget (the #249 hang class, read-side).
        let row: Option<MessageBoxRow> = with_d1_read_retry(|| {
            with_d1_op_timeout(q.fetch_optional(self.db), D1_READ_OP_TIMEOUT_MS)
        })
        .await?;
        Ok(row.and_then(|r| r.message_box_id.map(|v| v as i64)))
    }

    /// Get or create a message box, returning the message_box_id.
    pub async fn get_or_create_message_box(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<i64> {
        // Try find first
        if let Some(id) = self.find_message_box(identity_key, box_type).await? {
            return Ok(id);
        }
        // Create — INSERT OR IGNORE handles race conditions.
        //
        // Bounded write timeout+retry (`with_d1_write_retry`): this INSERT is on
        // the `/sendMessage` first-message-to-a-recipient path and shares the
        // write-stall hang risk that wedged `insert_message`. It is fully
        // idempotent — INSERT OR IGNORE on the `UNIQUE(type, identity_key)`
        // constraint, and the id is resolved by the re-fetch below regardless of
        // whether this attempt, a retry, or a dropped-but-landed attempt created
        // the row — so no changes-count reinterpretation is needed here.
        let insert = Query::new(
            "INSERT OR IGNORE INTO message_boxes (identity_key, type) VALUES (?, ?)",
        )
        .bind(identity_key)
        .bind(box_type);
        let (_meta, _retried) = with_d1_write_retry(|| insert.execute(self.db)).await?;
        // Re-fetch to get the ID (handles both fresh insert and race)
        self.find_message_box(identity_key, box_type)
            .await?
            .ok_or_else(|| worker::Error::from("Failed to create message box"))
    }

    // -- Message operations --

    /// Insert a message. Returns true if inserted, false if duplicate (messageId conflict).
    ///
    /// This is the `/sendMessage` hot-write. It is guarded by a bounded per-op
    /// timeout + transient-retry (`with_d1_write_retry`) so a momentary D1 write
    /// stall can no longer hang the send for the client's ~10s timeout (the
    /// bsv-low#249 send-path hang → spurious escalation).
    ///
    /// Idempotency under retry: `messages.message_id` is `NOT NULL UNIQUE`, so the
    /// statement is `INSERT OR IGNORE` — dedup-safe on `message_id`. A retry is
    /// triggered ONLY after a previous attempt errored or timed out. On a CF
    /// Worker a timed-out (dropped) write subrequest may still LAND on the
    /// platform, so the re-attempt's `INSERT OR IGNORE` can see the row already
    /// present and report `changes == 0`. After a retry that `0` means "our own
    /// earlier attempt of THIS send already stored it" (same message_id + body) —
    /// a SUCCESS, not a spurious duplicate. Only a CLEAN first-attempt `0`
    /// (`retried == false`) is a genuine duplicate `messageId`, preserving the
    /// existing duplicate-detection behaviour exactly.
    pub async fn insert_message(
        &self,
        message_id: &str,
        message_box_id: i64,
        sender: &str,
        recipient: &str,
        body: &str,
    ) -> worker::Result<bool> {
        let insert = Query::new(
            "INSERT OR IGNORE INTO messages (message_id, message_box_id, sender, recipient, body) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(message_id)
        .bind(message_box_id)
        .bind(sender)
        .bind(recipient)
        .bind(body);
        let (meta, retried) = with_d1_write_retry(|| insert.execute(self.db)).await?;
        Ok(insert_changes_mean_stored(meta.changes, retried))
    }

    /// List messages for a recipient in a given message box type.
    pub async fn list_messages(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<Vec<MessageDbRow>> {
        // Find the message box
        let box_id = match self.find_message_box(identity_key, box_type).await? {
            Some(id) => id,
            None => return Ok(Vec::new()), // No box = empty list (not an error)
        };

        // `acknowledged_at IS NULL`: a message in a RETAINED box (see
        // `retention::RetentionConfig`) is MARKED delivered by acknowledge
        // instead of deleted, and must then stop appearing in the live mailbox
        // (otherwise a long hand's acked backlog would crowd the LIMIT window
        // and starve fresh messages). Non-retained boxes never set the column,
        // so this filter is a no-op there — behavior unchanged. The retained
        // chain stays readable via `/listTranscript`.
        //
        // Bounded (see LIST_MESSAGES_LIMIT) and DELIBERATELY UN-ORDERED: an
        // `ORDER BY created_at` (no index covers it) forces SQLite/D1 to scan +
        // sort the ENTIRE matching set into a temp B-tree before applying LIMIT —
        // i.e. it loads the whole bloated box into the 128 MB isolate and OOMs,
        // defeating the bound. Without ORDER BY, the engine scans by the
        // (recipient, message_box_id) index and stops after LIMIT rows (rowid /
        // insertion order ≈ oldest-first), so memory is bounded by LIMIT. A
        // draining client (list → acknowledge → repeat) still walks the backlog.
        // Same bounded transient-retry as `find_message_box`: this is the second
        // (and only other) D1 touch on the `/listMessages` cold path and is an
        // equally-idempotent read, so a cold-start blip here self-heals in-request.
        let q = Query::new(
            "SELECT message_id AS messageId, body, sender, created_at, updated_at \
             FROM messages WHERE recipient = ? AND message_box_id = ? \
             AND acknowledged_at IS NULL \
             LIMIT ?",
        )
        .bind(identity_key)
        .bind(box_id)
        .bind(LIST_MESSAGES_LIMIT);
        with_d1_read_retry(|| q.fetch_all(self.db)).await
    }

    /// Acknowledge messages. For a RETAINED box (bsv-low #252 stage E — see
    /// `retention::RetentionConfig`) the row is MARKED delivered
    /// (`acknowledged_at`) so the transcript survives for mid-hand rejoin; for
    /// every other box it is DELETED, exactly as before. With retention off the
    /// statement is the legacy DELETE byte-for-byte
    /// (`retention::ack_delete_sql(n, 0)` — pinned by test).
    ///
    /// Returns the count of affected rows (marks + deletes). The
    /// `acknowledged_at IS NULL` guard in the UPDATE keeps the changes-count
    /// semantics identical to the delete path, so the caller's
    /// 0-changes → "Message not found" contract is unchanged.
    pub async fn acknowledge_messages(
        &self,
        identity_key: &str,
        message_ids: &[String],
        retention: &crate::retention::RetentionConfig,
    ) -> worker::Result<usize> {
        // Bounded write timeout+retry (`with_d1_write_retry`) on every
        // statement: a stall has the same hang risk as the send-path insert.
        // Fully idempotent — re-marking marks 0 rows (IS NULL guard), deleting
        // already-deleted rows is a no-op. If we RETRIED and the statements
        // report 0 changes, our own earlier (timed-out, dropped-but-landed)
        // attempt already applied them, so report the requested ids as
        // acknowledged rather than a spurious "Message not found".
        let n_prefixes = retention.prefix_count();
        let patterns = retention.like_patterns();
        let mut total_changes = 0usize;
        let mut any_retried = false;

        if n_prefixes > 0 {
            // Retained half: MARK delivered — never a delete (the stage-E pin).
            let sql = crate::retention::ack_update_sql(message_ids.len(), n_prefixes);
            let mut q = Query::new(&sql).bind(identity_key);
            for id in message_ids {
                q = q.bind(id.as_str());
            }
            for p in &patterns {
                q = q.bind(p.as_str());
            }
            let (meta, retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
            total_changes += meta.changes;
            any_retried |= retried;
        }

        // Delete half: everything OUTSIDE the retained class (with retention
        // off this is the whole request — the legacy statement).
        let sql = crate::retention::ack_delete_sql(message_ids.len(), n_prefixes);
        let mut q = Query::new(&sql).bind(identity_key);
        for id in message_ids {
            q = q.bind(id.as_str());
        }
        for p in &patterns {
            q = q.bind(p.as_str());
        }
        let (meta, retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
        total_changes += meta.changes;
        any_retried |= retried;

        if total_changes > 0 {
            return Ok(total_changes);
        }
        Ok(if any_retried { message_ids.len() } else { 0 })
    }

    // -- Fee operations --

    /// Get server delivery fee for a message box type. Returns 0 if not configured.
    pub async fn get_server_delivery_fee(&self, box_type: &str) -> worker::Result<i32> {
        let row: Option<ServerFeeRow> =
            Query::new("SELECT delivery_fee FROM server_fees WHERE message_box = ?")
                .bind(box_type)
                .fetch_optional(self.db)
                .await?;
        Ok(row
            .and_then(|r| r.delivery_fee.map(|v| v as i32))
            .unwrap_or(0))
    }

    /// Get recipient fee (hierarchical: sender-specific → box-wide → auto-create default).
    /// Returns -1 = blocked, 0 = free, >0 = satoshis required.
    pub async fn get_recipient_fee(
        &self,
        recipient: &str,
        sender: &str,
        box_type: &str,
    ) -> worker::Result<i32> {
        // 1. Check sender-specific permission
        let specific: Option<RecipientFeeRow> = Query::new(
            "SELECT recipient_fee FROM message_permissions \
             WHERE recipient = ? AND sender = ? AND message_box = ?",
        )
        .bind(recipient)
        .bind(sender)
        .bind(box_type)
        .fetch_optional(self.db)
        .await?;
        if let Some(row) = specific {
            return Ok(row.recipient_fee.map(|v| v as i32).unwrap_or(0));
        }

        // 2. Check box-wide default (sender IS NULL)
        let box_wide: Option<RecipientFeeRow> = Query::new(
            "SELECT recipient_fee FROM message_permissions \
             WHERE recipient = ? AND sender IS NULL AND message_box = ?",
        )
        .bind(recipient)
        .bind(box_type)
        .fetch_optional(self.db)
        .await?;
        if let Some(row) = box_wide {
            return Ok(row.recipient_fee.map(|v| v as i32).unwrap_or(0));
        }

        // 3. Auto-create default.
        //
        // #251: same op-timeout + bounded transient-retry as the other writes —
        // a stalled INSERT here hung the whole fee lookup. Fully idempotent
        // (`INSERT OR IGNORE` on the unique permission key, result discarded;
        // the returned fee is computed, not read back), so a dropped-but-landed
        // attempt re-run by the retry can never double-apply.
        let default_fee = smart_default_fee(box_type);
        let insert = Query::new(
            "INSERT OR IGNORE INTO message_permissions \
             (recipient, sender, message_box, recipient_fee) VALUES (?, NULL, ?, ?)",
        )
        .bind(recipient)
        .bind(box_type)
        .bind(default_fee);
        let (_meta, _retried) = with_d1_write_retry(|| insert.execute(self.db)).await?;
        Ok(default_fee)
    }

    /// #9 hot-path reader: recipient fee + server delivery fee + recipient's message-box id
    /// in ONE D1 `batch()` round-trip (the three are independent reads). Replaces the 3-4
    /// SEQUENTIAL queries `process_send` used per round-message — the dominant per-message
    /// relay cost for keygen/aux ceremonies. Semantics match `get_recipient_fee`
    /// (sender-specific preferred → box-wide → computed default) + `get_server_delivery_fee`
    /// + `find_message_box`. Unlike `get_recipient_fee`, it does NOT auto-create the default
    ///   permission row — that write is redundant (the default is recomputed identically on
    ///   every send), so dropping it removes one D1 write per message. `box_id == None` ⇒ the
    ///   caller creates the box (only on the very first message to a recipient).
    pub async fn read_send_context(
        &self,
        recipient: &str,
        sender: &str,
        box_type: &str,
    ) -> worker::Result<SendContext> {
        use crate::d1::QVal;
        // #9 reliability/no-flakiness: retry the batch on a TRANSIENT D1 error (the CF
        // `D1Error: ... storage ... object reset` blip during D1 cold-start/recovery that
        // intermittently 500s /sendMessage and stalls a ceremony). All three reads are
        // idempotent, so retry is always safe. 3 attempts, 100ms→200ms backoff.
        let mut last_err: Option<worker::Error> = None;
        for attempt in 0..3u32 {
            let fee_stmt = self
                .db
                .prepare(
                    "SELECT recipient_fee FROM message_permissions \
                     WHERE recipient = ? AND message_box = ? AND (sender = ? OR sender IS NULL) \
                     ORDER BY (sender IS NULL) ASC LIMIT 1",
                )
                .bind(&[
                    QVal::from(recipient).to_js(),
                    QVal::from(box_type).to_js(),
                    QVal::from(sender).to_js(),
                ])?;
            let server_stmt = self
                .db
                .prepare("SELECT delivery_fee FROM server_fees WHERE message_box = ?")
                .bind(&[QVal::from(box_type).to_js()])?;
            let box_stmt = self
                .db
                .prepare(
                    "SELECT message_box_id FROM message_boxes WHERE identity_key = ? AND type = ?",
                )
                .bind(&[QVal::from(recipient).to_js(), QVal::from(box_type).to_js()])?;

            match self.db.batch(vec![fee_stmt, server_stmt, box_stmt]).await {
                Ok(results) => {
                    let fee_rows: Vec<RecipientFeeRow> = results[0].results()?;
                    let recipient_fee = fee_rows
                        .first()
                        .and_then(|r| r.recipient_fee.map(|v| v as i32))
                        .unwrap_or_else(|| smart_default_fee(box_type));

                    let server_rows: Vec<ServerFeeRow> = results[1].results()?;
                    let server_fee = server_rows
                        .first()
                        .and_then(|r| r.delivery_fee.map(|v| v as i32))
                        .unwrap_or(0);

                    let box_rows: Vec<MessageBoxRow> = results[2].results()?;
                    let box_id = box_rows
                        .first()
                        .and_then(|r| r.message_box_id.map(|v| v as i64));

                    return Ok(SendContext {
                        recipient_fee,
                        server_fee,
                        box_id,
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < 2 {
                        worker::Delay::from(std::time::Duration::from_millis(100u64 << attempt))
                            .await;
                    }
                }
            }
        }
        Err(last_err.expect("read_send_context retry loop ran at least once"))
    }

    // -- Permission CRUD --

    /// Upsert a permission. Returns true on success.
    ///
    /// #251: guarded by the same op-timeout + bounded transient-retry as the
    /// send-path writes (`with_d1_write_retry`). The upsert is idempotent — the
    /// same values converge to the same row whether this attempt, a retry, or a
    /// dropped-but-landed attempt applied it. A retry that reports 0 changes
    /// means our own earlier (timed-out, dropped-but-landed) attempt already
    /// upserted the row — success, not failure (same reinterpretation rule as
    /// `insert_message`).
    pub async fn set_permission(
        &self,
        recipient: &str,
        sender: Option<&str>,
        message_box: &str,
        recipient_fee: i32,
    ) -> worker::Result<bool> {
        let q = match sender {
            Some(s) => Query::new(
                "INSERT INTO message_permissions (recipient, sender, message_box, recipient_fee) \
                     VALUES (?, ?, ?, ?) \
                     ON CONFLICT (recipient, sender, message_box) \
                     DO UPDATE SET recipient_fee = ?, updated_at = datetime('now')",
            )
            .bind(recipient)
            .bind(s)
            .bind(message_box)
            .bind(recipient_fee)
            .bind(recipient_fee),
            None => Query::new(
                "INSERT INTO message_permissions (recipient, sender, message_box, recipient_fee) \
                     VALUES (?, NULL, ?, ?) \
                     ON CONFLICT (recipient, sender, message_box) \
                     DO UPDATE SET recipient_fee = ?, updated_at = datetime('now')",
            )
            .bind(recipient)
            .bind(message_box)
            .bind(recipient_fee)
            .bind(recipient_fee),
        };
        let (meta, retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
        Ok(meta.changes > 0 || retried)
    }

    /// Get a single permission for (recipient, sender, message_box).
    pub async fn get_permission(
        &self,
        recipient: &str,
        sender: Option<&str>,
        message_box: &str,
    ) -> worker::Result<Option<PermissionDbRow>> {
        match sender {
            Some(s) => {
                Query::new(
                    "SELECT sender, message_box, recipient_fee, created_at, updated_at \
                     FROM message_permissions \
                     WHERE recipient = ? AND sender = ? AND message_box = ?",
                )
                .bind(recipient)
                .bind(s)
                .bind(message_box)
                .fetch_optional(self.db)
                .await
            }
            None => {
                Query::new(
                    "SELECT sender, message_box, recipient_fee, created_at, updated_at \
                     FROM message_permissions \
                     WHERE recipient = ? AND sender IS NULL AND message_box = ?",
                )
                .bind(recipient)
                .bind(message_box)
                .fetch_optional(self.db)
                .await
            }
        }
    }

    // -- Device operations --

    /// Upsert a device registration. INSERT OR REPLACE. Returns the last_row_id.
    ///
    /// #251: op-timeout + bounded transient-retry (`with_d1_write_retry`).
    /// Idempotent — `INSERT OR REPLACE` on the same values converges to the same
    /// row; a retry after a dropped-but-landed attempt just replaces it again.
    pub async fn upsert_device(
        &self,
        identity_key: &str,
        fcm_token: &str,
        device_id: Option<&str>,
        platform: Option<&str>,
    ) -> worker::Result<i64> {
        let q = Query::new(
            "INSERT OR REPLACE INTO device_registrations \
             (identity_key, fcm_token, device_id, platform, active) \
             VALUES (?, ?, ?, ?, 1)",
        )
        .bind(identity_key)
        .bind(fcm_token)
        .bind(device_id)
        .bind(platform);
        let (meta, _retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
        Ok(meta.last_row_id)
    }

    /// List all device registrations for an identity key.
    pub async fn list_devices(&self, identity_key: &str) -> worker::Result<Vec<DeviceDbRow>> {
        Query::new(
            "SELECT id, device_id, platform, fcm_token, active, created_at, updated_at, last_used \
             FROM device_registrations WHERE identity_key = ?",
        )
        .bind(identity_key)
        .fetch_all(self.db)
        .await
    }

    /// Get active device registrations for an identity key.
    pub async fn get_active_devices(&self, identity_key: &str) -> worker::Result<Vec<DeviceDbRow>> {
        Query::new(
            "SELECT id, device_id, platform, fcm_token, active, created_at, updated_at, last_used \
             FROM device_registrations WHERE identity_key = ? AND active = 1",
        )
        .bind(identity_key)
        .fetch_all(self.db)
        .await
    }

    /// Deactivate a device by FCM token (mark active = 0).
    ///
    /// #251: op-timeout + bounded transient-retry. Idempotent — re-marking an
    /// already-inactive row is a no-op (`updated_at` merely re-touches).
    pub async fn deactivate_device(&self, fcm_token: &str) -> worker::Result<()> {
        let q = Query::new(
            "UPDATE device_registrations SET active = 0, updated_at = datetime('now') \
             WHERE fcm_token = ?",
        )
        .bind(fcm_token);
        let (_meta, _retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
        Ok(())
    }

    /// Update the last_used timestamp for a device by FCM token.
    ///
    /// #251: op-timeout + bounded transient-retry. Idempotent — a re-applied
    /// timestamp touch converges (advisory column, no reader depends on an
    /// exact value).
    pub async fn update_device_last_used(&self, fcm_token: &str) -> worker::Result<()> {
        let q = Query::new(
            "UPDATE device_registrations SET last_used = datetime('now') WHERE fcm_token = ?",
        )
        .bind(fcm_token);
        let (_meta, _retried) = with_d1_write_retry(|| q.execute(self.db)).await?;
        Ok(())
    }

    /// List permissions with pagination. Returns (rows, total_count).
    pub async fn list_permissions(
        &self,
        recipient: &str,
        message_box: Option<&str>,
        limit: u32,
        offset: u32,
        sort_order: &str, // "asc" or "desc"
    ) -> worker::Result<(Vec<PermissionDbRow>, u64)> {
        // Build WHERE clause
        let (where_clause, count_sql, list_sql);
        match message_box {
            Some(mb) => {
                where_clause = "WHERE recipient = ? AND message_box = ?";
                count_sql = format!(
                    "SELECT COUNT(*) AS count FROM message_permissions {}",
                    where_clause
                );
                list_sql = format!(
                    "SELECT sender, message_box, recipient_fee, created_at, updated_at \
                     FROM message_permissions {} \
                     ORDER BY message_box ASC, \
                              CASE WHEN sender IS NULL THEN 0 ELSE 1 END ASC, \
                              sender ASC, \
                              created_at {} \
                     LIMIT ? OFFSET ?",
                    where_clause, sort_order
                );

                // Count
                let count_row: Option<CountRow> = Query::new(&count_sql)
                    .bind(recipient)
                    .bind(mb)
                    .fetch_optional(self.db)
                    .await?;
                let total = count_row
                    .and_then(|r| r.count.map(|v| v as u64))
                    .unwrap_or(0);

                // List
                let rows: Vec<PermissionDbRow> = Query::new(&list_sql)
                    .bind(recipient)
                    .bind(mb)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(self.db)
                    .await?;

                Ok((rows, total))
            }
            None => {
                where_clause = "WHERE recipient = ?";
                count_sql = format!(
                    "SELECT COUNT(*) AS count FROM message_permissions {}",
                    where_clause
                );
                list_sql = format!(
                    "SELECT sender, message_box, recipient_fee, created_at, updated_at \
                     FROM message_permissions {} \
                     ORDER BY message_box ASC, \
                              CASE WHEN sender IS NULL THEN 0 ELSE 1 END ASC, \
                              sender ASC, \
                              created_at {} \
                     LIMIT ? OFFSET ?",
                    where_clause, sort_order
                );

                let count_row: Option<CountRow> = Query::new(&count_sql)
                    .bind(recipient)
                    .fetch_optional(self.db)
                    .await?;
                let total = count_row
                    .and_then(|r| r.count.map(|v| v as u64))
                    .unwrap_or(0);

                let rows: Vec<PermissionDbRow> = Query::new(&list_sql)
                    .bind(recipient)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(self.db)
                    .await?;

                Ok((rows, total))
            }
        }
    }
}

/// Classify a `worker::Error` as a *transient* D1 failure that is safe to retry
/// on an idempotent read.
///
/// The dominant case is a cold-start blip: the FIRST D1 query after the Worker
/// or its D1 binding goes cold intermittently rejects with a `D1_ERROR`
/// ("Network connection lost" / "storage … reset") before the binding is warm,
/// then succeeds on the very next call. A live probe of low-relay reproduced
/// exactly this: 1st `/listMessages` after idle → 500, next 4/4 warm calls green.
///
/// Deliberately does NOT match not-found / auth / validation: those never reach
/// a storage read as an `Err` (a missing row is `Ok(None)`/`Ok(vec![])`, and
/// auth/validation short-circuit upstream in `lib.rs`), so they cannot be
/// mis-retried here and keep returning their correct status.
pub(crate) fn is_transient_d1_error(e: &worker::Error) -> bool {
    // Every D1-layer failure surfaces as `Error::D1(_)` — the worker crate tags
    // any JS error whose message starts with "D1". Our read queries are static
    // and well-formed, so a D1-layer error on them is infra, not a query bug.
    if matches!(e, worker::Error::D1(_)) {
        return true;
    }
    // Some cold-start failures surface as a generic runtime/JS error before D1
    // tags them; match the known-transient markers on the error text.
    let s = e.to_string().to_ascii_lowercase();
    const TRANSIENT_MARKERS: [&str; 8] = [
        "d1_error",
        "network connection lost",
        "storage",
        "reset",
        "internal error",
        "connection",
        "timed out",
        "please try again",
    ];
    TRANSIENT_MARKERS.iter().any(|m| s.contains(m))
}

/// Pure retry policy: given the zero-based `attempt` that just failed and its
/// error, return `Some(backoff)` to retry after `backoff`, or `None` to give up
/// and propagate the error. Extracted as a pure fn so the policy — bounded count
/// AND transient-only — is unit-testable without a live D1 or JS runtime.
fn d1_retry_backoff(attempt: u32, err: &worker::Error) -> Option<std::time::Duration> {
    d1_retry_backoff_bounded(attempt, D1_READ_ATTEMPTS, err)
}

/// Shared retry policy for both reads and writes, parameterised on the attempt
/// bound. Same transient-only rule and 50/100ms backoff; the READ path passes
/// `D1_READ_ATTEMPTS`, the WRITE path `D1_WRITE_ATTEMPTS`.
fn d1_retry_backoff_bounded(
    attempt: u32,
    max_attempts: u32,
    err: &worker::Error,
) -> Option<std::time::Duration> {
    // Bound: `attempt` is zero-based, so the last allowed attempt index is
    // max_attempts - 1; past that we stop (no unbounded loop).
    if attempt + 1 >= max_attempts {
        return None;
    }
    // Only the transient cold-start class is retried; a genuine error is returned
    // as-is so the caller still produces its correct (non-200) status.
    if !is_transient_d1_error(err) {
        return None;
    }
    // 50ms, 100ms — a cold binding warms in well under this, and total added
    // backoff on a genuine outage stays bounded (< 150ms).
    Some(std::time::Duration::from_millis(50u64 << attempt))
}

/// Bound one idempotent D1 WRITE future by a per-op wall-clock timeout
/// (`D1_WRITE_OP_TIMEOUT_MS`).
///
/// On wasm (the real Worker) the write future is raced against a `worker::Delay`;
/// if the delay wins, the write future is DROPPED and a transient timeout error
/// is returned so `with_d1_write_retry` re-attempts. A dropped D1 subrequest may
/// still land on the platform — which is exactly why every write we bound is
/// idempotent/dedup-safe on a `UNIQUE` key (see `insert_message` /
/// `acknowledge_messages`): a re-attempt can never double-apply.
///
/// On the host test target there is no JS event loop to drive `Delay`, so the op
/// is awaited directly (host tests exercise the retry/timeout POLICY via injected
/// errors, never a real hang).
#[cfg(target_arch = "wasm32")]
async fn with_d1_op_timeout<T, Fut>(op: Fut, timeout_ms: u64) -> worker::Result<T>
where
    Fut: std::future::Future<Output = worker::Result<T>>,
{
    use std::future::Future;
    use std::task::Poll;
    let mut op = Box::pin(op);
    let mut timeout =
        Box::pin(worker::Delay::from(std::time::Duration::from_millis(timeout_ms)));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(r) = op.as_mut().poll(cx) {
            return Poll::Ready(r);
        }
        if timeout.as_mut().poll(cx).is_ready() {
            // "d1_error" marker ⇒ classified transient ⇒ retried by the loop, and
            // ⇒ mapped to a client-retryable 503 by the send path if unrecovered.
            return Poll::Ready(Err(worker::Error::RustError(format!(
                "D1_ERROR: write op exceeded {timeout_ms}ms bound (transient; retrying)"
            ))));
        }
        Poll::Pending
    })
    .await
}
#[cfg(not(target_arch = "wasm32"))]
async fn with_d1_op_timeout<T, Fut>(op: Fut, _timeout_ms: u64) -> worker::Result<T>
where
    Fut: std::future::Future<Output = worker::Result<T>>,
{
    op.await
}

/// Run an idempotent D1 WRITE `op` with a per-op wall-clock bound
/// (`with_d1_op_timeout`) AND a bounded transient-retry (`D1_WRITE_ATTEMPTS`).
/// The write-path analogue of `with_d1_read_retry`, plus the timeout the reads
/// don't need (a read that stalls is rarer and out of scope here; the observed
/// hang was the write path).
///
/// Returns `(value, retried)`. `retried` is `true` iff at least one earlier
/// attempt failed/timed-out before success — callers use it to keep
/// INSERT-OR-IGNORE / DELETE idempotent, because a dropped-but-landed write makes
/// the successful re-attempt report `0` changes, which after a retry means "our
/// own earlier attempt already applied it", NOT a genuine duplicate / not-found.
pub(crate) async fn with_d1_write_retry<T, F, Fut>(mut op: F) -> worker::Result<(T, bool)>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = worker::Result<T>>,
{
    let mut attempt = 0u32;
    let mut retried = false;
    loop {
        match with_d1_op_timeout(op(), D1_WRITE_OP_TIMEOUT_MS).await {
            Ok(v) => return Ok((v, retried)),
            Err(e) => match d1_retry_backoff_bounded(attempt, D1_WRITE_ATTEMPTS, &e) {
                Some(backoff) => {
                    retry_backoff_sleep(backoff).await;
                    attempt += 1;
                    retried = true;
                }
                None => return Err(e),
            },
        }
    }
}

/// Interpret an `INSERT OR IGNORE` change count into "the row is stored" for
/// `insert_message`, honouring idempotency under retry.
///
/// * `changes > 0` ⇒ inserted now ⇒ stored (`true`).
/// * `changes == 0 && retried` ⇒ the row exists because our OWN earlier
///   (timed-out, dropped-but-landed) attempt of this same send stored it ⇒
///   stored (`true`), NOT a spurious duplicate.
/// * `changes == 0 && !retried` ⇒ a clean first-attempt collision ⇒ a genuine
///   duplicate `messageId` (`false`) — unchanged behaviour.
///
/// Pure fn so the idempotency rule is unit-testable without a live D1.
fn insert_changes_mean_stored(changes: usize, retried: bool) -> bool {
    changes > 0 || retried
}

/// Back off between retries. On the Worker (wasm) this is a real `setTimeout`-
/// backed `worker::Delay`; on the host test target it is a no-op (Delay needs a
/// JS event loop), which lets `with_d1_read_retry` be driven under `#[tokio::test]`.
#[cfg(target_arch = "wasm32")]
async fn retry_backoff_sleep(d: std::time::Duration) {
    worker::Delay::from(d).await;
}
#[cfg(not(target_arch = "wasm32"))]
async fn retry_backoff_sleep(_d: std::time::Duration) {}

/// Run an idempotent D1 read `op` with a bounded, transient-only retry
/// (`d1_retry_backoff`). Returns on the first success; retries a transient
/// cold-start error up to `D1_READ_ATTEMPTS`; on a non-transient error (or once
/// the bound is hit) propagates the original error unchanged.
pub(crate) async fn with_d1_read_retry<T, F, Fut>(mut op: F) -> worker::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = worker::Result<T>>,
{
    let mut attempt = 0u32;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => match d1_retry_backoff(attempt, &e) {
                Some(backoff) => {
                    retry_backoff_sleep(backoff).await;
                    attempt += 1;
                }
                None => return Err(e),
            },
        }
    }
}

/// Default fee for auto-created permissions: notifications = 10 sats, everything else = 0.
fn smart_default_fee(box_type: &str) -> i32 {
    if box_type == "notifications" {
        10
    } else {
        0
    }
}

/// Convert SQLite datetime format ("YYYY-MM-DD HH:MM:SS") to ISO 8601
/// ("YYYY-MM-DDTHH:MM:SS.000Z") for 1:1 parity with Node.js reference,
/// which uses MySQL's `Date.toISOString()`.
///
/// - `None` → empty string
/// - Already-ISO input (contains 'T' and ends with 'Z' or has timezone '+') → pass-through
/// - SQLite 19-char form "YYYY-MM-DD HH:MM:SS" → "YYYY-MM-DDTHH:MM:SS.000Z"
/// - Any other shape → trimmed pass-through (safe fallback)
pub fn to_iso8601(sqlite_ts: Option<&str>) -> String {
    match sqlite_ts {
        None => String::new(),
        Some(s) => {
            // If already ISO format (has T and Z or explicit offset), pass through.
            if s.contains('T') && (s.ends_with('Z') || s.contains('+')) {
                return s.to_string();
            }
            let trimmed = s.trim();
            if trimmed.len() == 19 && trimmed.chars().nth(10) == Some(' ') {
                let iso = trimmed.replacen(' ', "T", 1);
                format!("{}.000Z", iso)
            } else {
                trimmed.to_string()
            }
        }
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use std::cell::Cell;

    // Representative cold-start transient (the exact class the live probe hit).
    fn transient() -> worker::Error {
        worker::Error::RustError("D1_ERROR: Network connection lost.".into())
    }
    // A non-transient error (our own "couldn't create box" style message).
    fn permanent() -> worker::Error {
        worker::Error::RustError("Failed to create message box".into())
    }

    #[test]
    fn classifier_matches_cold_start_transients_only() {
        assert!(is_transient_d1_error(&transient()));
        assert!(is_transient_d1_error(&worker::Error::JsError(
            "D1_ERROR: storage caught an exception; object was reset".into()
        )));
        assert!(is_transient_d1_error(&worker::Error::RustError(
            "Internal error while accessing storage".into()
        )));
        // Not transient: a plain not-found-style / validation message must NOT retry.
        assert!(!is_transient_d1_error(&permanent()));
        assert!(!is_transient_d1_error(&worker::Error::Json((
            "Invalid messageBox".into(),
            400
        ))));
    }

    #[test]
    fn backoff_is_bounded_and_transient_only() {
        // Transient on the first two attempts → retry with growing backoff.
        assert_eq!(
            d1_retry_backoff(0, &transient()),
            Some(std::time::Duration::from_millis(50))
        );
        assert_eq!(
            d1_retry_backoff(1, &transient()),
            Some(std::time::Duration::from_millis(100))
        );
        // Bound reached (attempt index == D1_READ_ATTEMPTS - 1) → give up.
        assert_eq!(d1_retry_backoff(D1_READ_ATTEMPTS - 1, &transient()), None);
        // Non-transient → never retried, even on the first attempt.
        assert_eq!(d1_retry_backoff(0, &permanent()), None);
    }

    // Drives the real retry runner (host no-op backoff) with a mocked op that
    // fails once with a transient error then succeeds — the unit-level analogue
    // of "cold-start 500 self-heals to a 200 within the same request".
    #[tokio::test]
    async fn read_recovers_after_one_transient_failure() {
        let calls = Cell::new(0u32);
        let out: worker::Result<i64> = with_d1_read_retry(|| {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 1 {
                    Err(transient())
                } else {
                    Ok(42_i64)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 42);
        assert_eq!(calls.get(), 2, "failed once, succeeded on the retry");
    }

    #[tokio::test]
    async fn read_gives_up_after_bound_on_persistent_transient() {
        let calls = Cell::new(0u32);
        let out: worker::Result<i64> = with_d1_read_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<i64, _>(transient()) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), D1_READ_ATTEMPTS, "bounded, no unbounded loop");
    }

    // #251: a stalled READ (find_message_box now bounds its op) surfaces as the
    // same timeout-shaped transient error the write path produces — the
    // read-retry loop must re-attempt it, turning a would-be request hang into
    // an in-request self-heal.
    #[tokio::test]
    async fn read_retries_a_stall_timeout_error() {
        let calls = Cell::new(0u32);
        let out: worker::Result<i64> = with_d1_read_retry(|| {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 1 {
                    Err(timeout_err())
                } else {
                    Ok(7_i64)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 7);
        assert_eq!(calls.get(), 2, "stall → transient error → retried, not hung");
    }

    #[tokio::test]
    async fn read_does_not_retry_permanent_error() {
        let calls = Cell::new(0u32);
        let out: worker::Result<i64> = with_d1_read_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<i64, _>(permanent()) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "non-transient error returns immediately");
    }

    // ---- Write-path timeout + retry (bsv-low#249 send-path hang) ----

    use crate::d1::ExecMeta;

    fn meta(changes: usize) -> ExecMeta {
        ExecMeta {
            last_row_id: 0,
            changes,
        }
    }

    // The timeout wrapper produces this exact class of error on a stall; assert it
    // classifies transient so the loop retries it (and the send path 503s it).
    fn timeout_err() -> worker::Error {
        worker::Error::RustError(
            "D1_ERROR: write op exceeded 2000ms bound (transient; retrying)".into(),
        )
    }

    #[test]
    fn timeout_error_is_transient() {
        assert!(
            is_transient_d1_error(&timeout_err()),
            "a per-op write timeout must be retried, not surfaced as a hard error"
        );
    }

    #[test]
    fn write_backoff_bounded_and_transient_only() {
        assert_eq!(
            d1_retry_backoff_bounded(0, D1_WRITE_ATTEMPTS, &transient()),
            Some(std::time::Duration::from_millis(50))
        );
        assert_eq!(
            d1_retry_backoff_bounded(1, D1_WRITE_ATTEMPTS, &transient()),
            Some(std::time::Duration::from_millis(100))
        );
        // Bound reached → stop (fast-fail rather than a hang/unbounded loop).
        assert_eq!(
            d1_retry_backoff_bounded(D1_WRITE_ATTEMPTS - 1, D1_WRITE_ATTEMPTS, &transient()),
            None
        );
        // Non-transient (a real constraint/logic error) is never retried.
        assert_eq!(
            d1_retry_backoff_bounded(0, D1_WRITE_ATTEMPTS, &permanent()),
            None
        );
    }

    // A transient write stall on the FIRST attempt recovers on the retry — the
    // unit-level analogue of "the 10s send hang self-heals in ~ms against a warm
    // binding". `retried` comes back true, which drives the idempotency rule.
    #[tokio::test]
    async fn write_recovers_after_one_transient_stall() {
        let calls = Cell::new(0u32);
        let out: worker::Result<(ExecMeta, bool)> = with_d1_write_retry(|| {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 1 {
                    Err(timeout_err())
                } else {
                    Ok(meta(1))
                }
            }
        })
        .await;
        let (m, retried) = out.expect("recovers on retry");
        assert_eq!(m.changes, 1);
        assert!(retried, "a retry happened → idempotency reinterpretation armed");
        assert_eq!(calls.get(), 2);
    }

    // Genuinely-down D1: every attempt stalls → bounded fast-fail, NOT a hang.
    // The propagated error is transient → the send path maps it to a retryable
    // 503, never a 10s stranded client.
    #[tokio::test]
    async fn write_fails_fast_after_bound_on_persistent_stall() {
        let calls = Cell::new(0u32);
        let out: worker::Result<(ExecMeta, bool)> = with_d1_write_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<ExecMeta, _>(timeout_err()) }
        })
        .await;
        let err = out.err().expect("bounded give-up");
        assert!(
            is_transient_d1_error(&err),
            "surfaces as transient → client-retryable 503, not a hard 500"
        );
        assert_eq!(calls.get(), D1_WRITE_ATTEMPTS, "bounded, no unbounded loop");
    }

    #[tokio::test]
    async fn write_does_not_retry_permanent_error() {
        let calls = Cell::new(0u32);
        let out: worker::Result<(ExecMeta, bool)> = with_d1_write_retry(|| {
            calls.set(calls.get() + 1);
            async move { Err::<ExecMeta, _>(permanent()) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls.get(), 1, "non-transient error returns immediately");
    }

    // Idempotency under retry: a dropped-but-landed write makes the successful
    // re-attempt report 0 changes. After a retry that MUST read as "stored"
    // (success), never as a spurious duplicate.
    #[test]
    fn insert_idempotency_under_retry() {
        // Clean first attempt inserted the row.
        assert!(insert_changes_mean_stored(1, false), "fresh insert = stored");
        // Clean first-attempt collision = genuine duplicate messageId.
        assert!(
            !insert_changes_mean_stored(0, false),
            "first-attempt 0 changes = genuine duplicate (unchanged)"
        );
        // Retry that finally inserted.
        assert!(insert_changes_mean_stored(1, true));
        // Retry that saw the row already present (our own earlier attempt landed).
        assert!(
            insert_changes_mean_stored(0, true),
            "0 changes AFTER a retry = our own prior attempt stored it → success, not duplicate"
        );
    }

    // Full producer-path simulation for insert_message's core: attempt 1 stalls
    // (dropped write actually lands on the platform), attempt 2's INSERT OR IGNORE
    // reports 0 changes — the send must still report the message STORED.
    #[tokio::test]
    async fn insert_message_stall_then_dropped_write_landed_is_success() {
        let calls = Cell::new(0u32);
        let (m, retried): (ExecMeta, bool) = with_d1_write_retry(|| {
            calls.set(calls.get() + 1);
            let n = calls.get();
            async move {
                if n == 1 {
                    Err(timeout_err()) // stalled; the dropped write silently landed
                } else {
                    Ok(meta(0)) // OR IGNORE sees the already-present row
                }
            }
        })
        .await
        .expect("recovers");
        assert!(
            insert_changes_mean_stored(m.changes, retried),
            "dropped-but-landed insert must resolve to STORED, not ERR_DUPLICATE_MESSAGE"
        );
    }
}

#[cfg(test)]
mod iso_tests {
    use super::to_iso8601;

    #[test]
    fn sqlite_format_to_iso() {
        assert_eq!(
            to_iso8601(Some("2026-04-12 13:23:01")),
            "2026-04-12T13:23:01.000Z"
        );
    }

    #[test]
    fn already_iso_passthrough() {
        assert_eq!(
            to_iso8601(Some("2026-04-12T13:23:00.000Z")),
            "2026-04-12T13:23:00.000Z"
        );
    }

    #[test]
    fn already_iso_with_offset_passthrough() {
        assert_eq!(
            to_iso8601(Some("2026-04-12T13:23:00+00:00")),
            "2026-04-12T13:23:00+00:00"
        );
    }

    #[test]
    fn none_returns_empty_string() {
        assert_eq!(to_iso8601(None), "");
    }

    #[test]
    fn malformed_passthrough() {
        assert_eq!(to_iso8601(Some("not a date")), "not a date");
        assert_eq!(to_iso8601(Some("2026-04-12")), "2026-04-12");
        assert_eq!(to_iso8601(Some("")), "");
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            to_iso8601(Some("  2026-04-12 13:23:01  ")),
            "2026-04-12T13:23:01.000Z"
        );
    }

    #[test]
    fn midnight_edge_case() {
        assert_eq!(
            to_iso8601(Some("2026-01-01 00:00:00")),
            "2026-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn leap_year_edge_case() {
        assert_eq!(
            to_iso8601(Some("2024-02-29 12:34:56")),
            "2024-02-29T12:34:56.000Z"
        );
    }

    #[test]
    fn end_of_year_edge_case() {
        assert_eq!(
            to_iso8601(Some("2026-12-31 23:59:59")),
            "2026-12-31T23:59:59.000Z"
        );
    }

    #[test]
    fn wrong_length_passthrough() {
        // 20 chars but not standard format
        assert_eq!(
            to_iso8601(Some("2026-04-12 13:23:01x")),
            "2026-04-12 13:23:01x"
        );
    }

    #[test]
    fn separator_not_space_passthrough() {
        // 19 chars but separator at pos 10 is not a space
        assert_eq!(
            to_iso8601(Some("2026-04-12X13:23:01")),
            "2026-04-12X13:23:01"
        );
    }
}
