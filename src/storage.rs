// D1 storage operations for message-box.

use serde::Deserialize;
use worker::D1Database;

use crate::d1::Query;

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

impl<'a> Storage<'a> {
    pub fn new(db: &'a D1Database) -> Self {
        Self { db }
    }

    // -- Message box operations --

    /// Find message_box_id for (identity_key, type). Returns None if not found.
    pub async fn find_message_box(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<Option<i64>> {
        let row: Option<MessageBoxRow> = Query::new(
            "SELECT message_box_id FROM message_boxes WHERE identity_key = ? AND type = ?",
        )
        .bind(identity_key)
        .bind(box_type)
        .fetch_optional(self.db)
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
        // Create — INSERT OR IGNORE handles race conditions
        Query::new("INSERT OR IGNORE INTO message_boxes (identity_key, type) VALUES (?, ?)")
            .bind(identity_key)
            .bind(box_type)
            .execute(self.db)
            .await?;
        // Re-fetch to get the ID (handles both fresh insert and race)
        self.find_message_box(identity_key, box_type)
            .await?
            .ok_or_else(|| worker::Error::from("Failed to create message box"))
    }

    // -- Message operations --

    /// Insert a message. Returns true if inserted, false if duplicate (messageId conflict).
    pub async fn insert_message(
        &self,
        message_id: &str,
        message_box_id: i64,
        sender: &str,
        recipient: &str,
        body: &str,
    ) -> worker::Result<bool> {
        let meta = Query::new(
            "INSERT OR IGNORE INTO messages (message_id, message_box_id, sender, recipient, body) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(message_id)
        .bind(message_box_id)
        .bind(sender)
        .bind(recipient)
        .bind(body)
        .execute(self.db)
        .await?;
        Ok(meta.changes > 0)
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

        Query::new(
            "SELECT message_id AS messageId, body, sender, created_at, updated_at \
             FROM messages WHERE recipient = ? AND message_box_id = ?",
        )
        .bind(identity_key)
        .bind(box_id)
        .fetch_all(self.db)
        .await
    }

    /// Delete acknowledged messages. Returns count of deleted rows.
    pub async fn acknowledge_messages(
        &self,
        identity_key: &str,
        message_ids: &[String],
    ) -> worker::Result<usize> {
        // Build IN (?, ?, ...) clause dynamically
        let placeholders: Vec<&str> = message_ids.iter().map(|_| "?").collect();
        let sql = format!(
            "DELETE FROM messages WHERE recipient = ? AND message_id IN ({})",
            placeholders.join(", ")
        );
        let mut q = Query::new(&sql).bind(identity_key);
        for id in message_ids {
            q = q.bind(id.as_str());
        }
        let meta = q.execute(self.db).await?;
        Ok(meta.changes)
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

        // 3. Auto-create default
        let default_fee = smart_default_fee(box_type);
        Query::new(
            "INSERT OR IGNORE INTO message_permissions \
             (recipient, sender, message_box, recipient_fee) VALUES (?, NULL, ?, ?)",
        )
        .bind(recipient)
        .bind(box_type)
        .bind(default_fee)
        .execute(self.db)
        .await?;
        Ok(default_fee)
    }

    // -- Permission CRUD --

    /// Upsert a permission. Returns true on success.
    pub async fn set_permission(
        &self,
        recipient: &str,
        sender: Option<&str>,
        message_box: &str,
        recipient_fee: i32,
    ) -> worker::Result<bool> {
        let meta = match sender {
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
            .bind(recipient_fee)
            .execute(self.db)
            .await?,
            None => Query::new(
                "INSERT INTO message_permissions (recipient, sender, message_box, recipient_fee) \
                     VALUES (?, NULL, ?, ?) \
                     ON CONFLICT (recipient, sender, message_box) \
                     DO UPDATE SET recipient_fee = ?, updated_at = datetime('now')",
            )
            .bind(recipient)
            .bind(message_box)
            .bind(recipient_fee)
            .bind(recipient_fee)
            .execute(self.db)
            .await?,
        };
        Ok(meta.changes > 0)
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
    pub async fn upsert_device(
        &self,
        identity_key: &str,
        fcm_token: &str,
        device_id: Option<&str>,
        platform: Option<&str>,
    ) -> worker::Result<i64> {
        let meta = Query::new(
            "INSERT OR REPLACE INTO device_registrations \
             (identity_key, fcm_token, device_id, platform, active) \
             VALUES (?, ?, ?, ?, 1)",
        )
        .bind(identity_key)
        .bind(fcm_token)
        .bind(device_id)
        .bind(platform)
        .execute(self.db)
        .await?;
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
    pub async fn deactivate_device(&self, fcm_token: &str) -> worker::Result<()> {
        Query::new(
            "UPDATE device_registrations SET active = 0, updated_at = datetime('now') \
             WHERE fcm_token = ?",
        )
        .bind(fcm_token)
        .execute(self.db)
        .await?;
        Ok(())
    }

    /// Update the last_used timestamp for a device by FCM token.
    pub async fn update_device_last_used(&self, fcm_token: &str) -> worker::Result<()> {
        Query::new(
            "UPDATE device_registrations SET last_used = datetime('now') WHERE fcm_token = ?",
        )
        .bind(fcm_token)
        .execute(self.db)
        .await?;
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
