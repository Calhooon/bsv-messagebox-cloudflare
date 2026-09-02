//! Transcript retention-until-terminal (bsv-low #252 stage E server
//! prerequisite; owner decision 2026-08-06).
//!
//! A deployment can declare that message boxes whose TYPE matches a configured
//! prefix list are RETAINED: `acknowledgeMessage` marks those rows delivered
//! (`acknowledged_at`) instead of deleting them, and an authorized party can
//! re-fetch the full ordered envelope chain via `POST /listTranscript` — so a
//! reloaded client with no local state can resume mid-hand without depending on
//! the peer being alive. Rows delete at game end via `POST /purgeTranscript`
//! (client-driven, recipient-scoped) with a TTL backstop sweep (cron) so
//! abandoned games never accumulate forever.
//!
//! The relay stays GENERIC: retention is a naming-convention predicate
//! (`RETAIN_BOX_PREFIXES`, per-deployment wrangler `[vars]`), never game
//! semantics. LOW turns it on for `low_game_` boxes in wrangler.low.toml; the
//! shared deployment leaves it unset and behaves exactly as before. The relay
//! never becomes a money home — this is transcript durability for rejoin,
//! nothing more.
//!
//! Authorization model (mirrors the existing read rules — no new authority):
//! * A transcript read returns ONLY rows where the BRC-103/104-verified caller
//!   is the recipient (what `/listMessages` always granted them) or the sender
//!   (bytes they authored). Both seats of a LOW hand therefore each reconstruct
//!   the full pair chain; a third party sees only its own traffic; a stranger
//!   sees nothing.
//! * A purge deletes ONLY rows where the caller is the RECIPIENT (its own
//!   boxes). A sender can NOT retract an envelope it already delivered — purge
//!   grants no power over the counterparty's mailbox that acknowledge didn't
//!   already grant.
//!
//! No KV is touched anywhere in this module (relay-cors-kv429 lesson): config
//! is a per-request env-var string parse; all state is D1.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::d1::Query;
use crate::storage::{with_d1_read_retry, with_d1_write_retry, CountRow, Storage};
use crate::validation::validate_list_messages;

/// Env var: comma-separated box-type prefixes that retain (e.g. "low_game_").
/// Unset/empty ⇒ retention is OFF and every path behaves exactly as before.
pub const RETAIN_BOX_PREFIXES_VAR: &str = "RETAIN_BOX_PREFIXES";

/// Env var: TTL backstop in days for retained rows. Default 14; values < 1 or
/// unparseable fall back to the default (a 0-day TTL would immediately eat
/// live transcripts — never allowed).
pub const RETAIN_TTL_DAYS_VAR: &str = "RETAIN_TTL_DAYS";
pub const DEFAULT_RETAIN_TTL_DAYS: u32 = 14;

/// Row cap for one `/listTranscript` response — the same 128 MB-isolate OOM
/// guard rationale as `LIST_MESSAGES_LIMIT`, sized for "a whole hand's
/// envelope chain" (a LOW hand is tens of messages; 1000 is orders of
/// magnitude of headroom while still bounding a pathological box).
const TRANSCRIPT_LIMIT: u32 = 1_000;

// ---------------------------------------------------------------------------
// Retention predicate (pure, config-driven)
// ---------------------------------------------------------------------------

/// The opt-in retention predicate: a box type is retained iff it starts with
/// one of the configured prefixes. Parsed fresh per request from the env var —
/// a cheap string split, no storage reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    prefixes: Vec<String>,
}

impl RetentionConfig {
    /// Parse the comma-separated prefix list. Whitespace around entries is
    /// trimmed; empty entries are dropped (so "low_game_," ≡ "low_game_").
    pub fn parse(raw: Option<&str>) -> Self {
        let prefixes = raw
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        Self { prefixes }
    }

    pub fn from_env(env: &worker::Env) -> Self {
        let raw = env
            .var(RETAIN_BOX_PREFIXES_VAR)
            .ok()
            .map(|v| v.to_string());
        Self::parse(raw.as_deref())
    }

    /// True when NO box retains — every path must then be byte-identical to
    /// the pre-retention relay.
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    pub(crate) fn prefix_count(&self) -> usize {
        self.prefixes.len()
    }

    /// The predicate: does this box type retain?
    pub fn retains(&self, box_type: &str) -> bool {
        self.prefixes.iter().any(|p| box_type.starts_with(p))
    }

    /// LIKE patterns for SQL prefix matching, `%`/`_`/`\` escaped so a prefix
    /// can never smuggle a wildcard into the retained set.
    pub(crate) fn like_patterns(&self) -> Vec<String> {
        self.prefixes
            .iter()
            .map(|p| format!("{}%", escape_like_prefix(p)))
            .collect()
    }
}

/// Escape SQL LIKE metacharacters in a literal prefix (ESCAPE '\').
fn escape_like_prefix(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len());
    for c in prefix.chars() {
        if c == '\\' || c == '%' || c == '_' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ---------------------------------------------------------------------------
// SQL builders (pure — every load-bearing statement is unit-testable)
// ---------------------------------------------------------------------------

/// `?, ?, ...` for an IN list. Matches the legacy `placeholders.join(", ")`
/// byte-for-byte so the no-retention delete SQL is unchanged.
fn in_placeholders(n: usize) -> String {
    vec!["?"; n].join(", ")
}

/// `(type LIKE ? ESCAPE '\' OR ...)` over `n` prefix patterns, against the
/// given column reference.
fn type_filter_sql(column: &str, n_prefixes: usize) -> String {
    let one = format!("{column} LIKE ? ESCAPE '\\'");
    let ors = vec![one; n_prefixes].join(" OR ");
    format!("({ors})")
}

/// The subquery selecting message_box_ids of RETAINED boxes. Shared verbatim
/// between the ack UPDATE (IN) and ack DELETE (NOT IN) so the two are exact
/// complements — no box can be both marked and deleted, or neither.
fn retained_box_subquery(n_prefixes: usize) -> String {
    format!(
        "SELECT message_box_id FROM message_boxes WHERE {}",
        type_filter_sql("type", n_prefixes)
    )
}

/// Acknowledge, retained half: MARK delivered — never a DELETE. The
/// `acknowledged_at IS NULL` guard keeps the changes-count semantics identical
/// to the legacy delete (re-acking an already-acked message counts 0, exactly
/// like re-acking an already-deleted one).
///
/// Bind order: identity_key, message_ids..., like_patterns...
pub(crate) fn ack_update_sql(n_ids: usize, n_prefixes: usize) -> String {
    format!(
        "UPDATE messages SET acknowledged_at = datetime('now'), updated_at = datetime('now') \
         WHERE recipient = ? AND acknowledged_at IS NULL AND message_id IN ({}) \
         AND message_box_id IN ({})",
        in_placeholders(n_ids),
        retained_box_subquery(n_prefixes)
    )
}

/// Acknowledge, delete half. With `n_prefixes == 0` (retention off) this is
/// the LEGACY statement byte-for-byte; with retention on, retained boxes are
/// excluded via NOT IN over the same subquery the UPDATE uses.
///
/// Bind order: identity_key, message_ids..., [like_patterns...]
pub(crate) fn ack_delete_sql(n_ids: usize, n_prefixes: usize) -> String {
    if n_prefixes == 0 {
        return format!(
            "DELETE FROM messages WHERE recipient = ? AND message_id IN ({})",
            in_placeholders(n_ids)
        );
    }
    format!(
        "DELETE FROM messages WHERE recipient = ? AND message_id IN ({}) \
         AND message_box_id NOT IN ({})",
        in_placeholders(n_ids),
        retained_box_subquery(n_prefixes)
    )
}

/// Transcript read: the caller's full entitlement in one ordered pass — rows
/// they RECEIVED (their own box, what `/listMessages` always granted) plus
/// rows they SENT (bytes they authored, sitting in the peer's box of the same
/// type). Nothing more: no unscoped read of the box type exists.
///
/// Ordered by `m.rowid` = relay insertion order. The envelope chain's own seq
/// numbers remain the authoritative game order; this ordering is merely stable
/// and deterministic. Bounded by `TRANSCRIPT_LIMIT` (isolate guard); the
/// filtered set is per-game small, so the sort input is bounded too.
///
/// Bind order: box_type, identity_key, identity_key, limit.
fn transcript_select_sql() -> String {
    "SELECT m.message_id AS messageId, m.sender, m.recipient, m.body, \
     m.created_at, m.acknowledged_at \
     FROM messages m JOIN message_boxes mb ON mb.message_box_id = m.message_box_id \
     WHERE mb.type = ? AND (m.recipient = ? OR m.sender = ?) \
     ORDER BY m.rowid ASC LIMIT ?"
        .to_string()
}

/// The tombstone relevant to THIS caller's view: their own client purge, or a
/// box-wide TTL expiry. (A purge by the PEER of the peer's box removes the
/// caller's outbound copies without a tombstone visible here — documented
/// endpoint ambiguity; a terminal game is expected to be purged by both
/// seats.) Bind order: box_type, identity_key.
fn tombstone_select_sql() -> String {
    "SELECT reason, purged_at FROM transcript_tombstones \
     WHERE box_type = ? AND purged_for IN (?, '*') \
     ORDER BY purged_at DESC LIMIT 1"
        .to_string()
}

/// Participant gate for purge: the caller owns a box of this type (they were a
/// recipient) or authored/received at least one message in it. A stranger can
/// neither purge nor plant tombstones on a box type they were never party to.
/// Bind order: identity_key, box_type, box_type, identity_key, identity_key.
fn participant_check_sql() -> String {
    "SELECT (EXISTS(SELECT 1 FROM message_boxes WHERE identity_key = ? AND type = ?) \
     OR EXISTS(SELECT 1 FROM messages m \
     JOIN message_boxes mb ON mb.message_box_id = m.message_box_id \
     WHERE mb.type = ? AND (m.sender = ? OR m.recipient = ?))) AS count"
        .to_string()
}

/// Purge: delete ONLY rows the caller RECEIVED ("its own boxes"). Deliberately
/// no sender clause — a seat must never be able to RETRACT an envelope it
/// already delivered into the counterparty's mailbox (that would be a new
/// power over the peer's un-consumed messages that acknowledge never granted,
/// and a transcript-rewriting vector for the peer's future rejoin).
/// Bind order: identity_key, box_type.
fn purge_delete_sql() -> String {
    "DELETE FROM messages WHERE recipient = ? AND message_box_id IN \
     (SELECT message_box_id FROM message_boxes WHERE type = ?)"
        .to_string()
}

/// Bind order: box_type, identity_key.
fn purge_tombstone_sql() -> String {
    "INSERT OR REPLACE INTO transcript_tombstones (box_type, purged_for, reason) \
     VALUES (?, ?, 'client')"
        .to_string()
}

/// SQLite datetime modifier for "days ago".
fn days_ago_modifier(days: u32) -> String {
    format!("-{days} days")
}

/// Tombstones are kept for 2×TTL after which the "purged vs never-existed"
/// distinction honestly expires (documented at the endpoint) — the table stays
/// bounded instead of growing one row per game forever.
fn tombstone_gc_modifier(ttl_days: u32) -> String {
    days_ago_modifier(ttl_days.saturating_mul(2))
}

/// TTL sweep step 1: tombstone every retained box type about to lose rows to
/// expiry (reason 'expired', box-wide '*'), BEFORE the delete — a crash
/// between the two steps leaves an honest tombstone, never a silent gap.
/// Bind order: like_patterns..., days_ago_modifier.
fn sweep_tombstone_sql(n_prefixes: usize) -> String {
    format!(
        "INSERT OR REPLACE INTO transcript_tombstones (box_type, purged_for, reason) \
         SELECT DISTINCT mb.type, '*', 'expired' FROM message_boxes mb \
         JOIN messages m ON m.message_box_id = mb.message_box_id \
         WHERE {} AND m.created_at < datetime('now', ?)",
        type_filter_sql("mb.type", n_prefixes)
    )
}

/// TTL sweep step 2: delete expired rows — RESTRICTED to retained boxes. The
/// sweep must never touch a non-retained mailbox (those keep today's
/// no-time-expiry contract). Bind order: days_ago_modifier, like_patterns...
fn sweep_delete_messages_sql(n_prefixes: usize) -> String {
    format!(
        "DELETE FROM messages WHERE created_at < datetime('now', ?) \
         AND message_box_id IN ({})",
        retained_box_subquery(n_prefixes)
    )
}

/// TTL sweep step 3: GC now-empty, old retained box rows (hygiene — box rows
/// are tiny, but a per-game namespace should not grow monotonically).
/// Bind order: like_patterns..., days_ago_modifier.
fn sweep_delete_boxes_sql(n_prefixes: usize) -> String {
    format!(
        "DELETE FROM message_boxes WHERE {} AND created_at < datetime('now', ?) \
         AND message_box_id NOT IN (SELECT message_box_id FROM messages)",
        type_filter_sql("type", n_prefixes)
    )
}

/// TTL sweep step 4: GC tombstones older than 2×TTL. Bind: gc modifier.
fn sweep_gc_tombstones_sql() -> String {
    "DELETE FROM transcript_tombstones WHERE purged_at < datetime('now', ?)".to_string()
}

/// Parse the TTL var. Default on unset/garbage/zero — never a 0-day TTL.
pub(crate) fn ttl_days(raw: Option<&str>) -> u32 {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&d| d >= 1)
        .unwrap_or(DEFAULT_RETAIN_TTL_DAYS)
}

// ---------------------------------------------------------------------------
// D1 rows + storage operations
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TranscriptRow {
    #[serde(rename = "messageId")]
    pub message_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub body: Option<String>,
    pub created_at: Option<String>,
    pub acknowledged_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TombstoneRow {
    pub reason: Option<String>,
    pub purged_at: Option<String>,
}

/// Counters from one TTL sweep run (for the audit log line).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    pub messages_deleted: usize,
    pub boxes_deleted: usize,
    pub tombstones_gcd: usize,
}

impl<'a> Storage<'a> {
    /// Ordered transcript, scoped to the caller (recipient OR sender). Same
    /// bounded transient-retry as the other idempotent reads.
    pub async fn list_transcript(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<Vec<TranscriptRow>> {
        let sql = transcript_select_sql();
        let q = Query::new(&sql)
            .bind(box_type)
            .bind(identity_key)
            .bind(identity_key)
            .bind(TRANSCRIPT_LIMIT);
        with_d1_read_retry(|| q.fetch_all(self.db)).await
    }

    /// The tombstone governing this caller's view of the box, if any.
    pub async fn transcript_tombstone(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<Option<TombstoneRow>> {
        let sql = tombstone_select_sql();
        let q = Query::new(&sql).bind(box_type).bind(identity_key);
        with_d1_read_retry(|| q.fetch_optional(self.db)).await
    }

    /// Purge participant gate (see `participant_check_sql`).
    pub async fn is_transcript_participant(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<bool> {
        let sql = participant_check_sql();
        let q = Query::new(&sql)
            .bind(identity_key)
            .bind(box_type)
            .bind(box_type)
            .bind(identity_key)
            .bind(identity_key);
        let row: Option<CountRow> = with_d1_read_retry(|| q.fetch_optional(self.db)).await?;
        Ok(row.and_then(|r| r.count).unwrap_or(0.0) > 0.0)
    }

    /// Client purge at game-terminal: delete the caller's RECEIVED rows of the
    /// box type and tombstone the deletion. Idempotent — a re-purge deletes 0
    /// and refreshes the tombstone. Both writes carry the standard bounded
    /// timeout+retry (fully idempotent under a dropped-but-landed attempt).
    pub async fn purge_transcript(
        &self,
        identity_key: &str,
        box_type: &str,
    ) -> worker::Result<usize> {
        let del_sql = purge_delete_sql();
        let del = Query::new(&del_sql).bind(identity_key).bind(box_type);
        let (meta, _retried) = with_d1_write_retry(|| del.execute(self.db)).await?;

        let tomb_sql = purge_tombstone_sql();
        let tomb = Query::new(&tomb_sql).bind(box_type).bind(identity_key);
        let (_tmeta, _tretried) = with_d1_write_retry(|| tomb.execute(self.db)).await?;
        Ok(meta.changes)
    }

    /// TTL backstop sweep over retained boxes only. Tombstone-first ordering
    /// (see `sweep_tombstone_sql`). No-op when retention is off.
    pub async fn sweep_expired_transcripts(
        &self,
        cfg: &RetentionConfig,
        ttl: u32,
    ) -> worker::Result<SweepOutcome> {
        if cfg.is_empty() {
            return Ok(SweepOutcome::default());
        }
        let n = cfg.prefix_count();
        let patterns = cfg.like_patterns();
        let cutoff = days_ago_modifier(ttl);

        // 1. Tombstone expiring box types (before the delete).
        let sql = sweep_tombstone_sql(n);
        let mut q = Query::new(&sql);
        for p in &patterns {
            q = q.bind(p.as_str());
        }
        q = q.bind(cutoff.as_str());
        let (_m, _r) = with_d1_write_retry(|| q.execute(self.db)).await?;

        // 2. Delete expired rows in retained boxes.
        let sql = sweep_delete_messages_sql(n);
        let mut q = Query::new(&sql).bind(cutoff.as_str());
        for p in &patterns {
            q = q.bind(p.as_str());
        }
        let (msgs, _r) = with_d1_write_retry(|| q.execute(self.db)).await?;

        // 3. GC now-empty old retained box rows.
        let sql = sweep_delete_boxes_sql(n);
        let mut q = Query::new(&sql);
        for p in &patterns {
            q = q.bind(p.as_str());
        }
        q = q.bind(cutoff.as_str());
        let (boxes, _r) = with_d1_write_retry(|| q.execute(self.db)).await?;

        // 4. GC tombstones past the 2×TTL honesty window.
        let sql = sweep_gc_tombstones_sql();
        let q = Query::new(&sql).bind(tombstone_gc_modifier(ttl).as_str());
        let (tombs, _r) = with_d1_write_retry(|| q.execute(self.db)).await?;

        Ok(SweepOutcome {
            messages_deleted: msgs.changes,
            boxes_deleted: boxes.changes,
            tombstones_gcd: tombs.changes,
        })
    }
}

// ---------------------------------------------------------------------------
// Response builders (pure) + route handlers
// ---------------------------------------------------------------------------

/// 403 for a box the deployment does not retain — the endpoints exist only for
/// the retained class; everything else keeps the plain mailbox contract.
fn not_retained_response(box_type: &str) -> (Value, u16) {
    (
        json!({
            "status": "error", "code": "ERR_BOX_NOT_RETAINED",
            "description": format!(
                "Message box '{box_type}' is not in this deployment's retained class \
                 (RETAIN_BOX_PREFIXES); transcript endpoints only serve retained boxes."
            ),
        }),
        403,
    )
}

fn not_participant_response(box_type: &str) -> (Value, u16) {
    (
        json!({
            "status": "error", "code": "ERR_NOT_PARTICIPANT",
            "description": format!(
                "You are not a participant of message box '{box_type}' — nothing to purge."
            ),
        }),
        403,
    )
}

fn internal_error_response(what: &str) -> (Value, u16) {
    (
        json!({
            "status": "error", "code": "ERR_INTERNAL_ERROR",
            "description": format!("An internal error has occurred while {what}."),
        }),
        500,
    )
}

/// Build the `/listTranscript` 200 body. Rule-13 honesty: `purgedAt` /
/// `purgeReason` appear IFF a tombstone governs this caller's view — an empty
/// `messages` with no `purgedAt` means "never any messages" (within the 2×TTL
/// tombstone window), never a silent alias for "purged".
fn transcript_response(
    box_type: &str,
    rows: &[TranscriptRow],
    tombstone: Option<&TombstoneRow>,
) -> Value {
    let messages: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "messageId": r.message_id.as_deref().unwrap_or(""),
                "sender": r.sender.as_deref().unwrap_or(""),
                "recipient": r.recipient.as_deref().unwrap_or(""),
                "body": r.body.as_deref().unwrap_or(""),
                "createdAt": crate::storage::to_iso8601(r.created_at.as_deref()),
                "acknowledged": r.acknowledged_at.is_some(),
            })
        })
        .collect();
    let mut body = json!({
        "status": "success",
        "messageBox": box_type,
        "retained": true,
        "messages": messages,
    });
    if let Some(t) = tombstone {
        body["purgedAt"] = json!(crate::storage::to_iso8601(t.purged_at.as_deref()));
        body["purgeReason"] = json!(t.reason.as_deref().unwrap_or(""));
    }
    body
}

/// `POST /listTranscript` — body `{"messageBox": "<type>"}` (same validated
/// shape as `/listMessages`), BRC-103/104-authed like every route.
pub async fn handle_list_transcript(
    raw_body: &[u8],
    identity_key: &str,
    cfg: &RetentionConfig,
    store: &Storage<'_>,
) -> (Value, u16) {
    let validated = match validate_list_messages(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !cfg.retains(&validated.message_box) {
        return not_retained_response(&validated.message_box);
    }
    let rows = match store
        .list_transcript(identity_key, &validated.message_box)
        .await
    {
        Ok(r) => r,
        Err(_e) => return internal_error_response("listing the transcript"),
    };
    // A failed tombstone read must NOT degrade to "never purged" (the #313
    // could-not-look-vs-absent lesson): error out instead of omitting.
    let tombstone = match store
        .transcript_tombstone(identity_key, &validated.message_box)
        .await
    {
        Ok(t) => t,
        Err(_e) => return internal_error_response("reading the transcript purge marker"),
    };
    (
        transcript_response(&validated.message_box, &rows, tombstone.as_ref()),
        200,
    )
}

/// `POST /purgeTranscript` — body `{"messageBox": "<type>"}`. Either seat
/// calls this for its own boxes when the game is terminal.
pub async fn handle_purge_transcript(
    raw_body: &[u8],
    identity_key: &str,
    cfg: &RetentionConfig,
    store: &Storage<'_>,
) -> (Value, u16) {
    let validated = match validate_list_messages(raw_body) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !cfg.retains(&validated.message_box) {
        return not_retained_response(&validated.message_box);
    }
    match store
        .is_transcript_participant(identity_key, &validated.message_box)
        .await
    {
        Ok(true) => {}
        Ok(false) => return not_participant_response(&validated.message_box),
        Err(_e) => return internal_error_response("checking purge authorization"),
    }
    let deleted = match store
        .purge_transcript(identity_key, &validated.message_box)
        .await
    {
        Ok(n) => n,
        Err(_e) => return internal_error_response("purging the transcript"),
    };
    worker::console_log!(
        "AUDIT transcript.purge caller={} box={} deleted={}",
        identity_key,
        validated.message_box,
        deleted
    );
    (
        json!({
            "status": "success",
            "messageBox": validated.message_box,
            "deleted": deleted,
        }),
        200,
    )
}

/// Scheduled (cron) entry: the TTL backstop. A deployment without retention
/// configured no-ops (the shared relay can safely carry the handler with no
/// cron trigger, or a trigger with no prefixes).
pub async fn run_scheduled_sweep(env: &worker::Env) {
    let cfg = RetentionConfig::from_env(env);
    if cfg.is_empty() {
        return;
    }
    let ttl = ttl_days(
        env.var(RETAIN_TTL_DAYS_VAR)
            .ok()
            .map(|v| v.to_string())
            .as_deref(),
    );
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(e) => {
            worker::console_error!("AUDIT transcript.sweep D1 binding unavailable: {e}");
            return;
        }
    };
    let store = Storage::new(&db);
    match store.sweep_expired_transcripts(&cfg, ttl).await {
        Ok(out) => worker::console_log!(
            "AUDIT transcript.sweep ttl_days={} messages_deleted={} boxes_deleted={} tombstones_gcd={}",
            ttl,
            out.messages_deleted,
            out.boxes_deleted,
            out.tombstones_gcd
        ),
        Err(e) => worker::console_error!("AUDIT transcript.sweep FAILED: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn low_cfg() -> RetentionConfig {
        RetentionConfig::parse(Some("low_game_"))
    }

    // ---- predicate / config parsing ----

    #[test]
    fn parse_unset_and_empty_mean_retention_off() {
        assert!(RetentionConfig::parse(None).is_empty());
        assert!(RetentionConfig::parse(Some("")).is_empty());
        assert!(RetentionConfig::parse(Some(" , ,")).is_empty());
    }

    #[test]
    fn parse_single_and_multi_prefixes() {
        let one = low_cfg();
        assert_eq!(one.prefix_count(), 1);
        let two = RetentionConfig::parse(Some("low_game_, mpc_round_"));
        assert_eq!(two.prefix_count(), 2);
        assert!(two.retains("low_game_abc"));
        assert!(two.retains("mpc_round_7"));
    }

    #[test]
    fn retains_is_a_prefix_match_and_nothing_else() {
        let cfg = low_cfg();
        assert!(cfg.retains("low_game_deadbeef"));
        assert!(cfg.retains("low_game_")); // bare prefix itself
        assert!(!cfg.retains("low_lobby_deadbeef")); // LOW's lobby boxes stay plain
        assert!(!cfg.retains("inbox"));
        assert!(!cfg.retains("xlow_game_deadbeef")); // prefix, not substring
        assert!(!RetentionConfig::parse(None).retains("low_game_x")); // off = nothing retains
    }

    #[test]
    fn like_patterns_escape_wildcards_so_a_prefix_cannot_widen_itself() {
        let cfg = RetentionConfig::parse(Some("low%ga_me\\"));
        assert_eq!(cfg.like_patterns(), vec![r"low\%ga\_me\\%".to_string()]);
        // The benign case: plain prefix + trailing %.
        assert_eq!(low_cfg().like_patterns(), vec![r"low\_game\_%".to_string()]);
    }

    // ---- THE ack pin: retained boxes are MARKED, never DELETED ----

    /// The stage-E load-bearing invariant. The retained half of acknowledge is
    /// an UPDATE that stamps `acknowledged_at`; no acknowledge statement may
    /// delete from a retained box. RED-verified by injecting a delete spelled
    /// differently from the legacy statement.
    #[test]
    fn retained_ack_marks_delivered_and_never_deletes() {
        let sql = ack_update_sql(3, 1);
        assert!(
            sql.starts_with("UPDATE messages SET acknowledged_at = datetime('now')"),
            "retained ack must be an UPDATE stamping acknowledged_at, got: {sql}"
        );
        assert!(
            !sql.to_ascii_uppercase().contains("DELETE"),
            "the retained ack statement must not delete anything: {sql}"
        );
        assert!(
            sql.contains("acknowledged_at IS NULL"),
            "re-ack must count 0 changes (parity with the legacy delete): {sql}"
        );
        // And the delete half must EXCLUDE retained boxes.
        let del = ack_delete_sql(3, 1);
        assert!(
            del.contains("message_box_id NOT IN"),
            "the ack delete must exclude retained boxes: {del}"
        );
    }

    /// The update's IN and the delete's NOT IN use the IDENTICAL subquery, so
    /// the two halves are exact complements: every acked message is either
    /// marked (retained) or deleted (not retained) — never both, never neither.
    #[test]
    fn ack_update_and_delete_partition_on_the_same_subquery() {
        let sub = retained_box_subquery(2);
        assert!(ack_update_sql(1, 2).contains(&format!("message_box_id IN ({sub})")));
        assert!(ack_delete_sql(1, 2).contains(&format!("message_box_id NOT IN ({sub})")));
    }

    /// Retention off ⇒ the delete SQL is the legacy statement byte-for-byte —
    /// the shared deployment's behavior is provably unchanged.
    #[test]
    fn retention_off_ack_delete_is_the_legacy_statement() {
        assert_eq!(
            ack_delete_sql(2, 0),
            "DELETE FROM messages WHERE recipient = ? AND message_id IN (?, ?)"
        );
        assert_eq!(
            ack_delete_sql(1, 0),
            "DELETE FROM messages WHERE recipient = ? AND message_id IN (?)"
        );
    }

    // ---- transcript read: auth scoping + ordering ----

    #[test]
    fn transcript_read_is_scoped_to_the_callers_entitlement() {
        let sql = transcript_select_sql();
        assert!(
            sql.contains("(m.recipient = ? OR m.sender = ?)"),
            "the transcript read must be caller-scoped — no unscoped read of a \
             box type may exist: {sql}"
        );
        assert!(sql.contains("ORDER BY m.rowid ASC"), "stable insertion order: {sql}");
        assert!(sql.contains("LIMIT ?"), "isolate OOM bound: {sql}");
    }

    #[test]
    fn transcript_response_preserves_order_and_marks_delivery() {
        let rows = vec![
            TranscriptRow {
                message_id: Some("m1".into()),
                sender: Some("02aa".into()),
                recipient: Some("03bb".into()),
                body: Some("{\"seq\":1}".into()),
                created_at: Some("2026-08-06 10:00:00".into()),
                acknowledged_at: Some("2026-08-06 10:00:05".into()),
            },
            TranscriptRow {
                message_id: Some("m2".into()),
                sender: Some("03bb".into()),
                recipient: Some("02aa".into()),
                body: Some("{\"seq\":2}".into()),
                created_at: Some("2026-08-06 10:00:10".into()),
                acknowledged_at: None,
            },
        ];
        let body = transcript_response("low_game_abc", &rows, None);
        assert_eq!(body["status"], "success");
        assert_eq!(body["messageBox"], "low_game_abc");
        assert_eq!(body["retained"], json!(true));
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["messageId"], "m1", "insertion order preserved");
        assert_eq!(msgs[1]["messageId"], "m2");
        assert_eq!(msgs[0]["acknowledged"], json!(true), "delivered = marked, still readable");
        assert_eq!(msgs[1]["acknowledged"], json!(false));
        assert_eq!(msgs[0]["createdAt"], "2026-08-06T10:00:00.000Z");
        assert_eq!(msgs[0]["sender"], "02aa");
        assert_eq!(msgs[0]["recipient"], "03bb");
    }

    // ---- Rule 13: empty-because-purged vs empty-because-never ----

    #[test]
    fn empty_purged_and_empty_never_are_distinguishable() {
        let never = transcript_response("low_game_abc", &[], None);
        assert!(
            never.get("purgedAt").is_none(),
            "no tombstone ⇒ no purgedAt key — empty means never-any-messages: {never}"
        );
        let tomb = TombstoneRow {
            reason: Some("client".into()),
            purged_at: Some("2026-08-06 11:00:00".into()),
        };
        let purged = transcript_response("low_game_abc", &[], Some(&tomb));
        assert_eq!(purged["purgedAt"], "2026-08-06T11:00:00.000Z");
        assert_eq!(purged["purgeReason"], "client");
        assert_ne!(never, purged, "the two empties must not be the same wire bytes");
    }

    #[test]
    fn tombstone_lookup_covers_own_purge_and_boxwide_expiry_only() {
        let sql = tombstone_select_sql();
        assert!(
            sql.contains("purged_for IN (?, '*')"),
            "a caller sees their own purge or a box-wide expiry, never the \
             peer's private tombstones: {sql}"
        );
    }

    // ---- endpoint gate ----

    #[test]
    fn non_retained_box_is_refused_with_403() {
        let (body, status) = not_retained_response("inbox");
        assert_eq!(status, 403);
        assert_eq!(body["code"], "ERR_BOX_NOT_RETAINED");
    }

    // ---- purge scoping pins ----

    /// A purge must never grant retraction: no sender clause in the delete —
    /// the caller deletes only what it RECEIVED.
    #[test]
    fn purge_cannot_retract_messages_the_caller_sent() {
        let sql = purge_delete_sql();
        assert!(sql.contains("recipient = ?"), "recipient-scoped: {sql}");
        assert!(
            !sql.contains("sender"),
            "a sender clause here would let a seat retract delivered envelopes \
             from the peer's mailbox: {sql}"
        );
    }

    #[test]
    fn purge_gate_requires_participation_as_owner_sender_or_recipient() {
        let sql = participant_check_sql();
        assert!(sql.contains("identity_key = ? AND type = ?"));
        assert!(sql.contains("(m.sender = ? OR m.recipient = ?)"));
    }

    #[test]
    fn purge_tombstone_is_caller_scoped_with_reason_client() {
        let sql = purge_tombstone_sql();
        assert!(sql.contains("'client'"));
        assert!(sql.starts_with("INSERT OR REPLACE INTO transcript_tombstones"));
    }

    // ---- TTL sweep ----

    #[test]
    fn ttl_parses_with_safe_default_and_floor() {
        assert_eq!(ttl_days(None), 14);
        assert_eq!(ttl_days(Some("7")), 7);
        assert_eq!(ttl_days(Some(" 30 ")), 30);
        assert_eq!(ttl_days(Some("0")), 14, "a 0-day TTL would eat live transcripts");
        assert_eq!(ttl_days(Some("-3")), 14);
        assert_eq!(ttl_days(Some("nope")), 14);
        assert_eq!(ttl_days(Some("")), 14);
    }

    #[test]
    fn sweep_deletes_only_inside_the_retained_class() {
        let sql = sweep_delete_messages_sql(1);
        assert!(
            sql.contains(&format!("message_box_id IN ({})", retained_box_subquery(1))),
            "the sweep must never expire a non-retained mailbox: {sql}"
        );
        assert!(sql.contains("created_at < datetime('now', ?)"));
        let boxes = sweep_delete_boxes_sql(1);
        assert!(boxes.contains("LIKE ? ESCAPE"), "box GC also class-restricted: {boxes}");
        assert!(
            boxes.contains("NOT IN (SELECT message_box_id FROM messages)"),
            "box GC only removes EMPTY boxes: {boxes}"
        );
    }

    #[test]
    fn sweep_tombstones_expired_boxes_with_boxwide_marker() {
        let sql = sweep_tombstone_sql(1);
        assert!(sql.contains("'*', 'expired'"), "box-wide expiry marker: {sql}");
        assert!(sql.contains("LIKE ? ESCAPE"), "class-restricted: {sql}");
    }

    #[test]
    fn sweep_modifiers_and_tombstone_window() {
        assert_eq!(days_ago_modifier(14), "-14 days");
        assert_eq!(tombstone_gc_modifier(14), "-28 days");
        assert_eq!(tombstone_gc_modifier(7), "-14 days");
        let gc = sweep_gc_tombstones_sql();
        assert!(gc.contains("purged_at < datetime('now', ?)"));
    }

    // ---- LIKE filter shape ----

    #[test]
    fn type_filter_repeats_per_prefix_with_escape() {
        assert_eq!(type_filter_sql("type", 1), r"(type LIKE ? ESCAPE '\')");
        assert_eq!(
            type_filter_sql("mb.type", 2),
            r"(mb.type LIKE ? ESCAPE '\' OR mb.type LIKE ? ESCAPE '\')"
        );
    }
}
