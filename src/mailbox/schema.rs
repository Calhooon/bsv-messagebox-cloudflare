//! The storage layout of one recipient hub's mailbox (`MessageHubSql`, the
//! SQLite backend of a Durable Object): every table and index, and the
//! statements that make them. The hub runs `SCHEMA` before its earliest mailbox
//! statement on each instance; each statement is idempotent, so a cold hub,
//! a warm one and a hub born empty all reach the same layout.
//!
//! One hub is one identity (the hub id is `idFromName(identity_key)`), so no
//! table carries the recipient: `mailbox_meta` names it once.

/// `mailbox_rows`: the mailbox. One row per message the hub holds, keyed by
/// the message id (unique per hub, the design's row D-unique) and ordered by
/// `seq`, the hub's insertion order. `state` is `live` (listed, counted) or
/// `acknowledged` (neither; kept until the archive holds the acknowledged
/// version, then deleted). `version` counts the row's changes: 1 at the
/// insert, 2 at the acknowledgment. `archived_version` is the highest version
/// the archive confirmed (`/internal/archive-done`); `owed` is 1 while the
/// archive lacks the current version, and `enqueued_at` (epoch ms) when it
/// was last handed to the queue. `body` is the stored text, up to the 2 MB a
/// SQLite row holds; it is dropped at the acknowledgment once some version is
/// archived (the archive holds it). `body_bytes` is its length in bytes, the
/// measure the counters and the listing's budget use. `collision` is 1 when
/// D1 holds the id for another recipient: never archived, still served.
/// `created_at` and `updated_at` are D1's `datetime('now')` form.
pub const CREATE_ROWS: &str = "CREATE TABLE IF NOT EXISTS mailbox_rows ( \
       seq INTEGER PRIMARY KEY AUTOINCREMENT, \
       message_id TEXT NOT NULL UNIQUE, \
       message_box TEXT NOT NULL, \
       sender TEXT NOT NULL, \
       body TEXT, \
       body_bytes INTEGER NOT NULL, \
       state TEXT NOT NULL CHECK (state IN ('live', 'acknowledged')), \
       version INTEGER NOT NULL, \
       archived_version INTEGER NOT NULL DEFAULT 0, \
       owed INTEGER NOT NULL, \
       enqueued_at INTEGER, \
       collision INTEGER NOT NULL DEFAULT 0, \
       created_at TEXT NOT NULL, \
       updated_at TEXT NOT NULL)";

/// The listing's index: a box's live rows in insertion order, so a listing of
/// 100 reads 100 entries whatever the mailbox holds.
pub const CREATE_LISTING_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS mailbox_rows_listing ON mailbox_rows (message_box, state, seq)";

/// The replay's index: the owed rows by their last enqueue, so a request reads
/// at most 16 of them without walking the mailbox.
pub const CREATE_OWED_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS mailbox_rows_owed ON mailbox_rows (owed, enqueued_at)";

/// `mailbox_counters`: the two counters of the identity, one row (`id = 1`):
/// the live rows held and their bytes. Read on every send, moved by the insert
/// and the acknowledgment in the same synchronous run of statements.
pub const CREATE_COUNTERS: &str = "CREATE TABLE IF NOT EXISTS mailbox_counters ( \
       id INTEGER PRIMARY KEY CHECK (id = 1), \
       rows_held INTEGER NOT NULL, \
       bytes_held INTEGER NOT NULL)";

/// The counters' one row, born at zero.
pub const SEED_COUNTERS: &str =
    "INSERT OR IGNORE INTO mailbox_counters (id, rows_held, bytes_held) VALUES (1, 0, 0)";

/// `mailbox_meta`: facts of the hub by name. `identity` is the identity key
/// the hub serves (the archive message's `recipient`, the full mailbox's
/// `recipient`, the legacy merge's D1 reads).
pub const CREATE_META: &str = "CREATE TABLE IF NOT EXISTS mailbox_meta ( \
       key TEXT PRIMARY KEY, \
       value TEXT NOT NULL)";

/// `permissions_copy`: the recipient's permissions as a send needs them, per
/// sender and box: the recipient's fee (-1 blocked, 0 free, more is satoshis)
/// and the server's delivery fee for the box, copied from D1 at the earliest
/// send that needs them (`copied_at`, epoch ms), cleared by the identity's
/// `/permissions/set`, and read again from D1 past `PERMISSIONS_COPY_TTL_MS`.
pub const CREATE_PERMISSIONS: &str = "CREATE TABLE IF NOT EXISTS permissions_copy ( \
       sender TEXT NOT NULL, \
       message_box TEXT NOT NULL, \
       recipient_fee INTEGER NOT NULL, \
       server_fee INTEGER NOT NULL, \
       copied_at INTEGER NOT NULL, \
       PRIMARY KEY (sender, message_box))";

/// Every statement of the layout, in order.
pub const SCHEMA: [&str; 7] = [
    CREATE_ROWS,
    CREATE_LISTING_INDEX,
    CREATE_OWED_INDEX,
    CREATE_COUNTERS,
    SEED_COUNTERS,
    CREATE_META,
    CREATE_PERMISSIONS,
];
