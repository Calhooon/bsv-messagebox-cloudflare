-- 0002: transcript retention-until-terminal (bsv-low #252 stage E server
-- prerequisite, owner decision 2026-08-06).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME — a re-executed additive
-- migration is survivable; a destructive one is not). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that references acknowledged_at.

-- Delivered-marker for messages living in a RETAINED box (see
-- RETAIN_BOX_PREFIXES). NULL = not yet acknowledged. For non-retained boxes the
-- column stays NULL forever (acknowledge still DELETEs there, unchanged).
ALTER TABLE messages ADD COLUMN acknowledged_at TEXT;

-- The TTL backstop sweep filters on created_at across retained boxes.
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);

-- Rule-13 honesty: lets a transcript read distinguish "empty because
-- purged/expired" from "empty because never any messages". One row per
-- (box_type, purged_for): purged_for is the recipient identity whose retained
-- rows were client-purged, or '*' for a box-wide TTL expiry.
CREATE TABLE IF NOT EXISTS transcript_tombstones (
    box_type TEXT NOT NULL,
    purged_for TEXT NOT NULL,
    reason TEXT NOT NULL,
    purged_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (box_type, purged_for)
);
