-- 0004: a row names the object its payment rests in (NL-4c, the no-limits
-- program: an R2 object under a payment key is deleted only when no stored
-- row references its key).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that writes beef_key: the insert of every message names the
-- column. Like 0002 it adds a column and is applied once.

-- The R2 key of the payment a row's body names (`payment.beefR2Key`), NULL for
-- every row that carries no payment at rest. The reference is the row itself:
-- it is released when the row is deleted or its message retired
-- (acknowledged_at set), by whatever statement does it.
ALTER TABLE messages ADD COLUMN beef_key TEXT;

-- "Does a stored row name this key?" is one seek. Partial: the rows that
-- carry no payment (every unpaid message) are not in it.
CREATE INDEX IF NOT EXISTS idx_messages_beef_key ON messages(beef_key) WHERE beef_key IS NOT NULL;

-- The keys a row has let go of and nobody has yet looked at. One row per key.
-- The scheduled reclaim reads it, deletes the object when no row and no
-- deferred fee names the key, and clears the entry. Never a scan of messages
-- and never a listing of the bucket.
CREATE TABLE IF NOT EXISTS beef_released (
    key TEXT NOT NULL PRIMARY KEY,
    released_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- A row that names an object is deleted (the consumer's acknowledge, a
-- transcript purge, the TTL sweep, a box's cascade, an operator's own DELETE):
-- its key is released. Each trigger is one line, one statement.
CREATE TRIGGER IF NOT EXISTS trg_messages_beef_deleted AFTER DELETE ON messages WHEN OLD.beef_key IS NOT NULL BEGIN INSERT OR IGNORE INTO beef_released (key) VALUES (OLD.beef_key); END;

-- A row that names an object is retired (acknowledged in a retained box, where
-- the row stays for the transcript): its key is released.
CREATE TRIGGER IF NOT EXISTS trg_messages_beef_retired AFTER UPDATE OF acknowledged_at ON messages WHEN OLD.beef_key IS NOT NULL AND NEW.acknowledged_at IS NOT NULL BEGIN INSERT OR IGNORE INTO beef_released (key) VALUES (OLD.beef_key); END;
