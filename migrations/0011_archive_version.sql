-- 0011: the archive's version on a row (0.8.0, R1 of the relay mailbox: the
-- archive ready).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that binds the archive queue. 0.7.1 never reads the column, so
-- a rollback to 0.7.1 runs on the migrated schema unchanged.

-- The version of the row the archive last wrote: the hub counts it (the
-- insert is 1, the acknowledgment one more), and the archive consumer's
-- upsert moves it only forward. 0 is a row the archive never wrote (every
-- row stored by the D1 path before the mailbox).
ALTER TABLE messages ADD COLUMN archive_version INTEGER NOT NULL DEFAULT 0;

-- The consumer's read of a batch: who holds each message id and at what
-- version (`archive::ARCHIVE_HELD_SQL`). Covering, so the read never walks a
-- row's body (up to 2,000,000 bytes, stored before these columns).
CREATE INDEX IF NOT EXISTS idx_messages_archive ON messages(message_id, archive_version, recipient);
