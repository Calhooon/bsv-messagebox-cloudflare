-- 0008: an object recorded when its key is minted, reclaimed when no send
-- names it by a deadline (0.4.4, bsv-low #591 L3).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that mints with a record.

-- One row per key the relay minted: a presigned upload (/beef/upload-url) or
-- an inline payment spooled before its scripts ran. Through 0.4.3 an object
-- nobody named was never looked at again: an upload never sent stayed in the
-- bucket for good. The deadline is the URL's life and a day; the scheduled
-- event looks at the keys past it, deletes the object when no row, no fee and
-- no announcement names it (the reclaim's own rule), and forgets the record
-- either way. A key whose reading is still pending (its door state is there)
-- waits an hour more.
CREATE TABLE IF NOT EXISTS beef_minted (
    key TEXT NOT NULL PRIMARY KEY,
    deadline INTEGER NOT NULL               -- unix seconds
);

CREATE INDEX IF NOT EXISTS idx_beef_minted_deadline ON beef_minted(deadline);
