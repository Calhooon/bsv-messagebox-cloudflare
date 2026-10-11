-- 0005: the subject announced, and the re-ask a broadcaster's refusal owes
-- (0.4.4, bsv-low #591 M2).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that records announcements.

-- Since 0.4.4 the relay posts a verified payment's subject to a broadcaster in
-- the send itself, before delivery. The broadcaster's word is a hint (a 2xx
-- is not "mined", a refusal is not "rejected"): it is recorded on the
-- recipient's row, and when it is not an acceptance, or no answer came, one
-- row here names the bytes at rest so the scheduled drain asks again. The
-- delivery never waits on it: the door's own verdict (structure, scripts,
-- roots) is what the message is delivered on.
CREATE TABLE IF NOT EXISTS announce_owed (
    key TEXT NOT NULL PRIMARY KEY,          -- the R2 object key of the payment's BEEF
    etag TEXT NOT NULL,                     -- of the bytes the door verified
    txid TEXT NOT NULL,                     -- the subject
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL,               -- unix seconds: not before
    last_word TEXT,                         -- the broadcaster's last word, or why none came
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The drain reads the rows that are due, the longest waiting leading.
CREATE INDEX IF NOT EXISTS idx_announce_owed_next ON announce_owed(next_at);
