-- 0003: the deferred internalize of a delivery fee (NL-4b, the no-limits
-- program: nothing after the door's verdict refuses the sender).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that references fee_internalize.

-- One row per delivery fee whose recording in wallet-infra is still owed:
-- the BEEF was more than one request hands wallet-infra as one argument, or
-- wallet-infra could not answer. The row names the bytes at rest in R2 (the
-- key and the etag of the upload the door verified) and never carries them.
-- The scheduled drain records the fee and deletes the row; a fee that cannot
-- be recorded stays, with one more attempt and a later next_at. No row is
-- dropped for its age or its attempts.
CREATE TABLE IF NOT EXISTS fee_internalize (
    key TEXT NOT NULL PRIMARY KEY,          -- the R2 object key of the payment's BEEF
    etag TEXT NOT NULL,                     -- of the upload the door verified
    txid TEXT NOT NULL,                     -- the subject the door verified
    args TEXT NOT NULL,                     -- internalizeAction beside the bytes: outputs, description, labels (JSON)
    named INTEGER NOT NULL DEFAULT 0,       -- 1 when a recipient's row names the object too
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at INTEGER NOT NULL,               -- unix seconds: not before
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The drain reads the rows that are due, the longest waiting leading.
CREATE INDEX IF NOT EXISTS idx_fee_internalize_next ON fee_internalize(next_at);
