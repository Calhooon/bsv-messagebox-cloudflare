-- 0007: the claim a reclaim holds on a key while it looks and deletes (0.4.4,
-- bsv-low #591 L2).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that claims keys.

-- R2 deletes by key alone, with no condition, so a reclaim cannot delete "only
-- if nothing names it" in one step. It writes its claim here first, then looks
-- at the rows and the ledger, looks again, holds the delete to the etag it
-- looked at, deletes, and lets go of the claim. A send that names a key writes
-- its row first and then reads the claim: one of the two always sees the
-- other, so a row written after the reclaim's look is seen by the send, which
-- logs an orphan if the bytes are gone. A claim older than five minutes is a
-- reclaim that did not finish and is no claim.
CREATE TABLE IF NOT EXISTS beef_reclaiming (
    key TEXT NOT NULL PRIMARY KEY,
    claimed_at INTEGER NOT NULL             -- unix seconds
);
