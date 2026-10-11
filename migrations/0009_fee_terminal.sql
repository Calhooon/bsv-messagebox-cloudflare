-- 0009: a deferred fee that cannot be recorded ends, with its reason; and the
-- relay's word on whether wallet-infra reads its bucket (0.4.4, bsv-low #591
-- R403-L1).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that ends fees.

-- Through 0.4.3 a fee held for a reason that cannot clear by itself (another
-- upload at the key, the object gone, arguments that do not parse, no bucket
-- named) was put off and retried daily without end, as a transient failure
-- was. Now such a fee ends at once: `ended` is its reason, the row stays for
-- the operator's reading and the health figure, and the drain never takes it
-- up again. A transient failure is retried with the backoff up to a ceiling of
-- attempts, and then ends too. An ended fee names no object.
ALTER TABLE fee_internalize ADD COLUMN ended TEXT;

-- The relay's own words about what it depends on, by name. `wallet-bucket`:
-- wallet-infra's refusal to read the relay's bucket, recorded when the drain
-- meets it; while it stands, no fee is deferred into that wallet-infra.
CREATE TABLE IF NOT EXISTS relay_health (
    name TEXT NOT NULL PRIMARY KEY,
    word TEXT NOT NULL,
    at INTEGER NOT NULL                     -- unix seconds
);
