-- 0006: the per-identity send budget on /sendMessage (0.4.4, bsv-low #591 M3
-- and NOTE-3).
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that charges the budget.

-- One row per sender and window: the sends it made in the window, and the
-- bytes of the bodies no delivery fee judged. Each send is one upsert on the
-- primary key; the scheduled event deletes windows that have closed.
CREATE TABLE IF NOT EXISTS send_budget (
    identity TEXT NOT NULL,                 -- the sender's identity key
    window_start INTEGER NOT NULL,          -- unix seconds, a multiple of the window
    sends INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,       -- of message and payment text no delivery fee judged
    PRIMARY KEY (identity, window_start)
);

-- The sweep of closed windows.
CREATE INDEX IF NOT EXISTS idx_send_budget_window ON send_budget(window_start);
