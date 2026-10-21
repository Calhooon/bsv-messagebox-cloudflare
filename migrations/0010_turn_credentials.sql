-- 0010: the ICE credentials the relay mints (POST /turn-credentials) and the
-- budgets charged before the provider is asked.
--
-- ADDITIVE ONLY (D1 discipline: never DROP/RENAME). Applied explicitly with
-- `wrangler d1 migrations apply <db> -c <config> --remote` BEFORE deploying the
-- worker build that serves the route.

-- One row per budget and hour window: how many credentials it has paid for.
-- The keys are `turn:id:<identity>`, `turn:src:<group>` (an IPv4 address, an
-- IPv6 /64 or `none`), `turn:p48:<prefix>` (an IPv6 /48) and `turn:all`. A
-- mint charges every budget it counts against in one transaction, all or
-- none; the scheduled event deletes windows that have closed.
CREATE TABLE IF NOT EXISTS turn_budget (
    key TEXT NOT NULL,
    window_start INTEGER NOT NULL,          -- unix seconds, a multiple of 3600
    n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);

-- The sweep of closed windows.
CREATE INDEX IF NOT EXISTS idx_turn_budget_window ON turn_budget(window_start);

-- One row per TURN username minted: whose it is, so only that identity may
-- revoke it. The scheduled event forgets a row past its expiry.
CREATE TABLE IF NOT EXISTS turn_credentials (
    username TEXT PRIMARY KEY,
    identity_key TEXT NOT NULL,
    expires_at INTEGER NOT NULL,            -- ms since the epoch: the provider request's start plus the ttl
    created_at INTEGER NOT NULL             -- ms since the epoch
);

-- The sweep of expired credentials.
CREATE INDEX IF NOT EXISTS idx_turn_credentials_expires ON turn_credentials(expires_at);
