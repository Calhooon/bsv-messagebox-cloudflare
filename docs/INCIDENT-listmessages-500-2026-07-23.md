# INCIDENT — transient `/listMessages` 500 → permanent hand deadlock (2026-07-23)

**Status:** root-caused. Fix implemented (un-deployed). Sibling hazards catalogued.

> ## ⚠️ HEADLINE FINDING — the deployed relay runs an OLD, un-fixed middleware
>
> The relay's `Cargo.toml` requires `bsv-middleware-cloudflare = "0.2"` and
> `[patch.crates-io]`-points it at the local `../bsv-middleware-cloudflare-public`.
> That local crate has since been bumped to **`0.3.1`**, which **no longer
> satisfies `"0.2"`**, so cargo **silently ignores the patch** (`[patch.unused]`
> in `Cargo.lock`) and resolves **crates.io `0.2.0`** instead. `0.2.0` predates the
> BRC-31 liveness-touch fix — its touch is **unconditional + fatal**:
>
> ```rust
> // bsv-middleware-cloudflare 0.2.0, src/middleware/auth.rs (DEPLOYED)
> let mut updated_session = session.clone();
> updated_session.touch();
> session_storage.update_session(&updated_session).await?;  // shared session key, EVERY request, FATAL `?`
> ```
>
> `update_session` writes the **shared** `auth:session:{session_nonce}` key on
> **every** authenticated request. A same-session burst (the `deal_keys`
> `/sendMessage`×3 + list polls, all on one BRC-104 session) exceeds Cloudflare
> KV's **~1 write/sec/key** limit on that one key → **429 → `KvError` → fatal
> 500**. This is the **exact 2026-06-17 KV-429→500 incident, recurring** — because
> the "lazy + best-effort" fix (middleware `9e3004b`) was written but **never
> shipped**: the patch that was supposed to carry it has been dead since the local
> crate crossed the `0.3` line. **This deterministic shared-key 429, not a generic
> transient, is the most likely cause of the observed 2-in-0.4 s burst 500.**
>
> **Primary fix (implemented):** bump the relay dependency `"0.2" → "0.3"` so the
> patched `0.3.1` (lazy + best-effort touch, replay protection, and the new KV
> retry below) actually builds in. `Cargo.lock` now resolves the local `0.3.1`
> (patch **used**); `cargo test` (225) + `worker-build --release` both green.

## 1. Evidence (mainnet capture, `bothLeaveMidHandArm-2026-07-23_14-59-22/seat-A.log`)

```
14:59:56.271Z  relay.send ok 310ms — shuffle_pass #1     (POST /sendMessage)
14:59:56.812Z  relay.send ok 307ms — remask_pass  #1     (POST /sendMessage)
14:59:57.299Z  relay.send ok 299ms — deal_keys    #1     (POST /sendMessage)
14:59:57.705Z  HTTP 500  https://<your-relay>.workers.dev/listMessages
14:59:58.055Z  node-transition → felt-dealt_discard
14:59:58.080Z  HTTP 500  https://<your-relay>.workers.dev/listMessages
```

Three `/sendMessage` POSTs fire in ~1 s (the `deal_keys` handoff is a burst of
envelopes), then **two `/listMessages` polls both 500 within 0.4 s**. Those two
failed polls meant the peer's next envelope was never surfaced to seat A; both
seats wedged at `dealt_discard`, one escalated to the tower, `/respond` 422×60.
The relay is healthy now (unauth `/listMessages` → 401 correctly), so this was a
**transient** 500 that caused **permanent** damage.

## 2. Every internal error that becomes a `/listMessages` 500

> **Two builds to keep straight.** *Deployed* = crates.io `0.2.0` (fatal
> unconditional touch, no replay guard). *Fixed / this branch* = patched `0.3.1`
> (lazy + best-effort touch, per-request nonce-consume, plus the new KV retry).
> The table below is the **fixed** build's path; stage E is where the deployed
> `0.2.0` differs and is the deployed 500 source (see the headline finding).

Request flow for an authenticated `POST /listMessages`:

| Stage | Code | KV/D1 op | On error |
|---|---|---|---|
| A. binding | `env.kv("AUTH_SESSIONS")` (middleware `process_auth`) | — | `?` → 500 (infallible in practice) |
| B. session lookup | `get_session(nonce)` / `get_session_by_identity` (`kv_session.rs`) | **KV READ** | `?` → 500, **no retry** |
| C. verify sig | `verify_message_signature` | CPU | deterministic |
| D. replay guard | `try_consume_nonce` (`kv_session.rs`) | **KV READ + KV WRITE** | `?` → 500, **no retry** |
| E. liveness touch | `update_session` (`auth.rs`) | KV WRITE | **lazy (½-TTL) + best-effort → never 500** |
| F. box lookup | `store.find_message_box` (`storage.rs`) | D1 READ | **retried** (`with_d1_read_retry`, 3×, 50/100 ms) |
| G. message list | `store.list_messages` SELECT | D1 READ | **retried** |
| H. sign response | `sign_json_response` | CPU crypto | deterministic |

The `Err` at A–E propagates through `lib.rs process_auth(...).map_err(...)` →
`handle()` → the `cors_error_500()` wrapper (`lib.rs:56`). F–G surface as the
explicit `ERR_INTERNAL_ERROR` 500 at `lib.rs:304`.

### Ranked by likelihood under the 2-in-0.4 s burst

**#0 (DEPLOYED build only) — the unconditional fatal liveness touch's shared-key
429 (stage E in `0.2.0`). The single most likely cause of the actual incident.**
On the deployed `0.2.0`, stage E is `update_session(...).await?` on **every**
request, writing the **shared** `auth:session:{nonce}` key. A same-session burst
deterministically trips KV's ~1-write/sec/**key** limit → 429 → fatal 500. Unlike
the generic-transient story, this is a *deterministic* per-key rate limit under
concurrent same-session writes — a precise fit for `deal_keys` (3 `/sendMessage`
+ list polls on one session in ~1 s) yielding back-to-back 500s. This vector
**does not exist in the fixed build** (touch is lazy + best-effort there). Items
#1–#4 below rank the residual surface that remains **after** the fix (they are
what the KV retry in §4b addresses).

**#1 — a transient KV fault on the fatal, UN-RETRIED auth ops (B and D). Most
consistent with the evidence *on the fixed build*.**
`try_consume_nonce` adds a **KV WRITE on every authenticated request** (added in
middleware 0.3.0, the-composer replay-protection #30). KV writes are the least
reliable KV op, and — unlike the D1 reads (F/G) — the whole auth KV path has
**zero in-request retry**: a single transient fault (`Network connection lost` /
`storage … reset` / `internal error`, or a namespace/account throttle) surfaces
*immediately* as a fatal 500. During `deal_keys`, the `AUTH_SESSIONS` namespace
is under a spike (3 `/sendMessage` + concurrent list polls, each doing a session
READ + a nonce READ + a nonce WRITE). Two polls catching the same short blip
window 0.4 s apart is exactly the observed signature.

> **On 429 specifically:** the classic per-key `~1 write/sec/key` 429 is already
> *mitigated*. The shared session-key liveness touch was made lazy + best-effort
> (middleware `9e3004b`, relay `a044380` — the 2026-06-17 KV-429→500 incident),
> and the nonce-record write targets a **unique** key per request, so it can't
> hit per-key 429 either. The burst 500 is therefore most likely a *generic*
> transient KV error surfaced fatally — **not** a literal 429 — but the failure
> *mode* is identical to the old 429→500 (a transient KV condition made fatal by
> a `?`), so the same class of fix applies: never let a transient KV read/write
> surface as a 500 on a poll.

**#2 — a D1 transient that outlasts the 150 ms retry budget (F/G).**
`list_messages` is protected by `with_d1_read_retry` (3 attempts, 50 + 100 ms).
It self-heals a brief cold-start blip, but a degradation lasting > ~150 ms across
all three attempts still 500s. Under sustained burst load D1 can stay degraded
longer than the budget, so back-to-back 500s are possible — but this path *is*
protected, making it less likely than #1.

**#3 — `sign_json_response` / serialization — deterministic, not burst-correlated.
Negligible.**

**#4 — DO cold-start / overload — N/A for this endpoint.** `/listMessages`
touches no Durable Object (pure KV-auth + D1). This class only applies to `/ws`,
`/presence`, `/rejoin-deadline`, and `/socket.io/*`.

## 3. Delivery semantics — LOST vs DELAYED

**Verdict: DELAYED, never LOST — relay-side.** No atomicity bug.

`list_messages` (`storage.rs:174`) is a **pure read**: `find_message_box` SELECT
+ a `messages` SELECT with `LIMIT`. Zero writes, no cursor, no `delivered` flag,
no mark-on-read. Acknowledgement is a **separate, explicit** `POST
/acknowledgeMessage` → `DELETE` (`storage.rs:208`). Therefore:

- A 500 from **any** stage (auth KV path *or* the D1 read) happens with the
  message row still intact in D1. The next successful poll returns it.
- The only state mutation anywhere near the read is the auth **nonce-consume**
  (stage D), which burns a *per-request* nonce. The BRC-104 client mints a fresh
  `x-bsv-auth-nonce` per attempt, so a retry is a *new* request — not a replay —
  and is unaffected. (A byte-identical retry *would* be rejected `ERR_REPLAYED_REQUEST`,
  but honest AuthFetch clients never do that.)
- There is no read-then-500-after-partial-write window in the read path (it does
  no writes), and ack is never implicit.

So a `/listMessages` 500 can **never** drop a message at the relay. **The
permanent deadlock is a client-side failure to recover**: seat A treated the
transient 500 as terminal for that envelope (stopped re-polling / advanced its
state machine off the failed poll) and the WS push didn't cover the gap. The
relay-side fix removes the *trigger*; the client should additionally treat any
5xx on a poll as retryable-never-terminal (out of this repo — flag to the app).

## 4. Fix

### 4a. Implemented — ship the fixed middleware (the primary fix)

Bump the relay's dependency `bsv-middleware-cloudflare = "0.2"` → `"0.3"` (relay
`Cargo.toml`) and `cargo update -p bsv-middleware-cloudflare`. `Cargo.lock` now
resolves the local patched **`0.3.1`** (patch **used**, no more `[patch.unused]`),
which carries: the **lazy + best-effort** liveness touch (kills the deployed
shared-key 429→500 outright — a KV 429 on the touch is now logged, never fatal),
BRC-104 replay protection, and the KV retry in §4b. This is the change that
actually gets *any* of the fixes to production. Relay `cargo test` (225 green) and
`worker-build --release` (0.8.5) both pass against the patched crate.

> The relay code (`process_auth`, `sign_json_response`, `AuthMiddlewareOptions`,
> `AuthResult`, `add_cors_headers`, `handle_cors_preflight`, `init_panic_hook`) is
> source-compatible with 0.3.x — the 0.3 additions (`process_auth_with_storage`,
> nonce-consume) are additive. **Behavioral delta to weigh:** 0.3 enforces BRC-104
> replay protection (a byte-identical replay now gets `401 ERR_REPLAYED_REQUEST`)
> and adds one KV write (unique key) per request. Route through the middleware
> self-review gate before deploy.
>
> **Guard against silent recurrence:** a `[patch]` that stops matching the
> dependency requirement is dropped **with only a warning**. Add a CI/`make`
> assertion that `Cargo.lock` resolves `bsv-middleware-cloudflare` to the local
> path (not a `registry+` source), so a future version bump can't silently strand
> the relay on an unfixed crates.io build again.

### 4b. Implemented — bounded transient retry on the KV auth path

The D1 read path already self-heals via `with_d1_read_retry`; the KV auth path
did not. Added the **same pattern** to the fatal, un-retried KV ops in
`bsv-middleware-cloudflare-public/src/storage/kv_session.rs` (the crate the relay
patches in via `[patch.crates-io]`):

- `get_session` (KV READ), `get_sessions_for_identity` (KV LIST), and
  `try_consume_nonce` (KV READ + KV WRITE) now run under `with_kv_read_retry`:
  **3 attempts, 50 → 100 ms backoff, transient-class only** (`network connection
  lost`, `storage`, `reset`, `internal error`, `connection`, `timed out`, `429`,
  `too many requests`, `please try again`). A non-transient error (or the bound)
  propagates unchanged, preserving fail-closed replay protection.
- `try_consume_nonce` is idempotent under retry: the read is a read; the write is
  `put(key,"1")` (same value every time); a genuine replay is detected by the
  first read returning `Some` **before** any retry. Retrying only the transient
  *error* branch can never turn a fresh nonce into a false replay.
- Backoff uses `worker::Delay` on wasm and a no-op on the host test target, so the
  policy is unit-testable under `#[tokio::test]` (mirrors the relay's D1 helper).

Net effect: a transient KV blip during a burst self-heals **in-request** instead
of surfacing as a fatal 500 — exactly what the D1 path already does. No wire-shape
change, so TS/Go parity is preserved.

> This touches BRC-104 replay-protection code. Route it through the middleware's
> self-review gate before deploy. Un-deployed by design.

### 4c. Optional hardening (designed, not wired) — 503 + `Retry-After` on read-only endpoints

If a transient still exhausts retries, a *read-only* endpoint should answer a
poll with **`503` + `Retry-After`** (semantically "temporarily unavailable, retry"
— honest, since the row is still there and re-pollable) rather than a `500` a
client may treat as terminal. Applies to `/listMessages`, `/permissions/*`,
`/devices`, `/presence`. **Caveat:** this diverges from the byte-for-byte TS/Go
`ERR_INTERNAL_ERROR` 500 shape the repo prizes, so it needs an explicit parity
decision + a client that honours `Retry-After`. Not implemented; 4a already
removes the trigger without a wire change.

## 5. Sibling endpoints with the same hazard

Every authenticated route shares the same fatal KV auth path (E on deployed
`0.2.0`; B + D on the fixed build), so **§4a + §4b fix the auth-layer 500 for all
of them at once**. Remaining per-endpoint notes:

- **`POST /sendMessage`** — same KV auth path (fixed by 4a). Its D1 *reads*
  (`read_send_context`) are retried, but its D1 *writes* (`get_or_create_message_box`,
  `insert_message`) are **not** — a transient there → 500. Both are idempotent
  (`INSERT OR IGNORE`), so a bounded retry is safe and worth adding. A sendMessage
  500 is DELAYED-not-lost for the same reason (idempotent insert on `message_id`).
- **`POST /acknowledgeMessage`** — KV auth path (fixed by 4a) + an un-retried D1
  `DELETE`. Idempotent (re-acking a deleted id is a no-op), so a bounded retry is
  safe; a 500 here only makes the client re-ack.
- **`/socket.io/*` polling (`socketio_worker.rs`)** — KV is the source of truth
  for per-sid state; writes are already **lazy-touch + best-effort** (H5 /
  2026-06-17 lessons), so no 429→500 there. The per-sid `EngineIoSession` DO
  cold-start is off the critical path (stateless handshake + `wait_until` warm-up).
- **`/ws` upgrade + `MessageHub` DO** — DO cold-start/overload is the failure mode
  here (not KV). The **HEAD commit `e89cc11` adds last-seen WRITES on raw-socket
  drop (`peerLeft` teardown)** — extra DO-storage writes on the departure path;
  advisory/UX only and off the HTTP poll path, but worth watching as added write
  load under churn.
- **`/presence`, `/rejoin-deadline`** — already the model: the cross-DO hop is
  **fail-quiet** (any failure degrades to `present:false` / swallowed), never a
  500. UX-only, never a money/delivery gate.

## 6. Root cause, in one line

The deployed relay silently runs middleware **`0.2.0`** (its `[patch]` to the
fixed local crate went unused when that crate crossed to `0.3.1`), whose
**unconditional, fatal** BRC-31 liveness touch writes the shared session key on
every request; the `deal_keys` same-session burst tripped KV's ~1-write/sec/key
limit → **429 → fatal `/listMessages` 500** (the 2026-06-17 incident recurring).
The message was only **delayed** — the list is a pure read with a separate
explicit ack, never lost at the relay — but the client treated the transient 500
as terminal and the hand wedged. Fix: ship the patched middleware (`"0.2"→"0.3"`,
making the touch lazy + best-effort) and give the remaining fatal KV auth ops the
same bounded transient-retry the D1 read path already has.
</content>
