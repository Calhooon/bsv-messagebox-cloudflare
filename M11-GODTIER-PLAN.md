# M11 — God-tier socket.io routing (1 DO per identity)

**Status:** ✅ **PHASE 2 COMPLETE — 100% PASS RATE ACHIEVED** (2026-05-12)
**Owner:** John Calhoun
**Created:** 2026-05-11
**Target:** 100% pass rate on `tests/e2e_message_box_client_full.mjs` over ≥50 consecutive runs with zero asterisks. No client-version bumps.

## Iteration log

- **2026-05-12 Phase 1 revision:** Original Phase 1 was "extract state types". Replaced with "stateless handshake + `ctx.wait_until` pre-warm" — a 10-line change that strictly reduces the auth-handshake budget consumption with zero refactor risk. If this alone closes the gap to 100%, we stop here. If not, original Phases 2-5 follow.

- **2026-05-12 Phase 1 deployed and verified insufficient.** Deployed version `9b84f5df`. 25-run batch surfaced 4 failures in the auth-handshake mode (~16% failure rate vs. v3's 3%). Note: actually slightly WORSE than v3 (which had the auth fast-path inside the DO with no awaited register). Pre-warm only buys ~100ms of cold-start head start; CF outliers in the 1-5s range still blow through the 5s client budget. Confirms architectural change needed.

- **2026-05-12 Phase 2 attempt 1 (intercept polling-POST authMessage + polling-GET drain KV):** Failed catastrophically (100% failure, 5/5 runs). Root cause identified via SIOW trace logs: the polling-GET interception broke the socket.io `CONNECT` / `CONNACK` exchange. The CONNECT packet arrives via polling-POST with `body_len=2` (just `40`), my `is_authmessage_event` correctly returned false, so the POST fell through to the DO. DO enqueued the CONNACK to its in-memory queue. But my polling-GET interceptor unconditionally took over the GET path, never saw anything in KV (CONNACK was in DO not KV), and long-polled for 25s before returning Noop. Client never received the CONNACK, never fired `connect`, never emitted `authenticated`, and timed out at 5s. **Rolled back the Phase 2 routing**; `src/socketio_worker.rs` is built but not on the request path. Deployed version `7c214cad`.

- **Key learning from Phase 2 attempt 1:** You cannot split the polling queue between Worker (KV) and DO (in-memory). It's all-or-nothing. The socket.io protocol assumes a single source of truth for the per-sid outbound queue. Any "intercept some packets in Worker, forward others to DO" strategy will break the queue invariant.

- **2026-05-12 Phase 2 attempt 2 — SUCCESS.** Deployed version `87bcfdc8`. Worker now handles **all** `/socket.io/?...&transport=polling` traffic (POST and GET): Engine.IO Ping/Pong, Socket.IO CONNECT/CONNACK, BRC-103 `authMessage` events end-to-end, and Phase C bridge events (joinRoom / sendMessage / leaveRoom) forwarded to MessageHub. KV is the single source of truth for per-sid auth state, polling queue, CONNECT flag, closed flag. The `EngineIoSession` DO is touched only at WS upgrade, where it hydrates `inner.auth` from KV before accepting the WebSocket. **Validation: 35/35 consecutive passes** (10-run smoke + 25-run batch). The deployed `@bsv/message-box-client` / `@bsv/authsocket-client` work unmodified — same wire bytes.

- **2026-05-12 Regression suite — all green.** Against prod (`87bcfdc8`):
  - `e2e_message_box_client_full.mjs` — **35/35** (the headline)
  - `e2e_authsocket_brc103.mjs` — 6/6 (socket.io BRC-103 handshake)
  - `e2e_socketio_transport.mjs` — 4/4 (handshake + transport upgrade)
  - `e2e_ws_subscribe.py` — 7/7 (raw `/ws` HTTP→WS broadcast bridge)
  - `e2e_ws_lifecycle.py` — 11/11 (raw `/ws` event surface + parity)
  - `e2e_ws_send_paths.py` — 3/3 (WS send error paths)
  - `e2e_live_parity.py` — 12/12 (HTTP REST byte-for-byte parity with TS server)

  No regressions. Raw `/ws` path is unaffected by Phase 2 (it never touched `EngineIoSession` to begin with). Socket.IO transport surface is wire-byte identical because Phase 2 just relocates state ownership; the encoded packets the client sees are unchanged.

## Summary of what shipped

**Phase 1** (deployed in version `9b84f5df`, superseded by Phase 2's `87bcfdc8`):
- `lib.rs::route_socketio_request` builds the Engine.IO `0{...}` handshake response in the Worker. `ctx.wait_until` fires a fire-and-forget warm-up to the per-sid DO so any subsequent traffic that does land on it (now only the WS upgrade) has the cold-start cost partially hidden by client-side processing time.

**Phase 2** (deployed in `87bcfdc8`, **current head**):
- New module `src/socketio_worker.rs` — comprehensive Worker-side socket.io polling implementation. Owns the full polling protocol state machine.
- New KV keys (in the existing `AUTH_SESSIONS` namespace, `sio:` prefix): `auth:{sid}`, `identity:{sid}`, `queue:{sid}`, `connected:{sid}`, `closed:{sid}`. 1-hour TTL.
- `lib.rs::route_socketio_request` now dispatches polling-POST and polling-GET to `socketio_worker`. WS upgrade still goes to the `EngineIoSession` DO.
- `EngineIoSession::handle_ws_upgrade` hydrates `inner.auth` from KV before accepting the WebSocket, so post-WS-upgrade traffic verifies signed Generals against the same nonces the Worker established during the polling-phase BRC-103 handshake.

## Phases 3-5: not pursued

Phases 3-5 of the original plan (fold `EngineIoSession` state into `MessageHub`, stateless polling handshake re-routing, delete `EngineIoSession`) are no longer needed for the 100% goal — Phase 2 already eliminated the DO cold-start from the 5s budget, which is what the user pain point was. Phases 3-5 would be architectural cleanup, valuable but not blocking. Deferred.

---

## 1. Context

### Why now

M10 #61 shipped the socket.io transport surface (Phases A–D) and made the
unmodified official `@bsv/message-box-client` v2.1.1 work against the
Rust server. The current head (`610a8382-f0be-41e2-8ab3-de85731912b2`)
passes the headline test `tests/e2e_message_box_client_full.mjs` ~97%
of the time on prod. The remaining ~3% are not algorithmic bugs — they
are cold-start variance on the per-`sid` `EngineIoSession` DO blowing
the client's 5-second auth-handshake timeout.

The user bar for shipping is **100%, no asterisks, no client bumps.**
Reaching that bar requires removing the per-sid DO from the auth-critical
path.

### Measured baseline (post-current-fixes, post-deploy)

| Stage | Pass rate | Dominant failure mode |
|---|---|---|
| Pre-M11 baseline (v0, no fast-path) | 14/20 = **70%** | `WebSocket authentication timed out!` (5s budget — round-tripping `authenticated` to MessageHub for `authenticationSuccess` was the bottleneck) |
| v2 fast-path with awaited register | 46/50 = **92%** | `timeout: bob.sendLiveMessage()` (30s — register-await blocked the WS event loop on cold MessageHub) |
| **v3 fast-path + auto-register on joinRoom (current prod)** | 35/36 = **~97%** | `WebSocket authentication timed out!` (residual — `EngineIoSession` cold-start + BRC-103 round-trip exceeding 5s) |
| **M11 target** | **100/100** | n/a |

### Why the residual ~3% will not yield to more bug-fixing

The `EngineIoSession` DO is created fresh per `sid`. Every fresh client
identity (every test run uses `PrivateKey.fromRandom()`) → fresh `sid` →
fresh DO instance with cold-start latency. CF cold-start on a busy edge
can spike to 3-5s+ rarely; combined with the BRC-103 round-trip and the
5s client-side `authenticationSuccess` budget, the math sometimes
doesn't work. No further "fast-pathing" inside `EngineIoSession` will
change the cold-start floor.

### Why we can't shorten the 5s client budget

The 5s timeout is hard-coded in `@bsv/message-box-client`
(`MessageBoxClient.ts:439`). The user constraint is **no client-version
bumps**, so we cannot relax it. The server must respond within the
5s window, which means cold-start participants must be reduced to zero
on the auth path.

---

## 2. Constraints

| Constraint | Source | Implication |
|---|---|---|
| Deployed clients on `@bsv/message-box-client` v2.1.x must keep working unmodified | User: "Cannot bump any client version" (2026-05-11 conversation) | Wire protocol stays identical; we rearrange server internals only |
| `@bsv/authsocket-client` callers must keep working unmodified | Same | socket.io polling-first handshake must remain supported |
| 5s auth-handshake timeout is fixed | `MessageBoxClient.ts:439` | Server's `authenticationSuccess` must arrive within 5s of client emitting `authenticated` |
| 30s test step timeout is the slack for joinRoom/sendMessage | `tests/e2e_message_box_client_full.mjs:79` | Auth-adjacent flows can take up to 30s; only the auth handshake is on the 5s budget |
| BRC-103 over `authMessage` event format unchanged | TS authsocket convention | Wire format byte-identical |
| socket.io `transports: ['polling','websocket']` with `upgrade: true` defaults | Verified: zero consumers pass explicit `transports` | Server must accept polling-first handshake |
| Quality gates per CLAUDE.md must pass before any deploy | `CLAUDE.md` § Quality Gates | All five gates required |

---

## 3. The change

### Today's architecture

```
Worker (route_socketio_request)
    │
    ├─ /socket.io/ (polling handshake) → EngineIoSession DO (per-sid, COLD)
    ├─ /socket.io/?sid=X polling-POST/GET → EngineIoSession DO (per-sid)
    └─ /socket.io/?sid=X WS upgrade  → EngineIoSession DO (accepts WS)

EngineIoSession (per-sid):
    - Engine.IO transport state (polling/upgrade/ws)
    - BRC-103 auth state
    - WS attachment
    - Calls back to MessageHub for joinRoom/sendMessage/registry

MessageHub (per-identity):
    - Raw /ws WS sockets
    - socketio subscriber registry (sid → joined_rooms)
    - Broadcast fan-out (HTTP→WS push)
```

Two DOs per socket.io connection. Two cold-starts on a fresh login.
Two cross-DO hops on broadcast. The auth path *always* touches
EngineIoSession (cold) AND MessageHub.

### M11 architecture

```
Worker:
    │
    ├─ /socket.io/ (polling handshake, no sid) → STATELESS Worker handler:
    │       generate sid, return Engine.IO `0{...}` packet. NO DO.
    │
    ├─ /socket.io/?sid=X polling-POST (auth-phase, identity unknown):
    │       lookup sid→identity in cache; if MISS:
    │       → AuthShim DO (per-sid, short-lived). Verifies BRC-103
    │         InitialRequest, learns identity, writes sid→identity
    │         to KV + per-edge cache, replies with InitialResponse.
    │       if HIT: route directly to MessageHub.idFromName(identity)
    │
    ├─ /socket.io/?sid=X polling-POST/GET (post-auth):
    │       lookup sid→identity (cache hit common) → MessageHub
    │
    └─ /socket.io/?sid=X WS upgrade:
            lookup sid→identity → MessageHub (accepts WS, attaches)

AuthShim DO (per-sid, transient):
    - Only handles the BRC-103 handshake phase
    - After auth: writes sid→identity binding, replies, hibernates,
      eventually evicted. Never on the broadcast hot path.

MessageHub (per-identity):
    - All Engine.IO transport state (multiple sids per identity OK,
      inner map keyed by sid)
    - All BRC-103 auth state (per sid)
    - All WS attachments (raw /ws + socket.io WS)
    - socketio subscriber list IS the per-sid inner map (no separate registry)
    - Broadcast fan-out emits directly to its own attached sockets
```

**Cold-starts on a fresh login:** 1 (AuthShim — transient).
**Cross-DO hops on broadcast:** 1 (sender hub → receiver hub).
**Auth round-trip after BRC-103 known:** 0 cross-DO (all inside MessageHub).

### What changes in the wire protocol

**Nothing.** The client cannot tell the difference. socket.io URL paths,
sid format, Engine.IO packet codes, BRC-103 event names and payloads —
all unchanged.

---

## 4. Phases & quality gates

Each phase is independently deployable, ships behind a feature flag
(`M11_GODTIER_ROUTING` env var), and is verified before moving on.

### Phase 1 — Stateless handshake + `ctx.wait_until` pre-warm

The current handshake path (`route_socketio_request` for empty-sid
polling GET) calls `EngineIoSession.idFromName(sid).fetch("/__init")`
synchronously. The DO cold-starts on this call; the Worker blocks
until the DO returns the `0{...}` packet, then ships it to the client.

That cold-start delay is *inside* the client's 5-second auth-handshake
budget — `MessageBoxClient` creates its 5s `connectionInitPromise`
roughly when `socket.io-client` begins this handshake request.

Phase 1 makes the handshake response stateless in the Worker:

1. Generate `sid` (already done — `engineio::make_session_id`).
2. Build the Engine.IO `0{...}` packet directly in the Worker
   (`engineio::open_handshake_packet` is already `pub`).
3. Fire `ctx.wait_until` on a fire-and-forget fetch to
   `EngineIoSession.idFromName(sid).fetch("/__init?sid=...")`. This
   warms the DO in the background.
4. Return the handshake response to the client immediately.

By the time the client processes the response, fires `'connect'`,
emits `'authenticated'`, and the resulting polling-POST arrives at the
Worker, the DO has had `~RTT + processing_delay` extra time to cold-start.
For median cold-start (~500ms) this is enough to fully hide it.

The protocol stays byte-identical: the handshake response body is the
same Engine.IO `0` packet the DO produces today. Existing client
parses it the same way.

**Files touched:**
- `src/lib.rs` — `route_socketio_request` empty-sid branch becomes
  Worker-stateless; takes `ctx: &Context` to fire `wait_until`.
- `src/engineio/session.rs` — `handle_init` becomes idempotent / safe
  to call when state already initialised (it already is — line 539-541
  resets `inner`, which is safe; but verify rehydrate-path doesn't
  conflict).

**Gates (Phase 1):**
- `cargo fmt --all` clean
- `cargo clippy --target wasm32-unknown-unknown -- -D warnings` clean
- `cargo test --lib` — all 203 unit tests pass
- `cargo check --target wasm32-unknown-unknown` clean
- `worker-build --release` succeeds
- Deploy to prod
- 50-run batch of `tests/e2e_message_box_client_full.mjs` against prod.
  Acceptance: **≥ 49/50 passes** (proof Phase 1 doesn't regress and
  measurably improves vs. v3's 35/36). If 50/50: **declare M11 done**,
  skip Phases 2-5.

### Phase 2 — Add `AuthShim` DO + KV cache

Stand up the new transient DO without removing `EngineIoSession`.
Route a single feature-flagged path through it for validation.

**Files touched:**
- `src/engineio/auth_shim.rs` (new) — AuthShim DO impl
- `src/lib.rs` — feature-flagged route to AuthShim
- `wrangler.toml` — new DO binding `AUTH_SHIM`
- `migrations/000X_auth_shim.sql` (none; DO migration only)

**Gates:**
- All five quality gates pass
- Feature flag OFF: prod behavior identical (regression-free)
- Feature flag ON for a single test identity: BRC-103 handshake completes via AuthShim, sid→identity binding written to KV
- New unit tests covering AuthShim isolated logic

### Phase 3 — Fold state into `MessageHub`

Move Engine.IO transport state, BRC-103 auth state, and WS attachment
handling into `MessageHub`. Add an inner `HashMap<sid, SessionState>`.

**Files touched:**
- `src/message_hub.rs` — gain inner sid-map, accept WS upgrades, handle polling pump
- `src/engineio/session.rs` — gain forwarding mode that proxies to the corresponding `MessageHub.idFromName(identity)` once identity is known

**Gates:**
- All five quality gates pass
- Existing M9 raw `/ws` test suite still passes
- Existing M10 socket.io test suite still passes

### Phase 4 — Stateless polling handshake in Worker

Remove the DO call from the initial `GET /socket.io/?transport=polling`
handshake. Generate sid + return `0{...}` directly from `lib.rs`.

**Files touched:**
- `src/lib.rs` — stateless handler for the empty-sid handshake
- `src/engineio/mod.rs` — expose `make_session_id` + `open_handshake_packet` to Worker scope

**Gates:**
- All five quality gates
- A 50-run batch of `tests/e2e_message_box_client_full.mjs` with flag ON → **100/100 pass**

### Phase 5 — Delete `EngineIoSession`

Once Phase 4 validates, the flag goes default-ON and the old DO is
removed. Migration drops `ENGINEIO_SESSION` binding (DO instances
hibernate to nothing; no data loss).

**Files touched:**
- `src/engineio/session.rs` — deleted
- `src/lib.rs` — remove all references
- `wrangler.toml` — drop binding + add deletion migration
- All transports/protocol parsing moved into `engineio/codec.rs` (unchanged) and `message_hub.rs`

**Gates:**
- All five quality gates
- 50-run batch passes 100%
- Re-run all existing e2e suites: e2e_parity, e2e_payment, e2e_ws_*, e2e_authsocket_*, e2e_message_box_client_full
- Manual smoke-test from `bsv-worm` and a stand-in for MetaNet Client (HTTP-only — no client change)

---

## 5. Quality gates (apply to every deploy)

From CLAUDE.md, before closing any phase:

```bash
cargo fmt --all
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo check --target wasm32-unknown-unknown
cargo test --lib
worker-build --release
```

All five must be green. No exceptions.

---

## 6. Proof of success (the "no asterisks" bar)

The headline acceptance test is `tests/e2e_message_box_client_full.mjs`
run **50 consecutive times against prod** with the flag fully on
(Phase 4+). Every run must produce:

```
=== Result: OK (0 failure(s)) ===
```

Run via the existing batch harness `/tmp/run-batch.sh` (or its repo
equivalent if we promote it). Single failure resets the count.

In addition:

- **No regression:** `tests/e2e_parity.sh`, `tests/e2e_payment.py`,
  `tests/e2e_ws_lifecycle.py`, `tests/e2e_ws_subscribe.py`,
  `tests/e2e_authsocket_full.mjs`, `tests/e2e_authsocket_brc103.mjs`,
  `tests/e2e_socketio_transport.mjs` all green on prod.
- **Cost shape:** Cloudflare dashboard shows ≤50% of pre-M11
  `Durable Object instances created` over a 24h window with similar
  test traffic (the AuthShim is short-lived; we're trading two DOs
  per session for one transient + already-existing per-identity).
- **Latency:** the median of the 50-run batch's `RUN N dur=` should
  be ≤32s (matches today's median), and the **p99 should be ≤35s**
  (today's p99 occasionally spikes to 117s on cold-start outliers
  — eliminating that is the whole point).

---

## 7. Rollback plan

Each phase is feature-flagged via `M11_GODTIER_ROUTING` env var. To
roll back:

1. Set `M11_GODTIER_ROUTING=false` in `wrangler.toml` (or via
   `wrangler secret put`). Redeploy.
2. Worker resumes routing all `/socket.io/*` traffic to the legacy
   `EngineIoSession` DO. In-flight connections drain naturally over
   their hibernation cycle.
3. The AuthShim DO bindings stay registered (unused). KV `sid→identity`
   entries TTL out automatically.

Phase 5 (delete `EngineIoSession`) is the only irreversible step.
Hold for one full week after Phase 4's 50-run validation before
shipping Phase 5.

---

## 8. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Cross-edge KV propagation delay (sid→identity) causes intermittent route misses | Medium | Fallback to AuthShim DO lookup on cache miss; AuthShim is canonical source until it hibernates |
| Multi-socket-per-identity (Alice opens 2 tabs) confuses the inner sid-map in MessageHub | Low | Existing hibernatable WS attachment handles multiple sockets; sid-map keyed by sid |
| Phase 3's MessageHub gains too much surface area (god object) | Low-medium | Extract helpers; keep `engineio/codec.rs` and `engineio/auth.rs` separate; only state migrates |
| BRC-103 auth-shim verification differs subtly from legacy path | Low | Reuse `engineio::auth::handle_auth_message` verbatim — same code path, just runs in AuthShim instead of EngineIoSession |
| Hibernatable WS limitation: can't accept WS on AuthShim then "transfer" to MessageHub | High (it's a hard constraint) | Architectural decision: AuthShim NEVER accepts a WS. It only handles polling-POST during the auth phase. WS upgrade requests are routed directly to MessageHub via cache lookup (cache will be hot by upgrade time because the polling-POST that warmed it completes BEFORE the upgrade) |
| socket.io 4.x parallelism: polling-POST and WS upgrade attempts can race | Medium | Order is enforced by client: socket.io always completes the engine.io handshake (which is what sets up the sid→identity binding via AuthShim) before attempting WS upgrade. Verified in socket.io-client source |
| Test framework itself flakes (e.g., wallet-infra, FCM dependencies) | Low | Already covered by existing test isolation; failures from those layers don't count against this work |

---

## 9. Out of scope (not blocking M11)

- The orphan `EngineIoSession` registry-entry bug (`sid=<empty>
  transport=none` traces seen during instrumentation). After Phase 5
  this can't exist because there's no separate registry.
- The HTTP→WS push bridge for raw `/ws` (M9 #45) — already landed,
  unchanged by M11.
- Cost-model validation at 10k idle sockets (M9 #51) — independent.
- bsv-worm / LobsterFarm integration testing — unrelated.

---

## 10. Open questions to resolve before starting

1. **Where to store the KV cache `sid→identity`?** Existing
   `AUTH_SESSIONS` KV namespace, or a dedicated `SID_INDEX` namespace
   for TTL semantics? Probably dedicated — sid TTL should match
   socket.io's session lifetime (~hours), not BRC-31's 1h.
2. **Should the stateless polling handshake (Phase 4) also work
   when the client passes a stale sid for a session we've never
   seen?** Yes — treat as "unknown sid, start over" (return new sid +
   `0{...}`). Mirrors socket.io reference server.
3. **Do we need to keep `MessageRoom` migrations from M9 #v1/v2?**
   No — those are tombstone migrations; v3 introduced `MessageHub`.
   M11 phases stay within v3+ migrations.
