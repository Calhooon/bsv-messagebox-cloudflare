# INCIDENT — the "~10s /sendMessage latency" is a CLIENT WS-ack timeout, not a relay stall

**Date:** 2026-07-23
**Tracking:** bsv-low#249
**Status:** ROOT-CAUSED (evidence below). No relay deploy in this pass — instrumentation committed; fix identified.

---

## TL;DR

The four `relay.send fail ~10400ms` events in
`app/matrix-runs/twoHandRematch-2026-07-23_16-47-30/seat-B.log` are **NOT** a
relay server-side stall. They are the **client's `MessageBoxClient.sendLiveMessage`
waiting out its fixed 10 000 ms WebSocket-ack timeout**, then falling back to HTTP
which fast-returns `ERR_DUPLICATE_MESSAGE`.

- **Hang stage: client-side WS-ack wait.** Confidence: **HIGH.**
- **The published 0.3.0 middleware KV-auth-stall hypothesis (prime suspect) is
  NOT supported by this evidence and is effectively ELIMINATED for this run** —
  the HTTP fallback, which runs the *same* unbounded KV auth path, completed in
  ~400 ms. (The KV reads are still unbounded — a latent risk, see §6 — but they
  are not what produced these 10 s events.)
- **Structural, not load-induced** — but its *frequency* is amplified by
  resend-heavy scenarios (watchdog re-sends, a silent peer). A paced human hand
  hits it too, any time an already-delivered move is re-sent.
- **Right fix lives in THIS repo (the relay), not the middleware crate:**
  `message_hub.rs::outcome_to_outbound` maps a WS `DuplicateMessage` to
  `messageFailed`; the client only ever waits for `sendMessageAck`. A duplicate
  means *already delivered* — the relay should ack it as success so the client
  resolves in <1 s instead of burning the full 10 s timeout.

---

## 1. The evidence (seat-B.log)

```
16:48:22.497  perf relay.send ok   440ms  — resend         (WS delivered, got sendMessageAck, row stored)
16:49:07.461  perf relay.send fail 10399ms — resend Error   RelayDuplicateMessageError / ERR_DUPLICATE_MESSAGE
16:49:37.446  perf relay.send fail 10387ms — resend Error   RelayDuplicateMessageError / ERR_DUPLICATE_MESSAGE
16:50:13.311  perf relay.send fail 10473ms — resend Error   RelayDuplicateMessageError / ERR_DUPLICATE_MESSAGE
16:50:42.513  perf relay.send fail 10422ms — resend Error   RelayDuplicateMessageError / ERR_DUPLICATE_MESSAGE
```

Two facts jump out:

1. **The durations cluster tight around 10.0 s + ~0.4 s** (10399 / 10387 / 10473 /
   10422 ms). A KV / D1 stall would be *variable*. A cluster this tight is a
   **fixed timeout constant** (10 000 ms) plus a small, consistent tail (~400 ms).
2. **They are spaced ~30 s apart** — the LOW client watchdog interval — and all
   carry the `— resend` tag. This is the watchdog re-sending the *same*
   content-addressed move because the peer went silent. The *first* send of that
   move at 16:48:22 succeeded (`ok 440ms`); every re-send after is a **duplicate**.

## 2. The client path that produces the 10 s

`app/src/lib/table.ts:853` — the resend calls `mb.sendLiveMessage(...)`, wrapped
in `timeLeg('relay.send', 'resend', …)` which measures wall-clock.

`@bsv/message-box-client` `MessageBoxClient.sendLiveMessage`
(`dist/esm/src/MessageBoxClient.js:636`):

1. Joins the room; if the socket is **not** connected → immediate HTTP fallback
   (**fast**, ~400 ms). Our events are 10 s, so **the socket WAS connected** →
   the WS path was taken.
2. Emits the WS `sendMessage` event and registers a listener on **only**
   `sendMessageAck-${roomId}` (line 685, 721).
3. Sets a **10 000 ms `setTimeout`** (line 732). If no `sendMessageAck` arrives,
   it `Logger.warn('[CLIENT] WebSocket acknowledgment timed out, falling back to
   HTTP')` and calls `sendMessage()` over HTTP.
4. The HTTP `POST /sendMessage` returns `400 ERR_DUPLICATE_MESSAGE` (the row is
   already stored), which the app's `installRelayDuplicateCapture`
   (`app/src/lib/relayDuplicate.ts`) surfaces as `RelayDuplicateMessageError`.

**10 000 ms (WS-ack timeout) + ~400 ms (HTTP fallback RTT) = the ~10.4 s measured.**

## 3. WHY the `sendMessageAck` never comes — the relay-side contract bug

`src/message_hub.rs::outcome_to_outbound` (the WS `SendOutcome` → event mapping):

```rust
SendOutcome::Success        { .. } => "sendMessageAck" { status: "success", … }
SendOutcome::DuplicateMessage { .. } => "messageFailed" { reason: "Duplicate message." }   // <-- HERE
```

A WS `sendMessage` that resolves to `DuplicateMessage` emits **`messageFailed`**,
never `sendMessageAck`. But `sendLiveMessage` only listens for
`sendMessageAck-${roomId}` — it does **not** listen for `messageFailed`. So on
every duplicate WS resend, the client's ack handler never fires and the request
sits until the 10 s timeout.

Sequence, fully reconstructed:

| time | event | relay outcome | WS event emitted | client result |
|---|---|---|---|---|
| 16:48:22 | 1st send of move | `Success` | `sendMessageAck` | resolves 440 ms ✅ (row stored) |
| 16:49:07 | watchdog re-send (same msgId) | `DuplicateMessage` | `messageFailed` | ack never fires → 10 s → HTTP → `ERR_DUPLICATE` |
| 16:49:37 | watchdog re-send | `DuplicateMessage` | `messageFailed` | same 10 s |
| 16:50:13 | watchdog re-send | `DuplicateMessage` | `messageFailed` | same 10 s |
| 16:50:42 | watchdog re-send | `DuplicateMessage` | `messageFailed` | same 10 s |

The relay emits its WS response **promptly** in every case; the 10 s is spent
entirely on the client waiting for an event shape the relay chose not to send.

## 4. Why the "prime suspect" (0.3.0 middleware KV auth stall) is eliminated here

The hypothesis was that the published `bsv-middleware-cloudflare` 0.3.0
`process_auth` KV reads (`get_session`, `try_consume_nonce` in
`storage/kv_session.rs`) — which have **no op-timeout** (confirmed: plain
`self.kv.get(&key)…await`, no `Delay` race) — could stall ~10 s under the
harness's rapid same-session burst.

The evidence rules that out **for this run**:

- The HTTP fallback that resolves each event runs the **same** `process_auth` KV
  path (get_session + try_consume_nonce) and completed in **~400 ms**. If KV auth
  were stalling ~10 s, the fallback would ALSO take ~10 s and the totals would be
  ~20 s. They are ~10.4 s. So the auth KV path was fast.
- The 10 s is a **constant** (a `setTimeout`), not the variable latency a KV
  stall produces.

The unbounded KV reads remain a real latent risk worth fixing (§6), but they did
**not** cause these events. Do not ship the 0.3.2 KV-timeout change *claiming it
fixes this incident* — it would not have changed a single one of these 10 s waits.

## 5. Load-induced or structural?

**Structural** — a contract mismatch between the published `sendLiveMessage`
(waits only for `sendMessageAck`) and the relay's WS `outcome_to_outbound`
(returns `messageFailed` for a duplicate). It fires on **any** duplicate WS
resend.

The *rate* at which it bites is scenario-dependent, not the bug's cause:

- The harness runs hands back-to-back and, when a peer stalls, the watchdog
  re-sends the last (already-delivered) move every ~30 s → a 10 s burn each time.
- **A paced human hand hits it too**, any time an already-delivered move is
  re-sent: watchdog fire, reconnect replay, or the `mutualWait` idempotent-resend
  heal. It is not a pure harness artifact — it is just *more frequent* under
  resend pressure.

There is **no evidence of per-request KV/DO/D1 contention scaling with request
rate** in these events (the HTTP fallback stayed ~400 ms throughout the burst).

## 6. The fix

### Primary (fixes THIS incident) — relay, `src/message_hub.rs`

Treat a WS `DuplicateMessage` as **delivered**, and ack it as such, so the
client's `sendLiveMessage` resolves immediately instead of timing out:

- In `outcome_to_outbound`, map `SendOutcome::DuplicateMessage` to a
  `sendMessageAck` with `status: "success"` and the offending `messageId`
  (a duplicate = the exact content-addressed message is already stored ⇒ the
  recipient already has it ⇒ honest to ack as success).
- This matches the app's own semantics: `#210` / `isDuplicateMessage`
  (`app/src/lib/relayDuplicate.ts`, `table.ts:864`) already treats
  `ERR_DUPLICATE_MESSAGE` as "delivery, not failure."
- Effect: the watchdog resend resolves in <1 s (one WS round-trip) instead of
  10.4 s; no HTTP fallback, no `RelayDuplicateMessageError` surfaced.
- Keep the HTTP `outcome_to_http` mapping unchanged (it already returns 400
  `ERR_DUPLICATE_MESSAGE`, which the app maps to "delivered"). Only the WS
  ack-shape needs to change.

This fix is entirely in **this repo**. It does not touch the middleware crate.

### Secondary (latent hardening, NOT this incident) — middleware crate 0.3.2

The `bsv-middleware-cloudflare` 0.3.0 auth KV reads (`get_session`,
`try_consume_nonce`) and the relay's own `get_or_create_message_box` /
`find_message_box` READ still have **no op-timeout** (read-retry without a
timeout can't rescue a stalled read — the same lesson the D1 WRITE fix in
`d50615c` learned). Publishing 0.3.2 with an op-timeout+retry around the auth KV
reads is worth doing, but frame it as **defense-in-depth**, not the cause of the
10 s. The committed `TRACE_LAT auth_ms=` instrumentation (§7) will show these
reads are normally sub-100 ms; if a future run ever shows `auth_ms` in the
thousands, *that* is when the 0.3.2 timeout earns its keep.

### Not recommended: patching the client library

`sendLiveMessage` living in the published `@bsv/message-box-client` could be made
to also listen for `messageFailed` and resolve on a duplicate reason, but that is
upstream and not in our control. The relay-side ack fix is cleaner and sufficient.

## 7. Instrumentation committed (this pass — no deploy)

Per-stage `TRACE_LAT` logging so the next run/redeploy pins any *relay-side*
latency empirically (and confirms the auth/D1 stages stay fast, closing the
KV-stall hypothesis for good):

- `src/lib.rs` — one line per authed request:
  `TRACE_LAT req method=… path=… auth_ms=<process_auth, incl. all BRC-104 KV
  reads> route_ms=<handler> status=…`.
- `src/routes/send_message.rs` — per-op D1 timing inside `process_send`:
  `TRACE_LAT send.read_ctx … ms=…`, `send.get_or_create_box … ms=…`,
  `send.insert_message … ms=… dup=<bool>`.
- `src/message_hub.rs` — WS send outcome + duration:
  `TRACE_LAT ws.send room=… outcome=Duplicate->messageFailed(NO_ACK) ms=…` —
  this line is the empirical fingerprint of the bug: it will show the relay
  emitting its (wrong-shape) WS response in single-digit ms while the client
  waits 10 s.

**What the next run will reveal:** `auth_ms` and the `send.*` op timings all
sub-second (proving the relay is not the bottleneck), while `ws.send
outcome=Duplicate->messageFailed(NO_ACK)` appears immediately before each
client-side 10 s `relay.send fail`. That is the confirmation that the fix belongs
at the WS ack-shape, not in KV/D1 timeouts.

## 8. Reproducing locally (no mainnet sats)

The relay side can be exercised under `wrangler dev` / miniflare with a local
KV + D1 binding by POSTing the same message twice: the first stores, the second
returns `DuplicateMessage`. Over the WS channel the second emits `messageFailed`.
The client-side 10 s is reproduced by any `sendLiveMessage` call whose message is
already stored while the socket is connected — the existing
`app/src/hooks/mutualWaitRepro.test.ts` / `relayDuplicate.test.ts` already model
the duplicate answer without spending sats. No mainnet hand is needed to confirm
this incident.

## 9. Follow-up (2026-07-23, second bundle) — a SECOND, distinct 10 s cause: an unbounded DO→MessageHub forward hop

The `twoHandRematch-2026-07-23_17-13-21/seat-A.log` bundle shows
`relay.send ok 10597ms — shuffle_pass #1`. This is **not** the §3 duplicate bug
and is not fixed by `f09fd2d`:

- `ok` (not `fail`) + `#1` (the FIRST send of that move, not a watchdog resend) +
  no `[low:relay-duplicate]` marker anywhere near it ⇒ `sendLiveMessage`
  **resolved via the HTTP fallback with a FRESH 200 store**, which only happens
  if the WS attempt **never stored the message at all**. A duplicate would have
  been `fail` (§3); an ack-only loss would have stored the row and produced a
  `fail`/duplicate on the fallback. So the WS send was lost **end-to-end**, not
  just its ack.

**Mechanism (HIGH confidence).** A `sendMessage` over the **WebSocket** transport
is stored + acked through an EXTRA Durable-Object hop the HTTP path does not
take: `EngineIoSession` DO → subrequest `/internal/socketio-event` →
per-identity `MessageHub` DO → `process_send` (D1 insert) → ack back. The HTTP
`POST /sendMessage` fallback writes D1 **directly in the Worker**
(`lib.rs::handle_send_message`, no DO hop) — which is exactly why it returned in
~0.6 s while the WS attempt stalled >10 s. That DO→DO subrequest
(`engineio::session::forward_event_to_message_hub`, and the polling-path twin in
`socketio_worker`) was **UNBOUNDED**: when the target MessageHub DO is momentarily
cold / evicted / relocating (the run was a heavy funding+JOIN+broadcast burst),
the subrequest stalls past the client's fixed 10 000 ms WS-ack timeout → no
`sendMessageAck-<room>` → fallback → fresh store. Intermittent, mid-hand, after
several fast sends — inconsistent with a first-send race or a room-routing bug;
consistent with intermittent DO-hop staleness.

**Fix (relay-side, this repo).** `src/hub_forward.rs`: bound each forward attempt
with a `Delay` race (`FORWARD_OP_TIMEOUT_MS = 3 000`) and retry once
(`FORWARD_ATTEMPTS = 2`), mirroring `storage::with_d1_op_timeout` /
`with_d1_read_retry`. A stalled first attempt is abandoned in 3 s and a fresh
subrequest usually hits a warm instance and acks sub-second — inside the client's
10 s budget, so the WS ack wins and the move flow never stalls. If both attempts
fail, no events are emitted and the client's HTTP fallback remains the
at-least-once safety net (worst case = pre-fix behaviour). Money-safe: the
forwarded write is `INSERT OR IGNORE` on a UNIQUE `messageId`, so a
dropped-but-landed first attempt converges to a duplicate-ack (§3 `f09fd2d`
contract) on retry — never a double-delivery; one ack per frame; ordering
unchanged. New `TRACE_LAT ws.forward` / `siow.forward attempt=… outcome=… ms=…`
lines let a redeploy prove the hop now completes (or self-heals on retry)
sub-second. Producer-path unit tests in `hub_forward` cover: success-without-retry
(no regression), **retry recovers a stalled first attempt** (the fix), bounded
give-up → empty (fallback path), and empty-success-is-not-retried.

**Not a client-SDK change.** The fixed 10 000 ms lives in `@bsv/message-box-client`
(`node_modules`, not our source); shortening it is neither necessary nor
sufficient here. The true fix is relay-side and shipped above — it makes the WS
ack *land* rather than making the *lost-ack* cheaper.
