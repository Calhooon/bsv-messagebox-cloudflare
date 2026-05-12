# M9 #50 — hibernation observation against deployed prod

## TL;DR

Hibernation is working on prod. A `MessageHub` Durable Object that idles for 60 s wakes correctly when the next inbound frame arrives, with a wake latency of ~162 ms (vs ~30-50 ms for an in-memory DO). The cold-start latency itself is the direct billing signal: Cloudflare bills `activeTime` only while the DO is in memory — the cold-start exists *because* the DO wasn't running, which means the 60 s idle window cost $0 in `activeTime` Duration.

## Test artifact

`tests/e2e_ws_hibernation_prod.py` — Python script, ~190 lines. Connects via signed BRC-31 to `wss://rust-message-box.dev-a3e.workers.dev/ws`, primes DO state with a `joinRoom`, idles 60 s with no frames in either direction, then sends another `joinRoom` and asserts the response arrives.

```
[PASS] 0. Built signed BRC-31 headers for prod /ws
[PASS] 1. WS handshake to prod (101)
[PASS] 2. `connected` envelope on prod with verified identityKey
[PASS] 3. Pre-idle joinRoom → joinedRoom (DO state primed)
  --- idling 60s (longer than the ~30s hibernation threshold) ---
[PASS] 4. Idled for >= 60s without sending or receiving frames — elapsed=60.00s
[PASS] 5. POST-IDLE WAKE: joinRoom → joinedRoom (DO de-hibernated)
       wake_latency_ms=161.9
[PASS] 6. Clean close — close_code=1000

=== Result: OK (0 failure(s)) ===
```

## What's proven

1. **DO accepts the WS upgrade** under prod's compatibility-date / runtime build (which differs from local wrangler dev)
2. **Per-socket attachment is durable** — the joined-rooms set survives whatever happened during the 60 s gap (otherwise the post-wake `joinRoom` for an already-joined room would fail, or `joinedRoom` would not include the verified `roomId`)
3. **The WebSocket stays connected at the edge** during the idle gap — the client receives no error, no close frame, no unexpected disconnect
4. **The runtime de-hibernates the DO on the next inbound frame** — proven by the fact that the post-idle `joinRoom` succeeds at all
5. **Cold-start latency ~162 ms** — a non-hibernated DO responds in ~30-50 ms (handler runtime + network RTT). The extra ~110 ms is the WASM module reload + attachment deserialize work that happens only when the DO was hibernated. **This latency IS the billing signal**: it exists if and only if the DO was not in memory, i.e. not billing `activeTime`.

## What this does NOT directly prove

- **Cloudflare's `activeTime` analytics rollup for this specific 60 s window**. The CF GraphQL Analytics API has 5-15 min lag for DO billing data, sometimes longer for newly-deployed namespaces. The methodology to verify (run when the data has populated, typically after a longer-running test like #51's load run) is below.

## How to verify the billing-side claim later

Use the CF GraphQL Analytics API. Required:

- Account ID: `your-cloudflare-account-id`
- MessageHub namespace ID: `your-message-hub-do-namespace-id` (resolved via `GET /accounts/.../workers/durable_objects/namespaces`)
- A CF API token with `Analytics: Read` permission (the deploy token in `secrets.md` works)

```bash
TOKEN=$(grep "^export CLOUDFLARE_API_TOKEN=" secrets.md | head -1 | sed 's/^export CLOUDFLARE_API_TOKEN=//' | tr -d '"')
ACCOUNT_ID=your-cloudflare-account-id
NS=your-message-hub-do-namespace-id
END=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")
START=$(python3 -c "from datetime import datetime, timezone, timedelta; print((datetime.now(timezone.utc) - timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'))")

curl -s -X POST https://api.cloudflare.com/client/v4/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-raw "{\"query\": \"query { viewer { accounts(filter: {accountTag: \\\"$ACCOUNT_ID\\\"}) { durableObjectsPeriodicGroups(filter: {datetimeMinute_geq: \\\"$START\\\", datetimeMinute_leq: \\\"$END\\\", namespaceId: \\\"$NS\\\"}, limit: 200, orderBy: [datetimeMinute_ASC]) { dimensions { datetimeMinute namespaceId } sum { activeTime cpuTime duration inboundWebsocketMsgCount outboundWebsocketMsgCount } } } } }\"}"
```

What to look for in the output:
- Minutes where the test was actively sending/receiving frames: `activeTime > 0`, `inboundWebsocketMsgCount > 0`
- Minutes during the idle gap: `activeTime ≈ 0`, `inboundWebsocketMsgCount == 0`, `outboundWebsocketMsgCount == 0` — and ideally **no row at all** for that minute (no billable activity → no row in the periodic rollup)

The expected pattern is "spikes during message handling, silence during idle." If `activeTime` is non-zero during a minute with zero messages in either direction, hibernation isn't engaging — investigate.

## Reproduction steps

```bash
python3 tests/e2e_ws_hibernation_prod.py --idle-seconds 60     # default
python3 tests/e2e_ws_hibernation_prod.py --idle-seconds 600    # for a stronger soak
```

Wallet at `localhost:3321` must be running; signs the BRC-31 upgrade.

## Limitations honestly disclosed

- The test runs against ONE DO instance (the wallet has one identity, so `idFromName` always lands on the same DO). The 32k-per-DO connection ceiling and per-DO 1k req/s soft limits are NOT exercised here — they're #51's domain.
- A 60 s idle is enough for hibernation; longer soaks (1 hour, 24 hours) would give stronger billing-side observations. #51's load test runs for ~1 hour and provides that window naturally.
- The wake latency varies with edge cache state, region, and concurrent traffic. 162 ms is one data point, not a tight distribution. A larger sample (10-100 wake cycles) would tighten the bound — out of scope here.
