# Changelog

All notable changes to the relay. Public releases are cut from this repository with
`scripts/release-public.sh` (Cloudflare resource identifiers scrubbed) into
`Calhooon/bsv-messagebox-cloudflare`.

## 0.3.26 — 2026-09-20

### Three alarm re-arm nets and the counter bound (bsv-low #495, #496)
- `MessageHub::websocket_close` and `websocket_error` run `rearm_pending_departures_net` first, like every fetch and socket frame: a `pendingleft:` entry stranded in another room by a lost alarm is pulled back in by the highest-signal hub events (the 2 s gate keeps it free).
- `EngineIoSession::fetch` repairs a lost heartbeat chain on every attached socket (the polling transport and the Worker→DO paths were the one wake that did not); `disarm_heartbeat_if_idle` re-reads the socket census after its delete and re-arms when a socket attached under it.
- `x-low-session-n` is bounded at `Number.MAX_SAFE_INTEGER` and refused `malformed` by name above it (`session_lane::parse_counter`): the ask rides to the hub as a JSON number through JSON.parse + serde-wasm-bindgen, which faults above 2^53, so a crafted header used to turn into a hub fault (`reason=storage`, a lane the client drops). `HubMirror::last_h` rides as a decimal string like `seen_mask` (the bound and the serializer's limit were the same constant, zero headroom); a mirror persisted as a number still reads.

## 0.3.25 — 2026-09-20

### The presence answer has the departure's own flap window (bsv-low loop 13, #491)
- `/internal/presence` (and so the join-time `presence` snapshot the joiner's hub builds from it) answers `present: null` while the room's departure debounce is still running — the same ~4 s window the `peerLeft` push waits (`pendingleft:<room>`); `false` only once the room is empty past it (`presence_answer`, pinned). It used to answer `false` the instant the room emptied: a peer mid-re-listen (leave + rejoin within a second, the client's transport watchdog) read as absent (loop 12, #491), and a killed peer's snapshot 4 s after the kill wrote the owner's told-state to absent, so the real push 50 ms later was deduped against it — the snapshot was the only delivery (loop 13, survivorLooksOnly). `null` writes no told-state, so the push behind a flap window is never deduped; the public `/presence` route reads a `null` as a hub that could not answer (never a fabricated `false`).

## 0.3.24 — 2026-09-20

### The session mirror's replay window survives the storage boundary (bsv-low loop 12)
- `HubMirror::seen_mask` (the 64-deep HTTP replay window) is persisted as a decimal STRING. The Durable Object's serializer carried the `u64` as a JavaScript number and threw above `Number.MAX_SAFE_INTEGER` — every lane past its ~53rd HTTP call — so `verify_http`'s put failed and the hub answered every later call on that lane `reason=storage` (a 401 the client kept the lane through: the honest seat of a dispute never saw the tower's ruling on its felt). Seven identities in three hours on beta. Rows persisted as numbers still read. Pinned.

## 0.3.23 — 2026-09-19

### The socket close is named (bsv-low #466)
- `EngineIoSession::websocket_close` logs `WS closed sid=… code=… clean=… reason=…` before its teardown. An idle LOW games page's socket dropped twice in 30 minutes with every pong answered up to 14 s and 22 s before each close and no relay close path taken; the runtime's bare `close` event line carried no code, so neither side could say who closed. Observability only: no behaviour change.

## 0.3.22 — 2026-09-14

### One handshake per tab (bsv-low #443 step 4) and its gate's fix round
- `POST /session/attest` (bearer `BROADCAST_TOKEN`, like `/push`): a first-party door asks whether ONE hub-lane call verifies (the HTTP-lane verify body verbatim, forwarded to the identity's hub `/internal/session-verify`); answers `{ok, identity}` or `{ok:false, reason}`, 503 when the hub cannot be asked. The body's `id` and `identity` are exactly 64 / 66 hex.
- `sessionAttach {s, identity, n, mac, nonce}`: a socket of a tab that already holds a relay lane attaches through the hub mirror instead of a BRC-103 handshake of its own (the MAC is the HTTP-lane shape over the pseudo-call `ATTACH /socket`, the nonce as the body). Dispatched before the CONNECT guard (a wake rehydrates `connected=false`). The hub is asked with its own bound (`ATTACH_HUB_TIMEOUT_MS` 1.2 s, below the client's 1.5 s attach wait inside the SDK's 5 s auth budget); ONE attach per socket (`attach_attempted`, persisted); the socket lane is minted PURELY and then set together with `Authenticated` under a compare-and-set (a handshake that completed during the hub await owns the socket: `already-authenticated`). The ack `sessionAttached {d, m}` is a one-shot MAC `HMAC-SHA256(K_hub, "sessionAttached" ‖ 0x01 ‖ sha256(d))` (the domain byte keeps it disjoint from every frame MAC); a refusal is a plain `sessionAttachRefused {reason}`.
- Every lane and its hub mirror now die at most 12 h after the mint however busy (`LANE_MAX_LIFETIME_MS`, `minted_at_ms` with a serde default of 0 = past the lifetime for records written before this field; D12's posture). The mirror stores its identity lower-cased. Bearer tokens are compared in constant time (`bearer_matches`; an unset secret matches nothing).

## 0.3.21 — 2026-09-09

### The session lane (bsv-low W-B, ts-stack divergence register row D10)
- One BRC-103 handshake per socket, then a SESSION: when the client's `authenticated` General is answered, the relay mints a 32-byte session id and a 32-byte salt (the platform RNG) and carries `{ status: "success", session: { id, expiresAt, salt } }` in `authenticationSuccess` (the reference's shape plus one field a reference client ignores). Both sides derive `K = HMAC-SHA256(salt, "low-relay-session/v1" ‖ id ‖ clientNonce ‖ serverNonce)` from the handshake's own nonces; `K` never crosses the wire.
- A session-aware client sends every later event as `sessionMessage { s, n, e, d, m }` (`d` the event's data as JSON text, `m = HMAC-SHA256(K, n_le8 ‖ e ‖ 0x00 ‖ sha256(d))`, `n` strictly increasing); the relay verifies id, idle window (1 h, refreshed by every valid frame in either direction), counter and MAC in wasm, persists the moved counter BEFORE the hub await, and routes the event exactly like a verified General. Once the client has spoken on the lane, every delivery (the hub's answers and the broadcast fan-out) rides back as `sessionEvent { n, e, d, m }` under the relay's own counter, the room-suffixed event name unchanged. Zero wallet calls per frame in either direction.
- A refusal (`unknown-session`, `expired`, `replay`, `bad-mac`, `malformed`) is said as a signed General `sessionRefused { reason }` on the reference lane and routes nothing; the client re-handshakes. A client that never presents a session is served on the reference lane forever. The lane rides the socket's attachment through hibernation (~330 B of the 2 KB cap, pinned) and dies with its socket.
- THE HTTP LANE: an in-session HTTP call (`/listMessages`, `/acknowledgeMessage`, the `/sendMessage` fallback, `/presence`, …) carries `x-low-session` (the id), `x-low-session-identity`, `x-low-session-n` (the client's own HTTP counter `h`) and `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖ "METHOD path?query" ‖ 0x00 ‖ sha256(body))`. The Worker asks the identity's `MESSAGE_HUB` DO (`/internal/session-verify`, the body's digest, never the body; bounded like every hub ask) to verify against its MIRROR of the lane (`session:<id>`: K, the identity, the window, `h`), persists the moved counter before answering, and seals the route's answer with `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖ "response" ‖ 0x00 ‖ sha256(body))` under the same `h`. A refusal is 401 `ERR_SESSION_REFUSED { reason }` (the client falls back to BRC-104 for that call); a hub that cannot be asked is 503, never a refusal. The mirror is registered by the socket DO on the FIRST frame the client sends on its socket lane (piggybacked on the routed event, no extra await), refreshed when the window moved past a 60 s slack, revoked in the socket's unregister, swept when expired. The browser preflight allows the lane's headers beside the middleware's; the response's two headers are exposed. A request without `x-low-session` takes BRC-104 exactly as before.
- THE ASK: only an `authenticated` carrying `laneAsk` mints (the ask is echoed as `session.ask`); the reference client's own `authenticated` never touches the lane. Found by the first traced hand on the lane (bsv-low, 21:36Z): the SDK's own `authenticated` and the client's re-ask both minted, the handshake's Generals are verified asynchronously on the client and completed out of order, the two sides held different lanes and every frame was refused `unknown-session` until they agreed by luck (seven mints in 40 s). Now the client binds its lane to its own latest ask.
- THE HELLO: a session-aware client's first frame on a fresh lane is `sessionHello` (its forward registers the HTTP mirror at the identity's hub at once); the hub answers `sessionWelcome`, sealed back onto the lane: the client's first verified delivery at every mint, the lane proven in both directions.
- Pure module `src/session_lane.rs` (12 pins + the vectors pin, the MAC vectors PRODUCED for the client's byte-for-byte pin and sha256-pinned in both repos, socket frames and HTTP calls both); the host wiring in `engineio/session.rs`, `message_hub.rs` and `lib.rs` (14 source/behaviour pins, every one RED-verified mechanically). Two 0.3.20 source pins that rustfmt had turned RED (the Ping arm's persist order, the membership mirror) now match whitespace-stripped.

## 0.3.20 — 2026-09-09

- The first-party box refusal (0.3.19) now covers the LIVE send path too: the hub's `sendMessage` event (raw WS and socket.io) answers `messageFailed { code: "ERR_FIRST_PARTY_BOX" }` for `low_events` and `broadcast-*` right after the room's box is derived. Found by the same review's delta-verify (M-A): the HTTP door alone left `sendLiveMessage` able to store and live-bridge a forged row. One predicate, both doors; pinned in the hub's tests.

## 0.3.19 — 2026-09-09

- `/sendMessage` REFUSES the first-party boxes (`low_events`, `broadcast-*`) with 403 `ERR_FIRST_PARTY_BOX` at the door: only the bearer-gated `/push` and `/broadcast` write them. Found by bsv-low's from-scratch tower review at the loop-10 promotion (HIGH-1): an authenticated end user could file a forged tower `case` event into a seat's durable box. The client pins each event kind to its producer's identity as well. Pinned (`the_ordinary_send_route_refuses_the_first_party_boxes_and_nothing_else`).

## 0.3.18 — 2026-09-08

### The acknowledge statements stop scanning every box on every ack (bsv-low M19-5, issue #428)
- Cloudflare D1 query insights for the loop-8 window (2026-09-07 22:16–22:56Z) showed the retained-box acknowledge UPDATE reading 8.9M rows over 1,891 calls and the delete half 7.7M over 1,648: ~4.7k rows per ack. `EXPLAIN QUERY PLAN` on the real migrations names the cost: the outer statement already seeks `sqlite_autoindex_messages_1` (message_id) but the `message_box_id IN (SELECT … FROM message_boxes WHERE type LIKE … ESCAPE …)` subquery is a `SCAN message_boxes` on every statement (SQLite's LIKE optimization cannot apply: the ESCAPE clause rules it out, and `type` is BINARY-collated while LIKE is case-insensitive), so every ack read every box row.
- Both halves now test retention with a CORRELATED predicate on the candidate row (`EXISTS (SELECT 1 FROM message_boxes mb WHERE mb.message_box_id = messages.message_box_id AND mb.type LIKE …)` / `NOT EXISTS …`): one rowid lookup per candidate message. Semantics are the IN form's byte-for-byte (a retained row is marked, any other row is deleted, a row whose box is gone is deleted; re-ack counts 0), and the bind order is unchanged. No migration and no wire change; the daily TTL sweep keeps the box-list subquery (one statement a day).
- Pins (rusqlite, dev-only, on the real migrations): the plan for both ack statements contains no `SCAN message_boxes` and looks the box up `USING INTEGER PRIMARY KEY`; the pre-0.3.18 IN form on the same fixture plans the scan (the RED side); the partition semantics above.

## 0.3.17 — 2026-09-07

### A departure delivered to a socket being replaced is REPLAYED; the stranded-departure net runs on every hub event
- bsv-low loop 7 (2026-09-07, `survivorLooksOnly`): the survivor's felt re-listens every ~12 s under a silent inbox (a fresh socket.io session each time); the `peerLeft` push landed on the session it was replacing (`delivered` = 1, so nothing was parked) and died with it — told-state Absent, every later push deduped, the open seat heard nothing (it recovered from the join-time presence snapshot). The hub now remembers the LAST DELIVERED departure per room (`lastleft:<room>`) and REPLAYS it to a session that joins the room within 60 s while the told-state still says Absent (`departure_replay_due`, pure); a session that already latched it costs nothing.
- The same loop's first survivor run (16:17Z): the killed seat's departure pushed for its events-box room but NEVER for the game room — a `pendingleft:` entry whose DO alarm was lost on a live, quiet hub (the platform class the heartbeat met on 2026-09-03). The recovery net used to run once per isolate; it now runs on EVERY hub event (a fetch or a raw-WS frame), cheap-guarded to once per 2 s (`rearm_net_due`, pure), and a scheduled time in the past counts as absent (`alarm_needs_replacing`, unchanged). `ensure_alarm_no_later_than` reads the alarm back after each set and retries once (`alarm_set_confirmed`, pure) — the set-dropped class; the fired-but-never-run class leaves the row and is the net's job.
- Log lines are the counters: `peerLeft for <room> REPLAYED to sid=…`, `rearm net re-armed N stranded departure(s)`, `set_alarm read-back mismatch`. Four new pins; 311 tests green.

## 0.3.16 — 2026-09-05

### A peerJoined that reached no session is PARKED
- `parkedjoined:<room>` mirrors 0.3.13's parked departure: an arrival pushed to an identity whose only session was dead (a heartbeat-timeout reconnect in flight) is delivered on its next register / room join. One pure rule `parked_presence_choice` decides between a parked departure and a parked arrival: told=Present drops the departure (0.3.15), told=Absent drops the arrival, the 3-minute TTL drops stale news, the newer wins a tie. bsv-low 2026-09-05 `dealtLeaveNotifyRejoin`.
  (commit `ed38eb2`: 0.3.16: a peerJoined that reached NO session is PARKED (parkedjoined:<room>) and delivered on the identity's next register / room join — the arrival m)

## 0.3.15 — 2026-09-05

### A departure is a SOCKET CLOSE, for every room
- A client `leaveRoom` on a game room is a room HOP (the felt's inbound watchdog leaves and re-joins to recover a dropped envelope); under load the re-join outran the 4 s debounce and the peer was told "opponent lost connection" about a seat that never left. Only a socket close (tab close, crash, heartbeat timeout) or an explicit app-level goodbye signals. A parked departure is dropped when the peer's arrival already wrote told=Present.
  (commit `f39b18c`: 0.3.15: a departure is a SOCKET CLOSE for every room (a leaveRoom is a room hop, never a departure); a parked departure superseded by the peer's arriv)

## 0.3.14 — 2026-09-05

### A waiting host's lobby-room departure signals only on a socket CLOSE
- The lobby's `host-left` fans out only when the host's socket closes (a crash), never on a clean `leaveRoom` (a match / cancel is a room hop) — the lobby half of the rule 0.3.15 then applied to every room.
  (commit `aa501a9`: 0.3.14: a waiting host's lobby-room departure fans host-left ONLY on a socket CLOSE (crash), never on a clean leaveRoom)

## 0.3.13 — 2026-09-05

### A peerLeft that reached no session is PARKED
- `parkedleft:<room>` with a 3-minute TTL: a departure pushed while the counterparty's only session was between a leave and a re-join is delivered on its next register / room join instead of being lost with the told-state already flipped (bsv-low full18 run 2, survivorLooksOnly).
  (commit `e847407`: 0.3.13: a departure nobody was there to receive is PARKED and delivered on the identity's next register / room join; the lobby-room match is exact)

## 0.3.12 — 2026-09-04

### A waiting host's departure is an EVENT for the lobby
- The relay fans a waiting host's departure into `broadcast-low-lobby` so the lobby's away latch is event-driven (one confirming probe at `confirmDueAt`, never a poll), and the leaver's tier-2 countdown rides a `ladder` event (bsv-low re-run round 1).
  (commit `4ce92f0`: 0.3.12: two LOW lobby/ladder EVENTS the event-driven client was missing (bsv-low full18 re-run 2026-09-05))

## 0.3.11 — 2026-09-03

### A fresh socket is not "overdue"
- 0.3.10's overdue rule treated a socket with NO ping yet as overdue, so the first inbound
  frame after the upgrade (the CONNECT) logged `heartbeat REPAIRED … pinging now` and sent
  an early ping on every join (LOW run 15: four lines at join). Harmless to liveness,
  noise in the one signal that counts repairs. The upgrade commit now stamps the
  heartbeat epoch (`last_ping_at_ms`), and a missing stamp with a pending alarm is Armed.

## 0.3.10 — 2026-09-03

### The repair believes the ping schedule, not the alarm row
- LOW run 14 caught the platform's loss in the wild (19:53Z): the re-delivered tick was
  `canceled`, and `get_alarm()` KEPT ANSWERING the tick's scheduled time while the
  runtime never fired it. The client's nudge landed 8 s past that time; 0.3.8's 10 s
  "late grace" read the row as merely late, did nothing, and the socket closed at 45 s.
  Now a ping overdue by more than 2 s past the interval is the truth whatever the row
  says (`PING_OVERDUE_GRACE_MS`), the late grace is 2 s, and a client `6` (the nudge)
  logs its check's outcome so a tail shows the class repaired or not.

## 0.3.9 — 2026-09-03

### The fault knob cannot be switched on in production
- `HEARTBEAT_TEST_LOSE_ALARM_AFTER_PONG_EVERY` is read through `env.var`, which a
  `wrangler secret put` or a dashboard edit on the PRODUCTION worker can also set — no
  deploy, no config diff. It is now honored only on a deploy whose `R2_BUCKET_NAME`
  names a beta bucket (`test_knob_n`, tested): on prod the name is inert whatever its
  value. Found by the delta-verify round on the sibling tower change.

## 0.3.8 — 2026-09-03

### The heartbeat survives a lost alarm (Cloudflare at-least-once, in practice not)
- Two LOW runs (12 and 13) each recorded a COMPLETED heartbeat tick re-delivered
  ~300 ms later as `canceled` (0 ms of wall time) with no alarm left behind — about one
  tick in a hundred. The server stopped pinging and the client closed a live socket 45 s
  later ("ping timeout"). The alarm chain is no longer the heartbeat's only driver:
  - `alarm()` arms the next tick FIRST (before the socket loop and its awaits) and again
    after the work.
  - `ensure_heartbeat`: every inbound frame (before dispatch) and every delivery
    re-reads the alarm; a missing or long-lost one is repaired — a ping now when the
    interval has passed, an alarm for the remainder otherwise (`heartbeat_repair`,
    table-tested; source-pinned).
  - The client half (bsv-low `heartbeatNudge.ts`): when the server ping is 8 s late the
    client sends ONE engine.io `noop`, which is the inbound frame that triggers the
    repair — 33 s < the 45 s cliff, zero frames in the healthy case.
- The broadcast-registry refresh is judged by TIME (`registry_refreshed_at_ms`,
  `REGISTRY_REFRESH_EVERY_MS` = 175 s), replacing the 0.3.5 ping counter whose clobber
  and ordering bugs cost three releases in one day. A confirmed `joinRoom` stamps the
  refresh (the hub registered at join), so the first tick does not re-register.
- TEST-ONLY fault injector `HEARTBEAT_TEST_LOSE_ALARM_AFTER_PONG_EVERY=<n>` (env var;
  absent/0 = off; never in a production config): after every n-th tick's pong the alarm
  is deleted — the platform's loss with its real timing (after the pong, so nothing
  inbound follows) — so the repair is proven red→green against a deployed relay. (A
  first cut skipped the arm inside the alarm handler; the pong 40 ms later repaired it
  every time on beta — belt one proven, fault unfaithful.)

## 0.3.7 — 2026-09-03

### The heartbeat refresh no longer closes the socket it refreshes
- The alarm's Ping arm persisted its copy of the attachment AFTER awaiting the
  registry refresh. The client's pong for that very ping lands during the await and
  persists its own clear of `awaiting_pong_since_ms`; the late write erased it, and the
  next alarm judged the ping unanswered and closed a live socket — once per refresh
  (every 8th ping, ≈200 s after each join; LOW run 12's broadcast subscriber saw
  "transport close" at +213 s and +200 s). The arm now persists first and refreshes
  after; nothing is written to the attachment after the await. Source-pinned.

## 0.3.6 — 2026-09-03

### Broadcast subscribers stay subscribed (the second half of 0.3.5)
- The session's own `joined_rooms` — the list the heartbeat alarm reads to decide
  whether a socket keeps its broadcast-registry entry alive — was declared, persisted
  and read but never WRITTEN (only the per-identity hub tracked rooms). So the
  heartbeat refresh still never ran after 0.3.5 (228 alarms, 0 refreshes in a
  28-minute window) and a live socket went deaf 30 minutes after its join. The routed
  `joinRoom` (once the hub confirmed it) / `leaveRoom` now record membership in the
  session and persist it with the attachment. Pinned by a membership round-trip test
  and a source pin on the routing block.

## 0.3.5 — 2026-09-03

### Broadcast subscribers no longer go deaf after 30 minutes
- The heartbeat's registry-refresh counter (`pings_since_registry_refresh`) is now
  carried in the session state, so the attachment re-persisted on every pong keeps
  it. It was written back as a hard `0`, so the count never reached
  `REFRESH_EVERY_PINGS`, the registry entry was never refreshed, and a live socket
  holding `broadcast-*` rooms stopped receiving broadcasts exactly 30 minutes after
  its last join while still answering every ping (LOW run 10: a seat missed two
  block announcements). Pinned by a round-trip unit test.

## 0.3.4 — 2026-09-03

### Public-tree hygiene, enforced
- `scripts/release-public.sh` rewrites every account `workers.dev` host to a placeholder and
  REFUSES to publish while one survives (0.3.3 scrubbed the test defaults by hand and left
  the host in older reports and scripts; the export is now the gate, not a sweep).

## 0.3.3 — 2026-09-03

### Public-tree hygiene
- The e2e/probe test targets read the deployed relay URL from `PROD_URL`; no account host
  is named anywhere in the tree (the public mirror must never carry deployment identifiers).

## 0.3.2 — 2026-09-03

### Broadcast subscriptions live as long as their socket
- The broadcast registry entry is refreshed from the Engine.IO heartbeat every
  `REFRESH_EVERY_PINGS` (7 × 25 s) while a socket holds a `broadcast-*` room, and the
  freshness window is 30 min (was 10 min with NO refresh — a pre-heartbeat assumption that
  every socket re-joined every 45 s; once sockets lived for hours, a subscriber joined at
  T was stale by T+10 min and every broadcast after that fanned out to nobody).
  `register_identity` is one shared helper (hub join + heartbeat). Proven on a live felt:
  four consecutive block announcements delivered 0–11 s after each block.

### `/push` accepts the flat first-party body
- `POST /push` wraps a flat `{sender, recipient, messageBox, body}` into `/sendMessage`'s
  `{message: {…, messageId}}` with a minted 64-hex `messageId` (sha256 over the parts and
  the clock); an explicit `message` wrapper passes through unchanged. The route used to
  answer `ERR_MESSAGE_REQUIRED` to every flat first-party push, so no server event was
  ever stored. The validator runs on the wrapped body.

## 0.3.1 — 2026-09-03

### Presence as EVENTS (no client poll)
- `peerJoined-<room>` is pushed to the counterparty symmetric to `peerLeft` (hub-to-hub
  `/internal/peer-joined`, the same `peer_room` pairing and socket.io fan-out).
- A JOINING socket receives a `presence-<room>` SNAPSHOT of the peer room's occupancy
  (`present: true|false`, `null` when nothing is known) — the join hello's precedent.
- Departures and arrivals are deduped by a per-room TOLD-STATE, so a socket flap inside the
  debounce window is suppressed and a client never sees the same transition twice.
- The Engine.IO heartbeat's `ping timeout` close now runs the full departure teardown
  (`unregister_with_message_hub` → `peerLeft`): a seat whose process was killed sends no
  close frame, and before this its counterparty was never told.

### First-party server push
- `POST /push` (bearer `BROADCAST_TOKEN`, the same gate as `/broadcast`): a first-party
  worker files a DURABLE message into ONE identity's box — stored, live-bridged to the
  recipient's sockets, acknowledged by the client like any message, replayed un-acked after
  a reload. The `sender` is the producer's own identity key, trusted under the bearer; the
  rest of the body is the exact `/sendMessage` shape (`validate_send_message` + `process_send`).

### Operator note
- A Cloudflare Worker cannot reach this relay's `*.workers.dev` hostname with a plain `fetch()`
  when it lives on the same account (error 1042 behind a 404; every `*.workers.dev` host of
  one account is one zone). Producers on the same account call `/broadcast` and `/push`
  through a **service binding**.

## 0.3.0 — 2026-09-02

### Transport
- **Engine.IO SERVER heartbeat** (`EngineIoSession`): a Durable Object alarm armed at the
  `5` upgrade commit sends `2` every `pingInterval` (25 s); the client's `3` clears it; a ping
  unanswered past `pingTimeout` (20 s) closes the socket (`ping timeout`), exactly as the
  reference socket.io server behaves. The heartbeat state lives on the WebSocket attachment,
  so it is correct after hibernation, and the alarm disarms when the last socket closes.
  Before this the handshake advertised the interval and the server never pinged: every
  browser socket died 45 s after its upgrade and fell back to HTTP long-polling (measured on
  LOW: 354 long-poll frames in 37 minutes for one idle client).
- Socket.IO session TTL honours `SESSION_TTL_SECONDS` (was hardcoded 1 h) with lazy
  touch-on-traffic; the traffic-path touch fires on real `authMessage` generals.
- WS `sendMessage` acks and broadcasts on the recipient's room (official-client parity);
  duplicate WS acks are SUCCESS, not `messageFailed` (killed a 10 s send stall).
- The DO→MessageHub forward hop and the best-effort WS push are bounded and retried, so a
  wedged Durable Object can no longer hang `/sendMessage`.

### Rooms, presence, fan-out
- Public broadcast rooms (`broadcast-*` boxes) with a subscriber registry sharded by identity
  nibble (16 DOs, parallel reads) and a bearer-gated `POST /broadcast` fan-out.
- Join hello: one delivery-shaped frame to the joining socket (proves the socket to clients
  that are HTTP-first until a delivered frame).
- `peerLeft` when an identity's last session leaves a room, also on raw socket drop
  (`websocket_error` runs the same departure teardown); the push is debounced ~4 s behind a
  trailing occupancy re-check, with every stranded pending-left path closed.
- `GET /presence` returns an optional advisory `lastSeenMs`; the stayer publishes its real
  rejoin deadline; a hub fault is reported as a fault, never as an absence.

### Storage and reliability
- Transcripts retained until terminal for opt-in box classes (`/listTranscript`,
  `/purgeTranscript`).
- D1 write path bounded and retried; the remaining unguarded D1 writes guarded; the
  `find_message_box` read bounded; the transient D1 cold-start error on the first request
  retried.
- Per-recipient send context batched into one D1 round-trip.
- Uniform CORS on every response; lazy, non-fatal session touch (no 429 / CORS-less 500).
- `bsv-middleware-cloudflare` 0.3.2 (KV transient retry on the hot auth path); the dead
  path-patch that silently pinned 0.2.0 removed.

### Operations
- `SESSION_TTL_SECONDS` env var; a dedicated per-deployment config file pattern
  (`wrangler.<deployment>.toml`, private) with an isolated beta environment (own D1/KV/R2).

## 0.2.1 — 2026-05-26
- `listMessages` bounded (`LIST_MESSAGES_LIMIT`) to prevent the 128 MB Worker OOM.
