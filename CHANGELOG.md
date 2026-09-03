# Changelog

All notable changes to the relay. Public releases are cut from this repository with
`scripts/release-public.sh` (Cloudflare resource identifiers scrubbed) into
`Calhooon/bsv-messagebox-cloudflare`.

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
