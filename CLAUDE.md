# rust-message-box

BSV peer-to-peer messaging service on Cloudflare Workers. Rust compiled to WASM.
Port of the Node.js [`message-box-server`](https://github.com/bsv-blockchain/message-box-server)
(Express + MySQL) to a single CF Worker. Surface: HTTP REST + WebSocket. The
WebSocket layer (M9) restores parity with the TS server's `@bsv/authsocket`
event surface using a per-identity hibernatable Durable Object (`MessageHub`);
the Go port (`go-messagebox-server`) remains HTTP-only, so cross-port parity
holds at the HTTP layer and the WebSocket surface is a Rust↔TS concern only.

**Socket.io compat (M10 #61 / M11):** the same `@bsv/authsocket-client` and
`@bsv/message-box-client` that target the TS reference server connect
unchanged via `/socket.io/`. All polling traffic — handshake, CONNECT,
Engine.IO heartbeat, BRC-103 `authMessage`, and Phase C bridge events —
is handled in the Worker (`src/socketio_worker.rs`), keeping the per-sid
`EngineIoSession` DO off the client's 5-second auth budget. The DO is
touched only at WebSocket upgrade. Validation: `e2e_message_box_client_full.mjs`
runs 100% against deployed prod with no client modifications.

## Build & Run

```bash
npm install              # Install wrangler
npm run dev              # Local dev (D1 + KV emulated)
worker-build --release   # Build WASM
npm run deploy           # Deploy

# D1 migrations
npx wrangler d1 migrations apply rust-message-box-prod          # remote
npx wrangler d1 migrations apply rust-message-box-prod --local  # local
```

Build target: `wasm32-unknown-unknown`. Output: `build/worker/shim.mjs`.

## Architecture

```
HTTP Request → lib.rs (fetch) → BRC-31 auth → route dispatch
                                               ├─ routes/send_message.rs  (process_send)
                                               │     ├─ payments.rs   (HTTP → wallet-infra)
                                               │     ├─ storage.rs    → D1
                                               │     └─ fcm.rs        (HTTP → googleapis)
                                               ├─ storage.rs   → D1
                                               └─ …

WS Upgrade   → lib.rs (/ws) → BRC-31 auth on upgrade
             → MESSAGE_HUB.idFromName(identity_key)
             → message_hub.rs (MessageHub DO, hibernatable WS)
                  ├─ inbound  joinRoom / leaveRoom / sendMessage / authenticated
                  └─ outbound connected / authenticationSuccess / joinedRoom /
                              leftRoom / sendMessageAck / messageFailed /
                              paymentFailed / sendMessage (HTTP→WS push #45)
                  └─ WS sendMessage funnels into the same routes::send_message::process_send
                     as the HTTP path → identical D1 row + FCM fan-out.

/socket.io/* → lib.rs (/socket.io) → route_socketio_request
            (M10 #61 + M11 — TS socket.io compat shim, no client changes)
             ├─ handshake (no sid)           → Worker: 0{...} packet (stateless)
             ├─ polling-POST / polling-GET   → socketio_worker.rs
             │      ├─ Engine.IO Ping/Pong, Socket.IO CONNECT/CONNACK
             │      ├─ authMessage events    → engineio::auth (BRC-103 in Worker)
             │      └─ joinRoom/sendMessage  → MessageHub /internal/socketio-event
             │      State stored in KV (AUTH_SESSIONS, sio: prefix).
             └─ WS upgrade (transport=websocket)
                    → EngineIoSession DO (per-sid)
                    → DO hydrates inner.auth from KV, accepts hibernatable WS
                    → Post-upgrade: WS frames flow through DO; signed Generals
                      verify against the nonces the Worker established earlier.
```

- **lib.rs** — `#[event(fetch)]` entry. CORS preflight, `/api-docs` (public),
  BRC-31 auth + dispatch, plus `/ws` upgrade routing to the MessageHub DO
  and `/socket.io/*` routing to `socketio_worker` (polling) or
  `EngineIoSession` DO (WS upgrade).
- **socketio_worker.rs** — Worker-side socket.io polling-protocol
  implementation (M11). Owns the full per-sid polling state machine
  in KV: Engine.IO heartbeat, Socket.IO CONNECT/CONNACK, BRC-103
  `authMessage` end-to-end, Phase C bridge forward to `MessageHub`.
  Keeps the DO off the client's 5s auth budget.
- **engineio/session.rs** — `EngineIoSession` Durable Object. Per-sid
  hibernatable WebSocket host for socket.io clients after they
  complete the polling-phase handshake and upgrade. Reads BRC-103
  state from KV at upgrade so post-WS events verify against the same
  nonces the Worker established during polling.
- **engineio/auth.rs** — Pure BRC-103 driver (used by both the
  EngineIoSession DO and `socketio_worker`).
- **engineio/codec.rs** — Engine.IO + Socket.IO packet encode/decode.
- **message_hub.rs** — `MessageHub` Durable Object. Hibernatable raw
  WebSockets, per-socket attachment (identity + joined rooms), event
  dispatcher matching the TS authsocket envelope.
- **routes/send_message.rs** — Shared write-path core (`process_send`)
  used by both the HTTP `/sendMessage` handler and the WS `sendMessage`
  event so D1 inserts and FCM fan-out are byte-identical.
- **storage.rs** — D1 CRUD for messages, boxes, permissions, fees, devices.
- **permissions.rs** — Hierarchical resolution (sender-specific → box-wide → default).
- **payments.rs** — BSV `internalizeAction` via HTTP to `WALLET_STORAGE_URL`.
- **fcm.rs** — Google FCM v1 push. Signs RS256 JWT in WASM from the full
  service-account JSON (`FIREBASE_SERVICE_ACCOUNT_JSON` secret), exchanges
  for an access token via `oauth2.googleapis.com`, caches the token in KV.
- **fcm_jwt.rs / fcm_token.rs / fcm_cache.rs** — the JWT → OAuth2 → KV cache
  pipeline. Pure-Rust: `rsa 0.9` + `sha2` + `pkcs8` compile clean to wasm32.
- **validation.rs** — Request body shape + field checks, returns structured errors.
- **d1.rs** — Parameterized D1 query builder (shared pattern from rust-wallet-infra).
- **types.rs** — Shared request/response types.
- **api_docs.rs** — OpenAPI 3.0 spec served at `/api-docs`.

## Cloudflare Bindings

| Binding | Type | Purpose |
|---|---|---|
| `DB` | D1 | Messages, boxes, permissions, fees, devices |
| `AUTH_SESSIONS` | KV | BRC-31 session cache (1h TTL); also caches FCM OAuth2 tokens |
| `MESSAGE_HUB` | Durable Object (`MessageHub`) | Per-identity hibernatable WebSocket host. Routed via `idFromName(identity_key)`. Migration `v3` introduces it; `v1/v2` covered the deleted `MessageRoom` class. |
| `ENGINEIO_SESSION` | Durable Object (`EngineIoSession`) | Per-sid hibernatable WebSocket host for socket.io clients post-WS-upgrade. Routed via `idFromName(sid)`. Pre-upgrade polling state lives in KV, not the DO. |
| `BEEF_BLOBS` | R2 bucket | Holds large BEEF payloads (>100 MB) uploaded via presigned URL; consumed by `/sendMessage` when `payment.beefR2Key` is supplied. |
| `BSV_NETWORK` | Var | `mainnet` or `testnet` |
| `WALLET_STORAGE_URL` | Var | Wallet service for payment internalization |
| `R2_BUCKET_NAME` | Var | Bucket name for R2 presigning; matches `BEEF_BLOBS.bucket_name` |
| `SERVER_PRIVATE_KEY` | Secret | BRC-31 server identity key (hex) |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Secret | Google SA JSON used to mint FCM tokens in-WASM |
| `ENABLE_FIREBASE` | Var | `"true"` to activate FCM; else pushes no-op |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | Secrets | S3-compatible credentials used by `r2_presign.rs` to mint presigned PUT URLs in-WASM |

## HTTP API (mirrors message-box-server)

`/api-docs` is the only fully public route. Every other route requires
BRC-31 auth — including `/` and `/health` (the OpenAPI spec already
documents these as authed; matching the TS and Go reference servers).

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api-docs` | Public; OpenAPI 3.0 spec |
| `GET` | `/` or `/health` | BRC-31 required (parity with TS/Go) |
| `POST` | `/sendMessage` | Single or multi-recipient; payment optional. Accepts `payment.beefR2Key` (Rust-only) as alt to `payment.tx`. |
| `POST` | `/listMessages` | Caller owns box |
| `POST` | `/acknowledgeMessage` | Delete by messageId |
| `POST` | `/permissions/set` | Per-sender or box-wide rule |
| `GET` | `/permissions/get` | Resolved fee (incl. default) |
| `GET` | `/permissions/list` | All rules for caller |
| `GET` | `/permissions/quote` | Fee quote for recipients |
| `POST` | `/registerDevice` | FCM device registration |
| `GET` | `/devices` | Active FCM devices for caller |
| `POST` | `/beef/upload-url` | **Rust-only extension.** Presigned R2 PUT URL for BEEFs >100 MB. Not in TS/Go. See README "Above 100 MB" section. |
| `GET` | `/ws` | WebSocket upgrade. BRC-31 auth on the upgrade GET. See "WebSocket Surface" below. |
| `GET`/`POST` | `/socket.io/*` | Socket.io compat shim for unmodified `@bsv/authsocket-client` / `@bsv/message-box-client`. Polling traffic handled in the Worker (`src/socketio_worker.rs`), WS upgrade routes to the `EngineIoSession` DO. BRC-103 mutual auth runs over the `authMessage` Socket.IO event. M10 #61 + M11. |

## WebSocket Surface (M9)

Restores parity with the TS server's [`@bsv/authsocket`](https://github.com/bsv-blockchain/authsocket)
event surface using a hibernatable Cloudflare Durable Object. The TS
implementation rides socket.io; this Rust implementation is **raw
WebSockets** with the same JSON envelope and the same event names.

- **Path:** `GET /ws` with `Upgrade: websocket`.
- **Auth:** BRC-31 mutual auth runs on the upgrade GET via the same
  `process_auth` middleware as the HTTP routes. The verified identity
  is forwarded to the DO as `x-bsv-auth-identity-key`. After the upgrade
  the WebSocket *is* the BRC-103 channel — per-frame trust is inherited
  from the handshake (matches TS authsocket; no per-frame BRC-31
  signatures). On auth failure the middleware's parity wire shape
  `{"status":"error","code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}`
  is returned with HTTP 401 — the upgrade never completes.
- **Routing:** `MESSAGE_HUB.idFromName(identity_key)` lands every
  socket for a given identity on the same DO instance (one DO per
  identity, not one per socket or per room).
- **Hibernation:** registered via `state.accept_web_socket` (workers-rs
  0.8). Idle DOs hibernate after ~30s and resume on inbound frames.
  Per-socket attachment (identity key + joined rooms) is serialized
  through `serialize_attachment` so it survives hibernation.
- **Wire envelope (both directions):** `{"event":"<name>","data":{...}}`.
  Raw WS frames — **no Engine.IO / socket.io polling-then-upgrade dance**.
  Binary frames are rejected with `messageFailed`.
- **Rooms:** `roomId = "<identityKey>-<messageBox>"`. Ownership rule:
  the verified socket identity must equal `<identityKey>`. Cross-identity
  joins return `joinFailed`.

### Event surface

Inbound (client → server):

| Event | `data` | Notes |
|---|---|---|
| `joinRoom` | `{ roomId }` | Subscribe the socket to a room. Identity-owned only. |
| `leaveRoom` | `{ roomId }` | Unsubscribe. Idempotent (`leaveFailed` if not joined). |
| `sendMessage` | `{ roomId, message: { recipient, messageBox, messageId, body }, payment? }` | Funnels into the same `process_send` core as HTTP `/sendMessage`; paid sends work via the same `payment.tx` envelope. Real-sats WS success proven by `tests/e2e_ws_payment.py` (M9 #49, closed). |
| `authenticated` | `{}` | Optional ack to surface `authenticationSuccess`. |

Outbound (server → client):

| Event | When |
|---|---|
| `connected` | Immediately after upgrade with `{ identityKey }`. |
| `authenticationSuccess` | Reply to inbound `authenticated`. |
| `authenticationFailed` | Wired in `message_hub.rs` (`#[allow(dead_code)]`); not currently emitted because BRC-31 failures short-circuit before the WS opens. |
| `joinedRoom` / `leftRoom` | Successful room mutations. |
| `joinFailed` / `leaveFailed` | With `{ reason }`. |
| `sendMessageAck` | One per recipient on a successful `sendMessage`. |
| `messageFailed` | Validation / D1 / parse / unsupported-frame errors. |
| `paymentFailed` | When the WS `sendMessage` write path rejects a payment. |
| `sendMessage` (server→client fan-out) | Emitted by the HTTP→WS push bridge (M9 #45) when HTTP `/sendMessage` succeeds — recipient's DO broadcasts to subscribed sockets. Test: `tests/e2e_ws_subscribe.py`. |

### Parity boundary (WebSocket)

- **Event names + payload shapes** match TS authsocket byte-for-byte.
- **Two transports**:
  - **Raw `/ws`** — Rust-only path, JSON envelope, M9 surface. TS
    clients on socket.io will NOT connect here.
  - **`/socket.io/*`** — full socket.io compat shim (M10 #61 / M11).
    Unmodified TS `@bsv/authsocket-client` / `@bsv/message-box-client`
    connect here. Polling phase + BRC-103 handshake handled in the
    Worker; the DO is touched only at WS upgrade.

### Divergences from TS authsocket

- **HTTP→WS push bridge (M9 #45, landed).** When HTTP `/sendMessage`
  succeeds, `routes/send_message.rs::push_to_recipient_sockets` posts
  to each recipient's DO via `MESSAGE_HUB.idFromName(recipient)`'s
  internal `/internal/push` route. The DO fans out `sendMessage` to
  every socket whose attachment lists the matching room. Best-effort:
  push failures are logged but never fail the HTTP send (D1 row is the
  source of truth; offline clients pick up via `listMessages`). TS
  authsocket does not bridge HTTP→WS — this is a Rust-only divergence.
  Test: `tests/e2e_ws_subscribe.py`.
- **Paid `sendMessage` over WS** — proven with real sats via
  `tests/e2e_ws_payment.py` (M9 #49, closed).
- **Hibernation in production** — verified in staging (M9 #50, closed).
- **Load characteristics** — 10k idle-socket cost-model validated
  (M9 #51, closed). Matches Cloudflare's hibernation example.
- **TS socket.io clients on `/socket.io/*`** — wire-compat probe
  closed (M9 #52); the M11 implementation goes beyond a probe and
  actually serves the polling protocol from the Worker, so unmodified
  `@bsv/authsocket-client` works end-to-end against deployed prod
  (`tests/e2e_authsocket_brc103.mjs`,
  `tests/e2e_message_box_client_full.mjs`).

## Parity boundary

**HTTP, payloads ≤100 MB:** byte-for-byte compatible with TS
`message-box-server` and Go `go-messagebox-server`. TS/Go clients work
unchanged against this server.

**HTTP, payloads >100 MB:** Cloudflare Workers cap request bodies at
100 MB, so raw TS-compatible parity is impossible at that size. The
`/beef/upload-url` endpoint + `payment.beefR2Key` path is an opt-in
Rust-only extension that routes the BEEF through R2 (presigned direct
upload, up to 5 TB). Clients that target cross-SDK compatibility either
stay under 100 MB or feature-detect the endpoint.

**WebSocket / socket.io:** event names and payload shapes are
byte-compatible with the TS server's `@bsv/authsocket` surface across
both transports we expose:

- **Raw `/ws`** — Rust-only path, JSON envelope, M9 surface.
- **`/socket.io/*`** — full socket.io compat shim (M10 #61 + M11).
  Unmodified `@bsv/authsocket-client` and `@bsv/message-box-client`
  work as-is. Polling traffic is handled in the Worker
  (`src/socketio_worker.rs`); the per-sid `EngineIoSession` DO is
  touched only at WS upgrade. Proven by
  `tests/e2e_message_box_client_full.mjs` (35/35 against prod).

The HTTP→WS push bridge (M9 #45) is a Rust-only divergence not present
in TS; landed and proven via `tests/e2e_ws_subscribe.py`. Go
`go-messagebox-server` has no WebSocket surface; that boundary is
unchanged. See "WebSocket Surface" above for full detail.

## D1 Schema

Five tables in `migrations/0001_initial.sql`:
- `message_boxes` — one per `(identity_key, type)`
- `messages` — dedup on `message_id`
- `message_permissions` — `(recipient, sender, message_box)` unique; `sender IS NULL` = box-wide
- `server_fees` — seeded: `notifications=100`, `inbox=0`, `payment_inbox=0` (tune via SQL UPDATE)
- `device_registrations` — FCM token lifecycle, `active` flag

## Key Patterns

- **D1 numerics**: All numbers returned as f64. Entity structs use `Option<f64>`, cast to u32/i64.
- **No tokio**: WASM workers use `wasm-bindgen-futures`, not tokio. HTTP via `worker::Fetch`.
- **Permission resolution**: sender-specific row > box-wide row (sender IS NULL) > default
  (`notifications=100`, others=`0` — matches `server_fees` seed in
  `migrations/0001_initial.sql`). Fee `-1` = blocked → `ERR_DELIVERY_BLOCKED`.
- **Payment flow**: fee quote → client builds tx with delivery fee at output 0 and
  per-recipient outputs → `sendMessage` body includes `payment`; `payments.rs` posts
  `internalizeAction` to `WALLET_STORAGE_URL`; per-recipient outputs merged into stored body.
- **Timestamps**: stored as SQLite `datetime('now')` strings; normalized to ISO 8601
  via `storage::to_iso8601` for response parity with the TS server.
- **FCM**: `send_fcm_notification` is fire-and-forget on successful `/sendMessage` for
  the `notifications` box only.

## Quality Gates (YOU enforce these — no CI)

Before closing ANY issue, YOU must run all of these and fix until they pass:

```bash
cargo fmt --all                                                    # 1. Format
cargo clippy --target wasm32-unknown-unknown -- -D warnings        # 2. Zero warnings
cargo check --target wasm32-unknown-unknown                        # 3. Compiles to WASM
cargo test --lib                                                   # 4. All unit tests pass
worker-build --release                                             # 5. WASM binary builds
```

If ANY gate fails, you fix it before moving on. No exceptions.

## Testing Strategy

| Layer | What | How |
|---|---|---|
| **Unit** | types, validation, permission resolution, FCM body shape | `cargo test --lib` |
| **Integration** | Full HTTP→D1 stack | `npm run dev` + curl |
| **Parity** | Response shape matches Node.js server | `tests/e2e_parity.sh`, `tests/e2e_live_parity.py` |
| **Payment** | Paid delivery with real sats | `tests/e2e_payment.py` |

## Sibling Dependencies

Path deps (not yet on crates.io / public):
- `../bsv-rs` — BSV primitives (`bsv-rs` crate on GitHub)
- `../rust-middleware/bsv-middleware-cloudflare` — BRC-31 middleware for Workers

External services:
- `WALLET_STORAGE_URL` → wallet service with `internalizeAction` endpoint
- `fcm.googleapis.com` → FCM v1 API (requires pre-issued OAuth2 token)

## Reference Code

| What | Where |
|---|---|
| Original TS server | `~/bsv/message-box-server/` |
| BRC-31 auth middleware | `~/bsv/rust-middleware/bsv-middleware-cloudflare/` |
| BSV primitives | `~/bsv/bsv-rs/` |
| D1 query builder pattern | `~/bsv/rust-wallet-infra/src/d1/` |
| CF Worker pattern | `~/bsv/rust-chaintracks/src/lib.rs` |

## Consumers

- MetaNet Client wallet — paid notifications, paywalled mailbox
- `bsv-worm` — reliable delivery with retry
- `LobsterFarm` — coordination via FCM push and polling
