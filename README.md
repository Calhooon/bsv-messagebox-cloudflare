# rust-message-box

BSV peer-to-peer messaging service on Cloudflare Workers. Rust compiled to WASM.

Reimplementation of the Node.js [`message-box-server`](https://github.com/bsv-blockchain/message-box-server) as a single Cloudflare Worker. Delivers BRC-31-authenticated messages between identity keys, with optional BSV payment for delivery and FCM push notifications.

Surface: HTTP REST + WebSocket. The HTTP layer is byte-for-byte compatible with the TS server and the Go [`go-messagebox-server`](https://github.com/bsv-blockchain/go-messagebox-server). The WebSocket layer at `/ws` restores parity with the TS server's `@bsv/authsocket` event surface using a per-identity hibernatable Cloudflare Durable Object (`MessageHub`); event names and payloads are byte-compatible, but the transport is raw WebSockets rather than socket.io. See "WebSocket" below for what that means for existing TS clients.

## What it does

- Accepts authenticated messages (BRC-31 mutual identity auth) for delivery to one or many recipients
- Enforces per-recipient delivery permissions: free, paid (satoshis), or blocked
- Internalizes BSV payments via a wallet storage backend for paid delivery
- Stores messages in Cloudflare D1 (SQLite), caches auth sessions in KV
- Sends FCM push notifications for the `notifications` message box
- Hosts a per-identity WebSocket endpoint (`/ws`) backed by a hibernatable Durable Object, with `joinRoom` / `leaveRoom` / `sendMessage` events matching the TS authsocket envelope

## Parity with reference implementations

**HTTP, payloads ≤100 MB:** byte-for-byte compatible with the TS `message-box-server` and the Go `go-messagebox-server`. Any client built against TS or Go works against this server unchanged — same request shapes, same response shapes, same error codes, same headers, same ISO 8601 timestamps. Parity is enforced by `tests/e2e_parity.sh` (46/46 passing) and `tests/e2e_live_parity.py`.

**HTTP, above 100 MB:** see "R2 extension" below — opt-in Rust-only extension to clear Cloudflare's 100 MB body cap.

**WebSocket:** event names and payload shapes match the TS server's `@bsv/authsocket` surface; the transport is raw WebSockets rather than socket.io. Unmodified TS socket.io clients will not connect to `/ws` (no Engine.IO handshake). Go has no WebSocket surface; that boundary is unchanged. See "WebSocket" below.

Notes on platform adaptations (all transparent to clients):

- **D1 replaces MySQL.** Five MySQL migrations collapse into one SQLite schema (`migrations/0001_initial.sql`). Types, indexes, defaults, and seed data match.
- **KV session cache.** BRC-31 session nonces cache in KV with a 1-hour TTL. Set `session_ttl_seconds: 0` in the auth options to match the TS behavior of re-verifying every request.
- **FCM push.** Signs its own RS256 JWT in WASM from a Google service-account JSON (`FIREBASE_SERVICE_ACCOUNT_JSON` secret) and exchanges it for an access token via `oauth2.googleapis.com/token`. Access tokens are cached in the `AUTH_SESSIONS` KV namespace for ~1 hour. Zero external rotation plumbing required.

## Above 100 MB: R2 extension (Rust-only, opt-in)

Cloudflare Workers caps request bodies at 100 MB. The TS and Go servers have no equivalent cap (Express defaults to 1 GB; Go's `net/http` has no hard limit). To handle larger BEEF payloads, **this server offers an opt-in R2 upload extension that is not present in TS or Go**:

1. Client authenticates normally, then POSTs `/beef/upload-url` (BRC-31-authed).
2. Server returns a presigned R2 URL and an object `key`, both scoped to the caller's identity key.
3. Client `PUT`s the BEEF bytes directly to R2 (up to 5 TB per object — R2's only ceiling).
4. Client POSTs `/sendMessage` with `payment.beefR2Key = "<key>"` instead of `payment.tx`.
5. Server fetches the object from R2, inlines it into the internalize request, deletes the object on success.

### Compatibility rules

- **Client sending ≤100 MB payloads with inline `payment.tx`:** fully interoperable across TS, Go, and Rust servers. Drop-in.
- **Client sending `payment.beefR2Key`:** Rust-only. TS/Go servers will return `ERR_MISSING_PAYMENT_TX` (400) because they don't implement the extension.
- **Client sending >100 MB inline `payment.tx` to Rust:** fails at the Cloudflare edge with a platform-level body-too-large error before the Worker runs. TS/Go accept the same payload. Use the R2 extension if targeting Rust.

A well-designed cross-SDK client either (a) stays under 100 MB for universal compatibility, or (b) feature-detects `/beef/upload-url` and falls back to inline `tx` on servers that don't expose it. The extension is namespaced under `/beef/*` so it cannot collide with future TS/Go endpoints.

## HTTP API

All routes except `/api-docs` require BRC-31 authentication headers (matches TS and Go).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api-docs` | OpenAPI 3.0 spec (public) |
| `GET` | `/` or `/health` | Health check (auth required; returns `{ status: "success" }` on success) |
| `POST` | `/sendMessage` | Send message to one or many recipients (with optional payment) |
| `POST` | `/listMessages` | List messages in a box the caller owns |
| `POST` | `/acknowledgeMessage` | Delete one or more messages by ID |
| `POST` | `/permissions/set` | Set delivery permission for a sender+box |
| `GET` | `/permissions/get` | Get resolved permission (sender-specific → box-wide → default) |
| `GET` | `/permissions/list` | List all permissions for the caller |
| `GET` | `/permissions/quote` | Quote delivery fee for one or many recipients |
| `POST` | `/registerDevice` | Register an FCM device token |
| `GET` | `/devices` | List active FCM devices for the caller |
| `POST` | `/beef/upload-url` | **Rust-only extension.** Presigned R2 PUT URL for BEEFs >100 MB — see "Above 100 MB" section. |
| `GET`  | `/ws` | WebSocket upgrade. BRC-31 mutual auth on the upgrade GET. See "WebSocket" below. |

## WebSocket

`/ws` exposes the same event surface as the TS server's [`@bsv/authsocket`](https://github.com/bsv-blockchain/authsocket), running on a per-identity hibernatable Cloudflare Durable Object (`MessageHub`). Sockets for the same identity land on the same DO instance via `MESSAGE_HUB.idFromName(identityKey)`.

Auth runs on the upgrade GET using the same BRC-31 mutual-auth middleware as the HTTP routes; the WebSocket itself becomes the established BRC-103 channel and per-frame trust is inherited (no per-frame BRC-31 signatures, matching TS authsocket).

Both directions use the same JSON envelope:

```json
{ "event": "<name>", "data": { ... } }
```

Inbound (client → server): `joinRoom`, `leaveRoom`, `sendMessage`, `authenticated`. Rooms are keyed `<identityKey>-<messageBox>` and only the verified socket identity may join its own rooms.

Outbound (server → client): `connected`, `authenticationSuccess`, `joinedRoom`, `leftRoom`, `joinFailed`, `leaveFailed`, `sendMessageAck`, `messageFailed`, `paymentFailed`. (`authenticationFailed` is wired but not currently emitted, because BRC-31 failures are returned as HTTP 401 before the WebSocket opens.)

The WS `sendMessage` event funnels into the same shared `process_send` core as HTTP `/sendMessage`, so the resulting D1 row and FCM fan-out are byte-identical regardless of which entrypoint a client uses.

### Compatibility & status

- **Event names + payload shapes:** byte-compatible with TS authsocket.
- **Transport:** raw WebSockets, **not socket.io**. Unmodified TS socket.io clients cannot connect to `/ws` directly (no Engine.IO handshake or polling-then-upgrade dance). Migration to a raw-WS client is required; the precise failure mode is being characterized in M9 issue #52.
- **HTTP→WS push bridge:** when an HTTP `/sendMessage` succeeds, the recipient's DO broadcasts `sendMessage` to subscribed sockets (M9 #45, proven by `tests/e2e_ws_subscribe.py`). Best-effort: push failures don't fail the HTTP send. This is a deliberate divergence from TS authsocket, which does not bridge HTTP→WS.
- **Real-sats `sendMessage` over WS:** the failure path (`paymentFailed`) is wired and exercised; an end-to-end real-sats success test for the WS path is the open M9 issue #49.
- **Hibernation in production:** validated locally; staging confirmation via Cloudflare analytics is open M9 issue #50.
- **10k idle-socket cost model:** load test pending (M9 issue #51).

## Architecture

```
HTTP Request
  └─ lib.rs (#[event(fetch)])
     ├─ CORS preflight                    (handle_cors_preflight)
     ├─ /api-docs                         (api_docs.rs)
     ├─ /ws  (Upgrade: websocket)         → BRC-31 auth on upgrade
     │                                    → MESSAGE_HUB.idFromName(identityKey)
     │                                    → message_hub.rs (MessageHub DO)
     └─ BRC-31 auth → route dispatch
         ├─ /sendMessage       → routes/send_message.rs::process_send
         │                        ├─ payments.rs   (HTTP → wallet-infra)
         │                        ├─ storage.rs    → D1
         │                        └─ fcm.rs        (HTTP → googleapis)
         ├─ /listMessages      (lib.rs + storage.rs)
         ├─ /acknowledgeMessage (lib.rs + storage.rs)
         ├─ /permissions/*     (permissions.rs)
         ├─ /registerDevice, /devices (devices.rs)
         ├─ /beef/upload-url   (beef_upload.rs + r2_presign.rs)
         └─ → storage.rs → D1

WebSocket frames (inside the MessageHub DO)
  └─ message_hub.rs
     ├─ joinRoom / leaveRoom / authenticated      (channel control)
     └─ sendMessage  → routes/send_message.rs::process_send (shared with HTTP)
```

- **lib.rs** — Worker entry point, auth middleware integration, HTTP route dispatch + `/ws` upgrade routing
- **message_hub.rs** — `MessageHub` Durable Object: hibernatable raw WebSockets, per-socket attachment, event dispatcher
- **routes/send_message.rs** — Shared HTTP+WS write-path core (`process_send`) so D1 inserts and FCM fan-out are byte-identical
- **storage.rs** — D1 read/write for messages, boxes, permissions, fees, devices
- **permissions.rs** — Hierarchical permission resolution and fee quoting
- **payments.rs** — BSV payment internalization via HTTP to wallet storage
- **fcm.rs / fcm_jwt.rs / fcm_token.rs / fcm_cache.rs** — Google FCM v1 push delivery, in-WASM JWT signing, OAuth2 token cache
- **beef_upload.rs / r2_presign.rs** — `/beef/upload-url` handler and S3 v4 presigner for the R2 extension
- **validation.rs** — Request body validation (shape + field checks)
- **types.rs** — Shared request/response types
- **api_docs.rs** — OpenAPI 3.0 spec

## Cloudflare Bindings

| Binding | Type | Purpose |
|---|---|---|
| `DB` | D1 | Messages, boxes, permissions, server fees, devices |
| `AUTH_SESSIONS` | KV | BRC-31 session cache (1-hour TTL); also caches FCM OAuth2 tokens |
| `MESSAGE_HUB` | Durable Object (`MessageHub`) | Per-identity hibernatable WebSocket host. Routed via `idFromName(identityKey)`. Migration `v3` introduces it. |
| `BEEF_BLOBS` | R2 bucket | Holds large BEEF payloads (>100 MB) uploaded via presigned URL |
| `BSV_NETWORK` | Var | `mainnet` or `testnet` |
| `WALLET_STORAGE_URL` | Var | Upstream wallet service for payment internalization |
| `R2_BUCKET_NAME` | Var | Bucket name for R2 presigning; matches `BEEF_BLOBS.bucket_name` |
| `SERVER_PRIVATE_KEY` | Secret | BRC-31 server identity key (hex) |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Secret | Full Google service-account JSON (used to sign FCM JWTs in-WASM) |
| `ENABLE_FIREBASE` | Var | Set to `"true"` to enable FCM push for the `notifications` box |
| `R2_ACCOUNT_ID` / `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | Secrets | S3-compatible credentials used to mint presigned PUT URLs in-WASM |

## D1 Schema

Five tables in `migrations/0001_initial.sql`:

- `message_boxes` — one per `(identity_key, type)`
- `messages` — message storage, dedup on `message_id`
- `message_permissions` — per-sender or box-wide delivery rules
- `server_fees` — server delivery fee per box type (seeded: `notifications=100`, `inbox=0`, `payment_inbox=0` — all tunable via `UPDATE server_fees SET delivery_fee = ...`)
- `device_registrations` — FCM token lifecycle

## Build and Deploy

```bash
npm install
npm run dev              # local dev (D1 + KV emulated)
worker-build --release   # build WASM
npm run deploy           # deploy to Cloudflare Workers
```

### Initial Cloudflare setup

1. Create a Cloudflare account, note your `account_id`
2. `npx wrangler d1 create rust-message-box-prod` — record the returned `database_id`
3. `npx wrangler kv namespace create AUTH_SESSIONS` — record the returned `id`
4. Fill `wrangler.toml` with your `account_id`, `database_id`, and KV `id`
5. Apply migrations: `npx wrangler d1 migrations apply rust-message-box-prod --remote`
6. Set secrets:
   ```bash
   # 64-char hex secp256k1 private key used as the BRC-31 server identity.
   echo "<hex-private-key>" | npx wrangler secret put SERVER_PRIVATE_KEY

   # Full Google service-account JSON (only needed if you enable FCM push).
   # Download from Firebase console → Project Settings → Service accounts →
   # "Generate new private key". The JSON is fed in raw.
   cat service-account.json | npx wrangler secret put FIREBASE_SERVICE_ACCOUNT_JSON

   # Then flip the gate on in wrangler.toml:
   #   [vars] ENABLE_FIREBASE = "true"
   ```
7. Deploy: `npm run deploy`

## Testing

Quality gates — run all five before shipping:

```bash
cargo fmt --all
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo check --target wasm32-unknown-unknown
cargo test --lib
worker-build --release
```

End-to-end suites (require a deployed Worker + a BRC-31 client):

- `tests/e2e_message_cycle.sh` — send → list → acknowledge round trip
- `tests/e2e_parity.sh` — response shape parity vs Node.js server
- `tests/e2e_live_parity.py` — live parity comparison
- `tests/e2e_payment.py` — paid delivery with real sats (HTTP path)
- `tests/e2e_ws_auth.py` — BRC-31 mutual auth on the `/ws` upgrade
- `tests/e2e_ws_lifecycle.py` — WS upgrade, hibernation, ping/pong, reconnect
- `tests/e2e_ws_send_paths.py` — WS `joinRoom` / `sendMessage` / `leaveRoom` event surface
- `tests/e2e_ws_subscribe.py` — HTTP→WS push bridge (M9 #45)

Open M9 follow-ups (not yet covered by green tests): real-sats `sendMessage`
over WS (#49), staging hibernation verification (#50), 10k idle-socket
load test (#51), and a wire-compat characterization of `@bsv/authsocket`
against the raw-WS endpoint (#52).

## Consumers

Any client that implements BRC-31 auth and (for paid delivery) wallet `internalizeAction`. Known consumers:

- MetaNet Client wallet — paid notifications and paywalled mailbox delivery
- `bsv-worm` — reliable message delivery with retry semantics
- `LobsterFarm` — real-time coordination

## License

MIT — see [LICENSE](LICENSE).
