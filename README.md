# bsv-messagebox-cloudflare

BSV peer-to-peer messaging service on Cloudflare Workers. Rust compiled to WASM.

Reimplementation of the Node.js [`message-box-server`](https://github.com/bsv-blockchain/message-box-server) as a single Cloudflare Worker. Delivers BRC-31-authenticated messages between identity keys, with optional BSV payment for delivery and FCM push notifications.

Scope matches [`go-messagebox-server`](https://github.com/bsv-blockchain/go-messagebox-server): HTTP REST API only, no WebSocket. Clients poll `/listMessages` or rely on FCM push.

**Cross-SDK parity confirmed live:** `tests/e2e_live_parity.py` runs the same client against both `messagebox.babbage.systems` (TS reference) and this server and diffs every response field-by-field. Current status: **12/12 IDENTICAL** at the HTTP wire level for all endpoints and error paths.

## What it does

- Accepts authenticated messages (BRC-31 mutual identity auth) for delivery to one or many recipients
- Enforces per-recipient delivery permissions: free, paid (satoshis), or blocked
- Internalizes BSV payments via a wallet storage backend for paid delivery
- Stores messages in Cloudflare D1 (SQLite), caches auth sessions in KV
- Sends FCM push notifications for the `notifications` message box

## Parity with reference implementations

**For payloads ≤100 MB, this server is byte-for-byte compatible with the TS `message-box-server` and the Go `go-messagebox-server`.** Any client built against TS or Go works against this server unchanged — same request shapes, same response shapes, same error codes, same headers, same ISO 8601 timestamps. Parity is enforced by `tests/e2e_parity.sh` (46/46 passing) and `tests/e2e_live_parity.py`.

The only HTTP-level divergence is **above 100 MB** — see "R2 extension" below.

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

## Architecture

```
HTTP Request
  └─ lib.rs (#[event(fetch)])
     ├─ CORS preflight                    (handle_cors_preflight)
     ├─ /api-docs                         (api_docs.rs)
     └─ BRC-31 auth → route dispatch
         ├─ /sendMessage       (lib.rs + payments.rs + fcm.rs)
         ├─ /listMessages      (lib.rs + storage.rs)
         ├─ /acknowledgeMessage (lib.rs + storage.rs)
         ├─ /permissions/*     (permissions.rs)
         ├─ /registerDevice, /devices (devices.rs)
         └─ → storage.rs → D1
```

- **lib.rs** — Worker entry point, auth middleware integration, route dispatch
- **routes.rs** — Shared response helpers
- **storage.rs** — D1 read/write for messages, boxes, permissions, fees, devices
- **permissions.rs** — Hierarchical permission resolution and fee quoting
- **payments.rs** — BSV payment internalization via HTTP to wallet storage
- **fcm.rs** — Google FCM v1 push delivery
- **validation.rs** — Request body validation (shape + field checks)
- **types.rs** — Shared request/response types
- **api_docs.rs** — OpenAPI 3.0 spec

## Cloudflare Bindings

| Binding | Type | Purpose | Required? |
|---|---|---|---|
| `DB` | D1 | Messages, boxes, permissions, server fees, devices | ✅ |
| `AUTH_SESSIONS` | KV | BRC-31 session cache + FCM access token cache | ✅ |
| `BSV_NETWORK` | Var | `mainnet` or `testnet` | ✅ |
| `WALLET_STORAGE_URL` | Var | Upstream wallet service for payment internalization | Only for paid delivery |
| `SERVER_PRIVATE_KEY` | Secret | BRC-31 server identity key (64-char hex) | ✅ |
| `ENABLE_FIREBASE` | Var | `"true"` to enable FCM push; anything else = FCM is a no-op | — |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Secret | Full Google service-account JSON | Only when `ENABLE_FIREBASE="true"` |
| `BEEF_BLOBS` | R2 bucket | Direct-upload target for BEEFs >100 MB | Only for R2 extension |
| `R2_BUCKET_NAME` | Var | Bucket name (must match `[[r2_buckets]].bucket_name`) | Only for R2 extension |
| `R2_ACCOUNT_ID` | Secret | Cloudflare account ID (S3 host prefix) | Only for R2 extension |
| `R2_ACCESS_KEY_ID` | Secret | R2 S3 API access key for presigning PUTs | Only for R2 extension |
| `R2_SECRET_ACCESS_KEY` | Secret | R2 S3 API secret | Only for R2 extension |

## D1 Schema

Five tables in `migrations/0001_initial.sql`:

- `message_boxes` — one per `(identity_key, type)`
- `messages` — message storage, dedup on `message_id`
- `message_permissions` — per-sender or box-wide delivery rules
- `server_fees` — server delivery fee per box type (seeded: `notifications=10`, `inbox=0`, `payment_inbox=0`)
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
2. `npx wrangler d1 create bsv-messagebox-cloudflare-prod` — record the returned `database_id`
3. `npx wrangler kv namespace create AUTH_SESSIONS` — record the returned `id`
4. Fill `wrangler.toml` with your `account_id`, `database_id`, and KV `id`
5. Apply migrations: `npx wrangler d1 migrations apply bsv-messagebox-cloudflare-prod --remote`
6. Set the mandatory secret:
   ```bash
   # 64-char hex secp256k1 private key used as the BRC-31 server identity.
   echo "<hex-private-key>" | npx wrangler secret put SERVER_PRIVATE_KEY
   ```
7. **(Optional)** Enable FCM push:
   ```bash
   # Firebase console → Project Settings → Service accounts → "Generate new private key"
   cat service-account.json | npx wrangler secret put FIREBASE_SERVICE_ACCOUNT_JSON
   # Then set ENABLE_FIREBASE = "true" in wrangler.toml [vars].
   ```
8. **(Optional)** Enable the R2 >100 MB BEEF upload extension:
   ```bash
   npx wrangler r2 bucket create <your-bucket-name>
   # Then: dashboard → R2 → Manage R2 API Tokens → Create API Token
   #   (Object Read & Write scope). Paste returned values:
   echo "<r2-access-key-id>"     | npx wrangler secret put R2_ACCESS_KEY_ID
   echo "<r2-secret-access-key>" | npx wrangler secret put R2_SECRET_ACCESS_KEY
   echo "<your-account-id>"      | npx wrangler secret put R2_ACCOUNT_ID
   # Update wrangler.toml [[r2_buckets]].bucket_name + [vars].R2_BUCKET_NAME
   # to match the bucket you just created.
   ```
9. Deploy: `npm run deploy`

## Testing

Quality gates — run all five before shipping:

```bash
cargo fmt --all
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo check --target wasm32-unknown-unknown
cargo test --lib
worker-build --release
```

End-to-end suites (require a running dev server or deployment, a BRC-31 client such as the one in `tests/`, and a MetaNet Client wallet at `localhost:3321`):

| Suite | What it proves |
|---|---|
| `tests/e2e_message_cycle.sh` | send → list → acknowledge round trip (8 assertions) |
| `tests/e2e_parity.sh --rust-only` | Response shape parity vs the TS/Go servers (46 assertions) |
| `tests/e2e_live_parity.py` | **Live diff** against a second server (e.g. `messagebox.babbage.systems`). 12 tests covering every endpoint + error path. |
| `tests/e2e_real_sats.py` | Fee enforcement + cross-identity flows with real BSV sats (19 assertions) |
| `tests/e2e_payment.py` | Full BRC-29 paid delivery with a real on-chain payment tx (18 assertions) |
| `tests/e2e_r2_upload.py` | 150 MB BEEF upload via presigned R2 URL, bypassing the 100 MB Workers cap |

Env vars the tests read:
- `X402_CLI` or `X402_CLIENT_DIR` — path to your BRC-31 client's CLI / library
- `NODE_URL` and `RUST_URL` — reference + target server URLs for live parity
- `WALLET_A_IDENTITY`, `WALLET_B_IDENTITY`, `SELF_IDENTITY` — the public identity keys of the wallets on `localhost:3321` / `3322`

## Consumers

Any client that implements BRC-31 auth and (for paid delivery) wallet `internalizeAction` works unchanged against this server. Known consumers:

- MetaNet Client wallet — paid notifications and paywalled mailbox delivery
- `bsv-worm` — reliable message delivery with retry semantics
- AI agents using `bsv-middleware-cloudflare` — coordination via FCM push + polling

## Middleware dependency

This Worker is built on [`bsv-middleware-cloudflare`](https://crates.io/crates/bsv-middleware-cloudflare) (repo: [Calhooon/bsv-middleware-cloudflare](https://github.com/Calhooon/bsv-middleware-cloudflare)) — the Rust/WASM port of `auth-express-middleware` + `payment-express-middleware`. Pinned to `^0.1.2` in `Cargo.toml`.

## License

MIT — see [LICENSE](LICENSE).
