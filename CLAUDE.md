# bsv-messagebox-cloudflare

BSV peer-to-peer messaging service on Cloudflare Workers. Rust compiled to WASM.
Port of the Node.js [`message-box-server`](https://github.com/bsv-blockchain/message-box-server)
(Express + MySQL) to a single CF Worker. Scope matches the Go port
(`go-messagebox-server`): HTTP REST only, no WebSocket. Clients poll
`/listMessages` or rely on FCM push.

## Build & Run

```bash
npm install              # Install wrangler
npm run dev              # Local dev (D1 + KV emulated)
worker-build --release   # Build WASM
npm run deploy           # Deploy

# D1 migrations
npx wrangler d1 migrations apply bsv-messagebox-cloudflare-prod          # remote
npx wrangler d1 migrations apply bsv-messagebox-cloudflare-prod --local  # local
```

Build target: `wasm32-unknown-unknown`. Output: `build/worker/shim.mjs`.

## Architecture

```
Request → lib.rs (fetch) → BRC-31 auth → route dispatch → storage.rs → D1
/sendMessage → payments.rs (HTTP → wallet-infra) + fcm.rs (HTTP → googleapis)
```

- **lib.rs** — `#[event(fetch)]` entry. CORS preflight, `/api-docs` (public),
  then BRC-31 auth + dispatch.
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
| `AUTH_SESSIONS` | KV | BRC-31 session cache (1h TTL) |
| `BSV_NETWORK` | Var | `mainnet` or `testnet` |
| `WALLET_STORAGE_URL` | Var | Wallet service for payment internalization |
| `SERVER_PRIVATE_KEY` | Secret | BRC-31 server identity key (hex) |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Secret | Google SA JSON used to mint FCM tokens in-WASM |
| `ENABLE_FIREBASE` | Var | `"true"` to activate FCM; else pushes no-op |

## HTTP API (mirrors message-box-server)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` or `/health` | Public |
| `GET` | `/api-docs` | Public; OpenAPI 3.0 spec |
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

## Parity boundary

For payloads ≤100 MB: byte-for-byte compatible with TS `message-box-server` and Go `go-messagebox-server`. TS/Go clients work unchanged against this server.

For payloads >100 MB: Cloudflare Workers cap request bodies at 100 MB, so raw TS-compatible parity is impossible at that size. The `/beef/upload-url` endpoint + `payment.beefR2Key` path is an opt-in Rust-only extension that routes the BEEF through R2 (presigned direct upload, up to 5 TB). Clients that target cross-SDK compatibility either stay under 100 MB or feature-detect the endpoint.

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
  (`notifications=10`, others=`0`). Fee `-1` = blocked → `ERR_DELIVERY_BLOCKED`.
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
