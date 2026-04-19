# bsv-messagebox-cloudflare

**1:1 Rust/WASM/Cloudflare port of [message-box-server](https://github.com/bsv-blockchain/message-box-server).**

Complete replacement — REST API, FCM push, BRC-31 auth, BSV payment internalization. When this ships, the Node.js server sunsets.

> **Note (historical):** The original plan in M6 included WebSocket real-time via Durable Objects. That milestone was **dropped** on 2026-04-21 to match the scope of `go-messagebox-server`, which is REST-only. Clients poll `/listMessages` or use FCM push. Below M6 section retained for history.

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (Edition 2021) → wasm32-unknown-unknown |
| Runtime | Cloudflare Workers |
| Database | D1 (SQLite) — 5 tables |
| Auth sessions | KV (1hr TTL) |
| WebSocket | Durable Objects (`MessageRoom`) |
| Push | FCM v1 API (Google OAuth2 JWT from Worker) |
| Payments | BSV internalizeAction via wallet-infra |
| Auth | BRC-31 mutual identity (bsv-auth-cloudflare) |
| BSV SDK | bsv-rs (local path ../rust-sdk) |

## Architecture

```
HTTP Request
    ↓ (BRC-31 auth headers)
Cloudflare Worker (Rust → WASM)
    ├── Auth Middleware (BRC-31, session caching in KV)
    ├── Route Dispatcher (12 REST endpoints)
    ├── Storage (D1, 5 tables)
    ├── Payments (HTTP → wallet-infra internalizeAction)
    ├── FCM (HTTP → fcm.googleapis.com, Google JWT)
    └── WebSocket upgrade → Durable Object (MessageRoom)
         ├── BRC-31 auth on connect
         ├── Room join/leave
         └── Real-time message broadcast + DB persist
```

## Endpoints (1:1 match)

### Authenticated REST (BRC-31)
| Method | Path | Node.js source | Milestone |
|--------|------|-----------------|-----------|
| POST | `/sendMessage` | sendMessage.ts | M2 (single), M4 (multi+pay) |
| POST | `/listMessages` | listMessages.ts | M2 |
| POST | `/acknowledgeMessage` | acknowledgeMessage.ts | M2 |
| POST | `/permissions/set` | permissions/setPermission.ts | M3 |
| GET | `/permissions/get` | permissions/getPermission.ts | M3 |
| GET | `/permissions/list` | permissions/listPermissions.ts | M3 |
| GET | `/permissions/quote` | permissions/getQuote.ts | M3 |
| POST | `/registerDevice` | registerDevice.ts | M5 |
| GET | `/devices` | listDevices.ts | M5 |

### WebSocket (BRC-31 auth on handshake)
| Event | Direction | Milestone |
|-------|-----------|-----------|
| `sendMessage` | client → server → room | M6 |
| `joinRoom` | client → server | M6 |
| `leaveRoom` | client → server | M6 |
| `disconnect` | client → server | M6 |

### Public
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` or `/health` | Health check |

## Database (D1)

5 tables ported from MySQL — see `migrations/0001_initial.sql`:
- `message_boxes` — one per (identityKey, type)
- `messages` — message storage with dedup on messageId
- `message_permissions` — hierarchical sender/box permissions
- `server_fees` — delivery fee per box type (seeded)
- `device_registrations` — FCM token lifecycle

## Milestones

### M1: Foundation & Scaffold
- Worker skeleton, D1 schema, BRC-31 auth, CORS, health endpoint
- CI: `cargo test` passes, `npm run dev` starts

### M2: Core Message Operations
- POST /sendMessage (single recipient, no payments)
- POST /listMessages
- POST /acknowledgeMessage
- Auto-create message boxes on first use
- Unit tests ported from Node.js test suite

### M3: Permissions & Fees
- All 4 permission endpoints
- Hierarchical permission resolution (sender-specific → box-wide → auto-create)
- Server fee lookup
- Smart defaults (notifications=10, others=0)
- Quote calculation (single + multi-recipient)

### M4: Multi-Recipient & Payments
- Multi-recipient sendMessage
- Payment internalization via HTTP to wallet-infra
- Server delivery fee (output index 0) + per-recipient fees
- Custom instructions mapping for output routing
- Blocked recipient short-circuit (fee = -1)

### M5: FCM Push Notifications
- Google OAuth2 JWT generation (service account → access token)
- FCM v1 API: POST https://fcm.googleapis.com/v1/projects/{id}/messages:send
- POST /registerDevice, GET /devices
- Token lifecycle (register, update last_used, deactivate on error)
- Push on message delivery (notifications box only)

### M6: WebSocket via Durable Objects
- `MessageRoom` Durable Object class
- WebSocket upgrade from Worker → DO
- BRC-31 auth on WebSocket handshake
- Room join/leave/broadcast
- sendMessage event: persist to D1 + broadcast to room
- Graceful disconnect cleanup

### M7: Testing & Parity
- Port all existing Node.js tests (sendMessage, listMessages, acknowledgeMessage)
- Integration tests against deployed Worker
- E2E parity tests: same requests → same responses as Node.js server
- Vector tests with real sats (mainnet payment flows)
- WebSocket integration tests
- FCM delivery verification

### M8: Cutover & Deployment
- Production deploy with custom domain
- DNS cutover from Node.js to CF Worker
- Client migration verification
- Node.js server sunset

## Testing Strategy

| Layer | Tool | What |
|-------|------|------|
| Unit | `cargo test` | Types, storage, permissions, fee logic |
| Integration | `npm run test:e2e` | HTTP against deployed Worker |
| Parity | comparison script | Same payloads → Node.js vs Rust responses |
| Vector | hardcoded fixtures | Known good request/response pairs with real txids |
| Live | MetaNet Client wallet | Real sats, real BRC-31 auth, end-to-end |

## Sibling Dependencies

```
~/bsv/rust-sdk                              → bsv-rs (BSV primitives)
~/bsv/rust-middleware/bsv-auth-cloudflare   → BRC-31 auth middleware
~/bsv/rust-wallet-infra                     → wallet storage (HTTP target for payments)
~/bsv/rust-chaintracks                      → chain tracking (used by wallet-infra)
```

## Getting Started

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install worker-build
npm install

# Create Cloudflare resources (once)
npx wrangler d1 create bsv-messagebox-cloudflare
npx wrangler kv namespace create AUTH_SESSIONS
# Update wrangler.toml with IDs

# Run migrations
npm run migrate:local

# Dev
npm run dev

# Deploy
npm run deploy
```
