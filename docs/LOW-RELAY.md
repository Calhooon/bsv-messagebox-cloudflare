# LOW relay: 8h sessions + large payloads in the body

`low-relay` is LOW's dedicated deployment of this worker
(`wrangler.low.toml`, live at `https://your-worker.your-account.workers.dev`).
Same code as the shared instance; configuration only. This note records the
two properties LOW depends on (issue bsv-low#25) and the live proof of each.

## 8-hour auth session TTL

A multi-hand LOW table sitting outlives the default 1h BRC-31 session, so the
LOW deployment sets:

```toml
# wrangler.low.toml [vars]
SESSION_TTL_SECONDS = "28800"   # 8h
```

Plumbing: `src/lib.rs` reads `SESSION_TTL_SECONDS` (default 3600) into
`AuthMiddlewareOptions.session_ttl_seconds`, which `bsv-middleware-cloudflare`'s
`KvSessionStorage` applies as the KV `expiration_ttl` on both the
`auth:session:*` and `auth:identity:*` keys (`storage/kv_session.rs`). The
middleware also slides the window: any authenticated request past the half-TTL
mark re-touches the session (lazy + best-effort, `middleware/auth.rs`), so an
active table never lapses while a dead session still expires 8h after its last
activity.

Proof it is live (2026-07-02):

- The deployed version (`de74e8c5-1b69-4db8-acd5-5245a8cf535a`, 2026-06-17)
  shows `SESSION_TTL_SECONDS = "28800"` in its `[vars]` via
  `wrangler versions view`.
- Definitive KV check: a fresh BRC-31 session created against the live relay at
  `2026-07-02T16:56:59Z` produced `auth:session:*` / `auth:identity:*` keys
  whose KV `expiration` was `+28,801–28,804 s` from creation — exactly 8h (the
  few-second slack is the handshake round-trip), not the 1h default.

## Large payloads ride the request BODY, not headers

The 8 KB header ceiling that afflicts `x-bsv-payment`-style transports behind
common proxies (nginx 8 KB, Node 16 KB, ALB 16 KB) does not apply to any LOW
flow, because nothing LOW sends travels in an HTTP header:

- **Messages** — `POST /sendMessage` carries the message (and, if delivery
  were payable, the `payment` object with its BEEF) inside the JSON request
  body (`src/validation.rs`, `src/routes/send_message.rs`). The BRC-104 auth
  middleware authenticates the body itself
  (`AuthResult::Authenticated { body, .. }`), so body transport is covered by
  the mutual-auth signature.
- **>100 MB BEEF** — the opt-in R2 extension (`POST /beef/upload-url`,
  `src/beef_upload.rs`) presigns a direct R2 PUT and the client sends
  `payment.beefR2Key` instead of inline bytes, clearing Cloudflare's 100 MB
  Workers body cap (see README "R2 extension").
- **LOW's own caps** sit far below any transport limit: game envelopes are
  capped at 256 KiB by `low-wire` `MAX_BODY_BYTES` (mirrored as
  `MAX_ENVELOPE_CHARS = 700_000` on the app's wire JSON), and the engine.io
  WebSocket surface advertises `maxPayload = 1_000_000`, so even a
  ceiling-sized encrypted envelope fits the live-message path. The
  winner-claim evidence blob goes to the LOW watchtower as an AuthFetch JSON
  body (4 MB case cap) — also body transport, not this relay.

Live proof (2026-07-02, mainnet identities, plain messages, no payment, no
on-chain spend): 100,000 B and 262,144 B (the 256 KiB envelope ceiling)
payloads were sent p1→p2 through `https://your-worker.your-account.workers.dev` via
`@bsv/message-box-client` `sendMessage` (default AES-256-GCM encryption, so
~4/3 of that on the wire), then listed, integrity-checked byte-for-byte, and
acknowledged by the recipient. Send times: 2.2 s (first send, includes the
BRC-31 handshake) and 0.45 s.

## When the `x-bsv-payment` header WOULD matter

`bsv-middleware-cloudflare` also ships a payment middleware whose BRC-29
metering reads the `x-bsv-payment` header. This worker does not wire it —
`grep x-bsv-payment src/` is empty; only the auth middleware is used — so no
LOW-reachable path puts a BEEF in a header. The header path matters only for
BRC-29-metered endpoints, and breaks once a BEEF outgrows a fronting proxy's
header limit; the protocol fix (payment moved into the body, signalled by
`x-bsv-payment: body`) is specified in `rust-middleware/PLAN-payment-in-body.md`.
