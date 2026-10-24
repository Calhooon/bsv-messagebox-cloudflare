> **The code of record.** This repository is the home of `bsv-messagebox-cloudflare` since 0.5.5: every change lands here through a pull request under the machine gate (the `test`, `fmt`, `clippy`, `wasm32` and `scrub` checks, linear history), and a `v*` tag publishes the crate through crates.io trusted publishing. The deployment config carries placeholders only; the deployed Workers' identifiers live in the operator's private infra repository, never here, and the `scrub` check (`tools/scrub.sh`) refuses an identifier, a deployment hostname, a key-shaped or token-shaped string, a second wrangler config or a secrets file on every pull request.

# bsv-messagebox-cloudflare

A BSV messaging relay on Cloudflare Workers: BRC-31 authentication, delivery
permissions, optional paid delivery, D1 message storage, KV sessions, raw
WebSockets through a hibernatable Durable Object, and a Socket.IO transport for
unmodified `@bsv/authsocket-client` and `@bsv/message-box-client`. This
repository is the code of record: development happens on its branches and lands
on `main` through pull requests.

## Version and dependencies

The relay is **0.7.0**, published on crates.io as `bsv-messagebox-cloudflare`
(the library keeps its identifier `rust_message_box`). The release of record is
the tag `v0.7.0`. [Cargo.toml](Cargo.toml) pins **bsv-rs =0.7.0**,
**bsv-middleware-cloudflare =0.7.0** and **bsv-middleware-core =0.4.0**; the
bsv-middleware-rs dependency is the compatible `0.6.1` requirement, not an exact
pin. [CHANGELOG.md](CHANGELOG.md) is the record of changes.

## Routes

The router is `handle` in [src/lib.rs](src/lib.rs).

| Method | Path | Auth |
|---|---|---|
| `GET` | `/api-docs` | Public; the OpenAPI description in [src/api_docs.rs](src/api_docs.rs) |
| `POST` | `/push`, `/broadcast`, `/session/attest` | Bearer `BROADCAST_TOKEN` (producer workers, not end users) |
| `GET` | `/ws` | BRC-31 on the upgrade; raw WebSocket to the `MessageHub` Durable Object |
| `GET`, `POST` | `/socket.io/*` | Engine.IO and Socket.IO; BRC-103 over the `authMessage` event |
| `GET` | `/`, `/health` | BRC-31 |
| `POST` | `/sendMessage`, `/listMessages`, `/acknowledgeMessage` | BRC-31 |
| `POST` | `/listTranscript`, `/purgeTranscript` | BRC-31; boxes in `RETAIN_BOX_PREFIXES` only |
| `POST` | `/permissions/set` | BRC-31 |
| `GET` | `/permissions/get`, `/permissions/list`, `/permissions/quote` | BRC-31 |
| `POST` | `/registerDevice` | BRC-31 |
| `GET` | `/devices` | BRC-31 |
| `POST` | `/beef/upload-url`, `/beef/download-url` | BRC-31; presigned R2 URLs |
| `GET` | `/presence` | BRC-31 |
| `POST` | `/rejoin-deadline` | BRC-31 |
| `POST` | `/turn-credentials`, `/turn-credentials/revoke` | BRC-31; `TURN_CREDENTIALS = "on"` only |

HTTP and WebSocket sends share [src/routes/send_message.rs](src/routes/send_message.rs).
The scheduled event drains deferred delivery fees and reclaims released payment
objects.

## Messages and payment words

The paid door checks the fee and verifies BEEF ancestry and unproven spends.
It reads BEEF as a stream, including R2 objects, with a saved cursor when a
request pauses between elements or inputs. A local script-work decline is not
a verdict that the payment is invalid.

| HTTP | Word | Meaning |
|---|---|---|
| 400 | `ERR_INVALID_PAYMENT` | Invalid bytes, spend, output or merkle-root refusal; byte errors name offset and kind. |
| 400 | `ERR_INSUFFICIENT_PAYMENT` | The delivery output pays less than the fee. |
| 422 | `ERR_PAYMENT_WORK` | Local work budget exhausted; validity remains undetermined. |
| 500 | `ERR_SERVER_MISCONFIGURED` | No header service is configured. |
| 503 | `ERR_PAYMENT_UNAVAILABLE` | Header service could not answer; retry. |
| 503 | `ERR_PAYMENT_PENDING` | Reading paused; repeat the same request to resume. |
| 503 | `ERR_PAYMENT_CHANGED` | Object changed between verification and hand-off. |

`/sendMessage` also carries a per-identity send budget
([src/send_budget.rs](src/send_budget.rs)): past it the answer is 429
`ERR_SEND_BUDGET` naming the window (`SEND_BUDGET_SENDS`, `SEND_BUDGET_BYTES`,
`SEND_BUDGET_WINDOW_SECS`).

[wrangler.toml](wrangler.toml) sets `[limits] cpu_ms = 43000` and
`work_units = 10000000`. The latter is compiled by [build.rs](build.rs) into a
per-input budget; changing it requires a rebuild. bsv-rs reserves reached
opcodes and hash bytes before doing that work. The work refusal carries
`resource`, `input`, `budget`, `workSpent`, `attempted`, `offset` and `txid`.
Every resumed reader receives the budget again; the cursor does not store it.
There is no resume within a script and this is not a wall-clock guarantee.

## Build and gate

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --lib -- -D warnings
cargo test --no-fail-fast
cargo build --release --target wasm32-unknown-unknown --lib
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs exactly these on every
PR and main push. The full deployment artifact also requires worker-build
compatible with the Worker SDK in the manifest, and a clang with the
WebAssembly target for ring's C on wasm32. The payment reader's host witnesses
are in [src/beef_door.rs](src/beef_door.rs); integration suites are in
[tests](tests). Live paid tests require a separately authorized environment.

## Releases

The tag is the release of record. From 0.5.6 on, the crate
`bsv-messagebox-cloudflare` on crates.io carries the same version as the tag:
[.github/workflows/release.yml](.github/workflows/release.yml) publishes it on a
`v*` tag push through crates.io trusted publishing, after checking the tag
against the manifest's version, the tag's commit against `main`, and the
ci.yml gate. The Worker in production is deployed from the tag by the stack's
infra. No earlier version was published to crates.io under this name or as
`rust-message-box`.

## Deploy and operate a charging tenant

Use the public release tag `v0.5.6`, provision the bindings described in
[wrangler.toml](wrangler.toml), apply [migrations](migrations) in order, build the
Worker and deploy with an operator-owned configuration. Carry the CPU limit
into that configuration; the work limit comes from the build's source config.
Keep the payment door closed until the release is reviewed for that tenant and
the header service is bound and answering. A charging tenant needs a working
`HEADER_SERVICE` binding or `HEADER_SERVICE_URL`, and a wallet storage service
for fee internalization; a missing header service fails closed.

The archive queue (0.8.0). The Worker binds the queue `relay-archive` as its
producer (`ARCHIVE_QUEUE`) and is its consumer; migration 0011 adds the
version the consumer writes. Before deploying 0.8.0 the operator applies the
migration and creates the queue, once each:

```sh
wrangler d1 migrations apply <your-d1-database> -c <your-config> --remote
wrangler queues create relay-archive
```

Nothing enqueues in 0.8.0: the consumer is ready for the release that moves
the live mailbox into the recipient's hub, and every route still reads D1. A
rollback to 0.7.1 is whole: 0.7.1 binds no queue and never reads the column.

A second environment (a beta Worker beside a production one) needs its own
queue and its own consumer, because a queue has one consumer Worker and the
consumer writes its batches through its own D1 binding: a shared queue would
carry one environment's archive rows into the other's database. Wrangler does
not inherit queue bindings into `[env.*]`, so the operator creates
`wrangler queues create relay-archive-<env>` and declares, under
`[env.<name>]`, a `[[env.<name>.queues.producers]]` block binding
`ARCHIVE_QUEUE` to it and a `[[env.<name>.queues.consumers]]` block with the
template's settings (`max_batch_size = 100`, `max_batch_timeout = 2`,
`max_retries = 3`, `retry_delay = 10`). The template stays single-environment.

The listing's and the acknowledge's worst wait (message box #22). Each of the
two is bounded on its own: a D1 read that stalls on every attempt costs
6,150 ms and answers 503 `ERR_D1_UNAVAILABLE` with `Retry-After`. A client
that lists and then acknowledges may meet both bounds in a row, so its worst
wait before either answer arrives is two bounds (and a listing whose box read
answers slowly before its row read stalls is two reads in series, up to
12,300 ms).

The mailbox's class (0.8.1, R2 of the relay mailbox). The deploy carries the
Durable Object migration `v5`, `new_sqlite_classes = ["MessageHubSql"]`, and
the binding `MESSAGE_HUB_SQL`; both are in the template and ship with the
deploy, no command before it. A class lifecycle change refuses `wrangler
rollback` across it, so the rollback of 0.8.1 is forward only: a deploy that
keeps `v5` and the class exported. Two operator vars, neither set in the
template:

- `HUB_STORE` names the hub store: `kv` (the default when unset) keeps every
  path of 0.8.0 (hub ids to `MESSAGE_HUB`, sends, listings and acknowledgments
  through D1) and no request reaches `MessageHubSql`; `sql` sends hub ids to
  `MESSAGE_HUB_SQL`, stores each unpaid send in the recipient hub's mailbox
  (bounded at 10,000 unacknowledged rows and 1 GiB per identity, past which a
  send answers 429 `ERR_INBOX_QUOTA_EXCEEDED`), and archives each change to D1
  through `relay-archive`; `kv-drain`, the rollback of `sql`, routes as `kv`
  and also lists and acknowledges the rows each identity's `MessageHubSql`
  still holds. Any other value refuses every request with 500
  `ERR_HUB_STORE_INVALID` naming the var. A change of the var is a new
  version, not a class change, so `wrangler rollback` between two versions
  that both carry `v5` stays allowed. A deploy restarts every hub and
  disconnects every socket.
- `BOXES_OFF` is a comma-separated list of box names whose sends are refused
  403 `ERR_BOX_OFF` ("box <name> is off") before the send budget and before
  any store, on HTTP, on `/push` and on the socket; listings and
  acknowledgments of those boxes are served. Unset or empty, no box is off.

The code also reads names the template does not set: the `BROADCAST_TOKEN`
secret (the bearer of `/push`, `/broadcast` and `/session/attest`), the
`BROADCAST_REGISTRY` Durable Object (the `/broadcast` subscriber registry),
`ARC_URL` and `ARC_API_KEY` (the broadcaster a verified payment is announced
to), and `RETAIN_BOX_PREFIXES` (the transcript-retained box class). A deployment
that uses those features declares them itself.

The ICE credentials of a WebRTC hand are off until `TURN_CREDENTIALS = "on"`.
The routes need the Cloudflare Realtime TURN key's id in `TURN_KEY_ID` (the
operator's configuration, never the template) and its API token as a secret,
beside `SERVER_PRIVATE_KEY`'s:

```sh
wrangler secret put SERVER_PRIVATE_KEY
wrangler secret put TURN_KEY_API_TOKEN
```

`POST /turn-credentials` (an empty body or `{}`) answers `{iceServers,
expiresAt}` for the authenticated identity, `expiresAt` in milliseconds since
the epoch, counted from the start of the request to Cloudflare. A mint is
charged, before Cloudflare is asked, to the hourly budgets in `wrangler.toml`
(the identity, the source group from `CF-Connecting-IP`, the IPv6 /48, the
Worker), all or none; a spent budget is 429 `ERR_TURN_BUDGET` naming it, and a
Cloudflare failure is 502 `ERR_TURN_PROVIDER` with the charge standing.
`POST /turn-credentials/revoke` `{"username"}` revokes a username its caller
minted; any other is 404. Apply migration 0010 before deploying.

For bytes at rest, bind `BEEF_BLOBS`, configure presigning privately and retain
the lifecycle policy for `door-state/`. Inline payments can be spooled to R2;
large fee internalizations are deferred through `fee_internalize`. The wallet
service must be able to read the referenced bucket and verify recipient
metadata. Without an R2 binding, the inline door must finish in one request.
Retry pending reads and unavailable headers; do not interpret a work decline
as proof of invalidity. Cloudflare's request-body limit still applies before
an inline request reaches the Worker.

An unverifiable WebSocket General closes the socket with code 1008 and reason
`authentication failed; reconnect`. The client must reconnect, re-handshake on a
fresh session and rejoin its rooms.

The source for these contracts is [src/beef_door.rs](src/beef_door.rs),
[src/payments.rs](src/payments.rs) and [src/routes/send_message.rs](src/routes/send_message.rs).
Licensed under [MIT](LICENSE).
