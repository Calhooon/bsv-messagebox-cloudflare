> **Public release mirror.** This repository receives tagged releases of a private canonical repository (every Cloudflare resource identifier is scrubbed; deployment configs are placeholders). Issues and PRs are welcome here; development happens upstream and lands as the next release.

# bsv-messagebox-cloudflare

A BSV messaging relay on Cloudflare Workers: BRC-31 authentication, delivery
permissions, optional paid delivery, D1 message storage, KV sessions, raw
WebSockets through a hibernatable Durable Object, and a Socket.IO transport for
unmodified `@bsv/authsocket-client` and `@bsv/message-box-client`. The public
repository is a sanitized release mirror; development belongs on branches of the
canonical repository, and the maintainer cuts the mirror.

## Version and dependencies

The relay is **0.6.2**, published on crates.io as `bsv-messagebox-cloudflare`
(the library keeps its identifier `rust_message_box`). The release of record is
the tag `v0.6.2`. [Cargo.toml](Cargo.toml) pins **bsv-rs =0.7.0**,
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

The code also reads names the template does not set: the `BROADCAST_TOKEN`
secret (the bearer of `/push`, `/broadcast` and `/session/attest`), the
`BROADCAST_REGISTRY` Durable Object (the `/broadcast` subscriber registry),
`ARC_URL` and `ARC_API_KEY` (the broadcaster a verified payment is announced
to), and `RETAIN_BOX_PREFIXES` (the transcript-retained box class). A deployment
that uses those features declares them itself.

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
