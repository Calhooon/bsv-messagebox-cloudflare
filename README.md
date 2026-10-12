# bsv-messagebox-cloudflare

A BSV messaging relay on Cloudflare Workers: BRC-31 authentication, delivery
permissions, optional paid delivery, D1 message storage, KV sessions and raw
WebSockets through a hibernatable Durable Object. The public repository is a
sanitized release mirror; development belongs on branches of the canonical
repository, and the maintainer cuts the mirror.

## Version and dependencies

The relay is **0.4.5**, with **bsv-rs =0.4.5** and
**bsv-middleware-cloudflare =0.5.1** in [Cargo.toml](Cargo.toml).
The bsv-middleware-rs dependency is the compatible `0.4.1` requirement, not an
exact pin. [CHANGELOG.md](CHANGELOG.md) is the record of changes.

## Messages and payment words

HTTP send, list and acknowledge routes live in [src/lib.rs](src/lib.rs);
HTTP and WebSocket sends share [src/routes/send_message.rs](src/routes/send_message.rs).
The WebSocket transport is raw WebSocket, so a Socket.IO client needs an adapter.
The API description is [src/api_docs.rs](src/api_docs.rs).

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

[wrangler.toml](wrangler.toml) sets `[limits] cpu_ms = 43000` and
`work_units = 10000000`. The latter is compiled by [build.rs](build.rs) into a
per-input budget; changing it requires a rebuild. bsv-rs reserves reached
opcodes and hash bytes before doing that work. The work refusal carries
`resource`, `input`, `budget`, `workSpent`, `attempted`, `offset` and `txid`.
Every resumed reader receives the budget again; the cursor does not store it.
There is no resume within a script and this is not a wall-clock guarantee.

## Build and gate

```sh
cargo build --target wasm32-unknown-unknown --lib
cargo fmt --all -- --check
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs host tests, formatting,
host and wasm clippy, and the release wasm library build on every PR and main
push. The full deployment artifact also requires worker-build compatible with
the Worker SDK in the manifest. The payment reader's host witnesses are in
[src/beef_door.rs](src/beef_door.rs); integration suites are in [tests](tests).
Live paid tests require a separately authorized environment.

## Deploy and operate a charging tenant

Use the public release tag `v0.4.5`, provision the bindings described in
[wrangler.toml](wrangler.toml), apply [migrations](migrations) in order, build the
Worker and deploy with an operator-owned configuration. Carry the CPU limit
into that configuration; the work limit comes from the build's source config.
Keep the payment door closed until the release is reviewed for that tenant and
the header service is bound and answering. A charging tenant needs a working
`HEADER_SERVICE` binding or `HEADER_SERVICE_URL`, and a wallet storage service
for fee internalization; a missing header service fails closed.

For bytes at rest, bind `BEEF_BLOBS`, configure presigning privately and retain
the lifecycle policy for `door-state/`. Inline payments can be spooled to R2;
large fee internalizations are deferred through `fee_internalize`. The wallet
service must be able to read the referenced bucket and verify recipient
metadata. Without an R2 binding, the inline door must finish in one request.
Retry pending reads and unavailable headers; do not interpret a work decline
as proof of invalidity. Cloudflare's request-body limit still applies before
an inline request reaches the Worker.

The source for these contracts is [src/beef_door.rs](src/beef_door.rs),
[src/payments.rs](src/payments.rs) and [src/routes/send_message.rs](src/routes/send_message.rs).
Licensed under [MIT](LICENSE).

### 0.4.6 transport deploy note for LOW

An unverifiable websocket General closes the socket with code 1008 and reason
`authentication failed; reconnect`. The client must reconnect, re-handshake on a
fresh session and rejoin its rooms. A client without reconnect now sees closes it
previously did not see. Polling auth synchronously reaches the sid Durable Object;
include its cold-start latency in the transport lens.

0.4.6 is released on bsv-rs `=0.4.5` (the 0.5.0 re-lock follows the middleware crates' own 0.5.0 releases). LOW takes the mirror's tag `v0.4.6`, runs its lens, then its beta. Keep the existing header binding, migrations, payment-door configuration and object lifecycle requirements.
