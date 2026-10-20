# Changelog

All notable changes to the relay. Public releases are cut from this repository with
`scripts/release-public.sh` (Cloudflare resource identifiers scrubbed) into
`Calhooon/bsv-messagebox-cloudflare`.

## [0.6.1] - 2026-10-20

### A send is answered once durable; the push follows (bsv-low #787, #786)

- **The fact (loop 38, beta, 2026-10-20 19:15Z to 19:25Z, unsampled).** `/sendMessage` route_ms median 2,034 ms, of which the D1 steps are about 130 ms (`send.read_ctx` 47, `send.insert_message` 79); the rest was the live push to the recipient's hub (`broadcast.fanout.ok` rtt median 1,481 ms, 36 percent of fan-outs at the 2,000 ms `PUSH_FANOUT_TIMEOUT_MS`), a hub flooded by `broadcast-low-pots` pushes. The sender's answer waited on a queue it has no business in.
- **The order now, the reference's.** `process_send` returns a `Sent { outcome, after }`: the rows are stored (and the send budget charged) as before, and each stored row's push to its recipient's hub is recorded in `AfterAnswer` instead of awaited in the insert loop. HTTP `/sendMessage` and `/push` form the answer and hand the pushes to `ctx.wait_until` (`answer_then_defer`); the WS leg emits the `sendMessageAck` to the sender and then hands them to the hub's `state.wait_until` (`emit_then_defer`, raw `/ws` and the socket.io bridge alike). message-box-server stores, answers (`sendMessageAck-<room>`), and then emits to the recipient's sockets without awaiting a delivery ack.
- **What the answer means.** Durable, not delivered: the row is in D1; delivery is the recipient's socket push or its next `listMessages`. The answer body is unchanged.
- **Every bound kept.** Each push is still raced against the 2 s `PUSH_FANOUT_TIMEOUT_MS` (`push_one`, the same `broadcast.fanout.start/ok/err/timeout` lines); a push that times out after the answer is logged and backfilled by `listMessages`. A send that stops part way (a duplicate, a D1 fault) still runs the pushes of the rows stored before it, as before. The duplicate rule (#249: `Duplicate->sendMessageAck`), the first-party box refusal (D9, now `validate_ws_send` on the live leg, before any write), the session lane (D10) and the send budget are unchanged. FCM for the `notifications` box now also runs after the answer (below, R1 M3).
- **Trace.** `TRACE_LAT send.answered ms=<from request start>` (`path=/sendMessage`, `path=/push`, `leg=ws`) beside `TRACE_LAT req`, so the next loop's window shows the answer time apart from the push time.
- **Pins** (`decouple_787_tests` in `routes/send_message.rs` and `message_hub.rs`; RED base: this branch's parent, the mirror's v0.6.0 417d3bd, where `process_send`'s body awaits `push_to_recipient_sockets(` in the insert loop (`pin_a_source_the_write_path_awaits_no_push` and `pin_c_source_the_duplicate_return_waits_on_no_push` fail at that assertion) and `Sent`/`AfterAnswer`/`answer_then_defer`, `emit_then_defer` and `validate_ws_send` do not exist (`pin_a_a_send_answers_before_its_push_and_the_timeout_is_logged_after`, `pin_c_a_duplicate_answers_unchanged_and_the_owed_pushes_still_run`, `pin_b_the_ack_precedes_the_recipients_delivery_when_the_push_is_slow`, `pin_d_the_live_leg_refuses_the_first_party_boxes_before_any_write` do not compile there). `origin/main` 6607978 is not this branch's ancestor: main carries a4bda26/551cb54 that v0.6.0 lacks and v0.6.0 carries c11caf4/417d3bd that main lacks; the release decides which line takes the commit): (a) a hub that never answers: the HTTP answer is formed before the hub is touched, the `broadcast.fanout.timeout ... after_ms=2000` line follows it; (b) a slow hub: the `sendMessageAck` is emitted before the recipient's `sendMessage` delivery; (c) a duplicate still answers `ERR_DUPLICATE_MESSAGE` / acks, and the owed pushes still run; (d) the first-party boxes are refused on the live leg before any write. The source pins (`pin_a_source_*`, `pin_b_source_*`, `pin_c_source_*`, `pin_d_source_*`) read the code's text and are rename-defeatable; they stand beside the write-path pins below. No publish, tag, mirror cut or deploy in this lane.

### The R1 review folded (M28A-DECOUPLE-R1-2026-10-20: 4 MEDIUM, 5 LOW)

- **M1, the write path pinned for real.** `store_send` runs over a `SendStore` seam (`read_send_context`, `charge`, `settle`, `get_or_create_message_box`, `insert_message`, `forget_unnamed`, its clock and log; `WorkerStore` is D1, the budget and the payment through `Env`), and takes no hub: no push can run inside it. `decouple_r1_tests` drives a real send over a stub store: `m1_a_partial_send_answers_first_and_keeps_the_earlier_rows_push` (two recipients, the second insert `Ok(false)`: the answer is `ERR_DUPLICATE_MESSAGE`, `after` holds exactly the first row's push, a hub that never answers is untouched at the answer and its timeout follows it) and `m1_every_stored_row_leaves_its_push_and_nothing_else_does` (a D1 fault on the third row keeps the first two; a full send owes one push per row in insert order; a lone duplicate owes nothing).
- **M2, the pushes of one send joined.** `fan_out` runs one chain per recipient hub and joins the chains (`futures_util::future::join_all`; `futures-util` gains `alloc`), under the one `wait_until`, each push still raced against its 2 s bound: N wedged hubs hold the deferred work 2 s, not 2N s. The run opens with `TRACE_PHD broadcast.fanout.deferred n=<N> hubs=<H>` and closes with `TRACE_PHD broadcast.fanout.done n=<N> hubs=<H> ms=<..>`: a run cut by the Worker's post-response budget leaves the first line without the second, and each push it cut a `broadcast.fanout.start` without its ok/err/timeout. Pin `m2_the_pushes_of_one_send_are_joined_and_bracketed` (two wedged hubs both time out at virtual t=2000, not 4000).
- **M3, FCM after the answer.** The `notifications` box's FCM is recorded as an `FcmPush` in `AfterAnswer` and runs in the same `wait_until` beside the hub pushes (`notify_fcm`), each raced against `FCM_DEFERRED_TIMEOUT_MS` (10 s; in the request it had no bound of its own, the client's timeout was its bound), logging `fcm.deferred.err` / `fcm.deferred.timeout`. "Answered once durable" now holds for every box. Pin `m3_the_notifications_box_fcm_is_owed_after_the_answer`.
- **M4, the RED base** is named above: 417d3bd, the pins by name.
- **L1, a non-2xx hub reply is an error.** `hub_reply`: only a 2xx from `/internal/push` is `broadcast.fanout.ok`; the hub's 400 or a 5xx is `broadcast.fanout.err ... err=hub answered <status>`. Pin `l1_a_non_2xx_hub_reply_is_an_error`.
- **L2, concurrent pushes from one sender.** Within one send, two rows to one recipient stay chained in insert order (`fan_out`; pin `m2_...`, virtual t=4000 for the second). Across sends, A's push and B's may now be in flight together; they reach the recipient's one hub, whose input gates hold B's `/internal/push` while A's storage awaits complete, so emit order is arrival order, and arrival order is send order (A's fetch leaves at `wait_until`, one client round trip before B exists). Not fixed further, by design: no relay check depends on a push having run (the duplicate rule is `insert_message`'s), the SDK's `sendMessage-<room>` has no ordering contract, and reordering was already reachable before 0.6.1 by the abandoned-push path.
- **L3, the bound pinned as a timing over a stub clock.** The pins' `StubHub` runs on a virtual clock (a timer asked for `ms` moves it to its deadline when it fires); pin (a) asserts the race asked for `PUSH_FANOUT_TIMEOUT_MS` and the timeout line reads `t=2000`. It is an ordering pin over virtual time; wall time is not shown elapsing.
- **L4, one trace origin per kind.** `t_req_start` is taken at `handle`'s entry, so `send.answered path=/push` measures from the request's start like `path=/sendMessage` (both now `from=req`); the live leg's `send.answered leg=ws from=frame` measures from the frame's arrival, a frame having no request. Comparable within a kind, not across.
- **L5, a retried zero-change insert is read back.** `insert_message`: after a retry, `changes == 0` (`insert_count_verdict` → `ReadBack`) reads the row by its message id (`message_identity`) and is stored only when its sender, recipient and body are this insert's (`retried_row_is_ours`); another's row, or none, is a duplicate. Before, a retried 0 was taken as stored unseen, so a send racing a genuine duplicate across a retry was answered durable on a row not its own. Pins `insert_idempotency_under_retry`, `l5_a_retried_zero_is_stored_only_on_our_own_row`, `insert_message_stall_then_dropped_write_landed_is_success`.

## [0.6.0] - 2026-10-19

### The middleware 0.7.0 and core 0.4.0 on bsv-rs 0.7.0 (#105's last red here)

- **The pins.** bsv-rs `=0.7.0` (was `=0.6.0`), bsv-middleware-cloudflare `=0.7.0` (was `=0.6.2`), bsv-middleware-core `=0.4.0` (was `=0.3.2`), bsv-middleware-rs `0.6.1` (was `0.5.0`; 0.6.x asks bsv-rs ^0.7.0). One bsv-rs in the lock. bsv-rs types sit in the relay's public API, so the move is a minor release.
- **No direct sha2.** `beef_door::inline_spool_key` hashes the inline payment a chunk at a time with bsv-rs 0.6.1's incremental `primitives::hash::Sha256` (the one hash 0.6.0 could not serve); `tests/lone_mined_subject.rs` checks its rows with `bsv_rs::primitives::{sha256, sha256d}`. The middleware 0.7.0 and core 0.4.0 hash and MAC through bsv-rs too, so `cargo tree -i sha2 --depth 1` names bsv-rs, k256 and p256, `-i hmac` names bsv-rs, pbkdf2 and rfc6979, and `cargo deny check` is green against the unchanged `deny.toml` (no wrapper added, no ignore).
- **The signing digest (bsv-rs 0.7.0 moved `SigningContext::compute_sighash` to the node's dispatcher).** The Worker signs no transaction: its secp256k1 signatures are BRC-103's `create_signature` with `data`, ECDSA over one SHA-256 of the signing data by the BRC-42 child key, which 0.7.0 does not change. Pinned by `engineio::auth::signing_digest_tests::the_worker_signs_one_sha256_of_the_data_with_the_derived_key` (the digest, the RFC 6979 signature's bytes, verified by the derived public key over the single hash and refused over the double). The FCM RS256 signer is ring and unaffected.
- **The middleware's M14 (a derivation prefix binds its first txid).** The relay's door does not call the middleware's `process_payment_with_storage` and keeps no `payment_claims` table, so `PAYMENT_CLAIMS_MIGRATION` does not apply to its D1 and no migration ships here. The adapter's migration line for the message box (claim the prefix through `D1PrefixStore` / `claim_payment_prefix` in `payments::process_payment`, after verification and before internalize) is not taken in this release: it adds a table and a migration, a lane of its own.

## [0.5.6] - 2026-10-18

### The output check is given the subject's BUMP (the six `lone` cells of NL-8, W19)

- **The cause.** The door reads the BEEF's structure itself and hands the middleware's output check (`verify_payment_output_only`) only the subject. Through 0.5.5 `output_word` wrapped the subject's raw bytes as a BEEF of that one transaction with no BUMP, `[0x02, 0x00, 0xBE, 0xEF, 0, 1, 0]` then the subject (format byte 0, no BUMP index). bsv-rs 0.6.0's frame refuses a transaction with no BUMP index whose single input is the null outpoint (`UnprovenCoinbase`, `beef_stream.rs:394-402`), so a subject that is itself mined and alone in its BEEF, a proven coinbase (`lone.bin`, `lone_atomic.bin` of NL-8), was refused `Unverifiable(InvalidBeef { offset: 7, kind: UnprovenCoinbase })` at every entry: an offset of bytes the payer never sent, for a transaction the payer sent proven. The Lean row, bsv-rs 0.7.0 and the middleware 0.5.0 on the whole body accept it (bsv-stack-lean `docs/p0/doors-and-messaging-reading.md` section 3).
- **The change (`src/beef_door.rs`).** `tip_of` reads, beside the subject's txid and offset, the place of the BUMP that proves it, from the cursor's own index (its proven txids, each with the earliest BUMP that carries it, `Cursor::to_binary` `:2682-2694` at 0.6.0). A mined subject is handed over with that BUMP: `[0x02, 0x00, 0xBE, 0xEF, 1]`, the BUMP's bytes as the payer sent them, `[1, 1, 0]` (one transaction, format 1, BUMP index 0), then the subject. The BUMP is read back by `bump_bytes`: the frame again from the start with `BeefDecoder`, one BUMP in hand, to that BUMP, then its bytes fetched by its offset and its length on the wire; one read back otherwise is the door's error, never a word. A subject with unmined ancestry is handed over as before. The roots are asked as before, of the cursor's index: the BUMP in the wrapper decides no root.
- **The cost, said plainly.** A mined subject's BUMP costs one more read of the BEEF's head, from the start through that BUMP, in the request that judges the output (inline: bytes in hand; at rest: the object opened at 0 and at the BUMP's offset). That read is not resumed across requests; the BUMPs before the subject's are decoded and dropped one at a time, never held together.
- **Pins (RED on 0.5.5 `afbbeca` with the witness's observation, GREEN on the fix).** `tests/lone_mined_subject.rs`: `lone` and `lone_atomic` through `verify_inline` (hex), `verify_at_rest` (40-byte chunks, one request) and the same resumed one element per request, each `Verified { satoshis: 1 }` naming the coinbase; and the same six with a header carrying another root, each `RootMismatch` at 800005 (the BUMP handed over is no pass). The rows' bytes are the stack's (bsv-stack-lean `2745a8c`, `corpus/beef-of-any-size/bytes/`), copied under `tests/fixtures/` with their sha256 checked by the tests (`lone.bin` `38656f4c…bb50`, `lone_atomic.bin` `4fc97f61…e3bc`). The 22 BRC-29 vectors and the door witnesses are unchanged.

## [0.5.5] - 2026-10-18

### Publishable to crates.io from the tag (no change in the Worker)

- **The crate is `bsv-messagebox-cloudflare`** on crates.io (was the unpublished `rust-message-box`); `[lib] name = "rust_message_box"` keeps the library's identifier, so no `use` path moves. The manifest gains `description`, `repository`, `readme`, keywords, categories and an `include` list: the sources, `build.rs`, the migrations, `wrangler.toml` (build.rs reads its `[limits] work_units`), the two JSON fixtures the library's unit tests read, the README, the licence and this changelog.
- **`.github/workflows/release.yml`** publishes on a `v*` tag push through crates.io trusted publishing (no token stored): the tag must equal the manifest's version and sit on `main`, the `ci.yml` gate runs (now callable through `workflow_call`), then a host `cargo publish --dry-run` and `cargo publish`.
- **The README is refreshed to the code at this tag**: the version and pins, the router's routes, the Socket.IO transport, the send budget, the gate, the names the code reads that the template does not set, and a "Releases" section.

## [0.5.4] - 2026-10-15

### Bounded, concurrent `/broadcast` fan-out (bsv-low #668)

- **The fan-out is bounded-concurrent with a per-push timeout.** `fan_out_broadcast` pushed into each subscriber's hub DO SEQUENTIALLY (`for identity { stub.fetch_with_request(preq).await }`), with NO per-push bound: one cold or relocating `MESSAGE_HUB` DO stalled every subscriber behind it, and the whole room took N round-trips in series (measured 11 to 15 s p50 under the fleet, the dominant term in bsv-low #668's late pots-room push). Now the pushes run through `fan_out_with`: at most `BROADCAST_FANOUT_CONCURRENCY` (32) in flight at once (the 16 registry reads' own pattern), each push bounded by `hub_forward::FORWARD_OP_TIMEOUT_MS` (the 3 s the forward paths already use), and the whole fan-out bounded by `BROADCAST_FANOUT_WALL_BUDGET_MS` (15 s, below the app layer's 20 s announce wall). The room now delivers in about one hub round-trip for up to 32 subscribers (`BROADCAST_FANOUT_CONCURRENCY`); a larger room is `ceil(N/32)` windows, and a cold DO in an early window adds up to one per-push bound (3 s) to each later window. A cold DO stalls at most its own window, never the subscribers behind it.
- **A timed-out push is retried once.** A push the per-push bound dropped (`TimedOut`) is retried a single time within the same request when the wall budget still has room (a fresh subrequest typically routes to a now-warm DO); still-timed-out and transport-failed pushes are reported, never retried past the one.
- **The `/broadcast` answer carries per-subscriber outcomes.** `{subscribers, pushed, delivered, noSocket, timedOut, failed, skipped}` (`pushed` stays the delivered count, the pre-#668 field) so the app layer can tell a reached socket from a missed one and a cold DO from a transport fault.
- Pins (host-drivable; the real hub fetch is wasm-only): a slow push does not stall its window (`fanout_668_tests`), a timed-out push is retried once within budget, the budget skips the subscribers past the wall, the tally counts each outcome, and the source is bounded-concurrent (the sequential await-each-push loop is gone). `hub_forward::is_op_timeout` + `OP_TIMEOUT_MARKER` tell a per-op timeout from the op's own transport error. No publish, tag, mirror cut or deploy in this lane.

## [0.5.3] - 2026-10-15

### Presence: a re-join snapshot answers `null` unless the departure was CONFIRMED (LOW #85)

- **The rule.** A presence snapshot answers `false` for the peer ONLY when the relay has CONFIRMED a close (the departure debounce fired with the room STILL empty); a live, re-joining, or not-yet-confirmed-gone peer answers `null` (no signal), never a fabricated `false`.
- **The root red.** LOW loop 29 (2026-10-15T10:40:36Z, beta relay 0.4.6 `b60d27e4`), pair 19 `happyPathHumanCadence` (#258): seat A re-listened during a human-paced hand (a ~24 s server-ping gap), and each join-time presence read answered `absent` for a live, slow-approving seat B whose socket was up and sending. The exact state: an EMPTY room whose departure debounce alarm was LOST (overdue, never consumed) while a new sid of B re-joined — `presence_answer` fell to `_ => Some(false)` and painted a departure on a healthy peer (bsv-low `docs/audit/RC-L29-PEER-AWAY-2026-10-15.md`, `Calgooon/rust-message-box#85`).
- **The change (code only, `src/message_hub.rs`).** `presence_answer` gains a confirmed-gone argument: empty + `confirmed_gone == Absent` → `Some(false)`; every other empty state (an overdue/stranded pending, a never-confirmed empty room) → `None`. The confirmed-gone marker (`confirmed_gone:<room>`, a NEW key reusing the `ToldPresence` value type — NOT `presence_told:`, which is the owner's view of the peer) is written `Absent` by the one place a close is confirmed (`run_departure_debounce_alarm`, the trailing re-check still-empty) and cleared (`Present`) on a join to the room. The join-time snapshot NO LONGER writes a told-state (push-driven only; a self-read on a re-listen must never record the peer absent and dedupe the real push). The presence path pulls an OVERDUE pending's confirming re-check in directly (`handle_presence` → `ensure_alarm_no_later_than`), a belt beside the `fetch`-level 2 s-guarded re-arm net.
- **A genuinely killed peer is still caught:** its debounce fires still-empty → `Absent` → a survivor joining later reads `false` and the `peerLeft` push still fires. The killed-peer path is unchanged; only the flap/churn path moves (toward `null`). Strictly from a permanent false banner to a self-healing `null` the next live frame or confirmed departure resolves.
- **The register row (bsv-low's D4, "Relay join hello").** The join answer already carries more than the reference's `joinedRoom` (the delivery-shaped hello AND the counterparty's presence snapshot — OUR addition, the same class as D4). This refines that addition's semantics (null vs false); it introduces no new divergence from the reference's wire formats (presence and the whole join-answer surface are the reference's explicitly pluggable extension points). `present` is already `Option<bool>` on the wire; this changes only WHEN `null` vs `false` is returned. A reference client ignores the snapshot entirely.
- **Divergences from the design doc, stated (code's truth).** (1) The confirmed-gone marker uses a DISTINCT key, not `presence_told:`: in a hub `presence_told:<room>` is the owner's view of the PEER (load-bearing for parked-replay and push dedupe), while `handle_presence` answers about this hub's OWN room — opposite directions, so sharing the key would corrupt the dedupe. (2) The §3c re-arm belt is largely already present: `fetch` runs `rearm_pending_departures_net` on every hub event including the presence GET (since 0.3.17, 2 s guarded); the added `handle_presence` call is a targeted, unguarded pull-in for the narrow guard-skip window. (3) No DO-storage TTL exists in this crate, so the marker follows the same cleared-on-rejoin / never-swept lifecycle as `presence_told:`/`lastseen:`.
- **The six questions (owner's bar).** (1) No fabricated `false`: `false` requires `Absent`. (2) A killed peer is still detected: the confirm path is unchanged. (3) No self-healing→permanent trade: a permanent false banner becomes a self-healing `null`. (4) State keys on a socket close, never a timer or a name: `Absent` is written only by a confirmed close; `occupied` reads live membership. (5) A reference client still works: it ignores the snapshot. (6) Bounded and recovering under a lost alarm: an overdue pending → `null` + the belt pulls the re-check in.
- **Pins (RED on `419bf18`/0.4.7, GREEN on the fix).** `presence_answer_is_null_unless_the_departure_was_confirmed` (the design's table line for line: overdue-pending and no-pending both answered `Some(false)` before, now `None`; a confirmed `Absent` is the only `false`). `handle_presence_rearms_an_overdue_departure_for_this_room` (source pin: the targeted re-arm call did not exist in `handle_presence`). `a_confirmed_close_reads_false_but_a_suppressed_flap_reads_null` and `a_presence_read_rearms_a_lost_departure_alarm` (through the `PresenceSim` DO pipeline on the real pure cores). The prior loop-13 pin that asserted the leak (`Some(false)` on an overdue/settled empty room) is retired into the new one.
- **Deploy shape (D19).** `wrangler.low.toml` UNCHANGED — no new var, service binding, D1 migration or KV; the payment-door config is untouched (presence does not read it). `cargo test` whole repo green (lib 448 passed, 1 ignored), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`, release wasm32 library build and `worker-build --release` all clean. The lens, the beta deploy and the loop-29 live re-run are the captain's. No publish, tag, mirror cut or deploy in this lane.

## [0.5.2] - 2026-10-15

- The parser reads the PEM header and footer from the crate's constants (0.5.1 left them used by the tests alone, a dead-code error under clippy's -D warnings on the library target).

## [0.5.1] - 2026-10-15

- The PEM header and footer of the FCM signer assembled from parts in code (no change in behaviour): the public mirror's scan and the stack's secret-shape leg read a whole header literal as a key shape.

## [0.5.0] - 2026-10-15

bsv-rs types sit in the relay's public API (the door's `Verdict`, `Cursor`, `Hash32`, the middleware's words), so the move is a minor release.

- **The pins.** bsv-rs `=0.6.0` (was `=0.4.5`), bsv-middleware-cloudflare `=0.6.2` (was `=0.5.1`) with bsv-middleware-core `=0.3.2` pinned beside it (was 0.2.1 through the BRC-31 layer), bsv-middleware-rs 0.5.0 (was 0.4.1; 0.4.x asks bsv-rs ^0.4.1). One bsv-rs in the lock. The version guard moves with them.
- **The door on bsv-rs 0.5.0 and 0.6.0.** A mining check with no tip (`Verdict::Unverifiable`, finality or coinbase maturity) is the middleware's server-side `MiningContextUnavailable`, never a refusal of the payer's bytes. The cursor's magic is `BSC2` (`tip_of` reads it; the layout up to `last_raw` is unchanged); a door state saved under 0.4.x holds a `BSC1` cursor, reads as no state, and its reading starts over from the object's start. Non-canonical varints are now `BadVarint` (0.6.0): the memory test's fixture writes canonical lengths. The relay supplies no mining tip, so a payment with a nonzero lock time and a non-final sequence is declined as unavailable (5xx), not judged.
- **The hashes from bsv-rs.** sha256, double sha256 and HMAC-SHA256 come from `bsv_rs::primitives` (`sha256`, `sha256d`, `sha256_hmac`): the R2 presigner, the session MACs, the lane's body digest, the minted `messageId`, the door's subject check and the tests' txids. The direct `hmac` is gone. A known-answer test pins the presigner's signing key to AWS's published example; the cross-repo session MAC vectors re-derive unchanged. One site stays on the direct `sha2`: `inline_spool_key` hashes the inline payment a chunk at a time, and bsv-rs exposes one-shot hashes only.
- **The FCM signer on ring.** The service-account JWT (RS256) is signed by ring 0.17 (`RsaKeyPair::from_pkcs8`, `RSA_PKCS1_SHA256`) from the same `FIREBASE_SERVICE_ACCOUNT_JSON` secret in the same PKCS#8 PEM form. `rsa`, `pkcs8` and the dev `rand` leave the manifest; `rsa` leaves the lock, and with it RUSTSEC-2023-0071. The tests generate their key in the test, verify the signature with ring and, apart from ring, against RFC 8017's padding by modular exponentiation, and pin the signing input's bytes. ring compiles C for wasm32: a wasm32 build needs a clang with the WebAssembly target (`CC_wasm32_unknown_unknown`; Apple's clang has none).
- **The deny file.** The stack's template, byte for byte (sha256 `a2495808...d60570c`, bsv-stack-lean `2f1b513`). `cargo deny check`: advisories, licenses and sources green; bans red on `sha2` (the relay's `inline_spool_key`, bsv-middleware-cloudflare 0.6.2, bsv-middleware-core 0.3.2) and `hmac` (bsv-middleware-core 0.3.2). No allowance is added here.

## [0.4.7] - 2026-10-15

- **The load generator on the registry.** `tests/load_gen` pins bsv-rs `=0.6.0` from crates.io (was a path dependency on one machine's checkout) with its own `Cargo.lock`, and takes the BRC-104 length prefix from `bsv_rs::primitives::to_var_int`; the hand-rolled `write_varint` is deleted. Two tests hold the bytes at every varint width and for one request frame. The generator stays its own workspace and is not in the workflow; the relay crate keeps bsv-rs `=0.4.5` (its 0.5.0 re-lock follows the agents' middleware crates).
- **The deny file.** `deny.toml` is the stack's template, byte for byte (sha256 `ba065ed0...8ed5083`, bsv-stack-lean `stack.toml`). `cargo deny check` is red on the relay crate until its own migration: the relay's direct `sha2` and `hmac`, those of bsv-middleware-cloudflare 0.5.1 and bsv-middleware-core 0.2.1, and `rsa` 0.9.10 (RUSTSEC-2023-0071, no patched release; the FCM JWT signer). No allowance is added here. The workflow runs no deny job.

## 0.4.6 (2026-10-12)

- Websocket auth failures close with code 1008 and reason `authentication failed; reconnect`, using the ping-timeout teardown. A client can reconnect and re-handshake instead of waiting on a socket that drops every General.
- The Worker completes the polling handshake, then synchronously hands its verified state to the sid Durable Object before publishing the InitialResponse. That object owns completed rounds, the upgrade state and the attachment snapshot. KV remains a polling cache and a legacy upgrade fallback. This restores a DO hop on polling auth; cold-start latency needs a runtime lens.
- Retain the last 16 completed rounds plus the selected session. A General selects by nonce and then verifies its signature; a later InitialRequest cannot orphan that session. Round history lives in DO storage, outside the 2 KB websocket attachment. Delayed warm-up cannot reset a live session.
- The pin stays bsv-rs `=0.4.5`: bsv-middleware-cloudflare 0.5.1 (core 0.2.1) and bsv-middleware-rs 0.4.1 require bsv-rs 0.4, so one SDK in the lock cannot be 0.5.0 until their 0.5.0-based releases exist; the relay re-locks with that wave, nothing in this release waits on it.

Transport pins are RED on the 0.4.5 sources and GREEN after. On bsv-rs 0.4.5, the final release suite passes 505 tests (four expected ignored), all 22 payment vectors match, and all 13 wide-door witnesses pass with measurements enabled. Formatting, host/wasm clippy, the release wasm library and Worker packaging pass. Runtime flap recovery and the 0.5.0 gate remain unverified.

LOW deploy note: an unverifiable General now closes its socket. Clients must reconnect, establish a fresh session and rejoin their rooms. A client without reconnect will see closes it previously did not see. Use the captain's mirror tag only after dependency alignment, the runtime transport lens and paying beta. No publish, tag, mirror cut or deployment in this lane.

## 0.4.5 (2026-10-11)

### R404-H1: a local work budget inside one paying input (bsv-stack-lean #75 B)

- **The pin.** bsv-rs `=0.4.5` from crates.io, one copy in the lock, was `=0.4.4`. bsv-middleware-cloudflare stays `=0.5.1`, bsv-middleware-core 0.2.1 and bsv-middleware-rs 0.4.1. No other dependency moved; `tests/load_gen` keeps its path dependency.
- **The door.** Every constructed reader receives `set_work_limit(Some(n))`, including one resumed from a decoded cursor. The local configuration is absent from the cursor. `Slices::work_units` configures the request's per-input budget; the Worker and inline reader use `[limits] work_units` in `wrangler.toml`, default **10,000,000**, compiled into the relay (rebuild after changing it). Work is reached opcode count plus bytes fed to hashes, reserved by bsv-rs before execution. The slice's input count (20,000), transaction-byte weight (10,000,000,000), 15 s clock and root lookup count are unchanged; they still pause and resume between inputs and elements. The work budget bounds one input.
- **The tenant's word.** `SpendRefusal::Resource` naming `Work` is **422 `ERR_PAYMENT_WORK`**, `resource: "Work"`, `kind: "Work"`, `input`, `budget`, `workSpent`, `attempted`, `offset`, `txid`. The word says the local evaluator declined and payment validity is undetermined. No root is asked, no verified subject is produced, the saved reading is cleared as for other script refusals, and the uploaded object stays. This is no validity verdict and no within-script resume. The exact same payment with enough local work retains its validity verdict.
- **LOW's witness, red then green.** `tests/hostile_wide_door.rs`: a fabricated source and BUMP, one input with 10,000 successful `DUP <pubkey> CHECKSIGVERIFY` checks over `ALL|FORKID|CHRONICLE` (the original digest), a correct BRC-29 output paying 100, and a zero-value data output padding the subject by 1 MB. One signature is duplicated. All coin and keys are phantom. The 1,360,324-byte body at 0.4.4 ran its input to the fabricated root, **47,922.481 ms** at rest, and answered root mismatch; the red assertion expected Work. At 0.4.5, the same body declined after **61.423 ms** at rest and **65.801 ms** inline: input 0, budget 10,000,000, work spent 9,521,012, attempted 10,881,153, no root asked. Forced resumes on both the upload and spooled inline paths also decline by Work and clear saved state. An exact-budget valid control is accepted; one unit less declines.
- **The default and CPU, re-measured.** The default 10,000,000 stops this witness well inside the 15 s slice. Native release, rustc 1.95.0, aarch64-apple-darwin, fixture construction/signing outside the timer: original-digest paying bodies with 1, 7, 9, 100 and 500 checks fill the budget to within one check's count, measured on inline and at-rest paths with three samples each. The widest byte shape has one check, padding 9,999,821, BEEF 10,000,177 bytes, exact work 10,000,000; the largest observed complete door time is **1,127.292 ms** inline (the widest at-rest sample 629.647 ms). Nine checks at padding 1,110,644 use 9,999,993 units. Exact-work controls are valid, one less declines. The whole-door timer conservatively includes structure, output, scripts and the mock root lookup. Using 0.4.4's measured original-digest wasm32-under-V8 factor **1.2**: 1,127.292 * 1.2 = 1,352.7504 ms; add the 15,000 ms slice, then half again: **24,529.1256 ms**; round upward to a second: 25000 for that single-input shape. The retained between-input witness also ran: the 12,000-input original-digest subject remained valid in 19,764 ms whole, two pending requests at inputs 5,655 and 11,306, its slowest sliced request **9,811 ms**, longer than the single-input control. Preserve the count and weight slices and cover that larger measured stretch too: (15,000 + 9,811 * 1.2) * 1.5 = **40,159.8 ms**; round upward to a second: **`[limits] cpu_ms = 43000`**, was 30000. Host load varies; these are observed wall times, not a universal conversion from work units to CPU or a Worker CPU guarantee. The factor was not re-measured and workerd was not run.

### Compatibility and gate

Callers constructing `Slices` add `work_units: work_units_per_input()` or their explicit local budget. No stored-data migration or new validity rule. `cargo test`: 501 passed, 0 failed, 4 ignored; 22 payment vectors exact; six ancestry witnesses and all deep witnesses unchanged in expectations and green. Host clippy over all targets and wasm32 clippy with warnings denied, formatting, wasm32 check, release wasm32 library build and `worker-build --release` are clean. The native calibration and the existing wide-body benchmarks were explicitly enabled in release mode: all 13 wide-door tests passed, none ignored.

### For the deploy

LOW binds `HEADER_SERVICE` only after its 0.4.5 lens passes, then exercises beta from the mirror's tag before D19. Carry `cpu_ms = 43000` to its deployment configuration; `work_units` is the relay's compiled knob in `wrangler.toml`. No new migration or cursor layout: existing 0005 through 0009 and the `door-state/` lifecycle rule still apply. Stored cursor resumes get the current budget again. Rolling back restores 0.4.4's unbounded single-input case; keep the header binding held if rolling back. No publish, tag, mirror cut or deploy was performed by this lane.

## 0.4.4 (2026-10-10)

### LOW's R400 lens on 0.4.0 and R403 delta on 0.4.3, item by item (bsv-low #591)
Every finding by LOW's label, with what moved and its witness. bsv-rs is `=0.4.4`: the spend linear in its inputs and a clock between inputs (bsv-low #591), which the door now reads through. Five migrations (0005 to 0009) are applied before the deploy, in order.

- **H1, the order: the fee before a script runs.** The door read every input's script before it read the output that pays the box, so a body carrying no satoshis cost the whole walk. Now the structure is read first (bsv-rs `StreamVerifier::structure_only`: no script, no root), the paying output is judged on the subject, and only a payment that pays is read again for its scripts, then its roots: inline and at rest alike. The state at rest carries the phase (`RMBD2`; a state saved by 0.4.3 starts over) and `ERR_PAYMENT_PENDING` names it (`phase`: `structure`, `scripts` or `roots`). Witness `tests/hostile_wide_door.rs` (a proven parent of 64,000 `OP_TRUE` outputs, a subject spending all of them, 3,264,185 bytes; release, on the lane's host): no sats is refused at the output word in 23 to 26 ms at rest and 40 ms inline, 0 elements read with scripts, no root asked (at 0.4.3's order: 13,109 ms, the walk, then the refusal); the same frame paying the price is accepted in 47 to 49 ms at rest and 71 to 73 ms inline, its scripts then its one root (12.8 s on bsv-rs 0.4.3's quadratic spend).
- **H1, the inline payment spooled before its scripts.** An inline payment's structure and output are read in the request; a payment that pays is spooled to `<sender>/inline-<sha256>.beef` (the relay its reader) and read from rest in slices, so the slice and the 503 resume cover it as they cover an upload; the same request again finds the same key and its saved cursor. Where no bucket is bound it is read in the request, the output still first. Witness: a 300-link inline payment paused at every element (602 pending answers) resumes to the verdict of one request, spooled once.
- **H1, the clock between inputs (bsv-rs 0.4.4).** The door reads through `StreamVerifier::step_until`: the request's slice is asked between two inputs of a transaction whose scripts run, as well as between two elements, so a wide subject pauses inside itself. The saved state is bsv-rs 0.4.4's paused cursor (the state before the transaction and the input reached); the next request runs the scripts from that input, never from the first, on the inline path (spooled) and the R2 path alike. `ERR_PAYMENT_PENDING` carries `input`. A Worker's clock moves only at I/O, and between two inputs there is none, so the slice also counts work: 20,000 inputs a request (`SCRIPT_INPUTS_PER_PASS`) and a weight of 10,000,000,000, each input weighing its transaction's bytes (`SCRIPT_WEIGHT_PER_PASS`), since a signature over the original digest (no FORKID, or the CHRONICLE bit) serializes the whole transaction and its cost grows with it. Witnesses (`tests/hostile_wide_door.rs`, a paid 20,000-input subject): a clock moving a millisecond a read with a slice of 5,000 pauses inside the subject at inputs 4,967, 9,954, 14,941 and 19,928 on both paths, the subject stepped once and the verdict that of one request; under a frozen clock 6,000 inputs a request pauses at 6,000, 12,000 and 18,000, and the time slice alone does not pause; a 300-input original-digest subject under a weight of 2,000,000 pauses every 46 inputs; a reading with no slice never pauses.
- **H1, the CPU explicit.** `[limits] cpu_ms = 30000` in `wrangler.toml`: the slice (15 s, wall time read at I/O) plus the widest stretch a request runs with no I/O in it, which since the clock between inputs is no longer a whole element. Measured on the lane's host, release (`the_widest_element_at_0_4_4`, `--ignored`): the 64,000-input `OP_TRUE` subject 46 ms whole; 64,000 P2PKH inputs under `ALL|FORKID` (11.6 MB) 3,229 ms, 50.5 us an input; under the original digest 1,000, 2,000, 4,000 and 12,000 inputs 115, 365, 1,268 and 10,246 ms, quadratic. Under the Worker's slices the widest stretch is the weight's slice of the 12,000-input original-digest subject, 4,969 ms native; the same `verify_stream` in wasm32 under V8 (node 26) is 1.2 times native for that shape (1.7 for `OP_TRUE`, 2.1 for forkid P2PKH), so about 6,000 ms. 15 s + 6 s is 21 s, and 30 s is that with half again. Not measured in workerd. 0.4.4's first cut set 60 s from the quadratic spend's 64,000-input walk (13.0 s here, 18.5 to 24.9 s on LOW's host).
- **M1, the list budget in encoded bytes.** The per-response budget is about 16 MB of text (16 MiB, was 32 MiB of BEEF bytes), every served body counted; the per-row bound is 2,000,000 bytes of text (what a row ever held); a payment's text is bounded before it is read (an array at most 4 characters a byte, 3.57 on average; hex 2; base64 4 for 3); and a byte array is written straight to text, byte for byte 0.4.3's text, never a `Value` a byte. Witness: twelve rows of 450,000 bytes as an array served ten inline under 16 MiB and left the eleventh unread (0.4.3: all twelve, 19.2 MB).
- **M2, the subject announced before delivery.** A verified payment's subject is posted in the send to the ARC named by `ARC_URL` (the BEEF as bytes to `/v1/tx`, the Atomic prefix left off: ARC at `e7efc5b` has no case for it; bytes at rest posted as R2's own stream; `ARC_API_KEY` its bearer token when set). The broadcaster's word is a hint: the message is delivered on the door's verdict, the row keeps the word (`payment.announced`), and a word that is not an acceptance, or no answer, is owed (`announce_owed`, migration 0005) and asked again by the scheduled drain. Only wallet-infra's record is deferred. With no `ARC_URL` nothing is announced and the row says so. Witness: a send whose broadcaster answers 503 is delivered, its row carries the word, the drain re-asks. The post itself is not run here (nothing is broadcast).
- **M3 and NOTE-3, what nobody judged.** On a box that owes no delivery fee, the body is kept in its row as 0.3.x kept every payment, never spooled; its structure is read and its text held to a row's 2,000,000 bytes before a byte is read (413 `ERR_BODY_TOO_LARGE` beyond it). A per-identity send budget on `/sendMessage` (migration 0006): 100 sends (one listing, `LIST_MESSAGES_LIMIT`) and 4 MiB of text no delivery fee judges (0.3.28's `MAX_PAYMENT_BODY_BYTES`) per identity a minute, each a var (`SEND_BUDGET_SENDS`, `SEND_BUDGET_BYTES`, `SEND_BUDGET_WINDOW_SECS`); the next is 429 `ERR_SEND_BUDGET` naming the window and when the next opens; a paid payment's bytes are not counted; a store that cannot answer refuses nothing. The list statement stops at the budget in stored bytes (a running length over 0.4.3's own statement, still a seek). Witnesses: the no-fee hand-off keeps the bytes in the row (0.4.3 spooled them); the 101st send of a window is refused naming it; twenty 1.9 MB rows list eight under the budget (0.4.3: twenty, 38.0 MB).
- **L1, the door's stamp carried.** The verdict carries the stamp of the object the door read; the hand-off records nothing of other bytes (503 `ERR_PAYMENT_CHANGED`, both etags named; the same request again reads the object as it is). Witness: an upload replaced between the verdict and the hand-off is never recorded `verified` (0.4.3: recorded, the fee internalized, the subject announced).
- **L2, the reclaim's race.** R2 deletes by key alone, so the reclaim claims the key in D1 first (`beef_reclaiming`, migration 0007), looks, stamps the object, looks again and deletes only the bytes it stamped; a send writes its row and then reads the claim, and a row whose bytes went under a claim is logged with its key (`AUDIT beef.orphan`). Witness: a re-name between the look and the delete loses nothing (0.4.3: deleted).
- **L3, objects nobody names.** Every key the relay mints (an upload URL, an inline spool) is recorded with a deadline, the URL's life and a day (`beef_minted`, migration 0008; no record, no URL); the scheduled event deletes, past it, an object nothing names, leaves one a row names to the row, and gives a pending reading an hour more. `door-state/` is expired by a lifecycle rule on the prefix, stated in `wrangler.toml`. Witness: a minted, never-sent upload is reclaimed after its deadline; a sent one is not.
- **R403-M1, no in-place copy.** `/beef/upload-url` signs the reader into the presigned PUT (`x-amz-meta-recipient-identity-key` in `X-Amz-SignedHeaders` beside `host`) and hands it back in `headers`: the PUT must carry it. An object at rest with no reader (an upload of an earlier release) has it beside its key in the row (`payment.beefReader`). `name_reader` and its open-and-spool are gone: one head, no byte read, and the etag the door verified is the one every record names. Witness: a 135 MB object at rest is named without a byte read and keeps its etag (0.4.3: opened and written again). That R2 enforces the signed header is not run here.
- **R403-L1, a held fee.** A reason that cannot clear by itself (another upload at the key, the object gone, arguments that do not parse, no bucket named, wallet-infra's own word that it cannot read the bucket) ends the fee at once (`fee_internalize.ended`, migration 0009), its reason on its row; a transient refusal keeps the backoff up to 30 attempts (about three weeks), then ends too; an ended fee names no object. When wallet-infra says it cannot read the relay's bucket (`rust-wallet-infra@50a282f` `src/storage/internalize_action.rs:352-356`, `src/beef_at_rest.rs:430-434`) the relay records it (`relay_health`) and for a day defers no fee into it (the fee ends with its reason; the message is delivered); a fee recorded clears it. `GET /health` carries `fees`: `owed`, `ended`, `lastEnded`, and `walletInfra` while the word stands. Witnesses: each reason's end state, the ceiling, the figure's words.
- **NOTE-2, a row served by key.** It carries `payment.key` and `payment.words` (the key and `/beef/download-url` named): the reference client throws on a missing `tx` and keeps the payment on the message (ts-stack@edf6e03 `MessageBoxClient.ts:580, 2109-2131, 2155-2166`), so the word travels with it.
- **NOTE-4, the body read as bytes.** A `/sendMessage` body is held to 12 MiB in every shape before a byte is parsed (the BRC-31 layer's copy and at most two more under 40 MiB of the isolate's 128; an estimate on the host); 413 `ERR_BODY_TOO_LARGE` beyond it names the upload path, which has no bound. Below it a `payment.tx` sent as a byte array is read from the text as bytes (a byte scanner, escaped keys decoded) and handed on as hex with `payment.txShape: "array"`, so the door, the rows and the in-row path keep the shape. An array that is not bytes is refused by the door as no payment. Witness `tests/send_body_memory.rs` (counting allocator): a 15.3 MB array body is refused at a peak of 1,202 bytes (0.4.3: parsed whole, a peak of 268,438,232 bytes); a 9.97 MB array body is read at a peak of 18.9 MB.

### Answers that changed
- A payment whose output does not pay is refused before its scripts: a body that both pays nothing and carries a spend no script allows is now `WrongScript` or `Underpaid`, where 0.4.3 answered `SpendRefused`. Invalid bytes anywhere are still refused before the output. The 22 BRC-29 vectors are unchanged, 22 of 22 exact.
- New answers: 413 `ERR_BODY_TOO_LARGE` (a send over 12 MiB; an unjudged body over a row), 429 `ERR_SEND_BUDGET`, 503 `ERR_PAYMENT_CHANGED`, 503 `ERR_UPLOAD_UNAVAILABLE`.
- `ERR_PAYMENT_PENDING` carries `phase`, and `input`: the input a reading paused inside a transaction reached, `null` between two elements. Rows carry `announced`, and where it applies `beefReader`, `key` and `words`. `/beef/upload-url` answers `headers`, which the PUT must carry.

### Dependencies
- bsv-middleware-cloudflare `=0.5.1` (was 0.5.0) on bsv-middleware-core 0.2.1 (was 0.2.0): a patch, bsv-rs 0.4.1 the floor and the reader's `NoInputs` word, no behavior change for a host by its CHANGELOG. bsv-rs `=0.4.4` (was 0.4.3): the spend linear in its inputs, `step_until` and `Timed::Paused`, the cursor standing inside a transaction (a paused cursor's bytes are refused by 0.4.3), the `Spend` API by additions only; one copy; bsv-middleware-rs 0.4.1. `tests/middleware_version_guard.rs` holds the three, red at 0.4.3.

### Operators
- Apply migrations 0005 to 0009 before the deploy. Set `ARC_URL` (and `ARC_API_KEY` if the ARC asks) for the announcement; the send budget's vars if 100 sends a minute is too few for a box's traffic; a lifecycle rule on `door-state/`. A client that uploads must send the `headers` `/beef/upload-url` answers.

### The suite
- 498 passed, 3 ignored (0.4.3: 465, 1 ignored): `cargo test`; the 22 vectors through the payment path, 22 of 22 exact; the six door witnesses (`tests/hostile_ancestry_door.rs`) and the deep witness (`tests/deep_beef_door.rs`) green; clippy host and wasm32 with `-D warnings`, fmt, and the release wasm32 library build clean. The 64,000-input paid walk and the widest element's measurement are `--release --ignored`.

## 0.4.3 (2026-10-10)

### bsv-rs 0.4.3: a transaction with no output is invalid bytes at the door (bsv-stack-lean #59)
- **bsv-rs is 0.4.3**, pinned exactly (was 0.4.1), one copy in the graph: bsv-middleware-cloudflare 0.5.0, bsv-middleware-core 0.2.0 and bsv-middleware-rs 0.4.1 are built on it. Nothing else in the lock moved.
- **A payment whose BEEF carries a transaction with an input and no output is refused as invalid bytes**, `InvalidBeef` with the transaction's leading byte and the kind `NoOutputs`, inline and at rest, before any root is asked, as a transaction with no input has been since bsv-rs 0.4.1 (`NoInputs`; one with neither is `NoInputs`, the node's order). Through 0.4.2 the reader read such a transaction as valid and the door went on to its words. The rule is the node's (`checkTransactionCommon`: `vinEmpty`, then `voutEmpty`), cited by bsv-rs 0.4.3's CHANGELOG. The reader's kinds are twenty; the door's refusal names any of them, so no answer's shape changes: the code, the status, `offset` and `kind` in the body are as before.
- **Witness.** `beef_door::tests::a_transaction_with_no_output_is_refused_naming_it_and_asks_nothing`: a proven parent's `OP_TRUE` spent by a transaction with no output, refused at offset 147 with `NoOutputs` and no root asked. Red at bsv-rs 0.4.1 (nothing named), green at 0.4.3.
- **Fixtures.** None of the relay's carries a transaction with no output (every hand-built transaction has one output or two; the crafted parent of the payment tests has its one input and its one output), so no expectation moved. `Transaction::verify`, which 0.4.3 also holds to both counts, is not called by the relay.
- **The door's reading of the cursor is unchanged**: `Cursor::to_binary`, which `beef_door::tip_of` reads the subject from, is byte for byte 0.4.1's in 0.4.3.
- `tests/middleware_version_guard.rs` holds bsv-rs 0.4.3, one copy, and the BRC-31 layer on it.
- **Operators.** Nothing: no binding, no var, no migration. A stored payment is held to the rule on its next read; the BRC-29 vectors are unchanged, 22 of 22 exact.

## 0.4.2 (2026-10-10)

### The drain hands wallet-infra the reference, never the bytes (the no-limits program, NL-7b)
- **Every deferred fee is drained by reference.** The drain hands wallet-infra's `internalizeAction` the object the fee's payment rests in, in place of `tx`: `beefAtRest: { r2Key, size, etag, bucket }`, the ledger row's key, the object's exact size in bytes, R2's etag unquoted (the etag, not the HTTP etag), and the bucket's name (`R2_BUCKET_NAME`, the name the presigned URLs already sign), beside the delivery output, the description and the labels. wallet-infra reads the bytes from the bucket as a stream, held to the etag and the size (rust-wallet-infra 50a282f, NL-7). The relay reads none of them: one head per fee, for the etag check, as before.
- **A held fee no longer exists.** `DRAIN_INLINE_BYTES` (8 MiB) is gone: a fee is not held for its size. What is still held, not tried and never dropped: an object that is another upload at the key, an object that is gone, a row whose arguments do not parse, and a deployment with no `R2_BUCKET_NAME`. A fee that wallet-infra could not record stays with its backoff, as before.
- **Why 0.4.1's drain recorded nothing.** It sent `tx` as `{"beef": <base64>}`, a map; wallet-infra decodes `tx` as a hex string (bsv-rs 0.4.1 `hex_bytes`) and converts only a byte array, so every fee the drain tried was refused as `invalid type: map` and put off. The reference removes the question.
- **The fee that fits is still recorded in the request**, as `tx`, now always the hex string wallet-infra decodes, whatever shape the sender sent (0.4.1 passed the sender's `{"beef": <base64>}` through, refused the same way, so such a fee was deferred). Kept, not replaced by the reference: at most 1 MiB of BEEF (`INTERNALIZE_INLINE_BYTES`), so at most 2 MiB of hex in the relay's request and wallet-infra's; the reference in the request would cost wallet-infra two reads of the object (the verification and the copy into its own bucket), an inline payment no row names a spool it does not need now, and a deployment whose wallet-infra has not bound the relay's bucket would answer every fee by deferring it.
- **The object names its reader.** Every object a paid message rests in carries the custom metadata `recipient-identity-key`: the relay's identity key, the recipient of the delivery fee and the one caller that hands wallet-infra a reference to the relay's objects (its drain, signed in as the relay). wallet-infra's caller check (NL-7c) reads it before the body. The spool writes it on the inline path. A sender's upload (`beefR2Key`) is written again in place from its own stream, once, when the send keeps it (a row or a deferred fee names it) and it does not name the relay yet: one more read and one write of the object, a part of 8 MiB at a time, and the row and the deferred fee name the object as it is after. A key sent again whose object names the relay already is not written again, so an earlier row's etag holds.
- **Seams.** `FeeWallet::internalize` takes the whole argument (`handoff::internalize_inline`, `handoff::internalize_at_rest`, `handoff::beef_at_rest`); `PaymentStore::spool` takes the reader; `PaymentStore` gains `reader`, `name_reader` and `bucket_name`; `Paid` gains `reader`.
- **Operators.** No migration, no new binding or var. `R2_BUCKET_NAME` must be the `bucket_name` of `BEEF_BLOBS` (as `wrangler.toml` already says), and wallet-infra must bind the same bucket (`BEEF_AT_REST`, `BEEF_AT_REST_BUCKET`) before a reference can be recorded; until it does, every deferred fee is put off with wallet-infra's refusal and retried, never dropped. **Objects at rest before 0.4.2 carry no `recipient-identity-key`**: a fee deferred before the upgrade is refused by wallet-infra once NL-7c checks the reader, and waits in the ledger.

## 0.4.1 (2026-10-10)

### The 0.4 line alone: bsv-middleware-cloudflare 0.5.0, bsv-middleware-rs 0.4.1, one bsv-rs
- **The BRC-31 layer is bsv-middleware-cloudflare 0.5.0** (on bsv-middleware-core 0.2.0 and bsv-rs 0.4), in place of 0.3.3. The session, the wallet and the auth message it takes are the relay's own bsv-rs 0.4.1 types; the wallet-infra client the fee's internalize opens is that crate's `WorkerStorageClient` over the relay's wallet. The handshake, the served requests and response signing are those of the layer's 0.4.x line, byte for byte by its own CHANGELOG. **One answer a client can see:** since the layer's 0.4.1, an authentication refusal (an identity that is not the session's, a signature that does not verify, a session that never completed its handshake, a replayed nonce) is the layer's own 401 with its code; under 0.3.3 several of these were an error the relay answered 500. A client that re-handshakes on 401 now recovers a stale session.
- **The request body is still read whole before any route.** 0.5.0 reads it into memory to verify the signature over it (its `src/transport/cloudflare.rs`), so the inline `payment.tx` path is as 0.4.0 left it: decoded a chunk at a time from the JSON value already in memory, its ceiling the platform's. A payment at rest in R2 is unchanged: read as a stream, resumable across requests.
- **The six words are bsv-middleware-rs 0.4.1's** (was 0.3.0). The door keeps its own reading, the structure, the scripts and the cursor saved between requests, and hands the middleware the subject transaction alone for the output check (`verify_payment_output_only`, over the subject's bytes). The middleware's own full check reads a payment in one pass with no cursor, so it is not what the door calls. The order is that crate's: no header service; the bytes and the spends; the output (script, then amount); a proof; a height no header can carry; the roots, lowest height first.
- **Answers that changed.** The refusal text of the bytes is the middleware's: invalid bytes read "BEEF is invalid at offset N: Kind" and a refused spend names the transaction, its offset, the input and the interpreter's reason. The codes, the statuses, `offset` and `kind` in the body are unchanged. A BEEF with no transaction is the middleware's `NoTransaction`. A BUMP whose block height no header can carry is refused before any root is asked (a lower root the header service does not carry was the word before).
- **Dependencies.** bsv-rs 0.4.1 alone: the second copy (0.3.35) is gone, with the `bsv-stream` alias. `tests/middleware_version_guard.rs` holds the pins: bsv-middleware-cloudflare 0.5.0 from crates.io, built on the relay's bsv-rs 0.4.1; bsv-middleware-rs 0.4.1; one bsv-rs.
- **Operators.** Nothing new: no binding, no var, no migration beyond 0.4.0's four items. The BRC-29 vectors are unchanged, 22 of 22 exact.

## 0.4.0 (2026-10-09)

### A BEEF of any size at the payment door (the no-limits program, NL-4)
- **The posture.** A valid payment is never refused for its size or its counts. A refusal is for invalid bytes or for a spend no script allows, and names them: the stream offset and the kind (one of the nineteen kinds of bsv-rs 0.4.1's reader, none of which is a size or a count, or `SpendRefused`). This reverses the door of 0.3.28: the 413 `ERR_BODY_TOO_LARGE` above 4 MiB is gone, and so is the refusal of a BEEF over 128 transactions or 32 BUMPs that 0.3.29 took from bsv-middleware-rs.
- **The reader.** `beef_door` reads the payment's BEEF with bsv-rs 0.4.1's `StreamVerifier`: one element in hand, an index of one entry per element, and each transaction's outputs until an input of the BEEF spends them. The six words are still bsv-middleware-rs 0.3.0's: the door hands it the subject transaction for the output check (`verify_payment_output_only_with_limits`) and asks the roots itself, in that crate's order (no header service; the bytes; the output, script then amount; the roots, lowest height first). No root is asked before the output is judged; no payment is accepted with a root unasked. The BRC-29 vectors are unchanged: 22 of 22 exact, in each of the three shapes of `tx`.
- **What the door holds a payment to (NL-4c).** Two rules beside the structure and the roots, each with a witness inline and from R2, in one request and resumed at every element (`tests/hostile_ancestry_door.rs`):
  - **Every unproven spend is one its script allows.** The door runs the scripts: each input of an unproven transaction is executed against the output it spends, and an unproven transaction may not pay out more than it spends. A payment whose subject (or any unproven ancestor) spends an output its unlocking script does not satisfy is 400 `ERR_INVALID_PAYMENT`, `kind: "SpendRefused"`, `offset` the input's, the text naming the input, the transaction and the interpreter's reason. No header is asked.
  - **A transaction with no input is no transaction.** It is invalid bytes (bsv-rs 0.4.1, `NoInputs`, at the transaction's leading byte), with or without a BUMP: a payment that stands on one is refused whatever else the BEEF proves. 400 `ERR_INVALID_PAYMENT`, `kind: "NoInputs"`. No header is asked.
  - **What the scripts cost.** The reader keeps an output until an input of the BEEF spends it, so outputs that nothing in the BEEF spends are held to the end of the reading (and are in the cursor saved between requests). A chain whose megabytes ride in the outputs the next link spends is read flat; megabytes in outputs nothing spends are memory, about twice their size at the peak (`tests/door_memory.rs` measures both).
- **Inline (`payment.tx`).** Decoded a chunk at a time from the request's JSON value and verified in one pass. The request body itself is still read whole before any route (the BRC-31 layer verifies a signature over it), so the inline ceiling is the platform's: Cloudflare's 100 MB body and the isolate's memory holding that JSON. An inline body cannot be resumed, since its bytes are not at rest.
- **R2 (`payment.beefR2Key`).** The object is read from the bucket as a stream and is never held whole while it is verified: a 135 MB object of megabyte elements, each spent by the next, is verified in a peak heap of 11.0 MiB (`tests/door_memory.rs`, native). A verification one request does not finish (15 s of reading, or 500 header lookups) saves its cursor in the bucket under `door-state/<key>` and answers **503 `ERR_PAYMENT_PENDING`** with `elements`, `offset`, `size`, `rootsChecked` and `roots`; the same request sent again continues from the cursor, and the verdict is the verdict of the whole. A state saved for another upload at the same key (a different size or etag) is dropped and the reading starts over. A header service that could not answer keeps the state at the roots, so the retry does not read the bytes again.
- **The ceiling, named.** What one isolate cannot hold is the index: 185 to 283 bytes an element at its peak on the host, so between about 470,000 and 725,000 elements in 128 MiB, less the Worker's own heap (not measured in wasm32). The cursor carries the index, so resuming does not raise this ceiling; it removes the ceiling of time. Nothing in the code refuses at that number.
- **After the verdict, nothing refuses the sender (NL-4b).** The verdict is free of size and so is what follows it: the hand-off is the relay's own bookkeeping.
  - **The bytes stay at rest in R2.** An object the sender uploaded stays at its key. An inline payment that a row or a deferred fee will name is spooled there a chunk at a time, under a key of the same shape (`<sender's identity key>/<uuid>.beef`) that nothing presigned. The object belongs to what names it (below): it is deleted only when no stored row and no deferred fee names its key.
  - **The recipient's row carries the key, the verdict and the txid, never the BEEF.** The stored `payment` is the request's without its `tx`, with `beefR2Key`, `beefSize`, `beefEtag`, `txShape` (`array`, `hex` or `base64`: the shape the sender sent), `verdict` (`verified`, or `notJudged` on a box that owes no delivery fee) and `txid` (the subject the door verified). A row no longer grows with the payment: the row of a 6,200,112-byte payment is under 2,048 bytes.
  - **The readers stream.** `/listMessages` and `/listTranscript` hand a payment of up to 2,000,000 bytes (D1's bound on a row, so every payment a row ever carried) back inside `payment.tx`, in the shape the sender sent it, read from the object's body stream and held to the etag the door verified; the new fields stay beside it. A body that names no key is not parsed and the bucket is not asked. A larger payment is listed without `payment.tx`: its recipient calls the new **`POST /beef/download-url`** with the `messageId` and reads the BEEF from a presigned R2 GET (ten minutes, only for the row's recipient). One list response hands back 32 MiB of BEEF inline; a row past that is in the next listing, whole. Bytes the bucket could not give, or that are another upload at the key, leave the row served by its key.
  - **The fee's internalize is deferred when it does not fit.** wallet-infra still takes the BEEF as one JSON-RPC argument. A payment of at most 1 MiB is internalized in the request, as before. A larger one, and any payment while wallet-infra cannot answer, is deferred: a row of the new `fee_internalize` table (`key`, `etag`, `txid`, `args`, `named`, `attempts`, `next_at`, `last_error`), and the message is stored and delivered on the verdict. A fault in wallet-infra was 500 `ERR_INTERNALIZE_FAILED` with the message undelivered; that answer is gone from the send path. wallet-infra's own refusal of a payment (`accepted: false`) is still 400 `ERR_INSUFFICIENT_PAYMENT`.
  - **The drain.** The scheduled event takes ten due fees, reads each BEEF back from R2 as a stream, and hands it to wallet-infra. A fee recorded has its row cleared. A fee that could not be recorded stays with one more attempt and a backoff (a minute, doubling, a day at most). A fee over 8 MiB (what the drain's isolate hands wallet-infra as one argument, an estimate, not measured in a Worker), or whose object is no longer the upload the door verified, is held and not tried. No row is dropped for its age or its attempts. The fee is on chain at the server's derived key either way; what waits is wallet-infra's record of it.
  - **Ownership, not a copy (NL-4c).** An object under a payment key is deleted only when no stored row and no deferred fee names its key (`handoff::reclaim`, the one delete). A row names its object in a new column, `messages.beef_key`, written with the row; the reference is released when the row is deleted or its message retired (acknowledged in a retained box), by whatever statement does it: two triggers put the key in `beef_released`, and the scheduled event looks at the released keys after the fee drain, 25 a pass. So a key the sender names again in a later send cannot take the object from a row that names it, a recorded fee's object stays while a row names it, and the object of an acknowledged message is reclaimed once nothing names it. Who names a key is one seek on a partial index; nothing scans the rows or lists the bucket. A store that cannot answer deletes nothing. The etag check stays: bytes at the key that are another upload are never served into a row and never handed to wallet-infra, so an overwritten object is an unreadable payment, never a wrong one.
  - **Order.** The payment's outputs are routed to their recipients before the hand-off, so a payment that does not cover its recipients (`ERR_INSUFFICIENT_OUTPUTS`, `ERR_MISSING_RECIPIENT_OUTPUTS`) is refused with nothing put at rest and no fee recorded; before, the fee was internalized ahead of the routing. On a box that owes no delivery fee, a `payment.tx` that is none of the three shapes of bytes is 400 `ERR_INVALID_PAYMENT`; before, it was stored in the row as it came.
- **Answers that changed.** A payment that is not a BEEF (a raw transaction, or any other bytes) is still 400 `ERR_INVALID_PAYMENT`, now naming `BadVersion` at offset 0; a raw transaction that underpaid was `ERR_INSUFFICIENT_PAYMENT`. Every refusal of the bytes carries `offset` and `kind` beside `status`, `code` and `description`. A BEEF must hold together as the reader reads it: each unproven transaction after the ones it spends, and in an Atomic BEEF no transaction the subject does not descend from.
- **Dependencies.** bsv-rs 0.4.1 enters beside 0.3.35 (as `bsv-stream`, pinned exactly): bsv-middleware-rs 0.3.0 and bsv-middleware-cloudflare 0.3.3 are built on 0.3. The Worker carries both until the middleware moves. bsv-middleware-rs 0.4.0 (on bsv-rs 0.4.0) was published while this release was built and is not taken here: its full check reorders the words and has no cursor for a verification that spans requests; bsv-middleware-cloudflare, the BRC-31 layer, is on bsv-rs 0.3 at its newest release (0.4.1), so the second copy stays either way. `tests/middleware_version_guard.rs` holds the three pins.
- **Operators.** No new binding or var. **Apply migrations `0003_fee_internalize.sql` and `0004_beef_key.sql` before deploying** (additive: two tables, a column on `messages`, two indexes, two triggers; every send writes the new column, so the build must not run before 0004 is applied). **A cron trigger drains the deferred fees and reclaims the released objects**; a deployment with none records no deferred fee and reclaims nothing, and one that has only the daily retention cron does both once a day (`wrangler.toml` documents a cadence). **The bucket's lifecycle rule must not expire an object a row or a deferred fee names**: a paid message's BEEF lives in `BEEF_BLOBS` until nothing names it, and the relay deletes it then. The door writes under `door-state/` in `BEEF_BLOBS`; a lifecycle rule that expires uploads should cover that prefix too.

## 0.3.31 (2026-10-09)

### The BRC-29 vectors re-pinned: 22 cases, no root is the payer's (bsv-stack-lean #50)
- No change to the relay's answers; a test-only release. `tests/vectors/brc29-payment-vectors.json` is again the canonical file's bytes (sha256 `836579ad73e20ca0e259a6c7cce5b55d85095cf290f74458937aeb39c9b5253c`, 22 cases; 0.3.30 pinned the 20 of 2026-10-08, `dae68f0b...3a8d`, and `the_pinned_copy_is_the_canonical_file` was red against the canonical file).
- The two cases added there on 2026-10-09, `spv-no-root` (a BEEF with the payment and the parent it spends, no BUMP for either) and `spv-incomplete-beef` (the payment alone, its input's transaction not carried), run through the box's payment path as shipped in 0.3.29: both are `Unverifiable` with no fields, 400 `ERR_INVALID_PAYMENT`, and the header service is never asked.
- The runner follows the owner's ruling of 2026-10-09: `Unverifiable` takes its class from its reason's side (a header lookup the server could not complete is 5xx, no root is the payer's, 4xx); a payer-side reason carries no fields; a case whose `header_service.lookup` is `null` must ask nothing. 22 of 22 exact, in each of the three shapes of `tx` the route reads.

## 0.3.30 (2026-10-09)

### The header service over a service binding
- **A new service binding, `HEADER_SERVICE`**, names the header service as a Worker on the relay's own Cloudflare account. Cloudflare refuses a plain `fetch()` between two Workers of one account (error 1042 behind a 404, the callee never invoked), so on such a deployment 0.3.29's `HEADER_SERVICE_URL` could not reach the header service and every payment that owed a delivery fee was answered 503 `ERR_PAYMENT_UNAVAILABLE`.
- With the binding, every lookup is the binding's fetch of `https://header-service/findHeaderHexForHeight?height={h}`: a binding ignores the host and the callee sees the path and the query, the route 0.3.29 calls.
- **The binding wins when both exist.** Without the binding, `HEADER_SERVICE_URL` is read as in 0.3.29 (a Worker on another account may use it). With neither, every payment that owes a delivery fee is refused 500 `ERR_SERVER_MISCONFIGURED`, as before.
- The answers are those of 0.3.29: a status of 400 or above from the header service, a fetch that fails or a reply that cannot be read is 503 `ERR_PAYMENT_UNAVAILABLE` (fail closed).
- `wrangler.toml` documents the `[[services]]` block as a comment; a deployment sets its own.
- `payments::HeaderTransport` is the seam (one GET, the status and the body), with `BindingTransport` and `UrlTransport`; `WorkerHeaderService::over(binding, configured)` chooses. `WorkerHeaderService::configured` is unchanged.

## 0.3.29 (2026-10-09)

### The payment door on bsv-middleware-rs 0.3.0: six words, and a header service (bsv-stack-lean #57, #50)
- bsv-middleware-rs 0.3.0 (from crates.io). `verify_payment_output` and `PaymentOutputError` are gone from that crate; the delivery check now hands the payment to `verify_payment` and answers its verdict in one match with no catch-all arm (`payments::delivery_verdict`, `payments::delivery_answer`).
- **The delivery payment's merkle roots are checked.** Every root the payment's BEEF computes is compared with the header service's root at that height, lowest height first, before wallet-infra is asked to record the payment. Until this release nothing on the box's path checked the proof.
- **A new var, `HEADER_SERVICE_URL`**, names the header service (`GET {base}/findHeaderHexForHeight?height={h}`, answering `{"status":"success","value":{"merkleRoot":...}}`). **A deployment must set it before it takes this release:** with it unset, blank or naming a `.invalid` host, every payment that owes a delivery fee is refused 500 `ERR_SERVER_MISCONFIGURED`. Sends that owe no delivery fee are not affected.
- The answers. Unchanged: an underpayment is 400 `ERR_INSUFFICIENT_PAYMENT`; a wrong script, a malformed transaction, a missing output or a BEEF over the counts is 400 `ERR_INVALID_PAYMENT`. New: a root the header does not carry is 400 `ERR_INVALID_PAYMENT`; a payment with no merkle proof, or a BEEF that is not structurally complete, is 400 `ERR_INVALID_PAYMENT` (0.3.28 accepted these on the output alone); a header service that could not answer (outage, HTTP error, height not indexed, unreadable reply) is 503 `ERR_PAYMENT_UNAVAILABLE`, so the client retries the same payment: the payment is never accepted unchecked and never answered as unpaid (fail closed, the ruling of 2026-10-08).
- The refusal text of an invalid delivery output now carries the verdict's words (for a malformed transaction, "payment cannot be verified: transaction is malformed: ..."). The codes are unchanged.
- Plain BEEF (V1 and V2) is read as well as Atomic BEEF; a raw transaction carries no proof and is refused.
- No limit changes: the fee per recipient, the 413 above `MAX_PAYMENT_BODY_BYTES` (4 MiB) and the BEEF counts (128 transactions, 32 BUMPs) are those of 0.3.28.
- The BRC-29 conformance vectors run through the box's payment path (`tests/conformance_brc29.rs`, the canonical file's bytes pinned under `tests/vectors/`): 20 of 20 exact, in each of the three shapes of `tx` the route reads.
- The deep-BEEF witness (`tests/deep_beef_door.rs`) holds under the full check: a chain over the bound is refused naming it before any lookup; a chain at the bound parses on a 1 MiB thread, its one root is asked once and the fee is judged paid.

## 0.3.28 (2026-10-08)

### The payment door: the fee per recipient, the body bound, the SDK re-pin (bsv-low #580 M1 and H1; bsv-stack-lean #57)
- The server delivery fee is due once per recipient: a `sendMessage` to N recipients must pay N times `delivery_fee` on output 0, as the box's own quote and the reference server already said (M1).
- A payment transaction above `MAX_PAYMENT_BODY_BYTES` (4 MiB, the reference's default body limit) is refused 413 `ERR_BODY_TOO_LARGE` before any decode or parse, in every shape the route accepts (H1 a).
- bsv-rs 0.3.35 (the lock had pinned 0.3.20): every walk over a BEEF's ancestry on the heap, so a stranger's chain of unproven transactions no longer overflows the Worker's stack (H1 b); the BUMP parse linear in its leaves; a tree-height byte over 64 refused.
- bsv-middleware-rs 0.2.2: `verify_payment_output` refuses a payment over 4 MiB before it parses and parses an Atomic BEEF through the SDK's limits (128 transactions, 32 BUMPs), naming the count and the bound; the box maps every refusal but `Underpaid` to its existing invalid-payment error.
- The deep-BEEF witness (`tests/deep_beef_door.rs`) runs un-ignored: a chain one transaction over the bound is refused naming it, a chain at the bound parses on a 1 MiB thread and the delivery output is judged as before.

## 0.3.26 — 2026-09-20

### Three alarm re-arm nets and the counter bound (bsv-low #495, #496)
- `MessageHub::websocket_close` and `websocket_error` run `rearm_pending_departures_net` first, like every fetch and socket frame: a `pendingleft:` entry stranded in another room by a lost alarm is pulled back in by the highest-signal hub events (the 2 s gate keeps it free).
- `EngineIoSession::fetch` repairs a lost heartbeat chain on every attached socket (the polling transport and the Worker→DO paths were the one wake that did not); `disarm_heartbeat_if_idle` re-reads the socket census after its delete and re-arms when a socket attached under it.
- `x-low-session-n` is bounded at `Number.MAX_SAFE_INTEGER` and refused `malformed` by name above it (`session_lane::parse_counter`): the ask rides to the hub as a JSON number through JSON.parse + serde-wasm-bindgen, which faults above 2^53, so a crafted header used to turn into a hub fault (`reason=storage`, a lane the client drops). `HubMirror::last_h` rides as a decimal string like `seen_mask` (the bound and the serializer's limit were the same constant, zero headroom); a mirror persisted as a number still reads.

## 0.3.25 — 2026-09-20

### The presence answer has the departure's own flap window (bsv-low loop 13, #491)
- `/internal/presence` (and so the join-time `presence` snapshot the joiner's hub builds from it) answers `present: null` while the room's departure debounce is still running — the same ~4 s window the `peerLeft` push waits (`pendingleft:<room>`); `false` only once the room is empty past it (`presence_answer`, pinned). It used to answer `false` the instant the room emptied: a peer mid-re-listen (leave + rejoin within a second, the client's transport watchdog) read as absent (loop 12, #491), and a killed peer's snapshot 4 s after the kill wrote the owner's told-state to absent, so the real push 50 ms later was deduped against it — the snapshot was the only delivery (loop 13, survivorLooksOnly). `null` writes no told-state, so the push behind a flap window is never deduped; the public `/presence` route reads a `null` as a hub that could not answer (never a fabricated `false`).

## 0.3.24 — 2026-09-20

### The session mirror's replay window survives the storage boundary (bsv-low loop 12)
- `HubMirror::seen_mask` (the 64-deep HTTP replay window) is persisted as a decimal STRING. The Durable Object's serializer carried the `u64` as a JavaScript number and threw above `Number.MAX_SAFE_INTEGER` — every lane past its ~53rd HTTP call — so `verify_http`'s put failed and the hub answered every later call on that lane `reason=storage` (a 401 the client kept the lane through: the honest seat of a dispute never saw the tower's ruling on its felt). Seven identities in three hours on beta. Rows persisted as numbers still read. Pinned.

## 0.3.23 — 2026-09-19

### The socket close is named (bsv-low #466)
- `EngineIoSession::websocket_close` logs `WS closed sid=… code=… clean=… reason=…` before its teardown. An idle LOW games page's socket dropped twice in 30 minutes with every pong answered up to 14 s and 22 s before each close and no relay close path taken; the runtime's bare `close` event line carried no code, so neither side could say who closed. Observability only: no behaviour change.

## 0.3.22 — 2026-09-14

### One handshake per tab (bsv-low #443 step 4) and its gate's fix round
- `POST /session/attest` (bearer `BROADCAST_TOKEN`, like `/push`): a first-party door asks whether ONE hub-lane call verifies (the HTTP-lane verify body verbatim, forwarded to the identity's hub `/internal/session-verify`); answers `{ok, identity}` or `{ok:false, reason}`, 503 when the hub cannot be asked. The body's `id` and `identity` are exactly 64 / 66 hex.
- `sessionAttach {s, identity, n, mac, nonce}`: a socket of a tab that already holds a relay lane attaches through the hub mirror instead of a BRC-103 handshake of its own (the MAC is the HTTP-lane shape over the pseudo-call `ATTACH /socket`, the nonce as the body). Dispatched before the CONNECT guard (a wake rehydrates `connected=false`). The hub is asked with its own bound (`ATTACH_HUB_TIMEOUT_MS` 1.2 s, below the client's 1.5 s attach wait inside the SDK's 5 s auth budget); ONE attach per socket (`attach_attempted`, persisted); the socket lane is minted PURELY and then set together with `Authenticated` under a compare-and-set (a handshake that completed during the hub await owns the socket: `already-authenticated`). The ack `sessionAttached {d, m}` is a one-shot MAC `HMAC-SHA256(K_hub, "sessionAttached" ‖ 0x01 ‖ sha256(d))` (the domain byte keeps it disjoint from every frame MAC); a refusal is a plain `sessionAttachRefused {reason}`.
- Every lane and its hub mirror now die at most 12 h after the mint however busy (`LANE_MAX_LIFETIME_MS`, `minted_at_ms` with a serde default of 0 = past the lifetime for records written before this field; D12's posture). The mirror stores its identity lower-cased. Bearer tokens are compared in constant time (`bearer_matches`; an unset secret matches nothing).

## 0.3.21 — 2026-09-09

### The session lane (bsv-low W-B, ts-stack divergence register row D10)
- One BRC-103 handshake per socket, then a SESSION: when the client's `authenticated` General is answered, the relay mints a 32-byte session id and a 32-byte salt (the platform RNG) and carries `{ status: "success", session: { id, expiresAt, salt } }` in `authenticationSuccess` (the reference's shape plus one field a reference client ignores). Both sides derive `K = HMAC-SHA256(salt, "low-relay-session/v1" ‖ id ‖ clientNonce ‖ serverNonce)` from the handshake's own nonces; `K` never crosses the wire.
- A session-aware client sends every later event as `sessionMessage { s, n, e, d, m }` (`d` the event's data as JSON text, `m = HMAC-SHA256(K, n_le8 ‖ e ‖ 0x00 ‖ sha256(d))`, `n` strictly increasing); the relay verifies id, idle window (1 h, refreshed by every valid frame in either direction), counter and MAC in wasm, persists the moved counter BEFORE the hub await, and routes the event exactly like a verified General. Once the client has spoken on the lane, every delivery (the hub's answers and the broadcast fan-out) rides back as `sessionEvent { n, e, d, m }` under the relay's own counter, the room-suffixed event name unchanged. Zero wallet calls per frame in either direction.
- A refusal (`unknown-session`, `expired`, `replay`, `bad-mac`, `malformed`) is said as a signed General `sessionRefused { reason }` on the reference lane and routes nothing; the client re-handshakes. A client that never presents a session is served on the reference lane forever. The lane rides the socket's attachment through hibernation (~330 B of the 2 KB cap, pinned) and dies with its socket.
- THE HTTP LANE: an in-session HTTP call (`/listMessages`, `/acknowledgeMessage`, the `/sendMessage` fallback, `/presence`, …) carries `x-low-session` (the id), `x-low-session-identity`, `x-low-session-n` (the client's own HTTP counter `h`) and `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖ "METHOD path?query" ‖ 0x00 ‖ sha256(body))`. The Worker asks the identity's `MESSAGE_HUB` DO (`/internal/session-verify`, the body's digest, never the body; bounded like every hub ask) to verify against its MIRROR of the lane (`session:<id>`: K, the identity, the window, `h`), persists the moved counter before answering, and seals the route's answer with `x-low-session-mac` = `HMAC-SHA256(K, h_le8 ‖ "response" ‖ 0x00 ‖ sha256(body))` under the same `h`. A refusal is 401 `ERR_SESSION_REFUSED { reason }` (the client falls back to BRC-104 for that call); a hub that cannot be asked is 503, never a refusal. The mirror is registered by the socket DO on the FIRST frame the client sends on its socket lane (piggybacked on the routed event, no extra await), refreshed when the window moved past a 60 s slack, revoked in the socket's unregister, swept when expired. The browser preflight allows the lane's headers beside the middleware's; the response's two headers are exposed. A request without `x-low-session` takes BRC-104 exactly as before.
- THE ASK: only an `authenticated` carrying `laneAsk` mints (the ask is echoed as `session.ask`); the reference client's own `authenticated` never touches the lane. Found by the first traced hand on the lane (bsv-low, 21:36Z): the SDK's own `authenticated` and the client's re-ask both minted, the handshake's Generals are verified asynchronously on the client and completed out of order, the two sides held different lanes and every frame was refused `unknown-session` until they agreed by luck (seven mints in 40 s). Now the client binds its lane to its own latest ask.
- THE HELLO: a session-aware client's first frame on a fresh lane is `sessionHello` (its forward registers the HTTP mirror at the identity's hub at once); the hub answers `sessionWelcome`, sealed back onto the lane: the client's first verified delivery at every mint, the lane proven in both directions.
- Pure module `src/session_lane.rs` (12 pins + the vectors pin, the MAC vectors PRODUCED for the client's byte-for-byte pin and sha256-pinned in both repos, socket frames and HTTP calls both); the host wiring in `engineio/session.rs`, `message_hub.rs` and `lib.rs` (14 source/behaviour pins, every one RED-verified mechanically). Two 0.3.20 source pins that rustfmt had turned RED (the Ping arm's persist order, the membership mirror) now match whitespace-stripped.

## 0.3.20 — 2026-09-09

- The first-party box refusal (0.3.19) now covers the LIVE send path too: the hub's `sendMessage` event (raw WS and socket.io) answers `messageFailed { code: "ERR_FIRST_PARTY_BOX" }` for `low_events` and `broadcast-*` right after the room's box is derived. Found by the same review's delta-verify (M-A): the HTTP door alone left `sendLiveMessage` able to store and live-bridge a forged row. One predicate, both doors; pinned in the hub's tests.

## 0.3.19 — 2026-09-09

- `/sendMessage` REFUSES the first-party boxes (`low_events`, `broadcast-*`) with 403 `ERR_FIRST_PARTY_BOX` at the door: only the bearer-gated `/push` and `/broadcast` write them. Found by bsv-low's from-scratch tower review at the loop-10 promotion (HIGH-1): an authenticated end user could file a forged tower `case` event into a seat's durable box. The client pins each event kind to its producer's identity as well. Pinned (`the_ordinary_send_route_refuses_the_first_party_boxes_and_nothing_else`).

## 0.3.18 — 2026-09-08

### The acknowledge statements stop scanning every box on every ack (bsv-low M19-5, issue #428)
- Cloudflare D1 query insights for the loop-8 window (2026-09-07 22:16–22:56Z) showed the retained-box acknowledge UPDATE reading 8.9M rows over 1,891 calls and the delete half 7.7M over 1,648: ~4.7k rows per ack. `EXPLAIN QUERY PLAN` on the real migrations names the cost: the outer statement already seeks `sqlite_autoindex_messages_1` (message_id) but the `message_box_id IN (SELECT … FROM message_boxes WHERE type LIKE … ESCAPE …)` subquery is a `SCAN message_boxes` on every statement (SQLite's LIKE optimization cannot apply: the ESCAPE clause rules it out, and `type` is BINARY-collated while LIKE is case-insensitive), so every ack read every box row.
- Both halves now test retention with a CORRELATED predicate on the candidate row (`EXISTS (SELECT 1 FROM message_boxes mb WHERE mb.message_box_id = messages.message_box_id AND mb.type LIKE …)` / `NOT EXISTS …`): one rowid lookup per candidate message. Semantics are the IN form's byte-for-byte (a retained row is marked, any other row is deleted, a row whose box is gone is deleted; re-ack counts 0), and the bind order is unchanged. No migration and no wire change; the daily TTL sweep keeps the box-list subquery (one statement a day).
- Pins (rusqlite, dev-only, on the real migrations): the plan for both ack statements contains no `SCAN message_boxes` and looks the box up `USING INTEGER PRIMARY KEY`; the pre-0.3.18 IN form on the same fixture plans the scan (the RED side); the partition semantics above.

## 0.3.17 — 2026-09-07

### A departure delivered to a socket being replaced is REPLAYED; the stranded-departure net runs on every hub event
- bsv-low loop 7 (2026-09-07, `survivorLooksOnly`): the survivor's felt re-listens every ~12 s under a silent inbox (a fresh socket.io session each time); the `peerLeft` push landed on the session it was replacing (`delivered` = 1, so nothing was parked) and died with it — told-state Absent, every later push deduped, the open seat heard nothing (it recovered from the join-time presence snapshot). The hub now remembers the LAST DELIVERED departure per room (`lastleft:<room>`) and REPLAYS it to a session that joins the room within 60 s while the told-state still says Absent (`departure_replay_due`, pure); a session that already latched it costs nothing.
- The same loop's first survivor run (16:17Z): the killed seat's departure pushed for its events-box room but NEVER for the game room — a `pendingleft:` entry whose DO alarm was lost on a live, quiet hub (the platform class the heartbeat met on 2026-09-03). The recovery net used to run once per isolate; it now runs on EVERY hub event (a fetch or a raw-WS frame), cheap-guarded to once per 2 s (`rearm_net_due`, pure), and a scheduled time in the past counts as absent (`alarm_needs_replacing`, unchanged). `ensure_alarm_no_later_than` reads the alarm back after each set and retries once (`alarm_set_confirmed`, pure) — the set-dropped class; the fired-but-never-run class leaves the row and is the net's job.
- Log lines are the counters: `peerLeft for <room> REPLAYED to sid=…`, `rearm net re-armed N stranded departure(s)`, `set_alarm read-back mismatch`. Four new pins; 311 tests green.

## 0.3.16 — 2026-09-05

### A peerJoined that reached no session is PARKED
- `parkedjoined:<room>` mirrors 0.3.13's parked departure: an arrival pushed to an identity whose only session was dead (a heartbeat-timeout reconnect in flight) is delivered on its next register / room join. One pure rule `parked_presence_choice` decides between a parked departure and a parked arrival: told=Present drops the departure (0.3.15), told=Absent drops the arrival, the 3-minute TTL drops stale news, the newer wins a tie. bsv-low 2026-09-05 `dealtLeaveNotifyRejoin`.
  (commit `ed38eb2`: 0.3.16: a peerJoined that reached NO session is PARKED (parkedjoined:<room>) and delivered on the identity's next register / room join — the arrival m)

## 0.3.15 — 2026-09-05

### A departure is a SOCKET CLOSE, for every room
- A client `leaveRoom` on a game room is a room HOP (the felt's inbound watchdog leaves and re-joins to recover a dropped envelope); under load the re-join outran the 4 s debounce and the peer was told "opponent lost connection" about a seat that never left. Only a socket close (tab close, crash, heartbeat timeout) or an explicit app-level goodbye signals. A parked departure is dropped when the peer's arrival already wrote told=Present.
  (commit `f39b18c`: 0.3.15: a departure is a SOCKET CLOSE for every room (a leaveRoom is a room hop, never a departure); a parked departure superseded by the peer's arriv)

## 0.3.14 — 2026-09-05

### A waiting host's lobby-room departure signals only on a socket CLOSE
- The lobby's `host-left` fans out only when the host's socket closes (a crash), never on a clean `leaveRoom` (a match / cancel is a room hop) — the lobby half of the rule 0.3.15 then applied to every room.
  (commit `aa501a9`: 0.3.14: a waiting host's lobby-room departure fans host-left ONLY on a socket CLOSE (crash), never on a clean leaveRoom)

## 0.3.13 — 2026-09-05

### A peerLeft that reached no session is PARKED
- `parkedleft:<room>` with a 3-minute TTL: a departure pushed while the counterparty's only session was between a leave and a re-join is delivered on its next register / room join instead of being lost with the told-state already flipped (bsv-low full18 run 2, survivorLooksOnly).
  (commit `e847407`: 0.3.13: a departure nobody was there to receive is PARKED and delivered on the identity's next register / room join; the lobby-room match is exact)

## 0.3.12 — 2026-09-04

### A waiting host's departure is an EVENT for the lobby
- The relay fans a waiting host's departure into `broadcast-low-lobby` so the lobby's away latch is event-driven (one confirming probe at `confirmDueAt`, never a poll), and the leaver's tier-2 countdown rides a `ladder` event (bsv-low re-run round 1).
  (commit `4ce92f0`: 0.3.12: two LOW lobby/ladder EVENTS the event-driven client was missing (bsv-low full18 re-run 2026-09-05))

## 0.3.11 — 2026-09-03

### A fresh socket is not "overdue"
- 0.3.10's overdue rule treated a socket with NO ping yet as overdue, so the first inbound
  frame after the upgrade (the CONNECT) logged `heartbeat REPAIRED … pinging now` and sent
  an early ping on every join (LOW run 15: four lines at join). Harmless to liveness,
  noise in the one signal that counts repairs. The upgrade commit now stamps the
  heartbeat epoch (`last_ping_at_ms`), and a missing stamp with a pending alarm is Armed.

## 0.3.10 — 2026-09-03

### The repair believes the ping schedule, not the alarm row
- LOW run 14 caught the platform's loss in the wild (19:53Z): the re-delivered tick was
  `canceled`, and `get_alarm()` KEPT ANSWERING the tick's scheduled time while the
  runtime never fired it. The client's nudge landed 8 s past that time; 0.3.8's 10 s
  "late grace" read the row as merely late, did nothing, and the socket closed at 45 s.
  Now a ping overdue by more than 2 s past the interval is the truth whatever the row
  says (`PING_OVERDUE_GRACE_MS`), the late grace is 2 s, and a client `6` (the nudge)
  logs its check's outcome so a tail shows the class repaired or not.

## 0.3.9 — 2026-09-03

### The fault knob cannot be switched on in production
- `HEARTBEAT_TEST_LOSE_ALARM_AFTER_PONG_EVERY` is read through `env.var`, which a
  `wrangler secret put` or a dashboard edit on the PRODUCTION worker can also set — no
  deploy, no config diff. It is now honored only on a deploy whose `R2_BUCKET_NAME`
  names a beta bucket (`test_knob_n`, tested): on prod the name is inert whatever its
  value. Found by the delta-verify round on the sibling tower change.

## 0.3.8 — 2026-09-03

### The heartbeat survives a lost alarm (Cloudflare at-least-once, in practice not)
- Two LOW runs (12 and 13) each recorded a COMPLETED heartbeat tick re-delivered
  ~300 ms later as `canceled` (0 ms of wall time) with no alarm left behind — about one
  tick in a hundred. The server stopped pinging and the client closed a live socket 45 s
  later ("ping timeout"). The alarm chain is no longer the heartbeat's only driver:
  - `alarm()` arms the next tick FIRST (before the socket loop and its awaits) and again
    after the work.
  - `ensure_heartbeat`: every inbound frame (before dispatch) and every delivery
    re-reads the alarm; a missing or long-lost one is repaired — a ping now when the
    interval has passed, an alarm for the remainder otherwise (`heartbeat_repair`,
    table-tested; source-pinned).
  - The client half (bsv-low `heartbeatNudge.ts`): when the server ping is 8 s late the
    client sends ONE engine.io `noop`, which is the inbound frame that triggers the
    repair — 33 s < the 45 s cliff, zero frames in the healthy case.
- The broadcast-registry refresh is judged by TIME (`registry_refreshed_at_ms`,
  `REGISTRY_REFRESH_EVERY_MS` = 175 s), replacing the 0.3.5 ping counter whose clobber
  and ordering bugs cost three releases in one day. A confirmed `joinRoom` stamps the
  refresh (the hub registered at join), so the first tick does not re-register.
- TEST-ONLY fault injector `HEARTBEAT_TEST_LOSE_ALARM_AFTER_PONG_EVERY=<n>` (env var;
  absent/0 = off; never in a production config): after every n-th tick's pong the alarm
  is deleted — the platform's loss with its real timing (after the pong, so nothing
  inbound follows) — so the repair is proven red→green against a deployed relay. (A
  first cut skipped the arm inside the alarm handler; the pong 40 ms later repaired it
  every time on beta — belt one proven, fault unfaithful.)

## 0.3.7 — 2026-09-03

### The heartbeat refresh no longer closes the socket it refreshes
- The alarm's Ping arm persisted its copy of the attachment AFTER awaiting the
  registry refresh. The client's pong for that very ping lands during the await and
  persists its own clear of `awaiting_pong_since_ms`; the late write erased it, and the
  next alarm judged the ping unanswered and closed a live socket — once per refresh
  (every 8th ping, ≈200 s after each join; LOW run 12's broadcast subscriber saw
  "transport close" at +213 s and +200 s). The arm now persists first and refreshes
  after; nothing is written to the attachment after the await. Source-pinned.

## 0.3.6 — 2026-09-03

### Broadcast subscribers stay subscribed (the second half of 0.3.5)
- The session's own `joined_rooms` — the list the heartbeat alarm reads to decide
  whether a socket keeps its broadcast-registry entry alive — was declared, persisted
  and read but never WRITTEN (only the per-identity hub tracked rooms). So the
  heartbeat refresh still never ran after 0.3.5 (228 alarms, 0 refreshes in a
  28-minute window) and a live socket went deaf 30 minutes after its join. The routed
  `joinRoom` (once the hub confirmed it) / `leaveRoom` now record membership in the
  session and persist it with the attachment. Pinned by a membership round-trip test
  and a source pin on the routing block.

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
