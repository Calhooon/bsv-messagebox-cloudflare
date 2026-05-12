#!/usr/bin/env node
/**
 * M10 Phase B (#61) proof — BRC-103 mutual authentication over the
 * Socket.IO `authMessage` event, against an UNMODIFIED upstream
 * `@bsv/authsocket-client@2.0.2` client.
 *
 * Why this test matters: the entire bar for Phase B is "drop-in
 * compatibility with the TS authsocket ecosystem". If we have to patch
 * the client, we've broken the contract and downstream consumers
 * (LobsterFarm, the wallet) will not work.
 *
 * What this proves end-to-end:
 *   1. socket.io polling handshake completes against /socket.io/ on
 *      the local Worker (Phase A path still works).
 *   2. The unmodified `@bsv/authsocket-client@2.0.2`, given a fresh
 *      synthetic ProtoWallet, completes its BRC-103 handshake with
 *      our server's `authMessage` driver.
 *   3. After the handshake, the Rust server emits a follow-up
 *      `authenticated` event whose payload contains the verified
 *      identity key. The client decodes it via `peer.listenForGeneralMessages`
 *      and our `socket.on('authenticated', cb)` handler fires.
 *   4. Clean disconnect.
 *
 * Phase A's `tests/e2e_socketio_transport.mjs` is updated separately to
 * assert that pre-auth events are now silently dropped (Phase B
 * authoritatively requires auth before any event surface activates).
 *
 * Exit 0 on success; 1 otherwise. Run with:
 *   npm run dev   # in another shell, wait for "Ready on http://localhost:8787"
 *   node tests/e2e_authsocket_brc103.mjs
 */
import { AuthSocketClient } from "@bsv/authsocket-client";
import { ProtoWallet, PrivateKey } from "@bsv/sdk";

const SERVER = process.env.SERVER_URL || "http://localhost:8787";
const STEP_TIMEOUT_MS = 20_000;

let failures = 0;
function step(label, ok, detail = "") {
  const tag = ok ? "PASS" : "FAIL";
  console.log(`[${tag}] ${label}${detail ? " — " + detail : ""}`);
  if (!ok) failures++;
  return ok;
}

function withTimeout(promise, ms, label) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout: ${label}`)), ms);
    promise.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}

async function run() {
  // 1) Synthetic client wallet (matches the load_gen pattern from M9 #51).
  //    PrivateKey.fromRandom() produces an ephemeral identity that the
  //    server has never seen — proving the handshake doesn't depend on
  //    pre-shared state.
  const clientWallet = new ProtoWallet(PrivateKey.fromRandom());

  // 2) Open the authsocket. The library calls `io(SERVER)` internally
  //    and wires up its BRC-103 Peer + Transport for us.
  let socket;
  try {
    socket = AuthSocketClient(SERVER, {
      wallet: clientWallet,
      managerOptions: {
        // Force-new + no reconnection so a hung handshake doesn't
        // spam the server during debugging.
        forceNew: true,
        reconnection: false,
        timeout: STEP_TIMEOUT_MS,
      },
    });
  } catch (e) {
    step("0. construct AuthSocketClient", false, e?.message || String(e));
    return failures;
  }
  step("0. construct AuthSocketClient", true);

  // 3) Wait for the underlying socket.io 'connect' event — proves the
  //    Phase A polling handshake still completes under the auth wrapper.
  try {
    await withTimeout(
      new Promise((resolve, reject) => {
        socket.on("connect", () => resolve());
        // The auth-client wraps `connect_error` for us; surface anything.
        socket.on("connect_error", (e) => reject(e));
      }),
      STEP_TIMEOUT_MS,
      "socket.io 'connect'",
    );
    step("1. socket.io 'connect' event fires (Phase A path)", true, `id=${socket.id}`);
  } catch (e) {
    step(
      "1. socket.io 'connect' event fires (Phase A path)",
      false,
      e?.message || String(e),
    );
    try {
      socket.disconnect();
    } catch {}
    return failures;
  }

  // 4) Drive the BRC-103 handshake. The TS authsocket-client only
  //    starts the handshake on the *first* `socket.emit(...)` (it lazily
  //    calls peer.toPeer with no identityKey). Our server, on receiving
  //    the InitialRequest, signs an InitialResponse and follows up with
  //    the Phase B `authenticated` event.
  //
  //    From the client's perspective:
  //      - emit('ping', {}) → triggers peer.toPeer → InitialRequest
  //      - server replies InitialResponse → client sends General(ping)
  //      - server's General gets dropped by Phase B (Phase C will route
  //        it), but the InitialResponse alone has flipped the client's
  //        peer state to authenticated and the client's Peer issued a
  //        General with our payload, which we accept-and-drop.
  //      - server's `authenticated` follow-up arrives as a General →
  //        peer.listenForGeneralMessages fires → fires the client's
  //        eventCallbacks for 'authenticated'.
  let authenticatedPayload;
  try {
    authenticatedPayload = await withTimeout(
      new Promise((resolve, reject) => {
        socket.on("authenticated", (data) => resolve(data));
        socket.on("connect_error", (e) => reject(e));
        // Kick the BRC-103 handshake by emitting any event. The arg
        // here is irrelevant; the kick just causes peer.toPeer to fire.
        socket.emit("kickoff", { hello: "phase-b" });
      }),
      STEP_TIMEOUT_MS,
      "BRC-103 handshake → 'authenticated' event",
    );
    step(
      "2. BRC-103 handshake completes; server emits 'authenticated'",
      true,
      `payload=${JSON.stringify(authenticatedPayload)}`,
    );
  } catch (e) {
    step(
      "2. BRC-103 handshake completes; server emits 'authenticated'",
      false,
      e?.message || String(e),
    );
    try {
      socket.disconnect();
    } catch {}
    return failures;
  }

  // 5) The server's `authenticated` payload must include the client's
  //    *verified* identity key — proves the server actually parsed and
  //    signed against the right key, not echoed back something blank.
  try {
    const expectedHex = (
      await clientWallet.getPublicKey({ identityKey: true })
    ).publicKey;
    const reportedHex = authenticatedPayload?.identityKey;
    const ok = typeof reportedHex === "string" && reportedHex === expectedHex;
    step(
      "3. authenticated.identityKey matches client's verified pubkey",
      ok,
      `reported=${reportedHex} expected=${expectedHex}`,
    );
  } catch (e) {
    step(
      "3. authenticated.identityKey matches client's verified pubkey",
      false,
      e?.message || String(e),
    );
  }

  // 6) The client's view of the server's identity must be populated —
  //    proves it received and verified the server's General message.
  try {
    // serverIdentityKey is set by AuthSocketClient inside its
    // listenForGeneralMessages callback. After step 2 fired this MUST
    // be defined — if it's undefined we sent something but it didn't
    // verify.
    const serverKey = socket.serverIdentityKey;
    step(
      "4. client.serverIdentityKey populated (server signature verified)",
      typeof serverKey === "string" && /^[0-9a-fA-F]{66}$/.test(serverKey),
      `serverIdentityKey=${serverKey}`,
    );
  } catch (e) {
    step(
      "4. client.serverIdentityKey populated (server signature verified)",
      false,
      e?.message || String(e),
    );
  }

  // 7) Clean disconnect.
  try {
    await withTimeout(
      new Promise((resolve) => {
        socket.on("disconnect", () => resolve());
        socket.disconnect();
      }),
      5_000,
      "disconnect",
    );
    step("5. clean disconnect", true);
  } catch (e) {
    step("5. clean disconnect", false, e?.message || String(e));
  }

  return failures;
}

run().then(
  (n) => {
    console.log("");
    console.log(`=== Result: ${n === 0 ? "OK" : "FAIL"} (${n} failure(s)) ===`);
    process.exit(n === 0 ? 0 : 1);
  },
  (e) => {
    console.error(`UNCAUGHT: ${e?.stack || e}`);
    process.exit(1);
  },
);
