#!/usr/bin/env node
/**
 * M10 #61 Phase D — End-to-end proof that the UNMODIFIED official
 * `@bsv/message-box-client` (the high-level client app authors actually
 * `npm install`) wires up against our Rust shim.
 *
 * Phase A/B/C already proved the lower-level @bsv/authsocket-client
 * surface works against our /socket.io/ shim. Phase D is one level up
 * the stack: construct an unmodified `MessageBoxClient` from the npm
 * package and exercise the methods app code actually calls.
 *
 * What this test exercises (every method that does NOT require a second
 * paid wallet):
 *   - new MessageBoxClient({ host, walletClient, networkPreset: 'local' })
 *   - client.init()                          (now a no-op besides identity fetch in v2.1.1)
 *   - client.getIdentityKey()
 *   - client.listenForLiveMessages({ messageBox, onMessage })
 *       └─ implicitly: initializeConnection() + joinRoom() + WS subscribe
 *   - client.sendMessage({ recipient, messageBox, body })   ← HTTP /sendMessage
 *   - client.sendLiveMessage({ recipient, messageBox, body }) ← WS sendMessage
 *   - client.listMessages({ messageBox, host })             ← HTTP /listMessages
 *   - client.acknowledgeMessage({ messageIds, host })       ← HTTP /acknowledgeMessage
 *   - client.leaveRoom(messageBox)
 *   - client.disconnectWebSocket()
 *
 * WHY two synthetic identities (Alice + Bob): WS broadcast routing only
 * exercises the cross-DO push path when sender ≠ recipient. Single-id
 * self-send hits the same MessageHub DO via `idFromName(X)` and only
 * proves the intra-DO path. With Alice + Bob the broadcast must hop
 * from Bob's DO to Alice's DO via the internal /__internal/push channel.
 *
 * WHAT THIS TEST DOES NOT EXERCISE:
 *   - anointHost / queryAdvertisements / overlay routing — these need
 *     `walletClient.createAction()` which ProtoWallet does not
 *     implement. We pass `host` explicitly to all methods so the
 *     overlay paths are bypassed. (Note: v2.1.1 init() no longer calls
 *     anointHost automatically — it's now a manual op.)
 *   - checkPermissions=true → quote → payment → recipient internalize
 *     loop. That requires real sats and a wallet at :3321, covered by
 *     tests/e2e_payment.py.
 *   - sendMesagetoRecepients (multi-recipient) — also needs real sats.
 *   - All `permissions/*` methods — covered by tests/e2e_parity.sh.
 *   - Device registration — server-side fully tested by e2e_parity.sh.
 *
 * RUNS AGAINST:
 *   1. Local wrangler dev (http://localhost:8787) — full Phase A+B+C code path
 *   2. Deployed prod (https://rust-message-box.dev-a3e.workers.dev)
 *
 * IMPORTANT — PROD CAVEAT (per orchestrator hint):
 *   The deployed prod (commit f85e0bb) is still on M9 head; Phase A/B/C
 *   has NOT been deployed yet at the time this test was authored.
 *   Therefore the prod run is a "what works today" smoke test:
 *     - HTTP-only methods (sendMessage, listMessages, acknowledgeMessage)
 *       must work because they predate Phase A/B/C.
 *     - Anything that requires the socket.io transport (sendLiveMessage,
 *       listenForLiveMessages) is EXPECTED TO FAIL on prod until a
 *       deploy of m10-socketio occurs. We do not count those as test
 *       failures — they are recorded as 'EXPECTED-FAIL (prod not on
 *       Phase A/B/C yet)'.
 *
 *   Once Phase A/B/C ships to prod, change PROD_HAS_SOCKETIO=true at
 *   the top of run() and the prod path will be held to the same bar
 *   as local.
 *
 * Exit 0 if all REQUIRED checks pass against both local and prod;
 * 1 otherwise. Run with:
 *   npm run dev                                              # in another shell
 *   node tests/e2e_message_box_client_full.mjs
 */
import { MessageBoxClient } from "@bsv/message-box-client";
import { ProtoWallet, PrivateKey } from "@bsv/sdk";
import http from "node:http";
import https from "node:https";

const LOCAL_HOST = process.env.LOCAL_URL || "http://localhost:8787";
const PROD_HOST =
  process.env.PROD_URL || "https://rust-message-box.dev-a3e.workers.dev";

const STEP_TIMEOUT_MS = 30_000;
const RECV_TIMEOUT_MS = 8_000;

let totalFailures = 0;

function step(label, ok, detail = "", expectedFail = false) {
  if (expectedFail && !ok) {
    console.log(`[XFAIL] ${label}${detail ? " — " + detail : ""}`);
    return false;
  }
  const tag = ok ? "PASS" : "FAIL";
  console.log(`[${tag}] ${label}${detail ? " — " + detail : ""}`);
  if (!ok && !expectedFail) totalFailures++;
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

function urlGet(target) {
  const isHttps = target.startsWith("https:");
  const lib = isHttps ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.get(target, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (buf += c));
      res.on("end", () =>
        resolve({ status: res.statusCode || 0, body: buf }),
      );
    });
    req.on("error", reject);
  });
}

/**
 * Run one full Alice+Bob round-trip against `host`, returning failure
 * count for that environment. `socketioExpected` controls whether the
 * WS-dependent steps are XFAIL'd (prod) or counted as real failures
 * (local).
 */
async function runAgainst(envLabel, host, socketioExpected) {
  console.log("");
  console.log("============================================================");
  console.log(`  Environment: ${envLabel}  (host=${host})`);
  console.log(`  socketio expected to work: ${socketioExpected}`);
  console.log("============================================================");

  let envFails = 0;
  function envStep(label, ok, detail = "", isWsStep = false) {
    const xfail = isWsStep && !socketioExpected;
    if (!ok && !xfail) envFails++;
    return step(`[${envLabel}] ${label}`, ok, detail, xfail);
  }

  // 0. Sanity: server is up.
  try {
    const res = await urlGet(`${host}/api-docs`);
    envStep(
      "0. server is up at /api-docs",
      res.status === 200,
      `status=${res.status}`,
    );
  } catch (e) {
    envStep("0. server is up at /api-docs", false, e?.message || String(e));
    return envFails;
  }

  // 1. Construct two MessageBoxClients backed by ProtoWallet (synthetic id).
  const aliceWallet = new ProtoWallet(PrivateKey.fromRandom());
  const bobWallet = new ProtoWallet(PrivateKey.fromRandom());

  const alice = new MessageBoxClient({
    host,
    walletClient: aliceWallet,
    networkPreset: "local", // bypasses overlay/SHIP lookups (we pass host explicitly)
    enableLogging: false,
  });
  const bob = new MessageBoxClient({
    host,
    walletClient: bobWallet,
    networkPreset: "local",
    enableLogging: false,
  });

  // 2. init() — v2.1.1 just fetches the identity key. No anointHost.
  let aliceId, bobId;
  try {
    await withTimeout(alice.init(), STEP_TIMEOUT_MS, "alice.init()");
    await withTimeout(bob.init(), STEP_TIMEOUT_MS, "bob.init()");
    aliceId = await alice.getIdentityKey();
    bobId = await bob.getIdentityKey();
    envStep(
      "1. MessageBoxClient construction + init() + getIdentityKey()",
      typeof aliceId === "string" &&
        typeof bobId === "string" &&
        aliceId.length === 66 &&
        bobId.length === 66 &&
        aliceId !== bobId,
      `alice=${aliceId.slice(0, 10)}.. bob=${bobId.slice(0, 10)}..`,
    );
  } catch (e) {
    envStep(
      "1. MessageBoxClient construction + init() + getIdentityKey()",
      false,
      e?.message || String(e),
    );
    return envFails;
  }

  // 3. Bob → Alice over HTTP sendMessage. This is the bread-and-butter path
  //    used by any app that just wants to drop a message and not subscribe.
  //    `inbox` has fee=0 (default per CLAUDE.md), so no payment needed.
  const httpMessageBody = `phase-d-http-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  let httpMessageId = null;
  try {
    const result = await withTimeout(
      bob.sendMessage(
        {
          recipient: aliceId,
          messageBox: "inbox",
          body: httpMessageBody,
          // skipEncryption omitted: client encrypts via BRC-2 by default
        },
        host, // overrideHost → bypass overlay lookup
      ),
      STEP_TIMEOUT_MS,
      "bob.sendMessage() over HTTP",
    );
    httpMessageId = result.messageId;
    envStep(
      "2. bob.sendMessage(HTTP) → status=success + messageId returned",
      result.status === "success" && typeof httpMessageId === "string",
      `messageId=${httpMessageId?.slice(0, 16)}.. status=${result.status}`,
    );
  } catch (e) {
    envStep(
      "2. bob.sendMessage(HTTP) → status=success + messageId returned",
      false,
      e?.message || String(e),
    );
  }

  // 4. Alice listMessages — must contain Bob's HTTP message and be decrypted
  //    back to the original plaintext. listMessages internally calls
  //    walletClient.decrypt() with counterparty=sender, so this proves the
  //    encrypt→D1→decrypt round trip end-to-end.
  let aliceMsgs = [];
  try {
    aliceMsgs = await withTimeout(
      alice.listMessages({
        messageBox: "inbox",
        host, // bypass overlay
        acceptPayments: false, // ProtoWallet has no internalizeAction
      }),
      STEP_TIMEOUT_MS,
      "alice.listMessages()",
    );
    const found = aliceMsgs.find((m) => m.messageId === httpMessageId);
    const decryptedOk =
      !!found && (found.body === httpMessageBody || found.body === `"${httpMessageBody}"`);
    envStep(
      "3. alice.listMessages() returns Bob's HTTP message + decrypts body",
      decryptedOk,
      found
        ? `body=${JSON.stringify(found.body).slice(0, 80)} sender=${String(found.sender).slice(0, 10)}..`
        : `not found among ${aliceMsgs.length} messages`,
    );
  } catch (e) {
    envStep(
      "3. alice.listMessages() returns Bob's HTTP message + decrypts body",
      false,
      e?.message || String(e),
    );
  }

  // 5. Alice subscribes to live messages (this opens the AuthSocketClient,
  //    completes BRC-103 handshake, and joinRoom's <alice>-inbox).
  let liveReceived = null;
  let liveResolver;
  const livePromise = new Promise((r) => {
    liveResolver = r;
  });
  try {
    await withTimeout(
      alice.listenForLiveMessages({
        messageBox: "inbox",
        onMessage: (msg) => {
          liveReceived = msg;
          liveResolver(msg);
        },
        overrideHost: host,
      }),
      STEP_TIMEOUT_MS,
      "alice.listenForLiveMessages()",
    );
    envStep(
      "4. alice.listenForLiveMessages() (AuthSocket connect + BRC-103 + joinRoom)",
      true,
      "subscribed",
      true, // WS step
    );
  } catch (e) {
    envStep(
      "4. alice.listenForLiveMessages() (AuthSocket connect + BRC-103 + joinRoom)",
      false,
      e?.message || String(e),
      true, // WS step — XFAIL on prod
    );
    // If WS subscribe failed and prod doesn't have it yet, skip the WS-send step.
    if (socketioExpected) {
      // hard fail in local — do nothing extra
    } else {
      // proceed to disconnect/leave gracefully and finish env
      try {
        await alice.disconnectWebSocket();
      } catch {}
      return envFails;
    }
  }

  // 6. Bob sends a LIVE message to Alice (sendLiveMessage). This goes
  //    through the WS sendMessage event with ack, AND also broadcasts to
  //    Alice (who has joined her own inbox room), which triggers her
  //    onMessage callback above.
  const liveMessageBody = `phase-d-live-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  let liveSendResult = null;
  try {
    liveSendResult = await withTimeout(
      bob.sendLiveMessage(
        {
          recipient: aliceId,
          messageBox: "inbox",
          body: liveMessageBody,
        },
        host,
      ),
      STEP_TIMEOUT_MS,
      "bob.sendLiveMessage()",
    );
    envStep(
      "5. bob.sendLiveMessage() → status=success ack from server",
      liveSendResult?.status === "success" &&
        typeof liveSendResult?.messageId === "string",
      `result=${JSON.stringify(liveSendResult).slice(0, 120)}`,
      true, // WS step
    );
  } catch (e) {
    envStep(
      "5. bob.sendLiveMessage() → status=success ack from server",
      false,
      e?.message || String(e),
      true, // WS step
    );
  }

  // 7. Alice's listenForLiveMessages onMessage handler fired with the live message.
  try {
    await withTimeout(livePromise, RECV_TIMEOUT_MS, "alice live onMessage");
    // body is decrypted in-handler; should equal original plaintext (or possibly its JSON-string form).
    const liveOk =
      !!liveReceived &&
      (liveReceived.body === liveMessageBody ||
        liveReceived.body === `"${liveMessageBody}"`) &&
      liveReceived.sender === bobId;
    envStep(
      "6. alice.onMessage(live) fires with decrypted body + sender=bob",
      liveOk,
      liveReceived
        ? `body=${JSON.stringify(liveReceived.body).slice(0, 60)} sender=${String(liveReceived.sender).slice(0, 10)}..`
        : "no message received",
      true, // WS step
    );
  } catch (e) {
    envStep(
      "6. alice.onMessage(live) fires with decrypted body + sender=bob",
      false,
      e?.message || String(e),
      true, // WS step
    );
  }

  // 8. Alice acknowledges all of Bob's messages — proves /acknowledgeMessage
  //    deletes from D1.
  try {
    const ids = aliceMsgs.map((m) => m.messageId);
    if (liveSendResult?.messageId && !ids.includes(liveSendResult.messageId)) {
      ids.push(liveSendResult.messageId);
    }
    if (ids.length > 0) {
      const ackResult = await withTimeout(
        alice.acknowledgeMessage({ messageIds: ids, host }),
        STEP_TIMEOUT_MS,
        "alice.acknowledgeMessage()",
      );
      envStep(
        "7. alice.acknowledgeMessage() → status=success",
        ackResult === "success",
        `result=${ackResult} (acked ${ids.length} ids)`,
      );

      // 8b. Re-list — should be empty (or at least exclude the acked ids).
      const afterAck = await withTimeout(
        alice.listMessages({
          messageBox: "inbox",
          host,
          acceptPayments: false,
        }),
        STEP_TIMEOUT_MS,
        "alice.listMessages() post-ack",
      ).catch((e) => {
        // if no messages, listMessages may throw; accept that as proof of cleanup
        if (String(e).includes("Failed to retrieve messages")) return [];
        throw e;
      });
      const stillThere = afterAck.filter((m) => ids.includes(m.messageId));
      envStep(
        "8. alice.listMessages() after ack: previously-acked ids are gone",
        stillThere.length === 0,
        `${stillThere.length} of ${ids.length} acked ids still present (expected 0)`,
      );
    } else {
      envStep(
        "7. alice.acknowledgeMessage() → status=success",
        false,
        "no messageIds collected to ack — earlier steps must have failed",
      );
    }
  } catch (e) {
    envStep(
      "7. alice.acknowledgeMessage() → status=success",
      false,
      e?.message || String(e),
    );
  }

  // 9. leaveRoom + disconnect.
  try {
    await withTimeout(alice.leaveRoom("inbox"), 5000, "alice.leaveRoom()");
    await withTimeout(
      alice.disconnectWebSocket(),
      5000,
      "alice.disconnectWebSocket()",
    );
    // bob never opened a WS in HTTP-only mode unless sendLiveMessage was called.
    if (bob.testSocket) {
      await withTimeout(
        bob.disconnectWebSocket(),
        5000,
        "bob.disconnectWebSocket()",
      );
    }
    envStep(
      "9. leaveRoom + disconnectWebSocket clean teardown",
      true,
      "ok",
      true, // tagged WS-step because leaveRoom needs the socket
    );
  } catch (e) {
    envStep(
      "9. leaveRoom + disconnectWebSocket clean teardown",
      false,
      e?.message || String(e),
      true,
    );
  }

  return envFails;
}

async function run() {
  // Phase A/B/C/D-fix deployed to prod 2026-05-11 (version dd764f3d):
  // prod must pass the WS-dependent steps too.
  const PROD_HAS_SOCKETIO = true;

  const localFails = await runAgainst("LOCAL", LOCAL_HOST, true);
  const prodFails = await runAgainst("PROD ", PROD_HOST, PROD_HAS_SOCKETIO);

  console.log("");
  console.log("============================================================");
  console.log(
    `  LOCAL failures: ${localFails}    PROD (required) failures: ${prodFails}`,
  );
  console.log(
    `  TOTAL failures: ${totalFailures}    (XFAIL'd WS steps on prod do not count)`,
  );
  console.log("============================================================");

  return totalFailures;
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
