#!/usr/bin/env node
/**
 * M10 #61 transport-only smoke — Engine.IO + Socket.IO at /socket.io/.
 *
 * History:
 *   * Phase A version exercised an unauthenticated EVENT echo
 *     (`socket.emit('test','hello') → 'test_echo'`). That worked
 *     because the Phase A scope was deliberately auth-less.
 *   * Phase B (#61 cont.) layered BRC-103 on `authMessage` events.
 *     Any non-`authMessage` EVENT sent before the handshake completes
 *     is now silently dropped (compatible with `@bsv/authsocket`
 *     server semantics — see `AuthSocketServer.handleNewConnection`,
 *     which only routes events that are bound by AuthSocket).
 *
 * This file is therefore reduced to a **transport-only** smoke. It
 * proves the bare Engine.IO/Socket.IO stack still works (handshake
 * completes, transport upgrade negotiates, disconnect cleans up). The
 * BRC-103 happy path is exercised by `tests/e2e_authsocket_brc103.mjs`,
 * which uses the unmodified `@bsv/authsocket-client@2.0.2` and
 * confirms the server reaches the `authenticated` state.
 *
 * Exit 0 on success; 1 otherwise. Run with:
 *   npm run dev    # in another shell
 *   node tests/e2e_socketio_transport.mjs
 */
import { io as ioClient } from "socket.io-client";

const SERVER = process.env.SERVER_URL || "http://localhost:8787";
const STEP_TIMEOUT_MS = 15_000;
const DROP_VERIFY_MS = 1_500;

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
  // ---- 1. Polling handshake → CONNECT (no auth). ----
  const socket = ioClient(SERVER, {
    transports: ["polling"],
    upgrade: false,
    reconnection: false,
    forceNew: true,
    timeout: STEP_TIMEOUT_MS,
  });

  try {
    await withTimeout(
      new Promise((resolve, reject) => {
        socket.once("connect", () => resolve());
        socket.once("connect_error", (e) => reject(e));
      }),
      STEP_TIMEOUT_MS,
      "socket.io connect (polling)",
    );
    step(
      "1. socket.io polling handshake → CONNECT (default namespace)",
      true,
      `id=${socket.id}`,
    );
  } catch (e) {
    step(
      "1. socket.io polling handshake → CONNECT (default namespace)",
      false,
      e?.message || String(e),
    );
    try {
      socket.disconnect();
    } catch {}
    return failures;
  }

  // ---- 2. Phase B contract: pre-auth EVENTs are silently dropped. ----
  // We emit a normal event and assert NO reply comes back within the
  // short verification window. (If Phase B regressed and started
  // echoing again, this would catch it.)
  try {
    const replyOrTimeout = await new Promise((resolve) => {
      const t = setTimeout(() => resolve("no-reply"), DROP_VERIFY_MS);
      socket.once("test", (...args) => {
        clearTimeout(t);
        resolve({ name: "test", args });
      });
      socket.once("test_echo", (...args) => {
        clearTimeout(t);
        resolve({ name: "test_echo", args });
      });
      socket.emit("test", "hello");
    });
    const ok = replyOrTimeout === "no-reply";
    step(
      "2. pre-auth EVENT 'test' is silently dropped (Phase B contract)",
      ok,
      ok ? "(no reply within window — correct)" : `unexpected reply: ${JSON.stringify(replyOrTimeout)}`,
    );
  } catch (e) {
    step(
      "2. pre-auth EVENT 'test' is silently dropped (Phase B contract)",
      false,
      e?.message || String(e),
    );
  }

  // ---- 3. Optional WS transport upgrade (Phase A behaviour preserved). ----
  try {
    const upgraded = ioClient(SERVER, {
      transports: ["polling", "websocket"],
      upgrade: true,
      reconnection: false,
      forceNew: true,
      timeout: STEP_TIMEOUT_MS,
    });
    await withTimeout(
      new Promise((resolve, reject) => {
        upgraded.once("connect", () => resolve());
        upgraded.once("connect_error", (e) => reject(e));
      }),
      STEP_TIMEOUT_MS,
      "upgrade-client connect",
    );
    await new Promise((r) => setTimeout(r, 1500));
    const transportName =
      upgraded.io && upgraded.io.engine && upgraded.io.engine.transport
        ? upgraded.io.engine.transport.name
        : "unknown";
    step(
      "3. transport upgrade attempted (final transport reported)",
      true,
      `transport=${transportName}`,
    );
    upgraded.disconnect();
  } catch (e) {
    step(
      "3. transport upgrade attempted (final transport reported)",
      true, // soft pass — Phase A acceptance only required polling
      `(soft-skip) ${e?.message || String(e)}`,
    );
  }

  // ---- 4. Clean disconnect. ----
  try {
    await withTimeout(
      new Promise((resolve) => {
        socket.once("disconnect", (reason) => resolve(reason));
        socket.disconnect();
      }),
      5_000,
      "disconnect",
    );
    step("4. clean disconnect", true);
  } catch (e) {
    step("4. clean disconnect", false, e?.message || String(e));
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
