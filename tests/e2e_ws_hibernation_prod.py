#!/usr/bin/env python3
"""M9 #50 — hibernation observation against deployed prod.

Tests that a MessageHub Durable Object instance correctly survives an
idle period and wakes to handle subsequent frames. This is the
functional proof that the workers-rs 0.8 hibernation contract holds in
production:

  - DO accepts a WS upgrade and writes the per-socket attachment
  - DO goes idle (no inbound frames) — Cloudflare hibernates it
    silently after the platform's idle threshold (~30 s typical)
  - The WebSocket stays open at the edge (raw socket survives;
    workers-rs handles the bookkeeping)
  - When the next frame arrives, the runtime de-hibernates the DO,
    rebuilds the attachment from `serialize_attachment`, and the
    handler runs as if no time had passed

Failure mode characterization:
  - If hibernation didn't engage AT ALL, the DO would stay in memory
    the whole time. The test still passes — but Cloudflare bills full
    Duration. Cost-model failure, not functional failure.
  - If hibernation engaged but wake failed, the second frame would
    error or the socket would close. Test fails loudly.
  - If wake works but attachment was lost, the joinRoom check would
    pass but subsequent identity-bound behavior would diverge.

This test only proves the WAKE half of the cost model. Confirming
the BILLING half (Duration → 0 during hibernation) requires querying
Cloudflare Analytics — see RESULTS.md note appended after the test.

Requires: MetaNet wallet at localhost:3321 (signs the BRC-31 upgrade
for the deployed prod URL).

Usage:
    python3 tests/e2e_ws_hibernation_prod.py [--idle-seconds N]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

# Reuse the proven signing helper from #41/#42 — same code path, just
# pointed at the prod URL.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e_ws_lifecycle import build_signed_ws_headers  # noqa: E402

try:
    import websockets  # noqa: F401
    from websockets.asyncio.client import connect
except ImportError as e:
    print(f"FAIL: websockets not importable: {e}")
    sys.exit(1)


PROD_HTTP = "https://rust-message-box.dev-a3e.workers.dev"
PROD_WS = "wss://rust-message-box.dev-a3e.workers.dev/ws"
RECV_TIMEOUT_S = 10.0  # generous for prod
DEFAULT_IDLE_S = 60.0  # > 30 s threshold; should engage hibernation


def step(label: str, ok: bool, detail: str = "") -> bool:
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {label}" + (f" — {detail}" if detail else ""), flush=True)
    return ok


async def run(idle_seconds: float) -> int:
    failures = 0
    headers = build_signed_ws_headers(PROD_HTTP, PROD_WS)
    identity_key = headers.get("x-bsv-auth-identity-key", "?")
    own_room = f"{identity_key}-inbox"

    if not step(
        "0. Built signed BRC-31 headers for prod /ws",
        bool(identity_key) and identity_key != "?",
        f"identityKey={identity_key[:8]}…",
    ):
        return 1

    try:
        ws = await asyncio.wait_for(
            connect(PROD_WS, additional_headers=headers),
            timeout=RECV_TIMEOUT_S,
        )
        step("1. WS handshake to prod (101)", True, f"connected to {PROD_WS}")
    except Exception as e:
        step("1. WS handshake to prod (101)", False, f"{type(e).__name__}: {e}")
        return 1

    try:
        # --- Step 2: receive `connected` greeting ---
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_S)
            env = json.loads(raw)
            ok = (
                env.get("event") == "connected"
                and env.get("data", {}).get("identityKey") == identity_key
            )
            step(
                "2. `connected` envelope on prod with verified identityKey",
                ok,
                f"received={env}",
            )
            if not ok:
                failures += 1
        except Exception as e:
            step("2. `connected` envelope on prod", False, f"{type(e).__name__}: {e}")
            return 1

        # --- Step 3: prime the DO with a joinRoom (instantiates state) ---
        await ws.send(json.dumps({
            "event": "joinRoom",
            "data": {"roomId": own_room},
        }))
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_S)
            env = json.loads(raw)
            ok = (
                env.get("event") == "joinedRoom"
                and env.get("data", {}).get("roomId") == own_room
            )
            step(
                "3. Pre-idle joinRoom → joinedRoom (DO state primed)",
                ok,
                f"received={env}",
            )
            if not ok:
                failures += 1
        except Exception as e:
            step("3. Pre-idle joinRoom", False, f"{type(e).__name__}: {e}")
            failures += 1

        # --- Step 4: idle for N seconds ---
        # During this gap, the DO should hibernate. The WS stays open at
        # the edge. workers-rs's auto-response handles ping frames
        # without waking the DO.
        t0 = time.monotonic()
        print(f"  --- idling {idle_seconds:.0f}s (longer than the ~30s "
              f"hibernation threshold) ---", flush=True)
        await asyncio.sleep(idle_seconds)
        elapsed = time.monotonic() - t0
        step(
            f"4. Idled for >= {idle_seconds:.0f}s without sending or "
            f"receiving frames",
            elapsed >= idle_seconds * 0.95,
            f"elapsed={elapsed:.2f}s",
        )

        # --- Step 5: WAKE TEST. Send a frame; DO should de-hibernate ---
        # If hibernation broke wake, this would error or the socket
        # would close. If attachment serialization broke, joinedRoom
        # would still come back but subsequent state-bound behavior
        # would diverge. We test joinRoom (idempotent) so a re-join is
        # observable as a `joinedRoom` (the DO should de-dup if room is
        # already joined, but our impl just re-emits the success — both
        # outcomes confirm DO responsiveness).
        wake_t0 = time.monotonic()
        await ws.send(json.dumps({
            "event": "joinRoom",
            "data": {"roomId": own_room},
        }))
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_S)
            wake_ms = (time.monotonic() - wake_t0) * 1000
            env = json.loads(raw)
            ok = env.get("event") == "joinedRoom"
            step(
                "5. POST-IDLE WAKE: joinRoom → joinedRoom (DO de-hibernated)",
                ok,
                f"wake_latency_ms={wake_ms:.1f} received={env}",
            )
            if not ok:
                failures += 1
        except Exception as e:
            step("5. POST-IDLE WAKE", False, f"{type(e).__name__}: {e}")
            failures += 1

        # --- Step 6: clean close ---
        try:
            await asyncio.wait_for(ws.close(code=1000, reason="test done"),
                                   timeout=RECV_TIMEOUT_S)
            cc = getattr(ws, "close_code", None)
            ok = cc in (1000, None)
            step("6. Clean close", ok, f"close_code={cc}")
            if not ok:
                failures += 1
        except Exception as e:
            step("6. Clean close", False, f"{type(e).__name__}: {e}")
            failures += 1
    finally:
        try:
            await ws.close()
        except Exception:
            pass

    print()
    print(f"=== Result: {('OK' if failures == 0 else 'FAIL')} "
          f"({failures} failure(s)) ===", flush=True)
    return 0 if failures == 0 else 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--idle-seconds", type=float, default=DEFAULT_IDLE_S,
                   help=f"how long to idle (default {DEFAULT_IDLE_S}s)")
    args = p.parse_args()
    try:
        return asyncio.run(run(args.idle_seconds))
    except KeyboardInterrupt:
        print("FAIL: interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
