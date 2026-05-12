#!/usr/bin/env python3
"""
M9 #45 + #48 proof: HTTP→WS push bridge end-to-end.

When a successful HTTP POST /sendMessage stores a message into D1, the
recipient DO MUST broadcast a `sendMessage` envelope to any of that
identity's currently-connected sockets that have joined the matching
`<recipient>-<message_box>` room. This test is the live, REAL proof:

  1. Open WS as identity-X with BRC-31 signed headers.
  2. Receive `connected` greeting.
  3. joinRoom("<X>-inbox") → joinedRoom.
  4. HTTP POST /sendMessage from identity-X to recipient X (self) in
     the `inbox` box (free; no payment needed).
  5. Within RECV_TIMEOUT_S the WS receives the matching `sendMessage`
     envelope. Assert event name, roomId, sender, messageId, body all
     match what HTTP sent.
  6. Clean up: HTTP acknowledgeMessage so reruns are clean. Close WS.

## Cross-identity scope (Approach A)

The MetaNet wallet at localhost:3321 holds exactly ONE identity (see
EXPECTED_IDENTITY below). A true cross-identity test would need a
second wallet running on a different port — which is not available
in this environment. Rather than fabricate a second identity by
spoofing a key the wallet doesn't actually hold (which would defeat
the whole point of an end-to-end proof), we run the SELF-SUBSCRIBE
variant: identity X subscribes via WS and HTTP-sends to itself.

This still exercises the full bridge:

   * HTTP-side: process_send → insert_message → push_to_recipient_sockets
   * Bridge:   POST /internal/push to MESSAGE_HUB.idFromName(X) stub
   * DO-side: handle_internal_push → iterate sockets → emit_send_message
   * WS-side: subscribing socket receives the envelope

The DO instance is the same on both sides because both endpoints
resolve `idFromName(X)` to the same DO — exactly the same path a
true cross-identity send would take from the recipient's POV.

Each step prints PASS/FAIL on its own line. Exits non-zero on any
failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# x402-client deps (re-used from tests/e2e_ws_lifecycle.py)
# ---------------------------------------------------------------------------
X402_CLIENT_DIR = "../x402-client"
sys.path.insert(0, X402_CLIENT_DIR)

from lib.handshake import get_or_create_session  # noqa: E402
from lib.headers import filter_signable_headers, build_auth_headers  # noqa: E402
from lib.metanet import get_identity_key, create_signature  # noqa: E402
import lib.metanet as metanet  # noqa: E402
from lib.nonce import generate_nonce, generate_request_id, nonce_to_base64  # noqa: E402
from lib.serialize import serialize_request  # noqa: E402
from lib.auth_request import authenticated_request  # noqa: E402

try:
    import websockets  # noqa: F401
    from websockets.asyncio.client import connect
except ImportError as e:  # pragma: no cover
    print(f"FAIL: websockets package not importable: {e}")
    sys.exit(1)


SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8787")
WS_URL = os.environ.get("WS_URL", "ws://localhost:8787/ws")
WALLET_PORT = int(os.environ.get("WALLET_PORT", "3321"))
# Spec says 3 seconds — push fan-out is in-process Worker→DO so it
# should land in well under that.
RECV_TIMEOUT_S = 3.0
HANDSHAKE_TIMEOUT_S = 10.0

# Wallet identity (matches tests/e2e_ws_lifecycle.py and e2e_live_parity.py).
# This is identity-X for the self-subscribe Approach A.
EXPECTED_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"

# Point the metanet client at the local wallet (matches sibling tests).
metanet.METANET_URL = f"http://localhost:{WALLET_PORT}"

# BRC-31 protocol id used for general-message signatures.
AUTH_PROTOCOL = [2, "auth message signature"]


def step(label: str, ok: bool, detail: str = "") -> bool:
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {label}"
    if detail:
        line += f" — {detail}"
    print(line, flush=True)
    return ok


def build_signed_ws_headers(server_url: str, ws_url: str) -> dict[str, str]:
    """Build BRC-31 signed headers for a `GET /ws` upgrade.

    Mirrors tests/e2e_ws_lifecycle.py::build_signed_ws_headers. Inlined
    rather than imported because the lifecycle test is a module-less
    script under tests/.
    """
    session = get_or_create_session(server_url.rstrip("/"))

    parsed = urlparse(ws_url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else None

    msg_nonce_bytes = generate_nonce()
    msg_nonce_b64 = nonce_to_base64(msg_nonce_bytes)
    request_id_bytes = generate_request_id()
    request_id_b64 = nonce_to_base64(request_id_bytes)

    extra_headers: dict[str, str] = {}
    signable_headers = filter_signable_headers(extra_headers)

    serialized = serialize_request(
        request_id_bytes=request_id_bytes,
        method="GET",
        path=path,
        query=query,
        signable_headers=signable_headers,
        body=None,
    )

    key_id = f"{msg_nonce_b64} {session.server_nonce_b64}"
    signature = create_signature(
        data=serialized,
        protocol_id=AUTH_PROTOCOL,
        key_id=key_id,
        counterparty=session.server_identity_key,
    )

    my_identity_key = get_identity_key()
    auth_headers = build_auth_headers(
        identity_key=my_identity_key,
        message_type="general",
        nonce_b64=msg_nonce_b64,
        your_nonce_b64=session.server_nonce_b64,
        signature_hex=signature.hex(),
        request_id_b64=request_id_b64,
    )

    return {**extra_headers, **auth_headers}


async def send_event(ws, event: str, data: dict) -> None:
    await ws.send(json.dumps({"event": event, "data": data}))


async def recv_envelope(ws, timeout: float = RECV_TIMEOUT_S) -> dict:
    """Receive next text frame and parse as the {event,data} envelope."""
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    if not isinstance(raw, str):
        raise AssertionError(f"expected text frame, got {type(raw).__name__}: {raw!r}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or "event" not in parsed or "data" not in parsed:
        raise AssertionError(f"frame is not an event envelope: {raw!r}")
    return parsed


async def recv_specific_event(ws, want_event: str, timeout: float = RECV_TIMEOUT_S) -> dict:
    """Receive the next envelope whose `event` field equals `want_event`.

    Drops any unexpected envelopes (e.g. the `sendMessageAck` echoed back
    on the WS write path doesn't apply here — the HTTP path doesn't
    emit one — but we keep this for forward-compat). Aggregate timeout
    across all reads is the supplied `timeout`.
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError(f"no `{want_event}` event within {timeout}s")
        env = await recv_envelope(ws, timeout=remaining)
        if env.get("event") == want_event:
            return env
        # Anything else is unexpected on this socket at this point.
        # Print for diagnostics but keep waiting.
        print(f"  (skipped unexpected event while waiting for `{want_event}`: {env!r})",
              flush=True)


async def run() -> int:
    failures = 0
    ws = None

    # --- Step 0: build signed headers ---
    try:
        headers = build_signed_ws_headers(SERVER_URL, WS_URL)
        step(
            "0. Built signed BRC-31 headers for GET /ws",
            True,
            f"identityKey={headers.get('x-bsv-auth-identity-key')}",
        )
    except Exception as e:  # noqa: BLE001
        step(
            "0. Built signed BRC-31 headers for GET /ws",
            False,
            f"{type(e).__name__}: {e}",
        )
        return 1

    # --- Step 1: handshake ---
    try:
        ws = await asyncio.wait_for(
            connect(WS_URL, additional_headers=headers),
            timeout=HANDSHAKE_TIMEOUT_S,
        )
        step("1. WS handshake at /ws (101 Switching Protocols)", True,
             f"connected to {WS_URL}")
    except Exception as e:  # noqa: BLE001
        step("1. WS handshake at /ws (101 Switching Protocols)", False,
             f"{type(e).__name__}: {e}")
        return 1

    msg_id = ""

    try:
        # --- Step 2: server-initiated `connected` greeting ---
        try:
            env = await recv_envelope(ws)
            ok = (
                env.get("event") == "connected"
                and isinstance(env.get("data"), dict)
                and env["data"].get("identityKey") == EXPECTED_IDENTITY
            )
            failures += 0 if step(
                "2. First server frame is `connected` envelope with verified identityKey",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "2. First server frame is `connected` envelope with verified identityKey",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        own_room = f"{EXPECTED_IDENTITY}-inbox"

        # --- Step 3: joinRoom(own inbox) → joinedRoom ---
        try:
            await send_event(ws, "joinRoom", {"roomId": own_room})
            env = await recv_envelope(ws)
            ok = (
                env.get("event") == "joinedRoom"
                and isinstance(env.get("data"), dict)
                and env["data"].get("roomId") == own_room
            )
            failures += 0 if step(
                "3. joinRoom for own inbox room → joinedRoom",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "3. joinRoom for own inbox room → joinedRoom",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 4: HTTP POST /sendMessage from X to X in `inbox` ---
        # `inbox` has delivery_fee=0 and the default per-recipient fee
        # is 0 — no payment payload required. The push hook lands
        # AFTER successful insert_message in process_send.
        msg_id = f"e2e-ws-sub-{int(time.time() * 1000)}"
        msg_body = f"hello-bridge-{msg_id}"
        try:
            resp = authenticated_request(
                method="POST",
                url=f"{SERVER_URL}/sendMessage",
                headers={"content-type": "application/json"},
                body=json.dumps({
                    "message": {
                        "recipient": EXPECTED_IDENTITY,
                        "messageBox": "inbox",
                        "messageId": msg_id,
                        "body": msg_body,
                    },
                }),
            )
            ok = resp.status_code == 200
            detail = f"status={resp.status_code}"
            if ok:
                try:
                    j = resp.json()
                    ok = (
                        j.get("status") == "success"
                        and isinstance(j.get("results"), list)
                        and any(
                            r.get("messageId") == msg_id and r.get("recipient") == EXPECTED_IDENTITY
                            for r in j["results"]
                        )
                    )
                    detail = f"status=200 body={j!r}"
                except Exception as parse_err:
                    ok = False
                    detail = f"status=200 but body not JSON: {parse_err}"
            failures += 0 if step(
                "4. HTTP POST /sendMessage X→X (inbox) succeeds",
                ok,
                detail,
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "4. HTTP POST /sendMessage X→X (inbox) succeeds",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 5: WS receives `sendMessage` push within RECV_TIMEOUT_S ---
        # This is THE proof of #45. The HTTP send must trigger the DO
        # internal/push fan-out, which must emit on this very socket
        # because it has joined `<EXPECTED_IDENTITY>-inbox`. Assert
        # every field matches what HTTP sent.
        try:
            env = await recv_specific_event(ws, "sendMessage", timeout=RECV_TIMEOUT_S)
            data = env.get("data") or {}
            checks = {
                "event=sendMessage": env.get("event") == "sendMessage",
                f"roomId={own_room}": data.get("roomId") == own_room,
                f"sender={EXPECTED_IDENTITY}": data.get("sender") == EXPECTED_IDENTITY,
                f"messageId={msg_id}": data.get("messageId") == msg_id,
                f"body={msg_body!r}": data.get("body") == msg_body,
            }
            ok = all(checks.values())
            failed_fields = [k for k, v in checks.items() if not v]
            detail = f"received={env!r}"
            if not ok:
                detail = f"failed checks: {failed_fields} | received={env!r}"
            failures += 0 if step(
                "5. WS receives matching `sendMessage` push within 3s "
                "(roomId, sender, messageId, body all match HTTP)",
                ok,
                detail,
            ) else 1
        except asyncio.TimeoutError as e:
            step(
                "5. WS receives matching `sendMessage` push within 3s "
                "(roomId, sender, messageId, body all match HTTP)",
                False,
                f"TIMEOUT after {RECV_TIMEOUT_S}s: {e}",
            )
            failures += 1
        except Exception as e:  # noqa: BLE001
            step(
                "5. WS receives matching `sendMessage` push within 3s "
                "(roomId, sender, messageId, body all match HTTP)",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 6: clean close ---
        try:
            await asyncio.wait_for(ws.close(code=1000, reason="bye"),
                                   timeout=RECV_TIMEOUT_S)
            close_code = getattr(ws, "close_code", None)
            ok = close_code in (1000, None)
            step("6. Clean close (no error)", ok, f"close_code={close_code}")
            if not ok:
                failures += 1
        except Exception as e:  # noqa: BLE001
            step("6. Clean close (no error)", False, f"{type(e).__name__}: {e}")
            failures += 1
    finally:
        # Belt-and-suspenders close on exception paths.
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass
        # Best-effort cleanup of the inbox row so reruns are clean.
        if msg_id:
            try:
                authenticated_request(
                    method="POST",
                    url=f"{SERVER_URL}/acknowledgeMessage",
                    headers={"content-type": "application/json"},
                    body=json.dumps({"messageIds": [msg_id]}),
                )
            except Exception:
                pass

    print("", flush=True)
    print(f"=== Result: {('OK' if failures == 0 else 'FAIL')} "
          f"({failures} failure(s)) ===", flush=True)
    return 0 if failures == 0 else 1


def main() -> int:
    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        print("FAIL: interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
