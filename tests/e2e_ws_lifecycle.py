#!/usr/bin/env python3
"""
M9 #38 + #39 + #40 + #41 + #42 + #43 + #44 proof: WebSocket lifecycle
with BRC-31 auth + per-socket attachment + server-initiated greeting +
client→server event dispatch + server→client event envelope + the
real WS sendMessage write path.

Connects to ws://localhost:8787/ws with BRC-31 signed headers
(GET /ws — same scheme as authenticated_request) and verifies the
full event surface end-to-end:

   0. Build signed BRC-31 headers
   1. Signed handshake succeeds (101 Switching Protocols)
   2. First server frame is the `connected` envelope
      ({event:"connected",data:{identityKey:...}})           [#41 + #43]
   3. joinRoom for an owned room → joinedRoom                [#42 + #43]
   4. joinRoom for a NOT-owned room → joinFailed             [#42 ownership rule]
   5. leaveRoom for an owned room → leftRoom                 [#42 + #43]
   6. sendMessage to self in inbox (free) → sendMessageAck   [#44 real write]
   6b. HTTP listMessages reads back the same row             [#44 D1 parity]
   7. Unknown event type → messageFailed                     [#42 defensive]
   8. Garbage JSON → messageFailed                           [#42 defensive]
   9. Binary frame on event channel → messageFailed          [#42 defensive]
  10. Clean close                                            [#39]

Step 6+6b is the parity proof for #44: the message inserted by the
WebSocket write path is read back via the existing HTTP listMessages
route. Same row, same body, same sender — regardless of channel.

Each step prints PASS/FAIL on its own line. Exits non-zero on any
failure.

Requires `websockets` 16+ and the x402-client repo at the path noted
below (used by tests/e2e_live_parity.py too).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# x402-client deps (re-used from tests/e2e_live_parity.py — same convention)
# ---------------------------------------------------------------------------
X402_CLIENT_DIR = "/Users/johncalhoun/bsv/x402-client"
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
RECV_TIMEOUT_S = 5.0
HANDSHAKE_TIMEOUT_S = 10.0  # signing may briefly hit the wallet

# Wallet identity (same as tests/e2e_live_parity.py:55) — the test asserts the
# greeting carries this exact key.
EXPECTED_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"

# Point the metanet client at the local wallet (matches e2e_live_parity.py).
metanet.METANET_URL = f"http://localhost:{WALLET_PORT}"

# BRC-31 protocol id used for general-message signatures (lifted from
# x402-client/lib/auth_request.py).
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

    This is the GET-only WebSocket equivalent of the signing block in
    x402-client/lib/auth_request.py::authenticated_request. We:
      1. Reuse or create a BRC-31 session via get_or_create_session.
      2. Generate a per-message nonce and request id.
      3. Filter signable headers (none for a bare GET, but pass through
         the discipline so the signed payload matches what the server
         will reconstruct).
      4. serialize_request(... method="GET", path=ws-path, query=...,
                           body=None) into the BRC-31 binary form.
      5. Sign via metanet.create_signature with key_id
         "<msg_nonce_b64> <server_nonce_b64>".
      6. build_auth_headers(...) into the x-bsv-auth-* dict that goes
         on the upgrade GET as `additional_headers` for `websockets.connect`.

    The server runs the same `process_auth` it uses for HTTP — no WS-
    specific signing path on either end.
    """
    # The session is keyed by the HTTP origin (handshake hits /.well-known/auth
    # via http://); the WS path is just where we send the signed GET.
    session = get_or_create_session(server_url.rstrip("/"))

    # The path/query the server's BRC-31 transport will reconstruct from
    # the WS upgrade's request-line. Use the WS URL's path verbatim.
    parsed = urlparse(ws_url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else None

    msg_nonce_bytes = generate_nonce()
    msg_nonce_b64 = nonce_to_base64(msg_nonce_bytes)

    request_id_bytes = generate_request_id()
    request_id_b64 = nonce_to_base64(request_id_bytes)

    # No application-layer signable headers on a bare GET upgrade.
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

    # Caller may merge in extras; for now signed-auth headers alone are
    # what the server requires.
    return {**extra_headers, **auth_headers}


# ---------------------------------------------------------------------------
# Event helpers — match the wire envelope from src/message_hub.rs (#43)
# ---------------------------------------------------------------------------

async def send_event(ws, event: str, data: dict) -> None:
    await ws.send(json.dumps({"event": event, "data": data}))


async def recv_envelope(ws) -> dict:
    """Receive next text frame and parse as the {event,data} envelope."""
    raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_S)
    if not isinstance(raw, str):
        raise AssertionError(f"expected text frame, got {type(raw).__name__}: {raw!r}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or "event" not in parsed or "data" not in parsed:
        raise AssertionError(f"frame is not an event envelope: {raw!r}")
    return parsed


async def run() -> int:
    failures = 0
    ws = None  # type: Optional[object]

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

    try:
        # --- Step 2: server-initiated greeting (envelope shape) ---
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

        owned_room = f"{EXPECTED_IDENTITY}-inbox"
        not_owned_room = "someone-else-inbox"

        # --- Step 3: joinRoom (owned) → joinedRoom ---
        try:
            await send_event(ws, "joinRoom", {"roomId": owned_room})
            env = await recv_envelope(ws)
            ok = (
                env.get("event") == "joinedRoom"
                and isinstance(env.get("data"), dict)
                and env["data"].get("roomId") == owned_room
            )
            failures += 0 if step(
                "3. joinRoom for owned room → joinedRoom",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step("3. joinRoom for owned room → joinedRoom", False,
                 f"{type(e).__name__}: {e}")
            failures += 1

        # --- Step 4: joinRoom (not owned) → joinFailed ---
        try:
            await send_event(ws, "joinRoom", {"roomId": not_owned_room})
            env = await recv_envelope(ws)
            ok = (
                env.get("event") == "joinFailed"
                and isinstance(env.get("data"), dict)
                and isinstance(env["data"].get("reason"), str)
                and env["data"]["reason"] != ""
            )
            failures += 0 if step(
                "4. joinRoom for NOT-owned room → joinFailed (ownership rule)",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "4. joinRoom for NOT-owned room → joinFailed (ownership rule)",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 5: leaveRoom (owned) → leftRoom ---
        try:
            await send_event(ws, "leaveRoom", {"roomId": owned_room})
            env = await recv_envelope(ws)
            ok = (
                env.get("event") == "leftRoom"
                and isinstance(env.get("data"), dict)
                and env["data"].get("roomId") == owned_room
            )
            failures += 0 if step(
                "5. leaveRoom for owned room → leftRoom",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step("5. leaveRoom for owned room → leftRoom", False,
                 f"{type(e).__name__}: {e}")
            failures += 1

        # --- Step 6: sendMessage to self in inbox (free) → sendMessageAck ---
        # #44 wires the WS sendMessage event to the same `process_send`
        # core the HTTP handler uses. inbox has delivery_fee=0 and the
        # default per-recipient fee is 0, so this path needs no payment.
        msg_id_ws = f"e2e-ws-{int(asyncio.get_event_loop().time() * 1000)}"
        msg_body_ws = "hello-from-ws"
        try:
            await send_event(ws, "sendMessage", {
                "roomId": owned_room,
                "message": {
                    "recipient": EXPECTED_IDENTITY,
                    "messageId": msg_id_ws,
                    "body": msg_body_ws,
                },
            })
            env = await recv_envelope(ws)
            data = env.get("data") or {}
            ok = (
                env.get("event") == "sendMessageAck"
                and data.get("status") == "success"
                and data.get("roomId") == owned_room
                and data.get("messageId") == msg_id_ws
            )
            failures += 0 if step(
                "6. sendMessage event → sendMessageAck (real #44 write path)",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "6. sendMessage event → sendMessageAck (real #44 write path)",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 6b: HTTP listMessages reads back the WS-written row ---
        # Parity proof: same D1 row regardless of write channel.
        try:
            resp = authenticated_request(
                method="POST",
                url=f"{SERVER_URL}/listMessages",
                headers={"content-type": "application/json"},
                body=json.dumps({"messageBox": "inbox"}),
            )
            ok = False
            detail = f"status={resp.status_code}"
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except Exception:
                    body = None
                if isinstance(body, dict) and isinstance(body.get("messages"), list):
                    matches = [
                        m for m in body["messages"]
                        if isinstance(m, dict) and m.get("messageId") == msg_id_ws
                    ]
                    if matches:
                        m = matches[0]
                        # The HTTP path stores `{"message": <body>}` — the
                        # WS path MUST do the same (parity). The list
                        # endpoint returns body as a JSON-encoded string.
                        try:
                            stored = json.loads(m.get("body") or "")
                        except json.JSONDecodeError:
                            stored = None
                        ok = (
                            isinstance(stored, dict)
                            and stored.get("message") == msg_body_ws
                            and m.get("sender") == EXPECTED_IDENTITY
                        )
                        detail = (
                            f"messageId={m.get('messageId')} "
                            f"sender={m.get('sender')} "
                            f"body={m.get('body')!r}"
                        )
                    else:
                        detail = (
                            f"WS-written messageId {msg_id_ws} not found "
                            f"in HTTP list (n={len(body['messages'])})"
                        )
            failures += 0 if step(
                "6b. HTTP listMessages reads back WS-written row "
                "(parity: same D1 row from both channels)",
                ok,
                detail,
            ) else 1

            # Best-effort: clean up the inbox row so reruns are clean.
            if ok:
                try:
                    authenticated_request(
                        method="POST",
                        url=f"{SERVER_URL}/acknowledgeMessage",
                        headers={"content-type": "application/json"},
                        body=json.dumps({"messageIds": [msg_id_ws]}),
                    )
                except Exception:
                    pass
        except Exception as e:  # noqa: BLE001
            step(
                "6b. HTTP listMessages reads back WS-written row "
                "(parity: same D1 row from both channels)",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 7: unknown event type → messageFailed ---
        try:
            await send_event(ws, "unknownEvent", {})
            env = await recv_envelope(ws)
            reason = (env.get("data") or {}).get("reason", "")
            ok = (
                env.get("event") == "messageFailed"
                and "unknown event" in reason.lower()
            )
            failures += 0 if step(
                "7. Unknown event type → messageFailed with `unknown event` reason",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "7. Unknown event type → messageFailed with `unknown event` reason",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 8: garbage JSON → messageFailed (parse error) ---
        try:
            await ws.send("not-json-at-all")
            env = await recv_envelope(ws)
            reason = (env.get("data") or {}).get("reason", "")
            ok = (
                env.get("event") == "messageFailed"
                and "invalid event payload" in reason.lower()
            )
            failures += 0 if step(
                "8. Garbage JSON → messageFailed with parse-error reason",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "8. Garbage JSON → messageFailed with parse-error reason",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 9: binary frame → messageFailed ---
        try:
            await ws.send(bytes([0xDE, 0xAD, 0xBE, 0xEF]))
            env = await recv_envelope(ws)
            reason = (env.get("data") or {}).get("reason", "")
            ok = (
                env.get("event") == "messageFailed"
                and "binary frames not supported" in reason.lower()
            )
            failures += 0 if step(
                "9. Binary frame on event channel → messageFailed",
                ok,
                f"received={env!r}",
            ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "9. Binary frame on event channel → messageFailed",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 10: clean close ---
        try:
            await asyncio.wait_for(ws.close(code=1000, reason="bye"), timeout=RECV_TIMEOUT_S)
            close_code = getattr(ws, "close_code", None)
            ok = close_code in (1000, None)  # None acceptable if framework doesn't expose
            step("10. Clean close (no error)", ok,
                 f"close_code={close_code}")
            if not ok:
                failures += 1
        except Exception as e:  # noqa: BLE001
            step("10. Clean close (no error)", False,
                 f"{type(e).__name__}: {e}")
            failures += 1
    finally:
        # Belt-and-suspenders close on exception paths.
        if ws is not None:
            try:
                await ws.close()
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
