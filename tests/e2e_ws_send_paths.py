#!/usr/bin/env python3
"""
M9 #44 proof: WebSocket `sendMessage` failure-mode parity with HTTP.

The WS write path runs through the same `process_send` core the HTTP
`POST /sendMessage` handler uses (`src/routes/send_message.rs`), so
its failure modes MUST surface the same human-facing reasons. This
test covers the failure paths that don't require real sats:

  1. Bad recipient key (not a 66-char compressed pubkey)
       → messageFailed reason "Invalid recipient key: <key>"
         (matches HTTP ERR_INVALID_RECIPIENT_KEY description)

  2. Send to `notifications` box with no `payment` payload
       → paymentFailed reason
         "Payment transaction data is required for payable delivery."
         (matches HTTP ERR_MISSING_PAYMENT_TX description)

  3. Duplicate `messageId`: send the same (recipient, messageId, box)
     pair twice in a row
       → first send → sendMessageAck
       → second send → messageFailed reason "Duplicate message."
         (matches HTTP ERR_DUPLICATE_MESSAGE description)

Real-sats success of a paid WS send is OUT OF SCOPE for #44 — it
would mirror tests/e2e_payment.py for the WS path. Documented in
the M9 issue.

Each step prints PASS/FAIL on its own line. Exits non-zero on any
failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# x402-client deps (re-used from tests/e2e_ws_lifecycle.py)
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
HANDSHAKE_TIMEOUT_S = 10.0

EXPECTED_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"

metanet.METANET_URL = f"http://localhost:{WALLET_PORT}"

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

    Mirrors tests/e2e_ws_lifecycle.py::build_signed_ws_headers exactly —
    same handshake, same per-message nonce, same serialization. Kept
    inline rather than imported because the lifecycle test file lives
    under tests/ and isn't a package.
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


async def recv_envelope(ws) -> dict:
    raw = await asyncio.wait_for(ws.recv(), timeout=RECV_TIMEOUT_S)
    if not isinstance(raw, str):
        raise AssertionError(f"expected text frame, got {type(raw).__name__}: {raw!r}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or "event" not in parsed or "data" not in parsed:
        raise AssertionError(f"frame is not an event envelope: {raw!r}")
    return parsed


async def consume_connected(ws) -> None:
    """Drain the server-initiated `connected` greeting after upgrade."""
    env = await recv_envelope(ws)
    assert env.get("event") == "connected", f"expected connected, got {env!r}"


async def open_ws():
    headers = build_signed_ws_headers(SERVER_URL, WS_URL)
    return await asyncio.wait_for(
        connect(WS_URL, additional_headers=headers),
        timeout=HANDSHAKE_TIMEOUT_S,
    )


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

async def case_bad_recipient_key(failures: int) -> int:
    """Step 1: malformed recipient pubkey → messageFailed.

    Match the HTTP path's exact wire description:
        "Invalid recipient key: <key>"
    (validation::validate_send_message produces this — and the WS
    handler reuses the same is_valid_pubkey check.)
    """
    label = (
        "1. Bad recipient key → messageFailed "
        "with HTTP-parity description (\"Invalid recipient key: ...\")"
    )
    ws = None
    try:
        ws = await open_ws()
        await consume_connected(ws)
        bad_key = "not-a-valid-pubkey"
        await send_event(ws, "sendMessage", {
            "roomId": f"{EXPECTED_IDENTITY}-inbox",
            "message": {
                "recipient": bad_key,
                "messageId": "e2e-bad-recipient",
                "body": "x",
            },
        })
        env = await recv_envelope(ws)
        reason = (env.get("data") or {}).get("reason", "")
        ok = (
            env.get("event") == "messageFailed"
            and reason == f"Invalid recipient key: {bad_key}"
        )
        return failures + (0 if step(label, ok, f"received={env!r}") else 1)
    except Exception as e:  # noqa: BLE001
        step(label, False, f"{type(e).__name__}: {e}")
        return failures + 1
    finally:
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass


async def case_notifications_no_payment(failures: int) -> int:
    """Step 2: send to notifications box without payment → paymentFailed.

    The notifications box has delivery_fee=100 sats by default
    (commit 457e380 bumped it to 100), so any send to it requires a
    payment payload. The HTTP handler responds with 400 +
    ERR_MISSING_PAYMENT_TX +
    "Payment transaction data is required for payable delivery."
    The WS handler emits the SAME description on the `paymentFailed`
    event.
    """
    label = (
        "2. Send to `notifications` (paid box) with no payment → "
        "paymentFailed with HTTP-parity description"
    )
    ws = None
    try:
        ws = await open_ws()
        await consume_connected(ws)
        await send_event(ws, "sendMessage", {
            "roomId": f"{EXPECTED_IDENTITY}-notifications",
            "message": {
                "recipient": EXPECTED_IDENTITY,
                "messageId": f"e2e-no-pay-{int(asyncio.get_event_loop().time() * 1000)}",
                "body": "needs payment",
            },
        })
        env = await recv_envelope(ws)
        data = env.get("data") or {}
        reason = data.get("reason", "")
        ok = (
            env.get("event") == "paymentFailed"
            and reason == "Payment transaction data is required for payable delivery."
        )
        return failures + (0 if step(label, ok, f"received={env!r}") else 1)
    except Exception as e:  # noqa: BLE001
        step(label, False, f"{type(e).__name__}: {e}")
        return failures + 1
    finally:
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass


async def case_duplicate_message(failures: int) -> int:
    """Step 3: same (recipient, messageId, box) twice → second is rejected.

    First send must ack with sendMessageAck; second send with the same
    messageId must reject with messageFailed reason "Duplicate message."
    Matches HTTP ERR_DUPLICATE_MESSAGE wire description.
    """
    label = "3. Duplicate messageId → second send → messageFailed (\"Duplicate message.\")"
    ws = None
    msg_id = f"e2e-dup-{int(asyncio.get_event_loop().time() * 1000)}"
    sent_ack = False
    try:
        ws = await open_ws()
        await consume_connected(ws)
        # Use inbox (free) so we don't need payment plumbing in this test.
        room = f"{EXPECTED_IDENTITY}-inbox"
        # First send → ack.
        await send_event(ws, "sendMessage", {
            "roomId": room,
            "message": {
                "recipient": EXPECTED_IDENTITY,
                "messageId": msg_id,
                "body": "first",
            },
        })
        first = await recv_envelope(ws)
        if first.get("event") != "sendMessageAck":
            step(label, False, f"first send did not ack: {first!r}")
            return failures + 1
        sent_ack = True

        # Second send with the SAME messageId → duplicate.
        await send_event(ws, "sendMessage", {
            "roomId": room,
            "message": {
                "recipient": EXPECTED_IDENTITY,
                "messageId": msg_id,
                "body": "second",
            },
        })
        second = await recv_envelope(ws)
        reason = (second.get("data") or {}).get("reason", "")
        ok = (
            second.get("event") == "messageFailed"
            and reason == "Duplicate message."
        )
        return failures + (0 if step(label, ok, f"received={second!r}") else 1)
    except Exception as e:  # noqa: BLE001
        step(label, False, f"{type(e).__name__}: {e}")
        return failures + 1
    finally:
        # Best-effort ack so we don't leak a row across reruns.
        if sent_ack:
            try:
                authenticated_request(
                    method="POST",
                    url=f"{SERVER_URL}/acknowledgeMessage",
                    headers={"content-type": "application/json"},
                    body=json.dumps({"messageIds": [msg_id]}),
                )
            except Exception:
                pass
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass


async def run() -> int:
    failures = 0
    failures = await case_bad_recipient_key(failures)
    failures = await case_notifications_no_payment(failures)
    failures = await case_duplicate_message(failures)

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
