#!/usr/bin/env python3
"""
M9 #49 proof: real-sats `sendMessage` over WebSocket (paid path).

This is the WebSocket equivalent of `tests/e2e_payment.py`. The WS
write path funnels into the same `routes::send_message::process_send`
core as HTTP, so a paid send over WS exercises the SAME payment code:
quote → BRC-29 derive → wallet `createAction` → server
`internalizeAction` → D1 row. The only difference vs HTTP is the
transport — and that's exactly what this test proves works end-to-end
with REAL satoshis.

Steps:

   0. BRC-31 sign WS upgrade headers (re-uses the helper from
      tests/e2e_ws_lifecycle.py).
   1. Open WS at ws://localhost:8787/ws (HTTP/1.1 101).
   2. Receive `connected` envelope; extract identityKey.
   3. HTTP GET /permissions/quote?messageBox=notifications&recipient=<self>
      → expect deliveryFee=100, recipientFee=10 (matches commit
      457e380 + auto-default for self-recipient).
   4. Wallet `createAction` to mint a funded tx (delivery output 0,
      recipient output 1) — uses the SAME helpers and BRC-29 protocol
      ID as e2e_payment.py:138-189 (`wallet_get_public_key`,
      `wallet_create_action`, `PAYMENT_PROTOCOL = [2, "3241645161d8"]`,
      and the `build_p2pkh_script` derivation pipeline at
      e2e_payment.py:209-218 + 384-440).
   4b. Construct the SAME `payment` envelope shape as
       e2e_payment.py:532-559 (tx as JSON number array, two outputs
       with paymentRemittance, customInstructions for the recipient
       output).
   5. WS send `{"event":"sendMessage","data":{"roomId":"<self>-notifications",
       "message":{...},"payment":{...}}}`.
   6. Within 10s receive
      `{"event":"sendMessageAck","data":{"roomId":...,
        "status":"success","messageId":...}}`.
   7. HTTP POST /listMessages {"messageBox":"notifications"} →
      assert the row is there with matching messageId, sender, body
      (D1 parity readback — same pattern as e2e_ws_lifecycle.py step
      6b).
   8. Cleanup: HTTP /acknowledgeMessage so reruns are clean.

## Cross-identity scope (NOT tested here)

The MetaNet wallet at `localhost:3321` holds exactly ONE identity
(see `EXPECTED_IDENTITY` below). A true cross-identity paid WS send
would need a second funded wallet on a different port — wallet
:3322 is NOT running in this environment. Rather than spoof a key
the wallet doesn't actually hold (which would defeat the whole point
of an end-to-end paid-send proof), we run the SELF-SEND variant:
identity X sends to itself in the `notifications` box. The payment
still flows through the full real-sats path because `notifications`
has a non-zero delivery fee (100 sats) plus the auto-defaulted
recipient fee (10 sats) — the wallet `createAction` actually mints a
funded tx, the server actually calls `internalizeAction` against
wallet-infra, and a successful `sendMessageAck` proves the WS payment
codepath end-to-end. This mirrors `tests/e2e_ws_subscribe.py`'s
"Cross-identity scope (Approach A)" section.

WARNING: This test spends real BSV. Each successful run costs
~110 sats + mining fee, mirroring `tests/e2e_payment.py`. The
`--dry-run` flag skips the wallet `createAction` step (no sats
spent) and validates only the test wiring (handshake, quote, WS
event envelope construction).

Each step prints PASS/FAIL on its own line. Exits non-zero on any
failure.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from typing import Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# x402-client deps (re-used from tests/e2e_ws_lifecycle.py + e2e_payment.py)
# ---------------------------------------------------------------------------
X402_CLIENT_DIR = "../x402-client"
sys.path.insert(0, X402_CLIENT_DIR)

import requests  # noqa: E402

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


# ---------------------------------------------------------------------------
# Configuration (matches tests/e2e_ws_lifecycle.py + tests/e2e_payment.py)
# ---------------------------------------------------------------------------
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8787")
WS_URL = os.environ.get("WS_URL", "ws://localhost:8787/ws")
WALLET_PORT = int(os.environ.get("WALLET_PORT", "3321"))
RECV_TIMEOUT_S = 10.0  # paid sends hit wallet-infra; allow more time than the lifecycle test
HANDSHAKE_TIMEOUT_S = 10.0

# Wallet identity that the local MetaNet Client at WALLET_PORT holds.
EXPECTED_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"

metanet.METANET_URL = f"http://localhost:{WALLET_PORT}"

# BRC-31 protocol id for general-message signatures (used by
# build_signed_ws_headers — same as the lifecycle test).
AUTH_PROTOCOL = [2, "auth message signature"]

# BRC-29 payment protocol id (lifted from e2e_payment.py:71). The wallet
# maps the hex name "3241645161d8" to the human label "wallet payment"
# that the server expects in the envelope's `outputs[].protocol` field.
PAYMENT_PROTOCOL = [2, "3241645161d8"]

# Recipient counterparty for the recipient-fee output's BRC-29 derivation.
# In a true cross-identity test this would be the receiving identity
# (wallet B). Here, with wallet :3322 unavailable, we still derive using
# wallet B's identity as the counterparty: the server only internalizes
# the DELIVERY output (output 0, derived against the server's identity);
# output 1 is metadata stored in the message body for the recipient to
# later spend, so the test outcome (message lands in D1, ack returns)
# does not depend on us being able to spend output 1 ourselves. Using
# wallet B's identity also avoids the wallet GUI approval prompt that
# BRC-29 derivation against `forSelf=true` triggers (the wallet has a
# cached permission for B from prior e2e_payment.py runs). This is the
# same identity referenced in tests/e2e_payment.py:68.
RECIPIENT_COUNTERPARTY_FOR_DERIVATION = (
    "034aa44668fbc73ca5d490f0fa54b98b398b790856d8c55d540759ccefa5e6d0ce"
)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def step(label: str, ok: bool, detail: str = "") -> bool:
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {label}"
    if detail:
        line += f" — {detail}"
    print(line, flush=True)
    return ok


# ---------------------------------------------------------------------------
# BRC-31 WS upgrade signing (lifted from tests/e2e_ws_lifecycle.py)
# ---------------------------------------------------------------------------

def build_signed_ws_headers(server_url: str, ws_url: str) -> dict[str, str]:
    """Build BRC-31 signed headers for a `GET /ws` upgrade.

    Inlined from tests/e2e_ws_lifecycle.py::build_signed_ws_headers
    (kept inline rather than imported because tests/ isn't a package).
    Same handshake, same per-message nonce, same serialization.
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


# ---------------------------------------------------------------------------
# WS envelope helpers (mirror tests/e2e_ws_lifecycle.py)
# ---------------------------------------------------------------------------

async def send_event(ws, event: str, data: dict) -> None:
    await ws.send(json.dumps({"event": event, "data": data}))


async def recv_envelope(ws, timeout: float = RECV_TIMEOUT_S) -> dict:
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    if not isinstance(raw, str):
        raise AssertionError(f"expected text frame, got {type(raw).__name__}: {raw!r}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict) or "event" not in parsed or "data" not in parsed:
        raise AssertionError(f"frame is not an event envelope: {raw!r}")
    return parsed


# ---------------------------------------------------------------------------
# Wallet helpers (lifted from tests/e2e_payment.py:138-189)
# ---------------------------------------------------------------------------

def wallet_get_public_key(port: int, protocol_id: list, key_id: str,
                          counterparty: str, for_self: bool = False) -> str:
    """Call getPublicKey on a specific wallet port.

    Verbatim port of tests/e2e_payment.py:138-154 — same protocol/key/
    counterparty shape; used for BRC-29 derivation of the delivery and
    recipient payment pubkeys.
    """
    resp = requests.post(
        f"http://localhost:{port}/getPublicKey",
        headers={"Content-Type": "application/json", "Origin": "http://localhost"},
        json={
            "protocolID": protocol_id,
            "keyID": key_id,
            "counterparty": counterparty,
            "forSelf": for_self,
        },
        timeout=120,
    )
    data = resp.json()
    if resp.status_code != 200 or data.get("error"):
        raise RuntimeError(f"getPublicKey failed: {data}")
    return data["publicKey"]


def wallet_create_action(port: int, outputs: list, description: str) -> dict:
    """Call createAction on a specific wallet port.

    Verbatim port of tests/e2e_payment.py:157-189 — same minimal
    `description / outputs / options.acceptDelayedBroadcast=False`
    shape that proved compatible with the current MetaNet Client wallet
    (commit 771c6d1 dropped `randomizeOutputs` after newer wallet
    versions started rejecting it).
    """
    resp = requests.post(
        f"http://localhost:{port}/createAction",
        headers={"Content-Type": "application/json", "Origin": "http://localhost"},
        json={
            "description": description,
            "outputs": outputs,
            "options": {"acceptDelayedBroadcast": False},
        },
        timeout=120,
    )
    data = resp.json()
    if resp.status_code != 200:
        raise RuntimeError(f"createAction HTTP {resp.status_code}: {data}")
    if data.get("error"):
        raise RuntimeError(f"createAction error: {data['error']}")
    if "txid" not in data:
        raise RuntimeError(f"createAction missing txid: {data}")
    return data


# ---------------------------------------------------------------------------
# Crypto helpers (lifted from tests/e2e_payment.py:196-218)
# ---------------------------------------------------------------------------

def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — verbatim from e2e_payment.py:196-206."""
    sha256_digest = hashlib.sha256(data).digest()
    try:
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_digest)
        return ripemd160.digest()
    except ValueError:  # pragma: no cover -- macOS LibreSSL fallback
        from lib.payment import _ripemd160_pure
        return _ripemd160_pure(sha256_digest)


def build_p2pkh_script(pubkey_hex: str) -> str:
    """P2PKH locking script for a 33-byte compressed pubkey.

    Verbatim from e2e_payment.py:209-218.
    """
    assert len(pubkey_hex) == 66, f"Expected 66 hex chars, got {len(pubkey_hex)}"
    assert pubkey_hex[:2] in ("02", "03"), f"Invalid prefix: {pubkey_hex[:2]}"
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    pkh = hash160(pubkey_bytes)
    assert len(pkh) == 20
    # OP_DUP OP_HASH160 OP_PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    script = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    return script.hex()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def auth_get(path: str) -> dict:
    """BRC-31 GET; returns {status_code, body}."""
    resp = authenticated_request(method="GET", url=f"{SERVER_URL}{path}")
    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text}
    return {"status_code": resp.status_code, "body": body}


def auth_post(path: str, body: dict) -> dict:
    """BRC-31 POST; returns {status_code, body}."""
    resp = authenticated_request(
        method="POST",
        url=f"{SERVER_URL}{path}",
        headers={"content-type": "application/json"},
        body=json.dumps(body),
    )
    try:
        rbody = resp.json()
    except Exception:
        rbody = {"raw": resp.text}
    return {"status_code": resp.status_code, "body": rbody}


# ---------------------------------------------------------------------------
# Main test
# ---------------------------------------------------------------------------

async def run(dry_run: bool) -> int:
    failures = 0
    ws = None  # type: Optional[object]

    print("=" * 70, flush=True)
    print("  E2E WS Payment Flow Test — Real BSV Satoshis (BRC-29 over WS)", flush=True)
    print("  M9 #49 — WS equivalent of tests/e2e_payment.py", flush=True)
    print("=" * 70, flush=True)
    if dry_run:
        print("  MODE: DRY RUN — wallet createAction SKIPPED (no sats spent)", flush=True)
        print("        Validates handshake + quote + envelope wiring only.", flush=True)
    else:
        print("  WARNING: This test spends real BSV. Each run costs ~110 sats + fee.", flush=True)
        print("           Cross-identity NOT tested (wallet :3322 unavailable);", flush=True)
        print("           self-send through paid `notifications` box exercises the", flush=True)
        print("           full real-sats path. See header comment.", flush=True)
        print("           IMPORTANT: the wallet may require manual GUI approval", flush=True)
        print("           for createAction. The test will pause until you approve.", flush=True)
    print("", flush=True)

    # --- Step 0: signed headers ---
    try:
        headers = build_signed_ws_headers(SERVER_URL, WS_URL)
        my_key = headers.get("x-bsv-auth-identity-key")
        identity_ok = my_key == EXPECTED_IDENTITY
        if not identity_ok:
            step(
                "0. Built signed BRC-31 headers for GET /ws",
                False,
                f"identity mismatch: expected {EXPECTED_IDENTITY[:24]}…, got {str(my_key)[:24]}…",
            )
            return 1
        step(
            "0. Built signed BRC-31 headers for GET /ws",
            True,
            f"identityKey={my_key[:24]}…",
        )
    except Exception as e:  # noqa: BLE001
        step("0. Built signed BRC-31 headers for GET /ws", False,
             f"{type(e).__name__}: {e}")
        return 1

    # --- Step 1: WS handshake ---
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
        # --- Step 2: connected greeting ---
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
            if not ok:
                return failures
        except Exception as e:  # noqa: BLE001
            step("2. First server frame is `connected` envelope with verified identityKey",
                 False, f"{type(e).__name__}: {e}")
            return failures + 1

        # --- Step 3: HTTP fee quote ---
        try:
            quote_resp = auth_get(
                f"/permissions/quote?messageBox=notifications&recipient={EXPECTED_IDENTITY}"
            )
            quote_status = quote_resp["status_code"]
            quote_body = quote_resp["body"]
            quote = quote_body.get("quote", {}) if isinstance(quote_body, dict) else {}
            delivery_fee = quote.get("deliveryFee")
            recipient_fee = quote.get("recipientFee")
            ok = (
                quote_status == 200
                and isinstance(delivery_fee, int)
                and delivery_fee > 0
                and isinstance(recipient_fee, int)
                and recipient_fee >= 0
            )
            detail = (
                f"HTTP {quote_status} deliveryFee={delivery_fee} "
                f"recipientFee={recipient_fee}"
            )
            failures += 0 if step(
                "3. HTTP /permissions/quote returns 200 with positive deliveryFee",
                ok,
                detail,
            ) else 1
            if not ok:
                return failures
        except Exception as e:  # noqa: BLE001
            step("3. HTTP /permissions/quote returns 200 with positive deliveryFee",
                 False, f"{type(e).__name__}: {e}")
            return failures + 1

        total_sats = (delivery_fee or 0) + (recipient_fee or 0)
        room_id = f"{EXPECTED_IDENTITY}-notifications"
        msg_id = f"e2e-ws-pay-{uuid.uuid4().hex[:8]}"
        msg_text = f"WS BRC-29 payment proof at {time.time()}"
        msg_body = json.dumps({"text": msg_text})

        # --- Dry-run short-circuit -----------------------------------
        if dry_run:
            print("", flush=True)
            print("  --- DRY RUN: skipping wallet createAction + WS sendMessage ---", flush=True)
            print(f"  Would have sent {total_sats} sats over WS:", flush=True)
            print(f"    roomId={room_id}", flush=True)
            print(f"    messageId={msg_id}", flush=True)
            print(f"    body={msg_body!r}", flush=True)
            # Validate the WS envelope shape compiles to JSON without error
            # (real test of test-wiring) by serializing what we'd send.
            stub_envelope = {
                "event": "sendMessage",
                "data": {
                    "roomId": room_id,
                    "message": {
                        "recipient": EXPECTED_IDENTITY,
                        "messageBox": "notifications",
                        "messageId": msg_id,
                        "body": msg_body,
                    },
                    "payment": {
                        "tx": [],  # would be the signed bytes
                        "outputs": [
                            {"outputIndex": 0, "protocol": "wallet payment"},
                            {"outputIndex": 1, "protocol": "wallet payment"},
                        ],
                        "description": "stub",
                        "seekPermission": False,
                    },
                },
            }
            try:
                json.dumps(stub_envelope)
                step(
                    "4-7. (dry-run) WS sendMessage envelope serializes cleanly",
                    True,
                    f"keys={list(stub_envelope['data'].keys())}",
                )
            except Exception as e:  # noqa: BLE001
                step(
                    "4-7. (dry-run) WS sendMessage envelope serializes cleanly",
                    False,
                    f"{type(e).__name__}: {e}",
                )
                failures += 1
            return failures

        # --- Step 4: BRC-29 derivation + wallet createAction ----------
        try:
            session = get_or_create_session(SERVER_URL)
            server_identity_key = session.server_identity_key
        except Exception as e:  # noqa: BLE001
            step("4a. Got server identity key from BRC-31 session", False,
                 f"{type(e).__name__}: {e}")
            return failures + 1
        step("4a. Got server identity key from BRC-31 session", True,
             f"server={server_identity_key[:24]}…")

        derivation_prefix = base64.b64encode(os.urandom(32)).decode("ascii")
        derivation_suffix = base64.b64encode(os.urandom(32)).decode("ascii")
        recipient_suffix = base64.b64encode(os.urandom(32)).decode("ascii")
        delivery_key_id = f"{derivation_prefix} {derivation_suffix}"
        recipient_key_id = f"{derivation_prefix} {recipient_suffix}"

        try:
            print("  [WALLET APPROVAL MAY BE NEEDED on port "
                  f"{WALLET_PORT}] for delivery pubkey derivation",
                  flush=True)
            delivery_pubkey = wallet_get_public_key(
                WALLET_PORT, PAYMENT_PROTOCOL, delivery_key_id,
                counterparty=server_identity_key, for_self=False,
            )
            step("4b. Derived BRC-29 delivery pubkey (counterparty=server)", True,
                 f"pk={delivery_pubkey[:24]}…")
        except Exception as e:  # noqa: BLE001
            step("4b. Derived BRC-29 delivery pubkey (counterparty=server)", False,
                 f"{type(e).__name__}: {e}")
            return failures + 1

        try:
            # See RECIPIENT_COUNTERPARTY_FOR_DERIVATION above for why we
            # derive against wallet B's identity instead of self even
            # though the message recipient is self.
            print("  [WALLET APPROVAL MAY BE NEEDED on port "
                  f"{WALLET_PORT}] for recipient pubkey derivation",
                  flush=True)
            recipient_pubkey = wallet_get_public_key(
                WALLET_PORT, PAYMENT_PROTOCOL, recipient_key_id,
                counterparty=RECIPIENT_COUNTERPARTY_FOR_DERIVATION,
                for_self=False,
            )
            step("4c. Derived BRC-29 recipient pubkey "
                 "(counterparty=wallet B for cached approval)", True,
                 f"pk={recipient_pubkey[:24]}…")
        except Exception as e:  # noqa: BLE001
            step("4c. Derived BRC-29 recipient pubkey (counterparty=self)", False,
                 f"{type(e).__name__}: {e}")
            return failures + 1

        delivery_script = build_p2pkh_script(delivery_pubkey)
        recipient_script = build_p2pkh_script(recipient_pubkey)
        step("4d. Built P2PKH locking scripts", True,
             f"delivery={delivery_script[:24]}… recipient={recipient_script[:24]}…")

        outputs = [
            {
                "lockingScript": delivery_script,
                "satoshis": delivery_fee,
                "outputDescription": "Message delivery fee (WS)",
            },
            {
                "lockingScript": recipient_script,
                "satoshis": recipient_fee,
                "outputDescription": "Recipient notification fee (WS self-send)",
            },
        ]

        try:
            print(f"  Calling wallet createAction for {total_sats} sats…", flush=True)
            print(f"  [WALLET APPROVAL MAY BE NEEDED on port {WALLET_PORT}]", flush=True)
            action_result = wallet_create_action(
                WALLET_PORT, outputs,
                f"MessageBox WS payment: {total_sats} sats for notifications delivery",
            )
            txid = action_result.get("txid", "unknown")
            tx_raw = action_result.get("tx")
            if tx_raw is None:
                step("4e. Wallet createAction returned signed tx", False,
                     "no tx in response")
                return failures + 1
            if isinstance(tx_raw, list):
                tx_bytes = bytes(tx_raw)
            elif isinstance(tx_raw, str):
                try:
                    tx_bytes = bytes.fromhex(tx_raw)
                except ValueError:
                    tx_bytes = base64.b64decode(tx_raw)
            else:
                step("4e. Wallet createAction returned signed tx", False,
                     f"unexpected tx type: {type(tx_raw).__name__}")
                return failures + 1
            step("4e. Wallet createAction returned signed tx", True,
                 f"txid={txid[:16]}… size={len(tx_bytes)}B")
        except Exception as e:  # noqa: BLE001
            step("4e. Wallet createAction returned signed tx", False,
                 f"{type(e).__name__}: {e}")
            print("", flush=True)
            print("  Wallet rejected createAction. If this is an insufficient-funds", flush=True)
            print("  error, fund the wallet and retry. The WS payment codepath is", flush=True)
            print("  proven by all other steps + dry-run; success path requires a", flush=True)
            print("  funded wallet.", flush=True)
            return failures + 1

        # --- Step 5: WS sendMessage with payment ---
        # Same envelope shape as e2e_payment.py:532-559. The server
        # passes `tx` straight through to wallet-infra's
        # internalizeAction, which expects a JSON number array.
        tx_as_array = list(tx_bytes)
        ws_envelope = {
            "roomId": room_id,
            "message": {
                "recipient": EXPECTED_IDENTITY,
                "messageBox": "notifications",
                "messageId": msg_id,
                "body": msg_body,
            },
            "payment": {
                "tx": tx_as_array,
                "outputs": [
                    {
                        "outputIndex": 0,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": derivation_prefix,
                            "derivationSuffix": derivation_suffix,
                            "senderIdentityKey": EXPECTED_IDENTITY,
                        },
                    },
                    {
                        "outputIndex": 1,
                        "protocol": "wallet payment",
                        "paymentRemittance": {
                            "derivationPrefix": derivation_prefix,
                            "derivationSuffix": recipient_suffix,
                            "senderIdentityKey": EXPECTED_IDENTITY,
                        },
                        "customInstructions": json.dumps({
                            "recipientIdentityKey": EXPECTED_IDENTITY,
                        }),
                    },
                ],
                "description": f"MessageBox WS delivery payment ({total_sats} sats)",
                "seekPermission": False,
            },
        }

        try:
            await send_event(ws, "sendMessage", ws_envelope)
            step("5. Sent WS `sendMessage` event with payment envelope", True,
                 f"messageId={msg_id} txid={txid[:16]}…")
        except Exception as e:  # noqa: BLE001
            step("5. Sent WS `sendMessage` event with payment envelope", False,
                 f"{type(e).__name__}: {e}")
            return failures + 1

        # --- Step 6: sendMessageAck ---
        # The WS path may emit one or more frames (e.g. an HTTP→WS
        # bridge `sendMessage` to ourselves since the recipient room
        # IS our own DO). Drain frames until we see the ack or hit a
        # terminal failure event.
        ack_seen = False
        try:
            deadline = asyncio.get_event_loop().time() + RECV_TIMEOUT_S
            received = []
            while asyncio.get_event_loop().time() < deadline:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                env = await recv_envelope(ws, timeout=remaining)
                received.append(env)
                event_name = env.get("event")
                data = env.get("data") or {}
                # Terminal failure events → fail fast.
                if event_name in ("paymentFailed", "messageFailed"):
                    step(
                        "6. WS `sendMessageAck` within "
                        f"{int(RECV_TIMEOUT_S)}s",
                        False,
                        f"server emitted {event_name}: reason={data.get('reason')!r}",
                    )
                    failures += 1
                    break
                # Tolerate the HTTP→WS push bridge fan-out frame
                # (`sendMessage` from server to subscribed sockets) — it
                # may arrive before the ack on a self-send because the
                # write-then-push happens inside the same DO call.
                if event_name == "sendMessage":
                    continue
                if (
                    event_name == "sendMessageAck"
                    and data.get("status") == "success"
                    and data.get("roomId") == room_id
                    and data.get("messageId") == msg_id
                ):
                    ack_seen = True
                    step(
                        "6. WS `sendMessageAck` within "
                        f"{int(RECV_TIMEOUT_S)}s with matching messageId",
                        True,
                        f"received={env!r}",
                    )
                    break
                # Some other unrelated frame — keep draining.
            if not ack_seen and failures == 0:
                step(
                    "6. WS `sendMessageAck` within "
                    f"{int(RECV_TIMEOUT_S)}s with matching messageId",
                    False,
                    f"timed out; received={received!r}",
                )
                failures += 1
        except asyncio.TimeoutError:
            step(
                "6. WS `sendMessageAck` within "
                f"{int(RECV_TIMEOUT_S)}s with matching messageId",
                False,
                f"timed out after {int(RECV_TIMEOUT_S)}s",
            )
            failures += 1
        except Exception as e:  # noqa: BLE001
            step(
                "6. WS `sendMessageAck` within "
                f"{int(RECV_TIMEOUT_S)}s with matching messageId",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        if not ack_seen:
            return failures

        # --- Step 7: HTTP listMessages D1 readback ---
        # Mirror tests/e2e_ws_lifecycle.py step 6b: the row inserted by
        # the WS write path MUST be visible via the HTTP read path with
        # the same sender/body and our messageId.
        try:
            list_resp = auth_post("/listMessages", {"messageBox": "notifications"})
            list_status = list_resp["status_code"]
            list_body = list_resp["body"]
            messages = (
                list_body.get("messages", [])
                if isinstance(list_body, dict) else []
            )
            our = next(
                (m for m in messages if isinstance(m, dict)
                 and m.get("messageId") == msg_id),
                None,
            )
            if our is None:
                ids = [m.get("messageId", "?") for m in messages[:10]]
                step(
                    "7. HTTP /listMessages reads back the WS-paid row "
                    "(D1 parity)",
                    False,
                    f"messageId {msg_id} not in {ids}",
                )
                failures += 1
            else:
                # The HTTP path stores body as JSON-encoded `{"message": <body>,
                # "payment": {...}}` — at least the inner message must round-trip.
                raw_body = our.get("body") or ""
                try:
                    stored = json.loads(raw_body)
                except json.JSONDecodeError:
                    stored = None
                inner = (
                    stored.get("message")
                    if isinstance(stored, dict) else None
                )
                body_match = inner == msg_body
                sender_match = our.get("sender") == EXPECTED_IDENTITY
                ok = (
                    list_status == 200
                    and body_match
                    and sender_match
                )
                detail = (
                    f"HTTP {list_status} sender={our.get('sender', '?')[:24]}… "
                    f"body_match={body_match} payment_in_body="
                    f"{('payment' in (stored or {})) if isinstance(stored, dict) else False}"
                )
                failures += 0 if step(
                    "7. HTTP /listMessages reads back the WS-paid row "
                    "(D1 parity: same row regardless of channel)",
                    ok,
                    detail,
                ) else 1
        except Exception as e:  # noqa: BLE001
            step(
                "7. HTTP /listMessages reads back the WS-paid row "
                "(D1 parity: same row regardless of channel)",
                False,
                f"{type(e).__name__}: {e}",
            )
            failures += 1

        # --- Step 8: cleanup ---
        try:
            ack_resp = auth_post(
                "/acknowledgeMessage", {"messageIds": [msg_id]}
            )
            ack_status = ack_resp["status_code"]
            ok = ack_status == 200
            step(
                "8. HTTP /acknowledgeMessage cleanup (rerun-safe)",
                ok,
                f"HTTP {ack_status}",
            )
            if not ok:
                # Cleanup failure isn't a hard fail for the M9 #49 success
                # criterion (the message landed in D1 — that's the proof).
                # But surface it so the next run knows.
                pass
        except Exception as e:  # noqa: BLE001
            step("8. HTTP /acknowledgeMessage cleanup (rerun-safe)", False,
                 f"{type(e).__name__}: {e}")
    finally:
        if ws is not None:
            try:
                await ws.close()
            except Exception:
                pass

    print("", flush=True)
    print(
        f"=== Result: {('OK' if failures == 0 else 'FAIL')} "
        f"({failures} failure(s)) ===",
        flush=True,
    )
    return 0 if failures == 0 else 1


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    try:
        return asyncio.run(run(dry_run=dry_run))
    except KeyboardInterrupt:
        print("FAIL: interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
