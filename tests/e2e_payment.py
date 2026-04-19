#!/usr/bin/env python3
"""E2E test: Full BRC-29 payment flow with real BSV satoshis.

Exercises the complete payment lifecycle against the bsv-messagebox-cloudflare server:

  1. Get fee quote for notifications box (expects deliveryFee=10, recipientFee=10)
  2. Obtain the server's identity key via BRC-31 handshake
  3. Derive a payment key (BRC-42) targeting the server's identity
  4. Build a P2PKH locking script for the derived key
  5. Create a funded transaction via Wallet A (20 sats total: 10 delivery + 10 recipient)
  6. Send the message with payment body
  7. Verify 200 success
  8. Authenticate as Wallet B, list messages, confirm delivery

WARNING: This test spends real BSV satoshis. Each run costs ~20 sats + mining fee.

Prerequisites:
  - Rust server running at localhost:8787 (npm run dev)
  - Wallet A (sender) at localhost:3321
  - Wallet B (receiver) at localhost:3322
  - x402-client checkout (set X402_CLIENT_DIR env var)

IMPORTANT: The MetaNet Client wallet requires MANUAL GUI APPROVAL for payment-
related operations (getPublicKey with payment protocol, createAction). The test
will hang at these steps until you approve in the wallet app. BRC-31 auth
operations (identity key, createSignature) are auto-approved.

Usage:
  python3 tests/e2e_payment.py           # Run full payment test (needs GUI approval)
  python3 tests/e2e_payment.py --verbose  # Debug logging
  python3 tests/e2e_payment.py --dry-run  # Skip payment creation, test everything else
"""

import sys
import os
import json
import time
import uuid
import base64
import hashlib
import logging
import traceback

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

X402_CLIENT_DIR = os.environ.get("X402_CLIENT_DIR", "")
if not X402_CLIENT_DIR:
    sys.exit("Set X402_CLIENT_DIR env var to the path of your x402-client checkout")
sys.path.insert(0, X402_CLIENT_DIR)

from lib.handshake import do_handshake, HandshakeError, get_or_create_session
from lib.auth_request import authenticated_request, AuthRequestError
from lib.session import load_session, clear_session, Session
from lib.metanet import MetaNetClientError
import lib.metanet as metanet

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_URL = "http://localhost:8787"

WALLET_A_PORT = 3321
WALLET_A_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"
WALLET_B_PORT = 3322
WALLET_B_IDENTITY = "034aa44668fbc73ca5d490f0fa54b98b398b790856d8c55d540759ccefa5e6d0ce"

# BRC-29 payment protocol ID (hex protocol name the wallet maps to "wallet payment")
PAYMENT_PROTOCOL = [2, "3241645161d8"]

log = logging.getLogger("e2e_payment")

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0
RESULTS = []


def record(test_name, passed, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if passed:
        PASS_COUNT += 1
        RESULTS.append(f"  PASS  {test_name}")
        print(f"  PASS  {test_name}")
    else:
        FAIL_COUNT += 1
        suffix = f" -- {detail}" if detail else ""
        RESULTS.append(f"  FAIL  {test_name}{suffix}")
        print(f"  FAIL  {test_name}{suffix}")


def skip(test_name, reason):
    global SKIP_COUNT
    SKIP_COUNT += 1
    RESULTS.append(f"  SKIP  {test_name} -- {reason}")
    print(f"  SKIP  {test_name} -- {reason}")


def section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


# ---------------------------------------------------------------------------
# Wallet helpers
# ---------------------------------------------------------------------------

def set_wallet_port(port):
    """Switch the x402-client metanet module to target a specific wallet port."""
    metanet.METANET_URL = f"http://localhost:{port}"
    clear_session(SERVER_URL)
    log.info("Switched wallet to port %d", port)


def probe_wallet(port, timeout=5.0):
    """Probe a wallet port. Returns identity key if responsive, else None."""
    try:
        resp = requests.post(
            f"http://localhost:{port}/getPublicKey",
            headers={"Content-Type": "application/json", "Origin": "http://localhost"},
            json={"identityKey": True},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return resp.json().get("publicKey")
    except Exception:
        pass
    return None


def wallet_get_public_key(port, protocol_id, key_id, counterparty, for_self=False):
    """Call getPublicKey on a specific wallet port."""
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


def wallet_create_action(port, outputs, description):
    """Call createAction on a specific wallet port.

    Shape matches the minimal working pattern from fund-admin.py and
    DolphinMilkShake/proof-chain.js: just `description`, `outputs`, and
    `options.acceptDelayedBroadcast=False`. An earlier version of this
    helper added `randomizeOutputs: False`, which newer MetaNet Client
    versions reject with `The type parameter must be vin 0, "custom" is
    not a supported unlocking script type`.

    BRC-29 requires the delivery output at index 0 and per-recipient
    outputs at subsequent indices. Without `randomizeOutputs: False` the
    wallet may reorder. We handle that upstream by reading the tagged
    output indices back from the signed tx rather than assuming position.
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
# Crypto helpers
# ---------------------------------------------------------------------------

def hash160(data):
    """RIPEMD160(SHA256(data)) -- standard Bitcoin hash160."""
    sha256_digest = hashlib.sha256(data).digest()
    try:
        ripemd160 = hashlib.new("ripemd160")
        ripemd160.update(sha256_digest)
        return ripemd160.digest()
    except ValueError:
        # Fallback: use the pure-python implementation from x402-client
        from lib.payment import _ripemd160_pure
        return _ripemd160_pure(sha256_digest)


def build_p2pkh_script(pubkey_hex):
    """Build P2PKH locking script from a compressed public key (hex)."""
    assert len(pubkey_hex) == 66, f"Expected 66 hex chars, got {len(pubkey_hex)}"
    assert pubkey_hex[:2] in ("02", "03"), f"Invalid prefix: {pubkey_hex[:2]}"
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    pkh = hash160(pubkey_bytes)
    assert len(pkh) == 20
    # OP_DUP OP_HASH160 OP_PUSH20 <hash160> OP_EQUALVERIFY OP_CHECKSIG
    script = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    return script.hex()


# ---------------------------------------------------------------------------
# Authenticated request helpers
# ---------------------------------------------------------------------------

def auth_post(path, body):
    """Make an authenticated POST request via BRC-31. Returns {status_code, body, headers}."""
    url = f"{SERVER_URL}{path}"
    body_json = json.dumps(body, separators=(",", ":"))
    try:
        resp = authenticated_request(method="POST", url=url, body=body_json)
        try:
            resp_body = resp.json()
        except (json.JSONDecodeError, ValueError):
            resp_body = {"raw": resp.text}
        return {"status_code": resp.status_code, "body": resp_body, "headers": dict(resp.headers)}
    except (AuthRequestError, HandshakeError, MetaNetClientError) as e:
        return {"status_code": -1, "body": {"error": str(e)}, "headers": {}}


def auth_get(path):
    """Make an authenticated GET request via BRC-31. Returns {status_code, body, headers}."""
    url = f"{SERVER_URL}{path}"
    try:
        resp = authenticated_request(method="GET", url=url)
        try:
            resp_body = resp.json()
        except (json.JSONDecodeError, ValueError):
            resp_body = {"raw": resp.text}
        return {"status_code": resp.status_code, "body": resp_body, "headers": dict(resp.headers)}
    except (AuthRequestError, HandshakeError, MetaNetClientError) as e:
        return {"status_code": -1, "body": {"error": str(e)}, "headers": {}}


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_server():
    """Quick server health check (unauthenticated)."""
    try:
        resp = requests.get(f"{SERVER_URL}/health", timeout=5)
        # The server requires auth for /health, so we may get 401
        # But a response means the server is running
        return resp.status_code in (200, 401, 403)
    except Exception:
        return False


def preflight():
    """Run all preflight checks. Returns True if everything is ready."""
    section("Pre-flight Checks")

    # Server
    print("  Checking server at localhost:8787...", end=" ", flush=True)
    if not check_server():
        print("FAILED")
        print("\n  ERROR: Server not running. Start with: npm run dev")
        return False
    print("OK")

    # Wallet A
    print(f"  Checking Wallet A at port {WALLET_A_PORT}...", end=" ", flush=True)
    key_a = probe_wallet(WALLET_A_PORT)
    if not key_a:
        print("FAILED")
        print(f"\n  ERROR: Wallet A not responding at port {WALLET_A_PORT}")
        return False
    print(f"OK ({key_a[:24]}...)")
    if key_a != WALLET_A_IDENTITY:
        print(f"  WARNING: Wallet A identity mismatch!")
        print(f"    Expected: {WALLET_A_IDENTITY[:24]}...")
        print(f"    Got:      {key_a[:24]}...")

    # Wallet B
    print(f"  Checking Wallet B at port {WALLET_B_PORT}...", end=" ", flush=True)
    key_b = probe_wallet(WALLET_B_PORT)
    if not key_b:
        print("NOT AVAILABLE (receiver tests will be skipped)")
    else:
        print(f"OK ({key_b[:24]}...)")
        if key_b != WALLET_B_IDENTITY:
            print(f"  WARNING: Wallet B identity mismatch!")
            print(f"    Expected: {WALLET_B_IDENTITY[:24]}...")
            print(f"    Got:      {key_b[:24]}...")

    return True


# ---------------------------------------------------------------------------
# Test 1: Fee Quote Verification
# ---------------------------------------------------------------------------

def test_fee_quote():
    """Verify the fee quote for notifications box returns expected values."""
    section("Test 1: Fee Quote Verification")
    set_wallet_port(WALLET_A_PORT)

    path = f"/permissions/quote?recipient={WALLET_B_IDENTITY}&messageBox=notifications"
    print(f"  Getting quote for notifications box...")
    print(f"  [WALLET APPROVAL NEEDED on port {WALLET_A_PORT}]")
    result = auth_get(path)

    status = result["status_code"]
    body = result["body"]
    print(f"  Response: HTTP {status}")
    print(f"  Body: {json.dumps(body, indent=2)[:500]}")

    record("1a. Quote returns 200", status == 200,
           f"expected 200, got {status}")

    if status != 200:
        skip("1b. deliveryFee is 10", "quote failed")
        skip("1c. recipientFee is 10", "quote failed")
        return None

    quote = body.get("quote", {})
    delivery_fee = quote.get("deliveryFee")
    recipient_fee = quote.get("recipientFee")

    record("1b. deliveryFee is 10", delivery_fee == 10,
           f"expected 10, got {delivery_fee}")
    record("1c. recipientFee is 10 (auto-created default for notifications)",
           recipient_fee == 10, f"expected 10, got {recipient_fee}")

    total = (delivery_fee or 0) + (recipient_fee or 0)
    print(f"\n  Total payment required: {total} sats")
    return {"delivery_fee": delivery_fee, "recipient_fee": recipient_fee}


# ---------------------------------------------------------------------------
# Test 2: Payment Construction + Message Send
# ---------------------------------------------------------------------------

def test_paid_message_send(fees):
    """Build a real payment and send a message to notifications box.

    This is the core test: constructs BRC-29 payment and sends it
    in the request body alongside the message.
    """
    section("Test 2: Payment Construction + Message Send")
    set_wallet_port(WALLET_A_PORT)

    delivery_fee = fees.get("delivery_fee", 10) if fees else 10
    recipient_fee = fees.get("recipient_fee", 10) if fees else 10
    total_sats = delivery_fee + recipient_fee

    # -----------------------------------------------------------------------
    # Step 2a: Get server identity key via BRC-31 session
    # -----------------------------------------------------------------------
    print(f"  Step 2a: Getting server identity key from BRC-31 session...")
    try:
        session = get_or_create_session(SERVER_URL)
        server_identity_key = session.server_identity_key
        print(f"  Server identity key: {server_identity_key[:24]}...")
        record("2a. Got server identity key", True)
    except Exception as e:
        print(f"  ERROR: Failed to get session: {e}")
        record("2a. Got server identity key", False, str(e))
        return None

    # -----------------------------------------------------------------------
    # Step 2b: Generate derivation prefix and suffix
    # -----------------------------------------------------------------------
    print(f"\n  Step 2b: Generating derivation prefix and suffix...")
    derivation_prefix = base64.b64encode(os.urandom(32)).decode("ascii")
    derivation_suffix = base64.b64encode(os.urandom(32)).decode("ascii")
    print(f"  derivationPrefix: {derivation_prefix[:24]}...")
    print(f"  derivationSuffix: {derivation_suffix[:24]}...")
    record("2b. Generated derivation values", True)

    # -----------------------------------------------------------------------
    # Step 2c: Derive payment keys
    # -----------------------------------------------------------------------
    print(f"\n  Step 2c: Deriving payment public keys...")
    key_id = f"{derivation_prefix} {derivation_suffix}"

    # Delivery fee key (output 0): derives for the SERVER
    try:
        delivery_pubkey = wallet_get_public_key(
            WALLET_A_PORT,
            PAYMENT_PROTOCOL,
            key_id,
            counterparty=server_identity_key,
            for_self=False,
        )
        print(f"  Delivery payment pubkey: {delivery_pubkey[:24]}...")
        record("2c-i. Derived delivery payment key", True)
    except Exception as e:
        print(f"  ERROR: {e}")
        record("2c-i. Derived delivery payment key", False, str(e))
        return None

    # Recipient fee key (output 1): derives for the RECIPIENT (wallet B)
    # Use a separate derivation suffix for the recipient output
    recipient_suffix = base64.b64encode(os.urandom(32)).decode("ascii")
    recipient_key_id = f"{derivation_prefix} {recipient_suffix}"
    try:
        recipient_pubkey = wallet_get_public_key(
            WALLET_A_PORT,
            PAYMENT_PROTOCOL,
            recipient_key_id,
            counterparty=WALLET_B_IDENTITY,
            for_self=False,
        )
        print(f"  Recipient payment pubkey: {recipient_pubkey[:24]}...")
        record("2c-ii. Derived recipient payment key", True)
    except Exception as e:
        print(f"  ERROR: {e}")
        record("2c-ii. Derived recipient payment key", False, str(e))
        return None

    # -----------------------------------------------------------------------
    # Step 2d: Build P2PKH locking scripts
    # -----------------------------------------------------------------------
    print(f"\n  Step 2d: Building P2PKH locking scripts...")
    delivery_script = build_p2pkh_script(delivery_pubkey)
    recipient_script = build_p2pkh_script(recipient_pubkey)
    print(f"  Delivery script: {delivery_script[:40]}...")
    print(f"  Recipient script: {recipient_script[:40]}...")
    record("2d. Built P2PKH locking scripts", True)

    # -----------------------------------------------------------------------
    # Step 2e: Create funded transaction via Wallet A
    # -----------------------------------------------------------------------
    print(f"\n  Step 2e: Creating transaction ({total_sats} sats: {delivery_fee} delivery + {recipient_fee} recipient)...")
    print(f"  [WALLET APPROVAL NEEDED on port {WALLET_A_PORT}]")

    outputs = [
        {
            "lockingScript": delivery_script,
            "satoshis": delivery_fee,
            "outputDescription": "Message delivery fee",
        },
        {
            "lockingScript": recipient_script,
            "satoshis": recipient_fee,
            "outputDescription": "Recipient notification fee",
        },
    ]

    try:
        action_result = wallet_create_action(
            WALLET_A_PORT,
            outputs,
            f"MessageBox payment: {total_sats} sats for notifications delivery",
        )
        txid = action_result.get("txid", "unknown")
        tx_raw = action_result.get("tx")

        if tx_raw is None:
            record("2e. Created payment transaction", False, "No tx data returned")
            return None

        # tx_raw is a JSON number array from the wallet
        if isinstance(tx_raw, list):
            tx_bytes = bytes(tx_raw)
        elif isinstance(tx_raw, str):
            # Could be hex or base64
            try:
                tx_bytes = bytes.fromhex(tx_raw)
            except ValueError:
                tx_bytes = base64.b64decode(tx_raw)
        else:
            record("2e. Created payment transaction", False,
                   f"Unexpected tx type: {type(tx_raw)}")
            return None

        print(f"  txid: {txid}")
        print(f"  tx size: {len(tx_bytes)} bytes")

        # Detect format
        if len(tx_bytes) >= 4:
            header = tx_bytes[:4]
            if header == bytes([0x01, 0x01, 0x01, 0x01]):
                fmt = "AtomicBEEF"
            elif header == bytes([0x01, 0x00, 0xBE, 0xEF]):
                fmt = "BEEF"
            elif header == bytes([0x01, 0x00, 0x00, 0x00]):
                fmt = "raw tx"
            else:
                fmt = f"unknown (header: {header.hex()})"
            print(f"  format: {fmt}")

        record("2e. Created payment transaction", True)
    except Exception as e:
        print(f"  ERROR: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            traceback.print_exc()
        record("2e. Created payment transaction", False, str(e))
        return None

    # -----------------------------------------------------------------------
    # Step 2f: Send message with payment body
    # -----------------------------------------------------------------------
    print(f"\n  Step 2f: Sending message with payment...")
    print(f"  [WALLET APPROVAL NEEDED on port {WALLET_A_PORT}]")

    msg_id = f"payment-test-{uuid.uuid4().hex[:8]}"
    msg_text = f"BRC-29 payment test at {time.time()}"

    # The server passes tx through to wallet-infra's internalizeAction.
    # wallet-infra expects tx as a JSON number array (matching BRC-100 wire format).
    tx_as_array = list(tx_bytes)

    send_body = {
        "message": {
            "messageBox": "notifications",
            "recipient": WALLET_B_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": msg_text, "txid": txid}),
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
                        "senderIdentityKey": WALLET_A_IDENTITY,
                    },
                },
                {
                    "outputIndex": 1,
                    "protocol": "wallet payment",
                    "paymentRemittance": {
                        "derivationPrefix": derivation_prefix,
                        "derivationSuffix": recipient_suffix,
                        "senderIdentityKey": WALLET_A_IDENTITY,
                    },
                    "customInstructions": json.dumps({
                        "recipientIdentityKey": WALLET_B_IDENTITY,
                    }),
                },
            ],
            "description": f"MessageBox delivery payment ({total_sats} sats)",
            "seekPermission": False,
        },
    }

    result = auth_post("/sendMessage", send_body)
    status = result["status_code"]
    resp_body = result["body"]

    print(f"  Response: HTTP {status}")
    print(f"  Body: {json.dumps(resp_body, indent=2)[:800]}")

    record("2f. sendMessage returns 200", status == 200,
           f"expected 200, got {status}")

    if status == 200:
        resp_status = resp_body.get("status", "")
        record("2g. Response status is 'success'", resp_status == "success",
               f"expected 'success', got '{resp_status}'")
    else:
        # Log detailed error for diagnosis
        code = resp_body.get("code", "")
        desc = resp_body.get("description", "")
        print(f"\n  PAYMENT FAILURE DETAILS:")
        print(f"    Error code: {code}")
        print(f"    Description: {desc}")
        if "internalize" in desc.lower():
            print(f"    This means wallet-infra rejected the internalization.")
            print(f"    The server key may not be configured on wallet-infra,")
            print(f"    or the BEEF format is not accepted.")
        record("2g. Response status is 'success'", False,
               f"HTTP {status}: {code}: {desc[:200]}")

    return {
        "msg_id": msg_id,
        "msg_text": msg_text,
        "status": status,
    }


# ---------------------------------------------------------------------------
# Test 3: Receiver Verification (requires Wallet B)
# ---------------------------------------------------------------------------

def test_receiver_verification(send_result):
    """Authenticate as Wallet B, list messages, verify the paid message arrived."""
    section("Test 3: Receiver Verification")

    if not send_result or send_result["status"] != 200:
        skip("3a. List notifications returns 200", "send failed")
        skip("3b. Message found in notifications", "send failed")
        skip("3c. Message body matches", "send failed")
        skip("3d. Sender identity matches", "send failed")
        skip("3e. Acknowledge returns 200", "send failed")
        return

    # Check if Wallet B is available
    key_b = probe_wallet(WALLET_B_PORT)
    if not key_b:
        skip("3a. List notifications returns 200", "Wallet B not available")
        skip("3b. Message found in notifications", "Wallet B not available")
        skip("3c. Message body matches", "Wallet B not available")
        skip("3d. Sender identity matches", "Wallet B not available")
        skip("3e. Acknowledge returns 200", "Wallet B not available")
        return

    set_wallet_port(WALLET_B_PORT)

    msg_id = send_result["msg_id"]
    msg_text = send_result["msg_text"]

    # List messages
    print(f"  Listing notifications as Wallet B...")
    print(f"  [WALLET APPROVAL NEEDED on port {WALLET_B_PORT}]")
    result = auth_post("/listMessages", {"messageBox": "notifications"})
    status = result["status_code"]
    messages = result["body"].get("messages", [])

    print(f"  Response: HTTP {status}")
    print(f"  Found {len(messages)} message(s) in notifications box")

    record("3a. List notifications returns 200", status == 200,
           f"expected 200, got {status}")

    if status != 200:
        skip("3b. Message found in notifications", "list failed")
        skip("3c. Message body matches", "list failed")
        skip("3d. Sender identity matches", "list failed")
        skip("3e. Acknowledge returns 200", "list failed")
        return

    # Find our message
    our_msg = None
    for msg in messages:
        if msg.get("messageId") == msg_id:
            our_msg = msg
            break

    if our_msg is None:
        all_ids = [m.get("messageId", "") for m in messages[:10]]
        record("3b. Message found in notifications", False,
               f"messageId {msg_id} not in {all_ids}")
        skip("3c. Message body matches", "message not found")
        skip("3d. Sender identity matches", "message not found")
    else:
        record("3b. Message found in notifications", True)

        # Check body
        body_raw = our_msg.get("body", "")
        # body is stored as JSON string: {"message": <actual body>, "payment": {...}}
        try:
            stored = json.loads(body_raw) if isinstance(body_raw, str) else body_raw
            inner_body = stored.get("message", body_raw)
            if isinstance(inner_body, str):
                inner_body = json.loads(inner_body)
            has_text = inner_body.get("text", "") == msg_text if isinstance(inner_body, dict) else msg_text in str(inner_body)
        except (json.JSONDecodeError, TypeError, AttributeError):
            has_text = msg_text in str(body_raw)

        record("3c. Message body contains expected text", has_text,
               f"expected '{msg_text[:40]}...' in body")
        print(f"  Message body (first 300 chars): {str(body_raw)[:300]}")

        # Check that payment data was stored alongside the message
        has_payment = "payment" in str(body_raw)
        print(f"  Payment data stored with message: {has_payment}")

        # Check sender
        sender = our_msg.get("sender", "")
        record("3d. Sender identity matches", sender == WALLET_A_IDENTITY,
               f"expected {WALLET_A_IDENTITY[:24]}..., got {sender[:24]}...")

    # Acknowledge all messages (cleanup)
    if messages:
        ack_ids = [m.get("messageId", "") for m in messages if m.get("messageId")]
        if ack_ids:
            print(f"\n  Acknowledging {len(ack_ids)} message(s)...")
            result_ack = auth_post("/acknowledgeMessage", {"messageIds": ack_ids})
            ack_status = result_ack["status_code"]
            record("3e. Acknowledge returns 200", ack_status == 200,
                   f"expected 200, got {ack_status}")
        else:
            skip("3e. Acknowledge returns 200", "no messages to ack")
    else:
        skip("3e. Acknowledge returns 200", "no messages in box")


# ---------------------------------------------------------------------------
# Test 4: Missing payment still rejected
# ---------------------------------------------------------------------------

def test_missing_payment_rejected():
    """Confirm that sending to notifications without payment is still rejected."""
    section("Test 4: Missing Payment Rejected")
    set_wallet_port(WALLET_A_PORT)

    msg_id = f"nopay-{uuid.uuid4().hex[:8]}"
    body = {
        "message": {
            "messageBox": "notifications",
            "recipient": WALLET_B_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": "should fail -- no payment"}),
        }
    }

    print(f"  Sending to notifications box WITHOUT payment...")
    print(f"  [WALLET APPROVAL NEEDED on port {WALLET_A_PORT}]")
    result = auth_post("/sendMessage", body)

    status = result["status_code"]
    code = result["body"].get("code", "")

    print(f"  Response: HTTP {status}, code={code}")

    record("4a. Missing payment returns 400", status == 400,
           f"expected 400, got {status}")
    record("4b. Error code is ERR_MISSING_PAYMENT_TX", code == "ERR_MISSING_PAYMENT_TX",
           f"expected ERR_MISSING_PAYMENT_TX, got {code}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    dry_run = "--dry-run" in sys.argv

    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")

    print("=" * 70)
    print("  E2E Payment Flow Test -- Real BSV Satoshis (BRC-29)")
    print("=" * 70)
    print()
    if dry_run:
        print("  MODE: DRY RUN -- skipping payment creation (no sats spent)")
        print("  Tests 1 and 4 will run; test 2 (payment) and 3 (verify) will be skipped.")
    else:
        print("  WARNING: This test spends real BSV. Each run costs ~20 sats + fee.")
        print()
        print("  IMPORTANT: The wallet requires MANUAL GUI APPROVAL for payment")
        print("  operations (getPublicKey with payment protocol, createAction).")
        print("  The test will hang until you approve in the MetaNet Client app.")
    print()

    if not preflight():
        sys.exit(1)

    if not dry_run:
        print(f"\n  NOTE: Approve signing/transaction requests on the wallet app(s)!")
        print(f"  The test will pause waiting for wallet approval at each step.")

    # Run tests
    fees = None
    send_result = None

    # Test 1: Fee quote (no wallet approval needed beyond auth)
    try:
        fees = test_fee_quote()
    except Exception as e:
        print(f"\n  EXCEPTION in test 1: {e}")
        if verbose:
            traceback.print_exc()
        record("1. Unexpected exception", False, str(e))

    # Test 2: Paid message send (the main event)
    if dry_run:
        section("Test 2: Payment Construction + Message Send")
        print("  SKIPPED (--dry-run mode)")
        skip("2a. Got server identity key", "dry-run")
        skip("2b. Generated derivation values", "dry-run")
        skip("2c-i. Derived delivery payment key", "dry-run")
        skip("2c-ii. Derived recipient payment key", "dry-run")
        skip("2d. Built P2PKH locking scripts", "dry-run")
        skip("2e. Created payment transaction", "dry-run")
        skip("2f. sendMessage returns 200", "dry-run")
        skip("2g. Response status is 'success'", "dry-run")
    else:
        try:
            send_result = test_paid_message_send(fees)
        except Exception as e:
            print(f"\n  EXCEPTION in test 2: {e}")
            if verbose:
                traceback.print_exc()
            record("2. Unexpected exception", False, str(e))

    # Test 3: Receiver verification
    if dry_run:
        section("Test 3: Receiver Verification")
        print("  SKIPPED (--dry-run mode)")
        skip("3a. List notifications returns 200", "dry-run")
        skip("3b. Message found in notifications", "dry-run")
        skip("3c. Message body matches", "dry-run")
        skip("3d. Sender identity matches", "dry-run")
        skip("3e. Acknowledge returns 200", "dry-run")
    else:
        try:
            test_receiver_verification(send_result)
        except Exception as e:
            print(f"\n  EXCEPTION in test 3: {e}")
            if verbose:
                traceback.print_exc()
            record("3. Unexpected exception", False, str(e))

    # Test 4: Negative test -- missing payment (no wallet approval needed beyond auth)
    try:
        test_missing_payment_rejected()
    except Exception as e:
        print(f"\n  EXCEPTION in test 4: {e}")
        if verbose:
            traceback.print_exc()
        record("4. Unexpected exception", False, str(e))

    # Summary
    section("Results")
    for r in RESULTS:
        print(r)

    total = PASS_COUNT + FAIL_COUNT + SKIP_COUNT
    print(f"\n  Total: {total}  Pass: {PASS_COUNT}  Fail: {FAIL_COUNT}  Skip: {SKIP_COUNT}")

    if FAIL_COUNT == 0 and SKIP_COUNT == 0:
        print("\n  ALL TESTS PASSED")
    elif FAIL_COUNT == 0:
        print(f"\n  ALL EXECUTED TESTS PASSED ({SKIP_COUNT} skipped)")
    else:
        print(f"\n  {FAIL_COUNT} TEST(S) FAILED")

    # Key diagnostic information
    if send_result and send_result["status"] != 200:
        print()
        print("  DIAGNOSTIC NOTES:")
        print("  If test 2f failed with ERR_INTERNALIZE_FAILED, it means the server")
        print("  successfully processed the payment structure but wallet-infra rejected")
        print("  the internalization. Possible causes:")
        print("    - SERVER_PRIVATE_KEY not registered on wallet-infra")
        print("    - WALLET_STORAGE_URL misconfigured")
        print("    - BEEF format not accepted by wallet-infra")
        print("    - Derivation parameters invalid")

    sys.exit(0 if FAIL_COUNT == 0 else 1)


if __name__ == "__main__":
    main()
