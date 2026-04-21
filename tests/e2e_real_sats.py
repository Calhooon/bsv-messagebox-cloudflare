#!/usr/bin/env python3
"""E2E payment flow tests for bsv-messagebox-cloudflare using real BSV satoshis.

Tests the full payment lifecycle:
  1. Fee enforcement (missing payment -> 400)
  2. Quote verification (delivery + recipient fees)
  3. Permission blocking (recipientFee=-1 -> 403)
  4. Free delivery (inbox, no payment needed -> 200)
  5. Cross-identity message flow (A sends, B reads)

Prerequisites:
  - Rust server running at localhost:8787 (npm run dev)
  - At least ONE MetaNet Client wallet running (ports 3321 and/or 3322)
  - x402-client at /Users/johncalhoun/bsv/x402-client
  - Wallets must approve signing requests when prompted

Wallet auto-detection:
  The script probes both wallet ports (3321, 3322) with a short timeout.
  Whichever wallet(s) respond are used.  If only one wallet is live, tests
  that require two wallets (3: permission blocking, 5: cross-identity read)
  are skipped.

Usage:
  python3 tests/e2e_real_sats.py           # Run all tests
  python3 tests/e2e_real_sats.py --verbose  # Debug logging
"""

import sys
import os
import json
import time
import uuid
import logging
import traceback

# Add x402-client to path so we can import its libraries
X402_CLIENT_DIR = __import__("os").environ.get("X402_CLIENT_DIR", "") or __import__("sys").exit("Set X402_CLIENT_DIR env var")
sys.path.insert(0, X402_CLIENT_DIR)

from lib.handshake import do_handshake, HandshakeError
from lib.auth_request import authenticated_request, AuthRequestError
from lib.session import load_session, clear_session, Session
from lib.metanet import MetaNetClientError
import lib.metanet as metanet

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SERVER_URL = "http://localhost:8787"

# Known wallet ports and their expected identity keys
WALLETS = {
    3321: "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0",
    3322: "034aa44668fbc73ca5d490f0fa54b98b398b790856d8c55d540759ccefa5e6d0ce",
}

# Set at runtime by detect_wallets():
#   SENDER_PORT / SENDER_IDENTITY  = wallet we sign with (always set if any wallet is live)
#   RECEIVER_PORT / RECEIVER_IDENTITY = second wallet (None if only one is live)
SENDER_PORT: int | None = None
SENDER_IDENTITY: str | None = None
RECEIVER_PORT: int | None = None
RECEIVER_IDENTITY: str | None = None
BOTH_WALLETS_LIVE = False

log = logging.getLogger("e2e_real_sats")


# ---------------------------------------------------------------------------
# Wallet detection and switching
# ---------------------------------------------------------------------------

def probe_wallet(port: int, timeout: float = 5.0) -> str | None:
    """Probe a wallet port. Returns the identity key if responsive, else None."""
    import requests as _req
    try:
        resp = _req.post(
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


def detect_wallets():
    """Probe wallet ports and assign SENDER / RECEIVER roles."""
    global SENDER_PORT, SENDER_IDENTITY, RECEIVER_PORT, RECEIVER_IDENTITY, BOTH_WALLETS_LIVE

    live = {}  # port -> identity_key
    for port in WALLETS:
        print(f"  Probing wallet at port {port}...", end=" ", flush=True)
        key = probe_wallet(port)
        if key:
            print(f"OK  ({key[:20]}...)")
            live[port] = key
        else:
            print("not responding")

    if not live:
        return False

    ports = sorted(live.keys())
    # First live wallet is the sender (active signer)
    SENDER_PORT = ports[0]
    SENDER_IDENTITY = live[SENDER_PORT]

    if len(ports) >= 2:
        RECEIVER_PORT = ports[1]
        RECEIVER_IDENTITY = live[RECEIVER_PORT]
        BOTH_WALLETS_LIVE = True
    else:
        # Only one wallet: use the OTHER known identity as passive recipient
        # (we just need a valid 66-char compressed pubkey for the recipient field)
        other_port = [p for p in WALLETS if p != SENDER_PORT][0]
        RECEIVER_PORT = None  # can't actively sign with it
        RECEIVER_IDENTITY = WALLETS[other_port]
        BOTH_WALLETS_LIVE = False

    return True


def set_wallet_port(port: int):
    """Switch the x402-client metanet module to target a specific wallet port."""
    metanet.METANET_URL = f"http://localhost:{port}"
    clear_session(SERVER_URL)
    log.info("Switched wallet to port %d", port)


def use_sender():
    """Use the sender wallet for signing."""
    set_wallet_port(SENDER_PORT)


def use_receiver():
    """Use the receiver wallet for signing (only if both wallets are live)."""
    if not BOTH_WALLETS_LIVE or RECEIVER_PORT is None:
        raise RuntimeError("Receiver wallet is not live -- cannot sign as receiver")
    set_wallet_port(RECEIVER_PORT)


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------

def auth_post(path: str, body: dict) -> dict:
    """Make an authenticated POST request. Returns {status_code, body, headers}."""
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


def auth_get(path: str) -> dict:
    """Make an authenticated GET request. Returns {status_code, body, headers}."""
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
# Test infrastructure
# ---------------------------------------------------------------------------

PASS_COUNT = 0
FAIL_COUNT = 0
SKIP_COUNT = 0
RESULTS = []


def record(test_name: str, passed: bool, detail: str = ""):
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


def skip(test_name: str, reason: str):
    global SKIP_COUNT
    SKIP_COUNT += 1
    RESULTS.append(f"  SKIP  {test_name} -- {reason}")
    print(f"  SKIP  {test_name} -- {reason}")


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Test 1: Fee enforcement -- send to notifications without payment
# ---------------------------------------------------------------------------

def test_fee_enforcement():
    """Send to receiver's notifications box without payment -> 400."""
    section("Test 1: Fee Enforcement (missing payment -> 400)")
    use_sender()

    msg_id = f"test1-{uuid.uuid4().hex[:8]}"
    body = {
        "message": {
            "messageBox": "notifications",
            "recipient": RECEIVER_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": "test fee enforcement"}),
        }
        # No "payment" field -- should be rejected
    }

    print(f"  Sending to notifications box without payment...")
    print(f"  [WALLET APPROVAL NEEDED on port {SENDER_PORT}]")
    result = auth_post("/sendMessage", body)

    status = result["status_code"]
    code = result["body"].get("code", "")

    print(f"  Response: HTTP {status}, code={code}")
    print(f"  Body: {json.dumps(result['body'], indent=2)[:300]}")

    record("1a. Missing payment returns 400", status == 400,
           f"expected 400, got {status}")
    record("1b. Error code is ERR_MISSING_PAYMENT_TX", code == "ERR_MISSING_PAYMENT_TX",
           f"expected ERR_MISSING_PAYMENT_TX, got {code}")


# ---------------------------------------------------------------------------
# Test 2: Quote verification
# ---------------------------------------------------------------------------

def test_quote_verification():
    """Get delivery quotes for notifications and inbox boxes."""
    section("Test 2: Quote Verification")
    use_sender()

    # -- notifications quote --
    path = f"/permissions/quote?recipient={RECEIVER_IDENTITY}&messageBox=notifications"
    print(f"  Getting quote for notifications box...")
    print(f"  [WALLET APPROVAL NEEDED on port {SENDER_PORT}]")
    result = auth_get(path)

    status = result["status_code"]
    body = result["body"]
    print(f"  Response: HTTP {status}")
    print(f"  Body: {json.dumps(body, indent=2)[:500]}")

    quote = body.get("quote", {})
    delivery_fee = quote.get("deliveryFee")
    recipient_fee = quote.get("recipientFee")

    record("2a. Quote returns 200", status == 200,
           f"expected 200, got {status}")
    record("2b. deliveryFee is 100 (seeded in server_fees)", delivery_fee == 100,
           f"expected 100, got {delivery_fee}")
    record("2c. recipientFee is 10 (auto-created default for notifications)",
           recipient_fee == 10, f"expected 10, got {recipient_fee}")

    # -- inbox quote (should be free) --
    path_inbox = f"/permissions/quote?recipient={RECEIVER_IDENTITY}&messageBox=inbox"
    print(f"\n  Getting quote for inbox box...")
    result_inbox = auth_get(path_inbox)
    inbox_quote = result_inbox["body"].get("quote", {})
    inbox_delivery = inbox_quote.get("deliveryFee")
    inbox_recipient = inbox_quote.get("recipientFee")
    print(f"  Inbox quote: deliveryFee={inbox_delivery}, recipientFee={inbox_recipient}")

    record("2d. Inbox deliveryFee is 0", inbox_delivery == 0,
           f"expected 0, got {inbox_delivery}")
    record("2e. Inbox recipientFee is 0", inbox_recipient == 0,
           f"expected 0, got {inbox_recipient}")


# ---------------------------------------------------------------------------
# Test 3: Permission blocking (requires both wallets)
# ---------------------------------------------------------------------------

def test_permission_blocking():
    """Receiver blocks sender from inbox -> 403 on send."""
    section("Test 3: Permission Blocking")

    if not BOTH_WALLETS_LIVE:
        skip("3a. Set block permission", "receiver wallet not live")
        skip("3b. Blocked send returns 403", "receiver wallet not live")
        skip("3c. Error code is ERR_DELIVERY_BLOCKED", "receiver wallet not live")
        skip("3d. Unblock returns 200", "receiver wallet not live")
        return

    # Step 1: Receiver sets a block on sender for inbox
    use_receiver()

    set_body = {
        "messageBox": "inbox",
        "sender": SENDER_IDENTITY,
        "recipientFee": -1,  # blocked
    }
    print(f"  Receiver setting block on sender for inbox...")
    print(f"  [WALLET APPROVAL NEEDED on port {RECEIVER_PORT}]")
    result_set = auth_post("/permissions/set", set_body)
    set_status = result_set["status_code"]
    print(f"  Set permission response: HTTP {set_status}")
    print(f"  Body: {json.dumps(result_set['body'], indent=2)[:300]}")

    record("3a. Set block permission returns 200", set_status == 200,
           f"expected 200, got {set_status}")

    # Step 2: Sender tries to send -> should be blocked
    use_sender()

    msg_id = f"test3-{uuid.uuid4().hex[:8]}"
    send_body = {
        "message": {
            "messageBox": "inbox",
            "recipient": RECEIVER_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": "should be blocked"}),
        }
    }
    print(f"\n  Sender sending to receiver's inbox (should be blocked)...")
    print(f"  [WALLET APPROVAL NEEDED on port {SENDER_PORT}]")
    result_send = auth_post("/sendMessage", send_body)
    send_status = result_send["status_code"]
    send_code = result_send["body"].get("code", "")
    print(f"  Send response: HTTP {send_status}, code={send_code}")
    print(f"  Body: {json.dumps(result_send['body'], indent=2)[:300]}")

    record("3b. Blocked send returns 403", send_status == 403,
           f"expected 403, got {send_status}")
    record("3c. Error code is ERR_DELIVERY_BLOCKED", send_code == "ERR_DELIVERY_BLOCKED",
           f"expected ERR_DELIVERY_BLOCKED, got {send_code}")

    # Step 3: Clean up -- receiver removes block
    use_receiver()

    unblock_body = {
        "messageBox": "inbox",
        "sender": SENDER_IDENTITY,
        "recipientFee": 0,  # allow
    }
    print(f"\n  Receiver removing block...")
    print(f"  [WALLET APPROVAL NEEDED on port {RECEIVER_PORT}]")
    result_unblock = auth_post("/permissions/set", unblock_body)
    unblock_status = result_unblock["status_code"]
    print(f"  Unblock response: HTTP {unblock_status}")

    record("3d. Unblock returns 200", unblock_status == 200,
           f"expected 200, got {unblock_status}")


# ---------------------------------------------------------------------------
# Test 4: Free delivery (inbox, no payment needed)
# ---------------------------------------------------------------------------

def test_free_delivery():
    """Send to receiver's inbox (free) without payment -> 200."""
    section("Test 4: Free Delivery (inbox, no payment -> 200)")
    use_sender()

    msg_id = f"test4-{uuid.uuid4().hex[:8]}"
    body = {
        "message": {
            "messageBox": "inbox",
            "recipient": RECEIVER_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": "free delivery test", "ts": time.time()}),
        }
    }

    print(f"  Sending to inbox (free) with messageId={msg_id}...")
    print(f"  [WALLET APPROVAL NEEDED on port {SENDER_PORT}]")
    result = auth_post("/sendMessage", body)

    status = result["status_code"]
    resp_status = result["body"].get("status", "")
    print(f"  Response: HTTP {status}")
    print(f"  Body: {json.dumps(result['body'], indent=2)[:300]}")

    record("4a. Free delivery returns 200", status == 200,
           f"expected 200, got {status}")
    record("4b. Response status is 'success'", resp_status == "success",
           f"expected 'success', got '{resp_status}'")

    return msg_id


# ---------------------------------------------------------------------------
# Test 5: Cross-identity message flow (requires both wallets)
# ---------------------------------------------------------------------------

def test_cross_identity_flow(inbox_msg_id: str | None = None):
    """Sender sends message, receiver reads it from inbox."""
    section("Test 5: Cross-Identity Message Flow")

    # Step 1: Send from sender
    use_sender()

    msg_id = f"test5-{uuid.uuid4().hex[:8]}"
    msg_text = f"cross-identity test {time.time()}"
    send_body = {
        "message": {
            "messageBox": "inbox",
            "recipient": RECEIVER_IDENTITY,
            "messageId": msg_id,
            "body": json.dumps({"text": msg_text}),
        }
    }

    print(f"  Sender sending message (messageId={msg_id})...")
    print(f"  [WALLET APPROVAL NEEDED on port {SENDER_PORT}]")
    result_send = auth_post("/sendMessage", send_body)
    send_status = result_send["status_code"]
    print(f"  Send response: HTTP {send_status}")
    print(f"  Body: {json.dumps(result_send['body'], indent=2)[:300]}")

    record("5a. Send to inbox returns 200", send_status == 200,
           f"expected 200, got {send_status}")

    if send_status != 200:
        skip("5b. List inbox returns 200", "send failed")
        skip("5c. Message found in inbox", "send failed")
        skip("5d. Sender identity matches", "send failed")
        skip("5e. Message body matches", "send failed")
        skip("5f. Acknowledge returns 200", "send failed")
        return

    # Step 2: Receiver reads inbox
    if not BOTH_WALLETS_LIVE:
        skip("5b. List inbox returns 200", "receiver wallet not live")
        skip("5c. Message found in inbox", "receiver wallet not live")
        skip("5d. Sender identity matches", "receiver wallet not live")
        skip("5e. Message body matches", "receiver wallet not live")
        skip("5f. Acknowledge returns 200", "receiver wallet not live")
        return

    use_receiver()

    list_body = {"messageBox": "inbox"}
    print(f"\n  Receiver listing inbox messages...")
    print(f"  [WALLET APPROVAL NEEDED on port {RECEIVER_PORT}]")
    result_list = auth_post("/listMessages", list_body)
    list_status = result_list["status_code"]
    messages = result_list["body"].get("messages", [])
    print(f"  List response: HTTP {list_status}")
    print(f"  Found {len(messages)} message(s) in inbox")

    record("5b. List inbox returns 200", list_status == 200,
           f"expected 200, got {list_status}")

    # Find our message
    our_msg = None
    for msg in messages:
        if msg.get("messageId") == msg_id:
            our_msg = msg
            break

    if our_msg is None:
        all_ids = [m.get("messageId", "") for m in messages]
        record("5c. Message found in inbox", False,
               f"messageId {msg_id} not in {all_ids}")
        skip("5d. Sender identity matches", "message not found")
        skip("5e. Message body matches", "message not found")
    else:
        record("5c. Message found in inbox", True)

        sender = our_msg.get("sender", "")
        record("5d. Sender identity matches", sender == SENDER_IDENTITY,
               f"expected {SENDER_IDENTITY[:20]}..., got {sender[:20]}...")

        msg_body_raw = our_msg.get("body", "")
        record("5e. Message body contains expected text", msg_text in str(msg_body_raw),
               f"expected '{msg_text[:30]}...' in body")
        print(f"  Message body: {msg_body_raw[:200]}")

    # Step 3: Clean up
    if messages:
        ack_ids = [m.get("messageId", "") for m in messages if m.get("messageId")]
        if ack_ids:
            print(f"\n  Acknowledging {len(ack_ids)} message(s)...")
            result_ack = auth_post("/acknowledgeMessage", {"messageIds": ack_ids})
            ack_status = result_ack["status_code"]
            print(f"  Acknowledge response: HTTP {ack_status}")
            record("5f. Acknowledge returns 200", ack_status == 200,
                   f"expected 200, got {ack_status}")
        else:
            skip("5f. Acknowledge returns 200", "no messages to ack")
    else:
        skip("5f. Acknowledge returns 200", "no messages to ack")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def check_server():
    """Quick health check — 401 is expected (TS/Go parity: /health is authed)."""
    import requests
    try:
        resp = requests.get(f"{SERVER_URL}/health", timeout=5)
        # 200 (somehow auth'd) or 401 (unauth) both mean the server is up.
        return resp.status_code in (200, 401)
    except Exception:
        return False


def main():
    global SENDER_PORT, SENDER_IDENTITY, RECEIVER_PORT, RECEIVER_IDENTITY, BOTH_WALLETS_LIVE

    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")

    print("=" * 60)
    print("  E2E Payment Flow Tests -- Real BSV Satoshis")
    print("=" * 60)

    # Pre-flight: server
    section("Pre-flight Checks")
    print("  Checking server at localhost:8787...", end=" ", flush=True)
    if not check_server():
        print("FAILED")
        print("\n  ERROR: Server not running. Start with: npm run dev")
        sys.exit(1)
    print("OK")

    # Pre-flight: wallets
    print()
    if not detect_wallets():
        print("\n  ERROR: No wallets are responding.")
        print("  Need at least one MetaNet Client at port 3321 or 3322.")
        sys.exit(1)

    print(f"\n  Sender:   port {SENDER_PORT} -> {SENDER_IDENTITY[:24]}...")
    if BOTH_WALLETS_LIVE:
        print(f"  Receiver: port {RECEIVER_PORT} -> {RECEIVER_IDENTITY[:24]}...")
    else:
        print(f"  Receiver: OFFLINE (using identity {RECEIVER_IDENTITY[:24]}...)")
        print("  Tests 3 and 5 (require two wallets) will be partially skipped.")

    print(f"\n  NOTE: Approve signing requests on the wallet app(s)!")

    # Run tests
    inbox_msg_id = None
    for name, fn, args in [
        ("1", test_fee_enforcement, ()),
        ("2", test_quote_verification, ()),
        ("3", test_permission_blocking, ()),
        ("4", test_free_delivery, ()),
    ]:
        try:
            result = fn(*args)
            if name == "4" and result:
                inbox_msg_id = result
        except Exception as e:
            print(f"\n  EXCEPTION in test {name}: {e}")
            if verbose:
                traceback.print_exc()
            record(f"{name}. Unexpected exception", False, str(e))

    try:
        test_cross_identity_flow(inbox_msg_id)
    except Exception as e:
        print(f"\n  EXCEPTION in test 5: {e}")
        if verbose:
            traceback.print_exc()
        record("5. Unexpected exception", False, str(e))

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

    sys.exit(0 if FAIL_COUNT == 0 else 1)


if __name__ == "__main__":
    main()
