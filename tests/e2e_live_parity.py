#!/usr/bin/env python3
"""Live parity smoke test: Node.js reference vs Rust production message-box servers.

Runs the same set of requests against both the reference Node.js server and the
Rust port, and diffs response shapes field-by-field. Self-contained: only touches
the caller's own inbox — never sends messages to strangers.

Targets:
  Node.js reference:   http://localhost:8080  (local Docker: message-box-server-backend-1)
  Rust production:     https://bsv-messagebox-cloudflare.dev-a3e.workers.dev

NOTE: The public `messagebox.babbage.systems` was the original target, but it is
RETIRED as of 2026-04-12 (404 on all endpoints — see rust-bsv-worm handoff notes).
The local Docker container runs the exact same reference image, so it is the
canonical Node.js message-box-server for parity testing.

Prerequisites:
  - MetaNet Client wallet at localhost:3321
    (identity: 03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0)
  - x402-client at /Users/johncalhoun/bsv/x402-client

The x402-client persists BRC-31 sessions keyed by server URL, so talking to
two servers at once works naturally — no session-juggling required.
"""

import sys
import os
import json
import time
import uuid
import traceback

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

X402_CLIENT_DIR = "/Users/johncalhoun/bsv/x402-client"
sys.path.insert(0, X402_CLIENT_DIR)

from lib.handshake import do_handshake, HandshakeError, get_or_create_session
from lib.auth_request import authenticated_request, AuthRequestError
from lib.session import load_session, clear_session
from lib.metanet import MetaNetClientError
import lib.metanet as metanet
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NODE_URL = os.environ.get("NODE_URL", "http://localhost:8080")
RUST_URL = os.environ.get("RUST_URL", "https://bsv-messagebox-cloudflare.dev-a3e.workers.dev")

WALLET_PORT = 3321
SELF_IDENTITY = "03ef3231669022cc03aa26c74de784648faddb76609465c7181393efb335cbc7e0"

# Set the metanet module to point at our wallet
metanet.METANET_URL = f"http://localhost:{WALLET_PORT}"

# Fields to ignore when diffing. Two categories:
#   1. Dynamic values generated per-request (messageId, timestamps, etc.)
#   2. Operator-tunable config: deliveryFee and recipientFee are set per
#      deployment via the server_fees table and message_permissions rows.
#      Their *presence and type* is a parity concern, but their specific
#      numeric value is not (different operators will run with different
#      pricing — this repo defaults to 100 sats for notifications, the
#      babbage reference uses 10). normalize() replaces their values with
#      `<IGNORED>` so shape matches without requiring fee alignment.
DYNAMIC_FIELDS = {
    "messageId",
    "sentMessageId",
    "created_at",
    "updated_at",
    "createdAt",
    "updatedAt",
    "timestamp",
    "id",
    "deliveryFee",
    "recipientFee",
}

# Test results
RESULTS = []
PASS_COUNT = 0
FAIL_COUNT = 0


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def auth_request(server_url: str, method: str, path: str, body=None):
    """Authenticated request to a specific server. Returns {status, body, error}."""
    url = f"{server_url}{path}"
    try:
        if body is not None:
            body_json = json.dumps(body, separators=(",", ":"))
            resp = authenticated_request(method=method, url=url, body=body_json)
        else:
            resp = authenticated_request(method=method, url=url)
        try:
            return {"status": resp.status_code, "body": resp.json(), "error": None}
        except (json.JSONDecodeError, ValueError):
            return {"status": resp.status_code, "body": {"raw": resp.text}, "error": None}
    except (AuthRequestError, HandshakeError, MetaNetClientError) as e:
        return {"status": -1, "body": None, "error": str(e)}
    except Exception as e:
        return {"status": -1, "body": None, "error": f"{type(e).__name__}: {e}"}


def raw_get(server_url: str, path: str):
    """Unauthenticated GET. Returns {status, body, error}."""
    url = f"{server_url}{path}"
    try:
        resp = requests.get(url, timeout=30)
        try:
            return {"status": resp.status_code, "body": resp.json(), "error": None}
        except (json.JSONDecodeError, ValueError):
            return {"status": resp.status_code, "body": {"raw": resp.text}, "error": None}
    except Exception as e:
        return {"status": -1, "body": None, "error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------

import re

_ISO_8601_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
_MYSQL_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


def _classify_timestamp(value):
    """Return a shape tag for a timestamp-shaped string, or None if not a timestamp."""
    if not isinstance(value, str):
        return None
    if _ISO_8601_UTC.match(value):
        return "<ISO8601_UTC>"
    if _MYSQL_DATETIME.match(value):
        return "<MYSQL_DATETIME>"
    return None


def normalize(obj, ignore_fields=DYNAMIC_FIELDS):
    """Recursively normalize an object for comparison.

    - Replaces dynamic field VALUES with a shape sentinel:
      - Timestamp-shaped strings become a tag identifying the FORMAT
        (ISO8601 vs MySQL datetime etc.) so we still catch format drift.
      - Other ignored fields get a constant `<IGNORED>` sentinel so we
        still catch presence/absence differences.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ignore_fields:
                ts = _classify_timestamp(v)
                if ts is not None:
                    out[k] = ts
                elif k == "messageId" or k == "sentMessageId" or k == "id":
                    # IDs: only check that both sides have a string
                    out[k] = "<ID_STRING>" if isinstance(v, str) else f"<ID_{type(v).__name__}>"
                else:
                    out[k] = "<IGNORED>"
            else:
                out[k] = normalize(v, ignore_fields)
        return out
    if isinstance(obj, list):
        return [normalize(v, ignore_fields) for v in obj]
    return obj


def shape_diff(a, b, path="", diffs=None):
    """Walk two normalized objects and record shape/type/value differences."""
    if diffs is None:
        diffs = []

    # Type mismatch
    if type(a) is not type(b):
        # dict vs None etc
        diffs.append(f"{path or '<root>'}: type mismatch ({type(a).__name__} vs {type(b).__name__})")
        return diffs

    if isinstance(a, dict):
        a_keys = set(a.keys())
        b_keys = set(b.keys())
        only_a = a_keys - b_keys
        only_b = b_keys - a_keys
        for k in sorted(only_a):
            diffs.append(f"{path}.{k}: only in Node.js (value={a[k]!r})")
        for k in sorted(only_b):
            diffs.append(f"{path}.{k}: only in Rust (value={b[k]!r})")
        for k in sorted(a_keys & b_keys):
            shape_diff(a[k], b[k], f"{path}.{k}", diffs)
        return diffs

    if isinstance(a, list):
        if len(a) != len(b):
            diffs.append(f"{path}: list length {len(a)} vs {len(b)}")
            return diffs
        for i, (ai, bi) in enumerate(zip(a, b)):
            shape_diff(ai, bi, f"{path}[{i}]", diffs)
        return diffs

    # Scalars
    if a != b:
        diffs.append(f"{path or '<root>'}: value {a!r} vs {b!r}")
    return diffs


def compare(test_name: str, node_result: dict, rust_result: dict, ignore_fields=DYNAMIC_FIELDS):
    """Compare two results, record outcome, print a formatted block."""
    global PASS_COUNT, FAIL_COUNT

    # Status code diff
    status_diff = None
    if node_result["status"] != rust_result["status"]:
        status_diff = f"HTTP {node_result['status']} vs {rust_result['status']}"

    # Normalize bodies
    n_norm = normalize(node_result["body"], ignore_fields) if node_result["body"] is not None else None
    r_norm = normalize(rust_result["body"], ignore_fields) if rust_result["body"] is not None else None

    # Body shape diff
    body_diffs = []
    if n_norm is None and r_norm is None:
        pass
    elif n_norm is None or r_norm is None:
        body_diffs.append(f"<root>: one side has no body (node={n_norm!r}, rust={r_norm!r})")
    else:
        shape_diff(n_norm, r_norm, "", body_diffs)

    all_diffs = []
    if status_diff:
        all_diffs.append(f"status: {status_diff}")
    all_diffs.extend(body_diffs)

    passed = len(all_diffs) == 0
    if passed:
        PASS_COUNT += 1
        status_label = "PASS"
    else:
        FAIL_COUNT += 1
        status_label = "FAIL"

    print(f"\n{test_name}")
    print(f"  Node.js: HTTP {node_result['status']}, {_short(node_result['body'])}")
    print(f"  Rust:    HTTP {rust_result['status']}, {_short(rust_result['body'])}")
    if all_diffs:
        print(f"  DIFF:")
        for d in all_diffs:
            print(f"    - {d}")
    else:
        print(f"  DIFF:    IDENTICAL (ignoring dynamic fields)")
    print(f"  STATUS:  {status_label}")

    RESULTS.append({
        "name": test_name,
        "passed": passed,
        "diffs": all_diffs,
        "node_status": node_result["status"],
        "rust_status": rust_result["status"],
        "node_body": node_result["body"],
        "rust_body": rust_result["body"],
    })
    return passed


def _short(obj, limit=400):
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = str(obj)
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


def section(title):
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_1_connectivity():
    section("Step 1: Connectivity check (GET /health unauthenticated)")
    n = raw_get(NODE_URL, "/health")
    r = raw_get(RUST_URL, "/health")
    # Rust /health is supposed to require auth now to match Node.js. Compare.
    compare("TEST 1: GET /health (unauthenticated)", n, r)


def test_2_handshake():
    section("Step 2: BRC-31 handshake with both servers")

    # Clear any existing sessions to force a fresh handshake for observation
    clear_session(NODE_URL)
    clear_session(RUST_URL)

    node_session = None
    rust_session = None
    node_err = None
    rust_err = None

    try:
        node_session = get_or_create_session(NODE_URL)
    except Exception as e:
        node_err = str(e)

    try:
        rust_session = get_or_create_session(RUST_URL)
    except Exception as e:
        rust_err = str(e)

    print(f"\nTEST 2: BRC-31 handshake")
    if node_session:
        print(f"  Node.js: OK, server_identity_key={node_session.server_identity_key[:32]}...")
    else:
        print(f"  Node.js: FAILED — {node_err}")
    if rust_session:
        print(f"  Rust:    OK, server_identity_key={rust_session.server_identity_key[:32]}...")
    else:
        print(f"  Rust:    FAILED — {rust_err}")

    both_ok = bool(node_session) and bool(rust_session)
    print(f"  DIFF:    {'server identity keys differ as expected (recorded, ignored for parity)' if both_ok else 'handshake failure on one or both sides'}")
    print(f"  STATUS:  {'PASS' if both_ok else 'FAIL'}")

    global PASS_COUNT, FAIL_COUNT
    if both_ok:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1

    RESULTS.append({
        "name": "TEST 2: BRC-31 handshake",
        "passed": both_ok,
        "diffs": [] if both_ok else [f"node_err={node_err}", f"rust_err={rust_err}"],
    })
    return both_ok


def test_3_quote_notifications():
    section("Step 3: Quote for 'notifications' box")
    path = f"/permissions/quote?recipient={SELF_IDENTITY}&messageBox=notifications"
    n = auth_request(NODE_URL, "GET", path)
    r = auth_request(RUST_URL, "GET", path)
    compare("TEST 3: GET /permissions/quote (notifications, self)", n, r)


def test_4_quote_task_inbox():
    section("Step 4: Quote for 'task_inbox' box")
    path = f"/permissions/quote?recipient={SELF_IDENTITY}&messageBox=task_inbox"
    n = auth_request(NODE_URL, "GET", path)
    r = auth_request(RUST_URL, "GET", path)
    compare("TEST 4: GET /permissions/quote (task_inbox, self)", n, r)


def test_5_list_nonexistent_box():
    section("Step 5: List messages in non-existent box")
    body = {"messageBox": "rust-parity-test-box"}
    n = auth_request(NODE_URL, "POST", "/listMessages", body)
    r = auth_request(RUST_URL, "POST", "/listMessages", body)
    compare("TEST 5: POST /listMessages (non-existent box)", n, r)


def test_6_send_self(timestamp_box: str):
    section("Step 6: Send message to SELF")
    body = {
        "message": {
            "recipient": SELF_IDENTITY,
            "messageBox": timestamp_box,
            "messageId": f"parity-{uuid.uuid4().hex[:12]}",
            "body": json.dumps({"test": True}),
        }
    }
    # Use distinct messageIds per server so neither thinks it's a duplicate.
    body_node = json.loads(json.dumps(body))
    body_node["message"]["messageId"] = f"parity-node-{uuid.uuid4().hex[:12]}"
    body_rust = json.loads(json.dumps(body))
    body_rust["message"]["messageId"] = f"parity-rust-{uuid.uuid4().hex[:12]}"

    n = auth_request(NODE_URL, "POST", "/sendMessage", body_node)
    r = auth_request(RUST_URL, "POST", "/sendMessage", body_rust)
    compare("TEST 6: POST /sendMessage (to self)", n, r)
    return body_node["message"]["messageId"], body_rust["message"]["messageId"]


def test_7_list_own_box(timestamp_box: str, node_msg_id: str, rust_msg_id: str):
    section("Step 7: List our own test box")
    body = {"messageBox": timestamp_box}
    n = auth_request(NODE_URL, "POST", "/listMessages", body)
    r = auth_request(RUST_URL, "POST", "/listMessages", body)

    # Extract the single message we just sent on each side and compare the
    # envelope shape. We ignore messageId and timestamps.
    compare("TEST 7a: POST /listMessages (own box) — top-level shape", n, r)

    def find_msg(result, msg_id):
        if not result["body"]:
            return None
        msgs = result["body"].get("messages", [])
        for m in msgs:
            if m.get("messageId") == msg_id:
                return m
        # Fall back: if only one, return it
        if len(msgs) == 1:
            return msgs[0]
        return None

    node_msg = find_msg(n, node_msg_id)
    rust_msg = find_msg(r, rust_msg_id)

    if node_msg is None or rust_msg is None:
        print(f"\nTEST 7b: Message envelope comparison")
        print(f"  Node.js msg found: {node_msg is not None}")
        print(f"  Rust msg found:    {rust_msg is not None}")
        print(f"  STATUS:  SKIP (could not locate message on one/both sides)")
        return n, r, node_msg, rust_msg

    # Build a faux result for compare()
    n_wrap = {"status": 200, "body": node_msg, "error": None}
    r_wrap = {"status": 200, "body": rust_msg, "error": None}
    compare("TEST 7b: single message envelope shape", n_wrap, r_wrap)
    return n, r, node_msg, rust_msg


def test_8_acknowledge(node_list, rust_list, node_msg_id, rust_msg_id):
    section("Step 8: Acknowledge the test message")

    def find_internal_id(result, msg_id):
        if not result["body"]:
            return None
        for m in result["body"].get("messages", []):
            if m.get("messageId") == msg_id:
                # Some servers return id, others use messageId as the ack id
                return m.get("messageId") or m.get("id")
        return None

    n_ack_id = find_internal_id(node_list, node_msg_id)
    r_ack_id = find_internal_id(rust_list, rust_msg_id)

    if n_ack_id is None:
        n_ack_id = node_msg_id
    if r_ack_id is None:
        r_ack_id = rust_msg_id

    n = auth_request(NODE_URL, "POST", "/acknowledgeMessage", {"messageIds": [n_ack_id]})
    r = auth_request(RUST_URL, "POST", "/acknowledgeMessage", {"messageIds": [r_ack_id]})
    compare("TEST 8: POST /acknowledgeMessage", n, r)


def test_9_permissions():
    section("Step 9: Permissions set/get on ourselves")
    perms_box = "rust-parity-test-perms"
    set_body = {"messageBox": perms_box, "recipientFee": 0}
    n_set = auth_request(NODE_URL, "POST", "/permissions/set", set_body)
    r_set = auth_request(RUST_URL, "POST", "/permissions/set", set_body)
    compare("TEST 9a: POST /permissions/set", n_set, r_set)

    get_path = f"/permissions/get?messageBox={perms_box}"
    n_get = auth_request(NODE_URL, "GET", get_path)
    r_get = auth_request(RUST_URL, "GET", get_path)
    compare("TEST 9b: GET /permissions/get", n_get, r_get)


def test_10_error_missing_messagebox():
    section("Step 10: Error path — missing messageBox on /listMessages")
    # NOTE: x402-client's authenticated_request requires a body string for POST
    # to compute the signature. We send literal "{}" so both servers receive an
    # empty JSON object.
    n = auth_request(NODE_URL, "POST", "/listMessages", {})
    r = auth_request(RUST_URL, "POST", "/listMessages", {})
    compare("TEST 10: POST /listMessages (empty body — missing messageBox)", n, r)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 72)
    print("  LIVE PARITY SMOKE TEST: Node.js prod vs Rust prod")
    print("=" * 72)
    print(f"  Node.js: {NODE_URL}")
    print(f"  Rust:    {RUST_URL}")
    print(f"  Wallet:  localhost:{WALLET_PORT}")
    print(f"  Identity: {SELF_IDENTITY[:24]}...")
    print()
    print("  NOTE: Approve wallet signing prompts as they appear.")
    print("  This test is self-contained — it only touches the caller's own inbox.")

    try:
        test_1_connectivity()
    except Exception as e:
        print(f"  EXCEPTION in test 1: {e}")
        traceback.print_exc()

    try:
        handshake_ok = test_2_handshake()
    except Exception as e:
        print(f"  EXCEPTION in test 2: {e}")
        traceback.print_exc()
        handshake_ok = False

    if not handshake_ok:
        print("\nHandshake failed on one or both servers — aborting remaining tests.")
        summary()
        sys.exit(1)

    try:
        test_3_quote_notifications()
    except Exception as e:
        print(f"  EXCEPTION in test 3: {e}")
        traceback.print_exc()

    try:
        test_4_quote_task_inbox()
    except Exception as e:
        print(f"  EXCEPTION in test 4: {e}")
        traceback.print_exc()

    try:
        test_5_list_nonexistent_box()
    except Exception as e:
        print(f"  EXCEPTION in test 5: {e}")
        traceback.print_exc()

    timestamp_box = f"rust-parity-test-{int(time.time())}"
    node_msg_id = None
    rust_msg_id = None
    node_list = None
    rust_list = None

    try:
        node_msg_id, rust_msg_id = test_6_send_self(timestamp_box)
    except Exception as e:
        print(f"  EXCEPTION in test 6: {e}")
        traceback.print_exc()

    if node_msg_id and rust_msg_id:
        try:
            node_list, rust_list, _, _ = test_7_list_own_box(timestamp_box, node_msg_id, rust_msg_id)
        except Exception as e:
            print(f"  EXCEPTION in test 7: {e}")
            traceback.print_exc()

        if node_list and rust_list:
            try:
                test_8_acknowledge(node_list, rust_list, node_msg_id, rust_msg_id)
            except Exception as e:
                print(f"  EXCEPTION in test 8: {e}")
                traceback.print_exc()

    try:
        test_9_permissions()
    except Exception as e:
        print(f"  EXCEPTION in test 9: {e}")
        traceback.print_exc()

    try:
        test_10_error_missing_messagebox()
    except Exception as e:
        print(f"  EXCEPTION in test 10: {e}")
        traceback.print_exc()

    summary()
    sys.exit(0 if FAIL_COUNT == 0 else 1)


def summary():
    section("SUMMARY")
    print(f"  Total: {PASS_COUNT + FAIL_COUNT}  Pass: {PASS_COUNT}  Fail: {FAIL_COUNT}")
    print()
    if FAIL_COUNT == 0:
        print("  ALL PARITY CHECKS PASSED")
        return
    print("  PARITY BUGS FOUND:")
    for r in RESULTS:
        if not r["passed"]:
            print(f"\n  [FAIL] {r['name']}")
            for d in r["diffs"]:
                print(f"    - {d}")


if __name__ == "__main__":
    main()
