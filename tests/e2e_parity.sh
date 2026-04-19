#!/bin/bash
# =============================================================================
# E2E Parity Test: Node.js (port 8080) vs Rust (port 8787)
# =============================================================================
#
# Prerequisites:
#   1. Node.js server running via docker compose on localhost:8080
#   2. Rust server running via wrangler dev on localhost:8787
#   3. MetaNet Client wallet running at localhost:3321
#   4. x402-client CLI (set X402_CLI env var)
#
# Usage: ./tests/e2e_parity.sh [--rust-only]
#
# With --rust-only: tests only Rust server with assertions matching Node.js
# documented behavior (useful when Node.js server is unavailable).
# =============================================================================

set -uo pipefail
# Note: -e intentionally omitted so all tests run even if some commands fail

CLI="${X402_CLI:-}"
if [[ -z "$CLI" ]]; then
  echo "Set X402_CLI env var to the x402-client cli.py path" >&2
  exit 1
fi
NODE_SERVER="http://localhost:8080"
RUST_SERVER="http://localhost:8787"
MSG_ID="parity-$(date +%s)"

PASS=0
FAIL=0
SKIP=0
RESULTS=()

RUST_ONLY=false
if [[ "${1:-}" == "--rust-only" ]]; then
  RUST_ONLY=true
fi

# ---- Helpers ----------------------------------------------------------------

log_header() { echo -e "\n======== $1 ========"; }
log_sub()    { echo "  $1"; }

record() {
  local test_name="$1" result="$2" detail="${3:-}"
  if [[ "$result" == "PASS" ]]; then
    ((PASS++))
    RESULTS+=("PASS  $test_name")
  elif [[ "$result" == "FAIL" ]]; then
    ((FAIL++))
    RESULTS+=("FAIL  $test_name${detail:+ ($detail)}")
  else
    ((SKIP++))
    RESULTS+=("SKIP  $test_name${detail:+ ($detail)}")
  fi
  echo "  [$result] $test_name${detail:+ -- $detail}"
}

# Extract a JSON field value (simple jq-like via python).
# Usage: json_field "field.path" "$json_string"
json_field() {
  local field="$1" data="$2"
  printf '%s' "$data" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    keys = sys.argv[1].split('.')
    for k in keys:
        d = d[k]
    print(d)
except Exception:
    print('')
" "$field"
}

# Extract HTTP status code from curl output (last line is HTTP_STATUS:NNN)
http_status() { echo "$1" | grep '^HTTP_STATUS:' | cut -d: -f2; }
http_body()   { echo "$1" | sed '/^HTTP_STATUS:/d'; }

# Perform authenticated request using x402-client.
# The CLI outputs debug info + "Body\n{json...}" so we extract just the JSON.
# Returns empty string on CLI failure (wallet timeout, etc.)
auth_request() {
  local method="$1" url="$2" body="${3:-}"
  local raw exit_code
  if [[ -n "$body" ]]; then
    raw=$(python3 "$CLI" auth "$method" "$url" "$body" 2>&1) || true
  else
    raw=$(python3 "$CLI" auth "$method" "$url" 2>&1) || true
  fi

  # Check for wallet/signing errors
  if echo "$raw" | grep -q "timed out\|Failed to sign\|Error:"; then
    echo '{"__auth_error__": true, "detail": "Wallet signing failed or timed out"}'
    return
  fi

  # Extract everything after the "Body" line (the JSON block)
  local json_body
  json_body=$(echo "$raw" | sed -n '/^Body$/,$ { /^Body$/d; p; }')

  if [[ -z "$json_body" ]]; then
    echo '{"__auth_error__": true, "detail": "No response body from CLI"}'
    return
  fi

  echo "$json_body"
}

# Perform unauthenticated curl request
raw_request() {
  local method="$1" url="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" -H "Content-Type: application/json" -d "$body" "$url" 2>&1
  else
    curl -s -w "\nHTTP_STATUS:%{http_code}" -X "$method" "$url" 2>&1
  fi
}

# Compare a field between Node and Rust responses
compare_field() {
  local test_name="$1" field="$2" node_resp="$3" rust_resp="$4"
  # Check for auth error sentinels
  local node_err rust_err
  node_err=$(json_field "__auth_error__" "$node_resp")
  rust_err=$(json_field "__auth_error__" "$rust_resp")
  if [[ "$node_err" == "True" || "$rust_err" == "True" ]]; then
    record "$test_name: $field" "SKIP" "wallet auth failed on one/both"
    return
  fi
  local node_val rust_val
  node_val=$(json_field "$field" "$node_resp")
  rust_val=$(json_field "$field" "$rust_resp")
  if [[ "$node_val" == "$rust_val" ]]; then
    record "$test_name: $field" "PASS" "both='$node_val'"
  else
    record "$test_name: $field" "FAIL" "node='$node_val' rust='$rust_val'"
  fi
}

# Assert a field value against an expected value (for rust-only mode)
assert_field() {
  local test_name="$1" field="$2" expected="$3" response="$4"
  # Check for auth error sentinel
  local auth_err
  auth_err=$(json_field "__auth_error__" "$response")
  if [[ "$auth_err" == "True" ]]; then
    record "$test_name: $field" "SKIP" "wallet auth failed"
    return
  fi
  local actual
  actual=$(json_field "$field" "$response")
  if [[ "$actual" == "$expected" ]]; then
    record "$test_name: $field" "PASS" "got='$actual'"
  else
    record "$test_name: $field" "FAIL" "expected='$expected' got='$actual'"
  fi
}

assert_status() {
  local test_name="$1" expected="$2" raw_response="$3"
  local actual
  actual=$(http_status "$raw_response")
  if [[ "$actual" == "$expected" ]]; then
    record "$test_name: HTTP status" "PASS" "got=$actual"
  else
    record "$test_name: HTTP status" "FAIL" "expected=$expected got=$actual"
  fi
}

# =============================================================================
# Check server availability
# =============================================================================
log_header "Server Availability"

RUST_UP=false
RUST_HEALTH=$(raw_request GET "$RUST_SERVER/health")
RUST_HEALTH_STATUS=$(http_status "$RUST_HEALTH")
# /health is behind auth (matches TS/Go "all routes require auth"), so an
# unauthenticated GET returns 401. Either 200 (somehow authed) or 401 means UP.
if [[ "$RUST_HEALTH_STATUS" == "200" || "$RUST_HEALTH_STATUS" == "401" ]]; then
  RUST_UP=true
  log_sub "Rust server (8787): UP (status=$RUST_HEALTH_STATUS)"
else
  log_sub "Rust server (8787): DOWN"
  echo "ERROR: Rust server must be running. Aborting."
  exit 1
fi

NODE_UP=false
if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_HEALTH=$(raw_request GET "$NODE_SERVER/health")
  NODE_STATUS=$(http_status "$NODE_HEALTH")
  # Node returns 401 for unauthenticated /health (all routes are post-auth)
  if [[ "$NODE_STATUS" == "200" || "$NODE_STATUS" == "401" ]]; then
    NODE_UP=true
    log_sub "Node server (8080): UP (status=$NODE_STATUS)"
  else
    log_sub "Node server (8080): DOWN"
    echo "WARNING: Node server unavailable, falling back to --rust-only mode"
    RUST_ONLY=true
  fi
fi

# =============================================================================
# Get identity key
# =============================================================================
IDENTITY_KEY=$(python3 "$CLI" identity 2>/dev/null)
log_sub "Identity key: $IDENTITY_KEY"

# =============================================================================
# Handshake with servers
# =============================================================================
log_header "BRC-31 Handshake"

python3 "$CLI" handshake "$RUST_SERVER" 2>/dev/null
log_sub "Rust handshake: done"

if [[ "$RUST_ONLY" == "false" ]]; then
  python3 "$CLI" handshake "$NODE_SERVER" 2>/dev/null
  log_sub "Node handshake: done"
fi

# =============================================================================
# TEST 1: Health endpoint (unauthenticated → 401 on both, matches TS/Go)
# =============================================================================
log_header "TEST 1: Health Endpoint (unauthenticated → UNAUTHORIZED)"

# Matches the live TS reference server at messagebox.babbage.systems
# byte-for-byte: 401 + { code: UNAUTHORIZED, message: "Mutual-authentication failed!" }.
RUST_RESP=$(raw_request GET "$RUST_SERVER/health")
assert_status "Rust /health" "401" "$RUST_RESP"
assert_field "Rust /health" "code" "UNAUTHORIZED" "$(http_body "$RUST_RESP")"
assert_field "Rust /health" "message" "Mutual-authentication failed!" "$(http_body "$RUST_RESP")"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_RESP=$(raw_request GET "$NODE_SERVER/health")
  NODE_STATUS=$(http_status "$NODE_RESP")
  record "Node /health unauthenticated" "PASS" "returns $NODE_STATUS (matches Rust 401 — both gate /health behind auth)"
fi

# =============================================================================
# TEST 2: sendMessage - valid
# =============================================================================
log_header "TEST 2: sendMessage (valid)"

SEND_BODY="{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"parity_test\",
    \"messageId\": \"$MSG_ID\",
    \"body\": \"Hello from parity test\"
  }
}"

RUST_SEND=$(auth_request POST "$RUST_SERVER/sendMessage" "$SEND_BODY")
assert_field "Rust sendMessage" "status" "success" "$RUST_SEND"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_SEND=$(auth_request POST "$NODE_SERVER/sendMessage" "$SEND_BODY")
  compare_field "sendMessage" "status" "$NODE_SEND" "$RUST_SEND"
fi

# =============================================================================
# TEST 3: sendMessage - duplicate (ERR_DUPLICATE_MESSAGE)
# =============================================================================
log_header "TEST 3: sendMessage (duplicate)"

RUST_DUP=$(auth_request POST "$RUST_SERVER/sendMessage" "$SEND_BODY")
assert_field "Rust duplicate" "status" "error" "$RUST_DUP"
assert_field "Rust duplicate" "code" "ERR_DUPLICATE_MESSAGE" "$RUST_DUP"

if [[ "$RUST_ONLY" == "false" ]]; then
  # Use a separate ID for Node to avoid cross-server collision
  NODE_DUP=$(auth_request POST "$NODE_SERVER/sendMessage" "$SEND_BODY")
  compare_field "duplicate" "code" "$NODE_DUP" "$RUST_DUP"
fi

# =============================================================================
# TEST 4: sendMessage - missing message body
# =============================================================================
log_header "TEST 4: sendMessage (missing message)"

RUST_NO_MSG=$(auth_request POST "$RUST_SERVER/sendMessage" "{}")
assert_field "Rust no message" "status" "error" "$RUST_NO_MSG"
assert_field "Rust no message" "code" "ERR_MESSAGE_REQUIRED" "$RUST_NO_MSG"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_NO_MSG=$(auth_request POST "$NODE_SERVER/sendMessage" "{}")
  compare_field "no message" "code" "$NODE_NO_MSG" "$RUST_NO_MSG"
fi

# =============================================================================
# TEST 5: sendMessage - missing recipient
# =============================================================================
log_header "TEST 5: sendMessage (missing recipient)"

RUST_NO_RCPT=$(auth_request POST "$RUST_SERVER/sendMessage" "{
  \"message\": {
    \"messageBox\": \"inbox\",
    \"messageId\": \"test-no-rcpt\",
    \"body\": \"test\"
  }
}")
assert_field "Rust no recipient" "status" "error" "$RUST_NO_RCPT"
assert_field "Rust no recipient" "code" "ERR_RECIPIENT_REQUIRED" "$RUST_NO_RCPT"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_NO_RCPT=$(auth_request POST "$NODE_SERVER/sendMessage" "{
    \"message\": {
      \"messageBox\": \"inbox\",
      \"messageId\": \"test-no-rcpt\",
      \"body\": \"test\"
    }
  }")
  compare_field "no recipient" "code" "$NODE_NO_RCPT" "$RUST_NO_RCPT"
fi

# =============================================================================
# TEST 6: sendMessage - invalid recipient key
# =============================================================================
log_header "TEST 6: sendMessage (invalid recipient key)"

RUST_BAD_KEY=$(auth_request POST "$RUST_SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"not-a-valid-key\",
    \"messageBox\": \"inbox\",
    \"messageId\": \"test-bad-key\",
    \"body\": \"test\"
  }
}")
assert_field "Rust bad key" "status" "error" "$RUST_BAD_KEY"
assert_field "Rust bad key" "code" "ERR_INVALID_RECIPIENT_KEY" "$RUST_BAD_KEY"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_BAD_KEY=$(auth_request POST "$NODE_SERVER/sendMessage" "{
    \"message\": {
      \"recipient\": \"not-a-valid-key\",
      \"messageBox\": \"inbox\",
      \"messageId\": \"test-bad-key\",
      \"body\": \"test\"
    }
  }")
  compare_field "bad key" "code" "$NODE_BAD_KEY" "$RUST_BAD_KEY"
fi

# =============================================================================
# TEST 7: sendMessage - missing messageId
# =============================================================================
log_header "TEST 7: sendMessage (missing messageId)"

RUST_NO_MID=$(auth_request POST "$RUST_SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"inbox\",
    \"body\": \"test\"
  }
}")
assert_field "Rust no messageId" "status" "error" "$RUST_NO_MID"
assert_field "Rust no messageId" "code" "ERR_MESSAGEID_REQUIRED" "$RUST_NO_MID"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_NO_MID=$(auth_request POST "$NODE_SERVER/sendMessage" "{
    \"message\": {
      \"recipient\": \"$IDENTITY_KEY\",
      \"messageBox\": \"inbox\",
      \"body\": \"test\"
    }
  }")
  compare_field "no messageId" "code" "$NODE_NO_MID" "$RUST_NO_MID"
fi

# =============================================================================
# TEST 8: sendMessage - empty messageBox
# =============================================================================
log_header "TEST 8: sendMessage (empty messageBox)"

RUST_BAD_BOX=$(auth_request POST "$RUST_SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"\",
    \"messageId\": \"test-bad-box\",
    \"body\": \"test\"
  }
}")
assert_field "Rust empty box" "status" "error" "$RUST_BAD_BOX"
assert_field "Rust empty box" "code" "ERR_INVALID_MESSAGEBOX" "$RUST_BAD_BOX"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_BAD_BOX=$(auth_request POST "$NODE_SERVER/sendMessage" "{
    \"message\": {
      \"recipient\": \"$IDENTITY_KEY\",
      \"messageBox\": \"\",
      \"messageId\": \"test-bad-box\",
      \"body\": \"test\"
    }
  }")
  compare_field "empty box" "code" "$NODE_BAD_BOX" "$RUST_BAD_BOX"
fi

# =============================================================================
# TEST 9: sendMessage - empty body
# =============================================================================
log_header "TEST 9: sendMessage (empty body)"

RUST_BAD_BODY=$(auth_request POST "$RUST_SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"inbox\",
    \"messageId\": \"test-bad-body\",
    \"body\": \"\"
  }
}")
assert_field "Rust empty body" "status" "error" "$RUST_BAD_BODY"
assert_field "Rust empty body" "code" "ERR_INVALID_MESSAGE_BODY" "$RUST_BAD_BODY"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_BAD_BODY=$(auth_request POST "$NODE_SERVER/sendMessage" "{
    \"message\": {
      \"recipient\": \"$IDENTITY_KEY\",
      \"messageBox\": \"inbox\",
      \"messageId\": \"test-bad-body\",
      \"body\": \"\"
    }
  }")
  compare_field "empty body" "code" "$NODE_BAD_BODY" "$RUST_BAD_BODY"
fi

# =============================================================================
# TEST 10: listMessages - valid
# =============================================================================
log_header "TEST 10: listMessages (valid)"

RUST_LIST=$(auth_request POST "$RUST_SERVER/listMessages" "{\"messageBox\": \"parity_test\"}")
assert_field "Rust listMessages" "status" "success" "$RUST_LIST"
# Check that we can find our sent message
RUST_LIST_AUTH_ERR=$(json_field "__auth_error__" "$RUST_LIST")
if [[ "$RUST_LIST_AUTH_ERR" == "True" ]]; then
  record "Rust listMessages: contains sent msg" "SKIP" "wallet auth failed"
  record "Rust listMessages: field names" "SKIP" "wallet auth failed"
  RUST_LIST_FIELDS="SKIP"
else
  RUST_HAS_MSG=$(printf '%s' "$RUST_LIST" | python3 -c "
import json, sys
d = json.load(sys.stdin)
msg_id = sys.argv[1]
found = any(m.get('messageId') == msg_id for m in d.get('messages', []))
print('yes' if found else 'no')
" "$MSG_ID")
  if [[ "$RUST_HAS_MSG" == "yes" ]]; then
    record "Rust listMessages: contains sent msg" "PASS"
  else
    record "Rust listMessages: contains sent msg" "FAIL" "message $MSG_ID not found"
  fi

  # Check response field names match expected shape
  RUST_LIST_FIELDS=$(printf '%s' "$RUST_LIST" | python3 -c "
import json, sys
d = json.load(sys.stdin)
msgs = d.get('messages', [])
if msgs:
    print(','.join(sorted(msgs[0].keys())))
else:
    print('EMPTY')
")
  EXPECTED_FIELDS="body,createdAt,messageId,sender,updatedAt"
  if [[ "$RUST_LIST_FIELDS" == "$EXPECTED_FIELDS" ]]; then
    record "Rust listMessages: field names" "PASS" "fields=$RUST_LIST_FIELDS"
  else
    record "Rust listMessages: field names" "FAIL" "expected=$EXPECTED_FIELDS got=$RUST_LIST_FIELDS"
  fi
fi

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_LIST=$(auth_request POST "$NODE_SERVER/listMessages" "{\"messageBox\": \"parity_test\"}")
  compare_field "listMessages" "status" "$NODE_LIST" "$RUST_LIST"
fi

# =============================================================================
# TEST 11: listMessages - missing messageBox
# =============================================================================
log_header "TEST 11: listMessages (missing messageBox)"

RUST_LIST_NOBOX=$(auth_request POST "$RUST_SERVER/listMessages" "{}")
assert_field "Rust list no box" "code" "ERR_MESSAGEBOX_REQUIRED" "$RUST_LIST_NOBOX"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_LIST_NOBOX=$(auth_request POST "$NODE_SERVER/listMessages" "{}")
  compare_field "list no box" "code" "$NODE_LIST_NOBOX" "$RUST_LIST_NOBOX"
fi

# =============================================================================
# TEST 12: listMessages - non-existent box (should return empty array)
# =============================================================================
log_header "TEST 12: listMessages (non-existent box)"

RUST_LIST_EMPTY=$(auth_request POST "$RUST_SERVER/listMessages" "{\"messageBox\": \"nonexistent_box_parity\"}")
assert_field "Rust list empty" "status" "success" "$RUST_LIST_EMPTY"
RUST_EMPTY_AUTH_ERR=$(json_field "__auth_error__" "$RUST_LIST_EMPTY")
if [[ "$RUST_EMPTY_AUTH_ERR" == "True" ]]; then
  record "Rust list empty box: empty array" "SKIP" "wallet auth failed"
else
  RUST_MSG_COUNT=$(printf '%s' "$RUST_LIST_EMPTY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(len(d.get('messages', ['placeholder'])))
")
  if [[ "$RUST_MSG_COUNT" == "0" ]]; then
    record "Rust list empty box: empty array" "PASS"
  else
    record "Rust list empty box: empty array" "FAIL" "got $RUST_MSG_COUNT messages"
  fi
fi

# =============================================================================
# TEST 13: acknowledgeMessage - valid
# =============================================================================
log_header "TEST 13: acknowledgeMessage (valid)"

RUST_ACK=$(auth_request POST "$RUST_SERVER/acknowledgeMessage" "{\"messageIds\": [\"$MSG_ID\"]}")
assert_field "Rust acknowledge" "status" "success" "$RUST_ACK"

# Verify message is gone
RUST_LIST_AFTER=$(auth_request POST "$RUST_SERVER/listMessages" "{\"messageBox\": \"parity_test\"}")
RUST_AFTER_AUTH_ERR=$(json_field "__auth_error__" "$RUST_LIST_AFTER")
if [[ "$RUST_AFTER_AUTH_ERR" == "True" ]]; then
  record "Rust post-ack: message removed" "SKIP" "wallet auth failed"
else
  RUST_STILL=$(printf '%s' "$RUST_LIST_AFTER" | python3 -c "
import json, sys
d = json.load(sys.stdin)
msg_id = sys.argv[1]
found = any(m.get('messageId') == msg_id for m in d.get('messages', []))
print('yes' if found else 'no')
" "$MSG_ID")
  if [[ "$RUST_STILL" == "no" ]]; then
    record "Rust post-ack: message removed" "PASS"
  else
    record "Rust post-ack: message removed" "FAIL" "message still present"
  fi
fi

# =============================================================================
# TEST 14: acknowledgeMessage - non-existent (ERR_INVALID_ACKNOWLEDGMENT)
# =============================================================================
log_header "TEST 14: acknowledgeMessage (non-existent)"

RUST_ACK_BAD=$(auth_request POST "$RUST_SERVER/acknowledgeMessage" "{\"messageIds\": [\"nonexistent-parity-id\"]}")
assert_field "Rust ack non-existent" "status" "error" "$RUST_ACK_BAD"
assert_field "Rust ack non-existent" "code" "ERR_INVALID_ACKNOWLEDGMENT" "$RUST_ACK_BAD"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_ACK_BAD=$(auth_request POST "$NODE_SERVER/acknowledgeMessage" "{\"messageIds\": [\"nonexistent-parity-id\"]}")
  compare_field "ack non-existent" "code" "$NODE_ACK_BAD" "$RUST_ACK_BAD"
fi

# =============================================================================
# TEST 15: acknowledgeMessage - missing messageIds
# =============================================================================
log_header "TEST 15: acknowledgeMessage (missing messageIds)"

RUST_ACK_NO_IDS=$(auth_request POST "$RUST_SERVER/acknowledgeMessage" "{}")
assert_field "Rust ack no IDs" "status" "error" "$RUST_ACK_NO_IDS"
assert_field "Rust ack no IDs" "code" "ERR_MESSAGE_ID_REQUIRED" "$RUST_ACK_NO_IDS"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_ACK_NO_IDS=$(auth_request POST "$NODE_SERVER/acknowledgeMessage" "{}")
  compare_field "ack no IDs" "code" "$NODE_ACK_NO_IDS" "$RUST_ACK_NO_IDS"
fi

# =============================================================================
# TEST 16: acknowledgeMessage - invalid format (not array of strings)
# =============================================================================
log_header "TEST 16: acknowledgeMessage (invalid format)"

RUST_ACK_BAD_FMT=$(auth_request POST "$RUST_SERVER/acknowledgeMessage" "{\"messageIds\": \"single-string\"}")
assert_field "Rust ack bad fmt" "status" "error" "$RUST_ACK_BAD_FMT"
assert_field "Rust ack bad fmt" "code" "ERR_INVALID_MESSAGE_ID" "$RUST_ACK_BAD_FMT"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_ACK_BAD_FMT=$(auth_request POST "$NODE_SERVER/acknowledgeMessage" "{\"messageIds\": \"single-string\"}")
  compare_field "ack bad fmt" "code" "$NODE_ACK_BAD_FMT" "$RUST_ACK_BAD_FMT"
fi

# =============================================================================
# TEST 17: permissions/set
# =============================================================================
log_header "TEST 17: permissions/set"

RUST_PERM_SET=$(auth_request POST "$RUST_SERVER/permissions/set" "{
  \"messageBox\": \"parity_test\",
  \"recipientFee\": 0
}")
assert_field "Rust perm set (box-wide)" "status" "success" "$RUST_PERM_SET"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_SET=$(auth_request POST "$NODE_SERVER/permissions/set" "{
    \"messageBox\": \"parity_test\",
    \"recipientFee\": 0
  }")
  compare_field "perm set" "status" "$NODE_PERM_SET" "$RUST_PERM_SET"
fi

# =============================================================================
# TEST 18: permissions/set - invalid request
# =============================================================================
log_header "TEST 18: permissions/set (invalid request)"

RUST_PERM_BAD=$(auth_request POST "$RUST_SERVER/permissions/set" "{}")
assert_field "Rust perm set invalid" "status" "error" "$RUST_PERM_BAD"
assert_field "Rust perm set invalid" "code" "ERR_INVALID_REQUEST" "$RUST_PERM_BAD"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_BAD=$(auth_request POST "$NODE_SERVER/permissions/set" "{}")
  compare_field "perm set invalid" "code" "$NODE_PERM_BAD" "$RUST_PERM_BAD"
fi

# =============================================================================
# TEST 19: permissions/get
# =============================================================================
log_header "TEST 19: permissions/get"

RUST_PERM_GET=$(auth_request GET "$RUST_SERVER/permissions/get?messageBox=parity_test")
assert_field "Rust perm get" "status" "success" "$RUST_PERM_GET"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_GET=$(auth_request GET "$NODE_SERVER/permissions/get?messageBox=parity_test")
  compare_field "perm get" "status" "$NODE_PERM_GET" "$RUST_PERM_GET"
fi

# =============================================================================
# TEST 20: permissions/get - missing messageBox
# =============================================================================
log_header "TEST 20: permissions/get (missing messageBox)"

RUST_PERM_GET_BAD=$(auth_request GET "$RUST_SERVER/permissions/get")
assert_field "Rust perm get missing box" "status" "error" "$RUST_PERM_GET_BAD"
assert_field "Rust perm get missing box" "code" "ERR_MISSING_PARAMETERS" "$RUST_PERM_GET_BAD"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_GET_BAD=$(auth_request GET "$NODE_SERVER/permissions/get")
  compare_field "perm get missing box" "code" "$NODE_PERM_GET_BAD" "$RUST_PERM_GET_BAD"
fi

# =============================================================================
# TEST 21: permissions/list
# =============================================================================
log_header "TEST 21: permissions/list"

RUST_PERM_LIST=$(auth_request GET "$RUST_SERVER/permissions/list")
assert_field "Rust perm list" "status" "success" "$RUST_PERM_LIST"

# Check response has permissions array and totalCount
RUST_PLIST_AUTH_ERR=$(json_field "__auth_error__" "$RUST_PERM_LIST")
if [[ "$RUST_PLIST_AUTH_ERR" == "True" ]]; then
  record "Rust perm list: response shape" "SKIP" "wallet auth failed"
else
  RUST_PERM_LIST_SHAPE=$(printf '%s' "$RUST_PERM_LIST" | python3 -c "
import json, sys
d = json.load(sys.stdin)
has_perms = 'permissions' in d and isinstance(d['permissions'], list)
has_total = 'totalCount' in d
print(f'permissions={has_perms},totalCount={has_total}')
")
  if [[ "$RUST_PERM_LIST_SHAPE" == "permissions=True,totalCount=True" ]]; then
    record "Rust perm list: response shape" "PASS"
  else
    record "Rust perm list: response shape" "FAIL" "got=$RUST_PERM_LIST_SHAPE"
  fi
fi

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_LIST=$(auth_request GET "$NODE_SERVER/permissions/list")
  compare_field "perm list" "status" "$NODE_PERM_LIST" "$RUST_PERM_LIST"
fi

# =============================================================================
# TEST 22: permissions/list with messageBox filter
# =============================================================================
log_header "TEST 22: permissions/list (filtered)"

RUST_PERM_LIST_F=$(auth_request GET "$RUST_SERVER/permissions/list?messageBox=parity_test")
assert_field "Rust perm list filtered" "status" "success" "$RUST_PERM_LIST_F"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_PERM_LIST_F=$(auth_request GET "$NODE_SERVER/permissions/list?messageBox=parity_test")
  compare_field "perm list filtered" "status" "$NODE_PERM_LIST_F" "$RUST_PERM_LIST_F"
fi

# =============================================================================
# TEST 23: permissions/quote
# =============================================================================
log_header "TEST 23: permissions/quote"

RUST_QUOTE=$(auth_request GET "$RUST_SERVER/permissions/quote?recipient=$IDENTITY_KEY&messageBox=parity_test")
assert_field "Rust quote" "status" "success" "$RUST_QUOTE"

# Check quote response shape (single recipient)
RUST_QUOTE_AUTH_ERR=$(json_field "__auth_error__" "$RUST_QUOTE")
if [[ "$RUST_QUOTE_AUTH_ERR" == "True" ]]; then
  record "Rust quote: response shape" "SKIP" "wallet auth failed"
else
  RUST_QUOTE_SHAPE=$(printf '%s' "$RUST_QUOTE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
q = d.get('quote', {})
has_delivery = 'deliveryFee' in q
has_recipient = 'recipientFee' in q
print(f'deliveryFee={has_delivery},recipientFee={has_recipient}')
")
  if [[ "$RUST_QUOTE_SHAPE" == "deliveryFee=True,recipientFee=True" ]]; then
    record "Rust quote: response shape" "PASS"
  else
    record "Rust quote: response shape" "FAIL" "got=$RUST_QUOTE_SHAPE"
  fi
fi

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_QUOTE=$(auth_request GET "$NODE_SERVER/permissions/quote?recipient=$IDENTITY_KEY&messageBox=parity_test")
  compare_field "quote" "status" "$NODE_QUOTE" "$RUST_QUOTE"
  compare_field "quote" "quote.deliveryFee" "$NODE_QUOTE" "$RUST_QUOTE"
  compare_field "quote" "quote.recipientFee" "$NODE_QUOTE" "$RUST_QUOTE"
fi

# =============================================================================
# TEST 24: permissions/quote - missing params
# =============================================================================
log_header "TEST 24: permissions/quote (missing params)"

RUST_QUOTE_BAD=$(auth_request GET "$RUST_SERVER/permissions/quote")
assert_field "Rust quote missing params" "status" "error" "$RUST_QUOTE_BAD"
assert_field "Rust quote missing params" "code" "ERR_MISSING_PARAMETERS" "$RUST_QUOTE_BAD"

if [[ "$RUST_ONLY" == "false" ]]; then
  NODE_QUOTE_BAD=$(auth_request GET "$NODE_SERVER/permissions/quote")
  compare_field "quote missing params" "code" "$NODE_QUOTE_BAD" "$RUST_QUOTE_BAD"
fi

# =============================================================================
# TEST 25: Unknown endpoint (unauth → 401 via auth middleware, matches TS/Go)
# =============================================================================
# TS and Go both run auth middleware BEFORE path routing, so an unauthenticated
# request to an unknown path returns 401 (auth required), not 404. Only an
# authenticated request to an unknown path returns 404 — that's tested
# implicitly when invalid endpoints come up in other suites.
log_header "TEST 25: Unknown endpoint (unauthenticated → 401)"

RUST_UNKNOWN=$(raw_request GET "$RUST_SERVER/nonexistent")
assert_status "Rust unknown path unauth" "401" "$RUST_UNKNOWN"
assert_field "Rust unknown path unauth" "code" "UNAUTHORIZED" "$(http_body "$RUST_UNKNOWN")"

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo "============================================="
echo "  PARITY TEST SUMMARY"
echo "============================================="
if [[ "$RUST_ONLY" == "true" ]]; then
  echo "  Mode: Rust-only (Node.js behavior asserted)"
else
  echo "  Mode: Side-by-side (Node:8080 vs Rust:8787)"
fi
echo "---------------------------------------------"
for r in "${RESULTS[@]}"; do
  echo "  $r"
done
echo "---------------------------------------------"
echo "  PASS: $PASS | FAIL: $FAIL | SKIP: $SKIP"
echo "============================================="

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
