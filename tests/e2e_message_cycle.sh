#!/bin/bash
# E2E test: send → list → acknowledge cycle
# Prerequisites:
#   1. npm run dev (wrangler dev server at localhost:8787)
#   2. MetaNet Client wallet running at localhost:3321
#   3. Approve signing requests in wallet GUI when prompted
#   4. Set X402_CLI env var to the path of your x402-client cli.py
#
# Usage: X402_CLI=/path/to/x402-client/cli.py ./tests/e2e_message_cycle.sh

set -e
CLI="${X402_CLI:-}"
if [[ -z "$CLI" ]]; then
  echo "Set X402_CLI env var to the x402-client cli.py path" >&2
  exit 1
fi
SERVER="http://localhost:8787"
IDENTITY_KEY=$(python3 "$CLI" identity 2>/dev/null)
MSG_ID="e2e-test-$(date +%s)"

echo "Identity key: $IDENTITY_KEY"
echo "Message ID:   $MSG_ID"
echo ""

# --- Step 1: Handshake ---
echo "=== STEP 1: BRC-31 Handshake ==="
python3 "$CLI" handshake "$SERVER"
echo ""

# --- Step 2: Send a message to ourselves ---
echo "=== STEP 2: Send Message ==="
SEND_RESULT=$(python3 "$CLI" auth POST "$SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"inbox\",
    \"messageId\": \"$MSG_ID\",
    \"body\": \"Hello from E2E test\"
  }
}" 2>&1)
echo "$SEND_RESULT"

if echo "$SEND_RESULT" | grep -q '"status": "success"'; then
  echo "✅ Send: PASS"
else
  echo "❌ Send: FAIL"
  exit 1
fi
echo ""

# --- Step 3: Send duplicate (should fail with ERR_DUPLICATE_MESSAGE) ---
echo "=== STEP 3: Send Duplicate ==="
DUP_RESULT=$(python3 "$CLI" auth POST "$SERVER/sendMessage" "{
  \"message\": {
    \"recipient\": \"$IDENTITY_KEY\",
    \"messageBox\": \"inbox\",
    \"messageId\": \"$MSG_ID\",
    \"body\": \"duplicate\"
  }
}" 2>&1)
echo "$DUP_RESULT"

if echo "$DUP_RESULT" | grep -q 'ERR_DUPLICATE_MESSAGE'; then
  echo "✅ Duplicate rejection: PASS"
else
  echo "❌ Duplicate rejection: FAIL"
  exit 1
fi
echo ""

# --- Step 4: List messages ---
echo "=== STEP 4: List Messages ==="
LIST_RESULT=$(python3 "$CLI" auth POST "$SERVER/listMessages" "{
  \"messageBox\": \"inbox\"
}" 2>&1)
echo "$LIST_RESULT"

if echo "$LIST_RESULT" | grep -q "$MSG_ID"; then
  echo "✅ List (found message): PASS"
else
  echo "❌ List (message not found): FAIL"
  exit 1
fi
echo ""

# --- Step 5: List from non-existent box (should return empty) ---
echo "=== STEP 5: List Non-Existent Box ==="
EMPTY_RESULT=$(python3 "$CLI" auth POST "$SERVER/listMessages" "{
  \"messageBox\": \"nonexistent_box_12345\"
}" 2>&1)
echo "$EMPTY_RESULT"

if echo "$EMPTY_RESULT" | grep -q '"messages": \[\]'; then
  echo "✅ Empty box: PASS"
else
  echo "❌ Empty box: FAIL (expected empty array)"
  exit 1
fi
echo ""

# --- Step 6: Acknowledge message ---
echo "=== STEP 6: Acknowledge Message ==="
ACK_RESULT=$(python3 "$CLI" auth POST "$SERVER/acknowledgeMessage" "{
  \"messageIds\": [\"$MSG_ID\"]
}" 2>&1)
echo "$ACK_RESULT"

if echo "$ACK_RESULT" | grep -q '"status": "success"'; then
  echo "✅ Acknowledge: PASS"
else
  echo "❌ Acknowledge: FAIL"
  exit 1
fi
echo ""

# --- Step 7: List again (should be empty now) ---
echo "=== STEP 7: List After Acknowledge ==="
LIST2_RESULT=$(python3 "$CLI" auth POST "$SERVER/listMessages" "{
  \"messageBox\": \"inbox\"
}" 2>&1)
echo "$LIST2_RESULT"

if echo "$LIST2_RESULT" | grep -q '"messages": \[\]'; then
  echo "✅ Post-acknowledge empty: PASS"
else
  echo "⚠️  Post-acknowledge: messages still present (may have other messages)"
fi
echo ""

# --- Step 8: Acknowledge non-existent (should fail) ---
echo "=== STEP 8: Acknowledge Non-Existent ==="
ACK2_RESULT=$(python3 "$CLI" auth POST "$SERVER/acknowledgeMessage" "{
  \"messageIds\": [\"nonexistent-msg-id\"]
}" 2>&1)
echo "$ACK2_RESULT"

if echo "$ACK2_RESULT" | grep -q 'ERR_INVALID_ACKNOWLEDGMENT'; then
  echo "✅ Acknowledge non-existent: PASS"
else
  echo "❌ Acknowledge non-existent: FAIL"
  exit 1
fi
echo ""

echo "========================================="
echo "  All E2E tests passed!"
echo "========================================="
