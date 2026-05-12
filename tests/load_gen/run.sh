#!/usr/bin/env bash
# M9 #51 ramp runner — reproduce the 10k-identity load test.
#
# Usage:
#   ./run.sh                          # ramps 10 → 100 → 1000 → 10000 against prod
#   N=1000 SOAK=30 ./run.sh           # single override
#   SERVER=... WS=... ./run.sh        # override target

set -uo pipefail

# macOS soft FD limit defaults to 256 — bump it before opening 10k sockets.
ulimit -n 65536 || true

cd "$(dirname "$0")"

BIN="./target/release/load_gen"
[ -x "$BIN" ] || cargo build --release

SERVER="${SERVER:-https://rust-message-box.dev-a3e.workers.dev}"
WS="${WS:-wss://rust-message-box.dev-a3e.workers.dev/ws}"
SOAK="${SOAK:-60}"

if [ -n "${N:-}" ]; then
  WAVES=("$N")
else
  WAVES=(10 100 1000 10000)
fi

mkdir -p reports
ts=$(date -u +"%Y%m%dT%H%M%SZ")
echo "Run timestamp UTC: $ts"

for n in "${WAVES[@]}"; do
  if [ "$n" -le 100 ]; then
    H=32; U=64
  elif [ "$n" -le 1000 ]; then
    H=64; U=128
  else
    H=128; U=256
  fi
  out="reports/${ts}_n${n}.json"
  echo
  echo "=== wave n=$n soak=${SOAK}s handshakes=$H upgrades=$U ==="
  "$BIN" run \
    --server "$SERVER" \
    --ws "$WS" \
    --n "$n" \
    --soak-secs "$SOAK" \
    --concurrent-handshakes "$H" \
    --concurrent-upgrades "$U" \
    --report-json "$out"
done

echo
echo "All reports in tests/load_gen/reports/"
echo
echo "After ~10 min, query CF Analytics over the soak window:"
echo "  TOKEN=\$(grep '^export CLOUDFLARE_API_TOKEN=' ../../secrets.md | head -1 | sed 's/^export CLOUDFLARE_API_TOKEN=//' | tr -d '\"')"
echo "  $BIN analytics --token \"\$TOKEN\" --start <START_ISO> --end <END_ISO>"
