#!/usr/bin/env bash
# release-public.sh — cut a PUBLIC release of the relay from this (private, canonical) repo.
#
#   scripts/release-public.sh [--push]
#
# Exports HEAD as a scrubbed tree into the public mirror checkout (PUBLIC_DIR, default
# ~/bsv/bsv-messagebox-cloudflare-public, a clone of github.com/Calhooon/bsv-messagebox-cloudflare),
# commits it there as ONE release commit and tags it vX.Y.Z (the version in Cargo.toml).
# With --push it pushes main + the tag. Without it, it stops after the commit for review.
#
# WHAT NEVER LEAVES THIS REPO: wrangler.low.toml (LOW's Cloudflare ids), KICKOFF.md, .claude/, Cargo.lock,
# docs/LOW-RELAY.md, this script's private id list. Every account_id / database_id / KV id in the exported
# tree is replaced with a placeholder, and the VERIFIER below refuses to commit if any identifier survives.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PUBLIC_DIR="${PUBLIC_DIR:-$HOME/bsv/bsv-messagebox-cloudflare-public}"
PUBLIC_REMOTE="https://github.com/Calhooon/bsv-messagebox-cloudflare.git"
PUSH=0; [ "${1:-}" = "--push" ] && PUSH=1

VERSION="$(grep -m1 '^version' "$HERE/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$VERSION" ] || { echo "no version in Cargo.toml"; exit 1; }
SRC_SHA="$(git -C "$HERE" rev-parse --short HEAD)"

# The private identifiers this repo carries (kept here so the scrub is exact, not heuristic).
PRIVATE_IDS=(
  <your-account-id>   # cloudflare account_id
  <your-d1-database-id> # D1 (generic worker)
  <your-account-id>   # KV (generic worker)
  <your-d1-database-id> # D1 low-relay
  <your-account-id>   # KV low-relay
  <your-d1-database-id> # D1 low-relay-beta
)
EXCLUDE=( wrangler.low.toml KICKOFF.md .claude Cargo.lock secrets.md docs/LOW-RELAY.md scripts/release-public.sh graphify-out )

[ -d "$PUBLIC_DIR/.git" ] || { echo "public mirror checkout missing at $PUBLIC_DIR"; exit 1; }
[ "$(git -C "$PUBLIC_DIR" remote get-url origin)" = "$PUBLIC_REMOTE" ] || { echo "$PUBLIC_DIR is not a clone of $PUBLIC_REMOTE"; exit 1; }
[ -z "$(git -C "$PUBLIC_DIR" status --porcelain --untracked-files=no)" ] || { echo "public mirror has local modifications — refusing"; exit 1; }
git -C "$PUBLIC_DIR" fetch -q origin
git -C "$PUBLIC_DIR" checkout -q main
git -C "$PUBLIC_DIR" reset -q --hard origin/main

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git -C "$HERE" archive HEAD | tar -x -C "$TMP"
for x in "${EXCLUDE[@]}"; do rm -rf "$TMP/$x"; done

# Scrub: wrangler.toml keeps the code's bindings but loses the ids; every other file loses the ids too.
sed -i '' -E 's/^account_id = "[0-9a-f]{32}"/# account_id = "<your-cloudflare-account-id>"/' "$TMP/wrangler.toml"
sed -i '' -E 's/^database_id = "[0-9a-f-]{36}"/database_id = "<your-d1-database-id>"/' "$TMP/wrangler.toml"
sed -i '' -E 's/^id = "[0-9a-f]{32}"/id = "<your-kv-namespace-id>"/' "$TMP/wrangler.toml"
for id in "${PRIVATE_IDS[@]}"; do
  # (grep exits 1 when an id is already gone — that is success, not a pipefail)
  { grep -rl --exclude-dir=.git -- "$id" "$TMP" || true; } | while read -r f; do sed -i '' "s/$id/<redacted-cloudflare-id>/g" "$f"; done
done

# Our account's workers.dev subdomain is an identifier too (owner rule: the public tree carries
# no deployment identifiers). Every `<name>.dev-a3e.workers.dev` becomes a placeholder.
ACCOUNT_HOST_RE='[a-zA-Z0-9-]+\.dev-a3e\.workers\.dev'
{ grep -rlE --exclude-dir=.git -- "$ACCOUNT_HOST_RE" "$TMP" || true; } | while read -r f; do sed -i '' -E "s/$ACCOUNT_HOST_RE/<your-relay>.workers.dev/g" "$f"; done

# The canonical repo's own banners must NOT ship: strip the README quote block that starts with
# "THIS IS THE CANONICAL" (through its trailing blank line) and CLAUDE.md's "REPO MAP" section
# (through the next top-level heading).
awk 'BEGIN{skip=0} /^> \*\*THIS IS THE CANONICAL/{skip=1} { if(!skip) print; else if ($0 ~ /^$/) skip=0 }' "$TMP/README.md" > "$TMP/README.tmp" && mv "$TMP/README.tmp" "$TMP/README.md"
awk 'BEGIN{skip=0} /^# rust-message-box — REPO MAP/{skip=1; next} /^# /{ if(skip){skip=0} } { if(!skip) print }' "$TMP/CLAUDE.md" > "$TMP/CLAUDE.tmp" && mv "$TMP/CLAUDE.tmp" "$TMP/CLAUDE.md"

# Public banner on top of README.
BANNER='> **Public release mirror.** This repository receives tagged releases of a private canonical repository (every Cloudflare resource identifier is scrubbed; deployment configs are placeholders). Issues and PRs are welcome here; development happens upstream and lands as the next release.'
grep -q "Public release mirror" "$TMP/README.md" || { printf '%s\n\n' "$BANNER" | cat - "$TMP/README.md" > "$TMP/README.tmp" && mv "$TMP/README.tmp" "$TMP/README.md"; }

# VERIFY — refuse to ship anything identifier-shaped.
fail=0
for id in "${PRIVATE_IDS[@]}"; do if grep -rq --exclude-dir=.git -- "$id" "$TMP"; then echo "VERIFY FAIL: private id $id survives"; fail=1; fi; done
if grep -rEn --exclude-dir=.git '^(account_id|database_id|id) = "[0-9a-f-]{32,36}"' "$TMP"; then echo "VERIFY FAIL: a live resource id survives in a wrangler config"; fail=1; fi
if grep -rEn --exclude-dir=.git '(SERVER_PRIVATE_KEY|BROADCAST_TOKEN|FIREBASE_SERVICE_ACCOUNT_JSON|TAAL_API_KEY)\s*=\s*"[^<"]' "$TMP"; then echo "VERIFY FAIL: a secret value survives"; fail=1; fi
if grep -rq --exclude-dir=.git -- "dev-a3e" "$TMP"; then echo "VERIFY FAIL: the account workers.dev host survives"; fail=1; fi
for x in wrangler.low.toml secrets.md KICKOFF.md; do [ -e "$TMP/$x" ] && { echo "VERIFY FAIL: $x exported"; fail=1; }; done
if grep -rq --exclude-dir=.git -e "THIS IS THE CANONICAL" -e "REPO MAP" "$TMP"; then echo "VERIFY FAIL: a canonical-repo banner survives"; fail=1; fi
[ "$fail" = 0 ] || exit 2

rsync -a --delete --exclude .git "$TMP"/ "$PUBLIC_DIR"/
git -C "$PUBLIC_DIR" add --all
if git -C "$PUBLIC_DIR" diff --cached --quiet; then echo "nothing to release (mirror already at $VERSION)"; exit 0; fi
git -C "$PUBLIC_DIR" commit -q -m "release: v$VERSION (from canonical $SRC_SHA)

Exported by scripts/release-public.sh — private deployment configs excluded, resource identifiers scrubbed and verified."
git -C "$PUBLIC_DIR" tag -f "v$VERSION" >/dev/null
echo "public mirror: committed v$VERSION ($(git -C "$PUBLIC_DIR" rev-parse --short HEAD)); tag v$VERSION"
git -C "$PUBLIC_DIR" show --stat --format= HEAD | tail -3
if [ "$PUSH" = 1 ]; then git -C "$PUBLIC_DIR" push -q origin main && git -C "$PUBLIC_DIR" push -q -f origin "v$VERSION" && echo "pushed main + v$VERSION to $PUBLIC_REMOTE"; else echo "review in $PUBLIC_DIR, then re-run with --push"; fi
