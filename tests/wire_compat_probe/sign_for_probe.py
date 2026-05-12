#!/usr/bin/env python3
"""M9 #52 aggressive-probe helper.

Produces real BRC-31 signed headers for an arbitrary GET URL on the
local bsv-messagebox-cloudflare Worker, prints them as JSON on stdout. Used by
probe-aggressive.mjs to stuff the headers into socket.io's
`extraHeaders` so we can ask: 'what happens if a TS client somehow
manages to attach valid BRC-31 auth to its socket.io polling probe?'

Spoiler: even with valid auth, the polling endpoint doesn't exist on
our Worker (no /socket.io/ route), so the response shifts from 401
UNAUTHORIZED to 404 ERR_NOT_FOUND. Both are dead-ends for socket.io;
the protocol mismatch is the deeper barrier than the auth mismatch.

Usage:
    python3 sign_for_probe.py http://localhost:8787/socket.io/?EIO=4&transport=polling&t=probe
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Reuse e2e_ws_lifecycle's signing helper — already battle-tested in M9.
TESTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(TESTS_DIR))
from e2e_ws_lifecycle import build_signed_ws_headers  # noqa: E402

import os
SERVER_URL = os.environ.get("TARGET_URL", "http://localhost:8787")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <url>", file=sys.stderr)
        return 2
    target_url = sys.argv[1]
    headers = build_signed_ws_headers(SERVER_URL, target_url)
    json.dump(headers, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
