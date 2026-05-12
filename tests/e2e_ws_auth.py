#!/usr/bin/env python3
"""
M9 #40 proof: BRC-31 auth is mandatory on the /ws upgrade.

Connects to ws://localhost:8787/ws WITHOUT BRC-31 headers and asserts:

  1. websockets.connect raises InvalidStatus with status 401
  2. Either the rejection body (from the InvalidStatus.response) or a
     follow-up GET /ws via `requests` carries the parity wire shape
       {"code":"UNAUTHORIZED",
        "message":"Mutual-authentication failed!",
        "status":"error"}
     This is the same shape verified for HTTP routes in commit 41f81b2
     (e2e_live_parity vs the TS reference server).

Each step prints PASS/FAIL on its own line. Exits non-zero on any
failure.

Requires `websockets` 16+ and `requests`.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

try:
    import websockets  # noqa: F401
    from websockets.asyncio.client import connect
    from websockets.exceptions import InvalidStatus
except ImportError as e:  # pragma: no cover
    print(f"FAIL: websockets package not importable: {e}")
    sys.exit(1)

import requests


WS_URL = os.environ.get("WS_URL", "ws://localhost:8787/ws")
HTTP_WS_URL = os.environ.get("HTTP_WS_URL", "http://localhost:8787/ws")
RECV_TIMEOUT_S = 5.0

EXPECTED_BODY = {
    "code": "UNAUTHORIZED",
    "message": "Mutual-authentication failed!",
    "status": "error",
}


def step(label: str, ok: bool, detail: str = "") -> bool:
    tag = "PASS" if ok else "FAIL"
    line = f"[{tag}] {label}"
    if detail:
        line += f" — {detail}"
    print(line, flush=True)
    return ok


def _normalize_body(body) -> dict | None:
    """Best-effort decode of a JSON body, returning a dict or None."""
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None
    if isinstance(body, dict):
        return body
    return None


async def run() -> int:
    failures = 0

    # --- Step 1: unauth WS connect -> 401 ---
    rejection_body: dict | None = None
    status_code: int | None = None
    try:
        # No `additional_headers` means no x-bsv-auth-* — should be rejected.
        ws = await asyncio.wait_for(connect(WS_URL), timeout=RECV_TIMEOUT_S)
        # Should not reach here.
        try:
            await ws.close()
        except Exception:
            pass
        step(
            "1. Unauth WS connect to /ws is rejected with 401",
            False,
            "connect() succeeded but should have raised InvalidStatus(401)",
        )
        failures += 1
    except InvalidStatus as e:  # noqa: PERF203
        status_code = getattr(e.response, "status_code", None)
        rejection_body = _normalize_body(getattr(e.response, "body", None))
        ok = status_code == 401
        failures += 0 if step(
            "1. Unauth WS connect to /ws is rejected with 401",
            ok,
            f"status={status_code} body={rejection_body!r}",
        ) else 1
        if not ok:
            failures += 1
    except Exception as e:  # noqa: BLE001
        step(
            "1. Unauth WS connect to /ws is rejected with 401",
            False,
            f"unexpected {type(e).__name__}: {e}",
        )
        failures += 1

    # --- Step 2: wire-shape parity ---
    # Prefer the body we already have from the InvalidStatus exception. If
    # it's empty (some HTTP libs strip rejection bodies), fall back to a
    # plain HTTP GET — the route must answer the same way without an
    # Upgrade header.
    if not rejection_body:
        try:
            resp = requests.get(HTTP_WS_URL, timeout=5)
            status_code = status_code or resp.status_code
            rejection_body = _normalize_body(resp.content)
        except requests.RequestException as e:
            step(
                "2. Rejection body matches parity wire shape",
                False,
                f"follow-up GET failed: {e}",
            )
            failures += 1
            rejection_body = None

    if rejection_body is not None:
        ok = rejection_body == EXPECTED_BODY
        detail = f"got={rejection_body!r}"
        if not ok:
            detail = f"expected={EXPECTED_BODY!r} got={rejection_body!r}"
        failures += 0 if step(
            "2. Rejection body matches parity wire shape "
            "{code:UNAUTHORIZED, message:'Mutual-authentication failed!', status:error}",
            ok,
            detail,
        ) else 1
        if not ok:
            failures += 1
    elif failures == 0:
        # We never set rejection_body and never reported a failure for
        # step 2 above — flag it now.
        step(
            "2. Rejection body matches parity wire shape",
            False,
            "no body recovered from rejection or follow-up",
        )
        failures += 1

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
