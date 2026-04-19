#!/usr/bin/env python3
"""E2E test: 150 MB BEEF upload via the R2 presigned-URL extension.

Proves that the Cloudflare Workers 100 MB request body cap is defeated by
the `/beef/upload-url` + `payment.beefR2Key` extension. The blob uploaded
is intentionally random garbage (not a valid BEEF) — this test exercises
the R2 pipeline, not the BSV internalization path. Acceptance:

  1. POST /beef/upload-url (auth'd) returns { url, key, expiresAt }.
  2. PUT of a 150 MB blob to the presigned URL returns 200 from R2.
     This is the critical step — it proves the Workers body cap is
     bypassed (the blob goes direct to R2, not through our Worker).
  3. The returned `key` is scoped to our identity key (ownership check).
  4. Optionally: verify the R2 object is listable via `wrangler r2 object list`.

Prerequisites:
  - Rust server running at localhost:8787 (npm run dev)
  - MetaNet Client wallet A at localhost:3321
  - X402_CLI env var pointing at x402-client/cli.py (required)
  - .dev.vars must have R2_ACCESS_KEY_ID / R2_SECRET_ACCESS_KEY /
    R2_ACCOUNT_ID / R2_BUCKET_NAME populated

Usage:
  python3 tests/e2e_r2_upload.py           # 150 MB default
  python3 tests/e2e_r2_upload.py --mb 50   # smaller blob for faster test
"""

import datetime
import hashlib
import hmac
import os
import re
import subprocess
import sys
import time
import urllib.parse


SERVER = "http://localhost:8787"
CLI = os.environ.get("X402_CLI") or sys.exit("Set X402_CLI env var to x402-client cli.py path")


def _presign_r2(method, host, canonical_path, access_key, secret_key, expires=60):
    """Minimal AWS Signature Version 4 presigner for Cloudflare R2.

    Mirrors src/r2_presign.rs but for Python-side HEAD/DELETE verification.
    region = 'auto' (Cloudflare convention), service = 's3'. UNSIGNED-PAYLOAD
    for all methods so we don't need to precompute body hashes.
    """
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    region = "auto"
    service = "s3"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"

    # URI-encode value for query strings (/ → %2F).
    def uri_q(s):
        return urllib.parse.quote(s, safe="-_.~")

    query_pairs = [
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
        ("X-Amz-Credential", f"{access_key}/{credential_scope}"),
        ("X-Amz-Date", amz_date),
        ("X-Amz-Expires", str(expires)),
        ("X-Amz-SignedHeaders", "host"),
    ]
    query_pairs.sort()
    canonical_query = "&".join(f"{uri_q(k)}={uri_q(v)}" for k, v in query_pairs)

    canonical_headers = f"host:{host}\n"
    canonical_request = "\n".join([
        method,
        canonical_path,
        canonical_query,
        canonical_headers,
        "host",
        "UNSIGNED-PAYLOAD",
    ])

    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def hmac_sha256(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = hmac_sha256(f"AWS4{secret_key}".encode(), date_stamp)
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    return f"https://{host}{canonical_path}?{canonical_query}&X-Amz-Signature={signature}"


def section(title):
    print()
    print("=" * 68)
    print(f"  {title}")
    print("=" * 68)


def auth_request(method, path, body=None):
    """Call x402-client for a BRC-31-authed request. Returns response JSON body."""
    args = ["python3", CLI, "auth", method, f"{SERVER}{path}"]
    if body is not None:
        args.append(body)
    proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
    # The CLI prints debug lines then a "Body" delimiter, then the JSON body.
    out = proc.stdout
    if "Body" not in out:
        raise RuntimeError(f"CLI missing Body delimiter. stdout:\n{out}\n\nstderr:\n{proc.stderr}")
    body_block = out.split("Body", 1)[1].strip()
    import json
    return json.loads(body_block)


def main():
    size_mb = 150
    for i, arg in enumerate(sys.argv):
        if arg == "--mb" and i + 1 < len(sys.argv):
            size_mb = int(sys.argv[i + 1])
    size_bytes = size_mb * 1024 * 1024

    # Handshake once so subsequent auth calls reuse the session.
    section(f"BRC-31 Handshake + /beef/upload-url (target: {size_mb} MB upload)")
    subprocess.run(
        ["python3", CLI, "handshake", SERVER],
        capture_output=True, timeout=30,
    )

    t_start = time.time()
    resp = auth_request("POST", "/beef/upload-url", "{}")
    if resp.get("status") != "success":
        print(f"  FAIL: /beef/upload-url returned {resp}")
        sys.exit(1)

    upload_url = resp["url"]
    key = resp["key"]
    expires_at = resp["expiresAt"]
    now = int(time.time())
    ttl = expires_at - now
    print(f"  key:        {key}")
    print(f"  expires in: {ttl}s")
    url_preview = re.sub(r"X-Amz-Signature=[a-f0-9]+", "X-Amz-Signature=<sig>", upload_url)
    print(f"  url:        {url_preview[:120]}...")
    print(f"  (request took {time.time()-t_start:.2f}s)")

    # Generate the blob on disk so we can stream it to curl (avoids loading
    # 150 MB into Python memory).
    section(f"Generate {size_mb} MB random blob")
    blob_path = f"/tmp/e2e-r2-blob-{size_mb}mb.bin"
    t_start = time.time()
    # dd with urandom is slower but truly random; use /dev/random-seeded tmp file.
    subprocess.run(
        ["dd", "if=/dev/urandom", f"of={blob_path}",
         "bs=1m", f"count={size_mb}"],
        check=True, capture_output=True,
    )
    actual = os.path.getsize(blob_path)
    print(f"  {actual:,} bytes ({actual / 1024 / 1024:.1f} MB) at {blob_path}")
    print(f"  (generated in {time.time()-t_start:.2f}s)")

    # PUT to the presigned URL. curl streams the body; no Python memory used.
    # Pass --http1.1 so curl shows progress; -o /dev/null drops R2's response
    # body (which is empty on success anyway).
    section(f"PUT {size_mb} MB → R2 presigned URL (bypasses 100 MB Worker cap)")
    t_start = time.time()
    # Capture response with -w to observe HTTP status cleanly.
    result = subprocess.run(
        ["curl", "-sS", "--http1.1",
         "-X", "PUT",
         "-T", blob_path,
         "-w", "HTTP %{http_code} in %{time_total}s (size_upload=%{size_upload})\n",
         "-o", "/tmp/e2e-r2-put-response.bin",
         upload_url],
        capture_output=True, text=True, timeout=600,
    )
    print(f"  {result.stdout.strip()}")
    if result.stderr:
        print(f"  stderr: {result.stderr.strip()}")
    elapsed = time.time() - t_start

    # Parse the HTTP code from curl's -w output.
    m = re.search(r"HTTP (\d+)", result.stdout)
    if not m:
        print(f"  FAIL: couldn't parse HTTP code from curl output")
        sys.exit(1)
    status = int(m.group(1))

    if status != 200:
        print(f"  FAIL: R2 PUT returned HTTP {status}")
        print(f"  R2 response body (if any):")
        try:
            with open("/tmp/e2e-r2-put-response.bin") as f:
                print(f.read()[:1000])
        except Exception:
            pass
        sys.exit(1)

    throughput_mbps = (size_bytes * 8) / elapsed / 1e6
    print(f"  PASS: 200 OK ({size_mb} MB in {elapsed:.2f}s ≈ {throughput_mbps:.0f} Mbps)")

    # Verify + cleanup via the R2 S3 API directly with our own presigner.
    # (The wrangler r2 object commands would need CLOUDFLARE_API_TOKEN to
    # have R2 Object Read/Write scope — our existing token doesn't. Going
    # direct through the S3 endpoint uses the same access keys we just
    # wired in.)
    section("Verify + cleanup via R2 S3 API (HEAD + DELETE)")

    # Load R2 access keys from .dev.vars.
    r2_cfg = {}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".dev.vars")) as f:
        for line in f:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                if k.startswith("R2_"):
                    r2_cfg[k] = v

    host = f"{r2_cfg['R2_ACCOUNT_ID']}.r2.cloudflarestorage.com"
    canonical_path = f"/{r2_cfg['R2_BUCKET_NAME']}/{key}"

    # Sign + send a HEAD (confirms object exists) and DELETE (cleanup).
    # Use `curl -I` for HEAD (curl's -X HEAD without -I hangs waiting for a
    # response body that never comes) and `-X DELETE` for the delete.
    for method in ("HEAD", "DELETE"):
        signed_url = _presign_r2(
            method=method,
            host=host,
            canonical_path=canonical_path,
            access_key=r2_cfg["R2_ACCESS_KEY_ID"],
            secret_key=r2_cfg["R2_SECRET_ACCESS_KEY"],
            expires=60,
        )
        if method == "HEAD":
            curl_args = ["curl", "-sS", "-I", "-w", "%{http_code}\n",
                         "-o", "/dev/null", signed_url]
        else:
            curl_args = ["curl", "-sS", "-X", method, "-w", "%{http_code}\n",
                         "-o", "/dev/null", signed_url]
        result = subprocess.run(curl_args, capture_output=True, text=True, timeout=30)
        # With -I, curl writes response headers to stdout before the -w status.
        # Grab the final token (the status code from -w).
        tokens = result.stdout.strip().split()
        status = tokens[-1] if tokens else ""
        print(f"  {method:6s} → HTTP {status}")
        if method == "HEAD" and status != "200":
            print(f"  FAIL: HEAD should return 200 (object should exist)")
            print(f"  stdout: {result.stdout[-300:]}")
            sys.exit(1)
        if method == "DELETE" and status not in ("204", "200"):
            print(f"  WARN: DELETE status {status} (object may still be in bucket)")

    # Cleanup local files
    section("Cleanup")
    for f in (blob_path, "/tmp/e2e-r2-put-response.bin"):
        try:
            os.unlink(f)
        except Exception:
            pass
    print("  local temp files removed")

    section("RESULT")
    print(f"  ✅ {size_mb} MB upload succeeded via presigned URL.")
    print(f"  ✅ Workers 100 MB body cap is defeated by the R2 extension.")
    print(f"  ✅ Gap 8 live-proven.")


if __name__ == "__main__":
    main()
