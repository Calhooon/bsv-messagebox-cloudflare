#!/usr/bin/env node
/**
 * M9 #52 — Multi-version aggressive probe.
 *
 * Resolves the two outstanding asterisks from RESULTS.md (v1):
 *   - Asterisk 2 (aggressive probe): if env BRC31_HEADERS_JSON is set,
 *     attach those signed headers via socket.io's `extraHeaders`. We
 *     send them on BOTH the polling XHR (works) AND the websocket
 *     upgrade (some servers strip non-standard headers on upgrade).
 *   - Asterisk 3 (version coverage): try every version of
 *     @bsv/authsocket-client we installed side-by-side via npm aliases.
 *     1.0.0 has a pre-existing import bug — skip with note.
 *
 * Output: JSONL to stdout. One event per line, fully machine-parseable.
 *
 * Exit 0 if probe ran to completion (failure-to-connect is the EXPECTED
 * outcome and not an error here). Exit 1 only if the probe itself crashed.
 */

import { AuthSocketClient as AuthSocketClient_v1_0_13 } from 'asc-1-0-13'
import { AuthSocketClient as AuthSocketClient_v2_0_1 } from 'asc-2-0-1'
import { AuthSocketClient as AuthSocketClient_v2_0_2 } from 'asc-2-0-2'

const VERSIONS = {
  '1.0.13': AuthSocketClient_v1_0_13,
  '2.0.1':  AuthSocketClient_v2_0_1,
  '2.0.2':  AuthSocketClient_v2_0_2,
}

// 1.0.0 deliberately omitted — pre-existing import bug references
// a missing dist/cjs/mod.client.js path; not a wire-compat finding.

// Target Worker URL: defaults to local dev; override via TARGET_URL env
// to probe the deployed prod Worker (resolves RESULTS.md asterisk #1).
const SERVER_URL = process.env.TARGET_URL || 'http://localhost:8787'
const POLLING_PATH = '/socket.io/?EIO=4&transport=polling&t=probe'
const PER_TARGET_TIMEOUT_MS = 6000

// If env BRC31_HEADERS_JSON is set, this is the SIGNED variant.
// Otherwise, baseline UNSIGNED variant.
const SIGNED_HEADERS = process.env.BRC31_HEADERS_JSON
  ? JSON.parse(process.env.BRC31_HEADERS_JSON)
  : null

function log (label, ev, payload) {
  const ts = new Date().toISOString()
  let body = payload
  if (payload instanceof Error) {
    body = {
      name: payload.name,
      message: payload.message,
      description: payload.description,
      context: payload.context && {
        status: payload.context.status,
        statusText: payload.context.statusText,
        responseText: typeof payload.context.responseText === 'string'
          ? payload.context.responseText.slice(0, 200)
          : undefined,
        readyState: payload.context.readyState,
      },
      data: payload.data,
      type: payload.type,
    }
  }
  console.log(JSON.stringify({ ts, target: label, event: ev, body }))
}

async function rawFetchProbe (label, url, headers) {
  // What the server actually responds with at the wire layer, before
  // socket.io's retry logic obscures the picture.
  try {
    const res = await fetch(url, { method: 'GET', headers: headers || {} })
    const text = await res.text()
    log(label, 'raw-fetch', {
      url,
      status: res.status,
      statusText: res.statusText,
      body: text.slice(0, 300),
      headers_sent_count: Object.keys(headers || {}).length,
    })
  } catch (e) {
    log(label, 'raw-fetch-error', e)
  }
}

async function probeVersion (version, AuthSocketClient, mode, headers) {
  const label = `v${version}/${mode}`
  log(label, 'begin', {
    version,
    mode,
    server: SERVER_URL,
    headers_supplied: headers ? Object.keys(headers).length : 0,
  })

  // Step 1: raw fetch with the same headers, to see the wire layer truth.
  await rawFetchProbe(label, `${SERVER_URL}${POLLING_PATH}`, headers || {})

  // Step 2: actual socket.io client with extraHeaders if signed mode.
  let socket
  try {
    const opts = {
      reconnection: false,
      timeout: PER_TARGET_TIMEOUT_MS,
    }
    if (headers) opts.extraHeaders = headers
    socket = AuthSocketClient(SERVER_URL, opts)
  } catch (e) {
    log(label, 'construct-error', e)
    return
  }

  for (const ev of ['connect', 'connect_error', 'disconnect', 'error']) {
    socket.on(ev, (...a) => log(label, ev, a.length === 1 ? a[0] : a))
  }
  if (socket.io) {
    socket.io.on('error', (e) => log(label, 'manager:error', e))
    socket.io.on('open', () => log(label, 'manager:open', null))
    socket.io.on('close', (r) => log(label, 'manager:close', r))
    if (typeof socket.io.engine?.on === 'function') {
      socket.io.engine.on('error', (e) => log(label, 'engine:error', e))
      socket.io.engine.on('close', (r) => log(label, 'engine:close', r))
    }
  }

  await new Promise((resolve) => {
    setTimeout(() => {
      log(label, 'timeout', {
        afterMs: PER_TARGET_TIMEOUT_MS,
        connected: !!socket.connected,
      })
      resolve()
    }, PER_TARGET_TIMEOUT_MS)
    socket.on('connect', () => log(label, 'CONNECTED', { id: socket.id }))
  })
  try { socket.disconnect() } catch {}
  log(label, 'end', null)
}

async function main () {
  log('probe', 'startup', {
    node: process.versions.node,
    cwd: process.cwd(),
    versions: Object.keys(VERSIONS),
    mode: SIGNED_HEADERS ? 'SIGNED' : 'UNSIGNED',
    headers_env_present: !!process.env.BRC31_HEADERS_JSON,
  })

  for (const [version, ctor] of Object.entries(VERSIONS)) {
    const mode = SIGNED_HEADERS ? 'signed' : 'unsigned'
    const headers = SIGNED_HEADERS || null
    await probeVersion(version, ctor, mode, headers)
  }

  log('probe', 'done', null)
  process.exit(0)
}

main().catch((e) => {
  log('probe', 'crash', e)
  process.exit(1)
})
