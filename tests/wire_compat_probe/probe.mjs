#!/usr/bin/env node
/**
 * M9 issue #52 — Wire-compat probe.
 *
 * Goal: characterize how a TS authsocket client (socket.io under the hood)
 * fails when pointed at our raw-WS `/ws` endpoint on the Rust worker.
 *
 * We test multiple URLs because a TS client author who reads our docs
 * might naively pick any of these:
 *   - http://localhost:8787       (default socket.io path /socket.io/)
 *   - http://localhost:8787/ws    (custom path /ws/  — what our docs name)
 *   - ws://localhost:8787/ws      (raw WS scheme)
 *
 * For each, we:
 *   1) construct an authsocket-client instance (preferring the TS server's
 *      real shape: AuthSocketClient(url, opts))
 *   2) hook every diagnostic event socket.io exposes (connect, connect_error,
 *      error, disconnect, reconnect_*, ping, etc.)
 *   3) also do a raw `fetch()` against the same URL's polling endpoint to
 *      capture the literal HTTP response (status + body) the worker emits
 *   4) wait up to 6s, then disconnect and move on
 *
 * Success criterion: we produce a CLEAR, evidence-backed characterization
 * of the failure. We do NOT pretend this works. Exit code 0 = probe ran to
 * completion (whether or not connections succeeded — both outcomes are
 * informative). Exit code 1 = probe itself crashed.
 */

import { AuthSocketClient } from '@bsv/authsocket-client'

const TARGETS = [
  { label: 'default-path',  url: 'http://localhost:8787',     opts: {} },
  { label: 'custom-/ws',    url: 'http://localhost:8787',     opts: { path: '/ws/' } },
  { label: 'ws-scheme/ws',  url: 'ws://localhost:8787',       opts: { path: '/ws/' } },
  { label: 'polling-only',  url: 'http://localhost:8787',     opts: { transports: ['polling'] } },
  { label: 'ws-only',       url: 'http://localhost:8787',     opts: { transports: ['websocket'] } },
]

const PER_TARGET_TIMEOUT_MS = 6000

function log (label, ev, payload) {
  const ts = new Date().toISOString()
  // Defensive serialize: socket.io errors are plain Error objects with extra
  // .description / .context / .data we want to see in raw form.
  let body = payload
  if (payload instanceof Error) {
    body = {
      name: payload.name,
      message: payload.message,
      description: payload.description,
      context: payload.context && {
        // XHR object (polling): try to extract status + responseText
        status: payload.context.status,
        statusText: payload.context.statusText,
        responseText: typeof payload.context.responseText === 'string'
          ? payload.context.responseText.slice(0, 200)
          : undefined,
        readyState: payload.context.readyState,
      },
      data: payload.data,
      type: payload.type,
      stack: payload.stack && payload.stack.split('\n').slice(0, 3).join(' | '),
    }
  }
  console.log(JSON.stringify({ ts, target: label, event: ev, body }))
}

async function probeRawHttp (label, url, path) {
  // Hit the engine.io polling URL the way socket.io-client would on first contact.
  const polling = `${url.replace(/\/$/, '')}${path}?EIO=4&transport=polling&t=probe`
  try {
    const res = await fetch(polling, { method: 'GET' })
    const text = await res.text()
    log(label, 'raw-fetch:polling', {
      url: polling,
      status: res.status,
      statusText: res.statusText,
      headers: Object.fromEntries(res.headers.entries()),
      body: text.slice(0, 300),
    })
  } catch (e) {
    log(label, 'raw-fetch:polling-error', e)
  }
}

async function probeOne ({ label, url, opts }) {
  log(label, 'begin', { url, opts })

  const path = opts.path || '/socket.io/'
  await probeRawHttp(label, url, path)

  let socket
  try {
    socket = AuthSocketClient(url, { ...opts, reconnection: false, timeout: PER_TARGET_TIMEOUT_MS })
  } catch (e) {
    log(label, 'construct-error', e)
    return
  }

  // Wire EVERY diagnostic event we know socket.io v4 emits.
  const events = [
    'connect', 'connect_error', 'connecting', 'disconnect', 'error',
    'reconnect', 'reconnect_attempt', 'reconnect_error', 'reconnect_failed',
    'ping', 'pong',
  ]
  for (const ev of events) {
    socket.on(ev, (...args) => log(label, ev, args.length === 1 ? args[0] : args))
  }
  // Engine.IO underlying transport events (lower-level, often the real story)
  if (socket.io) {
    socket.io.on('error', (e) => log(label, 'manager:error', e))
    socket.io.on('reconnect_failed', () => log(label, 'manager:reconnect_failed', null))
    socket.io.on('open', () => log(label, 'manager:open', null))
    socket.io.on('close', (reason) => log(label, 'manager:close', reason))
    if (typeof socket.io.engine?.on === 'function') {
      socket.io.engine.on('error', (e) => log(label, 'engine:error', e))
      socket.io.engine.on('close', (reason) => log(label, 'engine:close', reason))
    }
  }

  // Wait up to PER_TARGET_TIMEOUT_MS for the dust to settle.
  await new Promise((resolve) => {
    const t = setTimeout(() => {
      log(label, 'timeout', { afterMs: PER_TARGET_TIMEOUT_MS, connected: !!socket.connected })
      resolve()
    }, PER_TARGET_TIMEOUT_MS)
    socket.on('connect', () => {
      log(label, 'CONNECTED', { id: socket.id })
      // Do NOT exit — let the timer fire so we capture any subsequent disconnect
    })
    socket.on('connect_error', () => {
      // Don't resolve early; multiple connect_errors are common — let the
      // timer drain so we see the full story.
    })
    void t
  })

  try { socket.disconnect() } catch {}
  log(label, 'end', null)
}

async function main () {
  log('probe', 'startup', {
    node: process.versions.node,
    cwd: process.cwd(),
    targets: TARGETS.map((t) => t.label),
  })

  for (const t of TARGETS) {
    await probeOne(t)
  }

  log('probe', 'done', null)
  process.exit(0)
}

main().catch((e) => {
  log('probe', 'crash', e)
  process.exit(1)
})
