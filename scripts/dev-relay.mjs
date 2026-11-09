// Local RFC 3161 relay for development (WP-08). Node 22, no npm deps.
//
// The browser cannot POST to public TSAs (no CORS headers), so the web app
// sends its TimeStampReq here: POST /v1/tsa, body = DER TimeStampReq,
// header X-TSA-URL = one of ALLOWED_TSA. The relay forwards the bytes with
// Content-Type application/timestamp-query and returns the DER response.
// The relay sees only a SHA-256 imprint and a nonce, never evidence or keys.
// It logs time, request size, response size and status only.
//
// Usage: node scripts/dev-relay.mjs   (listens on 127.0.0.1:8787)
// Env: NOREA_RELAY_PORT (default 8787), NOREA_RELAY_ORIGIN (default http://localhost:8080).
// relay/worker.ts is the same logic as a Cloudflare Worker.

import { createServer } from 'node:http';

const PORT = Number(process.env.NOREA_RELAY_PORT || 8787);
// The one origin allowed by CORS. Override only for local testing on another port.
const ALLOWED_ORIGIN = process.env.NOREA_RELAY_ORIGIN || 'http://localhost:8080';
const ALLOWED_TSA = new Set([
  'https://freetsa.org/tsr',
  'http://timestamp.digicert.com',
  'http://timestamp.sectigo.com',
]);
const MAX_BODY = 4096;
const MAX_RESPONSE = 64 * 1024;
const TIMEOUT_MS = 30_000;

function cors(origin) {
  if (origin !== ALLOWED_ORIGIN) return {};
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-TSA-URL',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}

function log(reqBytes, respBytes, status) {
  console.log(`${new Date().toISOString()} req=${reqBytes}B resp=${respBytes}B status=${status}`);
}

function send(res, status, headers, body, reqBytes) {
  const buf = typeof body === 'string' ? Buffer.from(body) : body;
  res.writeHead(status, { 'Content-Length': buf.length, 'Cache-Control': 'no-store', ...headers });
  res.end(buf);
  log(reqBytes, buf.length, status);
}

const server = createServer(async (req, res) => {
  const h = cors(req.headers.origin);
  const text = { ...h, 'Content-Type': 'text/plain; charset=utf-8' };
  if (req.url !== '/v1/tsa') return send(res, 404, text, 'not found\n', 0);
  if (req.method === 'OPTIONS') return send(res, h['Access-Control-Allow-Origin'] ? 204 : 403, h, '', 0);
  if (req.method !== 'POST') return send(res, 405, { ...text, Allow: 'POST, OPTIONS' }, 'method not allowed\n', 0);
  if (req.headers.origin !== undefined && !h['Access-Control-Allow-Origin']) return send(res, 403, text, 'origin not allowed\n', 0);
  const tsa = String(req.headers['x-tsa-url'] || '');
  if (!ALLOWED_TSA.has(tsa)) return send(res, 400, text, 'X-TSA-URL is not on the allowlist\n', 0);
  if (String(req.headers['content-type'] || '').split(';')[0].trim() !== 'application/timestamp-query') {
    return send(res, 415, text, 'Content-Type must be application/timestamp-query\n', 0);
  }

  const chunks = [];
  let size = 0;
  try {
    for await (const c of req) {
      size += c.length;
      if (size > MAX_BODY) return send(res, 413, { ...text, Connection: 'close' }, 'body too large\n', size);
      chunks.push(c);
    }
  } catch {
    return send(res, 400, text, 'read error\n', size);
  }
  const body = Buffer.concat(chunks);
  if (body.length < 2 || body[0] !== 0x30) return send(res, 400, text, 'body is not a DER SEQUENCE\n', size);

  try {
    const r = await fetch(tsa, {
      method: 'POST',
      headers: { 'Content-Type': 'application/timestamp-query' },
      body,
      redirect: 'error',
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const out = Buffer.from(await r.arrayBuffer());
    if (!r.ok) return send(res, 502, text, `TSA answered HTTP ${r.status}\n`, size);
    if (out.length > MAX_RESPONSE) return send(res, 502, text, 'TSA response too large\n', size);
    return send(res, 200, { ...h, 'Content-Type': 'application/timestamp-reply' }, out, size);
  } catch {
    return send(res, 502, text, 'TSA request failed\n', size);
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`norea dev relay on http://localhost:${PORT}/v1/tsa (origin ${ALLOWED_ORIGIN} only)`);
});
