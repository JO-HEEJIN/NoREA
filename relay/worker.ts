// NoREA RFC 3161 relay as a Cloudflare Worker (WP-08). NOT DEPLOYED.
// Same logic as scripts/dev-relay.mjs: POST /v1/tsa, body = DER TimeStampReq,
// X-TSA-URL from an allowlist, forwards with Content-Type
// application/timestamp-query, returns the DER TimeStampResp.
// Logs only time, sizes and status. The relay sees a SHA-256 imprint and a
// nonce, never evidence, canaries or keys.

export interface Env {
  /** Exact origin of the web app, for example "https://norea.example". */
  ALLOWED_ORIGIN: string;
}

const ALLOWED_TSA = new Set([
  'https://freetsa.org/tsr',
  'http://timestamp.digicert.com',
  'http://timestamp.sectigo.com',
]);
const MAX_BODY = 4096;
const MAX_RESPONSE = 64 * 1024;
const TIMEOUT_MS = 30_000;

function corsHeaders(origin: string | null, env: Env): Record<string, string> {
  if (!origin || origin !== env.ALLOWED_ORIGIN) return {};
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-TSA-URL',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}

function reply(status: number, headers: Record<string, string>, body: BodyInit | null, reqBytes: number, respBytes: number): Response {
  console.log(`${new Date().toISOString()} req=${reqBytes}B resp=${respBytes}B status=${status}`);
  return new Response(body, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');
    const h = corsHeaders(origin, env);
    const allowed = 'Access-Control-Allow-Origin' in h;
    const text = (status: number, msg: string, n = 0) =>
      reply(status, { ...h, 'Content-Type': 'text/plain; charset=utf-8' }, msg, n, msg.length);

    if (new URL(request.url).pathname !== '/v1/tsa') return text(404, 'not found\n');
    if (request.method === 'OPTIONS') return reply(allowed ? 204 : 403, h, null, 0, 0);
    if (request.method !== 'POST') return text(405, 'method not allowed\n');
    if (origin !== null && !allowed) return text(403, 'origin not allowed\n');
    const tsa = request.headers.get('X-TSA-URL') ?? '';
    if (!ALLOWED_TSA.has(tsa)) return text(400, 'X-TSA-URL is not on the allowlist\n');
    const ct = (request.headers.get('Content-Type') ?? '').split(';')[0].trim();
    if (ct !== 'application/timestamp-query') return text(415, 'Content-Type must be application/timestamp-query\n');
    const declared = Number(request.headers.get('Content-Length') ?? '0');
    if (declared > MAX_BODY) return text(413, 'body too large\n', declared);

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > MAX_BODY) return text(413, 'body too large\n', body.length);
    if (body.length < 2 || body[0] !== 0x30) return text(400, 'body is not a DER SEQUENCE\n', body.length);

    try {
      const r = await fetch(tsa, {
        method: 'POST',
        headers: { 'Content-Type': 'application/timestamp-query' },
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!r.ok) return text(502, `TSA answered HTTP ${r.status}\n`, body.length);
      const out = await r.arrayBuffer();
      if (out.byteLength > MAX_RESPONSE) return text(502, 'TSA response too large\n', body.length);
      return reply(200, { ...h, 'Content-Type': 'application/timestamp-reply' }, out, body.length, out.byteLength);
    } catch {
      return text(502, 'TSA request failed\n', body.length);
    }
  },
};
