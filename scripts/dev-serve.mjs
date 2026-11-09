// Local static server for web/public with the dev relay enabled (WP-08).
// FOR LOCAL DEVELOPMENT ONLY. Node 22, no npm deps.
//
// Serves web/public on http://localhost:8080 like `python3 -m http.server`, with
// two on-the-fly rewrites so the repo files stay unchanged:
//   index.html: CSP meta connect-src 'self' -> connect-src 'self' http://localhost:8787
//   config.js:  anchorRelay: null -> anchorRelay: 'http://localhost:8787'
// Start scripts/dev-relay.mjs too. Pass --no-relay to serve the files untouched.
// Env: NOREA_SERVE_PORT (default 8080). On another port, start the relay with
// NOREA_RELAY_ORIGIN=http://localhost:<port> so its CORS check accepts the page.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../web/public/', import.meta.url));
const PORT = Number(process.env.NOREA_SERVE_PORT || 8080);
const RELAY = 'http://localhost:8787';
const WITH_RELAY = !process.argv.includes('--no-relay');
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.wasm': 'application/wasm', '.svg': 'image/svg+xml', '.png': 'image/png',
};

function rewrite(rel, buf) {
  if (!WITH_RELAY) return buf;
  if (rel === 'index.html') {
    const s = buf.toString('utf8');
    const out = s.replace("connect-src 'self';", `connect-src 'self' ${RELAY};`);
    if (out === s) throw new Error('CSP connect-src not found in index.html');
    return Buffer.from(out);
  }
  if (rel === 'config.js') {
    const s = buf.toString('utf8');
    const out = s.replace('anchorRelay: null,', `anchorRelay: '${RELAY}',`);
    if (out === s) throw new Error('anchorRelay: null not found in config.js');
    return Buffer.from(out);
  }
  return buf;
}

createServer(async (req, res) => {
  let rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '');
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  const file = normalize(join(ROOT, rel));
  if (!file.startsWith(ROOT) || rel.split(/[\\/]/).includes('..') || file.includes(`${sep}.`)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const body = rewrite(rel, await readFile(file));
    res.writeHead(200, {
      'Content-Type': TYPES[extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
  } catch (e) {
    res.writeHead(e.code === 'ENOENT' ? 404 : 500).end();
  }
  console.log(`${new Date().toISOString()} ${req.method} /${rel} ${res.statusCode}`);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`norea dev server on http://localhost:${PORT} (${WITH_RELAY ? `relay ${RELAY} enabled` : 'no relay'}; local development only)`);
});
