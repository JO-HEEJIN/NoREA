# NoREA TSA relay

Status: **not deployed.** `worker.ts` is written and reviewed but has never run on
Cloudflare. Local development uses `scripts/dev-relay.mjs`, which has the same logic.

## Why a relay

The web app requests RFC 3161 time anchors (evidence-v1 §8). Public TSAs do not send
CORS headers (freetsa.org answers a preflight with HTTP 403, timestamp.digicert.com
with 501), so a browser cannot POST to them directly. The relay forwards the bytes.

## What it does

- `POST /v1/tsa`, body = DER TimeStampReq (at most 4096 bytes),
  `Content-Type: application/timestamp-query`, header `X-TSA-URL`.
- `X-TSA-URL` must be one of: `https://freetsa.org/tsr`, `http://timestamp.digicert.com`,
  `http://timestamp.sectigo.com`. Anything else is HTTP 400.
- Forwards the body unchanged to the TSA and returns the DER TimeStampResp
  (`application/timestamp-reply`). A TSA error becomes HTTP 502.
- CORS for one origin only (`http://localhost:8080` in the dev relay, `ALLOWED_ORIGIN` in the Worker).
- Logs only time, request size, response size and HTTP status.

What the relay sees: a SHA-256 imprint of the evidence's `anchor_subject` and a random
nonce. Never the evidence, the data, canaries or keys. The relay is not trusted for
correctness either: the browser checks that the returned token's imprint equals
`anchor_subject` before attaching it (`attachAnchor`), and the TSA certificate chain
is not verified by NoREA at all (`chain_verified: false`).

## Local development

```
./scripts/build-web.sh
node scripts/dev-relay.mjs     # 127.0.0.1:8787
node scripts/dev-serve.mjs     # 127.0.0.1:8080, adds the relay to the CSP on the fly
```

Then set `anchorRelay: 'http://localhost:8787'` in `web/public/config.js` (default is
`null`, which keeps the anchor button disabled) and open http://localhost:8080.
`dev-serve.mjs` serves `web/public` and rewrites the CSP meta in `index.html` to
`connect-src 'self' http://localhost:8787` for that response only; the file in the repo
is unchanged.

## Deploying (when someone does)

1. Set `ALLOWED_ORIGIN` in `wrangler.toml` to the web app origin, then `wrangler deploy`.
2. Set `anchorRelay` in `web/public/config.js` to the Worker origin.
3. Add the Worker origin to `connect-src` in BOTH `web/public/index.html` (CSP meta) and
   `web/public/_headers`. `scripts/test.sh` pins the CSP meta, so update that check too.
