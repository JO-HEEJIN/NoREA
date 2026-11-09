// Deployment config for the web build (WP-08). Read by platform-web.js only.
//
// anchorRelay: origin of a NoREA TSA relay (relay/README.md), for example
//   'https://relay.norea.example', or null. null keeps the anchor button
//   disabled and platform.anchor() throws ANCHOR_UNAVAILABLE.
//   When you set it, the deployment MUST also add that origin to connect-src in
//   BOTH index.html (CSP meta) and _headers, or the browser blocks the request.
//   Local development: scripts/dev-serve.mjs serves this file with
//   anchorRelay = 'http://localhost:8787' and adds that origin to the CSP meta
//   on the fly, so nothing here needs editing.
// tsaUrl: the TSA the relay forwards to. Must be on the relay allowlist.
export const config = {
  anchorRelay: null,
  tsaUrl: 'https://freetsa.org/tsr',
};
