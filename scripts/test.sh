#!/usr/bin/env bash
# Full verification. Run before every commit.
#   1. core unit tests + frozen-format vectors
#   2. wasm build + the exact WASM API end to end (node), incl. the ADR-0012 memory scan
#   3. the web platform contract incl. key custody, passphrase path (node + in-memory IndexedDB)
#   4. CLI tests: unit + cli/tests/e2e.rs (protect -> check -> disclose -> norea-verify, exit codes, no key material in output)
#   5. syntax check of all browser JS as ES modules + tests JS; browser JS imports only local modules;
#      web UI static checks (app.js imports only ./platform.js + ./ui-text.js, no WASM/custody/storage
#      strings, index.html has no inline script/style/handlers/external URLs, CSP meta unchanged)
#      and the ui-text.js unit tests (tests/ui.node.mjs, uses the step 3 copy in target/web-test)
#   6. no getrandom in the browser wasm dependency tree (CONTEXT.md invariant 2)
# Not covered (needs a real browser): WebAuthn PRF, DOM and app.js event wiring (WP-09).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. core tests"
cargo test --release -p noreacore

echo "== 2. wasm build + WASM e2e (node)"
cargo build --release -p norea-web --target wasm32-unknown-unknown
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
wasm-bindgen target/wasm32-unknown-unknown/release/norea_web.wasm --target nodejs --out-dir "$OUT/node"
node tests/smoke.node.cjs "$OUT/node"

echo "== 3. platform contract (node + fake-indexeddb)"
# Test copy of the browser JS with its own pkg/, so web/public/pkg stays the build-web.sh output.
WEBTEST=target/web-test
rm -rf "$WEBTEST" && mkdir -p "$WEBTEST"
cp web/public/*.js "$WEBTEST/"
wasm-bindgen target/wasm32-unknown-unknown/release/norea_web.wasm --target web --out-dir "$WEBTEST/pkg"
[ -d tests/node_modules/fake-indexeddb ] || (cd tests && npm ci --no-audit --no-fund --silent)
node tests/platform.node.mjs "$PWD/$WEBTEST"

echo "== 4. CLI tests (unit + e2e)"
cargo test -p norea-cli

echo "== 5. JS syntax + web UI static checks"
for f in web/public/*.js tests/*.mjs; do cp "$f" "$OUT/check.mjs"; node --check "$OUT/check.mjs"; done
for f in tests/*.cjs; do node --check "$f"; done
# Browser JS may import only ./pkg/norea_web.js, ./custody.js, ./platform*.js, ./ui-text.js (no CDN, no npm).
BAD=$(grep -hoE "(from|import)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" web/public/*.js \
  | grep -oE "['\"][^'\"]+['\"]" | tr -d "'\"" \
  | grep -vxE '\./pkg/norea_web\.js|\./custody\.js|\./platform(-[a-z]+)?\.js|\./ui-text\.js' || true)
if [ -n "$BAD" ]; then
  echo "FAIL: browser JS imports outside the allowed local modules: $BAD" >&2
  exit 1
fi

# Web UI (WP-07, platform-contract: the UI calls only platform.js).
uifail() { echo "FAIL: web UI static check: $*" >&2; exit 1; }
APPIMP=$(grep -oE "(from|import)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" web/public/app.js \
  | grep -oE "['\"][^'\"]+['\"]" | tr -d "'\"" | sort -u | tr '\n' ' ')
[ "$APPIMP" = "./platform.js ./ui-text.js " ] || uifail "app.js must import exactly ./platform.js and ./ui-text.js, got: $APPIMP"
if grep -qE "(^|[^A-Za-z_])import[[:space:]]|import[[:space:]]*\(" web/public/ui-text.js; then uifail "ui-text.js must import nothing"; fi
if grep -nE "pkg/|custody|indexedDB|crypto\.subtle|WebAssembly|localStorage|sessionStorage|innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|console\." \
  web/public/app.js web/public/ui-text.js; then uifail "forbidden string in app.js / ui-text.js (above)"; fi
H=web/public/index.html
if grep -oE "<script[^>]*>" "$H" | grep -v 'src=' | grep -q .; then uifail "inline <script> in index.html"; fi
if grep -nE "<script[^>]*src=[^>]*>[^<]" "$H"; then uifail "script with src= also has inline content"; fi
if grep -niE "<style|[[:space:]]style[[:space:]]*=" "$H"; then uifail "inline style in index.html (above)"; fi
if grep -niE "[[:space:]]on[a-z]+[[:space:]]*=" "$H"; then uifail "inline event handler in index.html (above)"; fi
if grep -niE "https?:|[\"'(=]//" "$H" web/public/style.css; then uifail "external URL in index.html / style.css (above)"; fi
if grep -niE "@import|url\(" web/public/style.css; then uifail "@import or url() in style.css (above)"; fi
CSP="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"
[ "$(grep -c "content=\"$CSP\">" "$H")" = "1" ] || uifail "CSP meta in index.html changed"
node tests/ui.node.mjs "$PWD/$WEBTEST"

echo "== 6. getrandom in browser wasm tree"
N=$(cargo tree -p norea-web --target wasm32-unknown-unknown | grep -c getrandom || true)
if [ "$N" != "0" ]; then
  echo "FAIL: getrandom appears $N times. Find it: cargo tree -p norea-web --target wasm32-unknown-unknown -i getrandom" >&2
  exit 1
fi

echo "ALL CHECKS PASSED"
