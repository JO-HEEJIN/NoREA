#!/usr/bin/env bash
# Full verification. Run before every commit.
#   1. core unit tests + frozen-format vectors
#   2. wasm build + the exact WASM API end to end (node), incl. the ADR-0012 memory scan
#   3. the web platform contract incl. key custody, passphrase path (node + in-memory IndexedDB)
#   4. CLI tests: unit + cli/tests/e2e.rs (protect -> check -> disclose -> norea-verify, exit codes, no key material in output)
#   5. syntax check of all browser JS as ES modules + tests JS; browser JS imports only local modules
#   6. no getrandom in the browser wasm dependency tree (CONTEXT.md invariant 2)
# Not covered (needs a real browser): WebAuthn PRF, DOM (WP-09).
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

echo "== 5. JS syntax"
for f in web/public/*.js tests/*.mjs; do cp "$f" "$OUT/check.mjs"; node --check "$OUT/check.mjs"; done
for f in tests/*.cjs; do node --check "$f"; done
# Browser JS may import only ./pkg/norea_web.js, ./custody.js, ./platform*.js (no CDN, no npm).
BAD=$(grep -hoE "(from|import)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" web/public/*.js \
  | grep -oE "['\"][^'\"]+['\"]" | tr -d "'\"" \
  | grep -vxE '\./pkg/norea_web\.js|\./custody\.js|\./platform(-[a-z]+)?\.js' || true)
if [ -n "$BAD" ]; then
  echo "FAIL: browser JS imports outside the allowed local modules: $BAD" >&2
  exit 1
fi

echo "== 6. getrandom in browser wasm tree"
N=$(cargo tree -p norea-web --target wasm32-unknown-unknown | grep -c getrandom || true)
if [ "$N" != "0" ]; then
  echo "FAIL: getrandom appears $N times. Find it: cargo tree -p norea-web --target wasm32-unknown-unknown -i getrandom" >&2
  exit 1
fi

echo "ALL CHECKS PASSED"
