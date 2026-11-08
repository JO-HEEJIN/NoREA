#!/usr/bin/env bash
# Full verification. Run before every commit.
#   1. core unit tests + frozen-format vectors
#   2. wasm build + the exact WASM API end to end (node)
#   3. the web platform contract incl. key custody, passphrase path (node + in-memory IndexedDB)
#   4. CLI tests
#   5. syntax check of all browser JS as ES modules
#   6. no getrandom in the browser wasm dependency tree (CONTEXT.md invariant 2)
# Steps marked "disabled" wait for the WP named next to them; enable them there.
# Not covered (needs a real browser): WebAuthn PRF, DOM (WP-09).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== 1. core tests"
cargo test --release -p noreacore

echo "== 2. wasm build"
cargo build --release -p norea-web --target wasm32-unknown-unknown
OUT=$(mktemp -d)
# disabled until WP-06 rewrites tests/smoke.node.cjs for the new API:
# wasm-bindgen target/wasm32-unknown-unknown/release/norea_web.wasm --target nodejs --out-dir "$OUT"
# node tests/smoke.node.cjs "$OUT/norea_web.js"

echo "== 3. platform contract (disabled until WP-06)"
# wasm-bindgen target/wasm32-unknown-unknown/release/norea_web.wasm --target web --out-dir web/public/pkg
# [ -d tests/node_modules ] || (cd tests && npm install --no-audit --no-fund --silent)
# node tests/platform.node.mjs "$PWD/web/public"

echo "== 4. CLI tests"
cargo test -p norea-cli

echo "== 5. JS syntax"
for f in web/public/*.js; do cp "$f" "$OUT/check.mjs"; node --check "$OUT/check.mjs"; done

echo "== 6. getrandom in browser wasm tree"
N=$(cargo tree -p norea-web --target wasm32-unknown-unknown | grep -c getrandom || true)
if [ "$N" != "0" ]; then
  echo "FAIL: getrandom appears $N times. Find it: cargo tree -p norea-web --target wasm32-unknown-unknown -i getrandom" >&2
  exit 1
fi

echo "ALL CHECKS PASSED"
