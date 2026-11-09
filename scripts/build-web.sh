#!/usr/bin/env bash
# Build the browser bundle into web/public/pkg.
# Requires: rustup target wasm32-unknown-unknown, wasm-bindgen-cli matching Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")/.."

WBV=$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | grep version | head -1 | cut -d'"' -f2)
HAVE=$(wasm-bindgen --version 2>/dev/null | awk '{print $2}' || true)
if [ "$HAVE" != "$WBV" ]; then
  echo "wasm-bindgen CLI $HAVE != crate $WBV. Run: cargo install wasm-bindgen-cli --version $WBV --locked" >&2
  exit 1
fi

cargo build --release -p norea-web --target wasm32-unknown-unknown
wasm-bindgen target/wasm32-unknown-unknown/release/norea_web.wasm --target web --out-dir web/public/pkg

WASM=web/public/pkg/norea_web_bg.wasm
size() { wc -c < "$1" | tr -d ' '; }
echo "wasm size before wasm-opt: $(size "$WASM") bytes"
if command -v wasm-opt >/dev/null; then
  wasm-opt -O3 "$WASM" -o "$WASM"
  echo "wasm size after wasm-opt -O3: $(size "$WASM") bytes (budget 600 KB, ARCHITECTURE §7)"
else
  echo "wasm-opt not found: size above is unoptimized" >&2
fi
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
$SHA web/public/pkg/norea_web_bg.wasm | tee web/public/pkg/BUILD_SHA256
echo "Serve locally (WebAuthn needs a secure context; localhost counts):"
echo "  python3 -m http.server 8080 -d web/public"
