#!/usr/bin/env bash
# NoREA judge demo. Idempotent: wipes and rebuilds target/demo/ on every run.
# Keys made here are TEST KEYS from /dev/urandom, for this demo only.
set -uo pipefail
export PATH="/opt/homebrew/opt/node@22/bin:$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/.."
ROOT=$(pwd)
D="$ROOT/target/demo"
NOREA="$ROOT/target/release/norea"
VERIFY="$ROOT/target/release/norea-verify"
T="--i-know-this-is-for-testing"

rm -rf "$D"; mkdir -p "$D"
exec > >(tee "$D/demo.log") 2>&1
START=$(date +%s)

step() { printf '\n=== %s ===\n' "$*"; }

# Always (no-op when up to date): a stale release binary would show old behavior.
# NOREA_DEMO_NO_BUILD=1 skips the build and uses the existing target/release binaries.
if [ "${NOREA_DEMO_NO_BUILD:-0}" = 1 ]; then
  step "release CLI build skipped (NOREA_DEMO_NO_BUILD=1)"
  [ -x "$NOREA" ] && [ -x "$VERIFY" ] || { echo "release binaries missing: run without NOREA_DEMO_NO_BUILD"; exit 1; }
else
  step "building release CLI"
  cargo build --release -p norea-cli || exit 1
fi

step "1. demo data"
# Default: synthetic San Francisco listings (scripts/demo-mkdata.mjs). Alternatives via NOREA_DEMO_INPUT:
# demo/data/world-cities.csv (GeoNames, CC BY 4.0) or demo/data/legal-dong-code.csv (Korean MOLIT).
SRC="${NOREA_DEMO_INPUT:-$ROOT/demo/data/sf-listings-synthetic.csv}"
case "$SRC" in /*) ;; *) SRC="$ROOT/$SRC" ;; esac
if [ ! -f "$SRC" ]; then
  echo "demo input not found: $SRC"
  exit 1
fi
cp "$SRC" "$D/input.csv"
echo "source: $SRC"
if head -1 "$SRC" | grep -q "^listing_id,address,neighborhood,price_usd,beds,sqft,listed"; then
  DATASET_ID="demo/sf-listings-synthetic"
  echo "input.csv: SYNTHETIC San Francisco listings made by scripts/demo-mkdata.mjs. No real addresses or prices. Row count: see inspect."
elif head -1 "$SRC" | grep -q "^name,country,subcountry,geonameid"; then
  DATASET_ID="demo/world-cities"
  echo "input.csv: GeoNames world cities (real public data, CC BY 4.0, via datahub.io). Row count: see inspect."
else
  DATASET_ID="demo/molit-bjd"
  echo "input.csv: Korean MOLIT legal-dong codes (real public data). Row count: see inspect."
fi

step "2. test keys (DEMO ONLY, not real keys)"
head -c 32 /dev/urandom > "$D/k.bin"
head -c 32 /dev/urandom > "$D/seed.bin"
echo "k.bin $(wc -c < "$D/k.bin" | tr -d ' ') B, seed.bin $(wc -c < "$D/seed.bin" | tr -d ' ') B from /dev/urandom. These are demo test keys; real keys live in the web UI, wrapped by WebAuthn PRF or a passphrase."

step "3. norea inspect"
"$NOREA" inspect "$D/input.csv" > "$D/inspect.json"
node -e '
const r=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
console.log(`rows=${r.rows} format=${r.format} suggestedMarkers=${r.suggestedMarkers.join(",")} threshold=${r.threshold}`);
for (const f of r.fields) console.log(`  ${f.name.padEnd(8)} ${f.kind.padEnd(12)} distinct=${f.distinct} spaceLog2=${f.spaceLog2}`);
console.log("warnings: "+r.warnings.map(w=>w.code+"("+w.field+")").join(", "));
' "$D/inspect.json"

step "4. norea protect --n 32"
t0=$(node -e 'console.log(Date.now())')
"$NOREA" protect --n 32 --dataset-id "$DATASET_ID" --key-file "$D/k.bin" $T --seed-file "$D/seed.bin" --out-dir "$D" "$D/input.csv" || exit 1
t1=$(node -e 'console.log(Date.now())')
echo "protect: $((t1 - t0)) ms (native, including process start)"
echo "input file untouched: $(shasum -a 256 "$SRC" | cut -c1-16) == $(shasum -a 256 "$D/input.csv" | cut -c1-16)"

step "4b. norea anchor (RFC 3161 TSA, freetsa.org)"
EV="$D/input.evidence.json"
ANCHORED=0
echo "\$ norea anchor input.evidence.json --tsa https://freetsa.org/tsr"
if "$NOREA" anchor "$EV" --tsa https://freetsa.org/tsr; then
  EV="$D/input.evidence.anchored.json"
  ANCHORED=1
  echo "using $(basename "$EV") from here on"
else
  echo "anchor skipped (no network or TSA error): this evidence does not prove when it was created."
fi

step "5. simulated crawler copies"
node "$ROOT/scripts/demo-crawler.mjs" "$D/input.marked.csv" "$D/input.csv" "$D" || exit 1
echo "copy-html.html     HTML <table>, renamed columns, &amp; entities, extra line breaks and whitespace"
echo "copy-api.json      {\"status\":\"ok\",\"data\":[...]} with renamed keys"
echo "copy-shuffled.csv  rows shuffled, CRLF line endings"
echo "unrelated.csv      rows of one neighborhood/country/province taken from the ORIGINAL input (no canaries)"

step "6. norea check (each copy)"
for f in copy-html.html copy-api.json copy-shuffled.csv unrelated.csv; do
  t0=$(node -e 'console.log(Date.now())')
  "$NOREA" check --key-file "$D/k.bin" $T "$D/$f" "$EV" > "$D/check-$f.json" 2>"$D/check-$f.err"
  rc=$?
  t1=$(node -e 'console.log(Date.now())')
  node -e '
const [p,name,rc,ms]=process.argv.slice(1);
let r; try { r=JSON.parse(require("fs").readFileSync(p,"utf8")); } catch { console.log(`${name.padEnd(18)} exit=${rc} (no report)`); process.exit(0); }
console.log(`${name.padEnd(18)} kind=${String(r.suspect_kind).padEnd(5)} matched=${r.matched}/${r.total} partial=${r.partial} absent=${r.absent}  (${ms} ms, exit=${rc})`);
' "$D/check-$f.json" "$f" "$rc" "$((t1 - t0))"
done

step "7. norea disclose (from the HTML copy)"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$NOREA" disclose --key-file "$D/k.bin" $T \
  --source-claim https://example-crawler.test/data \
  --captured-claim "$NOW" \
  --capture-method-claim "browser save-as" \
  --out "$D/disclosure.json" "$EV" "$D/copy-html.html" || exit 1
echo "disclosure.json: $(wc -c < "$D/disclosure.json" | tr -d ' ') B"

step "8. verify without any key: norea-verify disclosure"
echo "\$ norea-verify disclosure disclosure.json copy-html.html"
"$VERIFY" disclosure "$D/disclosure.json" "$D/copy-html.html"
echo "--> exit code $? (0 PASS, 1 FAIL, 2 input error)"

step "9. suspect copy with 1 byte changed"
node -e '
const fs=require("fs"); const b=fs.readFileSync(process.argv[1]);
const i=b.indexOf(Buffer.from("scraped")); b[i]=b[i]^0x20; fs.writeFileSync(process.argv[2], b);
console.log(`byte ${i} flipped (${String.fromCharCode(b[i]^0x20)} -> ${String.fromCharCode(b[i])})`);
' "$D/copy-html.html" "$D/copy-html.tampered.html"
echo "\$ norea-verify disclosure disclosure.json copy-html.tampered.html"
"$VERIFY" disclosure "$D/disclosure.json" "$D/copy-html.tampered.html"
echo "--> exit code $? (1 expected: FAIL)"

step "what this demo does NOT prove"
if [ "$ANCHORED" = 1 ]; then
  echo "1. The TSA genTime and imprint were checked, but norea-verify does not check the TSA certificate chain (manual: --export-anchors, then openssl ts -verify)."
else
  echo "1. No time anchor (skipped). created_claim is only a claim made by the local clock."
fi
echo "2. Where, when and how the copy was captured (source/captured/method) are operator claims and are not verified."
echo "3. The probability bound is relative to the generator model, not a real-world probability."

END=$(date +%s)
printf '\ntotal: %ss. output: %s\n' "$((END - START))" "$D"
