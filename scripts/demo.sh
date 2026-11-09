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

if [ ! -x "$NOREA" ] || [ ! -x "$VERIFY" ]; then
  step "release CLI 빌드 / building release CLI"
  cargo build --release -p norea-cli || exit 1
fi

step "1. 데모 데이터 / demo data"
SRC=""
for c in "$ROOT/target/public-csv/raw.csv" $(find /Users/mac/dev /private/tmp/claude-501 \( -iname "raw.csv" -o -iname "*법정동*.csv" \) 2>/dev/null); do
  if [ -f "$c" ] && head -1 "$c" | grep -q "법정동코드"; then SRC="$c"; break; fi
done
if [ -z "$SRC" ]; then
  echo "국토교통부 법정동 CSV를 찾지 못함 / MOLIT CSV not found. 이 데모는 그 파일이 필요하다."
  exit 1
fi
cp "$SRC" "$D/input.csv"
if grep -q '"' "$D/input.csv"; then echo "quoted CSV is not supported by demo-crawler.mjs"; exit 1; fi
echo "source: $SRC"
echo "input.csv: 국토교통부 법정동코드 (공공데이터), 행 수는 inspect 참조 / row count: see inspect"

step "2. 테스트 키 / test keys (DEMO ONLY, not real keys)"
head -c 32 /dev/urandom > "$D/k.bin"
head -c 32 /dev/urandom > "$D/seed.bin"
echo "k.bin $(wc -c < "$D/k.bin" | tr -d ' ') B, seed.bin $(wc -c < "$D/seed.bin" | tr -d ' ') B from /dev/urandom. 데모용 테스트 키다. 실제 키는 웹 UI의 WebAuthn PRF / passphrase 보관을 쓴다."

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
"$NOREA" protect --n 32 --dataset-id demo/molit-bjd --key-file "$D/k.bin" $T --seed-file "$D/seed.bin" --out-dir "$D" "$D/input.csv" || exit 1
t1=$(node -e 'console.log(Date.now())')
echo "protect: $((t1 - t0)) ms (native, process 포함 / including process start)"
echo "입력 파일은 수정하지 않는다 / input untouched: $(shasum -a 256 "$SRC" | cut -c1-16) == $(shasum -a 256 "$D/input.csv" | cut -c1-16)"

step "5. 크롤러 사본 생성 / simulated crawler copies"
node "$ROOT/scripts/demo-crawler.mjs" "$D/input.marked.csv" "$D/input.csv" "$D" || exit 1
echo "copy-html.html     HTML <table>, 열 이름 변경, &amp;, 줄바꿈/공백 삽입 / renamed columns, entities, whitespace"
echo "copy-api.json      {\"status\":\"ok\",\"data\":[...]} 키 이름 변경 / renamed keys"
echo "copy-shuffled.csv  행 순서 섞음, CRLF / shuffled rows"
echo "unrelated.csv      원본(canary 없음)의 부산광역시 행만 / unmarked original, one province"

step "6. norea check (각 사본 / each copy)"
for f in copy-html.html copy-api.json copy-shuffled.csv unrelated.csv; do
  t0=$(node -e 'console.log(Date.now())')
  "$NOREA" check --key-file "$D/k.bin" $T "$D/$f" "$D/input.evidence.json" > "$D/check-$f.json" 2>"$D/check-$f.err"
  rc=$?
  t1=$(node -e 'console.log(Date.now())')
  node -e '
const [p,name,rc,ms]=process.argv.slice(1);
let r; try { r=JSON.parse(require("fs").readFileSync(p,"utf8")); } catch { console.log(`${name.padEnd(18)} exit=${rc} (no report)`); process.exit(0); }
console.log(`${name.padEnd(18)} kind=${String(r.suspect_kind).padEnd(5)} matched=${r.matched}/${r.total} partial=${r.partial} absent=${r.absent}  (${ms} ms, exit=${rc})`);
' "$D/check-$f.json" "$f" "$rc" "$((t1 - t0))"
done

step "7. norea disclose (HTML 사본 기준 / from the HTML copy)"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
"$NOREA" disclose --key-file "$D/k.bin" $T \
  --source-claim https://example-crawler.test/data \
  --captured-claim "$NOW" \
  --capture-method-claim "browser save-as" \
  --out "$D/disclosure.json" "$D/input.evidence.json" "$D/copy-html.html" || exit 1
echo "disclosure.json: $(wc -c < "$D/disclosure.json" | tr -d ' ') B"

step "8. 키 없이 검증 / verify without any key: norea-verify disclosure"
echo "\$ norea-verify disclosure disclosure.json copy-html.html"
"$VERIFY" disclosure "$D/disclosure.json" "$D/copy-html.html"
echo "--> exit code $? (0 PASS, 1 FAIL, 2 input error)"

step "9. 사본 1바이트 변조 / suspect copy with 1 byte changed"
node -e '
const fs=require("fs"); const b=fs.readFileSync(process.argv[1]);
const i=b.indexOf(Buffer.from("scraped")); b[i]=b[i]^0x20; fs.writeFileSync(process.argv[2], b);
console.log(`byte ${i} flipped (${String.fromCharCode(b[i]^0x20)} -> ${String.fromCharCode(b[i])})`);
' "$D/copy-html.html" "$D/copy-html.tampered.html"
echo "\$ norea-verify disclosure disclosure.json copy-html.tampered.html"
"$VERIFY" disclosure "$D/disclosure.json" "$D/copy-html.tampered.html"
echo "--> exit code $? (1 expected / FAIL 기대)"

step "이 데모가 증명하지 않는 것 / what this demo does NOT prove"
echo "1. 시점 anchor가 없다. created_claim은 로컬 시계의 주장일 뿐이다 / no time anchor: created_claim is a local-clock claim."
echo "2. 사본의 출처와 포착 시점(source/captured/method)은 운영자 주장이고 검증되지 않는다 / capture source and time are operator claims."
echo "3. anchor가 붙어도 TSA 인증서 체인은 norea-verify가 검증하지 않는다(openssl로 수동) / TSA cert chain is not verified."

END=$(date +%s)
printf '\n총 소요 / total: %ss. 출력 / output: %s\n' "$((END - START))" "$D"
