# NoREA 구현 repo: 현재 상태 (STATE)

이 파일은 항상 현재 시제다. 계획은 `tasks/todo.md`, 설계(규범)는 `/Users/mac/dev/derator/Fable_5_1/`(protocol/, CORE-API.md, adr/).

## 무엇인가

NoREA는 운영자가 자기 소유의 공개 데이터에 canary를 심고, ML-DSA-65로 서명하고 외부 시점 anchor로 고정한 증거를 남겨, 운영자가 직접 가져온 의심 사본에서 canary를 대조해 복제를 증명하는 방어 제품이다. ProvGuard에서 재설계했고 호환성은 없다(ADR-0010).

## 지금 동작하는 것

Phase 1 구현 중. 로직이 있는 모듈은 `error`, `table`(WP-01), `norm`, `shape`, `canary`(WP-02)이다. 나머지 모듈(merkle, blob, sign, evidence, check, disclose, anchor)은 문서 주석만 있는 빈 파일이다. crate root에 `Key32 = [u8; 32]`가 있다.

- 뼈대(WP-00): workspace `core`(noreacore), `web`(norea-web), `cli`(norea-cli). web/src는 export가 없다. CLI 두 바이너리(norea-verify, norea)는 `--help`만 하고 다른 호출은 exit 2.
- `web/public/`의 JS/HTML은 이전 제품에서 이름만 바꿔 복사한 것이라 아직 새 API와 맞지 않는다(WP-06/07이 재작성). `tests/smoke.node.cjs`, `tests/platform.node.mjs`도 같다. 그래서 `scripts/test.sh`에서 2단계 node e2e와 3단계 플랫폼 계약은 꺼져 있다.
- toolchain은 `rust-toolchain.toml`(1.99.1 + wasm32-unknown-unknown)로 고정, node는 22. clippy component가 설치되어 있다.

### error (`core/src/error.rs`)
`noreacore::Error { code: ErrorCode, message: String }`, `ErrorCode` 8개(BadInput, NoMarker, CanaryExhausted, BadEvidence, BadSignature, BadBlob, BadDisclosure, BadAnchor). crate root에서 re-export한다. 메시지는 영어이고 입력 값, 비밀, 경로를 담지 않는다(serde_json 에러 문구는 값을 인용할 수 있어 그대로 넘기지 않고 line/column만 쓴다).

### table (`core/src/table.rs`)
`Format`, `detect_format`, `Cell`, `Row`(IndexMap), `Table`, `parse_table`, `serialize_with_inserts`, `canon_row`, `row_from_json`. 시그니처는 CORE-API §1 그대로. 입력 바이트를 바꾸지 않고 항상 새 버퍼를 돌려준다. shape 로직은 없다. crate 내부 `Table::format()`이 파싱한 포맷을 알려준다(shape가 CSV 빈 셀을 결측으로 세는 데 쓴다).

- `detect_format`: BOM을 뗀 바이트가 문법상 JSON이면 Json, 아니면 Csv. `{}`나 `[1]`도 Json으로 감지되고 `parse_table`에서 BadInput이 된다.
- 파싱된 `Table`의 모든 행은 `fields`의 모든 필드를 `fields` 순서로 가진다. JSON에서 키가 없는 셀은 `Cell::Missing`.
- JSON 입력: 최상위 배열, 원소는 모두 object(아니면 BadInput). 행의 키 순서는 직접 만든 serde visitor로 읽는다(`Value::Object`는 키를 정렬하므로). `fields` = 첫 행 키 순서 + 이후 처음 나온 순서. 중복 키는 마지막 값이 첫 위치에 남는다. 셀: string → Str, number → `Num { text: Number::to_string(), scale: 소수점 아래 자릿수(255에서 포화) }`, 지수가 있는 숫자 → `Opaque(Value::Number)`, bool/null → Bool/Null, array/object → Opaque.
- JSON 스타일: BOM 유무, 줄바꿈(첫 `\n` 앞이 `\r`이면 CRLF), 끝 줄바꿈 유무, 들여쓰기 단위(첫 줄 다음의 첫 비어 있지 않은 줄의 선행 공백이 공백만 또는 탭만이면 그것, 아니면 compact).
- JSON 출력: 전체 재직렬화(ADR-0013). 행 object 키는 `fields` 순서, Missing은 생략, `fields`에 없는 키(삽입 행에서만 가능)는 뒤에 행 순서대로. pretty 레이아웃은 serde_json PrettyFormatter와 같은 모양(`": "`, 빈 배열/객체는 `[]`/`{}`). 문자열 escape는 serde_json 기본과 같다(테스트로 대조). 숫자는 text 그대로. 삽입 행의 Num text가 JSON 숫자가 아니면 BadInput.
- JSON 한계: 원소 사이 공백·원본 레이아웃은 보존하지 않는다. 지수 표기는 serde_json 정규화(`1e3`→`1e+3`, `E`→`e`)를 거친다.
- CSV 입력: RFC 4180 직접 구현(`csv` crate 없음). 구분자 `,`, 따옴표 `"`, `""` escape, 따옴표 안 줄바꿈 허용, 레코드 종결자 LF 또는 CRLF(단독 CR은 데이터). UTF-8 필수, BOM 제거, 헤더 필수, 헤더 중복 이름 / 열 수 불일치 / 닫히지 않은 따옴표 / 닫는 따옴표 뒤 문자 → BadInput. 따옴표 없는 필드 중간의 `"`는 그대로 데이터. 빈 줄도 레코드라서 헤더가 2열 이상이면 BadInput. 모든 셀은 Str. 레코드별 바이트 범위와 지배적 줄바꿈(CRLF 수 > LF 수면 CRLF)을 기록한다.
- CSV 출력: 원본 레코드 바이트를 그대로 복사하고 그 사이에 삽입 레코드를 지배적 줄바꿈으로 끼운다. 삽입 셀은 `,` `"` CR LF 또는 앞뒤 공백이 있을 때만 따옴표. 원본 마지막 레코드 뒤에 줄바꿈이 없으면 출력도 없다. 삽입 0개면 원본과 바이트 동일. 헤더에 없는 키를 가진 삽입 행 → BadInput.
- `serialize_with_inserts`: inserts는 (최종 위치, 행). 위치 중복 또는 범위 밖 → BadInput. `original` 길이가 파싱 때와 다르면 BadInput.
- `canon_row`: evidence-v1 §7.1. Missing 생략, 키 UTF-8 바이트 정렬, Num은 text 그대로, Opaque는 같은 규칙으로 재귀(숫자는 `Number::to_string()`), escape `\" \\ \b \f \n \r \t` 그 외 제어문자 `\u00xx` 소문자, 비ASCII와 U+007F는 그대로.
- `row_from_json`: object만 받는다. 셀 변환은 JSON 파싱과 같다(키 순서는 입력 순서).
- serde_json preserve_order 켬: 중첩 object 키 순서가 출력에 보존된다. canon은 정렬한다. 이 feature가 `foldhash`(Zlib, deny.toml에 머리 승인으로 허용)를 끌어온다.
- 성능: 5만 행 JSON(3.69 MB) parse + serialize가 release에서 약 31 ms(Apple M4, rustc 1.99.1).

### norm (`core/src/norm.rs`)
대조와 충돌 회피 전용 정규화(shape-v1 §7.1). `canon_row`는 쓰지 않는다.
- `normalize_text`: NFC → 양끝 Unicode White_Space 제거 → 내부 공백 run(U+0009, U+0020, U+00A0, U+3000)을 U+0020 하나로 → 전각 ASCII(U+FF01..FF5E)를 반각으로. 대소문자 유지.
- `normalize_number`: `,`와 공백 제거 후 `[+-]?digits(.digits)?`만 받는다. 정수부 선행 0 제거, `+` 제거, 소수부 그대로(`"1,200.00"`→`"1200.00"`), `-0`은 `0`. 지수, `.5`, `1.` → None.

### shape (`core/src/shape.rs`)
shape-v1 **r2.2** 구현. `Kind`, `FieldShape`, `Shape`, `infer_shape`, `auto_markers`, `threshold`, `shape_summary`, `inspect`.
- 결측: JSON Missing + Null, CSV `Str("")`. `missing_ppm` = 정수 round half up. JSON에서 결측 중 Null이 과반이면 canary 결측도 Null, 아니면 키 생략.
- kind: m = 0이면 EMPTY → 모두 Bool이면 BOOL → 모두 Num(JSON) 또는 NUMERIC 정규식(CSV)이면 NUMERIC → 모두 Str이면 STRING → 그 외 OPAQUE(지수 숫자 셀 포함). NUMERIC/STRING은 `d ≤ max(2, floor(0.05m)) && d ≤ 64`이면 CATEGORICAL. `unique = d == m && m ≥ 2`(데이터 속성으로 보고).
- NUMERIC: scale = 최대 소수 자릿수(상한 8, 넘는 자릿수는 잘림). 정수 `v·10^scale`(i128, 넘치면 OPAQUE)를 중복 포함으로 정렬한 V[0..m)(r2.2, 행 밀도 가중)과 빈 정수 개수 G = (max−min+1) − (서로 다른 정수 개수)를 둔다. scale에서 잘려 같은 정수가 된 텍스트는 하나로 센다. 비결측 셀 전체를 복사 원천으로 보관한다. `code_like` = unique이고 모두 정수이고 텍스트 길이가 같음.
- STRING: char 단위 토큰화(D `0-9`, H U+AC00..D7A3, L `A-Za-z`, 그 외 literal 1개, 정규화 없음). 템플릿(첫 등장 순서)마다 count, D 슬롯 min/max, anchor 목록이 있다. anchor 목록은 모든 H/L 슬롯 값이 (템플릿, 슬롯) 안에서 빈도 2 이상인 값들의 H/L 값이고, 행 순서와 중복을 유지하며, 비면 전체를 쓴다. 템플릿 수 == m이면 OPAQUE.
- `space_log2_x100`: libm 없이 IEEE 기본 연산으로 log2를 구해 100배 정수로 둔다. NUMERIC은 max(1, G), STRING은 Σ_t (anchor H/L 조합 수 · Π D 범위), CATEGORICAL/BOOL은 d다. OPAQUE/EMPTY에는 없다.
- `auto_markers`(§4.1): kind STRING/NUMERIC, `missing_ppm < 200000`, 빈 공간(NUMERIC G ≥ d, STRING space ≥ 2d). (d 내림차순, STRING 먼저, 이름 바이트 오름차순) 앞 3개. 없으면 NoMarker이고, 메시지에 필드별 탈락 이유(kind / missing / free space)를 적는다.
- `inspect`: InspectResult JSON. camelCase이고 `pMissing`, `spaceLog2`는 정수에서 유도한 표시용 float다. `warnings: [{code, field?}]`는 OPAQUE_FIELD, UNIQUE_OPAQUE_COPIED, LOW_FREE_SPACE, HIGH_MISSING, NUMERIC_CODE_LIKE(필드 순서)이고, 마지막에 NO_MARKER_CANDIDATE.
- `shape_summary`(§6.1): 정수만. 필드별 `{kind, unique, distinct, missing_ppm, space_log2_x100?}`, 테이블 필드 순서.

### canary (`core/src/canary.rs`)
`MarkOptions`, `MarkOutput`, `draw`, `mark`. RNG 없음. 모든 선택은 `draw`(HMAC-SHA256(K_d), §5.1)로 한다.
- 보호 필드 = marker, 또는 unique이고 최종 kind가 STRING/NUMERIC인 필드.
- 후보 (i, attempt), 필드 순서대로(§5.2). 결측 draw 1회(EMPTY는 draw 없이 결측). 결측이 아니면 kind별로 다음과 같다.
  - 비보호 NUMERIC: 실제 셀 복사 1회.
  - 보호 NUMERIC: gap sampling 1회(r2.1/r2.2). k0 = (r>>32) mod (m−1), k = k0부터 (k+1) mod (m−1)로 이동해 첫 w_k > 0 구간, N = V[k]+1+((r & 0xFFFFFFFF) mod w_k). 이동은 `mark`에서 필드당 한 번 만든 next-gap 배열로 O(1)이고, 문자 그대로의 스캔과 같음을 테스트로 확인한다. G = 0이면 후보 기각.
  - STRING: 템플릿(count 비례) 1회, anchor(mod len) 1회, D 슬롯마다 1회. H/L은 anchor 값을 복사한다.
  - CATEGORICAL/BOOL(빈도 비례)과 OPAQUE(셀 복사): 1회.
- NUMERIC 텍스트: fixed_scale이면 scale자리 고정, 아니면 후행 0 제거.
- 충돌 회피(§5.3, 보호 필드만):
  - STRING은 `normalize_text`가 실제 값 ∪ (marker면) exclusions ∪ 앞선 canary에 있으면 기각.
  - NUMERIC은 값 기준이다. 정렬 집합에서 |x − c| < 0.5·10^-s인 x가 있으면 기각(s는 후보 텍스트의 소수 자릿수). exclusions는 `normalize_number`로 파싱한다.
  - marker가 결측으로 뽑히면 기각.
  - 64회 실패 → `CanaryExhausted "canary i: no acceptable candidate"`.
- 운영자 marker: 1~4개. 중복·없는 필드 → BadInput. OPAQUE → NoMarker(`field X has no reusable shape; choose other marker fields`). CATEGORICAL/BOOL/EMPTY → NoMarker. 빈 공간 조건은 요구하지 않는다. n = 0 → BadInput.
- 삽입: `pos_i = draw(K_d,"pos",i,0,0) mod (L+i+1)`를 순서대로 적용해 최종 위치를 계산하고 `serialize_with_inserts` 한 번으로 출력한다. CSV canary 셀은 모두 Str(결측은 `""`).
- 성능: 5만 행 JSON(7.25 MB) `mark(n=64)` release 약 0.15 s(Apple M4).

### 한계 (측정됨, WP-02 보고서 4차)
- 보호 NUMERIC은 값 사이의 빈 정수만 만든다(값 밀도는 따르지만 값 자체의 구조는 모른다). 코드성 정수의 자릿수 구조는 모른다(inspect `NUMERIC_CODE_LIKE`). 측정: 공개 CSV 법정동코드 n = 1000 KS 0.022~0.028(q95 0.044), A' log-uniform 면적 KS 0.024(q95 0.043).
- 필드 간 상관(예: 법정동코드와 시도명)은 학습하지 않는다. 한 필드 안의 어휘 조합은 anchor로 보존된다(데이터셋 A 시↔동 불일치 0/1000).
- 날짜 같은 의미 제약을 모른다(`2003-02-31`이 나올 수 있다).
- unique 자유 텍스트(OPAQUE)는 실제 값을 복사한다(inspect 경고).

### 테스트 도구
- `core/tests/shape_vectors.rs` + `tests/vectors/shape-v1.json`: draw 값과 canary canonical 행 vector(동결 아님). `NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test shape_vectors`로 재생성.
- `core/tests/distinguishability.rs`: §9 r2.2 판정(n = 1000, 자동 marker)과 n = 64 보고.
  - 지표: 직접 구현한 로지스틱 회귀 5-fold AUC, 필드별 ablation, KS bootstrap, Monte Carlo χ², §5.3 기준 충돌, NUMERIC decile 비율, 시↔동 불일치.
  - 결측률은 K = 10 키 평균을 실제 n·K 행 bootstrap 95% 구간과 비교한다(`missing_rate_judgement`). 키별 90% band는 보고만 한다.
  - 기본 테스트 `dataset_a_n1000`은 키 1 판정과 결측률 판정을 한다.
  - `full_report`(키 2~3 판정, n = 64와 A' 보고)와 `public_csv`(`NOREA_PUBLIC_CSV=경로 [NOREA_PUBLIC_CSV_SHA256=hex]`, 키 1~3 판정과 결측률 판정)는 `-- --ignored`로 돌린다.

### 검증 상태
`cargo test -p noreacore`(lib 43 + shape_vectors 1 + distinguishability 1, ignored 2), `cargo clippy -p noreacore --all-targets -- -D warnings`, wasm32 release build, getrandom 0(`cargo tree -p norea-web --target wasm32-unknown-unknown`), `cargo deny check`, `./scripts/test.sh`(ALL CHECKS PASSED)가 통과한다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-01.md`, `WP-02.md`.

## 불변 조건 (바꾸려면 ADR + 희진 승인)

1. `norea.evidence.v1` 필드, signing payload 바이트, `SIG_CTX = "norea/evidence/v1"`, Merkle 구조, blob AEAD. WP-03 vector 동결 이후 고정. vector 테스트가 깨지면 고치지 말고 멈춰서 보고(ADR-0008).
2. `noreacore`는 RNG, 네트워크, 파일 I/O, 키 저장, 시계에 의존하지 않는다. 브라우저 wasm 의존성 트리에 getrandom 0개(ADR-0005).
3. 입력 파일을 절대 수정하지 않는다. 항상 새 파일.
4. 하드웨어 정직성: `hardwareDuringSigning`을 사실대로(ADR-0006).
5. 로컬 시계는 시점 증거가 아니다(ADR-0004).
6. canary 생성기는 kind별로 고정. 기존 kind 로직을 바꾸지 말고 새 kind를 추가(ADR-0002).
7. UI는 `platform.js` 계약만 부른다(protocol/platform-contract.md).
8. 비밀은 WASM 경계를 한 번만 넘고 양쪽에서 0으로 덮는다(ADR-0012).
9. canary 후보, exclusions, 원본 데이터를 어떤 서버에도 보내지 않는다. anchor는 32바이트 subject 해시만.
10. 실제 존재하는 값(주소, 지번)을 canary로 쓰지 않는다.
