# NoREA 구현 repo: 현재 상태 (STATE)

이 파일은 항상 현재 시제다. 계획은 `tasks/todo.md`, 설계(규범)는 `/Users/mac/dev/derator/Fable_5_1/`(protocol/, CORE-API.md, adr/).

## 무엇인가

NoREA는 운영자가 자기 소유의 공개 데이터에 canary를 심고, ML-DSA-65로 서명하고 외부 시점 anchor로 고정한 증거를 남겨, 운영자가 직접 가져온 의심 사본에서 canary를 대조해 복제를 증명하는 방어 제품이다. ProvGuard에서 재설계했고 호환성은 없다(ADR-0010).

## 지금 동작하는 것

Phase 1 구현 중. 로직이 있는 모듈은 `error`, `table`(WP-01), `norm`, `shape`, `canary`(WP-02), `merkle`, `blob`, `sign`, `evidence`(WP-03), `check`, `disclose`(WP-04)이다. `anchor`는 문서 주석만 있는 빈 파일이다(WP-08). 동결 vector `tests/vectors/norea-evidence-v1.json`이 생성되어 있고 `core/tests/vectors.rs`가 대조한다. `norea.evidence.v1`과 `record.shape.v1`은 2026-11-09 머리 수락으로 Frozen이다. `norea.disclosure.v1`과 `norea.disclosure-report.v1`(disclosure-v1 §2~§4)도 WP-04 수락으로 Frozen이다. crate root에 `Key32 = [u8; 32]`가 있다.

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
- `inspect`: InspectResult JSON. camelCase이고 `pMissing`, `spaceLog2`는 정수에서 유도한 표시용 float다. `warnings: [{code, field?}]`는 OPAQUE_FIELD, UNIQUE_OPAQUE_COPIED, NO_FREE_SPACE 또는 LOW_FREE_SPACE, HIGH_MISSING, NUMERIC_CODE_LIKE(필드 순서)이고, 마지막에 NO_MARKER_CANDIDATE. NO_FREE_SPACE는 unique STRING/NUMERIC 필드의 빈 공간이 0일 때(NUMERIC `G == 0`, STRING `space <= d`, `FieldShape::no_free_space`)이고, 그 필드에는 LOW_FREE_SPACE를 내지 않는다.
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
  - 64회 실패 → `CanaryExhausted "canary i: no acceptable candidate (field f)"`. f는 그 canary에서 기각을 가장 많이 일으킨 필드(동률이면 필드 순서상 앞)이고 값은 넣지 않는다. 연번 `1..N` 같은 dense unique 필드가 있으면 그 필드 이름이 나온다.
- 운영자 marker: 1~4개. 중복·없는 필드 → BadInput. OPAQUE → NoMarker(`field X has no reusable shape; choose other marker fields`). CATEGORICAL/BOOL/EMPTY → NoMarker. 빈 공간 조건은 요구하지 않는다. n = 0 → BadInput.
- 삽입: `pos_i = draw(K_d,"pos",i,0,0) mod (L+i+1)`를 순서대로 적용해 최종 위치를 계산하고 `serialize_with_inserts` 한 번으로 출력한다. CSV canary 셀은 모두 Str(결측은 `""`).
- 성능: 5만 행 JSON(7.25 MB) `mark(n=64)` release 약 0.15 s(Apple M4).

### merkle (`core/src/merkle.rs`)
evidence-v1 §7.2, RFC 9162 §2.1 구조. `leaf_hash(i, canon) = SHA-256(0x00 || u32be(i) || canon)`, `merkle_root`(k = n보다 작은 최대 2의 거듭제곱, node = `SHA-256(0x01 || L || R)`, 빈 입력은 panic), `audit_path`(RFC 9162 §2.1.3.1 PATH, leaf→root 순서, 범위 밖 index는 빈 path), `verify_audit_path`(§2.1.3.2를 단계 번호와 함께 주석에 인용). path는 count에 path 모양으로만 묶인다. 모양이 같은 다른 count도 통과한다(n=1..9, c=1..10에서 64개 경우). 그래서 verifier는 서명된 `canary_count`를 넘겨야 한다.

### blob (`core/src/blob.rs`)
evidence-v1 §7.3. `K_blob = HKDF-SHA256(salt "norea/canary-blob/v1", ikm K_d, info marked_sha256 raw)`(`pub fn derive_blob_key`, `Zeroizing<Key32>` 반환). plaintext는 `{"rows":[canon_row...],"shape":<shape_summary compact>}`, AAD는 `"norea.evidence.v1\n" + dataset_id + "\n" + hex(marked_sha256)`, nonce는 12 x 0x00, ChaCha20-Poly1305. `seal_blob`은 `ct || tag`를 돌려준다. `open_blob`은 인증 실패, JSON이 아님, rows/shape 없음을 모두 `BadBlob`으로 돌려준다. rows는 `row_from_json`으로 파싱하고, 다시 `canon_row`하면 원래 바이트와 같다(Opaque, 지수, 중첩 포함 테스트). plaintext 버퍼는 `Zeroizing`이다.

### sign (`core/src/sign.rs`)
`SIG_CTX = b"norea/evidence/v1"`(17 B). `SoftwareSigner::from_seed`(seed 복사본은 zeroize), `verifying_key_bytes`(1952 B), `sign`(ML-DSA-65 deterministic, context SIG_CTX, 3309 B, 실패는 `BadSignature`), `verify`(형식이 틀리면 false). `SoftwareSigner`는 `ZeroizeOnDrop`이다. ml-dsa의 `zeroize` feature가 켜져 있어서 `SigningKey`와 expanded key가 drop 시 지워진다.

### evidence (`core/src/evidence.rs`)
`EVIDENCE_SCHEMA`, `CANARY_KIND_RECORD_SHAPE_V1`, `derive_dataset_key`(HKDF salt "norea/v1", info dataset_id), `sha256_hex`, `Anchor { kind, #[serde(flatten)] rest }`, `Evidence`(§4 필드를 §4 순서로 직렬화, 모르는 키는 무시, `anchors` 기본값 `[]`), `Prepared`, `EvidenceVerification`, `AnchorCheck`.
- `signing_payload`: §6의 11행을 `\n`으로 잇고 끝 줄바꿈은 없다. `marker_fields`는 §5.2 compact JSON(`"`와 `\`만 escape). `evidence_id` = hex(SHA-256(payload)). `anchor_subject` = SHA-256(payload || 0x0A || sig)이고 서명이 3309 B가 아니면 `BadEvidence`.
- `validate_fields`(모두 `BadInput`): schema가 정확히 일치해야 한다. dataset_id, created_claim, 각 marker, canary_kind는 비어 있지 않고 제어문자(U+0000..001F, U+007F)가 없어야 한다. dataset_id는 256 B 이하, format은 json/csv, hex64 4개는 소문자 64자, canary_count는 1 이상, marker는 1~4개다. created_claim은 `YYYY-MM-DDTHH:MM:SSZ` 20자이고 월 01-12, 일 01-31, 시 00-23, 분 00-59, 초 00-60 범위를 검사한다.
- `prepare_evidence`: dataset_id와 created_claim을 먼저 검사한다. 그다음 `mark`, 해시, Merkle root, `seal_blob`을 거쳐 서명 없는 Evidence를 만든다(vk/sig/evidence_id는 빈 문자열). `canary_kind = record.shape.v1`, `marker_fields = MarkOutput.markers`.
- `finalize_evidence`: validate 후 `verify(vk, payload, sig)`가 참일 때만 vk_b64, sig_b64, evidence_id를 채운다. 아니면 `BadSignature`. `build_evidence` = prepare + `SoftwareSigner::sign` + finalize.
- `verify_evidence`(비밀 없음): `signature_ok`는 validate_fields 통과와 서명 검증이 모두 참이어야 참이다. `evidence_id_ok`가 있다. `blob_hash_ok`는 blob이 비어 있지 않고 SHA-256이 일치해야 참이다. anchor마다 `imprint_ok: false, chain_verified: false, error: "anchor verification not implemented"`를 넣고(WP-08 전까지), `has_anchors`를 둔다.
- 성능: 5만 행 JSON(6.0 MB) `build_evidence(n=64)` release 128~139 ms(Apple M4, rustc 1.99.1).

### check (`core/src/check.rs`)
shape-v1 §7. `SuspectKind {Json, Csv, Text}`, `detect_suspect_kind`, `MatchResult`, `PerIndex`, `match_rows`(비밀 없음), `check`, `CHECK_REPORT_SCHEMA`. 정규식 crate 없이 수동 스캐너.
- `detect_suspect_kind`: BOM을 뗀 바이트가 JSON 값이면 Json. 아니면 첫 비공백 문자가 `<`이면 Text(HTML). 아니면 UTF-8이고 RFC 4180으로 나눈 레코드의 셀 수가 모두 같고 2 이상이면 Csv. 그 외 Text.
- 값 비교(§7.1): canary `Str`은 문자열 규칙(`normalize_text` 동일, 의심 숫자도 텍스트로 비교). 그 Str이 `normalize_number`로 파싱되면(CSV evidence의 숫자 열) 숫자 규칙도 함께 적용하고 하나라도 성립하면 발견이다. canary `Num`은 숫자 규칙: 의심 값을 `normalize_text` 후 `normalize_number`로 파싱해 `|x − v| < 0.5·10^-s`(s = canary 텍스트의 소수 자릿수)를 i128 정수 연산으로 판정한다(36자리 초과는 비교 안 함). `Missing`/`Null`/OPAQUE marker 값은 찾지 않는다.
- 레코드(§7.2, 행 배열 경계): 원소 중 object나 배열이 하나라도 있는 배열이 "행 배열"이다. 행 배열의 object/배열 원소 각각이 독립 레코드이고 scalar 원소는 무시한다. 레코드의 값은 그 레코드에서 object 멤버와 scalar 배열을 따라 닿는 scalar leaf(키 무시, string, number, bool의 텍스트. null 제외)이고 행 배열 안으로는 들어가지 않는다. 최상위 object는 그 자체가 레코드(감싸는 object면 메타데이터 값만), 최상위 배열은 행 배열 규칙을 따른다. 그래서 `{"data":[...]}`처럼 감싸도 서로 다른 행의 값이 한 레코드로 합쳐지지 않고, 행 안의 중첩 object, 배열인 행(`[[...],[...]]`), `{"row":{...}}`로 한 번 더 감싼 행은 한 레코드로 잡힌다. CSV는 관대한 RFC 4180 분할(빈 줄 건너뜀)로 레코드마다 셀 전부, 첫 레코드(헤더)도 레코드다. Json/Csv로 넘겼는데 파싱이 안 되면 텍스트로 찾는다.
- 일치(§7.3): marker 중 threshold(= min(2, 개수))개 이상이 한 레코드에서 발견되면 matched, 최대 발견 수가 1 이상이면 partial. `record_hint`는 일치한 레코드 중 leaf 수가 가장 적은 것(동률이면 문서 순서상 앞), partial이면 발견 수 최대 → leaf 최소 → 문서 순서. 형식은 JSON `$[12]`, `$.data[3]`, `$["키"]`, CSV `record N`(0부터), 텍스트 `text offset N`(정규화된 텍스트의 문자 위치).
- 텍스트/HTML(§7.4): HTML 판정은 첫 비공백 문자 `<` 또는 `<html`/`<body`/`<table` 포함(ASCII 대소문자 무시). `<script>`, `<style>` 내용과 주석을 지우고, 태그는 공백 하나로 바꾼다(인접 셀이 붙지 않게). 그다음 entity(`&amp; &lt; &gt; &quot; &apos; &nbsp;`(U+00A0), `&#N;`, `&#xH;`)를 디코드하고, 줄바꿈(CR, LF, FF)은 공백으로 바꾼 뒤 전체를 `normalize_text`한다. 비HTML 텍스트는 바로 `normalize_text`. marker 패턴은 문자열이면 정규화형이다. 숫자(Num, 또는 숫자로 파싱되는 Str)면 생성 텍스트, 후행 0 제거형, 그리고 둘의 천단위 콤마형(`1200.00`, `1200`, `1,200.00`, `1,200`)이다. 모든 패턴은 앞뒤 문자가 Unicode 영숫자가 아니어야 한다(`P-2170` 안의 `P-217`은 아님). 숫자 패턴은 추가로 숫자가 따라붙은 `.`/`,`도 없어야 한다(`1330.5`, `1,330.5`, `330.55` 안의 `330.5`는 아님). threshold개의 서로 다른 marker 시작 위치가 512자 이내(차이 ≤ 512)이면 matched.
- `check(suspect, k_d, ev)`: canary_kind가 `record.shape.v1`이 아니면 BadEvidence. blob을 열고(`open_blob`), rows 수 == 서명된 `canary_count`이고 재계산한 Merkle root == `canary_root`이면 `commit_ok`. commit_ok가 false면 대조하지 않는다(matched 0, partial 0, absent = canary_count). report 키 순서는 §7.5(`schema, evidence_id, suspect_sha256, suspect_kind, total, matched, partial, absent, matched_indices, partial_indices, per_index, evidence{signature_ok, evidence_id_ok, blob_hash_ok, anchors}, commit_ok`)이고 `per_index`는 matched와 partial만 담는다.
- 성능: 5만 행 사본 check(n = 32) release JSON 5.7 MB 약 94 ms, CSV 2.4 MB 약 74 ms, HTML 10.5 MB 약 143 ms(Apple M4, rustc 1.99.1).

### disclose (`core/src/disclose.rs`)
disclosure-v1. `SuspectMeta`, `disclose`, `verify_disclosure`, `DISCLOSURE_SCHEMA`, `DISCLOSURE_REPORT_SCHEMA`.
- `disclose`(§3, K_d 필요): created_claim은 evidence와 같은 형식 검사(BadInput), canary_kind 검사, evidence가 `verify_evidence`를 통과해야 한다(BadEvidence). blob이 열리고 commit해야 한다(BadBlob). indices가 None이나 빈 배열이면 matched 전부, 그래도 비면 BadDisclosure. 명시 indices는 정렬하고 중복·범위 밖은 BadInput, matched가 아닌 index는 `force` 없이는 BadDisclosure. 출력 키는 `schema, created_claim, evidence(수정 없이 통째로, blob 포함), suspect{sha256, kind, 있는 *_claim만}, disclosed[{index, row, path}], shape(blob의 shape summary)`. row는 canon_row 바이트를 그대로 JSON으로 읽은 것(키 정렬), path는 RFC 9162 audit path hex(leaf→root). `operator_note`는 쓰지 않는다.
- `verify_disclosure`(§4, 비밀 없음, blob은 `verify_evidence`의 해시만): 구조 문제(JSON 아님, schema, evidence 파싱 실패, canary_kind, suspect.sha256 없음, disclosed 항목 형식, index가 오름차순·중복 없음이 아님, path가 hex64 배열이 아님)는 BadDisclosure 에러. 그 밖의 실패는 report에 담는다. 항목마다 `merkle_ok` = 서명된 `canary_count`로 `verify_audit_path` 통과(index ≥ count면 실패) 그리고 marker 필드가 모두 있음(Missing/Null 아님). 대조는 공개된 row만으로 `match_rows`(종류는 사본 바이트에서 다시 감지). report 키 순서는 `schema, evidence{signature_ok, evidence_id_ok, blob_hash_ok, evidence_id, anchors(AnchorCheck 그대로)}, suspect_hash_ok, disclosed[{index, merkle_ok, matched, found}], summary{disclosed, merkle_ok, matched, not_reproduced}, verdict{integrity_ok, all_reproduced}, statement`. `integrity_ok` = signature_ok && evidence_id_ok && blob_hash_ok && suspect_hash_ok && disclosed 수 ≥ 1 && merkle_ok 수 == disclosed 수(statement 첫 줄 `무결성:`과 항상 같은 판정), `all_reproduced` = not_reproduced == 0(disclosure-v1 §4. CLI 종료 코드는 둘 다 true면 0, 아니면 1, 구조 `Err`는 2).
- statement(한국어, 줄 단위): `무결성: PASS|FAIL (이유)`(evidence 검증, 사본 해시, Merkle 전부, 공개 0개 아님), 서명과 공개키 지문(SHA-256(vk) 앞 16 hex), evidence_id, 시점(검증된 TSA anchor가 없으면 "이 증거는 생성 시점을 증명하지 않는다". WP-08 전까지 anchor는 항상 미검증), 사본 해시, Merkle 수, "공개된 canary N개 중 M개가 사본에서 재현되었다", `NOT REPRODUCED: index ...`, shape가 있고 모든 marker에 `space_log2_x100`이 있으면 확률 줄(shape-v1 §6.1): `X = (가장 작은 t개 space_log2 합) − log2 C(m,t)`(m = marker 수, t = threshold), 사본 레코드 수 R(JSON/CSV 경로에서 추출한 레코드 수, CSV는 헤더 포함)과 canary n(서명된 canary_count)으로 기대 수 `n·R·2^-X`. 텍스트 경로면 R 불명이라 기대 수는 쓰지 않는다. 생성기 모델 상한이라는 문장과 shape가 운영자 제공이라 미검증이라는 문장이 붙는다. 마지막 줄은 `*_claim`이 미검증이라는 문장. 동결 vector json evidence에서 X = 13.25, R = 10, n = 4.

### 대조 한계
- 구조 경로는 "행 = 행 배열의 원소"를 전제한다. 한 행의 값을 서로 다른 object 배열에 나눠 넣은 변환(EAV)은 구조 경로로 못 잡는다(shape-v1 §8 한계 6). 텍스트 경로 fallback은 없다(v2).
- 측정: 데이터셋 A와 같은 생성기로 만든 독립 데이터(seed 2~5, 우리 canary 없음)는 평평한 배열이든 `{"data":[...]}`로 감싸든 matched 0이고 partial 수가 같다(14, 13, 15, 18). partial의 대부분은 id(L1-D3 공간) 우연 일치다.

### 동결 vector (`core/tests/vectors.rs`, `tests/vectors/norea-evidence-v1.json`)
입력은 WP-03 스펙 "동결 vector 입력"이다(K = 0x11×32, seed = 0x22×32, dataset_id `vector/records/v1`, created_claim `2026-11-08T00:00:00Z`, n = 4, 6행 JSON 한 줄과 끝 LF 없음, CSV 7레코드 모두 LF). 케이스 json과 csv마다 `input_utf8, k_d_hex, k_blob_hex, markers, canaries, marked_utf8, canary_root, blob_hex, payload_utf8, evidence_id, anchor_subject_hex, vk_sha256, evidence`를 고정한다. 테스트는 K_d와 K_blob을 hkdf로 따로 계산해 대조하고, 고정된 evidence가 단독으로 검증되는지 확인한다(서명, id, blob 해시, 11행 payload, blob 복호화 rows == canaries, Merkle root). 자동 marker는 두 포맷 모두 `["addr","id","area_m2"]`. `SIG_CTX`를 1바이트 바꾸면 이 테스트가 실패한다(WP-03 2차에서 확인). 재생성은 `NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test vectors`이고 포맷 변경 승인 후에만 한다.

### zeroize 상태
켠 feature는 `ml-dsa/zeroize`, `sha2/zeroize`(HMAC/HKDF의 ipad/opad 상태가 들어 있는 Sha256VarCore를 drop 시 지운다), `hmac/zeroize`(digest/zeroize, block buffer), `chacha20poly1305/zeroize`(cipher key)다. 남은 것: hmac 0.13 `new_from_slice`가 스택에 만드는 key^ipad/opad 블록은 지워지지 않는다(crate 내부, feature로 해결 안 됨). `derive_dataset_key`의 반환값은 호출자가 지운다.

### 한계 (측정됨, WP-02 보고서 4차)
- 보호 NUMERIC은 값 사이의 빈 정수만 만든다(값 밀도는 따르지만 값 자체의 구조는 모른다). 코드성 정수의 자릿수 구조는 모른다(inspect `NUMERIC_CODE_LIKE`). 측정: 공개 CSV 법정동코드 n = 1000 KS 0.022~0.028(q95 0.044), A' log-uniform 면적 KS 0.024(q95 0.043).
- 필드 간 상관(예: 법정동코드와 시도명)은 학습하지 않는다. 한 필드 안의 어휘 조합은 anchor로 보존된다(데이터셋 A 시↔동 불일치 0/1000).
- 날짜 같은 의미 제약을 모른다(`2003-02-31`이 나올 수 있다).
- unique 자유 텍스트(OPAQUE)는 실제 값을 복사한다(inspect 경고).

### 테스트 도구
- `core/tests/shape_vectors.rs` + `tests/vectors/shape-v1.json`: draw 값과 canary canonical 행 vector(동결 아님). `NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test shape_vectors`로 재생성.
- `core/tests/check_disclose.rs`: WP-04 수락 기준 1~16. 데이터셋 A n = 32의 변형 사본 8종, marker 삭제, 무관한 데이터, 잘못된 K_d, 변조, 텍스트 window와 경계, disclose, verify_disclosure 변조 케이스와 verdict, 비밀 없는 verifier, 5만 행 시간, 감싼 독립 데이터, 행 모양 3종, CSV evidence, `&nbsp;`, 동결 vector evidence로 matched 4와 확률 줄. `-- --nocapture`로 측정치와 예시 JSON을 출력한다.
- `core/tests/common/mod.rs`: 테스트용 PRNG와 데이터셋 A 생성기. distinguishability.rs와 check_disclose.rs가 같이 쓴다.
- `core/tests/distinguishability.rs`: §9 r2.2 판정(n = 1000, 자동 marker)과 n = 64 보고.
  - 지표: 직접 구현한 로지스틱 회귀 5-fold AUC, 필드별 ablation, KS bootstrap, Monte Carlo χ², §5.3 기준 충돌, NUMERIC decile 비율, 시↔동 불일치.
  - 결측률은 K = 10 키 평균을 실제 n·K 행 bootstrap 95% 구간과 비교한다(`missing_rate_judgement`). 키별 90% band는 보고만 한다.
  - 기본 테스트 `dataset_a_n1000`은 키 1 판정과 결측률 판정을 한다.
  - `full_report`(키 2~3 판정, n = 64와 A' 보고)와 `public_csv`(`NOREA_PUBLIC_CSV=경로 [NOREA_PUBLIC_CSV_SHA256=hex]`, 키 1~3 판정과 결측률 판정)는 `-- --ignored`로 돌린다.

### 검증 상태
`cargo test -p noreacore`(lib 68 + check_disclose 15 + shape_vectors 1 + distinguishability 1, ignored 2. vectors 1), `cargo clippy -p noreacore --all-targets -- -D warnings`, wasm32 release build, getrandom 0(`cargo tree -p norea-web --target wasm32-unknown-unknown`), `cargo deny check`, `./scripts/test.sh`(ALL CHECKS PASSED)가 통과한다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-01.md`, `WP-02.md`, `WP-03.md`, `WP-04.md`.

## 불변 조건 (바꾸려면 ADR + 희진 승인)

1. `norea.evidence.v1` 필드, signing payload 바이트, `SIG_CTX = "norea/evidence/v1"`, Merkle 구조, blob AEAD. 2026-11-09 WP-03 수락으로 **Frozen**. 동결 vector `tests/vectors/norea-evidence-v1.json`이 감시한다. vector 테스트가 깨지면 고치지 말고 멈춰서 보고한다(ADR-0008).
2. `noreacore`는 RNG, 네트워크, 파일 I/O, 키 저장, 시계에 의존하지 않는다. 브라우저 wasm 의존성 트리에 getrandom 0개(ADR-0005).
3. 입력 파일을 절대 수정하지 않는다. 항상 새 파일.
4. 하드웨어 정직성: `hardwareDuringSigning`을 사실대로(ADR-0006).
5. 로컬 시계는 시점 증거가 아니다(ADR-0004).
6. canary 생성기는 kind별로 고정. 기존 kind 로직을 바꾸지 말고 새 kind를 추가(ADR-0002).
7. UI는 `platform.js` 계약만 부른다(protocol/platform-contract.md).
8. 비밀은 WASM 경계를 한 번만 넘고 양쪽에서 0으로 덮는다(ADR-0012).
9. canary 후보, exclusions, 원본 데이터를 어떤 서버에도 보내지 않는다. anchor는 32바이트 subject 해시만.
10. 실제 존재하는 값(주소, 지번)을 canary로 쓰지 않는다.
