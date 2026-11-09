# Canary generator `record.shape.v1`

Status: **Frozen r2.2** (2026-11-09, WP-03 수락과 함께 동결. 변경 요지는 끝의 "개정 기록"). 생성 규칙(§1~§5)과 summary(§6.1)는 고정이다. 바꾸려면 새 `canary_kind`(ADR-0002). inspect 경고 문구(§6.2), 대조 규칙(§7, WP-04에서 구현), 한계(§8)는 설명이며 동결 대상이 아니다. 규범 문서. 결정론적이어야 한다: 같은 (입력 바이트, K_d, options)이면 모든 플랫폼에서 같은 canary와 같은 marked 바이트가 나온다. 구현은 Rust `noreacore` 하나뿐이고 Swift/Kotlin은 재구현하지 않는다. 그래도 명세를 정확히 쓰는 이유는 (a) 테스트 vector를 설명하고, (b) 법정 감정인이 "canary가 어떻게 만들어졌는가"를 읽을 수 있어야 하기 때문이다.

목표: 운영자의 실제 레코드와 통계적으로 구분되지 않는 가상 레코드를 만든다. canary는 **실제 세계에 존재하지 않는 레코드**여야 한다(trap street). 생성기는 실제 데이터에서 형식과 분포를 배우고 값은 새로 만든다.

## 1. 입력 모델: Table

```
Table  = { fields: [FieldName], rows: [Row] }
Row    = ordered map FieldName -> Cell
Cell   = Str(text) | Num(text, scale) | Bool | Null | Missing | Opaque(json)
```

### 1.1 JSON (`format=json`)
- 입력은 UTF-8 JSON 배열이어야 하고 모든 원소가 object여야 한다. 아니면 거부. BOM은 제거하고 `original_sha256`은 BOM 포함 원본 바이트로 계산한다.
- `fields` = 첫 행의 키 순서, 그 뒤 처음 나타나는 순서로 새 키 추가.
- 셀: JSON string → Str; number → Num(원문 텍스트, scale = 소수점 아래 자릿수). 지수 표기가 있으면 parse 단계에서 Opaque; true/false → Bool; null → Null; 키 없음 → Missing; object/array → Opaque.
- 숫자 원문 보존을 위해 serde_json `arbitrary_precision`(지수부는 `e`, `+` 정규화됨. evidence-v1 §7.1)과 `preserve_order`를 켠다.

### 1.2 CSV (`format=csv`)
- RFC 4180. 구분자 `,`, 따옴표 `"`, 레코드 구분 CRLF 또는 LF(파일에서 다수인 것을 "지배적 줄바꿈"으로 기록). 첫 레코드는 헤더(필수). BOM 제거.
- 모든 셀은 Str. 빈 셀은 Str("")이며 **shape 추론과 결측률(§3.5)에서는 결측으로 센다**. 열 수가 헤더와 다른 레코드, 헤더 이름 중복, 닫히지 않은 따옴표, non-UTF-8은 거부(운영자에게 알림).
- 추론 단계에서 `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`에 맞는 Str은 NUMERIC 후보로 본다(§3). 선행 0("007")은 매치 안 되므로 STRING으로 남아 자릿수 템플릿으로 보존된다.

## 2. 출력: canary row

canary row는 `fields` 전부를 키로 가지는 JSON object다. 실제 행에 Missing인 필드가 있어도 canary는 필드별 결측 확률(§3.5)에 따라 Missing을 흉내 낸다. CSV는 모든 값이 string.

## 3. Shape 추론 (필드별)

m = 비결측 셀 수, d = 비결측 셀의 distinct 수(Str은 바이트 동일성, Num은 원문 텍스트 동일성).

결측률 `missing_ppm = round_half_up((Missing + Null 수) · 10^6 / 전체 행 수)`. 정수 연산 `(missing·2·10^6 + rows) / (2·rows)`.

kind 결정(순서대로 첫 매치):
1. 비결측 셀이 모두 Bool → `BOOL`
2. 비결측 셀이 모두 Num, 또는 csv에서 모두 NUMERIC 정규식 매치 → `NUMERIC`
3. 비결측 셀이 모두 Str → `STRING`
4. 그 외(Opaque 포함, 혼합) → `OPAQUE`
5. m == 0 → `EMPTY` (canary도 Missing)

그 다음 `NUMERIC`/`STRING`에 대해:
- `d ≤ max(2, floor(0.05·m))` 이고 `d ≤ 64` → `CATEGORICAL`로 재분류
- `unique = (d == m && m ≥ 2)` (데이터 속성. summary와 inspect에 보고한다)

**보호 필드** = marker 필드, 또는 최종 kind가 STRING/NUMERIC이고 unique인 필드. 보호 필드의 canary 값은 실제 값과 겹치면 안 된다(§5.3). 그 외는 비보호 필드다.

### 3.1 NUMERIC
- `scale` = 관측된 최대 소수 자릿수(상한 8. 넘는 자릿수는 추론 때 잘린다). `fixed_scale` = 모든 값의 소수 자릿수가 같으면 true.
- 모든 비결측 값을 정수 `v·10^scale`로 변환한다(i128. 넘치면 그 필드는 OPAQUE). **중복을 포함해** 정렬한 정수열 `V[0..m)`, `min = V[0]`, `max = V[m−1]`. (r2.2: distinct가 아니라 전체. 반복 값이 많은 구간이 행 밀도만큼 가중되게 하기 위해서다. 중복 사이 구간은 `w = 0`이라 아래 이동 규칙으로 다음 구간에 가중을 넘긴다.)
- `G` = `(max − min + 1) − d_int` (min과 max 사이의 빈 정수 개수). `d_int` = **정수로 변환한 뒤의** distinct 수(텍스트 distinct `d`와 다를 수 있다: 소수 9자리 이상이 scale 8에서 잘리면 다른 텍스트가 같은 정수가 된다. WP-02 4차에서 underflow로 발견). §4.1 조건과 summary의 `distinct`는 텍스트 `d`를 쓴다.
- **비보호 NUMERIC**: canary 값 = 실제 비결측 셀 하나를 복사(§3.4와 같은 방식, draw 1회). 텍스트 그대로.
- **보호 NUMERIC (gap sampling)**: draw 1회로 `r`(u64). `k0 = (r >> 32) mod (m − 1)`. 구간 `(V[k], V[k+1])`의 내부 정수 개수 `w_k = V[k+1] − V[k] − 1`(중복이면 음수가 아니라 0으로 본다. 같은 값이므로 `V[k+1] − V[k] = 0` → `w_k = 0`). `k = k0`에서 시작해 `w_k == 0`이면 `k = (k + 1) mod (m − 1)`로 옮기며 첫 `w_k > 0`을 찾는다(한 바퀴 돌아 없으면, 즉 `G == 0`이면 후보 기각 → 결국 `CanaryExhausted`). `N = V[k] + 1 + ((r & 0xFFFF_FFFF) mod w_k)`.
  왜 기각 대신 이동인가: 연속 코드처럼 빈 구간이 없는 영역이 많은 데이터에서 기각하면 canary가 값 밀도가 아니라 "빈 구간이 있는 위치"의 밀도를 따라가 분포가 틀어진다(WP-02 2차: 법정동코드 구간의 66.7%가 w=0, decile KS 0.133 → 이동 규칙으로 0.001). 이동은 구간 인덱스 분포를 보존한다.
  텍스트: `fixed_scale`이면 소수 `scale`자리 고정(예: `512.00`). 아니면 후행 0 제거(`512.5`, `512`). 음수는 `-` 접두. 후행 0을 제거한 결과의 소수 자릿수 `s`가 §5.3 숫자 충돌 판정의 기준이다.
- `space_log2_x100 = round(100 · log2(max(1, G)))`.
- 한계(의도됨): 자릿수 구조가 있는 코드성 정수(예: 행정구역 코드의 끝자리 00)는 gap sampling이 구조를 모른다. WP-02 측정에서 ablation AUC가 남는 원인이다. v2 과제(§8.3).

### 3.2 STRING: 템플릿과 anchor
각 문자열을 run으로 토큰화한다. 문자 클래스:
- `D` = `0-9`
- `H` = 한글 음절 U+AC00..U+D7A3
- `L` = `A-Za-z`
- 그 외 각 문자는 literal 토큰 1개(공백, `-`, `(`, 한자, 가나, 이모지 등)

템플릿 키 = 토큰 열. 같은 클래스 run은 길이를 포함한다(`D3`, `H2`). 예: `하남시 미사동 592-1` → `H3 ␠ H3 ␠ D3 - D1`.

템플릿별로:
- `count(t)` = 템플릿 t인 실제 비결측 셀 수. `values(t)` = 그 셀들의 값(행 순서, 중복 포함).
- D 슬롯 j: 정수값들의 `min_j`, `max_j`. 한 템플릿 안에서 run 길이 L이 같으므로 생성값은 항상 L자리 이하이고, 짧으면 좌측 0-padding(clamp 불필요. WP-02 확인).
- **anchor 목록** `anchors(t)`: `values(t)` 중, 모든 H/L 슬롯 값이 그 (템플릿, 슬롯) 안에서 빈도 ≥ 2인 것(행 순서, 중복 포함). 비면 `values(t)` 전체. 희귀 어휘가 canary에 재사용되는 것을 막는다.

생성(§5.2 순서): 템플릿 t를 `count` 비례로 draw → anchor `a ∈ anchors(t)`를 draw(`mod len`, 목록이 빈도를 반영하므로 균등) → H/L 슬롯은 `a`의 값을 **그대로 복사**(한 필드 안의 어휘 조합, 예: 시↔동 관계가 보존된다) → D 슬롯마다 `min_j + uniform(max_j − min_j + 1)`을 좌측 0-padding → literal 그대로.

D 슬롯이 없는 템플릿은 anchor 복사와 같다(실제 값). 그런 필드는 비보호로만 쓸 수 있다(§4.1이 자동 marker에서 뺀다).

`space(t) = (서로 다른 H/L 슬롯 값 조합 수 in anchors(t)) · Π_D (max_j − min_j + 1)`, `space = Σ_t space(t)`, `space_log2_x100 = round(100 · log2(max(1, space)))`.

퇴화 케이스: 템플릿 수가 m과 같다(모든 값의 모양이 다 다름, 자유 텍스트). 이때 STRING 필드는 `OPAQUE`로 재분류한다. 그 필드가 marker로 지정됐으면 에러 `NoMarker: field X has no reusable shape; choose other marker fields`.

### 3.3 CATEGORICAL / BOOL
값 어휘와 빈도. 생성은 빈도 비례 샘플(§5.1 샘플 규칙). `space_log2_x100 = round(100·log2(d))`.

### 3.4 OPAQUE
실제 비결측 셀 중 하나를 복사한다: 비결측 셀을 행 순서로 늘어놓고 `draw mod m`번째(빈도 비례와 같다). 원문 그대로(숫자는 `Number::to_string()` 텍스트). marker로 쓸 수 없다. unique인 OPAQUE(자유 텍스트)는 복사 때문에 "같은 텍스트가 두 번 나오는 행"이 canary 표시가 될 수 있다. inspect가 경고 `UNIQUE_OPAQUE_COPIED`를 낸다(§6.2). `space_log2_x100`은 없다(키 생략).

### 3.5 결측
각 canary 필드는 먼저 draw 1회로 `uniform(10^6) < missing_ppm`이면 결측. JSON: 결측 셀 중 Null이 과반이면 Null, 아니면 키 생략(Missing). CSV: `Str("")`. EMPTY 필드는 draw 없이 결측. marker 필드가 결측으로 뽑히면 후보 기각(§5.3).

## 4. Marker 필드

대조에 쓰는 필드. evidence `marker_fields`에 서명된다.

### 4.1 자동 선택
후보 = 다음을 모두 만족하는 필드:
1. 최종 kind ∈ {STRING, NUMERIC}
2. `missing_ppm < 200_000`
3. **빈 공간 조건**: NUMERIC이면 `G ≥ d`, STRING이면 `space ≥ 2·d`. (생성 가능한 값의 절반 이상이 실제 값이 아니어야 한다. 한 단어 지명, 촘촘한 일련번호가 여기서 빠진다. WP-02 측정)

정렬 키: (d 내림차순, STRING이 NUMERIC보다 먼저, 필드명 UTF-8 바이트 오름차순). 앞에서 `min(3, 후보 수)`개. 후보가 0개면 에러 `NoMarker`(메시지에 조건 1~3 중 무엇에 걸렸는지 필드별로. 값은 넣지 않는다).

### 4.2 운영자 지정
`options.marker_fields` 1~4개. 각각 존재하는 필드이고 최종 kind가 STRING 또는 NUMERIC이어야 한다(아니면 `NoMarker`). 없는 필드, 중복, 0개, 5개 이상은 `BadInput`. 빈 공간 조건은 요구하지 않는다(운영자 책임. inspect가 `LOW_FREE_SPACE` 경고).

### 4.3 대조 임계값
`threshold = min(2, len(marker_fields))`. marker 중 `threshold`개 이상이 한 레코드 안에서 일치하면 "일치". 1개만 일치(threshold가 2일 때)는 "부분 일치"로 따로 보고한다. 이 규칙은 kind `record.shape.v1`에 고정이다.

## 5. 결정론적 난수와 생성 절차

### 5.1 Stream
```
draw(K_d, label, i, attempt, ctr) = u64be( HMAC-SHA256(K_d, lp(utf8(label)) || lp(u32be(i)) || lp([attempt]) || lp(u32be(ctr)))[0..8] )
uniform(n) = draw(...) mod n            (n ≤ 2^32이므로 편향은 2^-32 이하. 허용)
```
한 canary 후보 (i, attempt) 안에서 `ctr`은 0부터 시작해 draw마다 1 증가한다. draw 순서는 §5.2에 고정된 순서를 따른다. label은 값 생성에 `"canary"`, 위치에 `"pos"`.

**빈도 비례 샘플 규칙**: 항목을 **첫 등장 순서(행 순서)**로 늘어놓고 각 항목의 빈도를 누적한 뒤 `draw mod 합계`가 속하는 항목을 고른다. HashMap 순회 순서에 의존하지 않는다.

### 5.2 후보 생성 순서
canary i, attempt a에 대해, `fields` 순서대로 각 필드 f:
1. 결측 판정 draw 1회 (EMPTY 필드는 draw 없이 Missing)
2. 결측이 아니면 kind별:
   - NUMERIC: draw 1회 (비보호: 복사 인덱스. 보호: gap sampling의 r)
   - STRING: 템플릿 선택 draw 1회 → anchor 선택 draw 1회 → D 슬롯 순서대로 슬롯마다 draw 1회(H/L/literal은 없음)
   - CATEGORICAL/BOOL/OPAQUE: draw 1회

### 5.3 충돌 회피
보호 필드 f마다 후보값을 검사한다. 다음 중 하나면 기각하고 attempt+1로 재시도(최대 64, 초과하면 에러 `CanaryExhausted: canary i: no acceptable candidate`. 메시지 뒤에 가장 많이 기각을 일으킨 보호 필드 이름을 ` (field f)`로 덧붙일 수 있다. 값은 넣지 않는다):
- f가 marker인데 결측으로 뽑힘
- f가 STRING: `normalize_text(후보)`가 `taken_text(f)`에 있음. `taken_text(f)` = f의 모든 실제 비결측 값의 `normalize_text` ∪ (f가 marker면) `exclusions`의 `normalize_text` ∪ 앞서 확정된 canary들의 f 값의 `normalize_text`
- f가 NUMERIC: 후보 `c`(텍스트의 소수 자릿수 s)에 대해, f의 실제 값 또는 (marker면) `normalize_number`로 파싱되는 `exclusions` 또는 앞선 canary의 f 값 중 `|x − c| < 0.5 · 10^-s`인 `x`가 있음. (§7.1 대조 규칙과 같은 기준. 텍스트 비교가 아니다. WP-02 제안 1)
- 보호 NUMERIC에서 빈 구간이 하나도 없음(`G == 0`, §3.1)

unique 조건은 **최종 kind가 STRING 또는 NUMERIC인 필드에만** 적용한다. OPAQUE/CATEGORICAL/BOOL로 (재)분류된 필드는 unique여도 충돌 검사를 하지 않는다(복사가 유일한 생성 방법이므로).

`exclusions`는 운영자가 넘기는 문자열 집합(예: 공식 지번 registry). 모든 marker 필드에 공통 적용한다. 어떤 서버에도 보내지 않는다.

### 5.4 삽입 위치
확정된 canary i는 현재 행 배열(실제 L행 + 앞선 canary i개) 안의 `pos_i = draw(K_d, "pos", i, 0, 0) mod (L + i + 1)` 위치에 삽입한다. i = 0..n−1 순서.

## 6. Shape summary와 inspect

### 6.1 Shape summary (blob에 들어가는 정보용 JSON)
blob은 해시가 서명 payload에 들어가므로 **바이트 결정론**이 필요하다. 그래서 부동소수점을 쓰지 않는다. 모든 수는 정수. 키 순서는 아래 순서, 필드는 테이블 순서, compact 직렬화.

```json
{"kind":"record.shape.v1","rows":50000,
 "fields":{"<f>":{"kind":"STRING","unique":true,"distinct":49870,"missing_ppm":0,"space_log2_x100":1840}},
 "markers":["addr","area_m2"],"threshold":2}
```
`space_log2_x100`은 OPAQUE/EMPTY에서 키 생략. log2는 정수 입력에 대해 IEEE 기본 연산만으로 계산하고(libm 금지) 소수 2자리로 반올림해 100배 정수로 저장한다.

검증에는 쓰지 않는다. 전문가 리포트에서 "우연 일치 확률 상한"을 설명하는 데 쓴다. 일치 판정은 marker m개 중 t개(`threshold`)이므로 상한은 **가장 약한 t개** 기준이어야 한다(WP-04 2차 개정. 이전 문장 "모든 marker의 곱"은 판정 기준과 맞지 않아 과소 추정이었다):

`X = (marker들의 space_log2 중 작은 것 t개의 합) − log2 C(m, t)` (space_log2 = `space_log2_x100 / 100`). 한 canary가 독립적으로 만들어진 **레코드 하나**와 판정 기준상 우연히 일치할 모델 상 확률은 `2^-X` 이하다(union bound: 크기 t인 부분집합마다 `Π 2^-space_log2` 이하, 부분집합 수 `C(m, t)`). 사본 레코드 R개, canary n개에 대한 우연 일치 기대 수는 `n · R · 2^-X` 이하다. 이것은 생성기 모델 기준의 상한이지 실제 세계 확률이 아니다. 리포트는 X, m, t, R, n과 이 한계 문구를 모두 써야 한다(disclosure-v1 §4).

### 6.2 inspect warnings (platform-contract `InspectResult`)
`warnings: [{code, field?}]`. 코드:
- `OPAQUE_FIELD`: 모양이 제각각이라 canary에 실제 값이 복사된다
- `UNIQUE_OPAQUE_COPIED`: 위에 더해 unique라서 중복 텍스트로 canary가 식별될 수 있다. 필드 제외 권고
- `LOW_FREE_SPACE`: 생성 가능한 값의 절반 이상이 실제 값이라 marker로 부적합(§4.1 조건 3)
- `NO_FREE_SPACE`: 보호 필드(unique STRING/NUMERIC)의 빈 공간이 0(NUMERIC `G == 0`, STRING `space ≤ d`). 연번 같은 dense key. protect가 `CanaryExhausted`로 실패할 가능성이 매우 높다(NUMERIC은 확실). 같은 필드에 `LOW_FREE_SPACE`는 내지 않는다
- `HIGH_MISSING`: 결측률 20% 이상이라 marker 후보에서 제외
- `NO_MARKER_CANDIDATE`: 자동 후보 0개
- `NUMERIC_CODE_LIKE`: 보호 NUMERIC이 정수이고 unique이고 자릿수가 모두 같음(코드성 숫자 의심, §3.1 한계)
UI(WP-07)가 코드를 한국어 문장으로 바꾼다.

## 7. 대조 규칙 (check)

### 7.1 정규화
- 문자열(`normalize_text`): Unicode NFC → 양끝 공백 제거(Unicode White_Space) → 내부 공백 run(U+0009, U+0020, U+00A0, U+3000)을 U+0020 하나로 → 전각 ASCII(U+FF01..FF5E)를 반각으로. 대소문자는 유지한다.
- 숫자(`normalize_number`): 문자열이면 `,`(천단위), 공백 제거, 선행 `+` 허용, 정수부 선행 0 제거, `-0`→`0`, 소수부 자릿수 유지 후 10진 파싱. canary 값 v(텍스트 소수 자릿수 s)와 의심 값 x는 `|x − v| < 0.5 × 10^-s`이면 같다.
- canary marker 값이 Str이고 의심 값이 숫자면 숫자의 텍스트를 문자열 규칙으로 비교한다. 반대(canary Num, 의심 Str)는 숫자 규칙.
- canary marker 값이 Str인데 `normalize_number`가 성공하면(CSV에서 온 evidence의 숫자 열) 문자열 규칙과 숫자 규칙을 둘 다 적용하고 하나라도 성립하면 발견이다. §7.4의 숫자 경계도 같은 값에 적용한다. (WP-04 2차, 2026-11-09)
- 의심 값이 문자열이면 숫자 규칙 전에 `normalize_text`(NFC, 전각→반각)를 거친다.

### 7.2 레코드 추출
- 종류 감지(`detect_suspect_kind`): 바이트가 JSON 값으로 파싱되면 `json`. 아니고 첫 비공백 문자가 `<`이거나 `<html`/`<body`/`<table`을 포함하면 `text`(HTML). 아니고 셀 수가 같은 2열 이상 레코드로 읽히면 `csv`. 그 외 `text`. json/csv로 감지됐는데 파싱이 안 되면 텍스트 경로로 떨어진다.
- JSON 의심본 (WP-04 2차, 2026-11-09 개정. 이전 규칙 "모든 object의 subtree 전체"는 감싸는 object가 여러 행의 값을 한 레코드로 합쳐 무관한 데이터에서 거짓 일치를 냈다. WP-04 측정: 독립 데이터 4종을 `{"data":[...]}`로 감싸면 canary 128개 중 8개가 matched):
  - **행 배열**: 원소 중 하나라도 object 또는 배열인 배열. 행 배열의 object 원소와 배열 원소는 각각 **독립 레코드**이고 그 안에 같은 규칙을 재귀 적용한다. 행 배열의 scalar 원소는 무시한다.
  - **레코드의 값** = 그 레코드(object 또는 배열 원소)에서 object 멤버와 scalar 배열(원소가 모두 scalar인 배열)을 따라 닿는 모든 scalar leaf. 행 배열 안으로는 들어가지 않는다. 키는 무시한다.
  - 최상위 object도 레코드다(감싸는 object는 행 배열을 제외한 메타데이터 값만 가진다). 최상위가 배열이면 행 배열 규칙을 적용한다.
  - leaf 변환: 숫자는 텍스트, bool은 `true`/`false`, null은 뺀다. 36자리를 넘는 숫자는 문자열 규칙만.
  - 알려진 우회: 한 행의 값을 서로 다른 object 배열에 나눠 넣는 변환(EAV)은 구조 경로로 잡지 못한다(§8 한계 6).
- CSV 의심본: 각 레코드의 셀 전부(헤더 유무 무관, 첫 행도 레코드로 취급). 관대한 RFC 4180 분할, 빈 줄 건너뜀, 열 수가 달라도 레코드다.
- 그 외(HTML, 텍스트): §7.4.

### 7.3 일치
canary c, 레코드 r: marker 필드 f마다 r의 값 중 c[f]와 같은 것이 있으면 f를 "발견". 발견 수 ≥ threshold → c는 r에서 일치. canary마다 일치한 레코드가 하나라도 있으면 `matched`, 아니면 발견 수 최대가 1 이상이면 `partial`, 아니면 `absent`.

`commit_ok`가 false이면(K_d가 틀렸거나 evidence 변조) 대조하지 않는다: matched 0, partial 0, absent = canary_count.

`record_hint`(리포트용): matched면 일치한 레코드 중 scalar leaf 수가 가장 적은 것, 동률이면 문서 순서상 앞. partial이면 발견 수 최대 → leaf 수 최소 → 문서 순서. `found`는 그 레코드에서 발견된 marker들(marker 순서). 형식: JSON `$`, `$[12]`, `$.data[3]`(키가 ASCII 영숫자·`_`가 아니면 `$["키"]`), CSV `record N`(0부터), 텍스트 `text offset N`(정규화된 텍스트의 문자 위치).

### 7.4 비구조 텍스트
HTML이면 `<script>`, `<style>` 내용과 주석을 제거하고, 태그는 공백 하나로 바꾼다(지우면 `<td>12</td><td>34</td>`가 `1234`가 된다). CR, LF, FF를 공백으로 바꾼다. entity 디코드: named `&amp; &lt; &gt; &quot; &apos; &#39; &nbsp;`(→ U+00A0, 정규화에서 공백이 된다) + numeric `&#NNN;`, `&#xHH;`. 전체를 §7.1 문자열 정규화. canary의 각 marker 값(문자열 정규화형; 숫자는 생성 텍스트 그대로, 후행 0 제거형, 그리고 두 형태의 천단위 콤마형 `1,200.00`, `1,200`까지 최대 4개 패턴. 정규화가 콤마를 지우지 않으므로 패턴 쪽에서 맞춘다)을 부분 문자열로 찾는다. 발견된 marker들 중 어떤 `threshold`개의 시작 위치 차이가 512자(Unicode scalar) 이내이면 일치.

경계: 모든 marker 매치는 앞뒤 문자가 Unicode 영숫자(letter 또는 digit)가 아니어야 한다(`P-217`이 `P-2170` 안에서 매치되지 않는다). 숫자 marker(Num, 또는 `normalize_number`가 성공하는 Str)는 추가로 앞뒤의 `.`나 `,` 뒤에 숫자가 이어지면 경계가 아니다(`1,330.5`와 `0.330.5` 안의 `330.5`는 매치되지 않는다).

### 7.5 리포트
```json
{ "schema": "norea.check-report.v1", "evidence_id": "...", "suspect_sha256": "...", "suspect_kind": "json|csv|text",
  "total": 32, "matched": 29, "partial": 1, "absent": 2,
  "matched_indices": [0,1,...], "partial_indices": [7],
  "per_index": { "0": { "found": ["addr","area_m2"], "record_hint": "items[12]" } },
  "evidence": { "signature_ok": true, "evidence_id_ok": true, "blob_hash_ok": true, "anchors": [...] },
  "commit_ok": true }
```
`commit_ok` = blob을 복호화해 재계산한 Merkle root == `canary_root`. false면 K_d가 틀렸거나 evidence가 변조됐다.

## 8. 의도된 한계

1. 데이터를 통째로 바꾼 클론은 못 잡는다.
2. 생성기는 형식과 분포를 흉내 내지 값의 의미를 모른다. 존재하지 않는 지번을 만들 확률이 높지만 보장은 `exclusions`(공식 registry)를 넘길 때만 된다. 날짜 템플릿(`D4-D2-D2`)은 존재하지 않는 날짜를 만들 수 있다. UI는 이걸 말해야 한다.
3. **필드 간** 상관은 학습하지 않는다(한 필드 안의 어휘 조합은 anchor로 보존된다). 예: `addr`의 시와 별도 `시도명` 열의 관계. 상관이 강한 데이터에서는 통계 검정으로 걸러질 수 있다. v2 과제. 코드성 정수의 자릿수 구조(§3.1)도 v2.
4. unique 자유 텍스트(OPAQUE)는 실제 값을 복사하므로 중복으로 식별될 수 있다. 경고로 알린다.
5. 보호 필드에 빈 공간이 없으면(연번 `1..N`, 꽉 찬 코드처럼 unique이면서 값 사이에 빈 정수가 없거나 템플릿 공간이 전부 실제 값인 필드) canary를 만들 수 없다. 새 행은 그 필드에 실제 값과 다른 값을 가져야 하는데 그런 값이 없기 때문이다. 범위 밖 값이나 중복 값으로 채우면 그 필드 하나로 canary가 식별되므로 v1은 만들지 않고 `CanaryExhausted`를 낸다. inspect가 `NO_FREE_SPACE`로 미리 알린다. 운영자 선택지는 그 필드를 뺀 발행본을 만드는 것뿐이다. WP-03 동결 vector 입력에서 발견(2026-11-09).
6. 대조의 구조 경로(§7.2)는 "행 = object 배열의 원소"를 전제한다. 한 행의 값을 서로 다른 object 배열에 나눠 넣는 변환(EAV, `[{"k":"addr","v":...},{"k":"id","v":...}]`)은 구조 경로로 잡지 못한다. 텍스트 경로(§7.4)는 512자 안에 있으면 잡는다. 구조 경로에서 absent인 canary를 텍스트 경로로 다시 찾는 fallback은 v2 과제(WP-04 2차, 2026-11-09).

## 9. 수락 기준 (WP-02)

측정은 두 표본 크기에서 한다. **판정(assert)은 n = 1000**에서 한다(n = 64는 이항 잡음과 AUC 표준오차 약 0.06 때문에 검정력이 없다. n = 64 결과는 보고만 한다). 데이터셋은 WP-02 스펙의 합성 A와 공개 CSV 1개, 둘 다 **자동 marker**로.

- 결정론: 같은 입력으로 두 번 돌리면 바이트 동일.
- 충돌 0: 모든 보호 필드에서 §5.3 기준(문자열 정규화형, 숫자는 `|x−c| < 0.5·10^-s`) 충돌이 없다.
- 구분 불가능성(n = 1000):
  - 분류기(필드별 템플릿/값/decile one-hot, class-balanced L2 로지스틱 회귀, 5-fold stratified) held-out AUC < 0.60.
  - 결측률(다중 검정을 피하기 위해 키를 묶어 판정한다): `K = 10`개의 서로 다른 K_d로 n개씩 생성한 canary의 **필드별 평균 결측률**이, 실제에서 `n·K`개를 복원 추출한 bootstrap(1000회) 결측률의 2.5~97.5% 구간 안. 키별·필드별 90% band 결과는 보고만 한다(필드 4개 × 키 3개면 편향 없는 생성기도 약 34% 확률로 어딘가 걸린다. WP-02 3차).
  - STRING/CATEGORICAL: 템플릿(값) 분포 χ² Monte Carlo p > 0.05 이거나 canary 템플릿 ⊆ 실제 상위 95% 템플릿 집합. "unseen template" 0.
  - 비보호 NUMERIC: KS < bootstrap q95.
  - 보호 NUMERIC: KS와 ablation AUC를 보고(assert 없음. §3.1 한계). 단 ablation AUC가 0.75를 넘으면 `NUMERIC_CODE_LIKE` 경고가 그 필드에 났는지 확인.
- 대조(WP-04): 키 이름 변경, 순서 변경, 중첩, 숫자↔문자열, NFD 변환, 전각 변환, 천단위 콤마, HTML 표 렌더링을 거친 사본에서 n개 전부 `matched`.
- 무관한 데이터에서 `matched = 0`.

---

## 개정 기록

- r1 (2026-11-08): 초안.
- r2.2 대조 규칙 개정 (2026-11-09, WP-04 1차 측정 후. §7은 동결 대상이 아니다): §7.2 JSON 레코드를 "행 배열" 경계로(감싸는 object의 거짓 일치 6.25% 제거), 종류 감지 규칙, leaf 변환, CSV 관대 분할 명시. §7.1 Str 숫자 marker에 숫자 규칙 병행. §7.3 commit_ok false 처리, record_hint 규칙. §7.4 HTML 처리(태그→공백, 줄바꿈→공백, `&apos; &nbsp;`), 모든 marker에 영숫자 경계, 숫자 marker에 `.`/`,` 경계. §6.1 확률 상한을 가장 약한 t개 기준 + `C(m,t)` + 기대 수로. §8 한계 6(EAV). 근거: `tasks/reports/WP-04.md`.
- r2.2 문서 보완 (2026-11-09, WP-03 중. 생성 규칙과 vector는 바뀌지 않음): §5.3 에러 메시지에 필드 이름 덧붙이기 허용. §6.2에 `NO_FREE_SPACE` 추가. §8에 한계 5(빈 공간 없는 보호 필드). 근거: `tasks/reports/WP-03.md` QUESTION 1.
- r2.2 (2026-11-09, WP-02 3차 측정 후): §3.1 gap sampling의 정렬열을 distinct `V[0..d)`에서 중복 포함 `V[0..m)`으로(행 밀도 가중). §9 결측률 판정을 키 10개 평균 + bootstrap 95% 구간으로(다중 검정 회피).
- r2.1 (2026-11-09, WP-02 2차 측정 후): §3.1 gap sampling에서 `w=0` 구간을 기각하지 않고 다음 비어 있지 않은 구간으로 이동(wrap). §5.3의 해당 기각 조건을 `G == 0`으로.
- r2 (2026-11-09, WP-02 측정 후): §3.1 NUMERIC을 [p5,p95] 균등에서 "비보호 복사 + 보호 gap sampling"으로. §3.2에 anchor(H/L 슬롯 값을 실제 값 하나에서 통째로 복사. 시↔동 불일치 61% 해결) 도입, 빈도 1 어휘 제외를 anchor 필터로 대체, D 슬롯 clamp 문장 삭제. §4.1 자동 marker에 빈 공간 조건. §5.2 draw 순서에 anchor draw 추가. §5.3 숫자 충돌을 값 기준(`|x−c| < 0.5·10^-s`)으로, unique 적용 범위를 최종 kind STRING/NUMERIC으로 한정. §6 summary를 정수만으로(`missing_ppm`, `space_log2_x100`), inspect 경고 코드화. §9 판정을 n = 1000, bootstrap band로. 근거: `tasks/reports/WP-02.md`.
