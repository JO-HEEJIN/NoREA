# NoREA 구현 repo: 현재 상태 (STATE)

이 파일은 항상 현재 시제다. 계획은 `tasks/todo.md`, 설계(규범)는 `/Users/mac/dev/derator/Fable_5_1/`(protocol/, CORE-API.md, adr/).

## 무엇인가

NoREA는 운영자가 자기 소유의 공개 데이터에 canary를 심고, ML-DSA-65로 서명하고 외부 시점 anchor로 고정한 증거를 남겨, 운영자가 직접 가져온 의심 사본에서 canary를 대조해 복제를 증명하는 방어 제품이다. ProvGuard에서 재설계했고 호환성은 없다(ADR-0010).

## 지금 동작하는 것

Phase 1 구현 중. 로직이 있는 모듈은 `error`, `table`(WP-01)이다. 나머지 모듈(shape, canary, merkle, blob, sign, evidence, check, disclose, anchor)은 문서 주석만 있는 빈 파일이다.

- 뼈대(WP-00): workspace `core`(noreacore), `web`(norea-web), `cli`(norea-cli). web/src는 export가 없다. CLI 두 바이너리(norea-verify, norea)는 `--help`만 하고 다른 호출은 exit 2.
- `web/public/`의 JS/HTML은 이전 제품에서 이름만 바꿔 복사한 것이라 아직 새 API와 맞지 않는다(WP-06/07이 재작성). `tests/smoke.node.cjs`, `tests/platform.node.mjs`도 같다. 그래서 `scripts/test.sh`에서 2단계 node e2e와 3단계 플랫폼 계약은 꺼져 있다.
- toolchain은 `rust-toolchain.toml`(1.99.1 + wasm32-unknown-unknown)로 고정, node는 22. clippy component가 설치되어 있다.

### error (`core/src/error.rs`)
`noreacore::Error { code: ErrorCode, message: String }`, `ErrorCode` 8개(BadInput, NoMarker, CanaryExhausted, BadEvidence, BadSignature, BadBlob, BadDisclosure, BadAnchor). crate root에서 re-export한다. 메시지는 영어이고 입력 값, 비밀, 경로를 담지 않는다(serde_json 에러 문구는 값을 인용할 수 있어 그대로 넘기지 않고 line/column만 쓴다).

### table (`core/src/table.rs`)
`Format`, `detect_format`, `Cell`, `Row`(IndexMap), `Table`, `parse_table`, `serialize_with_inserts`, `canon_row`, `row_from_json`. 시그니처는 CORE-API §1 그대로. 입력 바이트를 바꾸지 않고 항상 새 버퍼를 돌려준다. shape 로직은 없다.

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

### 검증 상태
`cargo test -p noreacore`(15 tests), `cargo clippy -p noreacore -- -D warnings`, wasm32 release build, getrandom 0(`cargo tree -p norea-web --target wasm32-unknown-unknown`), `cargo deny check`, `./scripts/test.sh`(ALL CHECKS PASSED)가 통과한다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-01.md`.

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
