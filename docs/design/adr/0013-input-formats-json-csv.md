# ADR-0013. 입력은 JSON 배열과 CSV. JSON은 재직렬화, CSV는 바이트 보존 splice

Status: Accepted 2026-11-08. 희진 승인(Phase 1에 CSV 포함).

## Context
공공·기업 데이터의 다수가 CSV다. ProvGuard는 JSON만 받았고, 출력은 키를 정렬한 compact JSON이라 운영자의 파일 모양이 바뀌었다.

## Decision
- JSON(`format=json`): 입력은 object 배열. 출력은 **재직렬화**한다. 키 순서는 첫 행의 키 순서(이후 새 키는 등장 순), 들여쓰기는 입력에서 감지(없음 / 공백 n / 탭; 첫 중첩 줄 기준, 감지 실패 시 compact), 숫자는 `arbitrary_precision`으로 원문 보존. canary 행도 같은 규칙으로 직렬화되므로 모양으로 구분되지 않는다. 원본 행의 바이트 보존은 목표가 아니다.
- CSV(`format=csv`): RFC 4180으로 레코드 경계(바이트 오프셋)를 찾고 canary 레코드를 **그 사이에 끼워 넣는다**. 원본 레코드는 바이트 그대로. canary 셀은 `,` `"` CR LF나 앞뒤 공백을 포함할 때만 따옴표로 감싼다. 줄바꿈은 파일의 지배적 줄바꿈을 따른다. 헤더 필수.
- 자동 감지: JSON 파싱 성공 → json, 아니면 csv. UI는 감지 결과를 보여주고 바꿀 수 있게 한다.
- Excel(.xlsx), Parquet, SQL dump는 v1 범위 밖. 운영자가 CSV/JSON으로 내보낸다.

## Alternatives rejected
- JSON도 splice로 바이트 보존: canary 행이 이웃 행의 들여쓰기·키 순서를 흉내 내야 하는데 행마다 다를 수 있어 오히려 튄다. 전체 재직렬화가 균일성을 보장한다.
- 키 정렬 canonical JSON 출력(ProvGuard): 사람이 보기에 부자연스럽고 운영자 파일을 바꾼다.

## Consequences
- JSON 운영자는 "출력 파일의 형식이 바뀔 수 있다(의미는 같다)"는 안내를 받는다.
- CSV에서 `arbitrary_precision`은 무관하다(모두 문자열).
- `serde_json`의 `arbitrary_precision` feature가 workspace 전체에 켜진다. Tauri workspace에 합칠 때 feature unification 영향을 WP-00이 확인한다.
