# ADR-0002. Canary는 데이터에서 형식을 배운 가상 레코드다

Status: Accepted 2026-11-08. ProvGuard ADR-002(생성기 v1 `b2d_geo.parcel.v1`)를 대체한다.

## Context
ProvGuard v1 생성기는 `하남시 미사동 {lot}-{sub}`, `P-1000..9999`를 hardcode했다. 실제 데이터의 id가 세 자리면 canary의 네 자리 id가 패턴으로 걸러진다. core가 한 데이터셋에 묶여 있어 제품이 아니라 데모였다. 또 canary 집합 전체가 단일 SHA-256으로 commit되어 하나를 증명하려면 전부 공개해야 했다.

## Decision
- 생성기 `record.shape.v1`(docs/protocol/canary-record-shape-v1.md): 입력 테이블에서 필드별 shape(문자 클래스 템플릿, 숫자 분위수 범위, 범주 빈도, 결측률)를 추론하고, HMAC(K_d) 결정론적 난수로 그 shape를 따르는 가상 레코드를 만든다. 지명 같은 어휘는 실제 데이터의 vocab에서 가져오되 빈도 1인 희귀값은 제외한다.
- 충돌 회피: marker 필드와 unique 필드의 값이 실제 값, 운영자 exclusions(공식 registry), 앞선 canary와 겹치면 재시도(64회).
- 대조는 값 기준, 레코드 단위, marker 필드 k-of-n(threshold = min(2, markers)). NFC, 공백, 전각, 천단위 콤마를 정규화한다.
- commit은 Merkle root(RFC 9162 구조)다(ADR-0008). canary 자체는 K_d로 암호화한 blob으로 evidence에 동봉해 check 때 원본 데이터가 필요 없게 한다.
- 입력 포맷은 JSON 배열과 CSV(ADR-0013).

## Alternatives rejected
- 데이터셋별 hardcode 생성기(v1): 확장 불가, 패턴으로 식별됨.
- LLM으로 canary 생성: 비결정론적, core의 "RNG·네트워크 없음" 원칙 위반, 재현 불가.
- canary를 재생성 가능하게만 두고 blob 없이 가기: check 때 원본 데이터와 shape가 필요해 Monitor 서버 설계가 복잡해진다.

## Consequences
- 필드 간 상관을 학습하지 않으므로 상관이 강한 데이터에서는 통계 검정에 걸릴 수 있다. v2 과제로 남긴다.
- canary가 실제 세계에 존재하지 않는다는 보장은 exclusions를 넘길 때만 완전하다. UI가 이를 말한다.
- 데이터를 통째로 바꾼 클론은 못 잡는다. UI 토큰 등 다른 kind가 필요하다(Phase 4).
- WP-02 수락 기준에 구분 불가능성 테스트(분류기 AUC < 0.60)를 넣었다. 통과 못 하면 생성기를 고치지 "기준을 낮추지" 않는다.
