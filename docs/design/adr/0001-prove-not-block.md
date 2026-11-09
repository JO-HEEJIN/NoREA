# ADR-0001. 막지 않고 증명한다

Status: Accepted 2026-11-08. ProvGuard ADR-001을 승계한다.

## Context
REA(reverse-engineering agent)류 도구는 코드를 바이트로 복사하지 않고 동작을 관찰해 코드를 새로 생성한다. 코드 레이어 워터마크, 난독화, 주석 문자열은 재생성 과정에서 사라진다. IP 차단, 봇 탐지, rate 기반 블랙리스트는 지는 군비경쟁이고 실고객 false positive, SEO, 접근성 손상을 부른다. "AI가 모르는 비밀 규칙"은 security through obscurity다.

## Decision
복제를 막지 않는다. 복제가 일어났을 때 **제3자가 독립적으로 검증할 수 있는 증거**를 만든다. 공개 알고리즘 + 비밀 키(Kerckhoffs). 제품 이름 NoREA는 "REA를 무력화한다"가 아니라 "REA로 베껴도 증명이 남는다"는 뜻으로 쓴다.

## Consequences
- 제품 품질 = 증거 품질. 저작권, 부정경쟁방지법 제2조 제1호 (파)목, DMCA 같은 절차에서 쓸 수 있는 형태여야 한다. 법적 판단은 변호사·변리사 확인이 필요하다(제품이 법률 자문을 하지 않는다).
- 구현하지 않는 것: 제3자 사이트 크롤링(운영자 watchlist 제외), 봇 차단, fingerprinting, 난독화.
- 증거의 세 축이 모두 있어야 한다: 무엇을(canary commit), 누가(ML-DSA 서명), 언제(외부 anchor). 셋 중 하나라도 빠지면 UI와 verifier가 그 사실을 말한다.
