# 설계 문서 (design)

이 디렉토리는 NoREA의 설계 패키지 사본이다. 설계 문서는 2026-11-08에 작성됐고, 구현(`core/`, `cli/`, `web/`)은 2026-11-09에 이 설계대로 만들었다.

- `ARCHITECTURE.md` 계층, 데이터 파이프라인, 신뢰 경계, 플랫폼 매트릭스, 성능 예산, 한계
- `THREAT-MODEL.md` 자산, 공격자, 대응, 테스트로 옮긴 항목
- `CORE-API.md` noreacore / norea-web / CLI 시그니처
- `SOURCES.md` 출처(재확인 여부 표시)
- `protocol/` 동결된 포맷 5개: `evidence-v1`(norea.evidence.v1), `canary-record-shape-v1`(생성기와 대조 규칙), `disclosure-v1`(분쟁 제출 패키지와 제3자 검증), `custody-web-v1`(웹 키 보관과 백업), `platform-contract`(UI와 플랫폼 계약 17개)
- `adr/` 결정 기록 14개(과거 시제, 불변)

동결 vector는 `../../tests/vectors/`에 있다. 문서의 WP 번호는 구현 작업 단위(WP-00~WP-11)를 가리킨다.
