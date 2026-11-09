# ADR-0010. ProvGuard 포맷 호환을 버리고 `norea.*`로 새로 시작한다

Status: Accepted 2026-11-08. 희진 승인.

## Context
ProvGuard Phase 0은 `provguard.evidence.v1`과 `SIG_CTX = "provguard/evidence/v1"`을 불변 조건으로 동결했다. 그러나 배포된 적이 없고 발급된 증거가 없다. 포맷 자체도 단일 해시 commit, parcel 전용 생성기 등 ADR-0002/0008이 고치는 결함을 갖고 있어 호환을 유지할 가치가 없다.

## Decision
- 새 namespace: schema `norea.evidence.v1`, `norea.disclosure.v1`, `norea.custody-backup.v1`; `SIG_CTX = "norea/evidence/v1"`; HKDF salt `norea/v1`; crate `noreacore`, `norea-web`, `norea-verify`.
- `provguard.evidence.v1`은 verifier가 지원하지 않는다. 구 vector 파일은 docs/LEGACY-REVIEW.md에 기록만 남기고 새 repo에 넣지 않는다.
- ProvGuard 코드는 "참고용 소스"다. 복사해 와도 되지만 이름, 포맷, 테스트를 전부 NoREA 스펙에 맞춰 바꾼다(LEGACY-REVIEW 재사용 맵).

## Consequences
- 지금이 포맷을 고칠 마지막 기회였다. WP-03 vector 동결 뒤에는 ADR-0008 정책이 적용된다.
- 다음에 또 "새로 시작"하지 않도록, 동결 전 WP-01~04에서 프로토콜 문서의 모든 열린 질문을 닫는다. 열린 질문은 설계 질문으로 올리고 설계 문서를 고친다.
