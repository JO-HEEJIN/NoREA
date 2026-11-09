# ADR-0011. 제3자 검증은 비밀 없이, 공개한 canary만으로

Status: Accepted 2026-11-08. 희진 승인.

## Context
ProvGuard의 `check_copy`는 K_d를 요구했다. 운영자만 대조할 수 있었고 법원 감정인이나 상대방은 운영자의 말을 믿어야 했다. 증거의 가치는 독립 검증 가능성에서 나온다(ADR-0001).

## Decision
- 분쟁 제출물은 disclosure package(docs/protocol/disclosure-v1.md)다: evidence 전체 + 의심 사본 해시 + 공개할 canary row와 Merkle path.
- `norea-verify` CLI(Rust, 오프라인)와 웹 UI의 "검증" 탭이 비밀 없이 (1) 서명, (2) evidence_id, (3) blob 해시, (4) anchor imprint, (5) Merkle path, (6) 사본에서의 일치 재현을 수행하고 사람이 읽는 statement를 낸다.
- verifier는 검증하지 못한 것을 검증했다고 말하지 않는다: TSA 체인(`chain_verified: false`), 사본 포착 시점(`*_claim`), 실제 세계에서의 우연 확률(모델 기준 상한만).
- 운영자는 일치한 canary만 공개한다. 일치하지 않은 canary 공개는 기본 거부(force 옵션 + 경고).

## Consequences
- CLI 배포물(macOS/Linux/Windows 바이너리)과 그 재현 가능 빌드가 Phase 1 산출물에 들어간다(WP-05, WP-10).
- 전문가 리포트 PDF(Phase 4)는 verifier 리포트 위에 해설을 얹는 것이지 새 검증 로직이 아니다.
