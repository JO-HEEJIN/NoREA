# ADR-0004. 시점은 외부 anchor로만 증명하고, anchor는 서명까지 묶는다

Status: Accepted 2026-11-08. ProvGuard ADR-004(Proposed)를 개정해 Accepted로 올린다.

## Context
`created_claim`은 운영자 시계의 주장이다. 그 위에 서명해도 "언제"는 증명되지 않는다. ProvGuard는 anchor를 Phase 1 뒤로 미뤘고 대상도 `content_sha256`이었다. content 해시만 anchor하면, 같은 marked 파일에 대해 나중에 다른 키로 다시 서명한 evidence가 그 anchor를 가져다 쓸 수 있다.

## Decision
- anchor 대상 `anchor_subject = SHA-256(payload || 0x0A || sig)`. 서명까지 고정한다.
- 1차 RFC 3161 TSA, 2차 OpenTimestamps. 둘 다 `anchors[]`에 넣고, 서명 payload 밖에 둔다(추가·갱신 가능).
- anchor는 Phase 1 범위다(WP-08). anchor 없는 evidence는 UI와 verifier가 "시점 미증명"을 표시한다.
- 브라우저에서 TSA를 직접 부르면 CORS에 막힐 가능성이 높다(미검증). WP-08은 먼저 실험하고, 안 되면 Cloudflare Worker relay를 둔다. relay에는 32바이트 subject만 간다.
- TSA 인증서 체인 검증은 v1 verifier가 하지 않는다. 토큰을 내보내고 `openssl ts -verify`를 안내한다. 정직하게 `chain_verified: false`로 표시한다.
- RFC 4998식 갱신: RSA로 서명된 TSA 토큰은 2030 전에 새 anchor를 추가한다(Phase 4).

## Consequences
- anchor 과정에서 기기 밖으로 나가는 것은 subject 해시뿐이다. canary, 데이터, 키는 안 나간다.
- relay가 생기면 CSP `connect-src`에 relay origin이 추가된다. 그 외 네트워크는 여전히 0.
- relay 운영 비용과 가용성이 생긴다. 실패해도 protect는 성공하고 anchor만 나중에 다시 할 수 있어야 한다.
