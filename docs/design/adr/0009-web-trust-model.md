# ADR-0009. 웹 버전의 신뢰 모델

Status: Accepted 2026-11-08. ProvGuard ADR-009를 승계한다.

## Context
웹앱은 접속할 때마다 받는 JS/WASM을 믿어야 한다. 호스팅이 변조되면 키가 위험하다.

## Decision
- 외부 스크립트, CDN, 폰트 0개. 모든 리소스 same-origin.
- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' <anchor relay origin>; style-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`. `frame-ancestors`는 헤더(`_headers`)로만 가능하다. relay origin은 anchor를 켠 빌드에서만 추가한다.
- 빌드마다 wasm 해시(`BUILD_SHA256`)를 공개하고 재현 가능 빌드를 문서화한다. 사용자가 받은 wasm 해시를 UI에서 볼 수 있게 한다.
- 키 생성 직후 암호화 백업 다운로드를 강제하고 `navigator.storage.persist()`를 요청한다. Safari의 저장소 정리 조건은 WP-09에서 실측한다.
- Subresource Integrity는 same-origin 모듈에는 의미가 적어 쓰지 않는다. 대신 해시 공개.

## Consequences
- 분석, 광고, 폰트, 프레임워크 CDN을 넣을 수 없다. 의도된 제약이다.
- 호스팅 제공자(Cloudflare)는 여전히 신뢰 대상이다. 고보증 고객은 데스크톱 앱.
