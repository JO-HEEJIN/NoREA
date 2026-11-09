# ADR-0003. 서명은 ML-DSA-65, FIPS 204 context `norea/evidence/v1`

Status: Accepted 2026-11-08. ProvGuard ADR-003을 승계하고 context 문자열만 바꾼다.

## Context
증거는 수년에서 수십 년 검증 가능해야 한다. NIST IR 8547은 양자 취약 공개키 알고리즘을 2030 이후 deprecated, 2035 이후 disallowed로 정했다(이전 세션 2026-11-08 확인, 이 세션에서 재확인하지 않음. docs/SOURCES.md). Apple(iOS/macOS 26 Secure Enclave MLDSA), Windows CNG, RustCrypto 모두 FIPS 204 context를 지원한다.

## Decision
- ML-DSA-65(security category 3), pure ML-DSA.
- `SIG_CTX = "norea/evidence/v1"`. 같은 키로 만든 서명이 다른 프로토콜에서 재사용되는 것을 막는다.
- Software signer는 deterministic. Hardware signer의 hedged 서명도 허용(검증 동일).
- 구현 RustCrypto `ml-dsa`, 버전 고정(`=`). 감사된 릴리스가 나오면 한 줄 교체, 동결 vector가 호환을 확인.

## Alternatives rejected
- RSA/ECDSA: 수명이 긴 증거에 부적합.
- `pqcrypto-dilithium`: Round 3 Dilithium이지 FIPS 204가 아니고 C 코드라 wasm 빌드가 어렵다.
- ML-DSA-87: 크기 대비 이득 없음. SE가 65를 지원하므로 65로 통일.

## Consequences
- 서명 3309 B, 공개키 1952 B. evidence 파일이 수 KB다. 문제 없음.
- `ml-dsa`는 1.0 이전, 미감사. Risk로 기록하고 CI에서 `cargo audit`을 돈다.
- 측정치(ProvGuard 세션): WASM sign 3.0 ms, verify 0.66 ms. 병목 아님. NoREA 구현 후 재측정한다.
