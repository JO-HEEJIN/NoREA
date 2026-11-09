# ADR-0006. 플랫폼별 키 보관과 하드웨어 정직성

Status: Accepted 2026-11-08 (web), 나머지 플랫폼은 설계만. ProvGuard ADR-006을 승계한다.

## Context
현재 보급된 Windows TPM은 ML-DSA를 하지 못한다(PQ TPM 실리콘은 2026-11 샘플링 단계, 이전 세션 확인). Apple Secure Enclave는 iOS/macOS 26부터 ML-DSA 키를 하드웨어 안에서 만들고 내보내지 않는다. 웹은 서명하는 동안 시드가 페이지 메모리에 있다.

## Decision

| 플랫폼 | 서명 | 키 보관 | 서명 순간 키가 하드웨어 안에 있나 |
|---|---|---|---|
| Web | WASM SoftwareSigner | WebAuthn PRF로 감싼 시드(IndexedDB). PRF 없으면 Argon2id(64 MiB, t=3) passphrase | 아니오 |
| macOS/iOS 26+ | Secure Enclave MLDSA65 → `finalize_evidence` | SE, export 불가 | 예 |
| macOS/iOS 25 이하 | SoftwareSigner | Keychain + SE P-256 래핑 | 아니오 |
| Windows 11 | SoftwareSigner(native) | TPM 기반 키로 봉인한 시드 + Windows Hello | 아니오 |
| Android | SoftwareSigner(native) | Keystore/StrongBox AES 래핑 + BiometricPrompt | 아니오 |

- `capabilities().hardwareDuringSigning`과 `keyInfo().hardwareDuringSigning`은 이 표를 그대로 반환한다. "키가 하드웨어를 떠나지 않는다"는 문장은 macOS/iOS 26+에서만 쓴다.
- 백업은 암호화 blob만 내보낸다(docs/protocol/custody-web-v1.md).
- 웹의 passphrase는 JS string이라 0으로 덮을 수 없다. 이 한계를 문서에 남긴다.

## Consequences
- 웹의 최대 위협은 같은 origin의 XSS다. 외부 스크립트 0, 엄격한 CSP, 정적 호스팅(ADR-0009).
- 고보증 고객에게는 데스크톱 앱(Phase 2)을 권한다.
- K를 잃으면 기존 evidence의 canary를 복원(check/disclose)할 수 없다. 복구 경로(이중 백업)를 custody 스펙 §5에 둔다.
