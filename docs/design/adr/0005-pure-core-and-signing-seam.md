# ADR-0005. 순수 core + ports/adapters, 서명 seam

Status: Accepted 2026-11-08. ProvGuard ADR-005를 승계한다.

## Decision
- `noreacore`는 순수 함수만 가진다: 파싱, shape 추론, canary 생성·삽입, evidence prepare/finalize/verify, Merkle, blob 암복호, check, disclose, disclosure verify, TSA 요청 encode/응답 parse. RNG, 네트워크, 파일 I/O, 키 저장, 시계가 없다. 시각과 nonce는 인자로 받는다.
- 공개 함수는 바이트와 문자열(JSON)만 주고받는다. wasm-bindgen, Tauri command, UniFFI에 1:1로 매핑된다.
- 서명 seam: `prepare_evidence` → (플랫폼이 payload에 서명) → `finalize_evidence`. finalize는 서명을 검증한 뒤에만 받는다. 고장 난 adapter는 증거를 만들지 못하고 바로 실패한다.
- 시드는 플랫폼이 만들어 넘긴다(`SoftwareSigner::from_seed`). Secure Enclave처럼 시드가 없는 플랫폼은 seam만 쓴다.
- 브라우저 wasm 의존성 트리에 `getrandom`이 0개여야 한다. CI가 확인한다.

## Consequences
- core 하나를 Web, macOS, Windows, iOS, Android가 그대로 쓴다. 플랫폼마다 새로 쓰는 것은 키 보관 adapter와 바인딩뿐이다.
- 암호 라이브러리는 `default-features = false`로 넣어 RNG feature가 따라오지 않게 한다. 새 의존성은 이유를 ADR이나 WP 보고서에 적는다.
- ASN.1(RFC 3161) 인코딩이 core에 들어온다. 네트워크는 여전히 adapter다.
