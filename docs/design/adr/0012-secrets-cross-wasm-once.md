# ADR-0012. 비밀은 WASM 경계를 한 번만 넘고, 양쪽에서 0으로 덮는다

Status: Accepted 2026-11-08.

## Context
ProvGuard 웹 구현은 한 번의 protect에서 K와 seed를 세 번(`deriveDatasetKey`, `markParcels`, `buildEvidence`) 경계 너머로 복사했다. wasm-bindgen은 `&[u8]` 인자를 linear memory에 복사하고 호출 뒤 free만 한다. 기본 allocator는 0으로 덮지 않으므로, JS가 `fill(0)`을 해도 wasm 메모리에 시드 사본이 남았다. 문서는 "0으로 덮어씀"이라고 적혀 있었다. 절반만 참이었다.

## Decision
- 바인딩 API는 비밀을 쓰는 작업마다 **단일 호출**이다: `protect(input, master_k, seed, dataset_id, options_json, created_claim)`, `check(suspect, master_k, evidence_json)`, `disclose(...)`. K_d, K_blob 파생은 WASM 안에서 한다.
- 비밀 인자는 `Vec<u8>`(소유)로 받고 `zeroize` crate로 사용 후 0으로 덮는다. `&[u8]`로 받지 않는다.
- JS는 호출 직후 자기 버퍼를 `fill(0)`한다. `withSecrets`가 finally에서 보장한다.
- core의 `SoftwareSigner`와 내부 키 버퍼는 `Zeroize`/`ZeroizeOnDrop`을 구현한다.
- 검증은 테스트로 한다: node에서 호출 뒤 wasm `memory.buffer`를 스캔해 시드 바이트열이 없어야 한다(WP-06 수락 기준). 완벽한 보장은 아니지만(allocator 재할당, JIT 복사) 문서의 주장과 구현을 일치시킨다.

## Consequences
- 바인딩 함수 수가 줄고 JS가 단순해진다.
- `zeroize` 의존성 추가(pure Rust, RNG 없음).
- 여전히 서명하는 순간 키는 메모리에 있다(ADR-0006). 이 ADR은 "쓰고 난 뒤"에 관한 것이다.
