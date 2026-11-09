# ADR-0014. WASM 바인딩은 해제되는 heap을 전부 0으로 덮고, 비밀 호출 뒤 stack을 덮는다

Status: Accepted 2026-11-09. ADR-0012를 보완한다(대체하지 않는다).

## Context
ADR-0012는 비밀을 소유 `Vec<u8>`로 받아 `zeroize`하고 JS가 `fill(0)`하면 "쓰고 난 뒤" 비밀이 남지 않는다고 봤다. WP-06의 메모리 스캔(node, `wasm.memory.buffer` 전체를 32 B와 16 B window로 검색)이 그 가정이 부족함을 보였다.

- `check` 뒤 K_d의 끝 20 B가 shadow stack에 남았다. `derive_dataset_key`가 by-value `[u8; 32]`를 돌려주고 그것이 `Zeroizing`으로 옮겨질 때 생긴 임시값이다. 32 B 전체 검색은 통과했고 16 B window에서만 잡혔다.
- `passphraseKek` 뒤 Argon2id 출력 S가 heap 1곳, stack 2곳에 남았다. heap 쪽은 wasm-bindgen glue가 `Vec<u8>` 반환값을 JS로 복사한 뒤 0으로 덮지 않고 free한 버퍼다. S와 IndexedDB의 `ct`가 있으면 K와 seed가 복호화된다.
- core의 SHA-256, HMAC, ML-DSA 내부 상태는 `Zeroizing`이 닿지 않는 stack 지역 변수다.

`zeroize`를 변수 단위로 더 붙이는 방법은 glue가 만든 사본과 컴파일러가 만든 임시값에 닿지 않는다. 측정값과 자세한 과정은 `tasks/reports/WP-06.md` "메모리 스캔".

## Decision
`norea-web`(wasm32 전용, core와 의존성 무변경)에 두 가지를 둔다.

1. **Zero-on-free global allocator.** `dealloc`이 블록 전체를 0으로 덮은 뒤 `System`에 돌려준다. `realloc`은 `GlobalAlloc` 기본 구현(alloc, copy, dealloc)을 써서 Vec이 커질 때 버려지는 옛 블록도 덮인다. 내용이 비밀인지 구분하지 않는다.
2. **Stack scrub.** 비밀을 받는 바인딩 5개(`protect`, `check`, `disclose`, `verifyingKey`, `passphraseKek`)는 본문을 `#[inline(never)]` frame에서 돌린 뒤 512 KiB 지역 배열을 0으로 덮는다(`black_box`로 제거를 막는다). 측정한 최대 stack 사용은 약 348 KiB(ML-DSA 서명)이고 shadow stack은 1 MiB다.

검증은 테스트가 한다: `tests/smoke.node.cjs`가 호출 뒤 K, seed, K_d, K_blob, S의 32 B와 16 B window 적중 0건, stack 영역의 0 아닌 바이트 < 1024를 확인한다. scrub이 없는 `sha256Hex`에 넘긴 32 B가 검색되는 positive control이 스캐너 자체를 검증한다.

기각한 대안:
- 변수 단위 `zeroize`만 유지: glue 사본과 임시값을 못 덮는다(측정으로 반증).
- 비밀을 받는 함수만 별도 allocator arena 사용: 비밀이 흘러가는 모든 할당을 추적해야 해서 누락이 생긴다. 전부 덮는 쪽이 단순하고 측정 가능하다.
- `argon2`의 `zeroize` feature: 출력 사본 하나만 덮는다. allocator가 같은 일을 하므로 뺐다.

## Consequences
- 5만 행 protect/check가 약 0~15% 느려진다(433→437~508 ms, 371→400~409 ms). 예산(1.5 s / 1 s) 안이다.
- 보장이 아니라 측정이다. 한계: JS 쪽(WebCrypto 내부, V8 GC 사본, JIT)은 보지 않는다. 정확한 바이트열만 찾으므로 byte-swap된 SHA-256 word나 ML-DSA 확장키 같은 변형은 검색하지 않는다(대신 allocator와 scrub이 내용과 무관하게 덮는다). 호출 중에는 비밀이 메모리에 있다(ADR-0006). leak된 메모리는 덮이지 않는다.
- scrub 크기 512 KiB는 상수다. stack 사용이 깊어지면 smoke의 stack 잔여량 검사가 깨진다. 그때 상수를 올리고 이 ADR에 기록한다.
- 컴파일러가 scrub을 제거하면 positive control과 잔여량 검사가 깨진다. 이 테스트들은 CI에서 항상 돈다.
- Tauri(Rust 네이티브)에서는 비밀이 JS로 오지 않으므로 이 ADR은 web 바인딩에만 적용된다.
