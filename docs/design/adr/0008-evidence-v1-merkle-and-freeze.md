# ADR-0008. Evidence v1: Merkle commit, 암호화 blob, 동결 정책

Status: Accepted 2026-11-08. ProvGuard ADR-008을 대체한다.

## Context
ProvGuard의 `canary_commit`은 집합 전체의 단일 해시였다. 분쟁에서 하나를 증명하려면 전부 공개해야 하고, 공개된 canary는 상대방이 다음 사본에서 제거한다. 또 check에 원본 데이터가 필요 없게 하려면 canary를 evidence에 동봉해야 하는데 평문으로 넣을 수는 없다.

## Decision
- `canary_root` = RFC 9162 구조의 Merkle root, leaf = `SHA-256(0x00 || u32be(i) || canon(row))`. 일치한 canary만 audit path와 함께 공개한다(docs/protocol/disclosure-v1.md).
- canary 집합은 `K_blob = HKDF(K_d, marked_sha256)`로 ChaCha20-Poly1305 암호화해 `canary_blob_b64`로 동봉하고 그 해시를 서명 payload에 넣는다. K_blob이 evidence마다 유일하므로 nonce는 0 고정.
- 서명 payload는 11행 `\n` 구분 UTF-8(docs/protocol/evidence-v1.md §6). JSON canonicalization(JCS)을 payload에 쓰지 않는다. Swift/Kotlin이 문자열 연결만으로 재현할 수 있어야 하기 때문이다.
- `original_sha256`을 payload에 넣는다. "같은 공개 출처에서 가져왔다"는 반박에 대해 "원본에는 없던 행"임을 보이기 위해서다.
- `evidence_id = SHA-256(payload)`를 handle로 쓴다.
- 동결: WP-03이 `tests/vectors/norea-evidence-v1.json`을 생성하는 순간 포맷은 동결된다. 이후 변경은 `norea.evidence.v2`로만 한다. vector 테스트가 깨지면 고치지 않고 멈춰서 머리에게 보고한다.
- 포맷 변경이 아닌 것: 새 `canary_kind`, 새 anchor kind, payload 밖 새 키.

## Alternatives rejected
- 단일 해시 commit: 선택 공개 불가.
- canary 재생성에 의존(blob 없음): check 때 원본과 shape 필요, Monitor 서버가 원본을 가져야 함.
- AES-GCM blob: 동일하게 가능하지만 core에 AES 구현을 또 넣을 이유가 없고 ChaCha20-Poly1305가 wasm에서 상수 시간 구현이 쉽다. 플랫폼 custody는 WebCrypto AES-GCM을 그대로 쓴다(브라우저 네이티브).

## Consequences
- `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `ml-dsa`가 core 의존성이다. 전부 RustCrypto, `default-features = false`.
- evidence 파일 크기는 canary 수에 비례한다(행당 수백 바이트). 256개면 수십 KB. 문제 없음.
- Merkle path 검증 코드가 verifier에 들어간다. RFC 9162 §2.1.3.2를 그대로 구현하고 n=1..9 전수 테스트를 둔다.
