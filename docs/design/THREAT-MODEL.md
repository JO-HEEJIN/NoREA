# NoREA Threat Model

현재 시제. 설계가 무엇을 막고 무엇을 못 막는지 적는다. 손은 코드를 쓸 때 이 문서의 공격자를 테스트 케이스로 옮긴다.

## 1. 자산

| 자산 | 기밀성 | 무결성 | 가용성 |
|---|---|---|---|
| K (master) | 최고. 유출되면 모든 데이터셋의 canary가 드러남 | | 분실하면 기존 evidence의 canary 복원 불가 |
| seed / 서명키 | 최고. 유출되면 증거 위조 가능(단, anchor 이전 시점으로의 위조는 anchor가 막음) | | 분실해도 기존 evidence 검증은 가능 |
| canary 값 | 높음. 알려지면 다음 사본에서 제거됨 | | |
| evidence.json | 중간(blob 암호화됨) | 최고. 변조는 서명이 잡음 | 분실하면 그 발행본 증명 불가. 백업 안내 |
| marked 파일 | 공개 | 운영자가 공개한 바이트가 `marked_sha256`과 같아야 "이 파일" 주장 가능 | |
| exclusions(registry) | 낮음 | | |

## 2. 공격자와 대응

### A. 복제자 (REA 에이전트 운영자)
목표: 데이터를 가져가되 증명을 피한다.
- A1 **그대로 복사**: canary 따라감. 대조 성공.
- A2 **재직렬화**(키 이름 변경, 순서, 중첩, 숫자↔문자열, CSV↔JSON, HTML 렌더): 값 기준 레코드 대조와 정규화가 잡음. 테스트 케이스 필수.
- A3 **일부 필드 삭제**: marker k-of-n(threshold 2)으로 한 필드 삭제까지 견딤. marker 전부 삭제하면 못 잡음(한계).
- A4 **통계적 필터링**으로 canary 제거: 생성기가 shape를 따르므로 단순 패턴 필터에 안 걸림. 수락 기준 AUC < 0.60. 필드 간 상관 기반 필터는 v1 한계.
- A5 **registry와 대조해 가짜 지번 제거**: 가능하다. 복제자가 그 비용을 들이면 canary 방식은 진다. 대응: canary 수를 늘리고, 일부 canary를 "registry에는 없지만 그럴듯한" 것보다 "registry에 있는 실제 값의 미세 변형"으로 만드는 kind는 **만들지 않는다**(실제 주소 사용 금지 원칙). 정직한 한계로 기록.
- A6 **데이터 전면 교체**: 못 잡음. 범위 밖.
- A7 **공개된 disclosure에서 canary를 배워 제거**: Merkle 선택 공개로 공개 범위를 최소화. 공개된 것은 소모된 것으로 간주.
- A8 **"같은 공개 출처에서 가져왔다" 주장**: `original_sha256`으로 원본에 없던 행임을 보이고, canary가 가상임을 registry 부재로 보인다. 법적 설득력은 변호사 영역.

### B. 운영자 자신(악의적 운영자가 증거를 위조하려 함) — 증거 신뢰성의 핵심
- B1 **backdating**: `created_claim`을 과거로 쓴다. 대응: anchor만 시점 증거. anchor 없는 evidence는 "시점 미증명" 표시. verifier가 TSA genTime을 쓴다.
- B2 **사후 canary 삽입** (상대방 데이터를 보고 그 값을 canary라고 주장): canary_root가 anchor 시점에 고정돼 있으므로 불가. Merkle path가 root와 맞아야 한다.
- B3 **다른 키로 재서명해 anchor 재사용**: anchor_subject가 서명을 포함하므로 불가(ADR-0004).
- B4 **blob 바꿔치기**: blob 해시가 payload 안에 있어 불가.
- B5 **사본 조작**(의심 사본에 canary를 직접 넣음): 이 제품은 사본 포착의 진정성을 증명하지 않는다. `*_claim`으로 표시하고 외부 증거(공증, 아카이브)를 권한다. 명시적 한계.

### C. 외부 공격자 (운영자 기기/호스팅 공격)
- C1 **XSS / 호스팅 변조**(web): 외부 스크립트 0, CSP, same-origin, wasm 해시 공개. 그래도 호스팅 신뢰가 필요. 고보증은 데스크톱 앱.
- C2 **기기 도난**: IndexedDB의 blob은 PRF(사용자 인증) 또는 Argon2id passphrase 없이 못 연다. passphrase 강도는 운영자 몫. UI가 최소 길이를 요구한다(WP-07: 12자 이상).
- C3 **메모리 덤프 중 서명**: Web/Windows/Android 한계(ADR-0006).
- C4 **relay 운영자**: subject 해시만 받는다. relay가 악의적이어도 가짜 토큰을 돌려줄 뿐이고 verifier가 TSA 서명(수동 체인 검증)으로 잡는다. relay가 토큰을 안 주면 가용성 문제일 뿐.
- C5 **백업 파일 탈취**: 암호화 blob. PRF 백업은 같은 passkey 없이는 무용, passphrase 백업은 passphrase 강도에 의존.
- C6 **공급망**(crates, wasm-bindgen): 버전 고정, `cargo audit`/`cargo deny`, 재현 가능 빌드, 해시 공개.

### D. 알고리즘 노화
- D1 **ML-DSA 또는 SHA-256 약화**: RFC 4998식 재anchor(Phase 4). schema v2 경로 존재.
- D2 **TSA의 RSA 서명 약화(2030)**: 토큰을 새 anchor로 덮는다(추가).

## 3. 가정

1. 운영자 기기의 OS와 브라우저는 신뢰한다.
2. 운영자는 백업 파일을 안전하게 보관한다.
3. TSA/OTS는 정직하거나, 최소한 한 곳은 정직하다(둘 다 쓰는 이유).
4. SHA-256, HKDF, HMAC, ChaCha20-Poly1305, ML-DSA-65는 설계 수명 동안 안전하다.

## 4. 테스트로 옮겨야 하는 항목

A1~A4, A6(음성), B1~B4, C5(import 검증), 그리고 ADR-0012 메모리 스캔. 각 WP 스펙의 수락 기준이 이걸 참조한다.
