# todo

## WP-00 Review

희진이 "WP-00 시작해"(바로 해)로 승인해 계획 확인 없이 진행했다. 1차에서는 Rust toolchain이 없어 막혔다. 희진이 선택지 A(설치)를 승인했고, 2차에서 rustc 1.99.1, wasm32 target, wasm-bindgen-cli 0.2.130, cargo-deny, cargo-audit, binaryen, node@22를 설치한 뒤 수락 기준을 다시 돌렸다.

결과: workspace build, wasm release build, getrandom 0, `cargo deny check`, `cargo audit`, `./scripts/test.sh` ALL CHECKS PASSED, 이전 이름 grep이 모두 통과했다.

2차에서 추가한 것:
- `rust-toolchain.toml`
- `build-web.sh`의 sha256 대체 명령
- arbitrary_precision 실험의 지수 케이스

WP-01이 알아야 할 것:
- JSON 숫자의 지수부는 serde_json이 정규화한다(`E`→`e`, 양수 지수에 `+` 추가).
- rustup이 `~/.zshenv`와 `~/.profile`을 만들었다. 유지할지 지울지 희진이 정한다.

보고서: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-00.md`(1차와 재실행 2차).

## WP-01 Review

희진이 "WP-01 시작해"(HANDS-PROTOCOL §1.4 "바로 해")로 승인해 계획 확인 단계 없이 진행했다. 체크리스트 12개 항목 모두 완료. `core/src/error.rs`(Error/ErrorCode), `core/src/table.rs`(JSON 파싱·스타일 재현 직렬화, RFC 4180 직접 구현 CSV 파싱·splice, canon_row, row_from_json, 테스트 13개)를 구현했고, `core/src/lib.rs`에 re-export를 추가했으며 `core/Cargo.toml`에서 `csv` crate를 뺐다. 새 의존성은 없다. 검증(실제 실행): `cargo test -p noreacore` 14 passed, clippy `-D warnings` 통과, wasm32 release build 성공, getrandom 0, `cargo deny check` ok, `./scripts/test.sh` ALL CHECKS PASSED, 5만 행 3.69 MB JSON parse+serialize release 약 31 ms(Apple M4). 스펙과 다르게 한 것 4개(보고서에 이유), QUESTION 없음. 상태는 `CONTEXT.md`, 상세는 `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-01.md`.

WP-01 2차(후속): `unicode-normalization` 주석은 고쳤다. serde_json `preserve_order`를 켜면 Zlib 라이선스 crate `foldhash` 0.2.0이 들어와 `cargo deny check`가 실패한다. 그래서 되돌렸고, deny.toml에 Zlib을 허용할지 묻는 QUESTION을 보고서에 올렸다. 지금 트리는 green이다.
WP-01 3차: 머리가 Zlib 허용을 결정했다. deny.toml에 Zlib을 추가했고 preserve_order 관련 네 가지를 재적용했다. 15 tests 통과, `cargo deny check`의 licenses ok, ALL CHECKS PASSED.

## WP-02 Review

희진이 "WP-02 시작해"(HANDS-PROTOCOL §1.4 "바로 해")로 승인해 계획 확인 단계 없이 진행했다. 체크리스트 10개 항목(norm, shape, canary, 지수/CSV 결측 테스트, shape vector, 구분 불가능성 도구, 공개 CSV, 수락 기준 실행, 전체 검증, CONTEXT와 보고서)을 모두 수행했다. `core/src/norm.rs`(신규), `shape.rs`, `canary.rs`를 구현했고, `lib.rs`에 `pub mod norm`과 `Key32`를 추가했으며, `table.rs`에 crate 내부 `Table::format()`을 추가했다. 테스트로 `core/tests/shape_vectors.rs`, `tests/vectors/shape-v1.json`, `core/tests/distinguishability.rs`를 추가했다. 새 의존성은 없고 Cargo.lock도 바뀌지 않았다.

검증(실제 실행): lib 38 + vector 1 + distinguishability 1 통과, clippy `--all-targets -D warnings` 통과, wasm build 성공, getrandom 0, `cargo deny` ok, `./scripts/test.sh` ALL CHECKS PASSED. 5만 행 `mark(n=64)`는 release에서 약 0.14 s였다. 합성 데이터셋 A는 수락 기준 3을 통과했다(키 1, AUC 0.544).

부분 완료다. 공개 CSV(국토교통부_전국 법정동, 20,561행)에서 기준 4가 실패한다. 자동 marker가 CanaryExhausted로 끝나고, 수동 marker로 돌리면 AUC 0.84~0.89다. 원인은 shape-v1 §3.1의 NUMERIC 균등 생성과 §4.1 marker 규칙이다. 명세 변경이 필요하므로 멈추고 QUESTION 3개를 올렸다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-02.md`.

WP-02 2차(shape-v1 r2): 머리 답변대로 r2를 구현했다. 바꾼 것은 다음과 같다.
- 정수 summary, NUMERIC 복사와 gap sampling, STRING anchor, 빈 공간 marker 조건, 값 기준 NUMERIC 충돌, warning 코드 6개.
- shape-v1.json 재생성(draw 값은 같고 canary는 바뀜).
- distinguishability를 §9 r2 판정으로 바꿨다.

검증(실제 실행): lib 42 통과, clippy/wasm/getrandom 0/deny/test.sh 통과, 5만 행 mark 약 0.15 s.

판정 결과:
- 데이터셋 A n=1000은 키 1~3 모두 통과(AUC 0.486~0.498, 시↔동 불일치 0/1000).
- 공개 CSV는 자동 marker가 [법정동코드, 생성일자]를 고르고 소진은 사라졌다. n=1000 AUC는 0.605/0.596/0.582로 키 1이 기준을 넘는다.
- 원인은 법정동코드 gap sampling의 w=0 기각이 만드는 밀도 편향이다(ablation 0.58~0.60). 명세 변경이 필요해 QUESTION을 올리고 멈췄다.

WP-02 3차(r2.1): gap sampling을 '기각' 대신 '다음 비어 있지 않은 구간으로 이동'으로 바꿨다(next-gap 배열, 스캔과 동등성 테스트). vector에 연속 코드 케이스를 추가해 재생성했다. 결과는 다음과 같다.
- 공개 CSV n=1000 AUC 0.516/0.506/0.491, 법정동코드 KS 0.022~0.028 < q95 0.044.
- 데이터셋 A n=1000 키 1~3 통과.
- 공개 CSV 판정은 결측률 band에서 걸린다(키 1 읍면동명 0.023 > 0.020). 30 키 보정에서 편향 없음(위반 14/150 = 9.3%, 공칭 10%)을 확인했다. 기준 문제라 QUESTION Q7을 올렸다.

WP-02 4차(r2.2): 보호 NUMERIC 정렬열을 중복 포함 V[0..m)으로 바꿨다(G는 서로 다른 정수 기준. scale 잘림으로 생기는 underflow를 고쳤다). 결측률 판정은 K=10 키 평균 + bootstrap 95% 구간이다. vector에 중복 값 케이스를 추가했다. 결과는 다음과 같다.
- 데이터셋 A와 공개 CSV n=1000 판정 모두 통과(AUC A 0.467~0.497, 공개 CSV 0.491~0.516).
- A' area KS 0.024 < q95 0.043.
- 전체 검증 통과.

## WP-03 Review

희진이 "WP-03 시작해"(HANDS-PROTOCOL §1.4 "바로 해")로 승인해 계획 확인 단계 없이 진행했다. 결과는 막힘(QUESTION 2개)이다. `merkle.rs`, `blob.rs`, `sign.rs`, `evidence.rs`를 CORE-API 시그니처대로 구현했고, 수락 기준 1~3, 5~8, 10의 단위 테스트를 추가했다(lib 56 passed). core/Cargo.toml에서 이미 있던 ml-dsa, sha2, hmac, chacha20poly1305의 `zeroize` feature를 켰다. 새 crate는 없고 Cargo.lock에는 zeroize 의존 edge만 추가됐다. getrandom은 0이다. 동결 vector(`core/tests/vectors.rs`, `tests/vectors/norea-evidence-v1.json`)는 만들지 않았다. 스펙의 6행 입력은 n=1에서도 `CanaryExhausted`가 난다. `id`(P-001..P-006)가 unique STRING이라 보호되는데 템플릿 공간이 6개뿐이고 6개 모두 실제 값이기 때문이다(QUESTION 1). 그래서 기준 4의 SIG_CTX 실험과 기준 9는 실행하지 않았다. 기준 1의 "count 변조 → 거짓"은 RFC 9162 알고리즘상 같은 path 모양에서는 성립하지 않는다. 64개 경우가 그렇고 테스트로 고정했다(QUESTION 2). clippy, wasm build, `cargo deny`, `./scripts/test.sh`는 통과했다. 5만 행 `build_evidence(n=64)`는 release에서 128~139 ms였다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-03.md`.

WP-03 2차: 머리가 QUESTION 1(vector 입력의 id를 P-013..P-406으로, JSON 끝 LF 없음, CSV 7레코드 모두 LF)과 QUESTION 2(기준 1 문구 수정)에 답했다. `blob::derive_blob_key`를 pub으로 올렸다. `core/tests/vectors.rs`를 쓰고 `tests/vectors/norea-evidence-v1.json`을 생성했고, 두 번째 실행에서 대조 통과를 확인했다. 입력 바이트는 스펙 텍스트와 같고 original_sha256도 일치한다. SIG_CTX 1바이트 실험에서 vector 테스트가 실패하는 것을 확인했고, 원복 뒤 실험 전 파일과 바이트 동일함을 확인했다. 전체 검증은 통과했다(lib 56 + vectors 1, clippy, wasm, getrandom 0, deny, test.sh). Frozen 표기는 머리 수락 대기다.

## WP-04 Review

희진이 "WP-04 시작해"라고 했다(HANDS-PROTOCOL §1.4 "바로 해"). 계획 확인 단계 없이 진행했다. 결과는 부분 완료다. 구현과 수락 기준 1~10은 모두 끝났지만 QUESTION 1개가 남아 있다.

바꾼 것:
- `core/src/check.rs`(신규 로직): suspect kind 감지, §7.1 비교, JSON/CSV 레코드, HTML·텍스트 수동 스캐너, 512자 window, 숫자 경계, `match_rows`, `check`.
- `core/src/disclose.rs`(신규 로직): `disclose`, `verify_disclosure`(statement 포함).
- `canary.rs`: CanaryExhausted 메시지에 ` (field f)`.
- `shape.rs`: inspect `NO_FREE_SPACE`.
- `evidence.rs`: 내부 helper 2개를 `pub(crate)`로.
- 테스트: `core/tests/check_disclose.rs`, `core/tests/common/mod.rs`(데이터셋 A 복사).

새 의존성은 없다. `unicode-normalization`은 이미 있었다. 동결 vector 2개는 그대로 통과한다.

검증(실제 실행):
- lib 65, check_disclose 11, vectors 1, shape_vectors 1 통과.
- clippy 0, wasm build, getrandom 0, deny ok, test.sh ALL CHECKS PASSED.
- 5만 행 check는 release JSON 약 94 ms.

QUESTION 1: 사본 전체를 감싸는 object가 있으면 JSON 레코드 정의(§7.2 subtree 전체) 때문에 무관한 독립 데이터에서도 matched가 나온다(seed 2~5에서 128개 중 8개). 대조 규칙을 바꿔야 하므로 머리 결정이 필요하다.

상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-04.md`.

WP-04 2차: 머리가 QUESTION 1에 B(행 배열 경계)로 답했고 제안 1~6을 수용해 shape-v1 §6.1, §7, §8과 disclosure-v1 §4를 개정했다. 이번 차수에 반영한 것:
- `check.rs`: JSON 레코드를 행 배열 경계로 바꿨다. 숫자로 파싱되는 Str marker에는 숫자 규칙을 함께 적용하고, 텍스트 경로에 천단위 콤마형 패턴을 더했다. 모든 marker에 Unicode 영숫자 경계를 두고 `&nbsp;`를 디코드한다. 내부 `match_rows_counted`가 R을 낸다.
- `disclose.rs`: report에 `verdict`를 넣었다. 확률 줄은 가장 약한 t개 합 − log2 C(m,t)로 계산하고 R, n, 기대 수를 쓴다.
- 데이터셋 A를 `core/tests/common/mod.rs`로 옮겼다. distinguishability 출력은 이전과 같다(시간 줄 제외 diff 동일).
- 기준 11~16 테스트를 추가했다.

검증(실제 실행):
- 기준 1~18 통과. 감싼 독립 데이터 seed 2~5는 matched 0/0/0/0, partial은 평평한 배열과 같다.
- 동결 vector json의 확률 줄은 `2^-13.25`, R=10, n=4이다.
- lib 68, check_disclose 15, vectors와 shape_vectors 그대로 통과. clippy, wasm, getrandom 0, deny, test.sh 통과. 새 의존성 없음.


## WP-05 Review

희진이 "WP-05 시작해"라고 했다(HANDS-PROTOCOL §1.4 "바로 해"). 계획 확인 단계 없이 진행했고 결과는 완료다. `cli/src/bin/norea-verify.rs`(evidence, disclosure, `--json`, `--export-anchors`, 종료 0/1/2)와 `cli/src/bin/norea.rs`(inspect, protect, check, disclose, anchor 종료 3, `--i-know-this-is-for-testing` gate, zeroize)를 구현했다. `cli/tests/e2e.rs`(11개), `cli/README.md`(감정인용, "이 도구가 검증하지 않는 것")를 추가했고 `scripts/test.sh` 4단계 설명을 고쳤다. `cli/Cargo.toml`에는 serde_json, base64, zeroize를 넣었다. 셋 다 core와 같은 버전으로 lock에 이미 있던 crate라 Cargo.lock은 norea-cli 항목 3줄만 바뀌었다. core 파일은 바꾸지 않았다. 검증(실제 실행): 수락 기준 1~8 통과, `cargo test --workspace`, clippy `-D warnings`, wasm build, getrandom 0, `cargo deny check`, `./scripts/test.sh` ALL CHECKS PASSED. release cold build는 13.6 s, `norea-verify` 1.36 MB, `norea` 1.54 MB(Apple M4)였다. QUESTION은 없다. 상세: `/Users/mac/dev/derator/Fable_5_1/tasks/reports/WP-05.md`.

WP-05 2차: 머리 답변(1차)대로 고쳤다.
- `norea disclose`에 `--source-claim`, `--captured-claim`, `--capture-method-claim`, `--created-claim`, `--force`를 넣었다.
- `norea protect`에 `--created-claim`을 넣었다.
- `norea-verify evidence`에 `--json`을 넣었다.
- `--export-anchors` README.txt와 `cli/README.md`의 ots 안내를 "WP-08에서 확정"으로 바꿨다.

e2e는 5개를 더해 16개다. claim, force, 재현 가능 protect, evidence --json, ots README를 확인한다. 검증(실제 실행): workspace test, clippy, getrandom 0, deny, test.sh 모두 통과했다. core, vectors, Cargo.lock은 1차 이후 바뀌지 않았다.
