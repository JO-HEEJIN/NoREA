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
