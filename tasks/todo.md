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
