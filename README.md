# NoREA

긁어간 데이터를 증명한다. 막지 않는다.

NoREA는 운영자가 자기 소유의 공개 데이터에 가상 레코드(canary)를 심고 ML-DSA-65로 서명한 증거를 남긴 뒤, 운영자가 직접 가져온 의심 사본에서 canary를 대조해 복제를 증명하고, 제3자가 비밀 없이 그 결과를 검증하게 하는 방어 도구다.

## 문제

공공기관과 데이터 사업자는 데이터를 공개해야 한다. 크롤러와 복제 사업자는 그것을 긁어가 재판매하거나 학습에 쓴다. 막는 기술(봇 차단, 난독화, fingerprinting)은 공개의 목적과 충돌하고 결국 뚫린다. 지도 업계는 trap street(가상의 거리)로 복제를 증명해 왔지만, 표 형태 데이터에는 그런 표준 도구가 없다. NoREA는 막는 기능을 만들지 않는다. 증명만 한다.

## 동작 원리

1. `inspect`: 필드별 kind, 빈 값 공간, 결측률을 보고 canary를 숨길 marker 필드를 추천한다. 빈 공간이 없는 필드(연번 등)는 경고한다.
2. `protect`: 필드 분포를 따라 만든 가상 레코드 n개(기본 32)를 원본 사이에 끼운 새 파일을 만든다. 생성은 HMAC 기반 결정적 draw이고 RNG를 쓰지 않는다. 입력 파일은 수정하지 않는다.
3. evidence: canary 집합의 Merkle root, 암호화된 canary blob 해시, 파일 해시를 ML-DSA-65(FIPS 204)로 서명한다. evidence는 운영자가 비공개로 보관한다.
4. `check`: 의심 사본(CSV, JSON, HTML, 텍스트. 키 이름 변경, 중첩, 전각, NFD, 행 순서 무관)에서 canary를 찾아 일치 수를 센다. 판정 기준은 marker k-of-n이다.
5. `disclose` / `norea-verify`: 일치한 canary만 Merkle audit path와 함께 공개한 disclosure를 만든다. 감정인은 키 없이 `norea-verify disclosure`로 서명, Merkle, 사본 해시, 재현을 확인하고 우연 일치 확률 상한이 적힌 statement를 받는다.

웹 앱에서는 이 모든 처리가 브라우저 안(WASM)에서 끝난다. 데이터, canary, 키는 서버로 가지 않는다.

## 무엇이 검증되고 무엇이 아닌가

검증된다(키 없이, 오프라인):
- evidence의 ML-DSA-65 서명, `evidence_id = SHA-256(payload)`, canary blob 해시
- 공개된 canary 각각의 Merkle path가 서명된 canary_root로 이어지는지
- 제출된 사본의 SHA-256이 disclosure에 적힌 값과 같은지(1바이트만 바뀌어도 FAIL, 종료 1)
- 공개된 canary가 그 사본에서 실제로 재현되는지

검증되지 않는다:
- 시점. 외부 시점 anchor(RFC 3161 TSA, OpenTimestamps)는 아직 구현 전이다(`norea anchor`는 미구현). `created_claim`은 운영자 기기 시계의 주장일 뿐이고, 현재 evidence는 "언제 심었는가"를 증명하지 않는다. verifier도 그렇게 출력한다.
- 사본의 출처, 포착 시점, 포착 방법(`*_claim` 필드). 운영자 주장이다.
- TSA 인증서 체인. anchor가 붙더라도 norea-verify는 체인을 검증하지 않는다(`--export-anchors` 후 openssl로 수동 확인).
- 확률 상한은 생성기 모델 기준이지 실제 세계 확률이 아니다. 근거인 shape 정보는 운영자가 disclosure에 넣은 것이다.

## 빠른 실행

준비물: Rust(`rust-toolchain.toml`이 1.99.1 고정), `rustup target add wasm32-unknown-unknown`, Cargo.lock 버전과 같은 `wasm-bindgen-cli`, Node 22+.

```
./scripts/test.sh                          # 전체 검증 (core, WASM e2e, 플랫폼 계약, CLI, 웹 UI 정적 검사, getrandom 0)
./scripts/demo.sh                          # 심사위원용 데모. 출력과 로그는 target/demo/ (demo.log)
./scripts/build-web.sh                     # web/public/pkg 빌드
python3 -m http.server 8080 -d web/public  # http://localhost:8080
```

`demo.sh`는 국토교통부 법정동코드 공개 CSV(20,561행)를 쓴다. 저장소의 `demo/data/legal-dong-code.csv`(국토교통부 법정동코드 전체자료, 공공데이터포털 data.go.kr 제공, 공공누리 출처표시 조건으로 재배포)를 쓴다. `/dev/urandom`으로 만든 데모용 테스트 키로 protect한 뒤, 크롤러 사본 3종(HTML 표, JSON API 응답, 행 섞은 CSV)과 무관한 데이터 1종을 check하고, HTML 사본으로 disclosure를 만들어 `norea-verify`로 검증한다. 마지막으로 1바이트 변조본이 FAIL 나는 것을 보인다. 2026-11-09 실행 결과(Apple M4, 전체 약 3~5 s):

| 사본 | 대조 경로 | matched |
|---|---|---|
| HTML `<table>`(열 이름 변경, `&amp;`, 줄바꿈과 공백) | text | 32/32 |
| `{"status":"ok","data":[...]}`(키 이름 변경) | json | 32/32 |
| 행 순서 섞은 CSV(CRLF) | csv | 32/32 |
| 원본(canary 없음)의 부산광역시 행 | csv | 0/32 |

`norea-verify disclosure` 종료 0(PASS), 1바이트 변조본 종료 1(FAIL, 사본 해시 불일치).

CLI의 `--key-file`과 `--i-know-this-is-for-testing`은 테스트 전용이다. 웹 앱은 키를 WebAuthn PRF 또는 passphrase(Argon2id)로 감싸 IndexedDB에 보관한다. 웹에서는 서명하는 동안 키가 브라우저 메모리에 올라오며, UI도 그렇게 표시한다.

## 저장소 구조

```
core/        noreacore: 순수 Rust 로직(table, norm, shape, canary, merkle, blob, sign, evidence, check, disclose). RNG, 네트워크, 파일 I/O, 시계 없음
web/         norea-web: wasm-bindgen 바인딩. web/public/ 정적 웹앱(platform.js 계약, custody.js 키 보관, app.js UI)
cli/         norea-verify(제3자 검증, 비밀 불필요), norea(개발·테스트용)
tests/       smoke.node.cjs(WASM e2e), platform.node.mjs(플랫폼 계약 + 키 보관), ui.node.mjs, vectors/(동결 vector)
scripts/     test.sh, build-web.sh, demo.sh, demo-crawler.mjs
CONTEXT.md   현재 동작 상태. 세부 사항은 여기가 기준이다
CLAUDE.md    작업 지침
```

## 동결 포맷과 vector

Frozen 포맷: `norea.evidence.v1`(signing payload 바이트, `SIG_CTX = "norea/evidence/v1"`, Merkle 구조, blob AEAD 포함), `record.shape.v1`, `norea.disclosure.v1`, `norea.disclosure-report.v1`, `norea.custody-backup.v1`, platform-contract v1. 동결 vector `tests/vectors/norea-evidence-v1.json`을 `core/tests/vectors.rs`가 대조하고, 같은 입력으로 WASM `protect`가 만든 evidence가 문자열까지 같은지를 `tests/smoke.node.cjs`가 확인한다. 포맷을 바꾸면 이미 발급한 증거가 검증 불가가 되므로, vector 테스트가 깨지면 고치지 않고 멈춘다.

## 측정치

환경: Apple M4, rustc 1.99.1 release.

- 구분 불가능성: 공개 CSV(법정동코드 20,561행) n = 1000, 로지스틱 회귀 5-fold held-out AUC 0.516 / 0.506 / 0.491(키 3개). 0.5가 우연 수준이다. 합성 데이터셋 A는 0.467~0.517.
- protect 5만 행, canary 64, 서명 포함: 437~447 ms. WASM을 node 22에서 측정했다(`tests/smoke.node.cjs`). 실제 브라우저 탭에서 잰 값은 아니다.
- check 5만 행(n = 32, native release): JSON 5.7 MB 약 94 ms, CSV 2.4 MB 약 74 ms, HTML 10.5 MB 약 143 ms.
- 거짓 일치: 데이터셋 A와 같은 생성기로 만든 독립 데이터 4종(seed 2~5, 우리 canary 없음)에서 matched 0/128(4 x 32). partial은 있다(14, 13, 15, 18. 주로 짧은 id 공간의 우연 일치).
- 테스트: `./scripts/test.sh` ALL CHECKS PASSED(2026-11-09 실행). Rust 103개(core lib 68, check_disclose 15, vectors 1, shape_vectors 1, distinguishability 1, CLI unit 1 + e2e 16), WASM e2e 74, 플랫폼 계약 84, UI 105.
- wasm 크기는 `wasm-opt -O3` 후 782 KB로 목표(600 KB)를 넘는다.

## 한계

- 완전 재작성 클론: 값을 새로 만들어 낸 사본에는 canary가 없으므로 잡지 못한다. NoREA는 canary를 골라 지우는 비용을 높일 뿐이다.
- 필드 간 상관(예: 법정동코드와 시도명)은 학습하지 않는다. 날짜 같은 의미 제약도 모른다(`2003-02-31`이 나올 수 있다). 상관을 아는 분석자에게는 canary가 드러날 수 있다.
- dense key: 연번 `1..N`처럼 빈 값 공간이 없는 unique 필드에는 canary를 만들 수 없다. inspect가 경고하고 그 필드를 뺀 발행본을 권한다.
- EAV: 한 행의 값을 서로 다른 배열에 나눠 넣은 변환은 구조 경로로 못 잡는다.
- 시점 anchor가 아직 없고, 붙더라도 TSA 체인 검증은 수동이다.
- WebAuthn PRF 경로와 Safari/Firefox 동작은 아직 실제 브라우저에서 검증하지 않았다(headless Chrome에서 passphrase 경로만 확인).

## 설계 문서

설계(규범), ADR 14개, 프로토콜 스펙, 위협 모델, 작업 보고서는 이 저장소 밖 `Fable_5_1/`에 있다(작성자 환경 기준 `/Users/mac/dev/derator/Fable_5_1/`: `docs/adr/`, `docs/protocol/`, `docs/THREAT-MODEL.md`, `docs/CORE-API.md`, `tasks/reports/`). 이 저장소의 현재 동작은 `CONTEXT.md`가 기준이다.

## 라이선스

MIT OR Apache-2.0 (각 crate의 `Cargo.toml`).
