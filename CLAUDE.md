# NoREA: Claude Code 작업 지침 (구현 repo)

Claude Code는 세션 시작 때 이 파일을 자동으로 읽는다.
- 현재 상태: `CONTEXT.md`
- 설계(규범): `design/` 또는 `/Users/mac/dev/derator/Fable_5_1/` — `docs/protocol/*`, `docs/CORE-API.md`, `docs/adr/*`
- 할 일: `tasks/todo.md`, 받은 WP: `design/tasks/specs/WP-*.md`
- 작업 규약: `design/tasks/HANDS-PROTOCOL.md` (반드시 먼저 읽는다)

## 제품 범위

운영자가 **자기 소유의 공개 데이터**에 canary(가상 레코드)를 넣고, ML-DSA-65로 서명하고 외부 anchor로 시점을 고정한 증거를 남기고, **운영자가 직접 제공한** 의심 사본에서 canary를 대조해 복제를 증명한다. 제3자는 비밀 없이 disclosure를 검증한다. 방어 제품이다. 막지 않고 증명한다(ADR-0001).

구현하지 말 것: 제3자 사이트 크롤링(운영자 watchlist 외), 봇 차단, 난독화, fingerprinting, 실제 존재하는 값의 canary 사용, canary·exclusions·데이터·키를 서버로 보내는 것(anchor는 32 B digest만).

## 명령어

| 목적 | 명령 |
|---|---|
| 전체 검증 (커밋 전 필수) | `./scripts/test.sh` |
| 웹 빌드 | `./scripts/build-web.sh` → `web/public/pkg/` |
| 로컬 실행 | `python3 -m http.server 8080 -d web/public` |
| 동결 vector 재생성 (포맷 변경 승인 후에만) | `NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test vectors` |
| CLI | `cargo run -p norea-cli --bin norea-verify -- --help` |

준비물: Rust stable(`rust-toolchain.toml`), `rustup target add wasm32-unknown-unknown`, `cargo install wasm-bindgen-cli --version <Cargo.lock 버전> --locked`, `wasm-opt`, Node 22+.

## 작업 방식 (희진 규칙, 반드시 지킬 것)

1. 먼저 관련 파일을 읽고 `tasks/todo.md`에 체크리스트로 계획을 쓴다.
2. 작업 시작 전에 희진에게 계획을 확인받는다.
3. 항목을 하나씩 완료 표시하며 진행한다.
4. 단계마다 무엇을 바꿨는지 high-level로 설명한다.
5. 변경은 최소로. 영향 범위가 가장 작은 방법을 고른다.
6. 끝나면 `tasks/todo.md` 맨 아래 Review 섹션에 요약을 쓰고, 보고서를 `design/tasks/reports/WP-NN.md`에 쓴다.
7. 생성과 검증은 별도 단계다. 검증 전에 "이제 검증한다"라고 선언하고 실제로 실행해서 확인한다. 실행하지 않은 것을 verified라고 쓰지 않는다. 확실하지 않으면 확실하지 않다고 쓴다. 인용은 원문을 열어 대조한다.
8. 코드를 쓴 뒤 보안 점검: 프런트엔드에 민감정보 없음, secret을 로그/URL/localStorage/에러 메시지에 남기지 않음, CSP 유지, 의존성 추가는 이유를 기록.
9. 이모지를 쓰지 않는다.
10. 한국어 문서에서도 기술 용어는 영어 그대로.

## Git
- author: `JO-HEEJIN <midmost44@gmail.com>`
- 커밋 메시지는 사람이 직접 쓴 것처럼 간단하게. Claude attribution 줄을 넣지 않는다.
- 커밋과 푸시는 희진이 요청할 때만.

## 깨면 안 되는 불변 조건 (바꾸려면 ADR + 희진 승인)

1. `norea.evidence.v1` 필드·payload 바이트·`SIG_CTX = "norea/evidence/v1"`·Merkle·blob AEAD. `core/tests/vectors.rs`가 감시한다. 깨지면 고치지 말고 멈춰서 보고한다.
2. `noreacore`는 RNG, 네트워크, 파일 I/O, 키 저장, 시계에 의존하지 않는다. `cargo tree -p norea-web --target wasm32-unknown-unknown | grep -c getrandom` → 0.
3. 입력 파일을 절대 수정하지 않는다.
4. 하드웨어 정직성(`hardwareDuringSigning` 사실대로).
5. 로컬 시계는 시점 증거가 아니다.
6. canary 생성기는 kind별 고정. 새 kind로 추가.
7. UI는 `platform.js` 계약만 부른다.
8. 비밀은 WASM 경계를 한 번만 넘고 양쪽에서 0으로 덮는다(`Vec<u8>` + zeroize).
9. canary·exclusions·데이터·키를 서버로 보내지 않는다.
10. 실제 존재하는 값을 canary로 쓰지 않는다.

## 멈추는 조건
포맷·암호 파라미터를 바꿔야 할 것 같을 때, 스펙이 모호할 때, 수락 기준을 못 맞출 때, 보안 문제를 봤을 때: 구현을 멈추고 보고서에 `QUESTION:`을 쓰고 희진에게 알린다(HANDS-PROTOCOL §4).

## 디렉터리

```
CLAUDE.md, CONTEXT.md, README.md
Cargo.toml                workspace (core, web, cli)
core/                     noreacore: table, shape, canary, merkle, blob, sign, evidence, check, disclose, anchor
  tests/vectors.rs        동결 포맷 감시
web/                      norea-web: wasm-bindgen 바인딩(타입 변환 + zeroize)
  public/                 정적 웹앱. index.html, app.js, platform.js, platform-web.js, custody.js, style.css, _headers, pkg/(빌드 산출물)
cli/                      norea-verify(제품), norea(개발용)
relay/                    Cloudflare Worker (WP-08, 필요 시)
tests/                    smoke.node.cjs, platform.node.mjs, browser/, vectors/norea-evidence-v1.json
scripts/                  build-web.sh, test.sh
design/                   Fable_5_1 복사본 또는 링크 (읽기 전용, reports/만 쓴다)
tasks/todo.md
```
