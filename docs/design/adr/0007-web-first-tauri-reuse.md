# ADR-0007. 배포는 웹 먼저, 같은 UI를 Tauri 2로 재사용

Status: Accepted 2026-11-08 (web), apps는 설계만. ProvGuard ADR-007을 승계한다.

## Decision
- Phase 1: 정적 웹앱(서버 없음, anchor relay 제외), Cloudflare Pages.
- Phase 2~3: Tauri 2로 macOS, Windows, iOS, Android. `web/public` UI를 그대로 쓰고 `platform.js` 한 줄만 `platform-tauri.js`로 바꾼다. SE, TPM, Keystore는 Tauri 플러그인(Swift/Kotlin/Rust).
- 앱에서는 비밀키가 JS로 넘어오지 않는다. Rust/네이티브가 키 보관과 서명을 하고 JS는 결과만 받는다.
- 제3자 verifier는 Rust CLI(`norea-verify`)로도 배포한다(ADR-0011). 감정인이 브라우저 없이 돌릴 수 있어야 한다.

## Alternatives
UniFFI + 네이티브 UI 4벌: UX는 좋지만 UI를 네 번 만든다. Tauri 웹뷰 UX가 부족하면 이 길로 간다. core API가 UniFFI 친화적이라 core는 바뀌지 않는다.

## Consequences
core와 UI는 Tauri에 의존하지 않는다. Tauri를 걷어내도 core, CLI, HTML/JS가 남는다.
