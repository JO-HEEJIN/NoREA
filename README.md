# NoREA

운영자가 자기 소유의 공개 데이터에 가상 레코드(canary)를 심고, ML-DSA-65로 서명하고 외부 시점 anchor로 고정한 증거를 남겨, 나중에 운영자가 직접 가져온 의심 사본에서 canary를 대조해 복제를 증명하는 방어 도구다. 막지 않고 증명한다. 제3자는 비밀 없이 disclosure package를 검증한다.

현재 상태는 `CONTEXT.md`, 작업 지침은 `CLAUDE.md`를 본다.

## 구성

- `core/` noreacore: 순수 Rust 로직(모든 플랫폼 공용)
- `web/` norea-web: wasm-bindgen 바인딩, `web/public/` 정적 웹앱
- `cli/` norea-verify(제3자 검증), norea(개발용)

## 명령

```
./scripts/test.sh          # 전체 검증
./scripts/build-web.sh     # web/public/pkg 빌드
python3 -m http.server 8080 -d web/public
```

준비물: Rust stable, `rustup target add wasm32-unknown-unknown`, Cargo.lock 버전과 같은 `wasm-bindgen-cli`, Node 22+.
