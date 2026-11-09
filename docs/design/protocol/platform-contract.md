# UI ↔ Platform contract v1

Status: **Frozen** (2026-11-09, WP-06 수락). 동결 대상은 17개 함수 이름·인자·반환 타입, `CONTRACT` 배열, 에러 코드 집합, 비밀 처리 규칙. 새 함수는 추가만 하고(배열 끝에) 기존 것은 바꾸지 않는다. 에러 메시지 문구는 UI 몫이라 바뀔 수 있다. UI(`app.js`)는 `platform.js`가 export하는 아래 함수만 부른다. WASM, custody, 네트워크를 직접 부르지 않는다. 모든 플랫폼 구현은 같은 이름과 시그니처를 export하고 `CONTRACT` 배열을 export한다. 계약 테스트가 배열과 export를 대조한다.

바이트는 `Uint8Array`, JSON 문서는 string. 비밀(K, seed, K_d)은 어떤 함수의 인자나 반환값에도 나타나지 않는다. `passphrase`는 예외적으로 인자로 들어가지만 반환되거나 저장되지 않는다.

| # | 함수 | 반환 | 비밀 필요 | 네트워크 | 설명 |
|---|---|---|---|---|---|
| 1 | `ready()` | void | | | 초기화(web: wasm init). 다른 함수보다 먼저 |
| 2 | `capabilities()` | `{platform, prf, hardwareDuringSigning, anchorRelay}` | | | `platform`: `web`/`tauri-macos`/`tauri-windows`/`tauri-ios`/`tauri-android`. `prf`: WebAuthn PRF 사용 가능 여부(모르면 `"unknown"`). `hardwareDuringSigning`: ADR-0006 표 그대로. `anchorRelay`: anchor에 쓸 relay origin 또는 null |
| 3 | `hasKey()` | bool | | | |
| 4 | `keyInfo()` | `{method, fingerprint, hardwareDuringSigning, createdClaim, persisted}` \| null | | | `method`: `prf`/`passphrase`/`secure-enclave`/`tpm-sealed`/`keystore`. `fingerprint`: `sha256(vk)` 앞 16 hex. `persisted`: `navigator.storage.persist()` 결과(`true`/`false`/`"unknown"`). UI가 "브라우저가 키 저장소를 지울 수 있음" 문구에 쓴다 |
| 5 | `setupKey({passphrase?})` | backup bytes | 생성 | | 새 K+seed(또는 SE 키) 생성, 저장, 암호화 백업 반환. 기존 키가 있으면 거부(UI가 먼저 `confirmAction` 후 `deleteKey`) |
| 6 | `deleteKey()` | void | | | 로컬 키 삭제. UI는 백업 확인 후 부른다 |
| 7 | `exportBackup({passphrase?})` | bytes | | | `norea.custody-backup.v1`. 인자 없음: 현재 방식(prf 또는 passphrase)의 백업. `{passphrase}`: prf 키를 passphrase로 감싼 두 번째 백업(custody §5. 호환 확장, 2026-11-09 설계 결정, WP-09에서 구현. 그 전까지 web은 인자를 무시한다) |
| 8 | `importBackup(bytes)` | void | | | 구조 검증 후 저장(custody 스펙 §3) |
| 9 | `inspect({input, format?})` | `InspectResult` | | | 비밀 없이 입력을 파싱해 필드, kind, 추천 marker, 행 수, 경고를 돌려준다. protect 전에 UI가 보여준다 |
| 10 | `protect({input, format?, datasetId, n, markerFields?, exclusions?, passphrase?})` | `{marked, evidenceJson, evidenceId, summary}` | 예 | | 입력 불변. `format` 생략 시 자동 감지(JSON 파싱 시도 → 아니면 csv) |
| 11 | `anchor({evidenceJson, kinds?})` | `{evidenceJson, results:[{kind, ok, error?}]}` | | 예 | relay를 통해 rfc3161/ots anchor를 받아 `anchors[]`에 추가한 evidence 반환. 실패한 kind는 결과에 남기고 나머지는 진행 |
| 12 | `check({suspect, evidenceJson, passphrase?})` | `CheckReport` | 예 | | canary-record-shape-v1 §7.5 |
| 13 | `disclose({evidenceJson, suspect, indices?, suspectMeta?, passphrase?})` | `{disclosureJson}` | 예 | | disclosure-v1 §3 |
| 14 | `verifyEvidence(evidenceJson)` | `EvidenceVerification` | | | evidence-v1 §10 |
| 15 | `verifyDisclosure(disclosureJson, suspect)` | `DisclosureReport` | | | disclosure-v1 §4 |
| 16 | `saveFile(name, bytes, mime?)` | void | | | web: `<a download>`; Tauri: dialog.save + fs |
| 17 | `confirmAction(message)` | bool | | | web: `window.confirm`; Tauri: dialog.ask |

모든 함수는 async이고 Promise를 돌려준다(web은 WASM init, IndexedDB, WebAuthn이 비동기다).

`CONTRACT = ['ready','capabilities','hasKey','keyInfo','setupKey','deleteKey','exportBackup','importBackup','inspect','protect','anchor','check','disclose','verifyEvidence','verifyDisclosure','saveFile','confirmAction']` (17개).

## 타입

```ts
InspectResult = {
  format: 'json'|'csv', rows: number,
  fields: { name: string, kind: 'STRING'|'NUMERIC'|'CATEGORICAL'|'BOOL'|'OPAQUE'|'EMPTY', unique: boolean, distinct: number, pMissing: number, spaceLog2?: number }[],
  suggestedMarkers: string[], threshold: number,
  warnings: { code: 'OPAQUE_FIELD'|'UNIQUE_OPAQUE_COPIED'|'LOW_FREE_SPACE'|'NO_FREE_SPACE'|'HIGH_MISSING'|'NO_MARKER_CANDIDATE'|'NUMERIC_CODE_LIKE', field?: string }[]
                                // UI가 코드를 한국어 문장으로 바꾼다 (shape-v1 §6.2)
}
ProtectSummary = { rows: number, canaries: number, markers: string[], threshold: number, format: string, evidenceId: string }
CheckReport = norea.check-report.v1 (canary-record-shape-v1 §7.5)
EvidenceVerification = { signatureOk, evidenceIdOk, blobHashOk, anchors: [{kind, imprintOk, genTime?, chainVerified:false, error?}], hasAnchors: boolean }
                                // anchors[].error가 있으면 그 anchor는 검증하지 않은 것(N/A). WP-08 전에는 항상 있다
DisclosureReport = norea.disclosure-report.v1 (disclosure-v1 §4)
```

## 에러

모든 함수는 실패 시 `Error`를 throw한다. 메시지는 사용자에게 보여줄 한국어 문장이고 비밀, 경로, 스택을 포함하지 않는다. 에러 종류를 코드로 구분해야 하면 `error.code`에 다음 중 하나를 둔다(2026-11-09 WP-06 후 확정): `KEY_MISSING`, `KEY_EXISTS`(setupKey인데 키가 이미 있음), `BAD_PASSPHRASE`, `PRF_UNSUPPORTED`(PRF 경로를 요청했는데 쓸 수 없음. UI는 passphrase로 전환), `CANCELLED`(사용자가 패스키 인증을 취소), `BAD_INPUT`(입력 파일·옵션·CSV 구조. core BadInput), `NO_MARKER`, `CANARY_EXHAUSTED`, `BAD_EVIDENCE`(evidence 파싱·서명·blob·canary_kind 불일치. core BadEvidence/BadSignature/BadBlob/BadAnchor. UI는 "키가 다르거나 증거가 변조됨"으로), `BAD_DISCLOSURE`(disclosure 구조. core BadDisclosure), `ANCHOR_UNAVAILABLE`, `BACKUP_INVALID`. 모든 계약 에러는 code를 가진다. `error.detail`(선택)에 core의 영어 `CODE: message`를 둘 수 있다. 비밀·경로·스택은 없다.

## 플랫폼별 메모

| 함수 | Web | Tauri (Phase 2~3) |
|---|---|---|
| `setupKey` | custody.js: PRF 또는 Argon2id로 래핑 | Rust command → SE / TPM / Keystore 플러그인 |
| `protect`/`check`/`disclose` | custody가 비밀을 풀어 WASM 호출 한 번에 넘기고 0으로 덮음(ADR-0012) | Rust command. 비밀이 JS에 안 옴 |
| `anchor` | `fetch(anchorRelay)`; CSP `connect-src`에 relay origin 추가 | Rust reqwest, 또는 relay |
| `verify*` | WASM, 비밀 불필요 | Rust command |

## 비밀 처리 규칙 (web)

1. custody가 푼 `K`와 `seed`는 한 번의 WASM 호출(`protect`/`check`/`disclose`)에 넘기고 호출이 끝나면 JS 쪽 버퍼를 `fill(0)`한다.
2. WASM 바인딩은 비밀 인자를 소유(`Vec<u8>`)로 받아 사용 후 `zeroize`한다. 바인딩이 `&[u8]`로 받으면 안 된다(wasm-bindgen의 복사본이 0으로 덮이지 않는다).
3. K_d, K_blob은 WASM 안에서만 만들어지고 밖으로 나오지 않는다.
4. `passphrase` 문자열은 JS string이라 0으로 덮을 수 없다. UI는 입력 필드를 즉시 비우고 변수 참조를 끊는다. 이 한계는 ADR-0006에 적는다.
5. WASM 바인딩의 global allocator는 해제되는 heap 블록을 전부 0으로 덮고, 비밀을 받는 호출은 끝난 뒤 stack 512 KiB를 0으로 덮는다(ADR-0014). `tests/smoke.node.cjs`의 메모리 스캔이 이것을 감시한다.
