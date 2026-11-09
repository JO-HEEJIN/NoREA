# Web key custody v1 (`norea.custody-backup.v1`)

Status: **Frozen** (2026-11-09, WP-06 수락). 동결 대상은 record 구조(§2), 백업 포맷 `norea.custody-backup.v1`과 import 검증(§3), KDF/HKDF/AEAD 파라미터. 바꾸려면 `norea.custody-backup.v2`. 웹 플랫폼의 키 보관 규격. Tauri 플랫폼은 네이티브 keystore를 쓰므로 이 문서의 백업 포맷만 공유한다(§3).

## 1. 비밀과 래핑

```
secrets  = K(32 B) || seed(32 B)                      crypto.getRandomValues(64)
KEK      = HKDF-SHA256(salt = 32×0x00, ikm = S, info = utf8("norea/kek/v1"), L = 32)
           S = PRF 출력(32 B)           method = "prf"
           S = Argon2id(passphrase, salt16, m = 64 MiB, t = 3, p = 1, L = 32)   method = "passphrase"
blob     = AES-256-GCM(KEK, iv(12 B random), AAD = utf8("norea/custody/v1"), secrets)
```
PRF: WebAuthn `prf` extension, `eval.first = utf8("norea/prf/v1")`. 같은 passkey → 같은 PRF 출력. `userVerification: "required"`, `residentKey: "required"`.

Argon2id는 WASM(`norea-web::passphraseKek`)에서 계산한다. 파라미터는 record에 기록한다(미래에 올릴 수 있게).

## 2. IndexedDB record

DB `norea`, store `custody`, key `v1`:
```
{ v: 1, method: "prf"|"passphrase", credId?: Uint8Array, salt?: Uint8Array(16), kdf?: {alg:"argon2id", m:65536, t:3, p:1},
  iv: Uint8Array(12), ct: Uint8Array(64+16), vk: Uint8Array(1952), createdClaim: "RFC3339" }
```
평문 비밀은 어떤 필드에도 없다. `vk`는 공개키라 평문.

저장 직후 `navigator.storage.persist()`를 요청하고 결과를 record 밖(메모리 또는 별도 IndexedDB 키)에 두어 `keyInfo().persisted`로 노출한다(`true`/`false`/`"unknown"`). UI는 계약만 부르므로 이 값으로 상태 문구를 만든다(2026-11-09 WP-06 후 개정. 이전 문장은 UI가 custody를 직접 보게 해 계약 규칙과 어긋났다).

## 3. 백업 파일

```json
{ "format": "norea.custody-backup.v1", "v": 1, "method": "passphrase", "kdf": {...}, "salt": "<b64>", "iv": "<b64>", "ct": "<b64>", "vk": "<b64>", "createdClaim": "..." }
```
- 암호화된 blob만 들어 있다. passkey 또는 passphrase 없이는 무용지물. 단 `method: "prf"` 백업은 **같은 passkey가 있는 기기에서만** 복원된다. UI가 이 사실을 키 생성 때 말해야 한다(passkey를 잃으면 PRF 백업도 못 연다 → passphrase 백업을 추가로 권장, §5).
- import 검증(모두 만족해야 저장):
  - `format` 정확 일치, `v == 1`, `method ∈ {prf, passphrase}`
  - `iv` 12 B, `ct` 80 B, `vk` 1952 B, prf면 `credId` 16..1023 B, passphrase면 `salt` 16 B 이상 64 B 이하이고 `kdf.alg == "argon2id"`, `m ∈ [8192, 1048576]`, `t ∈ [1, 10]`, `p == 1`. 이 범위는 import 허용 범위이고, **이 버전이 여는 값은 `m = 65536, t = 3, p = 1`뿐이다**(WASM `passphraseKek` 고정). 다른 값은 import는 되지만 열 때 `BACKUP_INVALID`("이 버전이 열 수 없는 KDF 파라미터")다. 파라미터를 올리는 버전이 나오면 `passphraseKek`에 인자를 추가한다
  - 알 수 없는 키는 버린다
  - 기존 키가 있으면 덮어쓰기 전 `confirmAction`(UI 책임)

## 4. 사용

`withSecrets(fn)`: record 로드 → S 획득(PRF 또는 Argon2id) → KEK → 복호화 → `fn(K, seed)` 호출 → finally `secrets.fill(0)`. `fn`은 비밀을 **정확히 한 번** WASM 호출에 넘긴다(platform-contract 비밀 처리 규칙).

PRF 가능 여부: `PublicKeyCredential.getClientCapabilities()`가 `extension:prf`를 주면 그 값. 없으면 `"unknown"`을 돌려주고 UI는 "시도해 보고 실패하면 passphrase" 흐름으로 간다. 생성 중 PRF 미지원이 드러나면 **방금 만든 credential은 고아가 된다**는 안내를 하고 passphrase로 전환한다(credential 삭제는 웹에서 불가).

## 5. 복구 설계

- 키 생성 직후 백업 다운로드를 강제한다.
- `method: "prf"`로 만들었어도 운영자가 원하면 같은 secrets를 passphrase로 한 번 더 래핑한 **두 번째 백업**을 만들 수 있다(`exportBackup({passphrase})` 확장, WP-06 선택 항목). 이게 passkey 분실 대비책이다.
- 서명키를 잃으면 기존 evidence는 여전히 검증 가능(공개키가 evidence에 있음)하지만 새 evidence를 같은 키로 못 만든다. check/disclose는 K가 필요하므로 **K를 잃으면 기존 evidence의 canary를 복원할 수 없다.** UI 문구에 넣는다.

## 6. 하지 않는 것

- 비밀을 localStorage, URL, 로그, 에러 메시지에 넣지 않는다.
- 서버에 어떤 키 자료도 보내지 않는다. PRF는 로컬 KDF로만 쓴다(로그인 아님).
- "키가 하드웨어를 떠나지 않는다"고 표시하지 않는다(web은 `hardwareDuringSigning: false`).
