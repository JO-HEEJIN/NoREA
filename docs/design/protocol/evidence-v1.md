# NoREA Evidence v1 (`norea.evidence.v1`)

Status: **Frozen** (2026-11-09, WP-03 수락. 동결 vector `tests/vectors/norea-evidence-v1.json`, json evidence_id `bb94b64d…`, csv `44c3b4c5…`). Frozen 이후에는 한 바이트도 바꾸지 않는다. 바꾸려면 `norea.evidence.v2`를 새로 만들고 verifier가 둘 다 지원한다.

이 문서는 규범(normative)이다. 구현은 이 문서를 따르고, 문서와 구현이 다르면 구현이 틀린 것이다. 단, 동결 vector와 문서가 다르면 멈추고 머리에게 보고한다.

표기: `||` 바이트 연결, `u32be(x)` 4바이트 big-endian, `lp(x) = u32be(len(x)) || x`, `hex()` 소문자 hex, `b64()` RFC 4648 §4 표준 base64(padding 있음), `utf8()` UTF-8 인코딩. 해시는 전부 SHA-256.

## 1. 역할

Evidence는 운영자가 "이 데이터셋에 이 canary 집합을 이 시점 이전에 심었다"는 것을 나중에 증명하기 위해 만드는 서명된 기록이다. 운영자가 비공개로 보관하고 분쟁 때 disclosure package(`disclosure-v1.md`)로 가공해 제출한다.

Evidence 하나는 데이터셋의 한 발행본(marked 파일 한 개)에 대응한다.

## 2. 키

| 이름 | 크기 | 정의 | 어디 있나 |
|---|---|---|---|
| K | 32 B | 운영자 master key. 플랫폼 CSPRNG | 기기 custody. 절대 안 나감 |
| seed | 32 B | ML-DSA-65 seed. 플랫폼 CSPRNG | 기기 custody. SE 플랫폼은 없음 |
| K_d | 32 B | `HKDF-SHA256(salt=utf8("norea/v1"), ikm=K, info=utf8(dataset_id), L=32)` | 메모리에서만. Monitor 서버에는 이것만 |
| K_blob | 32 B | `HKDF-SHA256(salt=utf8("norea/canary-blob/v1"), ikm=K_d, info=marked_sha256_raw, L=32)` | 메모리에서만 |

HKDF는 RFC 5869 extract-then-expand. `marked_sha256_raw`는 §4의 `marked_sha256`의 raw 32바이트.

## 3. 서명

- 알고리즘: ML-DSA-65 (FIPS 204), pure ML-DSA (HashML-DSA 아님).
- Context: `SIG_CTX = utf8("norea/evidence/v1")` (17바이트).
- Software signer는 deterministic 서명. Hardware signer(Secure Enclave)는 hedged여도 된다. 검증은 둘 다 같다.
- 공개키 encoding 1952 B, 서명 3309 B.
- `verify(vk, payload, sig)`: FIPS 204 `ML-DSA.Verify(vk, payload, sig, ctx=SIG_CTX)`.

## 4. 필드

파일은 JSON object 하나다. 키 순서는 아래 순서로 쓰되 읽을 때는 순서를 요구하지 않는다. 알 수 없는 키가 있으면 verifier는 경고하고 무시한다(서명 검증은 payload 필드만 쓰므로 영향 없음).

| 필드 | 타입 | payload에 들어가나 | 정의 |
|---|---|---|---|
| `schema` | string | 예 (1행) | 정확히 `norea.evidence.v1` |
| `evidence_id` | hex64 | 아니오(파생) | `hex(SHA-256(signing_payload))`. 파일명, anchor 요청, 분쟁 참조에 쓰는 handle |
| `canary_kind` | string | 예 (2행) | canary 생성기 식별자. v1에서는 `record.shape.v1`만 정의 |
| `dataset_id` | string | 예 (3행) | 운영자가 정하는 데이터셋 이름. §5 문자열 규칙 |
| `format` | string | 예 (4행) | `json` 또는 `csv` |
| `original_sha256` | hex64 | 예 (5행) | 운영자가 넣은 원본 입력 바이트의 해시 |
| `marked_sha256` | hex64 | 예 (6행) | 출력된 marked 파일 바이트의 해시 |
| `canary_count` | u32 | 예 (7행) | canary 개수 n ≥ 1. payload에는 10진 ASCII, 선행 0 없음 |
| `canary_root` | hex64 | 예 (8행) | §7 Merkle root |
| `marker_fields` | string[] | 예 (9행) | 대조에 쓰는 필드 이름. 1~4개. payload에는 §5.2 compact JSON |
| `canary_blob_sha256` | hex64 | 예 (10행) | §7 blob(ciphertext||tag)의 해시 |
| `created_claim` | string | 예 (11행) | 운영자 기기 시계. RFC 3339 UTC `YYYY-MM-DDTHH:MM:SSZ` 정확히 20자. **시점 증거가 아니다** |
| `vk_b64` | base64 | 아니오 | ML-DSA-65 공개키 1952 B |
| `sig_b64` | base64 | 아니오 | 서명 3309 B |
| `canary_blob_b64` | base64 | 아니오 (해시로 묶임) | §7 |
| `anchors` | Anchor[] | 아니오 | §8. 서명 뒤에 추가·갱신 가능. 기본 `[]` |

## 5. 문자열 규칙

### 5.1 단일 행 문자열
payload에 들어가는 모든 문자열 필드(`canary_kind`, `dataset_id`, `created_claim`, `marker_fields`의 각 원소)는:
- 비어 있지 않다.
- U+0000..U+001F, U+007F를 포함하지 않는다(줄바꿈 포함).
- UTF-8로 유효하다. NFC 정규화는 하지 않는다(운영자가 준 바이트 그대로). 단, `dataset_id`는 UTF-8 256바이트 이하.

위반하면 `prepare_evidence`가 거부한다.

### 5.2 `marker_fields`의 compact JSON
`["필드1","필드2"]` 형태. 공백 없음. 문자열 escape는 `"` → `\"`, `\` → `\\`만 한다(5.1 때문에 제어문자는 없다). 비ASCII는 escape 없이 UTF-8 그대로. `/`는 escape하지 않는다. 순서는 운영자가 지정한(또는 생성기가 고른) 순서 그대로이고 정렬하지 않는다.

## 6. Signing payload

UTF-8, 11행, `\n`(0x0A)으로 구분, 끝에 줄바꿈 없음:

```
norea.evidence.v1
{canary_kind}
{dataset_id}
{format}
{original_sha256}
{marked_sha256}
{canary_count}
{canary_root}
{marker_fields_compact_json}
{canary_blob_sha256}
{created_claim}
```

`sig = ML-DSA-65.Sign(sk, payload, ctx=SIG_CTX)`.
`evidence_id = hex(SHA-256(payload))`.

Swift/Kotlin 플랫폼이 재현해야 하는 것은 이 바이트열과 서명뿐이다. 동결 vector의 `payload_utf8`과 바이트 단위로 같아야 한다.

## 7. Canary commitment

### 7.1 Canary row의 canonical 바이트
canary row는 JSON object다(`canary-record-shape-v1.md` §2). canonical 직렬화:

```
canon(obj) = "{" + join(",", for key in sort_bytes(keys): jstr(key) + ":" + canon_val(obj[key])) + "}"
canon_val(string s)  = jstr(s)
canon_val(number)    = 생성기가 만든 값이면 10진 텍스트 그대로 (정규식 -?(0|[1-9][0-9]*)(\.[0-9]+)?, 지수 표기 없음).
                       실제 행에서 복사한 값(OPAQUE)이면 serde_json arbitrary_precision `Number::to_string()` 텍스트.
                       이 텍스트는 가수부를 원문 그대로 두고 지수부만 정규화한다: `E`→`e`, 양수 지수에 `+` 보장 (`1e3`→`1e+3`, `1E-3`→`1e-3`, `1e03`→`1e+03`). WP-00 실측
canon_val(true/false/null) = "true" / "false" / "null"
canon_val(array a)   = "[" + join(",", canon_val(x) for x in a) + "]"
canon_val(object)    = canon(object)
jstr(s) = "\"" + escape(s) + "\""   (escape: \" \\ 와 제어문자 \b \f \n \r \t, 그 외 U+0000..001F는 \u00xx 소문자 hex; 비ASCII는 그대로)
sort_bytes = 키를 UTF-8 바이트열로 비교해 오름차순
```

`format=csv`인 경우 모든 값은 string이다(숫자처럼 보여도).

중첩 값은 생성기가 실제 행에서 복사한 것이고(OPAQUE), 숫자 텍스트는 입력에서 파싱한 원문(`arbitrary_precision`)을 그대로 쓴다.

### 7.2 Merkle tree (RFC 9162 §2.1과 동일한 구조)
```
d_i        = u32be(i) || utf8(canon(canary_i))           i = 0..n-1
leaf(d)    = SHA-256(0x00 || d)
MTH([d])   = leaf(d)
MTH(D[0:n])= SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = n보다 작은 최대 2의 거듭제곱
canary_root = hex(MTH(D[0:n]))
```
n ≥ 1. n = 1이면 root = leaf(d_0).

Audit path(선택 공개용)는 RFC 9162 §2.1.3.1의 `PATH(m, D[n])`. 검증 알고리즘은 RFC 9162 §2.1.3.2. `disclosure-v1.md` §4에 그대로 옮겨 놓았다.

### 7.3 Encrypted canary blob
Check와 Monitor가 원본 데이터 없이 canary를 복원하기 위한 것이다. K_d 없이는 열 수 없다.

```
plaintext  = utf8( "{\"rows\":[" + join(",", canon(canary_i) for i) + "],\"shape\":" + shape_json + "}" )
AAD        = utf8("norea.evidence.v1\n" + dataset_id + "\n" + marked_sha256)
nonce      = 12 × 0x00          (K_blob이 marked_sha256으로 유일하므로 고정 nonce 허용)
ct || tag  = ChaCha20-Poly1305(K_blob, nonce, AAD, plaintext)      RFC 8439, tag 16 B
canary_blob_b64    = b64(ct || tag)
canary_blob_sha256 = hex(SHA-256(ct || tag))
```
`shape_json`은 `canary-record-shape-v1.md` §6.1의 shape summary(정보용, 검증에 안 씀). 정수만 포함하며 compact 직렬화(serde_json `to_string`, preserve_order로 키 순서 고정)한다. blob 해시가 payload에 들어가므로 이 바이트는 결정론적이어야 한다. 복호화 후 `rows`의 각 원소를 파싱해서 다시 `canon()`을 적용한 결과가 Merkle leaf 입력이어야 한다(§7.1은 파싱된 값의 함수이므로 성립한다). 성립하지 않으면 evidence가 변조된 것이다.

같은 K_d로 서로 다른 두 evidence가 같은 `marked_sha256`을 가지면 K_blob과 nonce가 겹치지만, 그 경우 plaintext도 같으므로(결정론적 생성) 정보 누출이 없다. 단, `dataset_id`가 다르면 K_d가 다르다.

## 8. Anchors (서명 밖, 시점 증거)

### 8.1 Anchor subject
```
anchor_subject = SHA-256( payload || 0x0A || sig_raw )        sig_raw = 서명 3309 B
```
서명까지 포함하므로, 나중에 같은 payload를 다른 키로 다시 서명해 anchor를 재사용하는 것이 불가능하다. verifier는 anchor의 imprint가 이 값과 같은지 확인한다.

### 8.2 Anchor 객체
```json
{ "kind": "rfc3161", "token_b64": "<DER TimeStampToken(ContentInfo)>", "tsa_url": "https://...", "fetched_claim": "2026-11-08T12:00:00Z" }
{ "kind": "ots", "proof_b64": "<.ots 파일 바이트>", "calendar_urls": ["https://..."], "fetched_claim": "..." }
```
- rfc3161: TimeStampReq는 `version=1`, `messageImprint = {sha256, anchor_subject(raw 32 B)}`, `certReq=TRUE`, `nonce`는 플랫폼이 준 랜덤(선택). TimeStampResp에서 `status=granted(0)` 또는 `grantedWithMods(1)`일 때 `timeStampToken`을 저장한다.
- ots: OpenTimestamps `stamp`의 대상 digest = anchor_subject. proof는 나중에 `upgrade`로 갱신할 수 있다(같은 anchor 객체를 교체).
- `fetched_claim`은 운영자 시계. 신뢰하지 않는다. 신뢰하는 시간은 토큰 안의 `genTime`(rfc3161) 또는 Bitcoin block time(ots)이다.
- anchors 배열은 추가만 하고 기존 원소는 지우지 않는다(ots upgrade 제외). 갱신(RFC 4998식 re-anchor)은 새 원소를 추가한다.

### 8.3 Anchor 없는 evidence
유효하지만 "언제"를 증명하지 못한다. UI와 verifier는 반드시 이 사실을 표시한다.

## 9. Evidence 생성 절차 (core)

```
prepare(original_bytes, format, dataset_id, options, K_d, created_claim):
  1. table = parse(original_bytes, format)                           (canary-record-shape-v1 §1)
  2. shape = infer(table), markers = options.marker_fields ?? auto(shape)
  3. canaries[0..n), marked_bytes = generate_and_insert(table, shape, markers, K_d, n, exclusions)
  4. original_sha256 = hex(SHA-256(original_bytes)); marked_sha256 = hex(SHA-256(marked_bytes))
  5. root = MTH(canaries); blob = encrypt(K_blob, canaries, shape)
  6. ev = Evidence{...payload 필드..., vk_b64:"", sig_b64:"", canary_blob_b64: b64(blob), anchors: []}
  7. return (ev, ev.signing_payload(), marked_bytes)
finalize(ev, vk, sig):
  verify(vk, ev.signing_payload(), sig)가 참일 때만 vk_b64, sig_b64, evidence_id를 채운다. 아니면 에러.
```
Software signer 플랫폼은 `build = prepare + sign + finalize`를 한 번에 부른다. Secure Enclave 플랫폼은 prepare → 네이티브 서명 → finalize.

## 10. 검증 절차 (비밀 불필요)

`verify_evidence(ev)`:
1. `schema == "norea.evidence.v1"`, 모든 payload 필드가 §4·§5 규칙을 만족.
2. `evidence_id == hex(SHA-256(payload))`.
3. `verify(vk, payload, sig)`.
4. `canary_blob_b64`가 있으면 `hex(SHA-256(decode))== canary_blob_sha256`.
5. 각 anchor: 토큰을 파싱해 imprint가 `anchor_subject`와 같은지 확인하고 `genTime`을 보고한다. TSA 인증서 체인 검증은 v1 verifier 범위 밖이다. verifier는 토큰을 파일로 내보내고 `openssl ts -verify` 명령을 안내한다(`disclosure-v1.md` §5). 이 한계를 리포트에 명시한다.

결과는 `{signature_ok, evidence_id_ok, blob_hash_ok, anchors: [{kind, imprint_ok, gen_time?, chain_verified: false}], has_anchors}`. 1단계(필드 규칙) 실패는 별도 항목 없이 `signature_ok = false`로 보고한다(규칙을 어긴 payload는 서명 대상이 될 수 없었으므로). `canary_blob_b64`가 비어 있거나 base64가 아니면 `blob_hash_ok = false`(v1 evidence는 blob이 항상 있다).

## 11. 바꾸면 안 되는 것 (동결 후)

- 필드 이름, 행 순서, 구분자, 문자열 규칙, hex/base64 형식
- SIG_CTX, HKDF salt/info, blob AEAD와 AAD, nonce
- Merkle 구조와 leaf/node prefix
- `canon()` 규칙

바꿔도 되는 것: `anchors` 안의 새 kind 추가, 새 `canary_kind` 추가(생성기 추가), 파일에 payload 밖 새 키 추가(verifier가 무시).

## 12. 동결 vector

`tests/vectors/norea-evidence-v1.json`. 입력: `K = 0x11×32`, `seed = 0x22×32`, `dataset_id = "vector/records/v1"`, `created_claim = "2026-11-08T00:00:00Z"`, JSON 입력 하나와 CSV 입력 하나(WP-03에 명시). 고정하는 것: `k_d_hex`, `k_blob_hex`, `canaries`(canonical 문자열 배열), `marked_utf8`, `canary_root`, `blob_hex`, `payload_utf8`, `evidence_id`, `vk_sha256`, `evidence`(전체). 생성은 `NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test vectors`, 포맷 변경 승인 후에만.
