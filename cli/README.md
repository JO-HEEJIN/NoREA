# norea-verify: 감정인용 사용법

`norea-verify`는 NoREA disclosure package를 **비밀 없이, 오프라인으로** 검증하는 도구다(ADR-0011). 운영자의 마스터 키나 서명키가 필요 없고 네트워크에 접속하지 않는다. 검증 규칙은 전부 `noreacore`에 있고 이 도구는 파일을 읽어 결과를 보여 줄 뿐이다.

운영자가 제출하는 것은 두 파일이다.
- `disclosure.json`: `norea.disclosure.v1`. 서명된 evidence 전체, 의심 사본의 SHA-256, 공개한 canary row와 Merkle path.
- 의심 사본 파일: 운영자가 포착했다고 주장하는 상대방 사본 그대로(JSON, CSV, HTML, 텍스트).

## 빌드

```
cargo build --release --locked -p norea-cli
# target/release/norea-verify, target/release/norea
```

## 명령

```
norea-verify disclosure <disclosure.json> <suspect-file> [--json] [--export-anchors DIR]
norea-verify evidence <evidence.json> [--json]
```

### disclosure

```
norea-verify disclosure disclosure.json suspect.json
```

출력은 섹션별 `PASS` / `FAIL` / `N/A`이고 한국어와 영어를 같이 쓴다.

1. Evidence: ML-DSA-65 서명(필드 규칙 포함), `evidence_id = SHA-256(payload)`, canary blob 해시.
2. 시점 anchor: 현재 버전은 anchor를 검증하지 않으므로 `N/A`다(아래 "검증하지 않는 것"). 종료 코드에 넣지 않는다.
3. 사본: 사본 파일의 SHA-256이 disclosure의 `suspect.sha256`과 같은가.
4. 공개된 canary: 각 row의 Merkle path가 **서명된** `canary_root`에 닿는가(count는 서명된 `canary_count`), 그리고 그 row가 사본에서 다시 찾아지는가(재현). 항목별 `index`, `found` 필드.
5. 판정: `verdict.integrity_ok`, `verdict.all_reproduced`.
6. Statement: verifier가 생성한 한국어 문장 원문. 공개키 지문(SHA-256(vk) 앞 16 hex), 시점 문구, "공개된 canary N개 중 M개가 사본에서 재현되었다", 확률 상한 줄, `*_claim`이 미검증이라는 문장이 들어 있다. 감정서에 인용할 때는 이 원문을 쓴다.

`--json`은 `norea.disclosure-report.v1` JSON을 가공 없이 stdout에 한 줄로 쓴다(끝에 줄바꿈 하나). 다른 출력은 stdout에 섞이지 않는다.

### evidence

```
norea-verify evidence evidence.json
```

disclosure 없이 `norea.evidence.v1` 하나만 검증한다(서명, evidence_id, blob 해시, anchor). `--json`은 core의 `EvidenceVerification` JSON(`signature_ok, evidence_id_ok, blob_hash_ok, anchors, has_anchors`)을 그대로 쓴다.

## 종료 코드

| 명령 | 0 | 1 | 2 |
|---|---|---|---|
| `disclosure` | `verdict.integrity_ok && verdict.all_reproduced` | 그 외(서명, evidence_id, blob 해시, 사본 해시, Merkle, 재현 중 하나라도 실패, 또는 공개 0개) | 입력 오류: 파일 없음, UTF-8 아님, JSON 아님, schema나 필드 형식, index 순서, `--export-anchors` 대상 파일이 이미 있음 |
| `evidence` | `signature_ok && evidence_id_ok && blob_hash_ok` | 그 외 | 파일 없음, JSON 아님, evidence 구조 아님 |

anchor 결과는 어느 명령의 종료 코드에도 들어가지 않는다. 오류는 stderr에 한 줄(`norea-verify: error: ...`)이고 스택 트레이스는 나오지 않는다.

## TSA 토큰 직접 검증 (`--export-anchors DIR`)

```
norea-verify disclosure disclosure.json suspect.json --export-anchors anchors/
```

`DIR`에 새 파일을 만든다(이미 있으면 덮어쓰지 않고 종료 코드 2).
- `anchor-<k>.tsr`: rfc3161 anchor k의 TimeStampToken(DER).
- `anchor-<k>.ots`: ots anchor k의 proof 바이트. OpenTimestamps 검증 명령은 WP-08에서 실제 proof로 확정한다. 이 파일은 proof 바이트 원본이다.
- `subject.bin`: anchor_subject 32 B = SHA-256(signing payload || 0x0A || signature).
- `README.txt`: 아래 명령에 실제 값을 채운 안내.

```
openssl ts -verify -digest <anchor_subject_hex> -in anchor-0.tsr -token_in -CAfile <TSA CA bundle>
```

CA bundle은 해당 TSA가 공개한 것을 감정인이 직접 구한다. 이 단계는 자동화하지 않는다(disclosure-v1 §5).

## 이 도구가 검증하지 않는 것

- **TSA 인증서 체인.** 리포트의 `chain_verified`는 항상 `false`다. 토큰을 내보내 `openssl ts -verify`로 직접 확인해야 한다.
- **anchor 자체(현재 상태).** anchor imprint와 genTime 검증은 아직 구현되지 않았다(WP-08). 지금은 모든 anchor가 `N/A`이고 리포트에 `error: "anchor verification not implemented"`가 있다. 그래서 현재 버전의 출력은 증거의 생성 시점에 대해 아무것도 증명하지 않는다.
- **`*_claim` 필드.** `created_claim`(운영자 기기 시계), `suspect.source_claim`, `captured_claim`, `capture_method_claim`은 운영자 주장이다. 사본을 언제, 어디서, 어떻게 포착했는지는 공증, 플랫폼 타임스탬프, 웹 아카이브 같은 외부 증거로 따로 보강해야 한다.
- **shape 정보.** 확률 줄의 근거인 `shape`는 운영자가 disclosure에 넣은 것이고 이 도구가 검증하지 않았다.
- **실제 세계 확률.** 확률 줄은 canary 생성기 모델 기준의 상한이다. 실제 데이터에서 우연히 같은 값이 나올 확률이 아니다.
- **공개되지 않은 canary.** 공개하지 않은 canary는 암호화된 blob 안에 있고 이 도구는 그 해시만 대조한다.
- **사본이 운영자 데이터에서 유래했다는 법적 판단.** 이 도구는 기술적 사실(서명, 해시, Merkle, 재현)만 보고한다.

## `norea` (개발·테스트용, 제품 아님)

```
norea inspect <input> [--format json|csv]
norea protect <input> --dataset-id ID --n N [--markers a,b] [--exclusions file] [--created-claim YYYY-MM-DDTHH:MM:SSZ] --key-file K.bin --seed-file S.bin --out-dir DIR --i-know-this-is-for-testing
norea check <suspect> <evidence.json> --key-file K.bin --i-know-this-is-for-testing
norea disclose <evidence.json> <suspect> --key-file K.bin [--indices 1,2,3] [--source-claim S] [--captured-claim T] [--capture-method-claim M] [--created-claim YYYY-MM-DDTHH:MM:SSZ] [--force] --out disclosure.json --i-know-this-is-for-testing
norea anchor <evidence.json> --tsa URL [--ots]
```

- 키 파일(`K.bin`, `S.bin`)은 raw 32 B이고 **테스트 전용**이다. `--i-know-this-is-for-testing`이 없으면 거부하고 종료 코드 2. 실제 키를 파일로 두지 않는다. 제품은 웹/앱의 custody를 쓴다.
- `protect`는 입력 파일을 바꾸지 않고 `DIR/<stem>.marked.<json|csv>`와 `DIR/<stem>.evidence.json`을 새로 만든다. 둘 중 하나라도 이미 있으면 아무것도 쓰지 않고 종료 코드 2. `--exclusions`는 한 줄에 값 하나인 UTF-8 파일(빈 줄 무시).
- `created_claim`은 `--created-claim`으로 주거나, 생략하면 이 컴퓨터의 시계(UTC)다. 주장일 뿐 시점 증거가 아니다. 형식이 틀리면 core가 거부하고 종료 코드 2.
- `--source-claim`, `--captured-claim`, `--capture-method-claim`은 disclosure의 `suspect.*_claim`에 그대로 들어간다. 운영자 주장이며 아무도 검증하지 않는다(core도 형식을 검사하지 않는다).
- `check`는 `norea.check-report.v1` JSON을 stdout에 쓴다(종료 코드 0). `disclose`는 `--out`에 새 파일을 쓴다(이미 있으면 종료 코드 2). `disclose`는 matched가 아닌 canary를 공개하지 않는다. `--force`를 주면 공개하고, 그 항목은 검증에서 NOT REPRODUCED가 되어 `norea-verify`가 종료 코드 1을 낸다.
- `anchor`는 아직 구현되지 않았다(WP-08). 네트워크 요청 없이 종료 코드 3.
- 키, K_d, seed는 어떤 출력에도 쓰지 않고 사용 후 메모리에서 0으로 덮는다.
