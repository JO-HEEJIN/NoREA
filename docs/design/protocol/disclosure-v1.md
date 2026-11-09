# Disclosure package v1 (`norea.disclosure.v1`) 와 제3자 검증

Status: **Frozen** (2026-11-09, WP-04 수락). 동결 대상은 §2 패키지 구조, §3 생성 규칙, §4 검증 절차와 report 키(`verdict` 포함). statement는 "반드시 포함할 내용"이 고정이고 문구는 다듬을 수 있다. 바꾸려면 `norea.disclosure.v2`. 규범 문서.

## 1. 목적

분쟁 때 운영자는 "내 evidence에 commit된 canary 중 이것들이 상대방 사본에 있다"를 **비밀(K, K_d) 없이** 제3자(법원 감정인, 상대방 변호인, 플랫폼 신고 창구)가 검증할 수 있는 형태로 제출한다. 공개하는 canary는 일치한 것만이고, 나머지 canary는 Merkle path 덕분에 비밀로 남는다. 그래서 같은 데이터셋의 evidence를 다음 분쟁에도 쓸 수 있다.

## 2. 파일

JSON object 하나 + 의심 사본 파일(별도, 해시로 참조). 운영자는 두 파일을 함께 제출한다.

```json
{
  "schema": "norea.disclosure.v1",
  "created_claim": "2026-12-01T09:00:00Z",
  "evidence": { ...norea.evidence.v1 전체, anchors 포함, canary_blob_b64 포함... },
  "suspect": {
    "sha256": "<hex64>",
    "kind": "json|csv|text",
    "source_claim": "https://example.com/data.json",
    "captured_claim": "2026-11-30T15:00:00Z",
    "capture_method_claim": "browser save-as"
  },
  "disclosed": [
    { "index": 12, "row": { ...canary row object... }, "path": ["<hex64>", "..."] }
  ],
  "shape": { ...canary-record-shape-v1 §6 shape summary, 선택... },
  "operator_note": "자유 텍스트, 선택"
}
```

- `evidence`는 수정 없이 통째로 넣는다. `canary_blob_b64`는 암호화돼 있어 넣어도 안전하고, verifier가 `canary_blob_sha256`을 대조할 수 있다.
- `disclosed[].row`는 canary row object. verifier는 `canon(row)`을 다시 계산한다(evidence-v1 §7.1).
- `disclosed[].path`는 RFC 9162 audit path, leaf에서 root 방향 순서.
- `disclosed`는 index 오름차순. 중복 index 금지. 운영자가 공개하기로 한 canary만 넣는다(보통 matched 전부, 때로는 일부).
- `*_claim` 필드는 운영자 주장이고 verifier가 검증하지 않는다. 사본 포착 시점은 공증, 플랫폼 타임스탬프, 웹 아카이브 등 외부 증거로 보강해야 한다(이 제품 범위 밖).

## 3. 생성 (core, K_d 필요)

```
disclose(ev, K_d, suspect_bytes, indices):
  rows = decrypt_blob(ev, K_d).rows ; root 재계산 == ev.canary_root 아니면 에러
  report = check(suspect_bytes, rows, ev.marker_fields)
  indices가 비어 있으면 indices = report.matched_indices
  indices ⊄ report.matched_indices 이면 에러 (일치하지 않은 canary는 공개하지 않는다. 운영자가 굳이 원하면 force 옵션, UI는 경고)
  for i in indices: path_i = PATH(i, leaves)
  return Disclosure{...}
```

## 4. 검증 (누구나, 비밀 불필요)

`verify_disclosure(disc, suspect_bytes)` → `norea.disclosure-report.v1`

1. `evidence` 검증: evidence-v1 §10 전부. 하나라도 실패하면 전체 FAIL.
2. `sha256(suspect_bytes) == disc.suspect.sha256`. 아니면 FAIL.
3. 각 `disclosed[j]`:
   a. `0 ≤ index < canary_count`, 오름차순, 중복 없음. 여기와 c의 `canary_count`는 반드시 **서명된 `evidence.canary_count`**다. disclosure 패키지의 다른 어떤 값도 count로 쓰지 않는다. inclusion proof는 count를 path의 좌우 모양으로만 묶으므로(RFC 9162 §2.1.3.2), 모양이 같은 다른 count로도 proof가 통과한다. count의 무결성은 서명이 담보한다(WP-03 QUESTION 2).
   b. `leaf = SHA-256(0x00 || u32be(index) || utf8(canon(row)))`.
   c. RFC 9162 §2.1.3.2로 `path`를 적용해 root 계산:
      ```
      if index >= canary_count: FAIL
      fn = index; sn = canary_count - 1; r = leaf
      for p in path:
        if sn == 0: FAIL (path too long)
        if LSB(fn) == 1 or fn == sn:
          r = H(0x01 || p || r)
          if LSB(fn) == 0:
            # fn과 sn을 같이 오른쪽으로 민다. LSB(fn)이 1이 되거나 fn이 0이 될 때까지
            while fn != 0 and LSB(fn) == 0: fn >>= 1; sn >>= 1
        else:
          r = H(0x01 || r || p)
        fn >>= 1; sn >>= 1
      sn == 0 이고 r == canary_root 여야 PASS
      ```
      구현은 RFC 9162 §2.1.3.2 원문을 따르고, 위 의사코드와 원문이 다르면 원문이 맞다. 테스트는 n=1..9 모든 index에 대해 path 생성→검증 round trip과, path 한 원소 변조 시 실패를 확인한다.
   d. `row`의 marker 필드 값이 모두 존재(결측 아님). 위반은 `merkle_ok = false`로 보고한다(§5.3이 marker 결측 canary를 만들지 않으므로 committed row가 여기 걸리면 변조다).
4. 대조: `check(suspect_bytes, disclosed rows, evidence.marker_fields)`를 공개된 row들만으로 수행(canary-record-shape-v1 §7). 각 disclosed canary가 `matched`인지 보고. 운영자가 주장한 일치가 재현되지 않으면 그 항목은 `NOT REPRODUCED`.
5. 리포트:
```json
{ "schema": "norea.disclosure-report.v1",
  "evidence": { "signature_ok": true, "evidence_id_ok": true, "blob_hash_ok": true, "evidence_id": "...",
                "anchors": [ { "kind": "rfc3161", "imprint_ok": true, "gen_time": "2026-11-08T12:00:03Z", "chain_verified": false, "error": null } ] },
  "suspect_hash_ok": true,
  "disclosed": [ { "index": 12, "merkle_ok": true, "matched": true, "found": ["addr","area_m2"] } ],
  "summary": { "disclosed": 29, "merkle_ok": 29, "matched": 29, "not_reproduced": 0 },
  "verdict": { "integrity_ok": true, "all_reproduced": true },
  "statement": "..." }
```
`evidence`는 evidence-v1 §10 결과 전부(`AnchorCheck` 그대로, `error` 포함). `verdict.integrity_ok` = `signature_ok && evidence_id_ok && blob_hash_ok && suspect_hash_ok && summary.disclosed >= 1 && summary.merkle_ok == summary.disclosed && anchors_consistent`(공개 항목 0개인 패키지는 `disclose`가 만들지 않으며 verifier는 FAIL로 본다. statement 첫 줄과 항상 같은 판정이어야 한다). `anchors_consistent` = anchors 중 `error`가 없는(검증을 실제로 수행한) 원소는 모두 `imprint_ok == true`. `error`가 있는 anchor(검증 미구현, 토큰 파싱 불가)는 판정에 넣지 않고 N/A로 표시한다. 즉 anchor는 시점을 더해 줄 뿐 없어도 PASS이지만, 이 증거의 것이 아닌 anchor가 붙어 있으면 FAIL이다(2026-11-09 WP-05 후 보완. WP-08 전까지 모든 anchor가 `error`를 가지므로 현재 구현과 결과가 같다). `verdict.all_reproduced` = `summary.not_reproduced == 0`. CLI 종료 코드는 둘 다 true면 0, 아니면 1, 구조 오류(`Err`)는 2. 구조 문제(JSON 아님, schema, 필드 형식, index 순서)는 `Err(BadDisclosure)`이고, 검증 실패(서명, 해시, Merkle, 재현)는 report로 낸다. verifier는 `suspect.kind`를 믿지 않고 사본 바이트에서 다시 감지한다. `canary_kind != record.shape.v1`은 `BadEvidence`.

`statement`는 verifier가 생성하는 사람이 읽는 한국어 줄 단위 문장이다. 첫 줄은 `무결성: PASS` 또는 `무결성: FAIL (이유)`. 반드시 포함할 내용:
- 서명이 유효한 공개키 지문(SHA-256(vk) 앞 16 hex)
- anchor가 없으면 "이 증거는 생성 시점을 증명하지 않는다"
- anchor가 있으면 "TSA 토큰의 genTime은 X이며 imprint가 서명된 증거와 일치한다. TSA 인증서 체인은 이 도구가 검증하지 않았다(§5)"
- "공개된 canary N개 중 M개가 사본에서 재현되었다"
- shape가 있으면 확률 줄(canary-record-shape-v1 §6.1의 X, m, t): "판정 기준(marker m개 중 t개) 아래 한 canary가 독립 레코드 하나와 우연히 일치할 확률의 생성기 모델 상한은 2^-X(가장 약한 marker t개 기준, 조합 수 C(m,t) 반영)이다. 사본 레코드 R개와 canary n개에 대한 우연 일치 기대 수 상한은 n·R·2^-X = Y이다. 이것은 생성기 모델 기준의 상한이지 실제 세계 확률이 아니다. 근거인 shape 정보는 운영자가 disclosure에 넣은 것이며 이 도구가 검증하지 않았다." R은 verifier가 사본에서 추출한 레코드 수(CSV는 첫 행 포함. 텍스트 경로면 "레코드 수 불명"으로 쓰고 기대 수 줄을 생략). n은 서명된 `evidence.canary_count`(공개된 수가 아니다). Y는 유효숫자 4자리 지수 표기(`4.120e-3`).
- `suspect.*_claim`은 운영자 주장이며 미검증이라는 문장. `NOT REPRODUCED: index ...` 줄(있으면).

## 5. TSA 인증서 체인 검증 (수동)

verifier CLI는 `--export-anchors DIR`로 각 토큰을 `anchor-<k>.tsr`(DER)로 쓰고 anchor_subject를 `subject.bin`으로 쓴 뒤 아래를 안내한다:
```
openssl ts -verify -digest <anchor_subject_hex> -in anchor-0.tsr -token_in -CAfile <TSA CA bundle>
```
OTS는 `ots verify`에 `subject.bin`을 넘긴다. 이 단계는 TSA가 정한 CA 번들이 필요해 자동화하지 않는다(v1). verifier 리포트의 `chain_verified`는 항상 false이고 리포트가 그 이유를 적는다.

## 6. 운영자 안내 문구 (UI)

- 공개 전: "공개하는 canary는 상대방이 알게 되어 다음 사본에서 제거될 수 있습니다. 일치한 canary만 공개하고, 전체 canary의 일부만 공개하는 것을 권합니다."
- 패키지에 비밀은 없다는 점: "이 파일에는 마스터 키나 서명키가 들어 있지 않습니다. 공개되지 않은 canary는 암호화된 상태로만 포함됩니다."
