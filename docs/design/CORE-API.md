# noreacore / norea-web 공개 API

손이 구현할 함수 목록과 시그니처. 이름을 바꾸지 않는다(바인딩, CLI, 테스트가 이 이름을 부른다). 반환 JSON의 스키마는 protocol/ 문서가 정의한다. 시그니처를 바꿔야 하면 보고서에 `QUESTION:`으로 올린다.

공통: `type Key32 = [u8; 32]`. 에러는 `noreacore::Error { code: ErrorCode, message: String }`, `ErrorCode ∈ {BadInput, NoMarker, CanaryExhausted, BadEvidence, BadSignature, BadBlob, BadDisclosure, BadAnchor}`. 메시지는 영어 기술 문구(UI가 한국어로 바꾼다). 메시지에 비밀, 입력 데이터 값, 경로를 넣지 않는다.

## 1. noreacore (Rust)

```rust
// ---- table.rs (WP-01)
pub enum Format { Json, Csv }
pub fn detect_format(bytes: &[u8]) -> Format;                      // JSON 파싱 성공이면 Json, 아니면 Csv
pub enum Cell { Str(String), Num { text: String, scale: u8 }, Bool(bool), Null, Missing, Opaque(serde_json::Value) }
    // Num.text는 지수 없는 10진 텍스트(serde_json Number::to_string()). 지수 표기 숫자는 parse 단계에서 Opaque(Value::Number)가 된다(WP-01 결정).
    // serde_json은 arbitrary_precision + preserve_order. 중첩 object 키 순서는 출력에 보존되고 canon_row/canon_val은 명시적으로 바이트 정렬한다.
pub struct Row(pub indexmap::IndexMap<String, Cell>);              // 필드 순서 유지. 또는 Vec<(String, Cell)>
pub struct Table { pub fields: Vec<String>, pub rows: Vec<Row>, style: Style /* 비공개: 들여쓰기, 줄바꿈, BOM */ }
pub fn parse_table(bytes: &[u8], format: Format) -> Result<Table, Error>;
pub fn serialize_with_inserts(original: &[u8], table: &Table, inserts: &[(usize, Row)]) -> Result<Vec<u8>, Error>;
    // inserts: (최종 배열에서의 위치, 행). JSON: 전체 재직렬화. CSV: 원본 바이트 splice. ADR-0013
pub fn canon_row(row: &Row) -> Vec<u8>;                            // evidence-v1 §7.1
pub fn row_from_json(v: &serde_json::Value) -> Result<Row, Error>; // disclosure의 row 파싱용

// ---- norm.rs (WP-02)
pub fn normalize_text(s: &str) -> String;     // shape-v1 §7.1 문자열 규칙: NFC → trim → 공백 run을 U+0020 하나로 → 전각 ASCII(U+FF01..FF5E) → 반각. 대조와 충돌 회피 전용
pub fn normalize_number(s: &str) -> Option<String>;  // shape-v1 §7.1 숫자 규칙: 천단위 `,`와 공백 제거 후 10진 파싱 가능하면 정규 텍스트(-?digits[.digits]) 반환

// ---- shape.rs (WP-02)
pub struct Shape { /* 필드별 FieldShape, rows */ }
pub fn infer_shape(table: &Table) -> Shape;
pub fn auto_markers(shape: &Shape) -> Result<Vec<String>, Error>;  // NoMarker
pub fn threshold(markers_len: usize) -> usize { markers_len.min(2) }
pub fn inspect(bytes: &[u8], format: Option<Format>) -> Result<String, Error>;   // InspectResult JSON (platform-contract)
pub fn shape_summary(shape: &Shape, markers: &[String]) -> serde_json::Value;    // shape-v1 §6

// ---- canary.rs (WP-02)
pub struct MarkOptions { pub n: u32, pub marker_fields: Option<Vec<String>>, pub exclusions: Vec<String> }
pub struct MarkOutput { pub marked: Vec<u8>, pub canaries: Vec<Row>, pub markers: Vec<String>, pub shape_summary: serde_json::Value, pub format: Format }
pub fn mark(original: &[u8], format: Format, k_d: &Key32, opts: &MarkOptions) -> Result<MarkOutput, Error>;
pub fn draw(k_d: &Key32, label: &str, i: u32, attempt: u8, ctr: u32) -> u64;    // shape-v1 §5.1, 테스트가 직접 부름

// ---- merkle.rs (WP-03)
pub fn leaf_hash(index: u32, canon: &[u8]) -> [u8; 32];
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32];                // leaves.len() >= 1
pub fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]>;
pub fn verify_audit_path(index: u32, count: u32, leaf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool;

// ---- blob.rs (WP-03)
pub fn derive_blob_key(k_d: &Key32, marked_sha256: &[u8; 32]) -> zeroize::Zeroizing<Key32>;   // K_blob (evidence-v1 §2). vector의 k_blob_hex용으로 공개
pub fn seal_blob(k_d: &Key32, dataset_id: &str, marked_sha256: &[u8; 32], canaries: &[Row], shape_summary: &serde_json::Value) -> Vec<u8>;
pub fn open_blob(k_d: &Key32, dataset_id: &str, marked_sha256: &[u8; 32], blob: &[u8]) -> Result<(Vec<Row>, serde_json::Value), Error>;

// ---- sign.rs (WP-03)
pub const SIG_CTX: &[u8] = b"norea/evidence/v1";
pub struct SoftwareSigner { /* ZeroizeOnDrop */ }
impl SoftwareSigner { pub fn from_seed(seed: &Key32) -> Self; pub fn verifying_key_bytes(&self) -> Vec<u8>; pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>; }
pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool;

// ---- evidence.rs (WP-03)
pub const EVIDENCE_SCHEMA: &str = "norea.evidence.v1";
pub const CANARY_KIND_RECORD_SHAPE_V1: &str = "record.shape.v1";
pub fn derive_dataset_key(k: &Key32, dataset_id: &str) -> Key32;
pub struct Anchor { pub kind: String, #[serde(flatten)] pub rest: serde_json::Map<String, Value> }   // kind별 필드는 evidence-v1 §8.2
pub struct Evidence { /* evidence-v1 §4 필드 전부, serde */ }
impl Evidence {
    pub fn signing_payload(&self) -> Vec<u8>;
    pub fn evidence_id(&self) -> String;                                    // hex(sha256(payload))
    pub fn anchor_subject(&self) -> Result<[u8; 32], Error>;               // sig 필요
    pub fn validate_fields(&self) -> Result<(), Error>;                     // §4, §5 규칙
}
pub struct Prepared { pub evidence: Evidence, pub marked: Vec<u8>, pub canaries: Vec<Row> }
pub fn prepare_evidence(original: &[u8], format: Format, dataset_id: &str, opts: &MarkOptions, k_d: &Key32, created_claim: &str) -> Result<Prepared, Error>;
pub fn finalize_evidence(ev: Evidence, vk: &[u8], sig: &[u8]) -> Result<Evidence, Error>;
pub fn build_evidence(original: &[u8], format: Format, dataset_id: &str, opts: &MarkOptions, k_d: &Key32, created_claim: &str, signer: &SoftwareSigner) -> Result<Prepared, Error>;
pub struct EvidenceVerification { pub signature_ok: bool, pub evidence_id_ok: bool, pub blob_hash_ok: bool, pub anchors: Vec<AnchorCheck>, pub has_anchors: bool }
pub struct AnchorCheck { pub kind: String, pub imprint_ok: bool, pub gen_time: Option<String>, pub chain_verified: bool /* 항상 false */, pub error: Option<String> }
pub fn verify_evidence(ev: &Evidence) -> EvidenceVerification;
pub fn sha256_hex(b: &[u8]) -> String;

// ---- check.rs (WP-04)
pub enum SuspectKind { Json, Csv, Text }
pub fn detect_suspect_kind(bytes: &[u8]) -> SuspectKind;
pub struct MatchResult { pub matched: Vec<u32>, pub partial: Vec<u32>, pub per_index: BTreeMap<u32, PerIndex> }
pub struct PerIndex { pub found: Vec<String>, pub record_hint: Option<String> }
pub fn match_rows(suspect: &[u8], kind: SuspectKind, rows: &[(u32, Row)], markers: &[String]) -> MatchResult;   // 비밀 없음
pub fn check(suspect: &[u8], k_d: &Key32, ev: &Evidence) -> Result<String, Error>;   // norea.check-report.v1 JSON

// ---- disclose.rs (WP-04)
pub struct SuspectMeta { pub source_claim: Option<String>, pub captured_claim: Option<String>, pub capture_method_claim: Option<String> }
pub fn disclose(ev: &Evidence, k_d: &Key32, suspect: &[u8], indices: Option<&[u32]>, meta: &SuspectMeta, created_claim: &str, force: bool) -> Result<String, Error>;  // norea.disclosure.v1 JSON
pub fn verify_disclosure(disclosure_json: &str, suspect: &[u8]) -> Result<String, Error>;   // norea.disclosure-report.v1 JSON

// ---- anchor.rs (WP-08)
pub fn tsa_request_der(subject: &[u8; 32], nonce: Option<&[u8]>) -> Vec<u8>;     // RFC 3161 TimeStampReq
pub struct TsaToken { pub imprint: [u8; 32], pub gen_time: String, pub token_der: Vec<u8> }
pub fn tsa_parse_response(der: &[u8]) -> Result<TsaToken, Error>;                   // status 확인 + token 추출 + TSTInfo 파싱
pub fn attach_anchor(ev: &mut Evidence, anchor: Anchor) -> Result<(), Error>;      // rfc3161: imprint == anchor_subject 확인
```

## 2. norea-web (wasm-bindgen, JS 이름)

비밀 인자는 `Vec<u8>`로 받아 zeroize(ADR-0012). 반환 JSON은 string.

| JS 이름 | 시그니처 | 비밀 |
|---|---|---|
| `inspect(input: Uint8Array, format?: string) -> string` | InspectResult JSON | |
| `protect(input: Uint8Array, masterK: Uint8Array, seed: Uint8Array, datasetId: string, optionsJson: string, createdClaim: string) -> ProtectResult` | `ProtectResult { marked: Uint8Array (getter), evidenceJson: string (getter), free() }` | K, seed |
| `check(suspect: Uint8Array, masterK: Uint8Array, evidenceJson: string) -> string` | check-report JSON | K |
| `disclose(evidenceJson: string, masterK: Uint8Array, suspect: Uint8Array, indicesJson: string, metaJson: string, createdClaim: string, force: boolean) -> string` | disclosure JSON | K |
| `verifyEvidence(evidenceJson: string) -> string` | EvidenceVerification JSON | |
| `verifyDisclosure(disclosureJson: string, suspect: Uint8Array) -> string` | disclosure-report JSON | |
| `anchorSubjectHex(evidenceJson: string) -> string` | | |
| `tsaRequest(evidenceJson: string, nonce: Uint8Array) -> Uint8Array` | DER | |
| `attachAnchor(evidenceJson: string, anchorJson: string) -> string` | evidence JSON | |
| `verifyingKey(seed: Uint8Array) -> Uint8Array` | 1952 B | seed |
| `sha256Hex(bytes: Uint8Array) -> string` | | |
| `passphraseKek(passphrase: string, salt: Uint8Array) -> Uint8Array` | Argon2id 32 B | |

`optionsJson`: `{"n": 32, "markerFields": ["addr","area_m2"] | null, "exclusions": ["..."], "format": "json"|"csv"|null}`.

`metaJson`(disclose, 2026-11-09 머리 결정): `{"sourceClaim": "...", "capturedClaim": "YYYY-MM-DDTHH:MM:SSZ", "captureMethodClaim": "..."}`. 셋 다 선택이고 없으면 빈 문자열. core `SuspectMeta`의 snake_case 필드로 매핑한다.

에러: 바인딩은 `JsError`를 던지고 메시지는 `CODE: message`(CODE는 core `ErrorCode` 이름 또는 `ANCHOR_UNAVAILABLE`). platform-web이 CODE를 잘라 `error.code`로, 나머지를 한국어 문구로 바꾼다.

WP-08 전 상태: `tsaRequest`, `attachAnchor`는 core `anchor.rs`가 없으므로 `ANCHOR_UNAVAILABLE: anchor not implemented until WP-08`을 던지는 바인딩으로 둔다(함수 표면 12개는 유지). WP-08이 본문을 교체한다.

## 3. CLI (WP-05)

```
norea-verify evidence <evidence.json> [--json]                # 비밀 없음. --json은 EvidenceVerification JSON
norea-verify disclosure <disclosure.json> <suspect-file> [--export-anchors DIR] [--json]
norea inspect <input> [--format json|csv]
norea protect <input> --dataset-id ID --n N [--markers a,b] [--exclusions file] [--created-claim RFC3339Z] --key-file K.bin --seed-file S.bin --out-dir DIR   # 개발·테스트용. 키 파일은 테스트 전용임을 --i-know-this-is-for-testing 플래그로 강제
norea check <suspect> <evidence.json> --key-file K.bin
norea disclose <evidence.json> <suspect> --key-file K.bin [--indices 1,2,3] [--source-claim S] [--captured-claim RFC3339Z] [--capture-method-claim M] [--created-claim RFC3339Z] [--force] --out disclosure.json
norea anchor <evidence.json> --tsa URL [--ots]                  # 네트워크. CLI는 relay 없이 직접
```
WP-05에서 정한 것(2026-11-09): `protect` 출력은 `DIR/<stem>.marked.<json|csv>`와 `DIR/<stem>.evidence.json`(pretty, LF). 기존 파일은 덮어쓰지 않는다(종료 2). `--exclusions`는 UTF-8, 한 줄에 값 하나. `--created-claim`이 없으면 시스템 시계 UTC. `check`는 report를 내면 종료 0. 종료 코드 규칙은 disclosure-v1 §4. anchor 결과는 WP-08 전까지 N/A로 표시한다. `--export-anchors`는 rfc3161을 `anchor-<k>.tsr`, ots를 `anchor-<k>.ots`로 쓰고 `subject.bin`, `README.txt`(openssl / ots 명령 안내)를 만든다.
`norea`(개발 CLI)는 제품이 아니다. 제품은 `norea-verify`와 웹/앱이다. 그래도 테스트와 감정인의 재현에 쓰이므로 같은 품질로 만든다.
