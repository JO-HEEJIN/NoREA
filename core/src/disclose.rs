//! norea.disclosure.v1: build (operator, K_d) and verify (anyone, no secret).
//!
//! Spec: Fable_5_1/docs/protocol/disclosure-v1.md (§3 build, §4 verify, report
//! `norea.disclosure-report.v1`), CORE-API §1 disclose.rs.
//!
//! `verify_disclosure` never opens the blob: it only hashes it (evidence-v1
//! §10 step 4 via `verify_evidence`). The Merkle count is always the signed
//! `evidence.canary_count` (disclosure-v1 §4 3.a).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::check::{committed_rows, detect_suspect_kind, match_rows, match_rows_counted};
use crate::error::{Error, ErrorCode};
use crate::evidence::{
    anchors_consistent, check_created_claim, decode_hex32, hex, sha256_hex, verify_evidence, Evidence, EvidenceVerification,
    CANARY_KIND_RECORD_SHAPE_V1,
};
use crate::merkle::{audit_path, leaf_hash, verify_audit_path};
use crate::shape::threshold;
use crate::table::{canon_row, row_from_json, Cell, Row};
use crate::Key32;

pub const DISCLOSURE_SCHEMA: &str = "norea.disclosure.v1";
pub const DISCLOSURE_REPORT_SCHEMA: &str = "norea.disclosure-report.v1";

/// Operator claims about the suspect copy (§2 `suspect.*_claim`). Not verified by anyone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuspectMeta {
    pub source_claim: Option<String>,
    pub captured_claim: Option<String>,
    pub capture_method_claim: Option<String>,
}

fn bad_disclosure(m: &str) -> Error {
    Error::new(ErrorCode::BadDisclosure, m)
}

fn evidence_ok(v: &EvidenceVerification) -> bool {
    v.signature_ok && v.evidence_id_ok && v.blob_hash_ok
}

fn check_kind(ev: &Evidence) -> Result<(), Error> {
    if ev.canary_kind != CANARY_KIND_RECORD_SHAPE_V1 {
        return Err(Error::new(ErrorCode::BadEvidence, "unsupported canary_kind; v1 defines record.shape.v1 only"));
    }
    Ok(())
}

/// §3. Discloses the matched canaries (default) or `indices`. An index that is
/// not matched in `suspect` is refused unless `force`; forced items show up as
/// NOT REPRODUCED in `verify_disclosure`. Returns `norea.disclosure.v1` JSON.
pub fn disclose(
    ev: &Evidence,
    k_d: &Key32,
    suspect: &[u8],
    indices: Option<&[u32]>,
    meta: &SuspectMeta,
    created_claim: &str,
    force: bool,
) -> Result<String, Error> {
    check_created_claim(created_claim)?;
    check_kind(ev)?;
    if !evidence_ok(&verify_evidence(ev)) {
        return Err(Error::new(ErrorCode::BadEvidence, "evidence does not verify (signature, evidence_id or blob hash)"));
    }
    let (rows, shape) = committed_rows(ev, k_d).ok_or_else(|| {
        Error::new(ErrorCode::BadBlob, "canary blob does not open with this key or does not commit to canary_root")
    })?;
    let kind = detect_suspect_kind(suspect);
    let indexed: Vec<(u32, Row)> = rows.iter().cloned().enumerate().map(|(i, r)| (i as u32, r)).collect();
    let report = match_rows(suspect, kind, &indexed, &ev.marker_fields);

    let selected: Vec<u32> = match indices {
        None | Some([]) => report.matched.clone(),
        Some(list) => {
            let mut sel = list.to_vec();
            sel.sort_unstable();
            if sel.windows(2).any(|w| w[0] == w[1]) {
                return Err(Error::bad_input("indices must not repeat"));
            }
            if sel.iter().any(|&i| i >= ev.canary_count) {
                return Err(Error::bad_input("index out of range of canary_count"));
            }
            if !force {
                if let Some(i) = sel.iter().find(|i| !report.matched.contains(i)) {
                    return Err(bad_disclosure(&format!(
                        "canary {i} is not matched in the suspect; disclosing it needs force"
                    )));
                }
            }
            sel
        }
    };
    if selected.is_empty() {
        return Err(bad_disclosure("no matched canary to disclose"));
    }

    let leaves: Vec<[u8; 32]> = rows.iter().enumerate().map(|(i, r)| leaf_hash(i as u32, &canon_row(r))).collect();
    let disclosed: Vec<Value> = selected
        .iter()
        .map(|&i| {
            let canon = canon_row(&rows[i as usize]);
            let row: Value = serde_json::from_slice(&canon).expect("canon_row is JSON");
            let path: Vec<String> = audit_path(i as usize, &leaves).iter().map(|p| hex(p)).collect();
            json!({ "index": i, "row": row, "path": path })
        })
        .collect();

    let mut sus = Map::new();
    sus.insert("sha256".into(), Value::from(sha256_hex(suspect)));
    sus.insert("kind".into(), Value::from(kind.as_str()));
    for (k, v) in [
        ("source_claim", &meta.source_claim),
        ("captured_claim", &meta.captured_claim),
        ("capture_method_claim", &meta.capture_method_claim),
    ] {
        if let Some(v) = v {
            sus.insert(k.into(), Value::from(v.as_str()));
        }
    }
    let out = json!({
        "schema": DISCLOSURE_SCHEMA,
        "created_claim": created_claim,
        "evidence": serde_json::to_value(ev).expect("Evidence serializes"),
        "suspect": Value::Object(sus),
        "disclosed": disclosed,
        "shape": shape,
    });
    Ok(out.to_string())
}

struct Item {
    index: u32,
    row: Row,
    merkle_ok: bool,
}

fn parse_items(v: &Value, ev: &Evidence) -> Result<Vec<Item>, Error> {
    let arr = v.as_array().ok_or_else(|| bad_disclosure("disclosed must be an array"))?;
    let root = decode_hex32(&ev.canary_root);
    let mut items = Vec::with_capacity(arr.len());
    let mut prev: Option<u32> = None;
    for d in arr {
        let o = d.as_object().ok_or_else(|| bad_disclosure("disclosed entry must be an object"))?;
        let index = o
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or_else(|| bad_disclosure("disclosed index must be a u32"))?;
        if prev.is_some_and(|p| index <= p) {
            return Err(bad_disclosure("disclosed indices must be ascending without repeats"));
        }
        prev = Some(index);
        let row = o
            .get("row")
            .filter(|r| r.is_object())
            .ok_or_else(|| bad_disclosure("disclosed row must be an object"))
            .and_then(|r| row_from_json(r).map_err(|_| bad_disclosure("disclosed row must be an object")))?;
        let path = o
            .get("path")
            .and_then(Value::as_array)
            .ok_or_else(|| bad_disclosure("disclosed path must be an array"))?
            .iter()
            .map(|p| p.as_str().and_then(decode_hex32).ok_or_else(|| bad_disclosure("path entries must be hex64")))
            .collect::<Result<Vec<[u8; 32]>, Error>>()?;
        // 3.b, 3.c with the signed count (3.a), 3.d markers present.
        let leaf = leaf_hash(index, &canon_row(&row));
        let path_ok = root.is_some_and(|r| verify_audit_path(index, ev.canary_count, &leaf, &path, &r));
        let markers_ok = ev
            .marker_fields
            .iter()
            .all(|f| matches!(row.0.get(f.as_str()), Some(c) if !matches!(c, Cell::Missing | Cell::Null)));
        items.push(Item { index, row, merkle_ok: path_ok && markers_ok });
    }
    Ok(items)
}

/// shape-v1 §6.1 bound inputs from the (operator-supplied) shape: the sum of
/// the t smallest marker `space_log2_x100`, with m and t. `None` if a marker
/// has no `space_log2_x100`.
fn weakest_sum_x100(shape: Option<&Value>, markers: &[String]) -> Option<(i64, usize, usize)> {
    let fields = shape?.get("fields")?.as_object()?;
    let mut xs: Vec<i64> =
        markers.iter().map(|m| fields.get(m)?.get("space_log2_x100")?.as_i64()).collect::<Option<_>>()?;
    let (m, t) = (markers.len(), threshold(markers.len()));
    if t == 0 {
        return None;
    }
    xs.sort_unstable();
    Some((xs[..t].iter().sum(), m, t))
}

fn binom(m: usize, t: usize) -> u64 {
    (0..t).fold(1u64, |acc, k| acc * (m - k) as u64 / (k + 1) as u64)
}

/// The probability line of disclosure-v1 §4. `x = Σ_t − log2 C(m,t)`.
fn probability_line(sum_x100: i64, m: usize, t: usize, records: Option<usize>, n: u32) -> String {
    let c = binom(m, t);
    let x = sum_x100 as f64 / 100.0 - (c as f64).log2();
    let mut line = format!(
        "확률: 판정 기준(marker {m}개 중 {t}개) 아래 한 canary가 독립 레코드 하나와 우연히 일치할 확률의 생성기 모델 상한은 2^-{x:.2}(가장 약한 marker {t}개 기준, 조합 수 C({m},{t})={c} 반영)이다."
    );
    match records {
        Some(r) => {
            let y = n as f64 * r as f64 * 2f64.powf(-x);
            line.push_str(&format!(
                " 사본 레코드 R={r}개와 canary n={n}개에 대한 우연 일치 기대 수 상한은 n·R·2^-X = {n}·{r}·2^-{x:.2} = {y:.3e}이다."
            ));
        }
        None => line.push_str(" 사본은 텍스트 경로로 대조했으므로 레코드 수 불명이고 기대 수는 쓰지 않는다."),
    }
    line.push_str(" 이것은 생성기 모델 기준의 상한이지 실제 세계 확률이 아니다. 근거인 shape 정보는 운영자가 disclosure에 넣은 것이며 이 도구가 검증하지 않았다.");
    line
}

/// What the statement is built from.
struct Facts<'a> {
    ver: &'a EvidenceVerification,
    ev: &'a Evidence,
    suspect_hash_ok: bool,
    n: usize,
    merkle_ok: usize,
    matched: usize,
    not_reproduced: &'a [u32],
    /// (Σ of t smallest space_log2_x100, m, t) and R
    bound: Option<(i64, usize, usize)>,
    records: Option<usize>,
}

fn statement(f: &Facts) -> String {
    let Facts { ver, ev, suspect_hash_ok, n, merkle_ok, matched, not_reproduced, bound, records } = *f;
    let mut s: Vec<String> = Vec::new();
    let integrity = evidence_ok(ver) && suspect_hash_ok && merkle_ok == n && n > 0 && anchors_consistent(ver);
    if integrity {
        s.push("무결성: PASS".into());
    } else {
        let mut why = Vec::new();
        if !evidence_ok(ver) {
            why.push("증거(evidence) 검증 실패(서명, evidence_id 또는 blob 해시)");
        }
        if !suspect_hash_ok {
            why.push("사본 해시 불일치");
        }
        if merkle_ok < n {
            why.push("Merkle 검증 실패 항목 있음");
        }
        if n == 0 {
            why.push("공개된 canary 없음");
        }
        if !anchors_consistent(ver) {
            why.push("anchor imprint가 이 증거와 불일치");
        }
        s.push(format!("무결성: FAIL ({}). 이 disclosure는 그대로 증거로 쓸 수 없다.", why.join(", ")));
    }
    if ver.signature_ok {
        let fp = B64.decode(&ev.vk_b64).map(|vk| sha256_hex(&vk)[..16].to_string()).unwrap_or_default();
        s.push(format!("서명: ML-DSA-65 서명이 유효하다. 공개키 지문(SHA-256(vk) 앞 16 hex): {fp}."));
    } else {
        s.push("서명: 유효하지 않다.".into());
    }
    s.push(format!("evidence_id: {}", ev.evidence_id));
    let mut time_proven = false;
    for (k, a) in ver.anchors.iter().enumerate() {
        match (&a.gen_time, a.imprint_ok) {
            (Some(t), true) => {
                time_proven = true;
                s.push(format!(
                    "시점: TSA 토큰의 genTime은 {t}이며 imprint가 서명된 증거와 일치한다. TSA 인증서 체인은 이 도구가 검증하지 않았다(disclosure-v1 §5)."
                ));
            }
            (Some(_), false) if a.error.is_none() => s.push(format!(
                "시점: anchor {k}({})의 imprint가 이 증거의 anchor_subject와 일치하지 않는다. 다른 증거의 anchor다.",
                a.kind
            )),
            _ => s.push(format!("시점: anchor {k}({})를 검증하지 못했다.", a.kind)),
        }
    }
    if !time_proven {
        s.push("시점: 이 증거는 생성 시점을 증명하지 않는다. created_claim은 운영자 기기 시계의 주장일 뿐이다.".into());
    }
    s.push(if suspect_hash_ok {
        "사본: SHA-256이 disclosure의 suspect.sha256과 일치한다.".into()
    } else {
        "사본: SHA-256이 disclosure의 suspect.sha256과 일치하지 않는다. 제출된 사본이 아니다.".into()
    });
    s.push(format!("Merkle: 공개된 canary {n}개 중 {merkle_ok}개의 path가 서명된 canary_root와 일치한다."));
    s.push(format!("재현: 공개된 canary {n}개 중 {matched}개가 사본에서 재현되었다."));
    if !not_reproduced.is_empty() {
        let l: Vec<String> = not_reproduced.iter().map(|i| i.to_string()).collect();
        s.push(format!("NOT REPRODUCED: index {}", l.join(", ")));
    }
    if let Some((sum, m, t)) = bound {
        s.push(probability_line(sum, m, t, records, ev.canary_count));
    }
    s.push("주장: suspect의 *_claim 필드(출처, 포착 시점, 방법)는 운영자 주장이며 이 도구가 검증하지 않았다.".into());
    s.join("\n")
}

/// §4, no secret. Structural problems (not JSON, wrong schema, malformed
/// fields, indices not ascending/unique) are `BadDisclosure`. Verification
/// failures are reported: evidence failure makes the statement `무결성: FAIL`.
/// Returns `norea.disclosure-report.v1` JSON.
pub fn verify_disclosure(disclosure_json: &str, suspect: &[u8]) -> Result<String, Error> {
    let d: Value = serde_json::from_str(disclosure_json).map_err(|_| bad_disclosure("disclosure is not JSON"))?;
    let d = d.as_object().ok_or_else(|| bad_disclosure("disclosure must be a JSON object"))?;
    if d.get("schema").and_then(Value::as_str) != Some(DISCLOSURE_SCHEMA) {
        return Err(bad_disclosure("schema must be norea.disclosure.v1"));
    }
    let ev: Evidence = d
        .get("evidence")
        .cloned()
        .and_then(|e| serde_json::from_value(e).ok())
        .ok_or_else(|| bad_disclosure("evidence is missing or malformed"))?;
    check_kind(&ev)?;
    let claimed = d
        .get("suspect")
        .and_then(|s| s.get("sha256"))
        .and_then(Value::as_str)
        .ok_or_else(|| bad_disclosure("suspect.sha256 is missing"))?;
    let items = parse_items(d.get("disclosed").unwrap_or(&Value::Null), &ev)?;
    let shape = d.get("shape").filter(|s| s.is_object());

    // 1. evidence (evidence-v1 §10), 2. suspect hash
    let ver = verify_evidence(&ev);
    let suspect_hash_ok = sha256_hex(suspect) == claimed;
    // 4. reproduce the match with the disclosed rows only
    let kind = detect_suspect_kind(suspect);
    let rows: Vec<(u32, Row)> = items.iter().map(|it| (it.index, it.row.clone())).collect();
    let (m, records) = match_rows_counted(suspect, kind, &rows, &ev.marker_fields);

    let mut out_items = Vec::with_capacity(items.len());
    let mut not_reproduced = Vec::new();
    for it in &items {
        let matched = m.matched.contains(&it.index);
        if !matched {
            not_reproduced.push(it.index);
        }
        let found = m.per_index.get(&it.index).map(|p| p.found.clone()).unwrap_or_default();
        out_items.push(json!({ "index": it.index, "merkle_ok": it.merkle_ok, "matched": matched, "found": found }));
    }
    let n = items.len();
    let merkle_ok = items.iter().filter(|i| i.merkle_ok).count();
    let matched = n - not_reproduced.len();
    let st = statement(&Facts {
        ver: &ver,
        ev: &ev,
        suspect_hash_ok,
        n,
        merkle_ok,
        matched,
        not_reproduced: &not_reproduced,
        bound: weakest_sum_x100(shape, &ev.marker_fields),
        records,
    });
    let integrity_ok = evidence_ok(&ver) && suspect_hash_ok && n >= 1 && merkle_ok == n && anchors_consistent(&ver);
    let report = json!({
        "schema": DISCLOSURE_REPORT_SCHEMA,
        "evidence": {
            "signature_ok": ver.signature_ok,
            "evidence_id_ok": ver.evidence_id_ok,
            "blob_hash_ok": ver.blob_hash_ok,
            "evidence_id": ev.evidence_id,
            "anchors": serde_json::to_value(&ver.anchors).expect("AnchorCheck serializes"),
        },
        "suspect_hash_ok": suspect_hash_ok,
        "disclosed": out_items,
        "summary": { "disclosed": n, "merkle_ok": merkle_ok, "matched": matched, "not_reproduced": not_reproduced.len() },
        "verdict": { "integrity_ok": integrity_ok, "all_reproduced": not_reproduced.is_empty() },
        "statement": st,
    });
    Ok(report.to_string())
}
