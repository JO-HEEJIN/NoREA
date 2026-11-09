//! norea.evidence.v1: prepare/finalize/build, signing payload, verify.
//!
//! Spec: Fable_5_1/docs/protocol/evidence-v1.md (normative), ADR-0005 (seam),
//! ADR-0008 (Merkle, blob, freeze). Frozen by tests/vectors/norea-evidence-v1.json.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::blob::seal_blob;
use crate::canary::{mark, MarkOptions};
use crate::error::{Error, ErrorCode};
use crate::merkle::{leaf_hash, merkle_root};
use crate::sign::{verify, SoftwareSigner};
use crate::table::{canon_row, Format, Row};
use crate::Key32;

pub const EVIDENCE_SCHEMA: &str = "norea.evidence.v1";
pub const CANARY_KIND_RECORD_SHAPE_V1: &str = "record.shape.v1";

const DATASET_SALT: &[u8] = b"norea/v1";
const DATASET_ID_MAX_BYTES: usize = 256;
const MAX_MARKERS: usize = 4;
const SIG_LEN: usize = 3309;

pub(crate) fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// `K_d = HKDF-SHA256(salt=utf8("norea/v1"), ikm=K, info=utf8(dataset_id), L=32)` (§2).
/// The caller owns the result and wipes it.
pub fn derive_dataset_key(k: &Key32, dataset_id: &str) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(DATASET_SALT), k);
    let mut okm = [0u8; 32];
    hk.expand(dataset_id.as_bytes(), &mut okm).expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

/// Time anchor outside the signature (§8). Kind-specific fields are in `rest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Anchor {
    pub kind: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// `norea.evidence.v1` (§4). Field declaration order is the serialized key order.
/// Unknown keys are ignored on parse.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub schema: String,
    pub evidence_id: String,
    pub canary_kind: String,
    pub dataset_id: String,
    pub format: String,
    pub original_sha256: String,
    pub marked_sha256: String,
    pub canary_count: u32,
    pub canary_root: String,
    pub marker_fields: Vec<String>,
    pub canary_blob_sha256: String,
    pub created_claim: String,
    pub vk_b64: String,
    pub sig_b64: String,
    pub canary_blob_b64: String,
    #[serde(default)]
    pub anchors: Vec<Anchor>,
}

fn bad_input(m: &str) -> Error {
    Error::bad_input(m)
}

/// §5.1 single-line string rule.
fn check_line(s: &str, what: &str) -> Result<(), Error> {
    if s.is_empty() {
        return Err(bad_input(&format!("{what} must not be empty")));
    }
    if s.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f) {
        return Err(bad_input(&format!("{what} must not contain control characters")));
    }
    Ok(())
}

fn check_dataset_id(s: &str) -> Result<(), Error> {
    check_line(s, "dataset_id")?;
    if s.len() > DATASET_ID_MAX_BYTES {
        return Err(bad_input("dataset_id must be at most 256 UTF-8 bytes"));
    }
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SSZ`, exactly 20 chars, field ranges checked.
fn check_created_claim(s: &str) -> Result<(), Error> {
    check_line(s, "created_claim")?;
    let b = s.as_bytes();
    let err = || bad_input("created_claim must be RFC 3339 UTC YYYY-MM-DDTHH:MM:SSZ");
    if b.len() != 20 {
        return Err(err());
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        };
        if !ok {
            return Err(err());
        }
    }
    let num = |a: usize| u32::from(b[a] - b'0') * 10 + u32::from(b[a + 1] - b'0');
    let (mo, d, h, mi, se) = (num(5), num(8), num(11), num(14), num(17));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return Err(err());
    }
    Ok(())
}

fn check_hex64(s: &str, what: &str) -> Result<(), Error> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(bad_input(&format!("{what} must be 64 lowercase hex characters")));
    }
    Ok(())
}

/// §5.2 compact JSON: escape only `"` and `\`, no spaces, order kept.
fn marker_fields_json(fields: &[String]) -> String {
    let mut s = String::from("[");
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        for c in f.chars() {
            if c == '"' || c == '\\' {
                s.push('\\');
            }
            s.push(c);
        }
        s.push('"');
    }
    s.push(']');
    s
}

fn format_name(f: Format) -> &'static str {
    match f {
        Format::Json => "json",
        Format::Csv => "csv",
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Evidence {
    /// §6: 11 lines joined by `\n`, no trailing newline.
    pub fn signing_payload(&self) -> Vec<u8> {
        let lines = [
            self.schema.clone(),
            self.canary_kind.clone(),
            self.dataset_id.clone(),
            self.format.clone(),
            self.original_sha256.clone(),
            self.marked_sha256.clone(),
            self.canary_count.to_string(),
            self.canary_root.clone(),
            marker_fields_json(&self.marker_fields),
            self.canary_blob_sha256.clone(),
            self.created_claim.clone(),
        ];
        lines.join("\n").into_bytes()
    }

    /// `hex(SHA-256(signing_payload))`.
    pub fn evidence_id(&self) -> String {
        sha256_hex(&self.signing_payload())
    }

    /// §8.1 `SHA-256(payload || 0x0A || sig_raw)`. Needs a 3309-byte signature.
    pub fn anchor_subject(&self) -> Result<[u8; 32], Error> {
        let sig = B64
            .decode(&self.sig_b64)
            .map_err(|_| Error::new(ErrorCode::BadEvidence, "sig_b64 is not base64"))?;
        if sig.len() != SIG_LEN {
            return Err(Error::new(ErrorCode::BadEvidence, "evidence has no 3309-byte signature"));
        }
        let mut h = Sha256::new();
        h.update(self.signing_payload());
        h.update([0x0a]);
        h.update(&sig);
        Ok(h.finalize().into())
    }

    /// §4 and §5 rules on the payload fields. Violations are `BadInput`.
    pub fn validate_fields(&self) -> Result<(), Error> {
        if self.schema != EVIDENCE_SCHEMA {
            return Err(bad_input("schema must be norea.evidence.v1"));
        }
        // Not in the §5.1 list, but a control character here would break the
        // 11-line payload, so the same rule applies.
        check_line(&self.canary_kind, "canary_kind")?;
        check_dataset_id(&self.dataset_id)?;
        if self.format != "json" && self.format != "csv" {
            return Err(bad_input("format must be json or csv"));
        }
        check_hex64(&self.original_sha256, "original_sha256")?;
        check_hex64(&self.marked_sha256, "marked_sha256")?;
        if self.canary_count == 0 {
            return Err(bad_input("canary_count must be at least 1"));
        }
        check_hex64(&self.canary_root, "canary_root")?;
        if self.marker_fields.is_empty() || self.marker_fields.len() > MAX_MARKERS {
            return Err(bad_input("marker_fields must have 1 to 4 entries"));
        }
        for f in &self.marker_fields {
            check_line(f, "marker field")?;
        }
        check_hex64(&self.canary_blob_sha256, "canary_blob_sha256")?;
        check_created_claim(&self.created_claim)?;
        Ok(())
    }
}

/// Output of `prepare_evidence` / `build_evidence`.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub evidence: Evidence,
    pub marked: Vec<u8>,
    pub canaries: Vec<Row>,
}

/// §9 prepare: mark, hash, Merkle root, blob. The evidence comes back unsigned
/// (`vk_b64`, `sig_b64`, `evidence_id` empty); sign `evidence.signing_payload()`
/// and call `finalize_evidence`.
pub fn prepare_evidence(
    original: &[u8],
    format: Format,
    dataset_id: &str,
    opts: &MarkOptions,
    k_d: &Key32,
    created_claim: &str,
) -> Result<Prepared, Error> {
    check_dataset_id(dataset_id)?;
    check_created_claim(created_claim)?;
    let out = mark(original, format, k_d, opts)?;
    let marked_raw: [u8; 32] = Sha256::digest(&out.marked).into();
    let leaves: Vec<[u8; 32]> =
        out.canaries.iter().enumerate().map(|(i, r)| leaf_hash(i as u32, &canon_row(r))).collect();
    let root = merkle_root(&leaves);
    let blob = seal_blob(k_d, dataset_id, &marked_raw, &out.canaries, &out.shape_summary);
    let evidence = Evidence {
        schema: EVIDENCE_SCHEMA.to_string(),
        evidence_id: String::new(),
        canary_kind: CANARY_KIND_RECORD_SHAPE_V1.to_string(),
        dataset_id: dataset_id.to_string(),
        format: format_name(format).to_string(),
        original_sha256: sha256_hex(original),
        marked_sha256: hex(&marked_raw),
        canary_count: opts.n,
        canary_root: hex(&root),
        marker_fields: out.markers.clone(),
        canary_blob_sha256: sha256_hex(&blob),
        created_claim: created_claim.to_string(),
        vk_b64: String::new(),
        sig_b64: String::new(),
        canary_blob_b64: B64.encode(&blob),
        anchors: Vec::new(),
    };
    evidence.validate_fields()?;
    Ok(Prepared { evidence, marked: out.marked, canaries: out.canaries })
}

/// §9 finalize: accept the external signature only if it verifies.
pub fn finalize_evidence(mut ev: Evidence, vk: &[u8], sig: &[u8]) -> Result<Evidence, Error> {
    ev.validate_fields()?;
    let payload = ev.signing_payload();
    if !verify(vk, &payload, sig) {
        return Err(Error::new(ErrorCode::BadSignature, "signature does not verify over the evidence payload"));
    }
    ev.vk_b64 = B64.encode(vk);
    ev.sig_b64 = B64.encode(sig);
    ev.evidence_id = sha256_hex(&payload);
    Ok(ev)
}

/// prepare + software sign + finalize.
pub fn build_evidence(
    original: &[u8],
    format: Format,
    dataset_id: &str,
    opts: &MarkOptions,
    k_d: &Key32,
    created_claim: &str,
    signer: &SoftwareSigner,
) -> Result<Prepared, Error> {
    let p = prepare_evidence(original, format, dataset_id, opts, k_d, created_claim)?;
    let sig = signer.sign(&p.evidence.signing_payload())?;
    let evidence = finalize_evidence(p.evidence, &signer.verifying_key_bytes(), &sig)?;
    Ok(Prepared { evidence, ..p })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorCheck {
    pub kind: String,
    pub imprint_ok: bool,
    pub gen_time: Option<String>,
    /// Always false: TSA certificate chains are not verified by v1 (§10.5).
    pub chain_verified: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceVerification {
    pub signature_ok: bool,
    pub evidence_id_ok: bool,
    pub blob_hash_ok: bool,
    pub anchors: Vec<AnchorCheck>,
    pub has_anchors: bool,
}

/// §10, no secrets. `signature_ok` is true only if the payload fields also
/// pass `validate_fields` (§10 step 1 has no field of its own in the result).
/// Anchor imprints are not checked until WP-08 and are reported as such.
pub fn verify_evidence(ev: &Evidence) -> EvidenceVerification {
    let fields_ok = ev.validate_fields().is_ok();
    let payload = ev.signing_payload();
    let evidence_id_ok = ev.evidence_id == sha256_hex(&payload);
    let signature_ok = fields_ok
        && match (B64.decode(&ev.vk_b64), B64.decode(&ev.sig_b64)) {
            (Ok(vk), Ok(sig)) => verify(&vk, &payload, &sig),
            _ => false,
        };
    let blob_hash_ok = match (B64.decode(&ev.canary_blob_b64), decode_hex32(&ev.canary_blob_sha256)) {
        (Ok(blob), Some(want)) => !blob.is_empty() && <[u8; 32]>::from(Sha256::digest(&blob)) == want,
        _ => false,
    };
    let anchors: Vec<AnchorCheck> = ev
        .anchors
        .iter()
        .map(|a| AnchorCheck {
            kind: a.kind.clone(),
            imprint_ok: false,
            gen_time: None,
            chain_verified: false,
            error: Some("anchor verification not implemented".to_string()),
        })
        .collect();
    EvidenceVerification { signature_ok, evidence_id_ok, blob_hash_ok, has_anchors: !anchors.is_empty(), anchors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::open_blob;

    const K: Key32 = [0x11; 32];
    const SEED: Key32 = [0x22; 32];
    // Unit-test fixture, not the frozen vector input (that one has ids P-001..P-006,
    // which exhaust the protected unique `id` field; see WP-03 report QUESTION 1).
    const INPUT: &str = r#"[{"id":"P-013","addr":"하남시 미사동 1-1","area_m2":330.5,"use":"대"},{"id":"P-027","addr":"하남시 미사동 2-7","area_m2":512.0,"use":"전"},{"id":"P-102","addr":"하남시 망월동 15-3","area_m2":98.25,"use":"대"},{"id":"P-245","addr":"광주시 역동 7-1","area_m2":1200.0,"use":"답"},{"id":"P-318","addr":"하남시 미사동 3-2","area_m2":450.75,"use":"대"},{"id":"P-406","addr":"하남시 망월동 8-9","area_m2":77.0,"use":"전"}]"#;
    const CLAIM: &str = "2026-11-08T00:00:00Z";

    fn opts() -> MarkOptions {
        MarkOptions { n: 4, marker_fields: None, exclusions: vec![] }
    }

    fn built() -> (Key32, Prepared) {
        let k_d = derive_dataset_key(&K, "test/ds");
        let p = build_evidence(INPUT.as_bytes(), Format::Json, "test/ds", &opts(), &k_d, CLAIM, &SoftwareSigner::from_seed(&SEED))
            .unwrap();
        (k_d, p)
    }

    /// AC5: field rules.
    #[test]
    fn ac5_validate_fields() {
        let (_, p) = built();
        let ev = p.evidence;
        ev.validate_fields().unwrap();
        let bad = |f: &dyn Fn(&mut Evidence)| {
            let mut e = ev.clone();
            f(&mut e);
            e.validate_fields().unwrap_err().code
        };
        assert_eq!(bad(&|e| e.dataset_id = "a\nb".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.dataset_id = "a\u{7f}b".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.dataset_id = String::new()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.dataset_id = "x".repeat(257)), ErrorCode::BadInput);
        let mut ok = ev.clone();
        ok.dataset_id = "x".repeat(256);
        ok.validate_fields().unwrap();
        assert_eq!(bad(&|e| e.dataset_id = "가".repeat(86)), ErrorCode::BadInput); // 258 bytes
        assert_eq!(bad(&|e| e.created_claim = "2026-11-08T00:00:00ZZ".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.created_claim = "2026-11-08T00:00:00".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.created_claim = "2026-13-08T00:00:00Z".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.created_claim = "2026-11-08 00:00:00Z".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.created_claim = String::new()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.marker_fields = vec![]), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.marker_fields = (0..5).map(|i| format!("f{i}")).collect()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.marker_fields = vec!["ok".into(), String::new()]), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.marker_fields = vec!["a\tb".into()]), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.schema = "norea.evidence.v2".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.format = "xml".into()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.canary_count = 0), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.canary_root = e.canary_root.to_uppercase()), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.marked_sha256.truncate(63)), ErrorCode::BadInput);
        assert_eq!(bad(&|e| e.canary_kind = "k\n".into()), ErrorCode::BadInput);
        // prepare rejects the same inputs before marking.
        let k_d = derive_dataset_key(&K, "x");
        for (ds, claim) in [("a\nb", CLAIM), ("", CLAIM), (&"x".repeat(257) as &str, CLAIM), ("ok", "2026-11-08T00:00:00ZZ")] {
            let e = prepare_evidence(INPUT.as_bytes(), Format::Json, ds, &opts(), &k_d, claim).unwrap_err();
            assert_eq!(e.code, ErrorCode::BadInput);
        }
        let e = prepare_evidence(
            INPUT.as_bytes(),
            Format::Json,
            "ok",
            &MarkOptions { n: 4, marker_fields: Some((0..5).map(|i| format!("f{i}")).collect()), exclusions: vec![] },
            &k_d,
            CLAIM,
        )
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
    }

    #[test]
    fn marker_fields_compact_json() {
        assert_eq!(marker_fields_json(&["a".into(), "주소".into()]), r#"["a","주소"]"#);
        assert_eq!(marker_fields_json(&["q\"x".into(), "b\\s/".into()]), r#"["q\"x","b\\s/"]"#);
    }

    /// AC6: seam with an external signer.
    #[test]
    fn ac6_seam() {
        let k_d = derive_dataset_key(&K, "seam");
        let p = prepare_evidence(INPUT.as_bytes(), Format::Json, "seam", &opts(), &k_d, CLAIM).unwrap();
        assert!(p.evidence.vk_b64.is_empty() && p.evidence.sig_b64.is_empty() && p.evidence.evidence_id.is_empty());
        let hw = SoftwareSigner::from_seed(&[0x33; 32]); // stand-in for a hardware signer
        let payload = p.evidence.signing_payload();
        let sig = hw.sign(&payload).unwrap();
        let ev = finalize_evidence(p.evidence.clone(), &hw.verifying_key_bytes(), &sig).unwrap();
        let v = verify_evidence(&ev);
        assert!(v.signature_ok && v.evidence_id_ok && v.blob_hash_ok);
        assert_eq!(ev.evidence_id, sha256_hex(&payload));

        let wrong_vk = SoftwareSigner::from_seed(&[0x44; 32]).verifying_key_bytes();
        assert_eq!(finalize_evidence(p.evidence.clone(), &wrong_vk, &sig).unwrap_err().code, ErrorCode::BadSignature);
        let mut tampered = payload.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let sig2 = hw.sign(&tampered).unwrap();
        assert_eq!(
            finalize_evidence(p.evidence.clone(), &hw.verifying_key_bytes(), &sig2).unwrap_err().code,
            ErrorCode::BadSignature
        );
        assert_eq!(finalize_evidence(p.evidence, &[], &[]).unwrap_err().code, ErrorCode::BadSignature);
    }

    /// AC7: verify_evidence flags.
    #[test]
    fn ac7_verify_evidence() {
        let (k_d, p) = built();
        let ev = p.evidence;
        let v = verify_evidence(&ev);
        assert_eq!(
            v,
            EvidenceVerification {
                signature_ok: true,
                evidence_id_ok: true,
                blob_hash_ok: true,
                anchors: vec![],
                has_anchors: false
            }
        );
        let mut e = ev.clone();
        e.created_claim = "2020-01-01T00:00:00Z".into();
        let v = verify_evidence(&e);
        assert!(!v.signature_ok && !v.evidence_id_ok && v.blob_hash_ok);

        let mut e = ev.clone();
        e.evidence_id = sha256_hex(b"x");
        let v = verify_evidence(&e);
        assert!(v.signature_ok && !v.evidence_id_ok && v.blob_hash_ok);

        let mut e = ev.clone();
        let mut blob = B64.decode(&e.canary_blob_b64).unwrap();
        blob[3] ^= 1;
        e.canary_blob_b64 = B64.encode(&blob);
        let v = verify_evidence(&e);
        assert!(v.signature_ok && v.evidence_id_ok && !v.blob_hash_ok);

        let mut e = ev.clone();
        e.canary_blob_b64 = String::new();
        assert!(!verify_evidence(&e).blob_hash_ok);

        let mut e = ev.clone();
        e.anchors.push(Anchor { kind: "rfc3161".into(), rest: Map::new() });
        let v = verify_evidence(&e);
        assert!(v.signature_ok && v.has_anchors);
        assert_eq!(v.anchors[0].error.as_deref(), Some("anchor verification not implemented"));
        assert!(!v.anchors[0].imprint_ok && !v.anchors[0].chain_verified);

        // Blob opens with K_d and matches the root.
        let marked_raw = decode_hex32(&ev.marked_sha256).unwrap();
        let (rows, _) = open_blob(&k_d, &ev.dataset_id, &marked_raw, &B64.decode(&ev.canary_blob_b64).unwrap()).unwrap();
        let leaves: Vec<[u8; 32]> = rows.iter().enumerate().map(|(i, r)| leaf_hash(i as u32, &canon_row(r))).collect();
        assert_eq!(hex(&merkle_root(&leaves)), ev.canary_root);
        assert_eq!(rows.iter().map(canon_row).collect::<Vec<_>>(), p.canaries.iter().map(canon_row).collect::<Vec<_>>());
        assert_eq!(ev.anchor_subject().unwrap().len(), 32);
    }

    /// AC8: JSON round trip, §4 key order, unknown keys accepted.
    #[test]
    fn ac8_json_round_trip() {
        let (_, p) = built();
        let mut ev = p.evidence;
        ev.anchors.push(Anchor {
            kind: "rfc3161".into(),
            rest: serde_json::from_str(r#"{"token_b64":"AAAA","tsa_url":"https://tsa.example","fetched_claim":"2026-11-08T12:00:00Z"}"#)
                .unwrap(),
        });
        let s = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
        let order = [
            "schema",
            "evidence_id",
            "canary_kind",
            "dataset_id",
            "format",
            "original_sha256",
            "marked_sha256",
            "canary_count",
            "canary_root",
            "marker_fields",
            "canary_blob_sha256",
            "created_claim",
            "vk_b64",
            "sig_b64",
            "canary_blob_b64",
            "anchors",
        ];
        let pos: Vec<usize> = order.iter().map(|k| s.find(&format!("\"{k}\":")).unwrap()).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "key order {pos:?}");
        assert!(s.starts_with("{\"schema\":\"norea.evidence.v1\",\"evidence_id\":"));

        let mut v: Value = serde_json::from_str(&s).unwrap();
        v.as_object_mut().unwrap().insert("future_key".into(), Value::from(1));
        v.as_object_mut().unwrap().remove("anchors");
        let parsed: Evidence = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert!(parsed.anchors.is_empty());
        assert!(verify_evidence(&parsed).signature_ok);
        // Pretty form too.
        let back: Evidence = serde_json::from_str(&serde_json::to_string_pretty(&ev).unwrap()).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn payload_shape_and_dataset_key() {
        let (_, p) = built();
        let payload = String::from_utf8(p.evidence.signing_payload()).unwrap();
        let lines: Vec<&str> = payload.split('\n').collect();
        assert_eq!(lines.len(), 11);
        assert_eq!(lines[0], "norea.evidence.v1");
        assert_eq!(lines[1], "record.shape.v1");
        assert_eq!(lines[6], "4");
        assert!(!payload.ends_with('\n'));
        assert_ne!(derive_dataset_key(&K, "a"), derive_dataset_key(&K, "b"));
        let sub = p.evidence.anchor_subject().unwrap();
        let mut h = Sha256::new();
        h.update(p.evidence.signing_payload());
        h.update(b"\n");
        h.update(B64.decode(&p.evidence.sig_b64).unwrap());
        assert_eq!(<[u8; 32]>::from(h.finalize()), sub);
        let mut unsigned = p.evidence.clone();
        unsigned.sig_b64 = String::new();
        assert_eq!(unsigned.anchor_subject().unwrap_err().code, ErrorCode::BadEvidence);
    }

    #[test]
    fn csv_build() {
        let csv = "id,addr,area_m2,use\nP-013,하남시 미사동 1-1,330.5,대\nP-027,하남시 미사동 2-7,512.0,전\nP-102,하남시 망월동 15-3,98.25,대\nP-245,광주시 역동 7-1,1200.0,답\nP-318,하남시 미사동 3-2,450.75,대\nP-406,하남시 망월동 8-9,77.0,전\n";
        let k_d = derive_dataset_key(&K, "c");
        let p = build_evidence(csv.as_bytes(), Format::Csv, "c", &opts(), &k_d, CLAIM, &SoftwareSigner::from_seed(&SEED)).unwrap();
        assert_eq!(p.evidence.format, "csv");
        assert!(verify_evidence(&p.evidence).signature_ok);
    }

    /// AC10: 50k rows, build_evidence(n=64). Timing printed; run with --release --nocapture.
    #[test]
    fn ac10_perf_50k_build() {
        let si = ["하남시", "성남시", "용인시"];
        let dong = ["미사동", "망월동", "정자동", "서현동", "죽전동", "보정동"];
        let mut v = Vec::with_capacity(50_000);
        for i in 0..50_000usize {
            v.push(format!(
                "  {{\n    \"id\": \"P-{:06}\",\n    \"addr\": \"{} {} {}-{}\",\n    \"area_m2\": {}.{:02},\n    \"use_type\": \"{}\"\n  }}",
                i * 7,
                si[i % 3],
                dong[(i / 3) % 6],
                1 + (i * 31) % 999,
                1 + i % 37,
                50 + (i * 53) % 1950,
                (i * 7) % 100,
                ["대", "전", "답", "임야", "잡종지"][i % 5],
            ));
        }
        let src = format!("[\n{}\n]\n", v.join(",\n"));
        let k_d = derive_dataset_key(&K, "perf");
        let signer = SoftwareSigner::from_seed(&SEED);
        let o = MarkOptions { n: 64, marker_fields: None, exclusions: vec![] };
        for run in 0..3 {
            let start = std::time::Instant::now();
            let p = build_evidence(src.as_bytes(), Format::Json, "perf", &o, &k_d, CLAIM, &signer).unwrap();
            let took = start.elapsed();
            println!("ac10 run {run}: input {} bytes, 50000 rows, build_evidence(n=64) {:?}", src.len(), took);
            assert_eq!(p.evidence.canary_count, 64);
            if !cfg!(debug_assertions) {
                assert!(took.as_millis() < 1500, "took {took:?}");
            }
        }
    }
}
