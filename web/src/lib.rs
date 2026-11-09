//! norea-web: wasm-bindgen bindings for noreacore.
//!
//! Type conversion and zeroize only, no logic. The JS API is
//! Fable_5_1/docs/CORE-API.md §2 (12 functions, JS names as listed there).
//!
//! Secrets (ADR-0012, platform-contract "비밀 처리 규칙 (web)"):
//! - K and seed arrive as owned `Vec<u8>` and are wrapped in `Zeroizing`
//!   before anything else runs, so every return path wipes them. They are
//!   borrowed as `&[u8; 32]` in place, never copied into a second buffer here.
//! - K_d is derived here into a `Zeroizing` buffer and never returned; K_blob
//!   is derived and wiped inside core.
//! - The passphrase arrives as an owned `String` and is wiped after Argon2id.
//! - wasm-bindgen frees its own argument and return copies (for example the
//!   Argon2id output after JS has copied it) without wiping them. The global
//!   allocator below wipes every heap block on free, so no freed block keeps a
//!   secret. Secret-taking calls run in a separate frame and then zero the
//!   stack region that frame used (`scrubbed`), because by-value temporaries
//!   (for example the `[u8; 32]` returned by `derive_dataset_key`) and core's
//!   hash/ML-DSA stack state are not covered by `Zeroizing`.
//! - tests/smoke.node.cjs scans the whole wasm memory after each such call.
//!
//! Errors are `JsError` with the message `CODE: message`. CODE is the core
//! `ErrorCode` name (`BadInput`, ...) or `ANCHOR_UNAVAILABLE`. platform-web.js
//! splits on the first `: ` and maps CODE to `error.code`.

use noreacore::canary::MarkOptions;
use noreacore::check::check as core_check;
use noreacore::disclose::{disclose as core_disclose, verify_disclosure as core_verify_disclosure, SuspectMeta};
use noreacore::evidence::{
    build_evidence, derive_dataset_key, sha256_hex as core_sha256_hex, verify_evidence as core_verify_evidence,
    Evidence,
};
use noreacore::shape::inspect as core_inspect;
use noreacore::sign::SoftwareSigner;
use noreacore::table::{detect_format, Format};
use noreacore::{Error, ErrorCode, Key32};
use serde_json::Value;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// Heap: every block is wiped before it goes back to the allocator (ADR-0012).
/// `realloc` keeps GlobalAlloc's default (alloc, copy, dealloc), so a block
/// left behind by a growing Vec is wiped too.
#[cfg(target_arch = "wasm32")]
struct ZeroOnFree;

#[cfg(target_arch = "wasm32")]
unsafe impl std::alloc::GlobalAlloc for ZeroOnFree {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            std::alloc::System.dealloc(ptr, layout)
        }
    }
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: ZeroOnFree = ZeroOnFree;

/// Stack bytes zeroed after a secret-taking call. Measured deepest use is
/// about 348 KiB (protect with ML-DSA-65 signing, WP-06 report); the wasm
/// shadow stack is 1 MiB and these calls start near its top.
const STACK_SCRUB_BYTES: usize = 512 * 1024;

#[inline(never)]
fn scrub_stack() {
    let mut buf = [0u8; STACK_SCRUB_BYTES];
    buf.zeroize();
    std::hint::black_box(&mut buf);
}

/// Runs `f` in its own (non-inlined) frame, then zeroes the stack below the
/// caller, which covers every frame `f` used.
fn scrubbed<R>(f: impl FnOnce() -> R) -> R {
    let r = isolated(f);
    scrub_stack();
    r
}

#[inline(never)]
fn isolated<R>(f: impl FnOnce() -> R) -> R {
    f()
}

/// Argon2id parameters, custody-web-v1 §1: m = 64 MiB, t = 3, p = 1, 32 B out.
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;
const ANCHOR_UNAVAILABLE: &str = "ANCHOR_UNAVAILABLE: anchor not implemented until WP-08";

fn js(e: Error) -> JsError {
    // Display is "{code:?}: {message}" (core/src/error.rs). Core messages
    // carry no secrets, input values or paths.
    JsError::new(&e.to_string())
}

fn bad_input(m: &str) -> JsError {
    js(Error::new(ErrorCode::BadInput, m))
}

/// Takes ownership of a secret and wipes it on every exit path. The length
/// check happens after wrapping, so a wrong-length secret is wiped too.
fn secret32(v: Vec<u8>, what: &str) -> Result<Zeroizing<Vec<u8>>, JsError> {
    let v = Zeroizing::new(v);
    if v.len() != 32 {
        return Err(bad_input(&format!("{what} must be exactly 32 bytes")));
    }
    Ok(v)
}

/// Borrow a checked 32-byte secret as `&Key32` without copying it.
fn as_key(v: &Zeroizing<Vec<u8>>) -> &Key32 {
    v.as_slice().try_into().expect("length checked by secret32")
}

fn parse_format(s: &str) -> Result<Format, JsError> {
    match s {
        "json" => Ok(Format::Json),
        "csv" => Ok(Format::Csv),
        _ => Err(bad_input("format must be \"json\" or \"csv\"")),
    }
}

fn parse_evidence(evidence_json: &str) -> Result<Evidence, JsError> {
    // serde_json messages can quote input text, so only line/column go out.
    serde_json::from_str(evidence_json).map_err(|e| {
        js(Error::new(
            ErrorCode::BadEvidence,
            format!("evidence is not a norea.evidence.v1 JSON object (line {}, column {})", e.line(), e.column()),
        ))
    })
}

fn parse_json(s: &str, what: &str) -> Result<Value, JsError> {
    serde_json::from_str(s).map_err(|_| bad_input(&format!("{what} is not JSON")))
}

fn string_list(v: &Value, what: &str) -> Result<Vec<String>, JsError> {
    let err = || bad_input(&format!("{what} must be an array of strings"));
    v.as_array().ok_or_else(err)?.iter().map(|x| x.as_str().map(str::to_string).ok_or_else(err)).collect()
}

/// `optionsJson` (CORE-API §2): `{"n", "markerFields", "exclusions", "format"}`.
fn parse_options(options_json: &str, input: &[u8]) -> Result<(MarkOptions, Format), JsError> {
    let o = parse_json(options_json, "optionsJson")?;
    let o = o.as_object().ok_or_else(|| bad_input("optionsJson must be a JSON object"))?;
    let n = o
        .get("n")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| bad_input("optionsJson.n must be a non-negative integer"))?;
    let marker_fields = match o.get("markerFields") {
        None | Some(Value::Null) => None,
        Some(v) => Some(string_list(v, "optionsJson.markerFields")?),
    };
    let exclusions = match o.get("exclusions") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => string_list(v, "optionsJson.exclusions")?,
    };
    let format = match o.get("format") {
        None | Some(Value::Null) => detect_format(input),
        Some(Value::String(s)) => parse_format(s)?,
        Some(_) => return Err(bad_input("optionsJson.format must be \"json\", \"csv\" or null")),
    };
    Ok((MarkOptions { n, marker_fields, exclusions }, format))
}

/// `indicesJson`: `null` or `[]` = all matched canaries, else an array of u32.
fn parse_indices(indices_json: &str) -> Result<Option<Vec<u32>>, JsError> {
    let err = || bad_input("indicesJson must be null or an array of non-negative integers");
    match parse_json(indices_json, "indicesJson")? {
        Value::Null => Ok(None),
        Value::Array(a) if a.is_empty() => Ok(None),
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(err))
            .collect::<Result<Vec<u32>, _>>()
            .map(Some),
        _ => Err(err()),
    }
}

/// `metaJson` (CORE-API §2, 2026-11-09): camelCase `sourceClaim`,
/// `capturedClaim`, `captureMethodClaim`, all optional; absent or "" = None.
/// An empty `metaJson` string or `null` means no claims.
fn parse_meta(meta_json: &str) -> Result<SuspectMeta, JsError> {
    if meta_json.trim().is_empty() {
        return Ok(SuspectMeta::default());
    }
    let v = parse_json(meta_json, "metaJson")?;
    let o = match &v {
        Value::Null => return Ok(SuspectMeta::default()),
        Value::Object(o) => o,
        _ => return Err(bad_input("metaJson must be a JSON object")),
    };
    let get = |k: &str| -> Result<Option<String>, JsError> {
        match o.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.is_empty() => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(bad_input(&format!("metaJson.{k} must be a string"))),
        }
    };
    Ok(SuspectMeta {
        source_claim: get("sourceClaim")?,
        captured_claim: get("capturedClaim")?,
        capture_method_claim: get("captureMethodClaim")?,
    })
}

fn internal() -> JsError {
    js(Error::new(ErrorCode::BadEvidence, "internal: result does not serialize"))
}

/// InspectResult JSON (platform-contract). No secrets.
#[wasm_bindgen]
pub fn inspect(input: &[u8], format: Option<String>) -> Result<String, JsError> {
    let format = format.as_deref().map(parse_format).transpose()?;
    core_inspect(input, format).map_err(js)
}

/// Output of `protect`. `marked` is the public file, `evidenceJson` the
/// private evidence. Neither contains a secret. Call `free()` when done.
#[wasm_bindgen]
pub struct ProtectResult {
    marked: Vec<u8>,
    evidence_json: String,
}

#[wasm_bindgen]
impl ProtectResult {
    #[wasm_bindgen(getter)]
    pub fn marked(&self) -> Vec<u8> {
        self.marked.clone()
    }

    #[wasm_bindgen(getter, js_name = evidenceJson)]
    pub fn evidence_json(&self) -> String {
        self.evidence_json.clone()
    }
}

/// Mark + sign in one call (ADR-0012). K and seed cross the boundary once.
/// The input bytes are borrowed and never modified.
#[wasm_bindgen]
pub fn protect(
    input: &[u8],
    master_k: Vec<u8>,
    seed: Vec<u8>,
    dataset_id: &str,
    options_json: &str,
    created_claim: &str,
) -> Result<ProtectResult, JsError> {
    scrubbed(|| {
        let master_k = secret32(master_k, "masterK")?;
        let seed = secret32(seed, "seed")?;
        let (opts, format) = parse_options(options_json, input)?;
        let prepared = {
            let k_d = Zeroizing::new(derive_dataset_key(as_key(&master_k), dataset_id));
            let signer = SoftwareSigner::from_seed(as_key(&seed));
            build_evidence(input, format, dataset_id, &opts, &k_d, created_claim, &signer).map_err(js)?
        };
        drop(master_k);
        drop(seed);
        let evidence_json = serde_json::to_string(&prepared.evidence).map_err(|_| internal())?;
        Ok(ProtectResult { marked: prepared.marked, evidence_json })
    })
}

/// norea.check-report.v1 JSON. K crosses once; K_d stays inside.
#[wasm_bindgen]
pub fn check(suspect: &[u8], master_k: Vec<u8>, evidence_json: &str) -> Result<String, JsError> {
    scrubbed(|| {
        let master_k = secret32(master_k, "masterK")?;
        let ev = parse_evidence(evidence_json)?;
        let k_d = Zeroizing::new(derive_dataset_key(as_key(&master_k), &ev.dataset_id));
        drop(master_k);
        core_check(suspect, &k_d, &ev).map_err(js)
    })
}

/// norea.disclosure.v1 JSON. K crosses once; K_d stays inside.
#[wasm_bindgen]
pub fn disclose(
    evidence_json: &str,
    master_k: Vec<u8>,
    suspect: &[u8],
    indices_json: &str,
    meta_json: &str,
    created_claim: &str,
    force: bool,
) -> Result<String, JsError> {
    scrubbed(|| {
        let master_k = secret32(master_k, "masterK")?;
        let ev = parse_evidence(evidence_json)?;
        let indices = parse_indices(indices_json)?;
        let meta = parse_meta(meta_json)?;
        let k_d = Zeroizing::new(derive_dataset_key(as_key(&master_k), &ev.dataset_id));
        drop(master_k);
        core_disclose(&ev, &k_d, suspect, indices.as_deref(), &meta, created_claim, force).map_err(js)
    })
}

/// EvidenceVerification JSON (core serde, snake_case). No secrets.
#[wasm_bindgen(js_name = verifyEvidence)]
pub fn verify_evidence(evidence_json: &str) -> Result<String, JsError> {
    let ev = parse_evidence(evidence_json)?;
    serde_json::to_string(&core_verify_evidence(&ev)).map_err(|_| internal())
}

/// norea.disclosure-report.v1 JSON. No secrets.
#[wasm_bindgen(js_name = verifyDisclosure)]
pub fn verify_disclosure(disclosure_json: &str, suspect: &[u8]) -> Result<String, JsError> {
    core_verify_disclosure(disclosure_json, suspect).map_err(js)
}

/// hex(anchor_subject), evidence-v1 §8.1. Needs a signed evidence.
#[wasm_bindgen(js_name = anchorSubjectHex)]
pub fn anchor_subject_hex(evidence_json: &str) -> Result<String, JsError> {
    let ev = parse_evidence(evidence_json)?;
    let s = ev.anchor_subject().map_err(js)?;
    Ok(s.iter().map(|b| format!("{b:02x}")).collect())
}

/// RFC 3161 TimeStampReq DER. core `anchor.rs` is WP-08; until then this throws.
#[wasm_bindgen(js_name = tsaRequest)]
pub fn tsa_request(_evidence_json: &str, _nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    Err(JsError::new(ANCHOR_UNAVAILABLE))
}

/// Adds an anchor to the evidence. core `anchor.rs` is WP-08; until then this throws.
#[wasm_bindgen(js_name = attachAnchor)]
pub fn attach_anchor(_evidence_json: &str, _anchor_json: &str) -> Result<String, JsError> {
    Err(JsError::new(ANCHOR_UNAVAILABLE))
}

/// ML-DSA-65 verifying key (1952 B) for a seed. The seed is wiped.
#[wasm_bindgen(js_name = verifyingKey)]
pub fn verifying_key(seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        let seed = secret32(seed, "seed")?;
        let vk = SoftwareSigner::from_seed(as_key(&seed)).verifying_key_bytes();
        Ok(vk)
    })
}

#[wasm_bindgen(js_name = sha256Hex)]
pub fn sha256_hex(bytes: &[u8]) -> String {
    core_sha256_hex(bytes)
}

/// Passphrase KEK input S = Argon2id(passphrase, salt, m = 64 MiB, t = 3,
/// p = 1, 32 B) (custody-web-v1 §1). The passphrase copy is wiped; the
/// 64 MiB of Argon2 blocks and the returned buffer (after the glue copies it
/// to JS) are wiped by the allocator on free.
#[wasm_bindgen(js_name = passphraseKek)]
pub fn passphrase_kek(passphrase: String, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    scrubbed(|| {
        use argon2::{Algorithm, Argon2, Params, Version};
        let passphrase = Zeroizing::new(passphrase);
        if !(16..=64).contains(&salt.len()) {
            return Err(bad_input("salt must be 16 to 64 bytes"));
        }
        let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
            .map_err(|_| bad_input("invalid Argon2id parameters"))?;
        let mut out = vec![0u8; 32];
        if Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .is_err()
        {
            out.zeroize();
            return Err(bad_input("Argon2id failed (passphrase too long)"));
        }
        Ok(out)
    })
}
