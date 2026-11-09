//! norea-verify: verify NoREA evidence or a disclosure package without any secret.
//!
//! Commands: Fable_5_1/docs/CORE-API.md §3. Rules: ADR-0011, disclosure-v1 §4-§5.
//! This binary does file I/O, argument parsing and presentation only. Every
//! verification rule is in noreacore (`verify_evidence`, `verify_disclosure`);
//! the PASS/FAIL lines below only read fields of the core result.
//!
//! Exit codes: 0 all checks PASS, 1 a check FAILs, 2 input or structure error.
//! Anchors are reported but are not part of the exit code until WP-08.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use noreacore::disclose::verify_disclosure;
use noreacore::evidence::{verify_evidence, AnchorCheck, Evidence};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "norea-verify",
    version,
    about = "Verify NoREA evidence or a disclosure package offline, without any secret.\nExit: 0 PASS, 1 FAIL, 2 input error."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a norea.evidence.v1 file (signature, evidence_id, blob hash, anchors).
    Evidence {
        /// evidence.json
        evidence: PathBuf,
        /// Print the EvidenceVerification JSON exactly as core returns it, nothing else on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Verify a norea.disclosure.v1 package against the suspect copy it refers to.
    Disclosure {
        /// disclosure.json
        disclosure: PathBuf,
        /// The suspect copy file submitted with the package.
        suspect: PathBuf,
        /// Write each anchor token, subject.bin and README.txt (openssl steps) into DIR.
        #[arg(long, value_name = "DIR")]
        export_anchors: Option<PathBuf>,
        /// Print the norea.disclosure-report.v1 JSON exactly as produced, nothing else on stdout.
        #[arg(long)]
        json: bool,
    },
}

/// Input or structure error: exit 2, one line on stderr, never a backtrace.
struct InputError(String);

fn read(path: &Path, what: &str) -> Result<Vec<u8>, InputError> {
    fs::read(path).map_err(|e| InputError(format!("cannot read {what} {}: {}", path.display(), e.kind())))
}

fn read_utf8(path: &Path, what: &str) -> Result<String, InputError> {
    String::from_utf8(read(path, what)?).map_err(|_| InputError(format!("{what} {} is not UTF-8", path.display())))
}

fn out(s: &str) {
    let _ = std::io::stdout().write_all(s.as_bytes());
}

fn pass(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Evidence { evidence, json } => cmd_evidence(&evidence, json),
        Cmd::Disclosure { disclosure, suspect, export_anchors, json } => {
            cmd_disclosure(&disclosure, &suspect, export_anchors.as_deref(), json)
        }
    };
    match r {
        Ok(code) => ExitCode::from(code),
        Err(InputError(m)) => {
            eprintln!("norea-verify: error: {m}");
            ExitCode::from(2)
        }
    }
}

/// Anchor lines. Until WP-08 core reports every anchor with an `error`; shown as N/A.
fn anchor_lines(anchors: &[AnchorCheck], s: &mut String) {
    if anchors.is_empty() {
        s.push_str("[N/A ] 시점 anchor / Time anchor: 없음 / none\n");
        s.push_str("       이 증거는 생성 시점을 증명하지 않는다. / This evidence does not prove when it was created.\n");
    }
    for (k, a) in anchors.iter().enumerate() {
        match &a.error {
            Some(e) => s.push_str(&format!("[N/A ] anchor {k} ({}): 검증하지 않음 / not verified: {e}\n", a.kind)),
            None => {
                let t = a.gen_time.as_deref().unwrap_or("-");
                s.push_str(&format!("[{}] anchor {k} ({}): imprint, genTime {t}\n", pass(a.imprint_ok), a.kind));
            }
        }
    }
    s.push_str("       TSA 인증서 체인은 이 도구가 검증하지 않는다(chain_verified: false). --export-anchors DIR 후 openssl ts -verify로 직접 확인한다.\n");
    s.push_str("       The TSA certificate chain is not verified by this tool (chain_verified: false). Use --export-anchors DIR and openssl ts -verify.\n");
}

fn cmd_evidence(path: &Path, json: bool) -> Result<u8, InputError> {
    let text = read_utf8(path, "evidence")?;
    let ev: Evidence = serde_json::from_str(&text).map_err(|e| {
        InputError(format!("evidence is not a norea.evidence.v1 JSON object (line {}, column {})", e.line(), e.column()))
    })?;
    let v = verify_evidence(&ev);
    let ok = v.signature_ok && v.evidence_id_ok && v.blob_hash_ok;
    if json {
        let j = serde_json::to_string(&v).map_err(|_| InputError("internal: verification does not serialize".to_string()))?;
        out(&j);
        out("\n");
        return Ok(if ok { 0 } else { 1 });
    }
    let mut s = String::new();
    s.push_str("NoREA evidence 검증 / evidence verification (norea.evidence.v1)\n");
    s.push_str(&format!("evidence_id: {}\n", ev.evidence_id));
    s.push_str(&format!("[{}] 서명 / Signature (ML-DSA-65, fields)\n", pass(v.signature_ok)));
    s.push_str(&format!("[{}] evidence_id = SHA-256(payload)\n", pass(v.evidence_id_ok)));
    s.push_str(&format!("[{}] canary blob 해시 / Canary blob hash\n", pass(v.blob_hash_ok)));
    anchor_lines(&v.anchors, &mut s);
    s.push_str("       created_claim은 운영자 기기 시계의 주장이며 검증하지 않았다. / created_claim is an unverified operator clock claim.\n");
    s.push_str(&format!("판정 / Verdict: {} (exit {})\n", pass(ok), if ok { 0 } else { 1 }));
    out(&s);
    Ok(if ok { 0 } else { 1 })
}

fn field<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(v, |cur, p| &cur[*p])
}

fn get_bool(v: &Value, path: &[&str]) -> bool {
    field(v, path).as_bool().unwrap_or(false)
}

fn get_u64(v: &Value, path: &[&str]) -> u64 {
    field(v, path).as_u64().unwrap_or(0)
}

fn cmd_disclosure(disc_path: &Path, suspect_path: &Path, export: Option<&Path>, json: bool) -> Result<u8, InputError> {
    let disc = read_utf8(disc_path, "disclosure")?;
    let suspect = read(suspect_path, "suspect")?;
    let report_json =
        verify_disclosure(&disc, &suspect).map_err(|e| InputError(format!("disclosure rejected: {e}")))?;
    let report: Value =
        serde_json::from_str(&report_json).map_err(|_| InputError("internal: report is not JSON".to_string()))?;
    // disclosure-v1 §4: exit 0 iff verdict.integrity_ok && verdict.all_reproduced.
    let code = if get_bool(&report, &["verdict", "integrity_ok"]) && get_bool(&report, &["verdict", "all_reproduced"]) {
        0
    } else {
        1
    };

    if json {
        out(&report_json);
        out("\n");
    } else {
        out(&human_disclosure(&report, code));
    }

    if let Some(dir) = export {
        let msg = export_anchors(&disc, dir)?;
        if json {
            eprint!("{msg}");
        } else {
            out(&msg);
        }
    }
    Ok(code)
}

fn human_disclosure(r: &Value, code: u8) -> String {
    let e = &r["evidence"];
    let mut s = String::new();
    s.push_str("NoREA disclosure 검증 / disclosure verification (norea.disclosure-report.v1)\n");
    s.push_str(&format!("evidence_id: {}\n\n", e["evidence_id"].as_str().unwrap_or("")));
    s.push_str("== 1. Evidence ==\n");
    s.push_str(&format!("[{}] 서명 / Signature (ML-DSA-65, fields)\n", pass(get_bool(e, &["signature_ok"]))));
    s.push_str(&format!("[{}] evidence_id = SHA-256(payload)\n", pass(get_bool(e, &["evidence_id_ok"]))));
    s.push_str(&format!("[{}] canary blob 해시 / Canary blob hash\n", pass(get_bool(e, &["blob_hash_ok"]))));
    let anchors: Vec<AnchorCheck> = serde_json::from_value(e["anchors"].clone()).unwrap_or_default();
    s.push_str("\n== 2. 시점 anchor / Time anchors (종료 코드에 넣지 않음 / not in exit code) ==\n");
    anchor_lines(&anchors, &mut s);

    let n = get_u64(r, &["summary", "disclosed"]);
    let merkle = get_u64(r, &["summary", "merkle_ok"]);
    let matched = get_u64(r, &["summary", "matched"]);
    let not_rep = get_u64(r, &["summary", "not_reproduced"]);
    s.push_str("\n== 3. 사본 / Suspect copy ==\n");
    s.push_str(&format!("[{}] 사본 SHA-256 = suspect.sha256 / Suspect hash\n", pass(get_bool(r, &["suspect_hash_ok"]))));
    s.push_str("\n== 4. 공개된 canary / Disclosed canaries ==\n");
    s.push_str(&format!(
        "[{}] Merkle path -> 서명된 canary_root / signed canary_root: {merkle}/{n}\n",
        pass(n >= 1 && merkle == n)
    ));
    s.push_str(&format!("[{}] 사본에서 재현 / Reproduced in suspect: {matched}/{n}\n", pass(not_rep == 0)));
    for d in r["disclosed"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let found: Vec<&str> =
            d["found"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
        s.push_str(&format!(
            "       index {}: merkle {}, matched {}, found [{}]\n",
            d["index"],
            pass(d["merkle_ok"].as_bool().unwrap_or(false)),
            if d["matched"].as_bool().unwrap_or(false) { "PASS" } else { "FAIL (NOT REPRODUCED)" },
            found.join(", ")
        ));
    }
    s.push_str("\n== 5. 판정 / Verdict ==\n");
    s.push_str(&format!(
        "integrity_ok: {}, all_reproduced: {} -> {} (exit {code})\n",
        get_bool(r, &["verdict", "integrity_ok"]),
        get_bool(r, &["verdict", "all_reproduced"]),
        if code == 0 { "PASS" } else { "FAIL" }
    ));
    s.push_str("\n== 6. Statement (verifier 생성 원문 / verbatim) ==\n");
    s.push_str(r["statement"].as_str().unwrap_or(""));
    s.push('\n');
    s
}

/// disclosure-v1 §5. Writes new files only; an existing file is an input error.
fn export_anchors(disc: &str, dir: &Path) -> Result<String, InputError> {
    let v: Value = serde_json::from_str(disc).map_err(|_| InputError("disclosure is not JSON".to_string()))?;
    let ev: Evidence = serde_json::from_value(v["evidence"].clone())
        .map_err(|_| InputError("disclosure.evidence is not a norea.evidence.v1 object".to_string()))?;
    let subject =
        ev.anchor_subject().map_err(|e| InputError(format!("cannot compute anchor_subject for export: {e}")))?;
    let subject_hex: String = subject.iter().map(|b| format!("{b:02x}")).collect();

    let mut files: Vec<(String, Vec<u8>)> = vec![("subject.bin".to_string(), subject.to_vec())];
    let mut readme = String::new();
    readme.push_str("NoREA anchor export (disclosure-v1 §5)\n\n");
    readme.push_str(&format!("evidence_id:    {}\nanchor_subject: {subject_hex}\n", ev.evidence_id));
    readme.push_str("subject.bin = anchor_subject, raw 32 bytes = SHA-256(signing payload || 0x0A || signature).\n\n");
    readme.push_str("norea-verify does not verify TSA certificate chains (chain_verified: false).\n");
    readme.push_str("Verify each token yourself with the CA bundle published by that TSA.\n");
    readme.push_str("이 도구는 TSA 인증서 체인을 검증하지 않는다. TSA가 공개한 CA bundle로 아래 명령을 직접 실행한다.\n\n");
    if ev.anchors.is_empty() {
        readme.push_str("This evidence has no anchors: it does not prove when it was created.\n");
        readme.push_str("이 증거에는 anchor가 없다. 생성 시점을 증명하지 않는다.\n");
    }
    for (k, a) in ev.anchors.iter().enumerate() {
        let (key, ext) = match a.kind.as_str() {
            "rfc3161" => ("token_b64", "tsr"),
            "ots" => ("proof_b64", "ots"),
            other => {
                readme.push_str(&format!("anchor {k}: kind {other} is not exported.\n"));
                continue;
            }
        };
        let bytes = a
            .rest
            .get(key)
            .and_then(|x| x.as_str())
            .and_then(|b| B64.decode(b).ok())
            .ok_or_else(|| InputError(format!("anchor {k}: {key} is missing or not base64")))?;
        let name = format!("anchor-{k}.{ext}");
        if ext == "tsr" {
            readme.push_str(&format!(
                "anchor {k} (rfc3161):\n  openssl ts -verify -digest {subject_hex} -in {name} -token_in -CAfile <TSA CA bundle>\n"
            ));
        } else {
            readme.push_str(&format!(
                "anchor {k} (ots): {name}\n  OpenTimestamps 검증 명령은 WP-08에서 실제 proof로 확정한다. 이 파일은 proof 바이트 원본이다.\n"
            ));
        }
        files.push((name, bytes));
    }
    files.push(("README.txt".to_string(), readme.into_bytes()));

    fs::create_dir_all(dir).map_err(|e| InputError(format!("cannot create {}: {}", dir.display(), e.kind())))?;
    for (name, _) in &files {
        let p = dir.join(name);
        if p.exists() {
            return Err(InputError(format!("{} already exists; not overwriting", p.display())));
        }
    }
    let mut msg = String::from("\n== anchor export ==\n");
    for (name, bytes) in &files {
        let p = dir.join(name);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .and_then(|mut f| f.write_all(bytes))
            .map_err(|e| InputError(format!("cannot write {}: {}", p.display(), e.kind())))?;
        msg.push_str(&format!("wrote {}\n", p.display()));
    }
    Ok(msg)
}
