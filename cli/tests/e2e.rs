//! WP-05 acceptance: the two CLI binaries end to end, as separate processes.
//! Spec: Fable_5_1/tasks/specs/WP-05-cli.md, CORE-API §3, disclosure-v1 §4-§5.
//!
//! Flow: dataset A -> `norea protect` -> suspect variants (as is, renamed keys +
//! nesting, CSV) -> `norea check` -> `norea disclose` -> `norea-verify
//! disclosure` (exit 0) -> tampering (exit 1) -> bad input (exit 2) -> key
//! file gate (exit 2). Every process output is checked for key material.
//!
//! Print the example outputs: cargo test -p norea-cli --test e2e -- --nocapture

#[path = "../../core/tests/common/mod.rs"]
mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use noreacore::disclose::verify_disclosure;
use noreacore::evidence::{derive_dataset_key, sha256_hex, Evidence};
use serde_json::{json, Map, Value};

const NOREA: &str = env!("CARGO_BIN_EXE_norea");
const VERIFY: &str = env!("CARGO_BIN_EXE_norea-verify");
const DS: &str = "test/cli-dataset-a";
const N: u64 = 16;
const TEST_FLAG: &str = "--i-know-this-is-for-testing";
const REFUSAL: &str = "실제 키를 파일로 두지 마세요. 제품은 웹/앱의 custody를 씁니다";

fn key_k() -> [u8; 32] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
}

fn key_seed() -> [u8; 32] {
    std::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(200))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Strings that must never appear in any output: K, seed and K_d as hex
/// (every 16-char window, both cases) and base64, plus 8-byte raw windows.
fn secrets() -> &'static (Vec<String>, Vec<Vec<u8>>) {
    static S: OnceLock<(Vec<String>, Vec<Vec<u8>>)> = OnceLock::new();
    S.get_or_init(|| {
        let keys = [key_k(), key_seed(), derive_dataset_key(&key_k(), DS)];
        let mut strs = Vec::new();
        let mut raws = Vec::new();
        for k in keys {
            let h = hex(&k);
            for w in 0..=(64 - 16) {
                strs.push(h[w..w + 16].to_string());
                strs.push(h[w..w + 16].to_uppercase());
            }
            strs.push(B64.encode(k));
            for w in 0..=(32 - 8) {
                raws.push(k[w..w + 8].to_vec());
            }
        }
        (strs, raws)
    })
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Runs a binary and checks what every output must satisfy: no key material,
/// no panic or backtrace.
fn run(bin: &str, args: &[&str]) -> Out {
    let o = Command::new(bin).args(args).env("RUST_BACKTRACE", "1").output().expect("spawn");
    let (strs, raws) = secrets();
    for stream in [&o.stdout, &o.stderr] {
        let text = String::from_utf8_lossy(stream);
        for s in strs {
            assert!(!text.contains(s.as_str()), "key material {s} in output of {bin} {args:?}");
        }
        for r in raws {
            assert!(!stream.windows(r.len()).any(|w| w == r.as_slice()), "raw key bytes in output of {bin} {args:?}");
        }
        assert!(!text.contains("panicked") && !text.contains("stack backtrace"), "panic in {bin} {args:?}: {text}");
    }
    Out {
        code: o.status.code().expect("exit code"),
        stdout: String::from_utf8(o.stdout).expect("utf8 stdout"),
        stderr: String::from_utf8(o.stderr).expect("utf8 stderr"),
    }
}

fn p(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn fresh_dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join("norea-cli-e2e").join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }
}

fn rows_of(v: &Value) -> Vec<Map<String, Value>> {
    v.as_array().unwrap().iter().map(|r| r.as_object().unwrap().clone()).collect()
}

/// Keys renamed to col_j, the first two cells moved into a nested object,
/// rows reversed, all wrapped in {"data": [...]}.
fn renamed_nested(v: &Value) -> String {
    let mut rows: Vec<Value> = rows_of(v)
        .into_iter()
        .map(|r| {
            let mut inner = Map::new();
            let mut outer = Map::new();
            for (j, (_, c)) in r.into_iter().enumerate() {
                if j < 2 {
                    inner.insert(format!("col_{j}"), c);
                } else {
                    outer.insert(format!("col_{j}"), c);
                }
            }
            outer.insert("nested".into(), Value::Object(inner));
            Value::Object(outer)
        })
        .collect();
    rows.reverse();
    json!({ "data": rows }).to_string()
}

fn to_csv(v: &Value) -> String {
    let rows = rows_of(v);
    let mut fields: Vec<String> = Vec::new();
    for r in &rows {
        for k in r.keys() {
            if !fields.contains(k) {
                fields.push(k.clone());
            }
        }
    }
    let q = |s: String| {
        if s.contains([',', '"', '\n', '\r']) || s.starts_with(' ') || s.ends_with(' ') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    let mut out = fields.join(",") + "\n";
    for r in &rows {
        let cells: Vec<String> = fields.iter().map(|f| q(r.get(f).map(scalar_text).unwrap_or_default())).collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    out
}

struct Fixture {
    dir: PathBuf,
    input: PathBuf,
    input_sha: String,
    k_file: PathBuf,
    s_file: PathBuf,
    out_dir: PathBuf,
    marked: PathBuf,
    evidence: PathBuf,
    /// (name, path, expected suspect_kind)
    variants: Vec<(&'static str, PathBuf, &'static str)>,
    disclosure: PathBuf,
    suspect: PathBuf,
}

/// protect once, write the variants and one disclosure (renamed + nested copy).
fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let dir = fresh_dir("fixture");
        let input = dir.join("parcels.json");
        fs::write(&input, common::dataset_a(2_000, false, 1)).unwrap();
        let input_sha = sha256_hex(&fs::read(&input).unwrap());
        let k_file = dir.join("K.bin");
        let s_file = dir.join("S.bin");
        fs::write(&k_file, key_k()).unwrap();
        fs::write(&s_file, key_seed()).unwrap();
        let out_dir = dir.join("out");
        let n = N.to_string();
        let o = run(
            NOREA,
            &[
                "protect", p(&input), "--dataset-id", DS, "--n", &n, "--key-file", p(&k_file), "--seed-file",
                p(&s_file), "--out-dir", p(&out_dir), TEST_FLAG,
            ],
        );
        println!("protect stdout:\n{}", o.stdout);
        assert_eq!(o.code, 0, "protect: {}", o.stderr);
        let marked = out_dir.join("parcels.marked.json");
        let evidence = out_dir.join("parcels.evidence.json");
        assert!(marked.is_file() && evidence.is_file());

        let mv: Value = serde_json::from_slice(&fs::read(&marked).unwrap()).unwrap();
        let nested = dir.join("suspect-nested.json");
        fs::write(&nested, renamed_nested(&mv)).unwrap();
        let csv = dir.join("suspect.csv");
        fs::write(&csv, to_csv(&mv)).unwrap();
        let variants = vec![("as is", marked.clone(), "json"), ("renamed + nested", nested.clone(), "json"), ("csv", csv, "csv")];

        let disclosure = dir.join("disclosure.json");
        let o = run(
            NOREA,
            &["disclose", p(&evidence), p(&nested), "--key-file", p(&k_file), "--out", p(&disclosure), TEST_FLAG],
        );
        assert_eq!(o.code, 0, "disclose: {}", o.stderr);
        assert!(disclosure.is_file());
        Fixture { dir, input, input_sha, k_file, s_file, out_dir, marked, evidence, variants, disclosure, suspect: nested }
    })
}

fn json_of(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// AC1 (part): protect leaves the input untouched and refuses to overwrite.
#[test]
fn protect_writes_new_files_only() {
    let f = fixture();
    assert_eq!(sha256_hex(&fs::read(&f.input).unwrap()), f.input_sha, "input file unchanged");
    let before = fs::read(&f.evidence).unwrap();
    let n = N.to_string();
    let o = run(
        NOREA,
        &[
            "protect", p(&f.input), "--dataset-id", DS, "--n", &n, "--key-file", p(&f.k_file), "--seed-file",
            p(&f.s_file), "--out-dir", p(&f.out_dir), TEST_FLAG,
        ],
    );
    println!("protect again: exit {} stderr {}", o.code, o.stderr.trim());
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("already exists"));
    assert_eq!(fs::read(&f.evidence).unwrap(), before, "existing evidence not overwritten");
    let ev = json_of(&f.evidence);
    assert_eq!(ev["schema"], "norea.evidence.v1");
    assert_eq!(ev["canary_count"], N);
    assert_eq!(sha256_hex(&fs::read(&f.marked).unwrap()), ev["marked_sha256"].as_str().unwrap());
    assert_eq!(f.input_sha, ev["original_sha256"].as_str().unwrap());
    let o = run(NOREA, &["inspect", p(&f.input)]);
    assert_eq!(o.code, 0);
    let ins: Value = serde_json::from_str(&o.stdout).unwrap();
    assert!(ins.is_object());
}

/// AC1 (part): check finds all canaries in every variant.
#[test]
fn check_variants() {
    let f = fixture();
    for (name, path, kind) in &f.variants {
        let o = run(NOREA, &["check", p(path), p(&f.evidence), "--key-file", p(&f.k_file), TEST_FLAG]);
        assert_eq!(o.code, 0, "{name}: {}", o.stderr);
        let r: Value = serde_json::from_str(&o.stdout).unwrap();
        println!("check {name:18} kind={} matched={} partial={} absent={}", r["suspect_kind"], r["matched"], r["partial"], r["absent"]);
        assert_eq!(r["schema"], "norea.check-report.v1");
        assert_eq!(r["suspect_kind"], *kind, "{name}");
        assert_eq!(r["commit_ok"], true);
        assert_eq!(r["matched"], N, "{name}");
    }
}

/// AC1 + AC2: verify the disclosure (exit 0) and the statement items.
#[test]
fn verify_disclosure_pass_and_statement() {
    let f = fixture();
    let o = run(VERIFY, &["disclosure", p(&f.disclosure), p(&f.suspect)]);
    println!("--- norea-verify disclosure (human) ---\n{}", o.stdout);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let out = &o.stdout;
    for need in [
        "공개키 지문",
        "이 증거는 생성 시점을 증명하지 않는다",
        &format!("공개된 canary {N}개 중 {N}개가 사본에서 재현되었다"),
        "chain_verified: false",
        "무결성: PASS",
        "[PASS] 서명 / Signature",
        "[N/A ] 시점 anchor",
        "-> PASS (exit 0)",
    ] {
        assert!(out.contains(need), "missing {need:?}");
    }
    // statement is included verbatim
    let disc = fs::read_to_string(&f.disclosure).unwrap();
    let report: Value = serde_json::from_str(&verify_disclosure(&disc, &fs::read(&f.suspect).unwrap()).unwrap()).unwrap();
    assert!(out.contains(report["statement"].as_str().unwrap()));

    let ev = run(VERIFY, &["evidence", p(&f.evidence)]);
    println!("--- norea-verify evidence ---\n{}", ev.stdout);
    assert_eq!(ev.code, 0);
}

/// AC3: --json prints the core report unchanged, with the report schema keys.
#[test]
fn verify_json_is_core_report() {
    let f = fixture();
    let o = run(VERIFY, &["disclosure", p(&f.disclosure), p(&f.suspect), "--json"]);
    assert_eq!(o.code, 0);
    let disc = fs::read_to_string(&f.disclosure).unwrap();
    let core = verify_disclosure(&disc, &fs::read(&f.suspect).unwrap()).unwrap();
    assert_eq!(o.stdout, format!("{core}\n"), "--json is the core report byte for byte");
    println!("--- norea-verify disclosure --json ---\n{}", o.stdout);
    let r: Value = serde_json::from_str(&o.stdout).unwrap();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&r), ["schema", "evidence", "suspect_hash_ok", "disclosed", "summary", "verdict", "statement"]);
    assert_eq!(r["schema"], "norea.disclosure-report.v1");
    assert_eq!(keys(&r["evidence"]), ["signature_ok", "evidence_id_ok", "blob_hash_ok", "evidence_id", "anchors"]);
    assert_eq!(keys(&r["disclosed"][0]), ["index", "merkle_ok", "matched", "found"]);
    assert_eq!(keys(&r["summary"]), ["disclosed", "merkle_ok", "matched", "not_reproduced"]);
    assert_eq!(keys(&r["verdict"]), ["integrity_ok", "all_reproduced"]);
}

/// AC4: signature bit, Merkle path element, suspect byte -> exit 1 each.
#[test]
fn tampering_exits_1() {
    let f = fixture();
    let dir = fresh_dir("tamper");
    let disc = json_of(&f.disclosure);

    let mut sig = disc.clone();
    let mut raw = B64.decode(sig["evidence"]["sig_b64"].as_str().unwrap()).unwrap();
    raw[100] ^= 0x01;
    sig["evidence"]["sig_b64"] = Value::from(B64.encode(&raw));
    let sig_path = dir.join("sig.json");
    fs::write(&sig_path, sig.to_string()).unwrap();

    let mut path = disc.clone();
    let el = path["disclosed"][0]["path"][0].as_str().unwrap().to_string();
    let flipped = format!("{}{}", &el[..63], if el.ends_with('0') { '1' } else { '0' });
    path["disclosed"][0]["path"][0] = Value::from(flipped);
    let path_path = dir.join("path.json");
    fs::write(&path_path, path.to_string()).unwrap();

    let mut suspect = fs::read(&f.suspect).unwrap();
    let last = suspect.len() - 1;
    suspect[last] = b' ';
    let suspect_path = dir.join("suspect-1byte.json");
    fs::write(&suspect_path, &suspect).unwrap();

    for (name, d, s, fail_line) in [
        ("signature bit", &sig_path, &f.suspect, "[FAIL] 서명 / Signature"),
        ("merkle path element", &path_path, &f.suspect, "[FAIL] Merkle path"),
        ("suspect 1 byte", &f.disclosure, &suspect_path, "[FAIL] 사본 SHA-256"),
    ] {
        let o = run(VERIFY, &["disclosure", p(d), p(s)]);
        println!("tamper {name:20} exit {} first statement line: {}", o.code, o.stdout.lines().find(|l| l.starts_with("무결성")).unwrap_or(""));
        assert_eq!(o.code, 1, "{name}");
        assert!(o.stdout.contains(fail_line), "{name}: {fail_line}");
        assert!(o.stdout.contains("무결성: FAIL"), "{name}");
        let j = run(VERIFY, &["disclosure", p(d), p(s), "--json"]);
        assert_eq!(j.code, 1, "{name} --json");
    }

    // evidence subcommand: signature bit
    let mut ev = json_of(&f.evidence);
    let mut raw = B64.decode(ev["sig_b64"].as_str().unwrap()).unwrap();
    raw[7] ^= 0x80;
    ev["sig_b64"] = Value::from(B64.encode(&raw));
    let ev_path = dir.join("evidence-sig.json");
    fs::write(&ev_path, ev.to_string()).unwrap();
    let o = run(VERIFY, &["evidence", p(&ev_path)]);
    assert_eq!(o.code, 1);
    assert!(o.stdout.contains("[FAIL] 서명"));
}

/// AC5: missing paths, broken JSON, wrong JSON -> exit 2, one error line, no backtrace.
#[test]
fn bad_input_exits_2() {
    let f = fixture();
    let dir = fresh_dir("bad-input");
    let broken = dir.join("broken.json");
    fs::write(&broken, "{\"schema\": \"norea.disclosure.v1\", ").unwrap();
    let empty_obj = dir.join("empty.json");
    fs::write(&empty_obj, "{}").unwrap();
    let not_utf8 = dir.join("bin.json");
    fs::write(&not_utf8, [0xff, 0xfe, 0x00]).unwrap();
    let missing = dir.join("does-not-exist.json");
    let cases: Vec<(&str, &str, Vec<&str>)> = vec![
        ("disclosure missing", VERIFY, vec!["disclosure", p(&missing), p(&f.suspect)]),
        ("suspect missing", VERIFY, vec!["disclosure", p(&f.disclosure), p(&missing)]),
        ("disclosure broken json", VERIFY, vec!["disclosure", p(&broken), p(&f.suspect)]),
        ("disclosure {}", VERIFY, vec!["disclosure", p(&empty_obj), p(&f.suspect)]),
        ("disclosure not utf8", VERIFY, vec!["disclosure", p(&not_utf8), p(&f.suspect)]),
        ("disclosure broken --json", VERIFY, vec!["disclosure", p(&broken), p(&f.suspect), "--json"]),
        ("evidence missing", VERIFY, vec!["evidence", p(&missing)]),
        ("evidence broken json", VERIFY, vec!["evidence", p(&broken)]),
        ("verify no args", VERIFY, vec![]),
        ("verify unknown subcommand", VERIFY, vec!["frobnicate"]),
        ("check evidence broken", NOREA, vec!["check", p(&f.suspect), p(&broken), "--key-file", p(&f.k_file), TEST_FLAG]),
        ("check key missing", NOREA, vec!["check", p(&f.suspect), p(&f.evidence), "--key-file", p(&missing), TEST_FLAG]),
        ("check key not 32 B", NOREA, vec!["check", p(&f.suspect), p(&f.evidence), "--key-file", p(&broken), TEST_FLAG]),
        ("inspect missing", NOREA, vec!["inspect", p(&missing)]),
    ];
    for (name, bin, args) in &cases {
        let o = run(bin, args);
        println!("bad input {name:28} exit {} stderr: {}", o.code, o.stderr.lines().next().unwrap_or(""));
        assert_eq!(o.code, 2, "{name}");
        assert!(o.stderr.contains("error"), "{name}: {}", o.stderr);
        assert!(!o.stdout.trim_start().starts_with('{'), "{name}: no report on stdout");
    }
    // disclose refuses to overwrite --out
    let o = run(
        NOREA,
        &["disclose", p(&f.evidence), p(&f.suspect), "--key-file", p(&f.k_file), "--out", p(&f.disclosure), TEST_FLAG],
    );
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("already exists"));
}

/// AC6: --key-file without the testing flag is refused (exit 2) before anything is written.
#[test]
fn key_file_needs_testing_flag() {
    let f = fixture();
    let dir = fresh_dir("gate");
    let out_dir = dir.join("out");
    let out = dir.join("d.json");
    let n = N.to_string();
    let cases: Vec<(&str, Vec<&str>)> = vec![
        (
            "protect",
            vec![
                "protect", p(&f.input), "--dataset-id", DS, "--n", &n, "--key-file", p(&f.k_file), "--seed-file",
                p(&f.s_file), "--out-dir", p(&out_dir),
            ],
        ),
        ("check", vec!["check", p(&f.suspect), p(&f.evidence), "--key-file", p(&f.k_file)]),
        ("disclose", vec!["disclose", p(&f.evidence), p(&f.suspect), "--key-file", p(&f.k_file), "--out", p(&out)]),
    ];
    for (name, args) in &cases {
        let o = run(NOREA, args);
        println!("gate {name:8} exit {}\n{}", o.code, o.stderr);
        assert_eq!(o.code, 2, "{name}");
        assert!(o.stderr.contains(REFUSAL), "{name}");
        assert!(o.stdout.is_empty(), "{name}");
    }
    assert!(!out_dir.exists() && !out.exists(), "nothing written");
}

/// anchor (WP-08): a TSA that cannot be reached is exit 2 and writes nothing;
/// a non-http URL is refused before any request; --ots is not implemented (exit 3).
#[test]
fn anchor_failures_write_nothing() {
    let f = fixture();
    let out = f.evidence.with_file_name(format!(
        "{}.anchored.json",
        f.evidence.file_stem().unwrap().to_str().unwrap()
    ));
    let o = run(NOREA, &["anchor", p(&f.evidence), "--tsa", "https://tsa.invalid"]);
    println!("unreachable TSA exit {}\n{}", o.code, o.stderr);
    assert_eq!(o.code, 2);
    let o = run(NOREA, &["anchor", p(&f.evidence), "--tsa", "file:///etc/passwd"]);
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("http"));
    assert!(!out.exists(), "nothing written");
    let o = run(NOREA, &["anchor", p(&f.evidence), "--tsa", "https://tsa.invalid", "--ots"]);
    assert_eq!(o.code, 3);
    assert!(o.stderr.contains("not implemented"));
}

/// WP-08: an evidence carrying a real TSA token for a different subject (fixture,
/// no network) parses (no `error`) but its imprint does not match -> exit 1.
#[test]
fn evidence_with_foreign_anchor_fails() {
    let f = fixture();
    let dir = fresh_dir("foreign-anchor");
    let resp = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/tsa-response-freetsa.der")).unwrap();
    let tok = noreacore::anchor::tsa_parse_response(&resp).unwrap();
    let mut ev = json_of(&f.evidence);
    ev["anchors"] = json!([{
        "kind": "rfc3161", "token_b64": B64.encode(&tok.token_der),
        "tsa_url": "https://freetsa.org/tsr", "fetched_claim": "2026-11-09T04:14:30Z"
    }]);
    let path = dir.join("foreign-anchor.evidence.json");
    fs::write(&path, ev.to_string()).unwrap();
    let o = run(VERIFY, &["evidence", p(&path)]);
    println!("{}", o.stdout);
    assert_eq!(o.code, 1);
    assert!(o.stdout.contains("[PASS] 서명"));
    assert!(o.stdout.contains("[FAIL] anchor 0 (rfc3161): imprint, genTime 2026-11-09T04:14:30Z"));
    let o = run(VERIFY, &["evidence", "--json", p(&path)]);
    assert_eq!(o.code, 1);
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["anchors"][0]["imprint_ok"], json!(false));
    assert_eq!(v["anchors"][0]["error"], Value::Null);
    // The unanchored evidence still passes.
    assert_eq!(run(VERIFY, &["evidence", p(&f.evidence)]).code, 0);
}

/// --export-anchors: a hand-added rfc3161 anchor (anchors are outside the
/// signature) is exported as DER, with subject.bin and README.txt. A token that does
/// not parse stays N/A and does not change the exit code.
#[test]
fn export_anchors() {
    let f = fixture();
    let dir = fresh_dir("export");
    let mut disc = json_of(&f.disclosure);
    let token = b"\x30\x03\x02\x01\x00 not a real TimeStampToken".to_vec();
    disc["evidence"]["anchors"] = json!([{
        "kind": "rfc3161", "token_b64": B64.encode(&token),
        "tsa_url": "https://tsa.invalid", "fetched_claim": "2026-11-09T00:00:00Z"
    }]);
    let disc_path = dir.join("with-anchor.json");
    fs::write(&disc_path, disc.to_string()).unwrap();
    let ev: Evidence = serde_json::from_value(disc["evidence"].clone()).unwrap();
    let subject = ev.anchor_subject().unwrap();
    let export = dir.join("anchors");

    let o = run(VERIFY, &["disclosure", p(&disc_path), p(&f.suspect), "--export-anchors", p(&export)]);
    println!("--- with anchor ---\n{}", o.stdout);
    assert_eq!(o.code, 0, "anchor N/A does not fail: {}", o.stderr);
    assert!(o.stdout.contains("[N/A ] anchor 0 (rfc3161)"));
    // WP-08: an unparsable rfc3161 token is an `error` (N/A), not a FAIL.
    assert!(o.stdout.contains("token does not parse"));
    assert_eq!(fs::read(export.join("anchor-0.tsr")).unwrap(), token);
    assert_eq!(fs::read(export.join("subject.bin")).unwrap(), subject.to_vec());
    let readme = fs::read_to_string(export.join("README.txt")).unwrap();
    println!("--- README.txt ---\n{readme}");
    assert!(readme.contains(&format!("openssl ts -verify -digest {} -in anchor-0.tsr -token_in -CAfile", hex(&subject))));
    assert!(readme.contains("chain_verified: false"));

    // never overwrites; --json keeps stdout pure JSON
    let o = run(VERIFY, &["disclosure", p(&disc_path), p(&f.suspect), "--export-anchors", p(&export)]);
    assert_eq!(o.code, 2);
    let export2 = dir.join("anchors2");
    let o = run(VERIFY, &["disclosure", p(&disc_path), p(&f.suspect), "--json", "--export-anchors", p(&export2)]);
    assert_eq!(o.code, 0);
    let _: Value = serde_json::from_str(&o.stdout).expect("stdout is only the report");
    assert!(export2.join("anchor-0.tsr").is_file());
}

/// The frozen vector evidence verifies through the CLI (fixture from WP-03).
#[test]
fn frozen_vector_evidence() {
    let dir = fresh_dir("vector");
    let v: Value =
        serde_json::from_str(&fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/vectors/norea-evidence-v1.json")).unwrap())
            .unwrap();
    for case in ["json", "csv"] {
        let path = dir.join(format!("{case}.evidence.json"));
        fs::write(&path, v[case]["evidence"].to_string()).unwrap();
        let o = run(VERIFY, &["evidence", p(&path)]);
        assert_eq!(o.code, 0, "{case}");
        assert!(o.stdout.contains(v[case]["evidence_id"].as_str().unwrap()));
    }
    let _ = &fixture().dir;
}

/// AC7 self-check: the scanner used by `run` really detects key material.
#[test]
fn secret_scanner_detects_keys() {
    let (strs, raws) = secrets();
    let leak = format!("x{}y", hex(&derive_dataset_key(&key_k(), DS)));
    assert!(strs.iter().any(|s| leak.contains(s.as_str())), "K_d hex detected");
    let leak = hex(&key_seed()).to_uppercase();
    assert!(strs.iter().any(|s| leak.contains(s.as_str())), "seed HEX detected");
    let mut raw = b"abc".to_vec();
    raw.extend_from_slice(&key_k());
    assert!(raws.iter().any(|r| raw.windows(r.len()).any(|w| w == r.as_slice())), "raw K detected");
}

// ---- WP-05 2차: claim options, --force, --created-claim, evidence --json

/// disclose with the three *_claim options and --created-claim: the claims are in
/// the package and verification passes (exit 0). A bad created_claim is core BadInput (exit 2).
#[test]
fn disclose_with_claims() {
    let f = fixture();
    let dir = fresh_dir("claims");
    let out = dir.join("d.json");
    let o = run(
        NOREA,
        &[
            "disclose", p(&f.evidence), p(&f.suspect), "--key-file", p(&f.k_file), "--source-claim",
            "https://example.com/data.json", "--captured-claim", "2026-11-30T15:00:00Z", "--capture-method-claim",
            "browser save-as", "--created-claim", "2026-12-01T09:00:00Z", "--out", p(&out), TEST_FLAG,
        ],
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    let d = json_of(&out);
    println!("claims: created_claim={} suspect={}", d["created_claim"], d["suspect"]);
    assert_eq!(d["created_claim"], "2026-12-01T09:00:00Z");
    assert_eq!(d["suspect"]["source_claim"], "https://example.com/data.json");
    assert_eq!(d["suspect"]["captured_claim"], "2026-11-30T15:00:00Z");
    assert_eq!(d["suspect"]["capture_method_claim"], "browser save-as");
    let v = run(VERIFY, &["disclosure", p(&out), p(&f.suspect)]);
    assert_eq!(v.code, 0, "{}", v.stderr);
    assert!(v.stdout.contains("-> PASS (exit 0)"));

    let bad = dir.join("bad.json");
    let o = run(
        NOREA,
        &[
            "disclose", p(&f.evidence), p(&f.suspect), "--key-file", p(&f.k_file), "--created-claim", "yesterday",
            "--out", p(&bad), TEST_FLAG,
        ],
    );
    println!("bad created_claim: exit {} stderr {}", o.code, o.stderr.trim());
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("BadInput"));
    assert!(!bad.exists());
}

/// --force discloses a canary that is not in the suspect: verify exits 1 and
/// verdict.all_reproduced is false (integrity still true). Without --force: exit 2.
#[test]
fn force_unmatched_index() {
    let f = fixture();
    let dir = fresh_dir("force");
    // suspect = marked copy with the first canary row removed
    let input_rows: std::collections::HashSet<String> =
        rows_of(&json_of(&f.input)).into_iter().map(|r| Value::Object(r).to_string()).collect();
    let mut rows = rows_of(&json_of(&f.marked));
    let canary_pos = rows.iter().position(|r| !input_rows.contains(&Value::Object(r.clone()).to_string())).unwrap();
    rows.remove(canary_pos);
    let suspect = dir.join("missing-one.json");
    fs::write(&suspect, Value::Array(rows.into_iter().map(Value::Object).collect()).to_string()).unwrap();

    let o = run(NOREA, &["check", p(&suspect), p(&f.evidence), "--key-file", p(&f.k_file), TEST_FLAG]);
    let r: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(r["matched"], N - 1);
    let matched: Vec<u64> = r["matched_indices"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect();
    let absent = (0..N).find(|i| !matched.contains(i)).unwrap();
    let indices = format!("{absent},{}", matched[0]);
    println!("force: absent canary index {absent}, disclosing {indices}");

    let refused = dir.join("refused.json");
    let o = run(
        NOREA,
        &["disclose", p(&f.evidence), p(&suspect), "--key-file", p(&f.k_file), "--indices", &indices, "--out", p(&refused), TEST_FLAG],
    );
    println!("without --force: exit {} stderr {}", o.code, o.stderr.trim());
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("BadDisclosure"));

    let forced = dir.join("forced.json");
    let o = run(
        NOREA,
        &[
            "disclose", p(&f.evidence), p(&suspect), "--key-file", p(&f.k_file), "--indices", &indices, "--force",
            "--out", p(&forced), TEST_FLAG,
        ],
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    let v = run(VERIFY, &["disclosure", p(&forced), p(&suspect)]);
    println!("--- forced, human ---\n{}", v.stdout);
    assert_eq!(v.code, 1);
    assert!(v.stdout.contains("FAIL (NOT REPRODUCED)"));
    let j = run(VERIFY, &["disclosure", p(&forced), p(&suspect), "--json"]);
    assert_eq!(j.code, 1);
    let r: Value = serde_json::from_str(&j.stdout).unwrap();
    println!("forced verdict {} summary {}", r["verdict"], r["summary"]);
    assert_eq!(r["verdict"]["all_reproduced"], false);
    assert_eq!(r["verdict"]["integrity_ok"], true);
}

/// --created-claim makes protect reproducible: two runs into different out-dirs
/// give byte-identical evidence and marked files. A bad claim is BadInput (exit 2).
#[test]
fn protect_created_claim_reproducible() {
    let f = fixture();
    let dir = fresh_dir("reproducible");
    let n = N.to_string();
    let mut evs = Vec::new();
    for name in ["a", "b"] {
        let out_dir = dir.join(name);
        let o = run(
            NOREA,
            &[
                "protect", p(&f.input), "--dataset-id", DS, "--n", &n, "--created-claim", "2026-11-08T00:00:00Z",
                "--key-file", p(&f.k_file), "--seed-file", p(&f.s_file), "--out-dir", p(&out_dir), TEST_FLAG,
            ],
        );
        assert_eq!(o.code, 0, "{}", o.stderr);
        evs.push((fs::read(out_dir.join("parcels.evidence.json")).unwrap(), fs::read(out_dir.join("parcels.marked.json")).unwrap()));
    }
    assert_eq!(evs[0].0, evs[1].0, "evidence bytes identical");
    assert_eq!(evs[0].1, evs[1].1, "marked bytes identical");
    let ev: Value = serde_json::from_slice(&evs[0].0).unwrap();
    println!("reproducible: created_claim={} evidence_id={} sha256(evidence file)={}", ev["created_claim"], ev["evidence_id"], sha256_hex(&evs[0].0));
    assert_eq!(ev["created_claim"], "2026-11-08T00:00:00Z");

    let bad_dir = dir.join("bad");
    let o = run(
        NOREA,
        &[
            "protect", p(&f.input), "--dataset-id", DS, "--n", &n, "--created-claim", "2026-13-01T00:00:00Z",
            "--key-file", p(&f.k_file), "--seed-file", p(&f.s_file), "--out-dir", p(&bad_dir), TEST_FLAG,
        ],
    );
    println!("bad created_claim protect: exit {} stderr {}", o.code, o.stderr.trim());
    assert_eq!(o.code, 2);
    assert!(o.stderr.contains("BadInput"));
    assert!(!bad_dir.join("parcels.evidence.json").exists());
}

/// norea-verify evidence --json: EvidenceVerification as serde writes it, 5 keys; exit code rule unchanged.
#[test]
fn verify_evidence_json() {
    let f = fixture();
    let o = run(VERIFY, &["evidence", p(&f.evidence), "--json"]);
    println!("evidence --json: {}", o.stdout.trim());
    assert_eq!(o.code, 0);
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    let keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["signature_ok", "evidence_id_ok", "blob_hash_ok", "anchors", "has_anchors"]);
    let ev: Evidence = serde_json::from_slice(&fs::read(&f.evidence).unwrap()).unwrap();
    let core = serde_json::to_string(&noreacore::evidence::verify_evidence(&ev)).unwrap();
    assert_eq!(o.stdout, format!("{core}\n"));

    let dir = fresh_dir("evidence-json");
    let mut t = json_of(&f.evidence);
    let mut raw = B64.decode(t["sig_b64"].as_str().unwrap()).unwrap();
    raw[0] ^= 0x01;
    t["sig_b64"] = Value::from(B64.encode(&raw));
    let tp = dir.join("t.json");
    fs::write(&tp, t.to_string()).unwrap();
    let o = run(VERIFY, &["evidence", p(&tp), "--json"]);
    assert_eq!(o.code, 1);
    let v: Value = serde_json::from_str(&o.stdout).unwrap();
    assert_eq!(v["signature_ok"], false);
}

/// ots anchors are exported as raw proof bytes; README.txt does not claim an ots command (decided in WP-08).
#[test]
fn export_ots_readme() {
    let f = fixture();
    let dir = fresh_dir("export-ots");
    let mut disc = json_of(&f.disclosure);
    let proof = b"not a real ots proof".to_vec();
    disc["evidence"]["anchors"] = json!([{ "kind": "ots", "proof_b64": B64.encode(&proof), "calendar_urls": [], "fetched_claim": "2026-11-09T00:00:00Z" }]);
    let dp = dir.join("ots.json");
    fs::write(&dp, disc.to_string()).unwrap();
    let export = dir.join("anchors");
    let o = run(VERIFY, &["disclosure", p(&dp), p(&f.suspect), "--export-anchors", p(&export)]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(fs::read(export.join("anchor-0.ots")).unwrap(), proof);
    let readme = fs::read_to_string(export.join("README.txt")).unwrap();
    println!("--- ots README.txt ---\n{readme}");
    assert!(readme.contains("OpenTimestamps 검증 명령은 WP-08에서 실제 proof로 확정한다. 이 파일은 proof 바이트 원본이다."));
    assert!(!readme.contains("ots verify"));
}
