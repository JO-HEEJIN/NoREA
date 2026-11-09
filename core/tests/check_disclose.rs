//! WP-04 acceptance: check, disclose, verify_disclosure.
//! Spec: Fable_5_1/tasks/specs/WP-04-check-and-disclose.md, shape-v1 §7,
//! disclosure-v1. THREAT-MODEL A1 (copy), A2 (re-serialization), A3 (field
//! deletion), A4/A6 negatives (unrelated data), B2 (late canary insertion =
//! Merkle path must match the signed root).
//!
//! Print the measurements and example JSON:
//!   cargo test --release -p noreacore --test check_disclose -- --nocapture

mod common;

use std::sync::OnceLock;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use noreacore::canary::MarkOptions;
use noreacore::check::{check, detect_suspect_kind, match_rows, SuspectKind};
use noreacore::disclose::{disclose, verify_disclosure, SuspectMeta};
use noreacore::evidence::{build_evidence, derive_dataset_key, Evidence, Prepared};
use noreacore::sign::SoftwareSigner;
use noreacore::table::{row_from_json, Format};
use noreacore::ErrorCode;
use serde_json::{json, Map, Value};
use unicode_normalization::UnicodeNormalization;

const K: [u8; 32] = [0x44; 32];
const SEED: [u8; 32] = [0x55; 32];
const DS: &str = "test/dataset-a";
const CLAIM: &str = "2026-11-09T00:00:00Z";
const N: u32 = 32;

struct Fixture {
    original: String,
    k_d: [u8; 32],
    p: Prepared,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let original = common::dataset_a(10_000, false, 1);
        let k_d = derive_dataset_key(&K, DS);
        let opts = MarkOptions { n: N, marker_fields: None, exclusions: vec![] };
        let p = build_evidence(original.as_bytes(), Format::Json, DS, &opts, &k_d, CLAIM, &SoftwareSigner::from_seed(&SEED))
            .unwrap();
        Fixture { original, k_d, p }
    })
}

fn report(suspect: &[u8], k_d: &[u8; 32], ev: &Evidence) -> Value {
    serde_json::from_str(&check(suspect, k_d, ev).unwrap()).unwrap()
}

fn counts(r: &Value) -> (u64, u64, u64) {
    (r["matched"].as_u64().unwrap(), r["partial"].as_u64().unwrap(), r["absent"].as_u64().unwrap())
}

fn marked_value() -> Value {
    serde_json::from_slice(&fixture().p.marked).unwrap()
}

/// Apply `f` to every scalar (strings and numbers), recursively.
fn map_scalars(v: &Value, f: &dyn Fn(&Value) -> Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.iter().map(|(k, c)| (k.clone(), map_scalars(c, f))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(|c| map_scalars(c, f)).collect()),
        Value::String(_) | Value::Number(_) => f(v),
        other => other.clone(),
    }
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

fn group_thousands(t: &str) -> String {
    let (sign, body) = t.strip_prefix('-').map_or(("", t), |b| ("-", b));
    let (int, frac) = body.split_once('.').map_or((body, None), |(i, f)| (i, Some(f)));
    let mut g = String::new();
    for (k, c) in int.chars().enumerate() {
        if k > 0 && (int.len() - k) % 3 == 0 {
            g.push(',');
        }
        g.push(c);
    }
    match frac {
        Some(f) => format!("{sign}{g}.{f}"),
        None => format!("{sign}{g}"),
    }
}

fn fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' ' => '\u{3000}',
            '!'..='~' => char::from_u32(c as u32 + 0xFEE0).unwrap(),
            c => c,
        })
        .collect()
}

fn rows_of(v: &Value) -> Vec<Map<String, Value>> {
    v.as_array().unwrap().iter().map(|r| r.as_object().unwrap().clone()).collect()
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

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// `<table>`, one `<td>` per cell, whitespace and line breaks inside cells,
/// numeric entities inside some values, `&amp;` in an extra column.
fn to_html(v: &Value) -> String {
    let rows = rows_of(v);
    let mut out = String::from(
        "<!DOCTYPE html>\n<html><head><style>td { padding: 2px }</style>\
         <script>var leak = \"P-000 하남시\";</script></head><body>\n<table>\n<tr><th>no</th><th>memo</th></tr>\n",
    );
    for (i, r) in rows.iter().enumerate() {
        out.push_str("<tr>\n");
        for c in r.values() {
            let mut t = html_escape(&scalar_text(c));
            if i % 3 == 0 {
                t = t.replacen('-', "&#45;", 1).replacen('1', "&#x31;", 1);
            }
            out.push_str(&format!("  <td class=\"c\">\n    {t}  \n  </td>\n"));
        }
        out.push_str("  <td>A &amp; B</td>\n</tr>\n");
    }
    out.push_str("</table></body></html>\n");
    out
}

fn without(v: &Value, keys: &[&str]) -> Value {
    Value::Array(
        rows_of(v)
            .into_iter()
            .map(|mut r| {
                for k in keys {
                    r.shift_remove(*k);
                }
                Value::Object(r)
            })
            .collect(),
    )
}

/// AC1: every variant has matched 32, partial 0. Also covers A1, A2, A3.
#[test]
fn ac1_variants_all_match() {
    let f = fixture();
    let ev = &f.p.evidence;
    println!("markers = {:?}", ev.marker_fields);
    assert_eq!(ev.marker_fields.len(), 3);
    for m in ["id", "addr", "area_m2"] {
        assert!(ev.marker_fields.iter().any(|x| x == m), "{m} is a marker");
    }
    let mv = marked_value();
    let renamed_nested = {
        let mut rows: Vec<Value> = rows_of(&mv)
            .into_iter()
            .map(|r| Value::Object(r.into_iter().enumerate().map(|(j, (_, c))| (format!("col_{j}"), c)).collect()))
            .collect();
        rows.reverse();
        json!({ "data": rows })
    };
    let numbers_as_strings =
        map_scalars(&mv, &|s| if s.is_number() { Value::from(group_thousands(&scalar_text(s))) } else { s.clone() });
    let nfd = map_scalars(&mv, &|s| match s {
        Value::String(t) => Value::from(t.nfd().collect::<String>()),
        o => o.clone(),
    });
    let wide = map_scalars(&mv, &|s| Value::from(fullwidth(&scalar_text(s))));
    let variants: Vec<(&str, Vec<u8>, &str)> = vec![
        ("as is", f.p.marked.clone(), "json"),
        ("renamed + reversed + nested", renamed_nested.to_string().into_bytes(), "json"),
        ("numbers as strings with commas", numbers_as_strings.to_string().into_bytes(), "json"),
        ("hangul NFD", nfd.to_string().into_bytes(), "json"),
        ("ascii full-width", wide.to_string().into_bytes(), "json"),
        ("json -> csv", to_csv(&mv).into_bytes(), "csv"),
        ("html table", to_html(&mv).into_bytes(), "text"),
        ("id deleted", without(&mv, &["id"]).to_string().into_bytes(), "json"),
    ];
    // sanity: the transforms really changed the values
    assert!(String::from_utf8_lossy(&variants[2].1).contains("\",\""), "commas inside number strings");
    assert!(!String::from_utf8_lossy(&variants[3].1).contains("하남시"), "NFD has no precomposed 하남시");
    assert!(String::from_utf8_lossy(&variants[4].1).contains('Ｐ'));
    for (name, bytes, kind) in &variants {
        let r = report(bytes, &f.k_d, ev);
        println!(
            "ac1 {name:32} kind={} matched={} partial={} absent={} hint0={}",
            r["suspect_kind"], r["matched"], r["partial"], r["absent"], r["per_index"]["0"]["record_hint"]
        );
        assert_eq!(r["suspect_kind"], *kind, "{name}");
        assert_eq!(counts(&r), (32, 0, 0), "{name}");
        assert_eq!(r["commit_ok"], true);
        assert_eq!(r["evidence"]["signature_ok"], true);
    }
    // hint rule: the smallest matching record, not the {"data": ...} wrapper
    let r = report(&variants[1].1, &f.k_d, ev);
    assert!(r["per_index"]["0"]["record_hint"].as_str().unwrap().starts_with("$.data["));
    assert_eq!(r["per_index"]["0"]["found"].as_array().unwrap().len(), 3);
}

/// AC2: id and addr deleted -> only area_m2 left: matched 0, partial 32.
#[test]
fn ac2_two_markers_deleted() {
    let f = fixture();
    let v = without(&marked_value(), &["id", "addr"]);
    let r = report(v.to_string().as_bytes(), &f.k_d, &f.p.evidence);
    println!("ac2 matched={} partial={}", r["matched"], r["partial"]);
    assert_eq!(counts(&r), (0, 32, 0));
    assert_eq!(r["per_index"]["5"]["found"], json!(["area_m2"]));
}

/// AC3: unrelated data -> matched 0. Partial counts are recorded.
#[test]
fn ac3_unrelated_data() {
    let f = fixture();
    let ev = &f.p.evidence;
    let other_kd = derive_dataset_key(&K, "test/other-dataset");
    let opts = MarkOptions { n: N, marker_fields: None, exclusions: vec![] };
    let other = build_evidence(f.original.as_bytes(), Format::Json, "test/other-dataset", &opts, &other_kd, CLAIM, &SoftwareSigner::from_seed(&SEED))
        .unwrap();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("other K_d marked file", other.marked.clone()),
        ("original data", f.original.clone().into_bytes()),
    ];
    for (name, bytes) in &cases {
        let r = report(bytes, &f.k_d, ev);
        println!("ac3 {name:30} matched={} partial={} absent={}", r["matched"], r["partial"], r["absent"]);
        assert_eq!(r["matched"], 0, "{name}");
    }
}

/// AC11 (round 2): independent data (dataset A seed 2..5, none of our canaries)
/// wrapped in {"data":[...]} -> matched 0, partial equal to the flat array.
#[test]
fn ac11_wrapped_independent_data() {
    let f = fixture();
    let ev = &f.p.evidence;
    for seed in 2..=5u64 {
        let flat = common::dataset_a(10_000, false, seed);
        let wrapped = format!("{{\"data\":{flat},\"source\":\"other\"}}");
        let rf = report(flat.as_bytes(), &f.k_d, ev);
        let rw = report(wrapped.as_bytes(), &f.k_d, ev);
        println!(
            "ac11 seed {seed}: flat matched={} partial={} | wrapped matched={} partial={} found={}",
            rf["matched"], rf["partial"], rw["matched"], rw["partial"], summarize_found(&rw)
        );
        assert_eq!(rw["matched"], 0, "seed {seed}");
        assert_eq!(rf["matched"], 0, "seed {seed}");
        assert_eq!(rw["partial"], rf["partial"], "seed {seed}");
        if seed == 2 {
            let html = to_html(&serde_json::from_str(&flat).unwrap());
            let rh = report(html.as_bytes(), &f.k_d, ev);
            println!("ac11 seed 2 as html: matched={} partial={}", rh["matched"], rh["partial"]);
        }
    }
}

/// AC12 (round 2): nesting inside a row, rows as arrays, rows wrapped once more -> matched 32.
#[test]
fn ac12_row_shapes() {
    let f = fixture();
    let rows = rows_of(&marked_value());
    let get = |r: &Map<String, Value>, k: &str| r.get(k).cloned().unwrap_or(Value::Null);
    let nested: Vec<Value> = rows
        .iter()
        .map(|r| json!({"id": get(r, "id"), "loc": {"addr": get(r, "addr")}, "m": {"area_m2": get(r, "area_m2")}, "use": get(r, "use_type")}))
        .collect();
    let arrays: Vec<Value> =
        rows.iter().map(|r| json!([get(r, "id"), get(r, "addr"), get(r, "area_m2"), get(r, "use_type")])).collect();
    let wrapped: Vec<Value> = rows.iter().map(|r| json!({"row": Value::Object(r.clone())})).collect();
    for (name, v) in [
        ("nested inside row", json!({"data": nested})),
        ("rows as arrays", Value::Array(arrays)),
        ("each row wrapped {\"row\":{...}}", json!({"items": wrapped})),
    ] {
        let r = report(v.to_string().as_bytes(), &f.k_d, &f.p.evidence);
        println!("ac12 {name:32} matched={} partial={} hint0={}", r["matched"], r["partial"], r["per_index"]["0"]["record_hint"]);
        assert_eq!(counts(&r), (32, 0, 0), "{name}");
    }
}

/// AC13 (round 2): CSV evidence (markers are Str) against JSON numbers and HTML with commas.
#[test]
fn ac13_csv_evidence_numeric_str_marker() {
    let f = fixture();
    let csv_in = to_csv(&serde_json::from_str::<Value>(&f.original).unwrap());
    let k_d = derive_dataset_key(&K, "test/dataset-a-csv");
    let opts = MarkOptions { n: N, marker_fields: None, exclusions: vec![] };
    let p = build_evidence(csv_in.as_bytes(), Format::Csv, "test/dataset-a-csv", &opts, &k_d, CLAIM, &SoftwareSigner::from_seed(&SEED))
        .unwrap();
    println!("ac13 csv evidence markers = {:?}", p.evidence.marker_fields);
    assert!(p.evidence.marker_fields.iter().any(|m| m == "area_m2"));
    assert!(matches!(p.canaries[0].0.get("area_m2"), Some(noreacore::table::Cell::Str(_))), "CSV canary is Str");
    let t = noreacore::table::parse_table(&p.marked, Format::Csv).unwrap();
    let as_json = |strip: bool| -> Vec<u8> {
        let rows: Vec<String> = t
            .rows
            .iter()
            .map(|r| {
                let mut o = Vec::new();
                for (k, c) in &r.0 {
                    let noreacore::table::Cell::Str(v) = c else { panic!("csv cell") };
                    if k == "area_m2" {
                        let n = if strip && v.contains('.') { v.trim_end_matches('0').trim_end_matches('.').to_string() } else { v.clone() };
                        o.push(format!("{}:{n}", Value::from(k.as_str())));
                    } else {
                        o.push(format!("{}:{}", Value::from(k.as_str()), Value::from(v.as_str())));
                    }
                }
                format!("{{{}}}", o.join(","))
            })
            .collect();
        format!("[{}]", rows.join(",")).into_bytes()
    };
    let html = {
        let v: Value = serde_json::from_slice(&as_json(false)).unwrap();
        let grouped = map_scalars(&v, &|s| if s.is_number() { Value::from(group_thousands(&scalar_text(s))) } else { s.clone() });
        to_html(&grouped).into_bytes()
    };
    assert!(String::from_utf8_lossy(&html).contains(",") && String::from_utf8_lossy(&as_json(true)).contains("\"area_m2\":"));
    for (name, bytes) in [("json numbers 1200", as_json(true)), ("json numbers 1200.00", as_json(false)), ("html 1,200.00", html)] {
        let r = report(&bytes, &k_d, &p.evidence);
        println!("ac13 {name:22} kind={} matched={} partial={}", r["suspect_kind"], r["matched"], r["partial"]);
        assert_eq!(counts(&r), (32, 0, 0), "{name}");
    }
    // text: Str "330.5" inside 1330.5 does not count
    let rows = vec![(0u32, row_from_json(&json!({"id": "X-731", "area_m2": "330.5"})).unwrap())];
    let m: Vec<String> = vec!["id".into(), "area_m2".into()];
    let r = match_rows("X-731 면적 1330.5㎡".as_bytes(), SuspectKind::Text, &rows, &m);
    println!("ac13 text Str 330.5 in 1330.5: matched={:?} partial={:?}", r.matched, r.partial);
    assert!(r.matched.is_empty());
    assert_eq!(match_rows("X-731 면적 330.5㎡".as_bytes(), SuspectKind::Text, &rows, &m).matched, vec![0]);
}

/// AC14 (round 2): alphanumeric boundary for every marker; &nbsp; decoded.
#[test]
fn ac14_text_boundaries_and_nbsp() {
    let rows = vec![(0u32, row_from_json(&json!({"id": "P-217", "area_m2": 330.5})).unwrap())];
    let m: Vec<String> = vec!["id".into(), "area_m2".into()];
    let r = match_rows("P-2170 330.5".as_bytes(), SuspectKind::Text, &rows, &m);
    println!("ac14 P-217 in P-2170: matched={:?} partial={:?} found={:?}", r.matched, r.partial, r.per_index.get(&0).map(|p| &p.found));
    assert!(r.matched.is_empty());
    assert_eq!(r.per_index[&0].found, vec!["area_m2"]);
    let html = "<table><tr><td>P-217&nbsp;</td><td>330.5</td></tr></table>";
    let r = match_rows(html.as_bytes(), SuspectKind::Text, &rows, &m);
    println!("ac14 <td>P-217&nbsp;</td>: matched={:?}", r.matched);
    assert_eq!(r.matched, vec![0]);
}

fn summarize_found(r: &Value) -> String {
    let mut by: std::collections::BTreeMap<String, usize> = Default::default();
    for (_, p) in r["per_index"].as_object().unwrap() {
        let f: Vec<&str> = p["found"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
        *by.entry(f.join("+")).or_default() += 1;
    }
    format!("{by:?}")
}

/// AC4: wrong K_d -> commit_ok false, matched 0.
#[test]
fn ac4_wrong_key() {
    let f = fixture();
    let wrong = derive_dataset_key(&[0x45; 32], DS);
    let r = report(&f.p.marked, &wrong, &f.p.evidence);
    assert_eq!(r["commit_ok"], false);
    assert_eq!(counts(&r), (0, 0, 32));
    assert_eq!(r["evidence"]["signature_ok"], true, "the evidence itself is fine");
}

/// AC5: canary_root changed by one character -> commit_ok false, signature_ok false.
#[test]
fn ac5_tampered_root() {
    let f = fixture();
    let mut ev = f.p.evidence.clone();
    let c = if ev.canary_root.starts_with('0') { "1" } else { "0" };
    ev.canary_root.replace_range(0..1, c);
    let r = report(&f.p.marked, &f.k_d, &ev);
    assert_eq!(r["commit_ok"], false);
    assert_eq!(r["evidence"]["signature_ok"], false);
    assert_eq!(r["matched"], 0);
}

/// AC6: text path window (512 chars) and number boundary.
#[test]
fn ac6_text_window_and_number_boundary() {
    let row = row_from_json(&json!({"id": "X-731", "addr": "하남시 미사동 5-3", "area_m2": 330.5})).unwrap();
    let rows = vec![(0u32, row)];
    let markers: Vec<String> = ["addr", "id", "area_m2"].iter().map(|s| s.to_string()).collect();
    let filler = |n: usize| "가".repeat(n);
    // start offsets: addr at 0, id at 11 chars + space + gap + space
    for (gap, expect_match) in [(480usize, true), (498, true), (499, true), (500, false), (600, false)] {
        let doc = format!("하남시 미사동 5-3 {} X-731", filler(gap));
        let start_diff = "하남시 미사동 5-3 ".chars().count() + gap + 1;
        let r = match_rows(doc.as_bytes(), SuspectKind::Text, &rows, &markers);
        println!("ac6 gap {gap} (start offset difference {start_diff}): matched={:?} partial={:?}", r.matched, r.partial);
        assert_eq!(!r.matched.is_empty(), expect_match, "gap {gap}");
        assert_eq!(start_diff <= 512, expect_match);
        if !expect_match {
            assert_eq!(r.partial, vec![0]);
        }
    }
    // the spec's two cases: > 512 apart -> no match, within 500 -> match
    let far = format!("X-731 {} 하남시 미사동 5-3", filler(700));
    assert!(match_rows(far.as_bytes(), SuspectKind::Text, &rows, &markers).matched.is_empty());
    let near = format!("X-731 {} 하남시 미사동 5-3", filler(400));
    assert_eq!(match_rows(near.as_bytes(), SuspectKind::Text, &rows, &markers).matched, vec![0]);
    // number boundary: 330.5 inside 1330.5 does not count
    let rows2 = vec![(0u32, row_from_json(&json!({"id": "X-731", "area_m2": 330.5})).unwrap())];
    let m2: Vec<String> = vec!["id".into(), "area_m2".into()];
    let r = match_rows("X-731 면적 1330.5㎡".as_bytes(), SuspectKind::Text, &rows2, &m2);
    assert!(r.matched.is_empty());
    assert_eq!(r.partial, vec![0]);
    let r = match_rows("X-731 면적 330.5㎡".as_bytes(), SuspectKind::Text, &rows2, &m2);
    assert_eq!(r.matched, vec![0]);
    let r = match_rows("X-731 면적 330.50㎡ 1,330.5".as_bytes(), SuspectKind::Text, &rows2, &m2);
    assert!(r.matched.is_empty(), "330.50 is not the generated text 330.5 nor its stripped form");
}

fn suspect_missing(drop: &[usize]) -> Vec<u8> {
    let f = fixture();
    let ids: Vec<String> = drop
        .iter()
        .map(|&i| match f.p.canaries[i].0.get("id") {
            Some(noreacore::table::Cell::Str(s)) => s.clone(),
            _ => panic!("id is Str"),
        })
        .collect();
    let rows: Vec<Value> = rows_of(&marked_value())
        .into_iter()
        .filter(|r| !ids.iter().any(|id| r.get("id") == Some(&Value::from(id.as_str()))))
        .map(Value::Object)
        .collect();
    Value::Array(rows).to_string().into_bytes()
}

fn meta() -> SuspectMeta {
    SuspectMeta {
        source_claim: Some("https://example.com/data.json".into()),
        captured_claim: Some("2026-11-09T10:00:00Z".into()),
        capture_method_claim: Some("browser save-as".into()),
    }
}

/// AC7: disclose defaults to all matched; non-matched index refused; force includes it.
#[test]
fn ac7_disclose() {
    let f = fixture();
    let ev = &f.p.evidence;
    let suspect = suspect_missing(&[5, 9]);
    let d: Value =
        serde_json::from_str(&disclose(ev, &f.k_d, &suspect, None, &meta(), CLAIM, false).unwrap()).unwrap();
    let keys: Vec<&String> = d.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["schema", "created_claim", "evidence", "suspect", "disclosed", "shape"]);
    assert_eq!(d["schema"], "norea.disclosure.v1");
    assert_eq!(d["created_claim"], CLAIM);
    assert_eq!(serde_json::from_value::<Evidence>(d["evidence"].clone()).unwrap(), *ev, "evidence is embedded unchanged");
    let sk: Vec<&String> = d["suspect"].as_object().unwrap().keys().collect();
    assert_eq!(sk, ["sha256", "kind", "source_claim", "captured_claim", "capture_method_claim"]);
    assert_eq!(d["suspect"]["kind"], "json");
    let idx: Vec<u64> = d["disclosed"].as_array().unwrap().iter().map(|x| x["index"].as_u64().unwrap()).collect();
    let want: Vec<u64> = (0..32).filter(|i| *i != 5 && *i != 9).collect();
    assert_eq!(idx, want, "default = all matched, ascending");
    let e0 = &d["disclosed"][0];
    let ek: Vec<&String> = e0.as_object().unwrap().keys().collect();
    assert_eq!(ek, ["index", "row", "path"]);
    assert_eq!(e0["path"].as_array().unwrap().len(), 5, "32 leaves -> 5 path nodes");
    assert!(e0["path"][0].as_str().unwrap().len() == 64);
    // explicit indices
    let d2: Value =
        serde_json::from_str(&disclose(ev, &f.k_d, &suspect, Some(&[7, 3]), &SuspectMeta::default(), CLAIM, false).unwrap())
            .unwrap();
    assert_eq!(d2["disclosed"].as_array().unwrap().len(), 2);
    assert_eq!(d2["disclosed"][0]["index"], 3);
    assert_eq!(d2["suspect"].as_object().unwrap().len(), 2, "no claims -> no claim keys");
    // non-matched -> error
    let e = disclose(ev, &f.k_d, &suspect, Some(&[1, 5]), &meta(), CLAIM, false).unwrap_err();
    assert_eq!(e.code, ErrorCode::BadDisclosure);
    println!("ac7 refused: {}", e.message);
    assert_eq!(disclose(ev, &f.k_d, &suspect, Some(&[1, 1]), &meta(), CLAIM, false).unwrap_err().code, ErrorCode::BadInput);
    assert_eq!(disclose(ev, &f.k_d, &suspect, Some(&[32]), &meta(), CLAIM, true).unwrap_err().code, ErrorCode::BadInput);
    assert_eq!(disclose(ev, &f.k_d, &suspect, None, &meta(), "yesterday", false).unwrap_err().code, ErrorCode::BadInput);
    let wrong = derive_dataset_key(&[0x45; 32], DS);
    assert_eq!(disclose(ev, &wrong, &suspect, None, &meta(), CLAIM, false).unwrap_err().code, ErrorCode::BadBlob);
    // force -> included, verifier says NOT REPRODUCED
    let forced = disclose(ev, &f.k_d, &suspect, Some(&[1, 5]), &meta(), CLAIM, true).unwrap();
    let r: Value = serde_json::from_str(&verify_disclosure(&forced, &suspect).unwrap()).unwrap();
    println!("ac7 forced report summary {} / statement:\n{}", r["summary"], r["statement"].as_str().unwrap());
    assert_eq!(r["disclosed"][0]["matched"], true);
    assert_eq!(r["disclosed"][1]["matched"], false);
    assert_eq!(r["disclosed"][1]["merkle_ok"], true, "the forced canary is committed, just not in the copy");
    assert_eq!(r["summary"]["not_reproduced"], 1);
    assert!(r["statement"].as_str().unwrap().contains("NOT REPRODUCED: index 5"));
    println!("ac16 forced verdict {}", r["verdict"]);
    assert_eq!(r["verdict"], json!({"integrity_ok": true, "all_reproduced": false}));
}

fn disclosure_full() -> (String, Vec<u8>) {
    let f = fixture();
    let d = disclose(&f.p.evidence, &f.k_d, &f.p.marked, None, &meta(), CLAIM, false).unwrap();
    (d, f.p.marked.clone())
}

fn verify(d: &str, suspect: &[u8]) -> Value {
    serde_json::from_str(&verify_disclosure(d, suspect).unwrap()).unwrap()
}

/// AC8: verify_disclosure, no secret.
#[test]
fn ac8_verify_disclosure() {
    let (d, suspect) = disclosure_full();
    let r = verify(&d, &suspect);
    let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["schema", "evidence", "suspect_hash_ok", "disclosed", "summary", "verdict", "statement"]);
    assert_eq!(r["verdict"], json!({"integrity_ok": true, "all_reproduced": true}));
    let ek: Vec<&String> = r["evidence"].as_object().unwrap().keys().collect();
    assert_eq!(ek, ["signature_ok", "evidence_id_ok", "blob_hash_ok", "evidence_id", "anchors"]);
    assert_eq!(r["summary"], json!({"disclosed": 32, "merkle_ok": 32, "matched": 32, "not_reproduced": 0}));
    assert!(r["disclosed"].as_array().unwrap().iter().all(|x| x["merkle_ok"] == true && x["matched"] == true));
    assert_eq!(r["suspect_hash_ok"], true);
    let st = r["statement"].as_str().unwrap();
    assert!(st.starts_with("Integrity: PASS"));
    assert!(st.contains("This evidence does not prove when it was created."), "no anchor -> time not proven");
    assert!(st.contains("Reproduced: 32 of 32 disclosed canaries were reproduced in the suspect copy."));
    assert!(st.contains("This is an upper bound under the generator model, not a real-world probability."));
    let fp = &noreacore::evidence::sha256_hex(&B64.decode(&fixture().p.evidence.vk_b64).unwrap())[..16];
    assert!(st.contains(fp), "vk fingerprint");

    let base: Value = serde_json::from_str(&d).unwrap();
    // B2: one row value changed -> that item fails Merkle
    let mut t = base.clone();
    t["disclosed"][3]["row"]["use_type"] = Value::from("임야X");
    let r = verify(&t.to_string(), &suspect);
    assert_eq!(r["disclosed"][3]["merkle_ok"], false);
    assert_eq!(r["summary"]["merkle_ok"], 31);
    assert!(r["statement"].as_str().unwrap().starts_with("Integrity: FAIL"));
    // B2: a row that is not a canary at all, with the path of index 4
    let mut t = base.clone();
    let real = rows_of(&serde_json::from_str::<Value>(&fixture().original).unwrap())[0].clone();
    t["disclosed"][4]["row"] = Value::Object(real);
    assert_eq!(verify(&t.to_string(), &suspect)["disclosed"][4]["merkle_ok"], false);
    // path changed
    let mut t = base.clone();
    let p0 = t["disclosed"][0]["path"][0].as_str().unwrap().to_string();
    let (first, rest) = p0.split_at(1);
    let flipped = format!("{}{rest}", if first == "0" { "1" } else { "0" });
    t["disclosed"][0]["path"][0] = Value::from(flipped);
    assert_eq!(verify(&t.to_string(), &suspect)["disclosed"][0]["merkle_ok"], false);
    // path too short
    let mut t = base.clone();
    t["disclosed"][0]["path"].as_array_mut().unwrap().pop();
    assert_eq!(verify(&t.to_string(), &suspect)["disclosed"][0]["merkle_ok"], false);
    // suspect bytes changed
    let mut s2 = suspect.clone();
    s2.push(b'\n');
    let r = verify(&d, &s2);
    assert_eq!(r["suspect_hash_ok"], false);
    assert!(r["statement"].as_str().unwrap().contains("suspect hash mismatch"));
    // evidence signature changed -> whole FAIL
    let mut t = base.clone();
    let mut sig = B64.decode(t["evidence"]["sig_b64"].as_str().unwrap()).unwrap();
    sig[100] ^= 1;
    t["evidence"]["sig_b64"] = Value::from(B64.encode(sig));
    let r = verify(&t.to_string(), &suspect);
    assert_eq!(r["evidence"]["signature_ok"], false);
    let st = r["statement"].as_str().unwrap();
    assert!(st.starts_with("Integrity: FAIL (evidence does not verify"), "{st}");
    assert!(st.contains("Signature: NOT valid"));
    println!("ac16 signature tampered verdict {}", r["verdict"]);
    assert_eq!(r["verdict"]["integrity_ok"], false);
    // signed count is what counts: changing canary_count breaks the signature
    let mut t = base.clone();
    t["evidence"]["canary_count"] = Value::from(33);
    assert_eq!(verify(&t.to_string(), &suspect)["evidence"]["signature_ok"], false);
    // hand-made package with nothing disclosed: verdict and statement agree on FAIL
    let mut t = base.clone();
    t["disclosed"] = json!([]);
    let r = verify(&t.to_string(), &suspect);
    println!("ac16 zero disclosed verdict {}", r["verdict"]);
    assert_eq!(r["verdict"]["integrity_ok"], false);
    assert!(r["statement"].as_str().unwrap().starts_with("Integrity: FAIL"));
    // structural problems are errors
    for bad in [
        "not json".to_string(),
        json!({"schema": "norea.disclosure.v2"}).to_string(),
        {
            let mut t = base.clone();
            let a = t["disclosed"].as_array_mut().unwrap();
            a.swap(0, 1);
            t.to_string()
        },
        {
            let mut t = base.clone();
            t["disclosed"][0]["path"][0] = Value::from("zz");
            t.to_string()
        },
    ] {
        assert_eq!(verify_disclosure(&bad, &suspect).unwrap_err().code, ErrorCode::BadDisclosure);
    }
}

/// AC9: the verifier works without K_d; the blob is only hashed.
#[test]
fn ac9_verifier_needs_no_secret() {
    let (d, suspect) = disclosure_full();
    let v: Value = serde_json::from_str(&d).unwrap();
    assert!(!v["evidence"]["canary_blob_b64"].as_str().unwrap().is_empty(), "blob is in the package");
    // verify_disclosure takes no key at all; it passes:
    assert_eq!(verify(&d, &suspect)["summary"]["merkle_ok"], 32);
    // the blob is hashed, never opened: a same-length replacement only fails blob_hash_ok
    let mut t = v.clone();
    let mut blob = B64.decode(t["evidence"]["canary_blob_b64"].as_str().unwrap()).unwrap();
    blob[0] ^= 1;
    t["evidence"]["canary_blob_b64"] = Value::from(B64.encode(blob));
    let r = verify(&t.to_string(), &suspect);
    assert_eq!(r["evidence"]["blob_hash_ok"], false);
    assert_eq!(r["summary"]["merkle_ok"], 32, "Merkle check does not depend on the blob");
    // source check: the verifier code path (from `struct Item` to the end of
    // disclose.rs) does not call blob decryption or take a key
    let src = include_str!("../src/disclose.rs");
    let verifier = &src[src.find("struct Item").unwrap()..];
    for forbidden in ["open_blob", "committed_rows", "derive_blob_key", "k_d", "Key32"] {
        assert!(!verifier.contains(forbidden), "verifier path mentions {forbidden}");
    }
}

/// AC10 plus extra kinds: 50 000-row suspect check (release timing).
#[test]
fn ac10_check_50k_rows() {
    let mut rows = Vec::with_capacity(50_000);
    let si = ["하남시 미사동", "하남시 망월동", "성남시 정자동", "용인시 죽전동"];
    for i in 0..50_000u64 {
        rows.push(format!(
            "  {{\"id\": \"P-{:06}\", \"addr\": \"{} {}-{}\", \"area_m2\": {}.{:02}, \"use\": \"{}\"}}",
            i * 3,
            si[(i % 4) as usize],
            1 + (i * 7) % 997,
            1 + i % 37,
            50 + (i * 13) % 1950,
            i % 100,
            ["대", "전", "답"][(i % 3) as usize]
        ));
    }
    let src = format!("[\n{}\n]\n", rows.join(",\n"));
    let k_d = derive_dataset_key(&K, "perf");
    let opts = MarkOptions { n: N, marker_fields: None, exclusions: vec![] };
    let p = build_evidence(src.as_bytes(), Format::Json, "perf", &opts, &k_d, CLAIM, &SoftwareSigner::from_seed(&SEED)).unwrap();
    let mv: Value = serde_json::from_slice(&p.marked).unwrap();
    let csv = to_csv(&mv).into_bytes();
    let html = to_html(&mv).into_bytes();
    for (name, bytes) in [("json", p.marked.clone()), ("csv", csv), ("html", html)] {
        let mut times = Vec::new();
        let mut last = Value::Null;
        for _ in 0..3 {
            let t = Instant::now();
            last = report(&bytes, &k_d, &p.evidence);
            times.push(t.elapsed());
        }
        println!(
            "ac10 {name}: {} bytes, 50032 rows, check n=32: {:?} (matched {})",
            bytes.len(),
            times,
            last["matched"]
        );
        assert_eq!(last["matched"], 32);
        if name == "json" && !cfg!(debug_assertions) {
            assert!(times.iter().all(|t| t.as_millis() < 1000), "{times:?}");
        }
    }
    let d = disclose(&p.evidence, &k_d, &p.marked, None, &SuspectMeta::default(), CLAIM, false).unwrap();
    let t = Instant::now();
    let r: Value = serde_json::from_str(&verify_disclosure(&d, &p.marked).unwrap()).unwrap();
    println!("ac10 verify_disclosure json 50k: {:?} (matched {})", t.elapsed(), r["summary"]["matched"]);
}

/// Frozen vector evidence + its marked file: matched 4 (WP-03 hand-off), and
/// the example JSON for the WP-04 report.
#[test]
fn vector_evidence_examples() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/vectors/norea-evidence-v1.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let k_d = derive_dataset_key(&[0x11; 32], "vector/records/v1");
    for case in ["json", "csv"] {
        let c = v.get(case).unwrap();
        let ev: Evidence = serde_json::from_value(c["evidence"].clone()).unwrap();
        let marked = c["marked_utf8"].as_str().unwrap().as_bytes();
        assert_eq!(detect_suspect_kind(marked), if case == "json" { SuspectKind::Json } else { SuspectKind::Csv });
        let rep = check(marked, &k_d, &ev).unwrap();
        let r: Value = serde_json::from_str(&rep).unwrap();
        assert_eq!(counts(&r), (4, 0, 0), "{case}");
        let d = disclose(&ev, &k_d, marked, Some(&[1, 2]), &meta(), "2026-11-09T12:00:00Z", false).unwrap();
        let vr = verify_disclosure(&d, marked).unwrap();
        let vrv: Value = serde_json::from_str(&vr).unwrap();
        assert_eq!(vrv["summary"]["matched"], 2);
        let prob = vrv["statement"].as_str().unwrap().lines().find(|l| l.starts_with("Probability:")).unwrap().to_string();
        println!("ac15 {case} probability line:\n{prob}");
        assert!(prob.contains("2 of 3 markers"), "{prob}");
        assert!(prob.contains("2^-13.25"), "{prob}");
        assert!(prob.contains("C(3,2)=3"));
        // R: JSON 10 rows; CSV 11 records (the header record counts, shape-v1 §7.2)
        let r = if case == "json" { 10 } else { 11 };
        assert!(prob.contains(&format!("R={r} suspect records")) && prob.contains("n=4 canaries"), "{prob}");
        assert!(prob.contains(&format!("4*{r}*2^-13.25")));
        if case == "json" {
            println!("EXAMPLE check-report:\n{rep}");
            let mut dv: Value = serde_json::from_str(&d).unwrap();
            for k in ["vk_b64", "sig_b64", "canary_blob_b64"] {
                let s = dv["evidence"][k].as_str().unwrap().to_string();
                dv["evidence"][k] = Value::from(format!("{}...({} chars)", &s[..16], s.len()));
            }
            println!("EXAMPLE disclosure (long base64 shortened):\n{dv}");
            println!("EXAMPLE disclosure-report:\n{vr}");
            println!("EXAMPLE statement:\n{}", vrv["statement"].as_str().unwrap());
        }
    }
}
