//! record.shape.v1 test vectors: `draw` values and canary rows for small fixed
//! inputs (WP-02). Separate from the WP-03 evidence vector and not frozen, but
//! a change here changes every canary: report it.
//!
//! Regenerate:
//!   NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test shape_vectors

use std::path::PathBuf;

use noreacore::canary::{draw, mark, MarkOptions};
use noreacore::table::{canon_row, Format};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn k_d() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn json_input() -> String {
    let si = ["하남시", "성남시", "광주시"];
    let dong = ["미사동", "망월동", "선동", "풍산동", "덕풍동"];
    let mut rows = Vec::new();
    for i in 0..40usize {
        let memo = match i % 6 {
            0 => "null".to_string(),
            1 => String::new(),
            _ => format!("\"확인 {}건\"", i % 4),
        };
        let memo = if memo.is_empty() { String::new() } else { format!(",\n    \"memo\": {memo}") };
        rows.push(format!(
            "  {{\n    \"id\": \"R-{:03}\",\n    \"addr\": \"{} {} {}-{}\",\n    \"area_m2\": {}.{:02},\n    \"use\": \"{}\",\n    \"public\": {}{}\n  }}",
            i * 5,
            si[i % 3],
            dong[i % 5],
            10 + (i * 37) % 900,
            i % 7 + 1,
            60 + (i * 53) % 1500,
            (i * 11) % 100,
            ["대", "전", "답", "임"][i % 4],
            i % 3 == 0,
            memo
        ));
    }
    format!("[\n{}\n]\n", rows.join(",\n"))
}

fn csv_input() -> String {
    let mut s = String::from("code,name,price,grade,remark\r\n");
    for i in 0..40usize {
        let remark = if i % 4 == 0 { String::new() } else { format!("\"비고, {}\"", i % 3) };
        s.push_str(&format!(
            "{:04},{}상회 {}호,{},{},{}\r\n",
            i * 13 + 7,
            ["가나", "다라", "마바사"][i % 3],
            i % 9 + 1,
            1000 + (i * 271) % 9000,
            ["A", "B", "C"][i % 3],
            remark
        ));
    }
    s
}

/// Protected NUMERIC with a consecutive run (w = 0 gaps) to lock the r2.1 move rule.
fn dense_codes_input() -> String {
    let mut codes: Vec<u32> = (1000..1020).collect();
    codes.extend((0..20).map(|k| 1100 + k * 5));
    let rows: Vec<String> = codes
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{{\"code\":{c},\"tag\":\"T-{:03}\"}}", i * 7))
        .collect();
    format!("[{}]\n", rows.join(",\n"))
}

/// Protected NUMERIC with many duplicates (r2.2: V keeps duplicates, so the
/// dense value 100 carries row weight into the gap after it).
fn dup_values_input() -> String {
    let mut prices: Vec<u32> = vec![100; 30];
    prices.extend((0..10).map(|k| 200 + k * 10));
    let rows: Vec<String> = prices
        .iter()
        .enumerate()
        .map(|(i, p)| format!("{{\"tag\":\"D-{:03}\",\"price\":{p}}}", i * 7))
        .collect();
    format!("[{}]\n", rows.join(",\n"))
}

fn case(name: &str, input: &str, format: Format, n: u32) -> Value {
    let k = k_d();
    let out = mark(input.as_bytes(), format, &k, &MarkOptions { n, marker_fields: None, exclusions: vec![] })
        .expect("mark");
    let canaries: Vec<String> = out.canaries.iter().map(|r| String::from_utf8(canon_row(r)).unwrap()).collect();
    json!({
        "name": name,
        "format": match format { Format::Json => "json", Format::Csv => "csv" },
        "n": n,
        "input_utf8": input,
        "markers": out.markers,
        "canaries": canaries,
        "marked_sha256": hex(&Sha256::digest(&out.marked)),
        "marked_utf8": String::from_utf8(out.marked.clone()).unwrap(),
        "shape_summary": out.shape_summary,
    })
}

fn build() -> Value {
    let k = k_d();
    let mut draws = Vec::new();
    for (label, i, attempt, ctr) in
        [("canary", 0u32, 0u8, 0u32), ("canary", 0, 0, 1), ("canary", 0, 1, 0), ("canary", 1, 0, 0), ("canary", 4_000_000_000, 63, 77), ("pos", 0, 0, 0), ("pos", 5, 0, 0), ("", 0, 0, 0), ("한글", 2, 2, 2)]
    {
        draws.push(json!({ "label": label, "i": i, "attempt": attempt, "ctr": ctr, "value": draw(&k, label, i, attempt, ctr).to_string() }));
    }
    json!({
        "kind": "record.shape.v1",
        "note": "WP-02 vector. Not frozen. Regenerate with NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test shape_vectors",
        "k_d_hex": hex(&k),
        "draws": draws,
        "cases": [
            case("json-parcels", &json_input(), Format::Json, 6),
            case("csv-shops", &csv_input(), Format::Csv, 5),
            case("json-dense-codes", &dense_codes_input(), Format::Json, 8),
            case("json-dup-values", &dup_values_input(), Format::Json, 8),
        ],
    })
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors/shape-v1.json")
}

#[test]
fn shape_v1_vectors() {
    let got = build();
    // Determinism within one process as well.
    assert_eq!(got, build());
    if std::env::var("NOREA_WRITE_VECTORS").as_deref() == Ok("1") {
        let mut s = serde_json::to_string_pretty(&got).unwrap();
        s.push('\n');
        std::fs::write(path(), s).expect("write vector");
        println!("wrote {}", path().display());
        return;
    }
    let want: Value = serde_json::from_slice(&std::fs::read(path()).expect("vector file missing; run with NOREA_WRITE_VECTORS=1"))
        .expect("vector json");
    assert_eq!(got["draws"], want["draws"], "draw values changed");
    for (g, w) in got["cases"].as_array().unwrap().iter().zip(want["cases"].as_array().unwrap()) {
        assert_eq!(g["input_utf8"], w["input_utf8"], "{} input changed", w["name"]);
        assert_eq!(g["markers"], w["markers"], "{} markers changed", w["name"]);
        assert_eq!(g["canaries"], w["canaries"], "{} canaries changed", w["name"]);
        assert_eq!(g["marked_utf8"], w["marked_utf8"], "{} marked bytes changed", w["name"]);
        assert_eq!(g["marked_sha256"], w["marked_sha256"], "{} marked hash changed", w["name"]);
        assert_eq!(g["shape_summary"], w["shape_summary"], "{} shape summary changed", w["name"]);
    }
    assert_eq!(got, want);
}
