//! Real-vs-canary distinguishability (WP-02 acceptance 3, 4; shape-v1 §9).
//! Test-only tool. No dev-dependencies: own PRNG, logistic regression, AUC,
//! KS, Monte Carlo chi-square, and an independent template tokenizer (it does
//! not reuse shape.rs, so a tokenizer bug there does not hide itself here).
//!
//! Judgement follows shape-v1 r2 §9: n = 1000, auto markers; n = 64 is reported only.
//! Fast check (runs in `cargo test`): dataset A, n = 1000, key 1.
//! Full report (dataset A keys 2..3 judged, n = 64 and A' reported):
//!   cargo test --release -p noreacore --test distinguishability full_report -- --ignored --nocapture
//! Missing rate is judged over K = 10 keys (r2.2 §9); per-key bands are reported only.
//! Public CSV (judged at n = 1000, keys 1..3):
//!   NOREA_PUBLIC_CSV=/path/file.csv [NOREA_PUBLIC_CSV_SHA256=hex] cargo test --release -p noreacore \
//!     --test distinguishability public_csv -- --ignored --nocapture

mod common;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use common::{dataset_a, Rng};

use noreacore::canary::{mark, MarkOptions};
use noreacore::norm::normalize_text;
use noreacore::shape::{infer_shape, inspect, Kind};
use sha2::{Digest, Sha256};
use noreacore::table::{parse_table, Cell, Format, Row};

// PRNG and dataset A live in tests/common (shared with check_disclose.rs).

// ---------------------------------------------------------------- independent template key

fn template_key(s: &str) -> String {
    fn class(c: char) -> Option<char> {
        if c.is_ascii_digit() {
            Some('D')
        } else if ('\u{AC00}'..='\u{D7A3}').contains(&c) {
            Some('H')
        } else if c.is_ascii_alphabetic() {
            Some('L')
        } else {
            None
        }
    }
    let mut out = String::new();
    let mut cur: Option<(char, usize)> = None;
    for c in s.chars() {
        match (class(c), cur) {
            (Some(k), Some((ck, n))) if k == ck => cur = Some((ck, n + 1)),
            (k, _) => {
                if let Some((ck, n)) = cur.take() {
                    out.push_str(&format!("{ck}{n}|"));
                }
                match k {
                    Some(k) => cur = Some((k, 1)),
                    None => out.push_str(&format!("'{c}'|")),
                }
            }
        }
    }
    if let Some((ck, n)) = cur {
        out.push_str(&format!("{ck}{n}|"));
    }
    out
}

fn text_of(c: &Cell, format: Format) -> Option<String> {
    match c {
        Cell::Missing | Cell::Null => None,
        Cell::Str(s) if format == Format::Csv && s.is_empty() => None,
        Cell::Str(s) => Some(s.clone()),
        Cell::Num { text, .. } => Some(text.clone()),
        Cell::Bool(b) => Some(b.to_string()),
        Cell::Opaque(v) => Some(v.to_string()),
    }
}

// ---------------------------------------------------------------- statistics

fn ks(a: &[f64], b: &[f64]) -> f64 {
    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort_by(f64::total_cmp);
    b.sort_by(f64::total_cmp);
    let (mut i, mut j, mut d) = (0, 0, 0.0f64);
    while i < a.len() && j < b.len() {
        let x = a[i].min(b[j]);
        while i < a.len() && a[i] <= x {
            i += 1;
        }
        while j < b.len() && b[j] <= x {
            j += 1;
        }
        d = d.max((i as f64 / a.len() as f64 - j as f64 / b.len() as f64).abs());
    }
    d
}

fn quantile(v: &mut [f64], q: f64) -> f64 {
    v.sort_by(f64::total_cmp);
    v[((v.len() - 1) as f64 * q).round() as usize]
}

/// Monte Carlo chi-square p-value of observed category counts against the
/// real distribution. Categories unseen in real data give p = 0.
fn chi2_mc(real: &BTreeMap<String, usize>, obs: &BTreeMap<String, usize>, rng: &mut Rng) -> (f64, usize) {
    let n: usize = obs.values().sum();
    let total: usize = real.values().sum();
    if n == 0 {
        return (1.0, 0);
    }
    let unseen = obs.keys().filter(|k| !real.contains_key(*k)).count();
    if unseen > 0 {
        return (0.0, unseen);
    }
    let cats: Vec<(&String, f64)> = real.iter().map(|(k, c)| (k, *c as f64 / total as f64)).collect();
    let stat = |counts: &dyn Fn(&String) -> usize| -> f64 {
        cats.iter()
            .map(|(k, p)| {
                let e = p * n as f64;
                let o = counts(k) as f64;
                (o - e) * (o - e) / e
            })
            .sum()
    };
    let x_obs = stat(&|k| obs.get(k).copied().unwrap_or(0));
    let cum: Vec<f64> = cats
        .iter()
        .scan(0.0, |s, (_, p)| {
            *s += p;
            Some(*s)
        })
        .collect();
    let reps = 2000;
    let mut ge = 0;
    for _ in 0..reps {
        let mut c = vec![0usize; cats.len()];
        for _ in 0..n {
            let u = rng.f64();
            let k = cum.partition_point(|&x| x <= u).min(cats.len() - 1);
            c[k] += 1;
        }
        let idx: BTreeMap<&String, usize> = cats.iter().enumerate().map(|(k, (s, _))| (*s, c[k])).collect();
        if stat(&|k| idx[k]) >= x_obs - 1e-9 {
            ge += 1;
        }
    }
    ((1 + ge) as f64 / (1 + reps) as f64, 0)
}

fn auc(scores: &[f64], labels: &[bool]) -> f64 {
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|&a, &b| scores[a].total_cmp(&scores[b]));
    let mut ranks = vec![0.0; scores.len()];
    let mut k = 0;
    while k < idx.len() {
        let mut e = k;
        while e + 1 < idx.len() && scores[idx[e + 1]] == scores[idx[k]] {
            e += 1;
        }
        let r = (k + e) as f64 / 2.0 + 1.0;
        for t in k..=e {
            ranks[idx[t]] = r;
        }
        k = e + 1;
    }
    let n1 = labels.iter().filter(|&&l| l).count() as f64;
    let n0 = labels.len() as f64 - n1;
    let s1: f64 = ranks.iter().zip(labels).filter(|(_, &l)| l).map(|(r, _)| r).sum();
    (s1 - n1 * (n1 + 1.0) / 2.0) / (n1 * n0)
}

/// Class-balanced L2 logistic regression on sparse binary features, full-batch
/// gradient descent. Returns pooled out-of-fold scores (5-fold stratified).
fn cv_scores(x: &[Vec<usize>], y: &[bool], nfeat: usize, rng: &mut Rng) -> Vec<f64> {
    let folds = 5;
    let mut fold = vec![0usize; y.len()];
    for class in [false, true] {
        let mut idx: Vec<usize> = (0..y.len()).filter(|&i| y[i] == class).collect();
        for k in (1..idx.len()).rev() {
            let j = rng.below(k + 1);
            idx.swap(k, j);
        }
        for (k, &i) in idx.iter().enumerate() {
            fold[i] = k % folds;
        }
    }
    let mut out = vec![0.0; y.len()];
    for f in 0..folds {
        let train: Vec<usize> = (0..y.len()).filter(|&i| fold[i] != f).collect();
        let n1 = train.iter().filter(|&&i| y[i]).count() as f64;
        let n0 = train.len() as f64 - n1;
        let (w1, w0) = (train.len() as f64 / (2.0 * n1), train.len() as f64 / (2.0 * n0));
        let mut w = vec![0.0f64; nfeat];
        let mut b = 0.0f64;
        let (lr, l2, iters) = (0.5, 1e-3, 400);
        for _ in 0..iters {
            let mut g = vec![0.0f64; nfeat];
            let mut gb = 0.0;
            for &i in &train {
                let z = b + x[i].iter().map(|&j| w[j]).sum::<f64>();
                let p = 1.0 / (1.0 + (-z).exp());
                let wt = if y[i] { w1 } else { w0 };
                let e = wt * (p - if y[i] { 1.0 } else { 0.0 });
                gb += e;
                for &j in &x[i] {
                    g[j] += e;
                }
            }
            let m = train.len() as f64;
            b -= lr * gb / m;
            for j in 0..nfeat {
                w[j] -= lr * (g[j] / m + l2 * w[j]);
            }
        }
        for i in (0..y.len()).filter(|&i| fold[i] == f) {
            out[i] = b + x[i].iter().map(|&j| w[j]).sum::<f64>();
        }
    }
    out
}

// ---------------------------------------------------------------- evaluation

#[derive(Debug)]
struct FieldReport {
    name: String,
    kind: Kind,
    marker: bool,
    protected: bool,
    collisions: usize,
    chi2_p: Option<f64>,
    unseen: usize,
    outside_top95: usize,
    ks: Option<f64>,
    ks_q95: Option<f64>,
    miss_real: f64,
    miss_canary: f64,
    miss_band: (f64, f64),
    /// held-out AUC with this field's features only (None if not computed)
    auc_alone: Option<f64>,
    /// NUMERIC: share of non-missing canaries in each real decile bin
    deciles: Option<Vec<f64>>,
}

#[derive(Debug)]
struct Eval {
    markers: Vec<String>,
    fields: Vec<FieldReport>,
    auc: f64,
    canaries: Vec<Row>,
    real: Vec<Row>,
    warnings: Vec<(String, Option<String>)>,
}

/// §5.3 collision count for a protected field: STRING by normalize_text,
/// NUMERIC by |x - c| < 0.5·10^-s (s = decimals of the canary text).
fn collisions(kind: Kind, real: &[Option<String>], can: &[Option<String>]) -> usize {
    if kind == Kind::Numeric {
        let mut xs: Vec<f64> = real.iter().flatten().filter_map(|s| s.parse().ok()).collect();
        xs.sort_by(f64::total_cmp);
        can.iter()
            .flatten()
            .filter(|t| {
                let c: f64 = t.parse().unwrap();
                let s = t.split_once('.').map_or(0, |(_, f)| f.len()) as i32;
                let tol = 0.5 * 10f64.powi(-s) * (1.0 - 1e-9);
                let k = xs.partition_point(|&x| x < c - tol);
                k < xs.len() && (xs[k] - c).abs() < tol
            })
            .count()
    } else {
        let set: HashSet<String> = real.iter().flatten().map(|s| normalize_text(s)).collect();
        can.iter().flatten().filter(|s| set.contains(&normalize_text(s))).count()
    }
}

fn evaluate(input: &[u8], format: Format, k_d: &[u8; 32], n: u32, ablate_all: bool) -> Eval {
    let table = parse_table(input, format).expect("parse");
    let shape = infer_shape(&table);
    let out = mark(input, format, k_d, &MarkOptions { n, marker_fields: None, exclusions: vec![] }).expect("mark");
    let insp: serde_json::Value = serde_json::from_str(&inspect(input, Some(format)).unwrap()).unwrap();
    let warnings = insp["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| (w["code"].as_str().unwrap().to_string(), w["field"].as_str().map(str::to_string)))
        .collect();
    let mut rng = Rng(0x5eed);
    let real = &table.rows;
    let can = &out.canaries;
    let mut fields = Vec::new();
    let mut feats_real: Vec<Vec<String>> = vec![Vec::new(); real.len()];
    let mut feats_can: Vec<Vec<String>> = vec![Vec::new(); can.len()];
    for f in &shape.fields {
        let name = f.name.as_str();
        let rv: Vec<Option<String>> = real.iter().map(|r| text_of(&r.0[name], format)).collect();
        let cv: Vec<Option<String>> = can.iter().map(|r| text_of(&r.0[name], format)).collect();
        let marker = out.markers.iter().any(|m| m == name);
        let protected = marker || f.unique && matches!(f.kind, Kind::String | Kind::Numeric);
        let key = |s: &str| -> String {
            match f.kind {
                Kind::Categorical | Kind::Bool => format!("={s}"),
                _ => template_key(s),
            }
        };
        let mut rc: BTreeMap<String, usize> = BTreeMap::new();
        for s in rv.iter().flatten() {
            *rc.entry(key(s)).or_default() += 1;
        }
        let mut oc: BTreeMap<String, usize> = BTreeMap::new();
        for s in cv.iter().flatten() {
            *oc.entry(key(s)).or_default() += 1;
        }
        let (mut chi2_p, mut unseen, mut outside_top95) = (None, 0, 0);
        let (mut ks_v, mut ks_q) = (None, None);
        if matches!(f.kind, Kind::String | Kind::Categorical | Kind::Bool) {
            let (p, u) = chi2_mc(&rc, &oc, &mut rng);
            chi2_p = Some(p);
            unseen = u;
            let mut byc: Vec<(&String, &usize)> = rc.iter().collect();
            byc.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
            let total: usize = rc.values().sum();
            let mut acc = 0;
            let mut top = HashSet::new();
            for (k, c) in byc {
                if acc as f64 >= 0.95 * total as f64 {
                    break;
                }
                acc += c;
                top.insert(k.clone());
            }
            outside_top95 = oc.iter().filter(|(k, _)| !top.contains(*k)).map(|(_, c)| c).sum();
        }
        let num = |v: &[Option<String>]| -> Vec<f64> { v.iter().flatten().filter_map(|s| s.parse::<f64>().ok()).collect() };
        let real_num = num(&rv);
        if f.kind == Kind::Numeric {
            let can_num = num(&cv);
            ks_v = Some(ks(&can_num, &real_num));
            let mut boots: Vec<f64> = (0..1000)
                .map(|_| {
                    let s: Vec<f64> = (0..can_num.len()).map(|_| real_num[rng.below(real_num.len())]).collect();
                    ks(&s, &real_num)
                })
                .collect();
            ks_q = Some(quantile(&mut boots, 0.95));
        }
        let miss_real = rv.iter().filter(|v| v.is_none()).count() as f64 / rv.len() as f64;
        let miss_canary = cv.iter().filter(|v| v.is_none()).count() as f64 / cv.len() as f64;
        let mut mb: Vec<f64> = (0..1000)
            .map(|_| (0..cv.len()).filter(|_| rv[rng.below(rv.len())].is_none()).count() as f64 / cv.len() as f64)
            .collect();
        let miss_band = (quantile(&mut mb, 0.05), quantile(&mut mb, 0.95));
        let mut deciles = real_num.clone();
        deciles.sort_by(f64::total_cmp);
        let cuts: Vec<f64> = (1..10).map(|k| if deciles.is_empty() { 0.0 } else { deciles[deciles.len() * k / 10] }).collect();
        let feat = |v: &Option<String>| -> String {
            match v {
                None => format!("{name}:MISSING"),
                Some(s) if f.kind == Kind::Numeric => {
                    let x: f64 = s.parse().unwrap_or(0.0);
                    format!("{name}:bin{}", cuts.partition_point(|&c| c <= x))
                }
                Some(s) => format!("{name}:{}", key(s)),
            }
        };
        for (k, v) in rv.iter().enumerate() {
            feats_real[k].push(feat(v));
        }
        for (k, v) in cv.iter().enumerate() {
            feats_can[k].push(feat(v));
        }
        let deciles = (f.kind == Kind::Numeric).then(|| {
            let xs: Vec<f64> = cv.iter().flatten().filter_map(|s| s.parse().ok()).collect();
            let mut d = vec![0.0; 10];
            for x in &xs {
                d[cuts.partition_point(|&c| c <= *x)] += 1.0 / xs.len() as f64;
            }
            d
        });
        fields.push(FieldReport {
            name: name.to_string(),
            kind: f.kind,
            marker,
            protected,
            collisions: if protected { collisions(f.kind, &rv, &cv) } else { 0 },
            chi2_p,
            unseen,
            outside_top95,
            ks: ks_v,
            ks_q95: ks_q,
            miss_real,
            miss_canary,
            miss_band,
            auc_alone: None,
            deciles,
        });
    }
    let names: BTreeSet<&String> = feats_real.iter().chain(&feats_can).flatten().collect();
    let id: BTreeMap<&String, usize> = names.into_iter().enumerate().map(|(k, s)| (s, k)).collect();
    let mut x: Vec<Vec<usize>> = Vec::new();
    let mut y: Vec<bool> = Vec::new();
    for r in &feats_real {
        x.push(r.iter().map(|s| id[s]).collect());
        y.push(false);
    }
    for r in &feats_can {
        x.push(r.iter().map(|s| id[s]).collect());
        y.push(true);
    }
    let scores = cv_scores(&x, &y, id.len(), &mut rng);
    // ablation: one field's features only (feature k of each row is field k)
    for (fi, fr) in fields.iter_mut().enumerate() {
        if !ablate_all && fr.kind != Kind::Numeric {
            continue;
        }
        let xs: Vec<Vec<usize>> = x.iter().map(|r| vec![r[fi]]).collect();
        let sc = cv_scores(&xs, &y, id.len(), &mut rng);
        fr.auc_alone = Some(auc(&sc, &y));
    }
    Eval { markers: out.markers, fields, auc: auc(&scores, &y), canaries: out.canaries, real: table.rows, warnings }
}

fn print_eval(title: &str, e: &Eval) {
    println!("\n### {title}");
    println!("markers = {:?}, held-out AUC (5-fold LR) = {:.3}", e.markers, e.auc);
    let w: Vec<String> = e.warnings.iter().map(|(c, f)| format!("{c}{}", f.as_ref().map_or(String::new(), |f| format!("({f})")))).collect();
    println!("inspect warnings = [{}]", w.join(", "));
    println!("| field | kind | marker | protected | collisions | chi2 MC p | unseen tmpl | outside top95 | KS | KS boot q95 | missing real | missing canary | missing band 5-95% | AUC this field only |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for f in &e.fields {
        let o = |x: Option<f64>| x.map_or("-".to_string(), |v| format!("{v:.3}"));
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.3} | {:.3} | {:.3}-{:.3} | {} |",
            f.name,
            f.kind.as_str(),
            if f.marker { "yes" } else { "" },
            if f.protected { "yes" } else { "" },
            if f.protected { f.collisions.to_string() } else { "-".into() },
            o(f.chi2_p),
            f.unseen,
            f.outside_top95,
            o(f.ks),
            o(f.ks_q95),
            f.miss_real,
            f.miss_canary,
            f.miss_band.0,
            f.miss_band.1,
            o(f.auc_alone)
        );
    }
    for f in &e.fields {
        if let Some(d) = &f.deciles {
            let v: Vec<String> = d.iter().map(|x| format!("{x:.3}")).collect();
            println!("canary decile shares {}: [{}] (real 0.100 each)", f.name, v.join(", "));
        }
    }
}

fn s(c: &Cell) -> &str {
    match c {
        Cell::Str(s) => s,
        _ => "",
    }
}

/// Dataset-A specific checks: id pattern, addr vocab, si-dong pairs not in real data.
fn dataset_a_checks(e: &Eval) -> (usize, usize, usize, usize) {
    let id_bad = e
        .canaries
        .iter()
        .filter(|c| {
            let v: Vec<char> = s(&c.0["id"]).chars().collect();
            !(v.len() == 5 && v[0].is_ascii_uppercase() && v[1] == '-' && v[2..].iter().all(char::is_ascii_digit))
        })
        .count();
    let mut si_vocab = HashSet::new();
    let mut dong_vocab = HashSet::new();
    let mut combos = HashSet::new();
    for r in &e.real {
        let p: Vec<&str> = s(&r.0["addr"]).split(' ').collect();
        si_vocab.insert(p[0].to_string());
        dong_vocab.insert(p[1].to_string());
        combos.insert((p[0].to_string(), p[1].to_string()));
    }
    let mut vocab_bad = 0;
    let mut mismatch = 0;
    for c in &e.canaries {
        let p: Vec<&str> = s(&c.0["addr"]).split(' ').collect();
        if p.len() != 3 || !si_vocab.contains(p[0]) || !dong_vocab.contains(p[1]) {
            vocab_bad += 1;
        }
        if p.len() >= 2 && !combos.contains(&(p[0].to_string(), p[1].to_string())) {
            mismatch += 1;
        }
    }
    (id_bad, vocab_bad, mismatch, e.canaries.len())
}

fn key(seed: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8).wrapping_mul(31);
    }
    k
}

/// shape-v1 r2.2 §9 judgement (n = 1000), except the missing rate (see missing_rate_judgement).
fn assert_criteria(e: &Eval) {
    for f in &e.fields {
        if f.protected {
            assert_eq!(f.collisions, 0, "field {} collides", f.name);
        }
        // per-key 90% missing band: reported only (r2.2 §9); judged by missing_rate_judgement
        if let Some(p) = f.chi2_p {
            assert_eq!(f.unseen, 0, "field {} unseen templates", f.name);
            assert!(p > 0.05 || f.outside_top95 == 0, "field {} template distribution p={p}", f.name);
        }
        if f.kind == Kind::Numeric && !f.protected {
            let (k, q) = (f.ks.unwrap(), f.ks_q95.unwrap());
            assert!(k < q, "unprotected NUMERIC {} KS {k} >= q95 {q}", f.name);
        }
        if f.kind == Kind::Numeric && f.protected && f.auc_alone.unwrap_or(0.0) > 0.75 {
            assert!(
                e.warnings.iter().any(|(c, w)| c == "NUMERIC_CODE_LIKE" && w.as_deref() == Some(f.name.as_str())),
                "protected NUMERIC {} ablation {:?} > 0.75 without NUMERIC_CODE_LIKE",
                f.name,
                f.auc_alone
            );
        }
    }
    assert!(e.auc < 0.60, "AUC {}", e.auc);
}

fn dataset_a_judged(seed: u8) {
    let src = dataset_a(10_000, false, 1);
    let e = evaluate(src.as_bytes(), Format::Json, &key(seed), 1000, false);
    print_eval(&format!("dataset A, n=1000, key {seed} (judged)"), &e);
    let (id_bad, vocab_bad, mismatch, n) = dataset_a_checks(&e);
    println!("id pattern violations {id_bad}/{n}, addr vocab violations {vocab_bad}/{n}, si-dong pairs not in real {mismatch}/{n}");
    assert_eq!(e.markers, vec!["addr", "id", "area_m2"]);
    assert_eq!((id_bad, vocab_bad, mismatch), (0, 0, 0));
    assert_criteria(&e);
}

#[test]
fn dataset_a_n1000() {
    dataset_a_judged(1);
    let src = dataset_a(10_000, false, 1);
    assert_missing(&missing_rate_judgement("dataset A", src.as_bytes(), Format::Json, 1000, 10));
}

/// Full report: dataset A keys 1..3 judged at n = 1000, n = 64 keys 1..5 and
/// A' (log-uniform area) reported.
#[test]
#[ignore]
fn full_report() {
    for seed in 2..=3u8 {
        dataset_a_judged(seed);
    }
    let src = dataset_a(10_000, false, 1);
    for seed in 1..=5u8 {
        let e = evaluate(src.as_bytes(), Format::Json, &key(seed), 64, true);
        print_eval(&format!("dataset A, n=64, key {seed} (report only)"), &e);
        let (id_bad, vocab_bad, mismatch, n) = dataset_a_checks(&e);
        println!("id pattern violations {id_bad}/{n}, addr vocab violations {vocab_bad}/{n}, si-dong pairs not in real {mismatch}/{n}");
    }
    let skew = dataset_a(10_000, true, 1);
    for n in [64, 1000] {
        let e = evaluate(skew.as_bytes(), Format::Json, &key(1), n, true);
        print_eval(&format!("dataset A' (log-uniform area), n={n}, key 1 (report only)"), &e);
    }
}

/// Public CSV (WP-02 acceptance 4), auto markers. Needs NOREA_PUBLIC_CSV.
#[test]
#[ignore]
fn public_csv() {
    let Ok(p) = std::env::var("NOREA_PUBLIC_CSV") else {
        println!("public CSV: NOREA_PUBLIC_CSV not set, skipped");
        return;
    };
    let bytes = std::fs::read(&p).expect("read public csv");
    let digest: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    println!("public CSV sha256 {digest}, {} bytes", bytes.len());
    if let Ok(want) = std::env::var("NOREA_PUBLIC_CSV_SHA256") {
        assert_eq!(digest, want, "public CSV changed");
    }
    let t = parse_table(&bytes, Format::Csv).expect("public csv parses");
    println!("{} rows, {} fields", t.rows.len(), t.fields.len());
    let shape = infer_shape(&t);
    for f in &shape.fields {
        println!(
            "  {} {} d={} missing_ppm={} space_log2_x100={:?} free_space={} unique={} code_like={}",
            f.name,
            f.kind.as_str(),
            f.distinct,
            f.missing_ppm,
            f.space_log2_x100,
            f.has_free_space(),
            f.unique,
            f.code_like
        );
    }
    println!("auto markers: {:?}", noreacore::shape::auto_markers(&shape));
    for seed in 1..=3u8 {
        let e = evaluate(&bytes, Format::Csv, &key(seed), 64, true);
        print_eval(&format!("public CSV, n=64, key {seed} (report only)"), &e);
    }
    let judged: Vec<Eval> = (1..=3u8)
        .map(|seed| {
            let e = evaluate(&bytes, Format::Csv, &key(seed), 1000, true);
            print_eval(&format!("public CSV, n=1000, key {seed} (judged)"), &e);
            e
        })
        .collect();
    let miss = missing_rate_judgement("public CSV", &bytes, Format::Csv, 1000, 10);
    for e in &judged {
        assert_criteria(e);
    }
    assert_missing(&miss);
}

/// shape-v1 r2.2 §9 missing-rate judgement: for K keys with n canaries each,
/// the per-field mean canary missing rate must lie in the 2.5-97.5% interval
/// of 1000 bootstrap missing rates of n·K rows drawn from the real data.
/// Returns (field, real, mean, lo, hi, outside-per-key-90%-band count).
fn missing_rate_judgement(name: &str, bytes: &[u8], format: Format, n: u32, k: u8) -> Vec<(String, f64, f64, f64, f64, usize)> {
    let t = parse_table(bytes, format).unwrap();
    let shape = infer_shape(&t);
    let outs: Vec<_> = (1..=k)
        .map(|s| mark(bytes, format, &key(s), &MarkOptions { n, marker_fields: None, exclusions: vec![] }).unwrap())
        .collect();
    let mut rng = Rng(0xca1);
    let mut res = Vec::new();
    println!("\n### missing rate judgement: {name}, K={k} keys, n={n} (bootstrap of n·K = {} rows)", u64::from(n) * u64::from(k));
    println!("| field | real missing | mean canary missing | bootstrap 2.5-97.5% | pass | keys outside per-key 90% band (report) |");
    println!("|---|---|---|---|---|---|");
    for f in &shape.fields {
        if f.missing == 0 {
            continue;
        }
        let fname = f.name.as_str();
        let rv: Vec<bool> = t.rows.iter().map(|r| text_of(&r.0[fname], format).is_none()).collect();
        let real = rv.iter().filter(|x| **x).count() as f64 / rv.len() as f64;
        let total = u64::from(n) * u64::from(k);
        let mut pooled: Vec<f64> =
            (0..1000).map(|_| (0..total).filter(|_| rv[rng.below(rv.len())]).count() as f64 / total as f64).collect();
        let (lo, hi) = (quantile(&mut pooled, 0.025), quantile(&mut pooled, 0.975));
        let mut per_key: Vec<f64> =
            (0..1000).map(|_| (0..n).filter(|_| rv[rng.below(rv.len())]).count() as f64 / f64::from(n)).collect();
        let band = (quantile(&mut per_key, 0.05), quantile(&mut per_key, 0.95));
        let rates: Vec<f64> = outs
            .iter()
            .map(|o| o.canaries.iter().filter(|c| text_of(&c.0[fname], format).is_none()).count() as f64 / f64::from(n))
            .collect();
        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        let outside = rates.iter().filter(|r| **r < band.0 || **r > band.1).count();
        let pass = mean >= lo && mean <= hi;
        println!("| {fname} | {real:.4} | {mean:.4} | {lo:.4}-{hi:.4} | {} | {outside}/{k} |", if pass { "yes" } else { "NO" });
        res.push((fname.to_string(), real, mean, lo, hi, outside));
    }
    res
}

fn assert_missing(res: &[(String, f64, f64, f64, f64, usize)]) {
    for (f, _, mean, lo, hi, _) in res {
        assert!(*mean >= *lo && *mean <= *hi, "field {f}: mean missing {mean} outside bootstrap 95% [{lo}, {hi}]");
    }
}
