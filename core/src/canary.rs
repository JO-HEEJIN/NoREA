//! Deterministic canary generation and insertion (kind record.shape.v1).
//!
//! Spec: Fable_5_1/docs/protocol/canary-record-shape-v1.md r2.2 §3, §4.2, §5.
//! API: Fable_5_1/docs/CORE-API.md §1 canary.rs.
//!
//! No RNG: every choice comes from `draw` (HMAC-SHA256 keyed by K_d). Hash
//! and tree sets are used only for membership and range queries; generation
//! never iterates a hash container.

use std::collections::{BTreeSet, HashSet};

use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::error::{Error, ErrorCode};
use crate::norm::{normalize_number, normalize_text};
use crate::shape::{
    auto_markers, format_scaled, infer_shape, is_missing, parse_scaled, shape_summary, text_scale, FieldShape, Kind,
    Shape, Tok,
};
use crate::table::{parse_table, serialize_with_inserts, Cell, Format, Row};
use crate::Key32;

type HmacSha256 = Hmac<Sha256>;

/// Attempts per canary before `CanaryExhausted` (shape-v1 §5.3).
const MAX_ATTEMPTS: u32 = 64;

#[derive(Debug, Clone, Default)]
pub struct MarkOptions {
    pub n: u32,
    pub marker_fields: Option<Vec<String>>,
    pub exclusions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MarkOutput {
    pub marked: Vec<u8>,
    /// Canary rows in index order i = 0..n-1. Every field is present; missing
    /// values are `Cell::Missing` / `Cell::Null` (JSON) or `Str("")` (CSV).
    pub canaries: Vec<Row>,
    pub markers: Vec<String>,
    pub shape_summary: Value,
    pub format: Format,
}

fn keyed(k_d: &Key32) -> HmacSha256 {
    <HmacSha256 as KeyInit>::new_from_slice(k_d).expect("HMAC accepts any key length")
}

fn draw_with(mac: &HmacSha256, label: &str, i: u32, attempt: u8, ctr: u32) -> u64 {
    let mut m = mac.clone();
    m.update(&(label.len() as u32).to_be_bytes());
    m.update(label.as_bytes());
    m.update(&4u32.to_be_bytes());
    m.update(&i.to_be_bytes());
    m.update(&1u32.to_be_bytes());
    m.update(&[attempt]);
    m.update(&4u32.to_be_bytes());
    m.update(&ctr.to_be_bytes());
    let out = m.finalize().into_bytes();
    let mut b = [0u8; 8];
    b.copy_from_slice(&out[..8]);
    u64::from_be_bytes(b)
}

/// shape-v1 §5.1:
/// `u64be(HMAC-SHA256(K_d, lp(utf8(label)) || lp(u32be(i)) || lp([attempt]) || lp(u32be(ctr)))[0..8])`.
pub fn draw(k_d: &Key32, label: &str, i: u32, attempt: u8, ctr: u32) -> u64 {
    draw_with(&keyed(k_d), label, i, attempt, ctr)
}

/// The draw stream of one candidate (i, attempt), label "canary". `ctr`
/// starts at 0 and increases by one per draw (§5.1).
struct Stream<'a> {
    mac: &'a HmacSha256,
    i: u32,
    attempt: u8,
    ctr: u32,
}

impl Stream<'_> {
    fn next(&mut self) -> u64 {
        let v = draw_with(self.mac, "canary", self.i, self.attempt, self.ctr);
        self.ctr += 1;
        v
    }
}

/// §5.1 frequency-proportional pick: items in first-appearance order,
/// `u mod total` located on the cumulative counts.
fn pick<T>(items: &[T], count: impl Fn(&T) -> u64, u: u64) -> &T {
    let total: u64 = items.iter().map(&count).sum();
    let mut r = u % total;
    for it in items {
        let c = count(it);
        if r < c {
            return it;
        }
        r -= c;
    }
    &items[items.len() - 1]
}

/// `b - a` for equal-length digit strings with `b >= a`, if it fits in u128.
fn digit_diff(a: &str, b: &str) -> Option<u128> {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut out = vec![0u8; b.len()];
    let mut borrow = 0i16;
    for k in (0..b.len()).rev() {
        let mut d = i16::from(b[k] - b'0') - i16::from(a[k] - b'0') - borrow;
        borrow = 0;
        if d < 0 {
            d += 10;
            borrow = 1;
        }
        out[k] = d as u8;
    }
    let first = out.iter().position(|&d| d != 0).unwrap_or(out.len());
    let sig = &out[first..];
    if sig.len() > 38 {
        return None;
    }
    Some(sig.iter().fold(0u128, |v, &d| v * 10 + u128::from(d)))
}

/// `a + x` as a digit string of `a.len()` digits (the result is at most the slot max).
fn digit_add(a: &str, x: u128) -> String {
    let mut digits: Vec<u8> = a.bytes().map(|b| b - b'0').collect();
    let mut carry = x;
    for d in digits.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        let s = u128::from(*d) + carry % 10;
        *d = (s % 10) as u8;
        carry = carry / 10 + s / 10;
    }
    digits.into_iter().map(|d| char::from(b'0' + d)).collect()
}

/// D slot value: `min + uniform(max - min + 1)`, written with the run length
/// (left zero padding). Never exceeds `max`, so no clamp (§3.2).
fn gen_digits(min: &str, max: &str, u: u64) -> String {
    let off = match digit_diff(min, max) {
        Some(diff) => (u128::from(u)) % (diff + 1),
        None => u128::from(u), // range > 10^38 > 2^64 > u: u mod range == u
    };
    digit_add(min, off)
}

/// §3.2: template (count-proportional) -> anchor (`mod len`) -> H/L slots
/// copied from the anchor, one draw per D slot.
fn gen_string(f: &FieldShape, s: &mut Stream) -> String {
    let t = pick(&f.templates, |t| t.count, s.next());
    let anchor = &t.anchors[(s.next() % t.anchors.len() as u64) as usize];
    let mut out = String::new();
    let (mut di, mut wi) = (0, 0);
    for tok in &t.tokens {
        match tok {
            Tok::Lit(c) => out.push(*c),
            Tok::Run(crate::shape::Class::D, _) => {
                let d = &t.digits[di];
                out.push_str(&gen_digits(&d.min, &d.max, s.next()));
                di += 1;
            }
            Tok::Run(..) => {
                out.push_str(&anchor[wi]);
                wi += 1;
            }
        }
    }
    out
}

fn missing_cell(f: &FieldShape, format: Format) -> Cell {
    match format {
        Format::Csv => Cell::Str(String::new()),
        Format::Json if f.missing_as_null => Cell::Null,
        Format::Json => Cell::Missing,
    }
}

enum Gen {
    Value(Cell),
    Missing(Cell),
    /// Protected NUMERIC field has no gap with an inner integer (§3.1 `G == 0`).
    Reject,
}

/// r2.1/r2.2 §3.1: for each gap index k of V[0..m) (duplicates kept), the first k' = k, k+1, ... (mod m−1)
/// with `w_k' > 0`. Empty when G == 0. Equivalent to the literal scan.
fn next_gaps(v: &[i128]) -> Vec<usize> {
    let n = v.len().saturating_sub(1);
    let nonempty = |k: usize| v[k + 1].abs_diff(v[k]) > 1;
    let Some(first) = (0..n).find(|&k| nonempty(k)) else {
        return Vec::new();
    };
    let mut out = vec![0; n];
    let mut nxt = first;
    for k in (0..n).rev() {
        if nonempty(k) {
            nxt = k;
        }
        out[k] = nxt;
    }
    out
}

/// One field of a candidate, in the §5.2 draw order.
fn gen_field(f: &FieldShape, protected: bool, next_gap: &[usize], format: Format, s: &mut Stream) -> Gen {
    if f.kind == Kind::Empty {
        return Gen::Missing(missing_cell(f, format));
    }
    if s.next() % 1_000_000 < f.missing_ppm {
        return Gen::Missing(missing_cell(f, format));
    }
    let cell = match f.kind {
        Kind::Numeric if !protected => {
            let u = s.next();
            f.cells[(u % f.cells.len() as u64) as usize].clone()
        }
        Kind::Numeric => {
            let st = f.numeric.as_ref().expect("NUMERIC has stats");
            let r = s.next();
            let v = &st.values;
            let k0 = ((r >> 32) % (v.len() as u64 - 1)) as usize; // mod (m - 1), r2.2
            // r2.1: move from k0 to the first non-empty gap (wrap); none means G == 0.
            let Some(&k) = next_gap.get(k0) else {
                return Gen::Reject;
            };
            let w = v[k + 1].abs_diff(v[k]) - 1;
            let off = u128::from(r & 0xFFFF_FFFF) % w;
            let n = v[k].checked_add_unsigned(1 + off).unwrap_or(v[k + 1] - 1);
            let text = format_scaled(n, st.scale, st.fixed_scale);
            match format {
                Format::Csv => Cell::Str(text),
                Format::Json => {
                    let scale = text_scale(&text) as u8;
                    Cell::Num { text, scale }
                }
            }
        }
        Kind::String => Cell::Str(gen_string(f, s)),
        Kind::Categorical | Kind::Bool => pick(&f.vocab, |v| v.1, s.next()).0.clone(),
        Kind::Opaque => {
            let u = s.next();
            f.cells[(u % f.cells.len() as u64) as usize].clone()
        }
        Kind::Empty => unreachable!(),
    };
    Gen::Value(cell)
}

fn cell_str(c: &Cell) -> &str {
    match c {
        Cell::Str(s) => s,
        Cell::Num { text, .. } => text,
        _ => "",
    }
}

/// Taken set of one protected field (§5.3).
enum Taken {
    /// `normalize_text` of real values, exclusions (markers) and earlier canaries.
    Text(HashSet<String>),
    /// Integers at the field scale: real values, numeric exclusions (markers)
    /// and earlier canaries. A candidate `c` with text precision `s` collides
    /// when some `x` has `|x - c| < 0.5·10^-s`.
    Num { scale: u8, values: BTreeSet<i128> },
}

impl Taken {
    /// Whether a candidate collides (§5.3).
    fn hits(&self, c: &Cell) -> bool {
        match self {
            Taken::Text(set) => set.contains(&normalize_text(cell_str(c))),
            Taken::Num { scale, values } => {
                let t = cell_str(c);
                let Some(x) = parse_scaled(t, *scale) else { return true };
                let s = text_scale(t).min(usize::from(*scale));
                // 2|x - c| < 10^(scale - s)  <=>  |x - c| <= (10^(scale-s) - 1) / 2 for integers
                let full = 10i128.pow(u32::from(*scale) - s as u32);
                let r = (full - 1) / 2;
                values.range(x.saturating_sub(r)..=x.saturating_add(r)).next().is_some()
            }
        }
    }

    fn insert(&mut self, c: &Cell) {
        match self {
            Taken::Text(set) => {
                set.insert(normalize_text(cell_str(c)));
            }
            Taken::Num { scale, values } => {
                if let Some(x) = parse_scaled(cell_str(c), *scale) {
                    values.insert(x);
                }
            }
        }
    }
}

/// §4.2 operator markers, or §4.1 auto selection.
fn select_markers(shape: &Shape, requested: Option<&[String]>) -> Result<Vec<String>, Error> {
    let Some(req) = requested else {
        return auto_markers(shape);
    };
    if req.is_empty() || req.len() > 4 {
        return Err(Error::bad_input("marker_fields must name 1 to 4 fields"));
    }
    for (k, name) in req.iter().enumerate() {
        if req[..k].contains(name) {
            return Err(Error::bad_input(format!("marker field {name} is listed twice")));
        }
        let f = shape
            .field(name)
            .ok_or_else(|| Error::bad_input(format!("marker field {name} does not exist")))?;
        match f.kind {
            Kind::String | Kind::Numeric => {}
            Kind::Opaque => {
                return Err(Error::new(
                    ErrorCode::NoMarker,
                    format!("field {name} has no reusable shape; choose other marker fields"),
                ))
            }
            k => {
                return Err(Error::new(
                    ErrorCode::NoMarker,
                    format!("field {name} is {} and cannot be a marker; choose STRING or NUMERIC fields", k.as_str()),
                ))
            }
        }
    }
    Ok(req.to_vec())
}

pub fn mark(original: &[u8], format: Format, k_d: &Key32, opts: &MarkOptions) -> Result<MarkOutput, Error> {
    if opts.n == 0 {
        return Err(Error::bad_input("n must be at least 1"));
    }
    let table = parse_table(original, format)?;
    let shape = infer_shape(&table);
    let markers = select_markers(&shape, opts.marker_fields.as_deref())?;

    // Protected fields (§3): markers, and unique fields whose final kind is STRING/NUMERIC.
    let nf = shape.fields.len();
    let is_marker: Vec<bool> = shape.fields.iter().map(|f| markers.contains(&f.name)).collect();
    let mut taken: Vec<Option<Taken>> = Vec::with_capacity(nf);
    for (j, f) in shape.fields.iter().enumerate() {
        let protected = is_marker[j] || (f.unique && matches!(f.kind, Kind::String | Kind::Numeric));
        if !protected {
            taken.push(None);
            continue;
        }
        let t = match &f.numeric {
            Some(st) if f.kind == Kind::Numeric => {
                let mut values: BTreeSet<i128> = st.values.iter().copied().collect();
                if is_marker[j] {
                    for e in &opts.exclusions {
                        if let Some(x) = normalize_number(e).and_then(|n| parse_scaled(&n, st.scale)) {
                            values.insert(x);
                        }
                    }
                }
                Taken::Num { scale: st.scale, values }
            }
            _ => {
                let mut set = HashSet::new();
                for row in &table.rows {
                    if let Some(c) = row.0.get(f.name.as_str()) {
                        if !is_missing(c, format) {
                            set.insert(normalize_text(cell_str(c)));
                        }
                    }
                }
                if is_marker[j] {
                    for e in &opts.exclusions {
                        set.insert(normalize_text(e));
                    }
                }
                Taken::Text(set)
            }
        };
        taken.push(Some(t));
    }

    let gaps: Vec<Vec<usize>> = shape
        .fields
        .iter()
        .zip(&taken)
        .map(|(f, t)| match (&f.numeric, t) {
            (Some(st), Some(_)) if f.kind == Kind::Numeric => next_gaps(&st.values),
            _ => Vec::new(),
        })
        .collect();
    let mac = keyed(k_d);
    let mut canaries: Vec<Row> = Vec::with_capacity(opts.n as usize);
    for i in 0..opts.n {
        let mut accepted = None;
        'attempts: for attempt in 0..MAX_ATTEMPTS {
            let mut s = Stream { mac: &mac, i, attempt: attempt as u8, ctr: 0 };
            let mut cells = Vec::with_capacity(nf);
            for (j, f) in shape.fields.iter().enumerate() {
                let cell = match gen_field(f, taken[j].is_some(), &gaps[j], format, &mut s) {
                    Gen::Reject => continue 'attempts,
                    Gen::Missing(c) => {
                        if is_marker[j] {
                            continue 'attempts;
                        }
                        c
                    }
                    Gen::Value(c) => {
                        if taken[j].as_ref().is_some_and(|t| t.hits(&c)) {
                            continue 'attempts;
                        }
                        c
                    }
                };
                cells.push(cell);
            }
            accepted = Some(cells);
            break;
        }
        let Some(cells) = accepted else {
            return Err(Error::new(ErrorCode::CanaryExhausted, format!("canary {i}: no acceptable candidate")));
        };
        for (j, c) in cells.iter().enumerate() {
            if let Some(t) = taken[j].as_mut() {
                if !is_missing(c, format) {
                    t.insert(c);
                }
            }
        }
        canaries.push(Row(shape.fields.iter().map(|f| f.name.clone()).zip(cells).collect()));
    }

    // §5.4: canary i goes to pos_i in the current sequence (L real rows plus
    // the i canaries before it). Track final positions of earlier canaries.
    let l = table.rows.len() as u64;
    let mut positions: Vec<usize> = Vec::with_capacity(canaries.len());
    for i in 0..opts.n {
        let p = (draw_with(&mac, "pos", i, 0, 0) % (l + u64::from(i) + 1)) as usize;
        for q in positions.iter_mut() {
            if *q >= p {
                *q += 1;
            }
        }
        positions.push(p);
    }
    let inserts: Vec<(usize, Row)> = positions.into_iter().zip(canaries.iter().cloned()).collect();
    let marked = serialize_with_inserts(original, &table, &inserts)?;
    let summary = shape_summary(&shape, &markers);
    Ok(MarkOutput { marked, canaries, markers, shape_summary: summary, format })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::canon_row;

    const K1: Key32 = [0x33; 32];
    const K2: Key32 = [0x44; 32];

    fn opts(n: u32) -> MarkOptions {
        MarkOptions { n, marker_fields: None, exclusions: Vec::new() }
    }

    fn text(c: &Cell) -> String {
        cell_str(c).to_string()
    }

    fn parcels(rows: usize) -> String {
        let si = [("하남시", ["미사동", "망월동"]), ("성남시", ["정자동", "서현동"]), ("광주시", ["선동", "탄벌동"])];
        let mut v = Vec::new();
        for i in 0..rows {
            let note = if i % 5 == 0 { "null".to_string() } else { format!("\"메모 {}\"", i % 7) };
            let (s, d) = si[i % 3];
            v.push(format!(
                "{{\"id\":\"P-{:04}\",\"addr\":\"{} {} {}-{}\",\"area\":{}.{:02},\"use\":\"{}\",\"note\":{}}}",
                i * 7,
                s,
                d[(i / 3) % 2],
                100 + (i * 7) % 800,
                i % 13 + 1,
                50 + (i * 37) % 1900,
                i % 100,
                ["대", "전", "답"][i % 3],
                note
            ));
        }
        format!("[\n{}\n]\n", v.join(",\n"))
    }

    #[test]
    fn draw_message_layout() {
        // Independent assembly of the §5.1 message.
        let mut msg = Vec::new();
        msg.extend_from_slice(&6u32.to_be_bytes());
        msg.extend_from_slice(b"canary");
        msg.extend_from_slice(&4u32.to_be_bytes());
        msg.extend_from_slice(&7u32.to_be_bytes());
        msg.extend_from_slice(&1u32.to_be_bytes());
        msg.push(3);
        msg.extend_from_slice(&4u32.to_be_bytes());
        msg.extend_from_slice(&9u32.to_be_bytes());
        let mut m = <HmacSha256 as KeyInit>::new_from_slice(&K1).unwrap();
        m.update(&msg);
        let out = m.finalize().into_bytes();
        let want = u64::from_be_bytes(out[..8].try_into().unwrap());
        assert_eq!(draw(&K1, "canary", 7, 3, 9), want);
        assert_ne!(draw(&K1, "canary", 7, 3, 9), draw(&K1, "canary", 7, 3, 10));
        assert_ne!(draw(&K1, "pos", 7, 0, 0), draw(&K1, "canary", 7, 0, 0));
    }

    #[test]
    fn digit_helpers() {
        assert_eq!(digit_diff("005", "123"), Some(118));
        assert_eq!(digit_add("005", 118), "123");
        assert_eq!(gen_digits("05", "05", 999), "05");
        assert_eq!(gen_digits("00", "99", 1234), "34");
        let big_min = "1".repeat(45);
        let big_max = "9".repeat(45);
        assert_eq!(digit_diff(&big_min, &big_max), None);
        let g = gen_digits(&big_min, &big_max, u64::MAX);
        assert_eq!(g.len(), 45);
        assert!(g.as_str() >= big_min.as_str() && g.as_str() <= big_max.as_str());
    }

    /// AC1: same input, K_d, options -> identical bytes; different K_d -> different.
    #[test]
    fn ac1_deterministic() {
        let src = parcels(500);
        let a = mark(src.as_bytes(), Format::Json, &K1, &opts(16)).unwrap();
        let b = mark(src.as_bytes(), Format::Json, &K1, &opts(16)).unwrap();
        assert_eq!(a.marked, b.marked);
        assert_eq!(a.canaries, b.canaries);
        assert_eq!(a.shape_summary, b.shape_summary);
        let c = mark(src.as_bytes(), Format::Json, &K2, &opts(16)).unwrap();
        assert_ne!(a.marked, c.marked);
        assert_ne!(a.canaries, c.canaries);
        assert_eq!(a.markers, vec!["addr", "id", "area"]);
    }

    #[test]
    fn canaries_avoid_real_values_and_are_inserted() {
        let src = parcels(400);
        let table = parse_table(src.as_bytes(), Format::Json).unwrap();
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(32)).unwrap();
        let marked = parse_table(&out.marked, Format::Json).unwrap();
        assert_eq!(marked.rows.len(), 400 + 32);
        let mut positions: Vec<usize> = Vec::new();
        for i in 0..32u32 {
            let p = (draw(&K1, "pos", i, 0, 0) % (400 + u64::from(i) + 1)) as usize;
            for q in positions.iter_mut() {
                if *q >= p {
                    *q += 1;
                }
            }
            positions.push(p);
        }
        for (i, p) in positions.iter().enumerate() {
            assert_eq!(canon_row(&marked.rows[*p]), canon_row(&out.canaries[i]), "canary {i}");
        }
        for m in &out.markers {
            let real: HashSet<String> = table.rows.iter().map(|r| normalize_text(&text(&r.0[m.as_str()]))).collect();
            let mut seen = HashSet::new();
            for c in &out.canaries {
                assert!(!matches!(c.0[m.as_str()], Cell::Missing | Cell::Null), "marker never missing");
                let k = normalize_text(&text(&c.0[m.as_str()]));
                assert!(!real.contains(&k), "marker {m} collides");
                assert!(seen.insert(k), "marker {m} repeats among canaries");
            }
        }
        let originals: Vec<Vec<u8>> = table.rows.iter().map(canon_row).collect();
        let rest: Vec<Vec<u8>> = marked
            .rows
            .iter()
            .enumerate()
            .filter(|(k, _)| !positions.contains(k))
            .map(|(_, r)| canon_row(r))
            .collect();
        assert_eq!(originals, rest);
    }

    /// §3.1: protected NUMERIC is strictly inside a gap of V; unprotected NUMERIC is a real value.
    #[test]
    fn numeric_gap_sampling_and_copy() {
        let mut v = Vec::new();
        for i in 0..300 {
            v.push(format!("{{\"k\":\"K{:04}\",\"price\":{},\"qty\":{}}}", i * 3, 1000 + i * 10 + (i % 3), i % 97));
        }
        let src = format!("[{}]", v.join(","));
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        let sh = infer_shape(&t);
        let price_v = sh.field("price").unwrap().numeric.clone().unwrap().values;
        let qty: HashSet<String> = t.rows.iter().map(|r| text(&r.0["qty"])).collect();
        let o = MarkOptions { n: 40, marker_fields: Some(vec!["k".into(), "price".into()]), exclusions: vec![] };
        let out = mark(src.as_bytes(), Format::Json, &K1, &o).unwrap();
        for c in &out.canaries {
            let p: i128 = text(&c.0["price"]).parse().unwrap();
            let k = price_v.partition_point(|&x| x < p);
            assert!(k > 0 && k < price_v.len() && price_v[k] != p && price_v[k - 1] < p, "price {p} inside a gap");
            assert!(qty.contains(&text(&c.0["qty"])), "unprotected NUMERIC copies a real value");
        }
    }

    /// r2.1: precomputed next-gap index equals the literal scan of §3.1.
    #[test]
    fn next_gap_matches_scan() {
        let cases: Vec<Vec<i128>> = vec![
            vec![1, 2, 3, 10, 11, 12, 20],
            vec![1, 5, 6, 7, 8],
            vec![1, 2, 3, 4],
            vec![0, 2],
            (0..200).map(|i| i * if i % 7 == 0 { 3 } else { 1 } + i / 13).collect(),
        ];
        for v in cases {
            let mut v = v;
            v.sort_unstable();
            v.dedup();
            let g = next_gaps(&v);
            let n = v.len() - 1;
            let w = |k: usize| v[k + 1] - v[k] - 1;
            if (0..n).all(|k| w(k) == 0) {
                assert!(g.is_empty());
                continue;
            }
            for (k0, &got) in g.iter().enumerate() {
                let mut k = k0;
                while w(k) == 0 {
                    k = (k + 1) % n;
                }
                assert_eq!(got, k, "{v:?} k0={k0}");
            }
            assert_eq!(g.len(), n);
        }
    }

    /// §5.3: NUMERIC collision is value based: |x - c| < 0.5·10^-s.
    #[test]
    fn numeric_collision_is_value_based() {
        let mut taken = Taken::Num { scale: 2, values: [51230i128, 70000].into_iter().collect() };
        let num = |t: &str| Cell::Num { text: t.into(), scale: text_scale(t) as u8 };
        assert!(taken.hits(&num("512.30")));
        assert!(taken.hits(&num("512.3"))); // s = 1: |512.30 - 512.3| < 0.05
        assert!(!taken.hits(&num("512.31")));
        assert!(taken.hits(&num("700"))); // 700.00 is real
        assert!(taken.hits(&num("512"))); // s = 0: 512.30 is within 0.5 of 512
        assert!(!taken.hits(&num("511")));
        taken.insert(&num("600.5"));
        assert!(taken.hits(&Cell::Str("600.50".into())));
        assert!(!taken.hits(&Cell::Str("600.55".into())));
    }

    /// §3.2 anchor: H/L slot values come from one real value, so si-dong pairs exist.
    #[test]
    fn anchor_preserves_word_combinations() {
        let src = parcels(600);
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        let pairs: HashSet<(String, String)> = t
            .rows
            .iter()
            .map(|r| {
                let a = text(&r.0["addr"]);
                let p: Vec<&str> = a.split(' ').collect();
                (p[0].to_string(), p[1].to_string())
            })
            .collect();
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(100)).unwrap();
        for c in &out.canaries {
            let a = text(&c.0["addr"]);
            let p: Vec<&str> = a.split(' ').collect();
            assert!(pairs.contains(&(p[0].to_string(), p[1].to_string())), "{a}");
        }
    }

    #[test]
    fn exclusions_are_avoided() {
        let src = parcels(300);
        let first = mark(src.as_bytes(), Format::Json, &K1, &opts(4)).unwrap();
        let addr0 = text(&first.canaries[0].0["addr"]);
        let area0 = text(&first.canaries[0].0["area"]);
        // Same values written differently still count (normalized).
        let excl = vec![format!("  {}　", addr0.replace(' ', "\u{3000}")), format!("+{area0}")];
        let o = MarkOptions { n: 4, marker_fields: None, exclusions: excl };
        let second = mark(src.as_bytes(), Format::Json, &K1, &o).unwrap();
        for c in &second.canaries {
            assert_ne!(text(&c.0["addr"]), addr0);
            assert_ne!(text(&c.0["area"]), area0);
        }
        assert_ne!(first.canaries[0], second.canaries[0]);
    }

    #[test]
    fn csv_missing_is_empty_string() {
        let mut src = String::from("id,area,note\r\n");
        for i in 0..300 {
            let note = if i % 2 == 0 { String::new() } else { format!("n{}", i % 10) };
            src.push_str(&format!("A{:03},{}.5,{}\r\n", i * 3, 10 + i * 2, note));
        }
        let out = mark(src.as_bytes(), Format::Csv, &K1, &opts(40)).unwrap();
        let mut empty = 0;
        for c in &out.canaries {
            for (_, v) in &c.0 {
                assert!(matches!(v, Cell::Str(_)), "CSV canary cells are strings");
            }
            if c.0["note"] == Cell::Str(String::new()) {
                empty += 1;
            }
        }
        assert!(empty > 5 && empty < 35, "about half missing, got {empty}");
        let marked = parse_table(&out.marked, Format::Csv).unwrap();
        assert_eq!(marked.rows.len(), 340);
        assert!(out.marked.starts_with(b"id,area,note\r\n"));
    }

    #[test]
    fn json_null_majority_kept() {
        let mut v = Vec::new();
        for i in 0..200 {
            let note = match i % 4 {
                0 => ",\"note\":null".to_string(),
                1 => String::new(),
                _ => format!(",\"note\":\"n{}\"", i % 5),
            };
            v.push(format!("{{\"id\":\"K{:03}\"{}}}", i * 3, note));
        }
        let src = format!("[{}]", v.join(","));
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(30)).unwrap();
        // null and absent are tied (50 each): not a majority -> key omitted
        assert!(out.canaries.iter().all(|c| c.0["note"] != Cell::Null));
        assert!(out.canaries.iter().any(|c| c.0["note"] == Cell::Missing));
    }

    /// AC8 edge cases.
    #[test]
    fn ac8_edges() {
        // one row: every field CATEGORICAL -> no auto marker
        let e = mark(b"[{\"a\":\"x1\",\"b\":2}]", Format::Json, &K1, &opts(1)).unwrap_err();
        assert_eq!(e.code, ErrorCode::NoMarker);
        let i: Value = serde_json::from_str(&crate::shape::inspect(b"[{\"a\":\"x1\",\"b\":2}]", None).unwrap()).unwrap();
        assert_eq!(i["suggestedMarkers"], serde_json::json!([]));
        assert_eq!(i["threshold"], 0);

        // one field
        let src: String = format!("[{}]", (0..100).map(|i| format!("{{\"id\":\"Q{:03}\"}}", i * 3)).collect::<Vec<_>>().join(","));
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(8)).unwrap();
        assert_eq!(out.markers, vec!["id"]);
        assert_eq!(out.shape_summary["threshold"], 1);
        assert_eq!(out.canaries.len(), 8);

        // all-missing field and all-same field next to a usable marker
        let src: String = format!(
            "[{}]",
            (0..100).map(|i| format!("{{\"id\":\"Q{:03}\",\"e\":null,\"s\":\"same\"}}", i * 3)).collect::<Vec<_>>().join(",")
        );
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(8)).unwrap();
        for c in &out.canaries {
            assert_eq!(c.0["e"], Cell::Null);
            assert_eq!(c.0["s"], Cell::Str("same".into()));
        }
        assert_eq!(out.shape_summary["fields"]["e"]["kind"], "EMPTY");
        assert_eq!(out.shape_summary["fields"]["s"]["kind"], "CATEGORICAL");

        // free text with all-different templates: OPAQUE (copied), unique flag not enforced
        let src: String = format!(
            "[{}]",
            (0..80)
                .map(|i| format!("{{\"id\":\"Q{:03}\",\"memo\":\"{}{}\"}}", i * 3, "가".repeat(i + 1), "!".repeat(i % 3)))
                .collect::<Vec<_>>()
                .join(",")
        );
        let table = parse_table(src.as_bytes(), Format::Json).unwrap();
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(8)).unwrap();
        assert_eq!(out.shape_summary["fields"]["memo"]["kind"], "OPAQUE");
        for c in &out.canaries {
            assert!(table.rows.iter().any(|r| r.0["memo"] == c.0["memo"]), "OPAQUE copies a real value");
        }
        // OPAQUE as marker -> NoMarker
        let o = MarkOptions { n: 1, marker_fields: Some(vec!["memo".into()]), exclusions: vec![] };
        let e = mark(src.as_bytes(), Format::Json, &K1, &o).unwrap_err();
        assert_eq!(e.code, ErrorCode::NoMarker);
        assert_eq!(e.message, "field memo has no reusable shape; choose other marker fields");
        // CATEGORICAL / unknown / bad count as markers
        let src2 = r#"[{"id":"Q001","t":"a"},{"id":"Q002","t":"b"},{"id":"Q003","t":"a"}]"#;
        let o = MarkOptions { n: 1, marker_fields: Some(vec!["t".into()]), exclusions: vec![] };
        assert_eq!(mark(src2.as_bytes(), Format::Json, &K1, &o).unwrap_err().code, ErrorCode::NoMarker);
        let o = MarkOptions { n: 1, marker_fields: Some(vec!["zz".into()]), exclusions: vec![] };
        assert_eq!(mark(src2.as_bytes(), Format::Json, &K1, &o).unwrap_err().code, ErrorCode::BadInput);
        let o = MarkOptions { n: 1, marker_fields: Some(vec![]), exclusions: vec![] };
        assert_eq!(mark(src2.as_bytes(), Format::Json, &K1, &o).unwrap_err().code, ErrorCode::BadInput);
        assert_eq!(mark(src2.as_bytes(), Format::Json, &K1, &opts(0)).unwrap_err().code, ErrorCode::BadInput);
        assert_eq!(mark(b"[]", Format::Json, &K1, &opts(1)).unwrap_err().code, ErrorCode::NoMarker);
    }

    /// AC7: 50k-row JSON, mark(n=64). Target < 1 s native (asserted in release only).
    #[test]
    fn ac7_perf_50k_mark() {
        let si = ["하남시", "성남시", "용인시"];
        let dong = ["미사동", "망월동", "정자동", "서현동", "죽전동", "보정동"];
        let mut v = Vec::with_capacity(50_000);
        for i in 0..50_000usize {
            let note = if i % 5 == 0 { String::new() } else { format!(",\n    \"note\": \"도로 접함 {}\"", i % 17) };
            v.push(format!(
                "  {{\n    \"id\": \"P-{:06}\",\n    \"addr\": \"{} {} {}-{}\",\n    \"area_m2\": {}.{:02},\n    \"use_type\": \"{}\"{}\n  }}",
                i * 7,
                si[i % 3],
                dong[(i / 3) % 6],
                1 + (i * 31) % 999,
                1 + i % 37,
                50 + (i * 53) % 1950,
                (i * 7) % 100,
                ["대", "전", "답", "임야", "잡종지"][i % 5],
                note
            ));
        }
        let src = format!("[\n{}\n]\n", v.join(",\n"));
        let start = std::time::Instant::now();
        let out = mark(src.as_bytes(), Format::Json, &K1, &opts(64)).unwrap();
        let took = start.elapsed();
        println!("ac7: input {} bytes, 50000 rows, mark(n=64) {:?}, markers {:?}", src.len(), took, out.markers);
        assert_eq!(out.canaries.len(), 64);
        if !cfg!(debug_assertions) {
            assert!(took.as_millis() < 1000, "took {took:?}");
        }
    }

    #[test]
    fn exhaustion_reports_index() {
        // A00..A64 as an operator marker: one template L1 D2, D range 00..64, every value taken.
        let src: String = format!("[{}]", (0..65).map(|i| format!("{{\"k\":\"A{:02}\"}}", i)).collect::<Vec<_>>().join(","));
        let o = MarkOptions { n: 1, marker_fields: Some(vec!["k".into()]), exclusions: vec![] };
        let e = mark(src.as_bytes(), Format::Json, &K1, &o).unwrap_err();
        assert_eq!(e.code, ErrorCode::CanaryExhausted);
        assert_eq!(e.message, "canary 0: no acceptable candidate");
        // and auto selection refuses it (free space condition)
        assert_eq!(mark(src.as_bytes(), Format::Json, &K1, &opts(1)).unwrap_err().code, ErrorCode::NoMarker);
    }

    #[test]
    fn error_messages_carry_no_values() {
        let src = parcels(50);
        let o = MarkOptions { n: 1, marker_fields: Some(vec!["note".into()]), exclusions: vec!["SECRETX".into()] };
        if let Err(e) = mark(src.as_bytes(), Format::Json, &K1, &o) {
            assert!(!e.message.contains("메모") && !e.message.contains("SECRETX"));
        }
        let e = mark(b"[{\"a\":\"VALUEX\"}]", Format::Json, &K1, &opts(1)).unwrap_err();
        assert!(!e.message.contains("VALUEX"));
    }
}
