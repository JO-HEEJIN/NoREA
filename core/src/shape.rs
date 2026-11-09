//! Shape inference, auto marker selection, inspect, shape summary.
//!
//! Spec: Fable_5_1/docs/protocol/canary-record-shape-v1.md r2.2 §3, §4, §6.
//! API: Fable_5_1/docs/CORE-API.md §1 shape.rs.
//!
//! Determinism: everything that feeds canary generation or the shape summary
//! is integer or string arithmetic. Frequency tables keep first-appearance
//! order (row order), never hash order. `space_log2_x100` uses a log2 built
//! from IEEE basic operations only (no libm), stored as an integer (§6.1).

use std::collections::HashSet;

use indexmap::IndexMap;
use serde_json::{json, Map, Value};

use crate::error::{Error, ErrorCode};
use crate::table::{detect_format, parse_table, Cell, Format, Table};

/// Field kind after reclassification (shape-v1 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    String,
    Numeric,
    Categorical,
    Bool,
    Opaque,
    Empty,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::String => "STRING",
            Kind::Numeric => "NUMERIC",
            Kind::Categorical => "CATEGORICAL",
            Kind::Bool => "BOOL",
            Kind::Opaque => "OPAQUE",
            Kind::Empty => "EMPTY",
        }
    }
}

/// Character class of a template run (shape-v1 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// `0-9`
    D,
    /// Hangul syllable U+AC00..U+D7A3
    H,
    /// `A-Za-z`
    L,
}

/// Template token: a run of one class with its length in chars, or one literal char.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Tok {
    Run(Class, u32),
    Lit(char),
}

/// D slot statistics. `min`/`max` are `len`-digit strings (same length, so
/// string order is numeric order). Generated values never exceed `max`.
#[derive(Debug, Clone, PartialEq)]
pub struct DigitSlot {
    pub len: u32,
    pub min: String,
    pub max: String,
}

/// One string template (shape-v1 §3.2).
#[derive(Debug, Clone)]
pub struct Template {
    pub tokens: Vec<Tok>,
    /// count(t): real non-missing cells with this template.
    pub count: u64,
    /// D slots in token order.
    pub digits: Vec<DigitSlot>,
    /// anchors(t): the H/L slot values (in token order) of each anchor value,
    /// row order, duplicates kept. An anchor is a value whose every H/L slot
    /// value has frequency >= 2 within (template, slot); all values if none.
    pub anchors: Vec<Vec<String>>,
    /// Distinct H/L value combinations in `anchors`.
    pub combos: u64,
}

/// NUMERIC statistics (shape-v1 §3.1). Values are integers `v·10^scale`.
#[derive(Debug, Clone)]
pub struct NumericStats {
    pub scale: u8,
    pub fixed_scale: bool,
    /// V[0..m): all non-missing values sorted, duplicates kept (r2.2).
    pub values: Vec<i128>,
    /// G = (max - min + 1) - d: empty integers between min and max.
    pub gaps: u128,
}

/// Shape of one field.
#[derive(Debug, Clone)]
pub struct FieldShape {
    pub name: String,
    pub kind: Kind,
    /// `d == m && m >= 2`, computed for fields that start as NUMERIC or STRING
    /// (shape-v1 §3). Reported as a data property; collision avoidance uses it
    /// only when the final kind is STRING or NUMERIC (§5.3).
    pub unique: bool,
    /// d: distinct non-missing values.
    pub distinct: u64,
    /// m: non-missing cells.
    pub non_missing: u64,
    /// Missing cells: JSON Missing + Null, CSV empty string.
    pub missing: u64,
    /// JSON only: more than half of the missing cells are `null` (§3.5).
    pub missing_as_null: bool,
    /// round_half_up(missing · 10^6 / rows), integer arithmetic (§3).
    pub missing_ppm: u64,
    pub numeric: Option<NumericStats>,
    /// STRING: templates in first-appearance order.
    pub templates: Vec<Template>,
    /// STRING: Σ_t space(t) (IEEE products and sums of integers).
    pub string_space: f64,
    /// CATEGORICAL / BOOL: values with counts in first-appearance order.
    pub vocab: Vec<(Cell, u64)>,
    /// OPAQUE and NUMERIC: all non-missing cells in row order (copy source, §3.1, §3.4).
    pub cells: Vec<Cell>,
    /// None for OPAQUE and EMPTY.
    pub space_log2_x100: Option<i64>,
    /// NUMERIC, unique, all integers, all texts the same length (§6.2 NUMERIC_CODE_LIKE).
    pub code_like: bool,
}

impl FieldShape {
    /// §4.1 condition 3: NUMERIC `G >= d`, STRING `space >= 2·d`. Other kinds: false.
    pub fn has_free_space(&self) -> bool {
        match self.kind {
            Kind::Numeric => self.numeric.as_ref().is_some_and(|n| n.gaps >= u128::from(self.distinct)),
            Kind::String => self.string_space >= 2.0 * self.distinct as f64,
            _ => false,
        }
    }
}

/// Shape of a table.
#[derive(Debug, Clone)]
pub struct Shape {
    pub format: Format,
    pub rows: u64,
    pub fields: Vec<FieldShape>,
}

impl Shape {
    pub fn field(&self, name: &str) -> Option<&FieldShape> {
        self.fields.iter().find(|f| f.name == name)
    }
}

pub fn threshold(markers_len: usize) -> usize {
    markers_len.min(2)
}

/// §4.1 condition 2 bound.
const MAX_MARKER_MISSING_PPM: u64 = 200_000;

/// Whether a cell counts as missing (shape-v1 §1.2, §3).
pub(crate) fn is_missing(c: &Cell, format: Format) -> bool {
    match c {
        Cell::Missing | Cell::Null => true,
        Cell::Str(s) => format == Format::Csv && s.is_empty(),
        _ => false,
    }
}

/// CSV NUMERIC candidate: `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$` (shape-v1 §1.2).
fn is_numeric_text(s: &str) -> bool {
    let b = s.strip_prefix('-').unwrap_or(s).as_bytes();
    let (int, frac) = match b.iter().position(|&c| c == b'.') {
        Some(p) => (&b[..p], Some(&b[p + 1..])),
        None => (b, None),
    };
    let int_ok = match int {
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
        [] => false,
    };
    int_ok && frac.is_none_or(|f| !f.is_empty() && f.iter().all(u8::is_ascii_digit))
}

/// Decimal places of a number text (`-?digits(.digits)?`).
pub(crate) fn text_scale(t: &str) -> usize {
    t.split_once('.').map_or(0, |(_, f)| f.len())
}

/// `t · 10^scale` as an integer for a text `[-]digits[.digits]`. Extra
/// fraction digits beyond `scale` are truncated. None on overflow or bad text.
pub(crate) fn parse_scaled(t: &str, scale: u8) -> Option<i128> {
    let (neg, body) = match t.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, t),
    };
    let (int, frac) = body.split_once('.').unwrap_or((body, ""));
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut v: i128 = 0;
    for b in int.bytes() {
        v = v.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
    }
    let fb = frac.as_bytes();
    for k in 0..usize::from(scale) {
        let d = fb.get(k).map_or(0, |b| b - b'0');
        v = v.checked_mul(10)?.checked_add(i128::from(d))?;
    }
    Some(if neg { -v } else { v })
}

/// Text of the integer `n` read as `n / 10^scale` (shape-v1 §3.1): fixed
/// `scale` decimals when `fixed`, else trailing zeros (and a bare `.`) removed.
pub(crate) fn format_scaled(n: i128, scale: u8, fixed: bool) -> String {
    let digits = n.unsigned_abs().to_string();
    let s = usize::from(scale);
    let padded = if digits.len() <= s { format!("{}{}", "0".repeat(s + 1 - digits.len()), digits) } else { digits };
    let (int, frac) = padded.split_at(padded.len() - s);
    let frac = if fixed { frac } else { frac.trim_end_matches('0') };
    let mut out = String::with_capacity(padded.len() + 2);
    if n < 0 {
        out.push('-');
    }
    out.push_str(int);
    if !frac.is_empty() {
        out.push('.');
        out.push_str(frac);
    }
    out
}

fn class_of(c: char) -> Option<Class> {
    match c {
        '0'..='9' => Some(Class::D),
        '\u{AC00}'..='\u{D7A3}' => Some(Class::H),
        'A'..='Z' | 'a'..='z' => Some(Class::L),
        _ => None,
    }
}

/// Tokenize by char (shape-v1 §3.2). Returns the template key and the text of
/// each run slot in order. No normalization: NFD jamo stay literal tokens.
pub(crate) fn tokenize(s: &str) -> (Vec<Tok>, Vec<&str>) {
    let mut toks = Vec::new();
    let mut parts = Vec::new();
    let mut run: Option<(Class, usize, u32)> = None; // class, start byte, length in chars
    for (i, c) in s.char_indices() {
        let cls = class_of(c);
        if let Some((rc, start, len)) = run {
            if cls == Some(rc) {
                run = Some((rc, start, len + 1));
                continue;
            }
            toks.push(Tok::Run(rc, len));
            parts.push(&s[start..i]);
            run = None;
        }
        match cls {
            Some(k) => run = Some((k, i, 1)),
            None => toks.push(Tok::Lit(c)),
        }
    }
    if let Some((rc, start, len)) = run {
        toks.push(Tok::Run(rc, len));
        parts.push(&s[start..]);
    }
    (toks, parts)
}

/// round(100 · log2(max(1, x))) using only IEEE basic operations (bit-by-bit
/// squaring), so the result is identical on every platform (§6.1).
fn log2_x100(x: f64) -> i64 {
    if !x.is_finite() {
        return 102_400;
    }
    if x <= 1.0 {
        return 0;
    }
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut y = f64::from_bits((bits & ((1u64 << 52) - 1)) | (1023u64 << 52)); // [1, 2)
    let mut frac = 0.0f64;
    let mut bit = 0.5f64;
    for _ in 0..52 {
        y *= y;
        if y >= 2.0 {
            y /= 2.0;
            frac += bit;
        }
        bit /= 2.0;
    }
    ((exp as f64 + frac) * 100.0).round() as i64
}

/// Identity key for distinct counting: Str by bytes, Num by text (shape-v1 §3).
fn identity(c: &Cell) -> String {
    match c {
        Cell::Str(s) => format!("s{s}"),
        Cell::Num { text, .. } => format!("n{text}"),
        Cell::Bool(b) => format!("b{b}"),
        Cell::Opaque(v) => format!("o{v}"),
        Cell::Null => "z".into(),
        Cell::Missing => "m".into(),
    }
}

fn cell_text(c: &Cell) -> &str {
    match c {
        Cell::Str(s) => s,
        Cell::Num { text, .. } => text,
        _ => "",
    }
}

struct TemplateAcc {
    count: u64,
    digits: Vec<DigitSlot>,
    /// per H/L slot: value -> count
    word_counts: Vec<IndexMap<String, u64>>,
    /// per value (row order): its H/L slot values
    rows: Vec<Vec<String>>,
}

/// Build templates (§3.2). None if degenerate (template count == m).
fn build_templates(vals: &[&Cell]) -> Option<Vec<Template>> {
    let mut map: IndexMap<Vec<Tok>, TemplateAcc> = IndexMap::new();
    for c in vals {
        let (toks, parts) = tokenize(cell_text(c));
        let runs: Vec<Class> = toks
            .iter()
            .filter_map(|t| match t {
                Tok::Run(c, _) => Some(*c),
                Tok::Lit(_) => None,
            })
            .collect();
        let acc = map.entry(toks).or_insert_with_key(|toks| TemplateAcc {
            count: 0,
            digits: toks
                .iter()
                .filter_map(|t| match t {
                    Tok::Run(Class::D, l) => Some(DigitSlot { len: *l, min: String::new(), max: String::new() }),
                    _ => None,
                })
                .collect(),
            word_counts: runs.iter().filter(|c| **c != Class::D).map(|_| IndexMap::new()).collect(),
            rows: Vec::new(),
        });
        let first = acc.count == 0;
        acc.count += 1;
        let (mut di, mut wi) = (0, 0);
        let mut words = Vec::with_capacity(acc.word_counts.len());
        for (cls, part) in runs.iter().zip(parts) {
            if *cls == Class::D {
                let s = &mut acc.digits[di];
                if first || part < s.min.as_str() {
                    s.min = part.to_string();
                }
                if first || part > s.max.as_str() {
                    s.max = part.to_string();
                }
                di += 1;
            } else {
                *acc.word_counts[wi].entry(part.to_string()).or_insert(0) += 1;
                words.push(part.to_string());
                wi += 1;
            }
        }
        acc.rows.push(words);
    }
    if map.len() == vals.len() {
        return None;
    }
    Some(
        map.into_iter()
            .map(|(tokens, acc)| {
                let mut anchors: Vec<Vec<String>> = acc
                    .rows
                    .iter()
                    .filter(|w| w.iter().zip(&acc.word_counts).all(|(v, wc)| wc[v.as_str()] >= 2))
                    .cloned()
                    .collect();
                if anchors.is_empty() {
                    anchors = acc.rows;
                }
                let combos = anchors.iter().collect::<HashSet<_>>().len() as u64;
                Template { tokens, count: acc.count, digits: acc.digits, anchors, combos }
            })
            .collect(),
    )
}

fn template_space(templates: &[Template]) -> f64 {
    let mut total = 0.0f64;
    for t in templates {
        let mut p = t.combos as f64;
        for s in &t.digits {
            p *= s.max.parse::<f64>().unwrap_or(0.0) - s.min.parse::<f64>().unwrap_or(0.0) + 1.0;
        }
        total += p;
    }
    total
}

fn infer_field(table: &Table, name: &str) -> FieldShape {
    let format = table.format();
    let rows = table.rows.len() as u64;
    let mut missing = 0u64;
    let mut nulls = 0u64;
    let mut vals: Vec<&Cell> = Vec::with_capacity(table.rows.len());
    for row in &table.rows {
        let c = row.0.get(name).unwrap_or(&Cell::Missing);
        if is_missing(c, format) {
            missing += 1;
            if matches!(c, Cell::Null) {
                nulls += 1;
            }
        } else {
            vals.push(c);
        }
    }
    let m = vals.len() as u64;
    let mut counts: IndexMap<String, (&Cell, u64)> = IndexMap::new();
    for c in &vals {
        counts.entry(identity(c)).or_insert((c, 0)).1 += 1;
    }
    let d = counts.len() as u64;
    let missing_ppm = if rows == 0 {
        0
    } else {
        ((u128::from(missing) * 2_000_000 + u128::from(rows)) / (2 * u128::from(rows))) as u64
    };
    let mut f = FieldShape {
        name: name.to_string(),
        kind: Kind::Empty,
        unique: false,
        distinct: d,
        non_missing: m,
        missing,
        missing_as_null: format == Format::Json && nulls * 2 > missing,
        missing_ppm,
        numeric: None,
        templates: Vec::new(),
        string_space: 0.0,
        vocab: Vec::new(),
        cells: Vec::new(),
        space_log2_x100: None,
        code_like: false,
    };
    if m == 0 {
        return f;
    }
    let vocab: Vec<(Cell, u64)> = counts.values().map(|(c, n)| ((*c).clone(), *n)).collect();
    let all_bool = vals.iter().all(|c| matches!(c, Cell::Bool(_)));
    let all_num = match format {
        Format::Json => vals.iter().all(|c| matches!(c, Cell::Num { .. })),
        Format::Csv => vals.iter().all(|c| matches!(c, Cell::Str(s) if is_numeric_text(s))),
    };
    let all_str = vals.iter().all(|c| matches!(c, Cell::Str(_)));
    let copy_all = |f: &mut FieldShape| f.cells = vals.iter().map(|c| (*c).clone()).collect();

    if all_bool {
        f.kind = Kind::Bool;
        f.vocab = vocab;
        f.space_log2_x100 = Some(log2_x100(d as f64));
        return f;
    }
    if !all_num && !all_str {
        f.kind = Kind::Opaque;
        copy_all(&mut f);
        return f;
    }
    f.unique = d == m && m >= 2;
    if d <= 2.max(m * 5 / 100) && d <= 64 {
        f.kind = Kind::Categorical;
        f.vocab = vocab;
        f.space_log2_x100 = Some(log2_x100(d as f64));
        return f;
    }
    if all_num {
        let max_scale = vals.iter().map(|c| text_scale(cell_text(c))).max().unwrap_or(0);
        let first_scale = text_scale(cell_text(vals[0]));
        let fixed_scale = vals.iter().all(|c| text_scale(cell_text(c)) == first_scale);
        let scale = max_scale.min(8) as u8;
        let ints: Option<Vec<i128>> = vals.iter().map(|c| parse_scaled(cell_text(c), scale)).collect();
        let Some(mut ints) = ints else {
            // Does not fit i128 at this scale: no numeric model (§3.1).
            f.kind = Kind::Opaque;
            copy_all(&mut f);
            return f;
        };
        // r2.2: V keeps duplicates (row-density weighting); G counts empty integers via d.
        ints.sort_unstable();
        let span = ints[ints.len() - 1].abs_diff(ints[0]).saturating_add(1);
        // Distinct integers, not distinct texts: scale truncation can merge texts.
        let distinct_ints = 1 + ints.windows(2).filter(|w| w[0] != w[1]).count() as u128;
        let gaps = span - distinct_ints;
        let first_len = cell_text(vals[0]).len();
        f.code_like = f.unique && max_scale == 0 && vals.iter().all(|c| cell_text(c).len() == first_len);
        f.kind = Kind::Numeric;
        f.space_log2_x100 = Some(log2_x100(gaps.max(1) as f64));
        f.numeric = Some(NumericStats { scale, fixed_scale, values: ints, gaps });
        copy_all(&mut f);
        return f;
    }
    match build_templates(&vals) {
        Some(templates) => {
            f.kind = Kind::String;
            f.string_space = template_space(&templates);
            f.space_log2_x100 = Some(log2_x100(f.string_space));
            f.templates = templates;
        }
        None => {
            f.kind = Kind::Opaque;
            copy_all(&mut f);
        }
    }
    f
}

pub fn infer_shape(table: &Table) -> Shape {
    Shape {
        format: table.format(),
        rows: table.rows.len() as u64,
        fields: table.fields.iter().map(|n| infer_field(table, n)).collect(),
    }
}

/// Why a field is not an auto marker candidate (§4.1), if it is not.
fn rejection(f: &FieldShape) -> Option<&'static str> {
    if !matches!(f.kind, Kind::String | Kind::Numeric) {
        return Some("kind");
    }
    if f.missing_ppm >= MAX_MARKER_MISSING_PPM {
        return Some("missing");
    }
    if !f.has_free_space() {
        return Some("free space");
    }
    None
}

/// shape-v1 §4.1: candidates satisfy kind STRING/NUMERIC, `missing_ppm <
/// 200000`, and the free-space condition; ordered by (distinct desc, STRING
/// before NUMERIC, name bytes asc), first min(3, n).
pub fn auto_markers(shape: &Shape) -> Result<Vec<String>, Error> {
    let mut cand: Vec<&FieldShape> = shape.fields.iter().filter(|f| rejection(f).is_none()).collect();
    if cand.is_empty() {
        let why: Vec<String> =
            shape.fields.iter().filter_map(|f| rejection(f).map(|r| format!("{} ({r})", f.name))).collect();
        let why = if why.is_empty() { "no fields".to_string() } else { why.join(", ") };
        return Err(Error::new(ErrorCode::NoMarker, format!("no field is suitable as a marker: {why}")));
    }
    cand.sort_by(|a, b| {
        b.distinct
            .cmp(&a.distinct)
            .then_with(|| (a.kind == Kind::Numeric).cmp(&(b.kind == Kind::Numeric)))
            .then_with(|| a.name.as_bytes().cmp(b.name.as_bytes()))
    });
    Ok(cand.iter().take(3).map(|f| f.name.clone()).collect())
}

/// shape-v1 §6.1. Integers only, fixed key order, fields in table order.
pub fn shape_summary(shape: &Shape, markers: &[String]) -> Value {
    let mut fields = Map::new();
    for f in &shape.fields {
        let mut o = Map::new();
        o.insert("kind".into(), Value::from(f.kind.as_str()));
        o.insert("unique".into(), Value::from(f.unique));
        o.insert("distinct".into(), Value::from(f.distinct));
        o.insert("missing_ppm".into(), Value::from(f.missing_ppm));
        if let Some(s) = f.space_log2_x100 {
            o.insert("space_log2_x100".into(), Value::from(s));
        }
        fields.insert(f.name.clone(), Value::Object(o));
    }
    json!({
        "kind": "record.shape.v1",
        "rows": shape.rows,
        "fields": fields,
        "markers": markers,
        "threshold": threshold(markers.len()),
    })
}

fn warning(code: &str, field: Option<&str>) -> Value {
    let mut o = Map::new();
    o.insert("code".into(), Value::from(code));
    if let Some(f) = field {
        o.insert("field".into(), Value::from(f));
    }
    Value::Object(o)
}

/// InspectResult JSON (platform-contract). camelCase keys. `pMissing` and
/// `spaceLog2` are display floats derived from the integer shape values.
pub fn inspect(bytes: &[u8], format: Option<Format>) -> Result<String, Error> {
    let format = format.unwrap_or_else(|| detect_format(bytes));
    let table = parse_table(bytes, format)?;
    let shape = infer_shape(&table);
    let mut warnings: Vec<Value> = Vec::new();
    for f in &shape.fields {
        let name = Some(f.name.as_str());
        match f.kind {
            Kind::Opaque => {
                warnings.push(warning("OPAQUE_FIELD", name));
                if f.unique {
                    warnings.push(warning("UNIQUE_OPAQUE_COPIED", name));
                }
            }
            Kind::String | Kind::Numeric => {
                if !f.has_free_space() {
                    warnings.push(warning("LOW_FREE_SPACE", name));
                }
                if f.missing_ppm >= MAX_MARKER_MISSING_PPM {
                    warnings.push(warning("HIGH_MISSING", name));
                }
                if f.code_like {
                    warnings.push(warning("NUMERIC_CODE_LIKE", name));
                }
            }
            _ => {}
        }
    }
    let markers = auto_markers(&shape).unwrap_or_default();
    if markers.is_empty() {
        warnings.push(warning("NO_MARKER_CANDIDATE", None));
    }
    let fields: Vec<Value> = shape
        .fields
        .iter()
        .map(|f| {
            let mut o = Map::new();
            o.insert("name".into(), Value::from(f.name.as_str()));
            o.insert("kind".into(), Value::from(f.kind.as_str()));
            o.insert("unique".into(), Value::from(f.unique));
            o.insert("distinct".into(), Value::from(f.distinct));
            o.insert("pMissing".into(), Value::from(f.missing_ppm as f64 / 1e6));
            if let Some(s) = f.space_log2_x100 {
                o.insert("spaceLog2".into(), Value::from(s as f64 / 100.0));
            }
            Value::Object(o)
        })
        .collect();
    let v = json!({
        "format": match format { Format::Json => "json", Format::Csv => "csv" },
        "rows": shape.rows,
        "fields": fields,
        "suggestedMarkers": markers,
        "threshold": threshold(markers.len()),
        "warnings": warnings,
    });
    Ok(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape_of(src: &str, format: Format) -> Shape {
        infer_shape(&parse_table(src.as_bytes(), format).unwrap())
    }

    fn json_rows(field: &str, vals: &[&str]) -> String {
        let rows: Vec<String> = vals.iter().map(|v| format!("{{\"{field}\":{v}}}")).collect();
        format!("[{}]", rows.join(","))
    }

    #[test]
    fn tokenize_example() {
        let (t, p) = tokenize("하남시 미사동 592-1");
        use Class::*;
        assert_eq!(
            t,
            vec![Tok::Run(H, 3), Tok::Lit(' '), Tok::Run(H, 3), Tok::Lit(' '), Tok::Run(D, 3), Tok::Lit('-'), Tok::Run(D, 1)]
        );
        assert_eq!(p, vec!["하남시", "미사동", "592", "1"]);
        let (t, _) = tokenize("P-001ab漢");
        assert_eq!(t, vec![Tok::Run(L, 1), Tok::Lit('-'), Tok::Run(D, 3), Tok::Run(L, 2), Tok::Lit('漢')]);
        // NFD jamo are not H: each is a literal token (no normalization).
        let (t, _) = tokenize("\u{1112}\u{1161}");
        assert_eq!(t, vec![Tok::Lit('\u{1112}'), Tok::Lit('\u{1161}')]);
    }

    #[test]
    fn numeric_text_and_scaled() {
        for ok in ["0", "-0", "12", "-12.50", "0.001"] {
            assert!(is_numeric_text(ok), "{ok}");
        }
        for bad in ["007", "", "-", "1.", ".5", "1e3", "+1", "1,000", " 1"] {
            assert!(!is_numeric_text(bad), "{bad}");
        }
        assert_eq!(parse_scaled("-12.5", 2), Some(-1250));
        assert_eq!(parse_scaled("3.14159", 2), Some(314));
        assert_eq!(parse_scaled("1e3", 0), None);
        assert_eq!(format_scaled(51200, 2, true), "512.00");
        assert_eq!(format_scaled(51200, 2, false), "512");
        assert_eq!(format_scaled(51250, 2, false), "512.5");
        assert_eq!(format_scaled(-5, 2, true), "-0.05");
        assert_eq!(format_scaled(7, 0, true), "7");
        assert_eq!(log2_x100(1024.0), 1000);
        assert_eq!(log2_x100(3.0), 158);
        assert_eq!(log2_x100(1.0), 0);
        assert_eq!(log2_x100(0.0), 0);
        assert_eq!(log2_x100(195_001.0), 1757);
    }

    #[test]
    fn kinds_in_order() {
        let mut rows = Vec::new();
        for i in 0..100 {
            rows.push(format!(
                "{{\"b\":{},\"num\":{}.5,\"s\":\"x{}y\",\"mix\":{},\"e\":null,\"cat\":\"c{}\",\"exp\":{}e3,\"same\":\"z\"}}",
                i % 2 == 0,
                i,
                i,
                if i % 2 == 0 { "1".to_string() } else { "\"1\"".to_string() },
                i % 3,
                i
            ));
        }
        let s = shape_of(&format!("[{}]", rows.join(",")), Format::Json);
        let k = |n: &str| s.field(n).unwrap().kind;
        assert_eq!(k("b"), Kind::Bool);
        assert_eq!(k("num"), Kind::Numeric);
        assert_eq!(k("s"), Kind::String);
        assert_eq!(k("mix"), Kind::Opaque);
        assert_eq!(k("e"), Kind::Empty);
        assert_eq!(k("cat"), Kind::Categorical);
        assert_eq!(k("same"), Kind::Categorical);
        assert!(s.field("num").unwrap().unique);
        assert!(s.field("s").unwrap().unique);
        assert!(!s.field("cat").unwrap().unique);
        assert_eq!(s.field("e").unwrap().missing_ppm, 1_000_000);
        assert!(s.field("e").unwrap().missing_as_null);
    }

    /// WP-01 hand-over: exponent numbers are Opaque cells, so the field is OPAQUE.
    #[test]
    fn exponent_numbers_make_field_opaque() {
        let vals: Vec<String> = (0..50).map(|i| format!("{}.{}", i + 10, i % 10)).collect();
        let mut v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        assert_eq!(s.field("a").unwrap().kind, Kind::Numeric);
        v[7] = "1.5e3";
        let s = shape_of(&json_rows("a", &v), Format::Json);
        assert_eq!(s.field("a").unwrap().kind, Kind::Opaque);
    }

    #[test]
    fn csv_empty_is_missing_and_numeric_regex() {
        let mut src = String::from("id,area,code,note\n");
        for i in 0..100 {
            let note = if i % 4 == 0 { String::new() } else { format!("n{i}") };
            src.push_str(&format!("{},{}.25,{:03},{}\n", i, 100 + i, i, note));
        }
        let s = shape_of(&src, Format::Csv);
        let f = |n: &str| s.field(n).unwrap();
        assert_eq!(f("id").kind, Kind::Numeric);
        assert_eq!(f("area").kind, Kind::Numeric);
        assert_eq!(f("code").kind, Kind::String, "leading zeros are not NUMERIC");
        assert_eq!(f("note").missing, 25);
        assert_eq!(f("note").missing_ppm, 250_000);
        assert_eq!(f("note").non_missing, 75);
        assert!(!f("note").missing_as_null);
    }

    #[test]
    fn missing_ppm_rounds_half_up() {
        // 1 missing of 3 rows = 333333.33 -> 333333; 1 of 8 = 125000; 1 of 2_000_000 = 0.5 -> 1
        let s = shape_of("[{\"a\":1},{\"a\":2},{}]", Format::Json);
        assert_eq!(s.field("a").unwrap().missing_ppm, 333_333);
        let s = shape_of("[{\"a\":1},{\"a\":2},{\"a\":3},{\"a\":4},{\"a\":5},{\"a\":6},{\"a\":7},{}]", Format::Json);
        assert_eq!(s.field("a").unwrap().missing_ppm, 125_000);
    }

    #[test]
    fn numeric_values_gaps_and_scale() {
        // 1..=100 step 1 at scale 0 plus 300: V has 101 values, G = (300-1+1) - 101 = 199
        let mut vals: Vec<String> = (1..=100).map(|i| i.to_string()).collect();
        vals.push("300".into());
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        let f = s.field("a").unwrap();
        let st = f.numeric.clone().unwrap();
        assert_eq!((st.values.len(), st.gaps, st.scale, st.fixed_scale), (101, 199, 0, true));
        assert!(f.has_free_space()); // 199 >= 101
        assert_eq!(f.space_log2_x100, Some(log2_x100(199.0)));
        assert_eq!(f.cells.len(), 101);
        assert!(!f.code_like, "texts have different lengths");
        // r2.2: duplicates are kept in V, G counts distinct values
        let mut vals: Vec<String> = (0..60).map(|i| (i * 3).to_string()).collect();
        vals.extend((0..20).map(|_| "3".to_string()));
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        let st = s.field("a").unwrap().numeric.clone().unwrap();
        assert_eq!((st.values.len(), st.gaps), (80, 178 - 60));
        assert_eq!(st.values.iter().filter(|&&x| x == 3).count(), 21);
        // dense integers: G = 0
        let vals: Vec<String> = (1..=100).map(|i| i.to_string()).collect();
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        let f = s.field("a").unwrap();
        assert_eq!(f.numeric.as_ref().unwrap().gaps, 0);
        assert!(!f.has_free_space());
        assert_eq!(f.space_log2_x100, Some(0));
        // scale is capped at 8, fixed_scale false on mixed decimals
        let vals: Vec<String> = (0..60).map(|i| format!("0.{:010}", i * 7 + 1)).collect();
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        assert_eq!(s.field("a").unwrap().numeric.as_ref().unwrap().scale, 8);
        // code-like: unique equal-length integers
        let vals: Vec<String> = (0..100).map(|i| (1_100_000_000u64 + i * 100).to_string()).collect();
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("a", &v), Format::Json);
        assert!(s.field("a").unwrap().code_like);
    }

    #[test]
    fn templates_anchors_and_degenerate() {
        let mut vals = Vec::new();
        for i in 0..100 {
            let (si, dong) = match i {
                0 => ("하남시", "희귀동"),
                _ if i % 2 == 0 => ("하남시", "미사동"),
                _ => ("성남시", "정자동"),
            };
            vals.push(format!("\"{} {} {}-{}\"", si, dong, 100 + i, i % 9 + 1));
        }
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("addr", &v), Format::Json);
        let f = s.field("addr").unwrap();
        assert_eq!(f.kind, Kind::String);
        assert_eq!(f.templates.len(), 1);
        let t = &f.templates[0];
        assert_eq!(t.count, 100);
        // anchors: the row with the count-1 word is dropped; combos keep si-dong pairs
        assert_eq!(t.anchors.len(), 99);
        assert_eq!(t.anchors[0], vec!["성남시".to_string(), "정자동".to_string()]);
        assert_eq!(t.combos, 2);
        assert_eq!(t.digits[0], DigitSlot { len: 3, min: "100".into(), max: "199".into() });
        assert_eq!(t.digits[1], DigitSlot { len: 1, min: "1".into(), max: "9".into() });
        // space = 2 combos * 100 * 9 = 1800
        assert_eq!(f.string_space, 1800.0);
        assert_eq!(f.space_log2_x100, Some(1081));
        assert!(f.has_free_space()); // 1800 >= 200

        // template without D slots: space = combos, below 2d -> no free space
        let vals: Vec<String> = (0..100).map(|i| format!("\"{}동\"", ["가나", "다라", "마바"][i % 3].to_string() + &"사".repeat(i % 40 / 3))).collect();
        let v: Vec<&str> = vals.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("dong", &v), Format::Json);
        let f = s.field("dong").unwrap();
        assert_eq!(f.kind, Kind::String);
        assert!(!f.has_free_space());

        // free text with all-different templates -> OPAQUE
        let free: Vec<String> = (0..80).map(|i| format!("\"{}{}\"", "가".repeat(i + 1), "!".repeat(i % 3))).collect();
        let v: Vec<&str> = free.iter().map(String::as_str).collect();
        let s = shape_of(&json_rows("memo", &v), Format::Json);
        let f = s.field("memo").unwrap();
        assert_eq!(f.kind, Kind::Opaque);
        assert!(f.unique);
        assert_eq!(f.cells.len(), 80);
        assert_eq!(f.space_log2_x100, None);
    }

    #[test]
    fn auto_markers_rule() {
        // a, b, n: d 100 with free space; c: d 90; m: 30% missing; dense: G = 0
        let mut rows = Vec::new();
        for i in 0..100 {
            let m = if i % 10 < 3 { "null".to_string() } else { format!("\"m{i}\"") };
            rows.push(format!(
                "{{\"n\":{},\"b\":\"b{:03}\",\"a\":\"a{:03}\",\"c\":\"c{:03}\",\"m\":{},\"dense\":{}}}",
                i * 3,
                i * 3,
                i * 3,
                (i % 90) * 3,
                m,
                1000 + i
            ));
        }
        let s = shape_of(&format!("[{}]", rows.join(",")), Format::Json);
        assert_eq!(auto_markers(&s).unwrap(), vec!["a", "b", "n"]);
        let s1 = shape_of("[{\"x\":1}]", Format::Json);
        let e = auto_markers(&s1).unwrap_err();
        assert_eq!(e.code, ErrorCode::NoMarker);
        assert_eq!(e.message, "no field is suitable as a marker: x (kind)");
        // only the dense field and a high-missing field
        let mut rows = Vec::new();
        for i in 0..100 {
            let m = if i % 2 == 0 { "null".to_string() } else { format!("\"m{i}\"") };
            rows.push(format!("{{\"dense\":{},\"m\":{}}}", 1000 + i, m));
        }
        let s = shape_of(&format!("[{}]", rows.join(",")), Format::Json);
        let e = auto_markers(&s).unwrap_err();
        assert_eq!(e.message, "no field is suitable as a marker: dense (free space), m (missing)");
    }

    #[test]
    fn inspect_and_summary_shape() {
        let mut rows = Vec::new();
        for i in 0..100 {
            let memo = format!("{}{}", "가".repeat(i + 1), "!".repeat(i % 3));
            rows.push(format!(
                "{{\"id\":\"P-{:03}\",\"area\":{}.50,\"t\":\"{}\",\"code\":{},\"seq\":{},\"memo\":\"{}\",\"rare\":{}}}",
                i * 3,
                100 + i * 2,
                ["a", "b"][i % 2],
                1_100_000_000u64 + i as u64 * 100,
                i,
                memo,
                if i % 3 == 0 { "\"r\"".to_string() } else { "null".into() }
            ));
        }
        let src = format!("[{}]", rows.join(","));
        let out = inspect(src.as_bytes(), None).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["format", "rows", "fields", "suggestedMarkers", "threshold", "warnings"]);
        assert_eq!(v["format"], "json");
        assert_eq!(v["rows"], 100);
        let f0: Vec<&String> = v["fields"][0].as_object().unwrap().keys().collect();
        assert_eq!(f0, ["name", "kind", "unique", "distinct", "pMissing", "spaceLog2"]);
        assert_eq!(v["fields"][2]["kind"], "CATEGORICAL");
        assert_eq!(v["fields"][5]["kind"], "OPAQUE");
        assert!(v["fields"][5].get("spaceLog2").is_none());
        assert_eq!(v["suggestedMarkers"], json!(["id", "area", "code"]));
        assert_eq!(v["threshold"], 2);
        assert_eq!(
            v["warnings"],
            json!([
                {"code": "NUMERIC_CODE_LIKE", "field": "code"},
                {"code": "LOW_FREE_SPACE", "field": "seq"},
                {"code": "OPAQUE_FIELD", "field": "memo"},
                {"code": "UNIQUE_OPAQUE_COPIED", "field": "memo"},
            ])
        );
        let none = inspect(b"[{\"x\":1}]", None).unwrap();
        let v: Value = serde_json::from_str(&none).unwrap();
        assert_eq!(v["warnings"], json!([{"code": "NO_MARKER_CANDIDATE"}]));
        // HIGH_MISSING
        let mut rows = Vec::new();
        for i in 0..100 {
            let a = if i % 4 == 0 { "null".into() } else { format!("\"A{:03}\"", i * 3) };
            rows.push(format!("{{\"a\":{a}}}"));
        }
        let v: Value = serde_json::from_str(&inspect(format!("[{}]", rows.join(",")).as_bytes(), None).unwrap()).unwrap();
        assert_eq!(v["warnings"], json!([{"code": "HIGH_MISSING", "field": "a"}, {"code": "NO_MARKER_CANDIDATE"}]));

        let shape = shape_of(&src, Format::Json);
        let sm = shape_summary(&shape, &["id".to_string(), "area".to_string()]);
        let s = sm.to_string();
        fn all_int(v: &Value) -> bool {
            match v {
                Value::Number(n) => n.is_u64() || n.is_i64(),
                Value::Array(a) => a.iter().all(all_int),
                Value::Object(o) => o.values().all(all_int),
                _ => true,
            }
        }
        assert!(all_int(&sm), "summary numbers are integers: {s}");
        assert!(s.starts_with(
            "{\"kind\":\"record.shape.v1\",\"rows\":100,\"fields\":{\"id\":{\"kind\":\"STRING\",\"unique\":true,\"distinct\":100,\"missing_ppm\":0,\"space_log2_x100\":"
        ));
        assert!(s.contains("\"memo\":{\"kind\":\"OPAQUE\",\"unique\":true,\"distinct\":100,\"missing_ppm\":0}"));
        assert!(s.contains("\"rare\":{\"kind\":\"CATEGORICAL\",\"unique\":false,\"distinct\":1,\"missing_ppm\":660000,\"space_log2_x100\":0}"));
        assert!(s.ends_with("\"markers\":[\"id\",\"area\"],\"threshold\":2}"));
    }
}
