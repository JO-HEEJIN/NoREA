//! Copy check: find canaries in a suspect file.
//!
//! Spec: Fable_5_1/docs/protocol/canary-record-shape-v1.md §7 (matching rules,
//! report `norea.check-report.v1`), CORE-API §1 check.rs.
//!
//! `match_rows` needs no secret: it takes canary rows (from the blob for
//! `check`, from a disclosure for `verify_disclosure`). `check` opens the blob
//! with K_d and recomputes the Merkle root (`commit_ok`).
//!
//! No regex crate: HTML and CSV are read by small hand-written scanners.

use std::collections::{BTreeMap, HashMap};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};

use crate::blob::open_blob;
use crate::error::Error;
use crate::evidence::{decode_hex32, hex, sha256_hex, verify_evidence, Evidence};
use crate::merkle::{leaf_hash, merkle_root};
use crate::norm::{normalize_number, normalize_text};
use crate::shape::threshold;
use crate::table::{canon_row, Cell, Row};
use crate::Key32;

pub const CHECK_REPORT_SCHEMA: &str = "norea.check-report.v1";

/// §7.4 window: two markers match in text when their start offsets are at most
/// this many characters apart.
const TEXT_WINDOW: usize = 512;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Suspect file kind (report `suspect_kind`). HTML is `Text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspectKind {
    Json,
    Csv,
    Text,
}

impl SuspectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SuspectKind::Json => "json",
            SuspectKind::Csv => "csv",
            SuspectKind::Text => "text",
        }
    }
}

/// Per-canary result for matched and partial canaries (§7.5 `per_index`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerIndex {
    /// Marker fields found in the best record, in marker order.
    pub found: Vec<String>,
    /// Where: JSON path (`$[12]`, `$.data[3]`), `record N` (CSV, 0-based, the
    /// first record counts), or `text offset N` (characters of the normalized text).
    pub record_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchResult {
    pub matched: Vec<u32>,
    pub partial: Vec<u32>,
    pub per_index: BTreeMap<u32, PerIndex>,
}

fn strip_bom(b: &[u8]) -> &[u8] {
    b.strip_prefix(BOM).unwrap_or(b)
}

/// JSON if the bytes (BOM removed) parse as any JSON value. Otherwise text if
/// the first non-whitespace character is `<` (HTML). Otherwise CSV if the
/// bytes are UTF-8 and split into RFC 4180 records that all have the same
/// number of cells, at least 2. Otherwise text.
pub fn detect_suspect_kind(bytes: &[u8]) -> SuspectKind {
    let body = strip_bom(bytes);
    if serde_json::from_slice::<serde::de::IgnoredAny>(body).is_ok() {
        return SuspectKind::Json;
    }
    let Ok(s) = std::str::from_utf8(body) else {
        return SuspectKind::Text;
    };
    if s.trim_start().starts_with('<') {
        return SuspectKind::Text;
    }
    match split_csv(s) {
        Some(recs) if !recs.is_empty() && recs[0].len() >= 2 && recs.iter().all(|r| r.len() == recs[0].len()) => {
            SuspectKind::Csv
        }
        _ => SuspectKind::Text,
    }
}

// ---------------------------------------------------------------------------
// values and comparison (§7.1)

/// Decimal `mant · 10^-scale`. Only for texts of at most 36 digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Dec {
    mant: i128,
    scale: u32,
}

/// Parses the canonical text of `normalize_number` (`-?digits(.digits)?`).
fn dec(norm: &str) -> Option<Dec> {
    let (neg, body) = match norm.strip_prefix('-') {
        Some(b) => (true, b),
        None => (false, norm),
    };
    let (i, f) = body.split_once('.').unwrap_or((body, ""));
    if i.len() + f.len() > 36 {
        return None;
    }
    let mut mant: i128 = 0;
    for b in i.bytes().chain(f.bytes()) {
        mant = mant * 10 + i128::from(b - b'0');
    }
    Some(Dec { mant: if neg { -mant } else { mant }, scale: f.len() as u32 })
}

fn pow10(e: u32) -> Option<i128> {
    10i128.checked_pow(e)
}

/// `|x − v| < 0.5 · 10^-s` with s = scale of v (§7.1). Exact integer arithmetic.
fn num_eq(v: Dec, x: Dec) -> bool {
    let t = x.scale.max(v.scale + 1);
    let (Some(px), Some(pv), Some(ph)) = (pow10(t - x.scale), pow10(t - v.scale), pow10(t - v.scale - 1)) else {
        return false;
    };
    let (Some(xx), Some(vv), Some(half)) = (x.mant.checked_mul(px), v.mant.checked_mul(pv), ph.checked_mul(5)) else {
        return false;
    };
    match xx.checked_sub(vv) {
        Some(d) => d.unsigned_abs() < half.unsigned_abs(),
        None => false,
    }
}

/// A suspect scalar, prepared once: string-rule form and number-rule form.
struct Leaf {
    text: String,
    num: Option<Dec>,
    /// Records (ids) this leaf belongs to.
    recs: Vec<u32>,
}

fn leaf_of(raw: &str, recs: Vec<u32>) -> Leaf {
    let text = normalize_text(raw);
    let num = normalize_number(&text).and_then(|n| dec(&n));
    Leaf { text, num, recs }
}

/// What a canary marker value looks for (§7.1, §7.4).
struct Want {
    /// String rule (canary `Str`): normalized text.
    text: Option<String>,
    /// Number rule: canary `Num`, or a `Str` for which `normalize_number` succeeds.
    num: Option<Dec>,
    /// Text-path patterns: the value as generated, its trailing-zero-stripped
    /// form and (numbers) the thousands-grouped forms of both.
    pats: Vec<String>,
}

impl Want {
    fn numeric(&self) -> bool {
        self.num.is_some()
    }
}

fn strip_trailing_zeros(t: &str) -> String {
    if !t.contains('.') {
        return t.to_string();
    }
    let s = t.trim_end_matches('0');
    s.strip_suffix('.').unwrap_or(s).to_string()
}

/// `1200.00` -> `1,200.00`. Unchanged when the integer part has at most 3 digits.
fn group_thousands(t: &str) -> String {
    let (sign, body) = t.strip_prefix('-').map_or(("", t), |b| ("-", b));
    let (int, frac) = body.split_once('.').map_or((body, None), |(i, f)| (i, Some(f)));
    let mut g = String::with_capacity(t.len() + int.len() / 3);
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

fn number_pats(t: &str) -> Vec<String> {
    let mut pats = vec![t.to_string()];
    let st = strip_trailing_zeros(t);
    for p in [st.clone(), group_thousands(t), group_thousands(&st)] {
        if !pats.contains(&p) {
            pats.push(p);
        }
    }
    pats
}

fn want_of(c: Option<&Cell>) -> Want {
    let none = Want { text: None, num: None, pats: Vec::new() };
    match c {
        Some(Cell::Str(s)) => {
            let t = normalize_text(s);
            if t.is_empty() {
                return none;
            }
            let num = normalize_number(&t).and_then(|n| dec(&n));
            let pats = if num.is_some() { number_pats(&t) } else { vec![t.clone()] };
            Want { text: Some(t), num, pats }
        }
        Some(Cell::Num { text, .. }) => match normalize_number(text).and_then(|n| dec(&n)) {
            Some(v) => Want { text: None, num: Some(v), pats: number_pats(text) },
            None => none,
        },
        _ => none,
    }
}

// ---------------------------------------------------------------------------
// records (§7.2)

struct Records {
    /// Per record: hint and number of scalar leaves in it.
    hints: Vec<String>,
    sizes: Vec<usize>,
    leaves: Vec<Leaf>,
}

impl Records {
    fn new() -> Self {
        Records { hints: Vec::new(), sizes: Vec::new(), leaves: Vec::new() }
    }
}

fn path_key(path: &str, k: &str) -> String {
    let simple = !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if simple {
        format!("{path}.{k}")
    } else {
        format!("{path}[{}]", Value::from(k))
    }
}

/// A row array: an array with at least one object or array element (§7.2).
fn is_row_array(a: &[Value]) -> bool {
    a.iter().any(|e| e.is_object() || e.is_array())
}

/// Starts a record at `v` (the top-level object, or an object/array element
/// of a row array) and collects its values.
fn new_record(v: &Value, path: &str, out: &mut Records) {
    let id = out.hints.len() as u32;
    out.hints.push(path.to_string());
    out.sizes.push(0);
    let n = fill(v, path, id, out);
    out.sizes[id as usize] = n;
}

/// Values of record `id`: scalar leaves reached through object members and
/// scalar arrays. A row array is not entered; each of its object/array
/// elements becomes its own record and its scalar elements are ignored.
/// Returns the number of leaves added to `id`.
fn fill(v: &Value, path: &str, id: u32, out: &mut Records) -> usize {
    let leaf = |raw: &str, out: &mut Records| {
        out.leaves.push(leaf_of(raw, vec![id]));
        1
    };
    match v {
        Value::Object(m) => m.iter().map(|(k, c)| fill(c, &path_key(path, k), id, out)).sum(),
        Value::Array(a) if is_row_array(a) => {
            row_array(a, path, out);
            0
        }
        Value::Array(a) => a.iter().map(|c| fill(c, path, id, out)).sum(),
        Value::String(t) => leaf(t, out),
        Value::Number(n) => leaf(&n.to_string(), out),
        Value::Bool(b) => leaf(if *b { "true" } else { "false" }, out),
        Value::Null => 0,
    }
}

fn row_array(a: &[Value], path: &str, out: &mut Records) {
    for (i, e) in a.iter().enumerate() {
        if e.is_object() || e.is_array() {
            new_record(e, &format!("{path}[{i}]"), out);
        }
    }
}

/// Lenient RFC 4180 split for suspects: `,` and `"` with `""` escape, LF or
/// CRLF terminators, quoted newlines allowed. Empty lines are skipped. `None`
/// on an unclosed quote or a character after a closing quote other than `,` or
/// a line end.
fn split_csv(s: &str) -> Option<Vec<Vec<String>>> {
    let mut recs = Vec::new();
    let mut rec: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut chars = s.chars().peekable();
    let mut at_cell_start = true;
    let mut line_empty = true;
    while let Some(c) = chars.next() {
        match c {
            '"' if at_cell_start => {
                line_empty = false;
                loop {
                    match chars.next()? {
                        '"' => {
                            if chars.peek() == Some(&'"') {
                                chars.next();
                                cell.push('"');
                            } else {
                                break;
                            }
                        }
                        ch => cell.push(ch),
                    }
                }
                match chars.peek() {
                    None | Some(',') | Some('\n') | Some('\r') => {}
                    _ => return None,
                }
                at_cell_start = false;
            }
            ',' => {
                line_empty = false;
                rec.push(std::mem::take(&mut cell));
                at_cell_start = true;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                if !line_empty {
                    rec.push(std::mem::take(&mut cell));
                    recs.push(std::mem::take(&mut rec));
                }
                cell.clear();
                at_cell_start = true;
                line_empty = true;
            }
            ch => {
                line_empty = false;
                cell.push(ch);
                at_cell_start = false;
            }
        }
    }
    if !line_empty {
        rec.push(cell);
        recs.push(rec);
    }
    Some(recs)
}

fn records_json(bytes: &[u8]) -> Option<Records> {
    let v: Value = serde_json::from_slice(strip_bom(bytes)).ok()?;
    let mut out = Records::new();
    match &v {
        Value::Object(_) => new_record(&v, "$", &mut out),
        Value::Array(a) if is_row_array(a) => row_array(a, "$", &mut out),
        _ => {}
    }
    Some(out)
}

fn records_csv(bytes: &[u8]) -> Option<Records> {
    let s = std::str::from_utf8(strip_bom(bytes)).ok()?;
    let mut out = Records::new();
    for (i, r) in split_csv(s)?.into_iter().enumerate() {
        let id = i as u32;
        out.hints.push(format!("record {i}"));
        out.sizes.push(r.len());
        for c in r {
            out.leaves.push(leaf_of(&c, vec![id]));
        }
    }
    Some(out)
}

/// §7.3 over records. `record_hint` rule (WP-04 open question): the smallest
/// matching record (fewest scalar leaves), then first in document order; for a
/// partial canary the record with most markers found, then smallest, then first.
fn match_records(recs: &Records, rows: &[(u32, Row)], markers: &[String]) -> MatchResult {
    let t = threshold(markers.len()) as u32;
    let mut index: HashMap<&str, Vec<u32>> = HashMap::new();
    for l in &recs.leaves {
        index.entry(l.text.as_str()).or_default().extend_from_slice(&l.recs);
    }
    let nums: Vec<(Dec, &[u32])> = recs.leaves.iter().filter_map(|l| l.num.map(|n| (n, l.recs.as_slice()))).collect();
    let mut res = MatchResult::default();
    for (idx, row) in rows {
        let mut masks: HashMap<u32, u64> = HashMap::new();
        for (fi, f) in markers.iter().enumerate().take(64) {
            let bit = 1u64 << fi;
            let w = want_of(row.0.get(f.as_str()));
            if let Some(t) = &w.text {
                if let Some(ids) = index.get(t.as_str()) {
                    for &r in ids {
                        *masks.entry(r).or_default() |= bit;
                    }
                }
            }
            if let Some(v) = w.num {
                for (x, ids) in &nums {
                    if num_eq(v, *x) {
                        for &r in *ids {
                            *masks.entry(r).or_default() |= bit;
                        }
                    }
                }
            }
        }
        if t == 0 {
            continue;
        }
        // Matching records first, the smallest of them (fewest leaves); without
        // one, the record with most markers, then smallest. Ties: document order.
        let best = masks
            .iter()
            .map(|(&r, &m)| {
                let c = m.count_ones();
                let rank = if c >= t { (1, 0) } else { (0, c) };
                (rank, std::cmp::Reverse(recs.sizes[r as usize]), std::cmp::Reverse(r), m)
            })
            .max();
        let Some((_, _, std::cmp::Reverse(r), m)) = best else { continue };
        let count = m.count_ones();
        if count == 0 {
            continue;
        }
        let found = markers
            .iter()
            .enumerate()
            .filter(|(fi, _)| *fi < 64 && m & (1 << fi) != 0)
            .map(|(_, f)| f.clone())
            .collect();
        if count >= t {
            res.matched.push(*idx);
        } else {
            res.partial.push(*idx);
        }
        res.per_index.insert(*idx, PerIndex { found, record_hint: Some(recs.hints[r as usize].clone()) });
    }
    res
}

// ---------------------------------------------------------------------------
// text and HTML (§7.4)

fn looks_html(s: &str) -> bool {
    if s.trim_start().starts_with('<') {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    ["<html", "<body", "<table"].iter().any(|t| lower.contains(t))
}

/// Byte index of the `>` that ends the tag starting at `i` (quotes respected).
fn tag_end(b: &[u8], i: usize) -> usize {
    let mut q: Option<u8> = None;
    let mut j = i + 1;
    while j < b.len() {
        match (q, b[j]) {
            (None, b'"') | (None, b'\'') => q = Some(b[j]),
            (Some(x), c) if c == x => q = None,
            (None, b'>') => return j,
            _ => {}
        }
        j += 1;
    }
    b.len()
}

fn find_from(hay: &str, from: usize, needle: &str) -> Option<usize> {
    hay.get(from..)?.find(needle).map(|p| p + from)
}

/// Removes `<script>`/`<style>` with their content, comments and tags. Each
/// removed piece becomes one space so neighbouring cells do not run together.
fn strip_tags(s: &str) -> String {
    let lower = s.to_ascii_lowercase(); // same byte offsets as `s`
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let Some(lt) = find_from(s, i, "<") else {
            out.push_str(&s[i..]);
            break;
        };
        out.push_str(&s[i..lt]);
        i = lt;
        let rest = &lower[i..];
        if rest.starts_with("<!--") {
            i = find_from(&lower, i + 4, "-->").map_or(b.len(), |e| e + 3);
            out.push(' ');
            continue;
        }
        let raw = ["script", "style"].into_iter().find(|n| {
            rest.get(1..1 + n.len()) == Some(*n)
                && matches!(b.get(i + 1 + n.len()), Some(b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'))
        });
        if let Some(name) = raw {
            let close = format!("</{name}");
            i = match find_from(&lower, i + 1, &close) {
                Some(c) => (tag_end(b, c) + 1).min(b.len()),
                None => b.len(),
            };
            out.push(' ');
            continue;
        }
        match b.get(i + 1) {
            Some(c) if c.is_ascii_alphabetic() || matches!(c, b'/' | b'!' | b'?') => {
                i = (tag_end(b, i) + 1).min(b.len());
                out.push(' ');
            }
            _ => {
                out.push('<');
                i += 1;
            }
        }
    }
    out
}

/// Entity decode: `&amp; &lt; &gt; &quot; &apos; &nbsp;`, `&#NNN;`, `&#xHH;`. Others stay as is.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let semi = rest[1..].find(';').map(|x| x + 1).filter(|&x| x <= 12);
        let decoded = semi.and_then(|e| {
            let name = &rest[1..e];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{00A0}'),
                _ => {
                    let n = name.strip_prefix('#')?;
                    let v = match n.strip_prefix(['x', 'X']) {
                        Some(h) if !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) => {
                            u32::from_str_radix(h, 16).ok()
                        }
                        Some(_) => None,
                        None if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => n.parse().ok(),
                        None => None,
                    };
                    v.and_then(char::from_u32)
                }
            };
            c.map(|c| (c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &rest[e + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The §7.4 search text: HTML reduced to its text (line breaks count as
/// spaces, as when rendered), then the §7.1 string rule over the whole.
fn search_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(strip_bom(bytes));
    if looks_html(&s) {
        let t = decode_entities(&strip_tags(&s));
        let t: String = t.chars().map(|c| if matches!(c, '\n' | '\r' | '\x0c') { ' ' } else { c }).collect();
        normalize_text(&t)
    } else {
        normalize_text(&s)
    }
}

/// Byte offset -> char offset, with a checkpoint every 256 chars.
struct CharIndex<'a> {
    text: &'a str,
    cps: Vec<usize>,
}

impl<'a> CharIndex<'a> {
    fn new(text: &'a str) -> Self {
        let cps = text.char_indices().step_by(256).map(|(b, _)| b).collect();
        CharIndex { text, cps }
    }
    fn char_at(&self, byte: usize) -> usize {
        let k = self.cps.partition_point(|&b| b <= byte).saturating_sub(1);
        let base = self.cps.get(k).copied().unwrap_or(0);
        k * 256 + self.text[base..byte].chars().count()
    }
}

/// §7.4 boundary: no Unicode letter or digit right before or after the
/// occurrence. Numbers additionally must not continue through `.`/`,` followed
/// (or preceded) by a digit (`1,330.5`, `0.330.5`, `330.5.1`).
fn boundary(text: &str, start: usize, end: usize, numeric: bool) -> bool {
    let mut before = text[..start].chars().rev();
    match before.next() {
        Some(c) if c.is_alphanumeric() => return false,
        Some('.' | ',') if numeric && before.next().is_some_and(|c| c.is_ascii_digit()) => return false,
        _ => {}
    }
    let mut after = text[end..].chars();
    match after.next() {
        Some(c) if c.is_alphanumeric() => false,
        Some('.' | ',') if numeric => !after.next().is_some_and(|c| c.is_ascii_digit()),
        _ => true,
    }
}

fn match_text(text: &str, rows: &[(u32, Row)], markers: &[String]) -> MatchResult {
    let t = threshold(markers.len());
    let ci = CharIndex::new(text);
    let mut cache: HashMap<(String, bool), Vec<usize>> = HashMap::new();
    let mut occ = |pat: &str, numeric: bool| -> Vec<usize> {
        cache
            .entry((pat.to_string(), numeric))
            .or_insert_with(|| {
                text.match_indices(pat)
                    .filter(|(b, m)| boundary(text, *b, b + m.len(), numeric))
                    .map(|(b, _)| ci.char_at(b))
                    .collect()
            })
            .clone()
    };
    let mut res = MatchResult::default();
    for (idx, row) in rows {
        // (char position, marker index) for every occurrence of every marker
        let mut events: Vec<(usize, usize)> = Vec::new();
        let mut found_any = vec![false; markers.len()];
        for (fi, f) in markers.iter().enumerate() {
            let w = want_of(row.0.get(f.as_str()));
            let pos: Vec<usize> = w.pats.iter().flat_map(|p| occ(p, w.numeric())).collect();
            found_any[fi] = !pos.is_empty();
            events.extend(pos.into_iter().map(|p| (p, fi)));
        }
        if t == 0 || !found_any.iter().any(|&x| x) {
            continue;
        }
        events.sort_unstable();
        // First position p where `t` distinct markers start within TEXT_WINDOW chars.
        let mut last: Vec<Option<usize>> = vec![None; markers.len()];
        let near = |last: &[Option<usize>], p: usize| -> Vec<usize> {
            (0..markers.len()).filter(|&g| last[g].is_some_and(|q| p - q <= TEXT_WINDOW)).collect()
        };
        let mut hit: Option<Vec<usize>> = None;
        for &(p, fi) in &events {
            last[fi] = Some(p);
            let n = near(&last, p);
            if n.len() >= t {
                hit = Some(n);
                break;
            }
        }
        let (found, hint) = match hit {
            Some(n) => {
                res.matched.push(*idx);
                let start = n.iter().filter_map(|&g| last[g]).min().unwrap_or(0);
                (n.iter().map(|&g| markers[g].clone()).collect(), start)
            }
            None => {
                res.partial.push(*idx);
                ((0..markers.len()).filter(|&g| found_any[g]).map(|g| markers[g].clone()).collect(), events[0].0)
            }
        };
        res.per_index.insert(*idx, PerIndex { found, record_hint: Some(format!("text offset {hint}")) });
    }
    res
}

/// §7.2–§7.4 for the given canary rows. No secret. A `Json`/`Csv` suspect that
/// does not parse as that kind is searched as text.
pub fn match_rows(suspect: &[u8], kind: SuspectKind, rows: &[(u32, Row)], markers: &[String]) -> MatchResult {
    match_rows_counted(suspect, kind, rows, markers).0
}

/// `match_rows` plus the number of records R taken from the suspect (`None`
/// on the text path). R feeds the disclosure statement (shape-v1 §6.1).
pub(crate) fn match_rows_counted(
    suspect: &[u8],
    kind: SuspectKind,
    rows: &[(u32, Row)],
    markers: &[String],
) -> (MatchResult, Option<usize>) {
    let recs = match kind {
        SuspectKind::Json => records_json(suspect),
        SuspectKind::Csv => records_csv(suspect),
        SuspectKind::Text => None,
    };
    match recs {
        Some(r) => (match_records(&r, rows, markers), Some(r.hints.len())),
        None => (match_text(&search_text(suspect), rows, markers), None),
    }
}

// ---------------------------------------------------------------------------
// check (§7.5)

/// Canary rows and shape from the blob, if they open with `k_d` and commit to
/// the signed root and count (`commit_ok`). `None` otherwise (wrong K_d or tampering).
pub(crate) fn committed_rows(ev: &Evidence, k_d: &Key32) -> Option<(Vec<Row>, Value)> {
    let marked = decode_hex32(&ev.marked_sha256)?;
    let blob = B64.decode(&ev.canary_blob_b64).ok()?;
    let (rows, shape) = open_blob(k_d, &ev.dataset_id, &marked, &blob).ok()?;
    // merkle_root panics on an empty slice: check the count first.
    if rows.is_empty() || rows.len() != ev.canary_count as usize {
        return None;
    }
    let leaves: Vec<[u8; 32]> = rows.iter().enumerate().map(|(i, r)| leaf_hash(i as u32, &canon_row(r))).collect();
    if hex(&merkle_root(&leaves)) != ev.canary_root {
        return None;
    }
    Some((rows, shape))
}

pub(crate) fn per_index_json(m: &BTreeMap<u32, PerIndex>) -> Value {
    let mut o = Map::new();
    for (i, p) in m {
        o.insert(i.to_string(), json!({ "found": p.found, "record_hint": p.record_hint }));
    }
    Value::Object(o)
}

/// Operator check: open the blob with K_d, recompute the Merkle root, match the
/// suspect, verify the evidence. Returns `norea.check-report.v1` JSON.
///
/// When `commit_ok` is false (wrong K_d, or the blob/root/count was changed)
/// nothing is matched: rows that do not commit to the signed root prove
/// nothing, so `matched` and `partial` are 0 and `absent` is `canary_count`.
pub fn check(suspect: &[u8], k_d: &Key32, ev: &Evidence) -> Result<String, Error> {
    if ev.canary_kind != crate::evidence::CANARY_KIND_RECORD_SHAPE_V1 {
        return Err(Error::new(
            crate::error::ErrorCode::BadEvidence,
            "unsupported canary_kind; v1 defines record.shape.v1 only",
        ));
    }
    let kind = detect_suspect_kind(suspect);
    let committed = committed_rows(ev, k_d);
    let commit_ok = committed.is_some();
    let res = match &committed {
        Some((rows, _)) => {
            let indexed: Vec<(u32, Row)> = rows.iter().cloned().enumerate().map(|(i, r)| (i as u32, r)).collect();
            match_rows(suspect, kind, &indexed, &ev.marker_fields)
        }
        None => MatchResult::default(),
    };
    let total = ev.canary_count;
    let matched = res.matched.len() as u32;
    let partial = res.partial.len() as u32;
    let ver = verify_evidence(ev);
    let report = json!({
        "schema": CHECK_REPORT_SCHEMA,
        "evidence_id": ev.evidence_id,
        "suspect_sha256": sha256_hex(suspect),
        "suspect_kind": kind.as_str(),
        "total": total,
        "matched": matched,
        "partial": partial,
        "absent": total.saturating_sub(matched + partial),
        "matched_indices": res.matched,
        "partial_indices": res.partial,
        "per_index": per_index_json(&res.per_index),
        "evidence": {
            "signature_ok": ver.signature_ok,
            "evidence_id_ok": ver.evidence_id_ok,
            "blob_hash_ok": ver.blob_hash_ok,
            "anchors": serde_json::to_value(&ver.anchors).expect("AnchorCheck serializes"),
        },
        "commit_ok": commit_ok,
    });
    Ok(report.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::row_from_json;

    fn row(v: Value) -> Row {
        row_from_json(&v).unwrap()
    }

    fn markers(m: &[&str]) -> Vec<String> {
        m.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detect_kinds() {
        assert_eq!(detect_suspect_kind(b"[{\"a\":1}]"), SuspectKind::Json);
        assert_eq!(detect_suspect_kind(b"\xEF\xBB\xBF{\"a\":1}"), SuspectKind::Json);
        assert_eq!(detect_suspect_kind(b"\"just a string\""), SuspectKind::Json);
        assert_eq!(detect_suspect_kind(b"a,b\n1,2\n"), SuspectKind::Csv);
        assert_eq!(detect_suspect_kind(b"a,\"b,c\"\r\n1,\"x\"\"y\"\r\n"), SuspectKind::Csv);
        assert_eq!(detect_suspect_kind(b"<table><tr><td>a,b</td></tr></table>"), SuspectKind::Text);
        assert_eq!(detect_suspect_kind(b"hello world\nsecond line"), SuspectKind::Text);
        assert_eq!(detect_suspect_kind(b"a,b\n1,2,3\n"), SuspectKind::Text);
        assert_eq!(detect_suspect_kind(b"\xff\xfe,\n"), SuspectKind::Text);
    }

    #[test]
    fn number_rule() {
        let d = |s: &str| dec(&normalize_number(s).unwrap()).unwrap();
        assert!(num_eq(d("132.70"), d("132.7")));
        assert!(num_eq(d("132.70"), d("132.704")));
        assert!(!num_eq(d("132.70"), d("132.705")), "exactly half is not < half");
        assert!(num_eq(d("132.70"), d("132.6951")));
        assert!(!num_eq(d("132.70"), d("132.71")));
        assert!(num_eq(d("1200.00"), d("1,200")));
        assert!(num_eq(d("512"), d("512.4")));
        assert!(!num_eq(d("512"), d("512.5")));
        assert!(num_eq(d("-5.5"), d("-5.50")));
        assert!(!num_eq(d("5.5"), d("-5.5")));
    }

    #[test]
    fn json_records_keys_ignored_and_nested() {
        let rows = vec![(0, row(json!({"id": "P-217", "addr": "하남시 미사동 5-3", "area_m2": 132.72})))];
        let m = markers(&["addr", "id", "area_m2"]);
        let s = r#"{"x":[{"q":"P-217","w":{"z":["하남시 미사동 5-3"]}},{"area":"132.72"}]}"#;
        let r = match_rows(s.as_bytes(), SuspectKind::Json, &rows, &m);
        // the outer object holds all three; the smallest matching record is $.x[0] (id + addr)
        assert_eq!(r.matched, vec![0]);
        assert_eq!(r.per_index[&0].record_hint.as_deref(), Some("$.x[0]"));
        assert_eq!(r.per_index[&0].found, vec!["addr", "id"]);
        // one marker only -> partial
        let r = match_rows(br#"[{"a":"P-217"}]"#, SuspectKind::Json, &rows, &m);
        assert_eq!((r.matched.len(), r.partial.clone()), (0, vec![0]));
        assert_eq!(r.per_index[&0].found, vec!["id"]);
        // nothing
        let r = match_rows(br#"[{"a":"P-218"}]"#, SuspectKind::Json, &rows, &m);
        assert!(r.matched.is_empty() && r.partial.is_empty() && r.per_index.is_empty());
    }

    #[test]
    fn str_canary_vs_number_and_num_canary_vs_string() {
        let rows = vec![(3, row(json!({"a": "330.5", "b": 1200.00})))];
        let m = markers(&["a", "b"]);
        // canary Str "330.5" vs suspect number 330.5: string rule on the text
        let r = match_rows(br#"[{"x":330.5,"y":"1,200"}]"#, SuspectKind::Json, &rows, &m);
        assert_eq!(r.matched, vec![3]);
        // suspect number 330.50: string rule fails, but "330.5" parses as a number,
        // so the number rule also applies (shape-v1 §7.1, WP-04 round 2) -> matched
        let r = match_rows(br#"[{"x":330.50,"y":"1,200"}]"#, SuspectKind::Json, &rows, &m);
        assert_eq!(r.matched, vec![3]);
        // a non-numeric Str only has the string rule
        let rows = vec![(3, row(json!({"a": "P-217", "b": 1200.00})))];
        let r = match_rows(br#"[{"x":"P-0217","y":"1,200"}]"#, SuspectKind::Json, &rows, &m);
        assert_eq!(r.partial, vec![3]);
    }

    #[test]
    fn csv_records() {
        let rows = vec![(0, row(json!({"id": "P-217", "area_m2": "132.72"})))];
        let m = markers(&["id", "area_m2"]);
        let r = match_rows(b"P-217,132.72\nP-1,1\n", SuspectKind::Csv, &rows, &m);
        assert_eq!(r.matched, vec![0]);
        assert_eq!(r.per_index[&0].record_hint.as_deref(), Some("record 0"));
        // different records -> partial
        let r = match_rows(b"P-217,1\nP-1,132.72\n", SuspectKind::Csv, &rows, &m);
        assert_eq!(r.partial, vec![0]);
    }

    #[test]
    fn html_scanner() {
        let h = "<html><head><style>td{x:1}</style><script type=\"a\">var s='P-217';</script></head>\
                 <body><!-- P-217 --><table><tr><td a=\"x>y\">A&amp;B</td><td>&#53;&#x31;2</td><td>&lt;b&gt;</td></tr></table>&nbsp;&#xZZ;</body></html>";
        let t = search_text(h.as_bytes());
        assert!(!t.contains("P-217"), "script, style and comments are removed: {t}");
        assert!(!t.contains("td{"));
        assert!(t.contains("A&B 512 <b>"), "{t}");
        assert!(t.ends_with("</b> &#xZZ;") || t.contains("&#xZZ;"), "unknown entities stay: {t}");
        assert!(!t.contains("&nbsp;"), "&nbsp; is decoded: {t}");
        assert_eq!(decode_entities("&quot;&apos;&#39;&#x41;&#65;&amp"), "\"''AA&amp");
    }

    #[test]
    fn boundaries() {
        assert!(boundary("x 330.5 y", 2, 7, true));
        assert!(!boundary("1330.5", 1, 6, true));
        assert!(!boundary("330.55", 0, 5, true));
        assert!(!boundary("1,330.5", 2, 7, true));
        assert!(!boundary("0.330.5", 2, 7, true));
        assert!(boundary("330.5.", 0, 5, true));
        assert!(boundary("(330.5)", 1, 6, true));
        assert!(boundary("330.5, 7", 0, 5, true));
        // every marker: no Unicode letter or digit next to it
        assert!(!boundary("P-2170", 0, 5, false));
        assert!(!boundary("XP-217", 1, 6, false));
        assert!(!boundary("가P-217", 3, 8, false));
        assert!(boundary("(P-217)", 1, 6, false));
        assert!(boundary("P-217.", 0, 5, false), "non-numeric: '.' is a boundary");
        assert!(!boundary("P-217.5", 0, 5, true), "numeric: '.' + digit is not");
    }

    #[test]
    fn number_patterns() {
        assert_eq!(number_pats("1200.00"), vec!["1200.00", "1200", "1,200.00", "1,200"]);
        assert_eq!(number_pats("330.5"), vec!["330.5"]);
        assert_eq!(group_thousands("-1234567.5"), "-1,234,567.5");
    }

    #[test]
    fn row_arrays() {
        let rows = vec![(0, row(json!({"id": "P-217", "addr": "하남시 미사동 5-3"})))];
        let m = markers(&["addr", "id"]);
        // values in two different rows of a wrapped array: no match (was matched under the subtree rule)
        let s = r#"{"data":[{"id":"P-217"},{"addr":"하남시 미사동 5-3"}],"meta":"x"}"#;
        let r = match_rows(s.as_bytes(), SuspectKind::Json, &rows, &m);
        assert!(r.matched.is_empty());
        assert_eq!(r.partial, vec![0]);
        // nesting inside a row is followed; rows that are arrays are records
        let s = r#"{"data":[{"row":{"x":"P-217","loc":{"a":["하남시 미사동 5-3"]}}}]}"#;
        let r = match_rows(s.as_bytes(), SuspectKind::Json, &rows, &m);
        assert_eq!(r.matched, vec![0]);
        assert_eq!(r.per_index[&0].record_hint.as_deref(), Some("$.data[0]"));
        let r = match_rows(r#"[["P-1","x"],["P-217","하남시 미사동 5-3"]]"#.as_bytes(), SuspectKind::Json, &rows, &m);
        assert_eq!(r.per_index[&0].record_hint.as_deref(), Some("$[1]"));
        assert_eq!(r.matched, vec![0]);
        // metadata of the wrapping object is a record of its own
        let (_, count) = match_rows_counted(br#"{"m":"P-217","data":[{"a":1},{"a":2}]}"#, SuspectKind::Json, &rows, &m);
        assert_eq!(count, Some(3));
    }

    #[test]
    fn str_number_marker_both_rules() {
        // CSV evidence: area is Str "1200.00"
        let rows = vec![(0, row(json!({"id": "P-217", "area_m2": "1200.00"})))];
        let m = markers(&["id", "area_m2"]);
        for s in [r#"[{"a":"P-217","b":1200}]"#, r#"[{"a":"P-217","b":1200.00}]"#, r#"[{"a":"P-217","b":"1,200.00"}]"#] {
            assert_eq!(match_rows(s.as_bytes(), SuspectKind::Json, &rows, &m).matched, vec![0], "{s}");
        }
        let html = "<table><tr><td>P-217&nbsp;</td><td>1,200.00</td></tr></table>";
        assert_eq!(match_rows(html.as_bytes(), SuspectKind::Text, &rows, &m).matched, vec![0]);
    }

    #[test]
    fn char_index() {
        let s = "가".repeat(1000) + "x";
        let ci = CharIndex::new(&s);
        assert_eq!(ci.char_at(0), 0);
        assert_eq!(ci.char_at(3 * 300), 300);
        assert_eq!(ci.char_at(3 * 1000), 1000);
    }
}
