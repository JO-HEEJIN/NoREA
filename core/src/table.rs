//! Table parsing and serialization (JSON, CSV), canon_row.
//!
//! Spec: Fable_5_1/docs/CORE-API.md §1 table.rs, ADR-0013,
//! protocol/canary-record-shape-v1.md §1-2, protocol/evidence-v1.md §7.1.
//!
//! - JSON: parsed into `Cell`s with number text kept (`arbitrary_precision`).
//!   Output is a full re-serialization in the detected style (BOM, indent,
//!   newline, final newline). Key order is `Table.fields`.
//! - CSV: RFC 4180, hand-written. Output splices inserted records between the
//!   original record bytes, which are copied unchanged.
//! - No function modifies its input; every output is a new buffer.
//! - No shape logic here (WP-02).

use std::collections::HashSet;
use std::fmt;

use indexmap::{IndexMap, IndexSet};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::error::Error;

const BOM: &[u8] = b"\xEF\xBB\xBF";

/// Input format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Csv,
}

/// One table cell (shape-v1 §1).
///
/// `Num.text` is serde_json `Number::to_string()`: the mantissa exactly as
/// written. `scale` is the number of digits after `.` (saturates at 255).
/// A JSON number whose text has an exponent has no defined scale and is
/// `Opaque` (shape-v1 §1.1, WP-01 "숫자 텍스트 정책").
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Str(String),
    Num { text: String, scale: u8 },
    Bool(bool),
    Null,
    Missing,
    Opaque(Value),
}

/// One row: field name to cell, in field order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Row(pub IndexMap<String, Cell>);

/// Parsed input. Every row of a parsed table has every field of `fields`, in
/// `fields` order; absent JSON keys are `Cell::Missing`.
#[derive(Debug, Clone)]
pub struct Table {
    pub fields: Vec<String>,
    pub rows: Vec<Row>,
    style: Style,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Newline {
    Lf,
    CrLf,
}

impl Newline {
    fn bytes(self) -> &'static [u8] {
        match self {
            Newline::Lf => b"\n",
            Newline::CrLf => b"\r\n",
        }
    }
}

#[derive(Debug, Clone)]
enum Style {
    Json(JsonStyle),
    Csv(CsvStyle),
}

#[derive(Debug, Clone)]
struct JsonStyle {
    src_len: usize,
    bom: bool,
    /// One indent unit (e.g. two spaces, one tab). None = compact.
    indent: Option<Vec<u8>>,
    newline: Newline,
    trailing_newline: bool,
}

#[derive(Debug, Clone)]
struct CsvStyle {
    src_len: usize,
    /// End of the header record including its terminator (and the BOM before it).
    header_end: usize,
    /// Data records as [start, end) byte ranges of the original, terminator included.
    records: Vec<(usize, usize)>,
    /// Dominant record terminator.
    newline: Newline,
    /// Whether the last record of the file ends with a terminator.
    last_terminated: bool,
}

fn strip_bom(bytes: &[u8]) -> (bool, &[u8]) {
    match bytes.strip_prefix(BOM) {
        Some(rest) => (true, rest),
        None => (false, bytes),
    }
}

/// JSON if the bytes (BOM removed) are syntactically valid JSON, else CSV.
/// Whether the JSON is an array of objects is checked by `parse_table`.
pub fn detect_format(bytes: &[u8]) -> Format {
    let (_, body) = strip_bom(bytes);
    if serde_json::from_slice::<IgnoredAny>(body).is_ok() {
        Format::Json
    } else {
        Format::Csv
    }
}

pub fn parse_table(bytes: &[u8], format: Format) -> Result<Table, Error> {
    match format {
        Format::Json => parse_json(bytes),
        Format::Csv => parse_csv(bytes),
    }
}

/// Output bytes with `inserts` placed at their final positions.
///
/// `inserts`: (index in the final row sequence, row). Positions must be
/// distinct and less than `table.rows.len() + inserts.len()`. `original` must
/// be the bytes `table` was parsed from. JSON: full re-serialization. CSV:
/// original record bytes spliced (ADR-0013).
pub fn serialize_with_inserts(
    original: &[u8],
    table: &Table,
    inserts: &[(usize, Row)],
) -> Result<Vec<u8>, Error> {
    let total = table.rows.len() + inserts.len();
    let ordered = order_inserts(inserts, total)?;
    match &table.style {
        Style::Json(st) => {
            if original.len() != st.src_len {
                return Err(Error::bad_input("original bytes do not match the parsed table"));
            }
            serialize_json(table, st, &ordered)
        }
        Style::Csv(st) => {
            if original.len() != st.src_len {
                return Err(Error::bad_input("original bytes do not match the parsed table"));
            }
            serialize_csv(original, table, st, &ordered)
        }
    }
}

/// Canonical bytes of a row (evidence-v1 §7.1). `Missing` cells are omitted.
pub fn canon_row(row: &Row) -> Vec<u8> {
    let mut out = Vec::new();
    let mut entries: Vec<(&String, &Cell)> =
        row.0.iter().filter(|(_, c)| !matches!(c, Cell::Missing)).collect();
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    out.push(b'{');
    for (i, (k, c)) in entries.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_jstr(&mut out, k);
        out.push(b':');
        match c {
            Cell::Str(s) => write_jstr(&mut out, s),
            Cell::Num { text, .. } => out.extend_from_slice(text.as_bytes()),
            Cell::Bool(true) => out.extend_from_slice(b"true"),
            Cell::Bool(false) => out.extend_from_slice(b"false"),
            Cell::Null => out.extend_from_slice(b"null"),
            Cell::Opaque(v) => canon_val(&mut out, v),
            Cell::Missing => {}
        }
    }
    out.push(b'}');
    out
}

/// A disclosure row (JSON object) as a Row. Number text is kept.
pub fn row_from_json(v: &Value) -> Result<Row, Error> {
    match v {
        Value::Object(m) => Ok(Row(m.iter().map(|(k, v)| (k.clone(), cell_from_value(v.clone()))).collect())),
        _ => Err(Error::bad_input("row must be a JSON object")),
    }
}

// ---------------------------------------------------------------------------
// shared helpers

fn cell_from_value(v: Value) -> Cell {
    match v {
        Value::String(s) => Cell::Str(s),
        Value::Number(n) => {
            let text = n.to_string();
            if text.bytes().any(|b| b == b'e' || b == b'E') {
                Cell::Opaque(Value::Number(n))
            } else {
                let scale = text.find('.').map(|i| text.len() - i - 1).unwrap_or(0);
                Cell::Num { text, scale: scale.min(u8::MAX as usize) as u8 }
            }
        }
        Value::Bool(b) => Cell::Bool(b),
        Value::Null => Cell::Null,
        v @ (Value::Array(_) | Value::Object(_)) => Cell::Opaque(v),
    }
}

/// JSON string with the escape rule of evidence-v1 §7.1, which is also the
/// serde_json default: `\"` `\\` `\b` `\f` `\n` `\r` `\t`, other U+0000..001F as
/// `\u00xx` lowercase, everything else (non-ASCII, U+007F) as is.
fn write_jstr(out: &mut Vec<u8>, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &[u8] = match b {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            0x08 => b"\\b",
            0x0c => b"\\f",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            0x00..=0x1f => b"",
            _ => continue,
        };
        out.extend_from_slice(&bytes[start..i]);
        if esc.is_empty() {
            out.extend_from_slice(b"\\u00");
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0xf) as usize]);
        } else {
            out.extend_from_slice(esc);
        }
        start = i + 1;
    }
    out.extend_from_slice(&bytes[start..]);
    out.push(b'"');
}

fn canon_val(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_jstr(out, s),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canon_val(out, x);
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, x)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_jstr(out, k);
                out.push(b':');
                canon_val(out, x);
            }
            out.push(b'}');
        }
    }
}

/// Sorted inserts. Rejects duplicate or out-of-range positions.
fn order_inserts(inserts: &[(usize, Row)], total: usize) -> Result<Vec<&(usize, Row)>, Error> {
    let mut v: Vec<&(usize, Row)> = inserts.iter().collect();
    v.sort_by_key(|(p, _)| *p);
    for (i, (p, _)) in v.iter().enumerate() {
        if *p >= total {
            return Err(Error::bad_input("insert position out of range"));
        }
        if i > 0 && v[i - 1].0 == *p {
            return Err(Error::bad_input("duplicate insert position"));
        }
    }
    Ok(v)
}

enum FinalRow<'a> {
    Original(usize, &'a Row),
    Inserted(&'a Row),
}

/// Visits rows in final order: inserts at their positions, original rows in between.
fn for_each_final<'a>(
    rows: &'a [Row],
    ordered: &[&'a (usize, Row)],
    mut f: impl FnMut(FinalRow<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    let total = rows.len() + ordered.len();
    let (mut oi, mut ii) = (0, 0);
    for k in 0..total {
        if ii < ordered.len() && ordered[ii].0 == k {
            f(FinalRow::Inserted(&ordered[ii].1))?;
            ii += 1;
        } else {
            f(FinalRow::Original(oi, &rows[oi]))?;
            oi += 1;
        }
    }
    Ok(())
}

/// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`
fn is_json_number(t: &str) -> bool {
    let b = t.as_bytes();
    let mut i = 0;
    if b.first() == Some(&b'-') {
        i += 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            while matches!(b.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let s = i;
        while matches!(b.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == s {
            return false;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let s = i;
        while matches!(b.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == s {
            return false;
        }
    }
    i == b.len()
}

// ---------------------------------------------------------------------------
// JSON

/// Top-level array of objects, keeping each object's key order. serde_json has
/// `preserve_order` on, so nested `Value::Object`s keep input order too; this
/// visitor additionally lets rows land directly in an `IndexMap`.
struct RawRows(Vec<IndexMap<String, Value>>);
struct RawRow(IndexMap<String, Value>);

impl<'de> Deserialize<'de> for RawRows {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawRows;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of objects")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RawRows, A::Error> {
                let mut rows = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(RawRow(r)) = seq.next_element()? {
                    rows.push(r);
                }
                Ok(RawRows(rows))
            }
        }
        d.deserialize_seq(V)
    }
}

impl<'de> Deserialize<'de> for RawRow {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawRow;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawRow, A::Error> {
                let mut m = IndexMap::with_capacity(map.size_hint().unwrap_or(0));
                // Duplicate key: last value wins at the first position (same as serde_json).
                while let Some((k, v)) = map.next_entry::<String, Value>()? {
                    m.insert(k, v);
                }
                Ok(RawRow(m))
            }
        }
        d.deserialize_map(V)
    }
}

fn parse_json(bytes: &[u8]) -> Result<Table, Error> {
    let (bom, body) = strip_bom(bytes);
    // serde_json messages can quote input values, so they are not passed on.
    let raw: RawRows = serde_json::from_slice(body).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => Error::bad_input("JSON input must be an array of objects"),
        _ => Error::bad_input(format!("invalid JSON at line {} column {}", e.line(), e.column())),
    })?;

    let mut fields: IndexSet<String> = IndexSet::new();
    for r in &raw.0 {
        for k in r.keys() {
            if !fields.contains(k) {
                fields.insert(k.clone());
            }
        }
    }
    let rows = raw
        .0
        .into_iter()
        .map(|mut r| {
            Row(fields
                .iter()
                .map(|f| {
                    let c = r.swap_remove(f).map(cell_from_value).unwrap_or(Cell::Missing);
                    (f.clone(), c)
                })
                .collect())
        })
        .collect();

    let (indent, newline, trailing_newline) = detect_json_style(body);
    Ok(Table {
        fields: fields.into_iter().collect(),
        rows,
        style: Style::Json(JsonStyle { src_len: bytes.len(), bom, indent, newline, trailing_newline }),
    })
}

/// (indent unit, newline, ends with newline). The indent unit is the leading
/// whitespace of the first non-blank line after the first line, when it is
/// made of only spaces or only tabs; otherwise compact.
fn detect_json_style(body: &[u8]) -> (Option<Vec<u8>>, Newline, bool) {
    let newline = match body.iter().position(|&b| b == b'\n') {
        Some(p) if p > 0 && body[p - 1] == b'\r' => Newline::CrLf,
        _ => Newline::Lf,
    };
    let trailing_newline = body
        .iter()
        .rev()
        .find(|&&b| b != b' ' && b != b'\t')
        .is_some_and(|&b| b == b'\n');

    let start = body.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(body.len());
    let mut indent = None;
    let mut lines = body[start..].split(|&b| b == b'\n');
    lines.next(); // first line
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let lead: &[u8] = &line[..line.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(0)];
        if !lead.is_empty() && lead.iter().all(|&b| b == lead[0]) {
            indent = Some(lead.to_vec());
        }
        break;
    }
    (indent, newline, trailing_newline)
}

struct JsonWriter<'a> {
    out: Vec<u8>,
    indent: Option<&'a [u8]>,
    nl: &'static [u8],
}

impl JsonWriter<'_> {
    fn line(&mut self, level: usize) {
        if let Some(unit) = self.indent {
            self.out.extend_from_slice(self.nl);
            for _ in 0..level {
                self.out.extend_from_slice(unit);
            }
        }
    }

    fn key(&mut self, k: &str) {
        write_jstr(&mut self.out, k);
        self.out.extend_from_slice(if self.indent.is_some() { b": " } else { b":" });
    }

    fn value(&mut self, v: &Value, level: usize) {
        match v {
            Value::Array(a) if !a.is_empty() => {
                self.out.push(b'[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.line(level + 1);
                    self.value(x, level + 1);
                }
                self.line(level);
                self.out.push(b']');
            }
            Value::Object(m) if !m.is_empty() => {
                self.out.push(b'{');
                for (i, (k, x)) in m.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.line(level + 1);
                    self.key(k);
                    self.value(x, level + 1);
                }
                self.line(level);
                self.out.push(b'}');
            }
            Value::Array(_) => self.out.extend_from_slice(b"[]"),
            Value::Object(_) => self.out.extend_from_slice(b"{}"),
            Value::Null => self.out.extend_from_slice(b"null"),
            Value::Bool(true) => self.out.extend_from_slice(b"true"),
            Value::Bool(false) => self.out.extend_from_slice(b"false"),
            Value::Number(n) => self.out.extend_from_slice(n.to_string().as_bytes()),
            Value::String(s) => write_jstr(&mut self.out, s),
        }
    }

    fn cell(&mut self, c: &Cell, level: usize) -> Result<(), Error> {
        match c {
            Cell::Str(s) => write_jstr(&mut self.out, s),
            Cell::Num { text, .. } => {
                if !is_json_number(text) {
                    return Err(Error::bad_input("number cell text is not a JSON number"));
                }
                self.out.extend_from_slice(text.as_bytes());
            }
            Cell::Bool(true) => self.out.extend_from_slice(b"true"),
            Cell::Bool(false) => self.out.extend_from_slice(b"false"),
            Cell::Null => self.out.extend_from_slice(b"null"),
            Cell::Opaque(v) => self.value(v, level),
            Cell::Missing => {}
        }
        Ok(())
    }

    /// Row object: keys in `fields` order, Missing omitted, then keys not in
    /// `fields` (only possible for inserted rows) in row order.
    fn row(&mut self, row: &Row, fields: &[String], field_set: &HashSet<&str>, level: usize) -> Result<(), Error> {
        let mut entries: Vec<(&str, &Cell)> = Vec::with_capacity(row.0.len());
        let mut seen = 0;
        for f in fields {
            if let Some(c) = row.0.get(f.as_str()) {
                seen += 1;
                if !matches!(c, Cell::Missing) {
                    entries.push((f, c));
                }
            }
        }
        if seen < row.0.len() {
            for (k, c) in &row.0 {
                if !field_set.contains(k.as_str()) && !matches!(c, Cell::Missing) {
                    entries.push((k, c));
                }
            }
        }
        if entries.is_empty() {
            self.out.extend_from_slice(b"{}");
            return Ok(());
        }
        self.out.push(b'{');
        for (i, (k, c)) in entries.into_iter().enumerate() {
            if i > 0 {
                self.out.push(b',');
            }
            self.line(level + 1);
            self.key(k);
            self.cell(c, level + 1)?;
        }
        self.line(level);
        self.out.push(b'}');
        Ok(())
    }
}

fn serialize_json(table: &Table, st: &JsonStyle, ordered: &[&(usize, Row)]) -> Result<Vec<u8>, Error> {
    let mut w = JsonWriter {
        out: Vec::with_capacity(st.src_len + st.src_len / 8 + 64),
        indent: st.indent.as_deref(),
        nl: st.newline.bytes(),
    };
    if st.bom {
        w.out.extend_from_slice(BOM);
    }
    let field_set: HashSet<&str> = table.fields.iter().map(String::as_str).collect();
    let total = table.rows.len() + ordered.len();
    w.out.push(b'[');
    let mut first = true;
    for_each_final(&table.rows, ordered, |fr| {
        if !first {
            w.out.push(b',');
        }
        first = false;
        w.line(1);
        let row = match fr {
            FinalRow::Original(_, r) | FinalRow::Inserted(r) => r,
        };
        w.row(row, &table.fields, &field_set, 1)
    })?;
    if total > 0 {
        w.line(0);
    }
    w.out.push(b']');
    if st.trailing_newline {
        w.out.extend_from_slice(st.newline.bytes());
    }
    Ok(w.out)
}

// ---------------------------------------------------------------------------
// CSV (RFC 4180, delimiter `,`, quote `"`, terminator CRLF or LF)

struct CsvRecord {
    start: usize,
    end: usize,
    cells: Vec<String>,
    term: Option<Newline>,
}

fn is_term(bytes: &[u8], i: usize) -> bool {
    bytes[i] == b'\n' || (bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n'))
}

fn parse_csv(bytes: &[u8]) -> Result<Table, Error> {
    let (bom, body) = strip_bom(bytes);
    if std::str::from_utf8(body).is_err() {
        return Err(Error::bad_input("CSV input is not valid UTF-8"));
    }
    let n = bytes.len();
    let mut i = if bom { BOM.len() } else { 0 };
    if i == n {
        return Err(Error::bad_input("CSV input has no header"));
    }

    let mut records: Vec<CsvRecord> = Vec::new();
    while i < n {
        let rec_no = records.len() + 1;
        // The header record starts at 0 so that splicing copies the BOM with it.
        let start = if records.is_empty() { 0 } else { i };
        let mut cells = Vec::new();
        loop {
            let mut cell: Vec<u8> = Vec::new();
            if bytes.get(i) == Some(&b'"') {
                i += 1;
                loop {
                    match bytes.get(i) {
                        None => {
                            return Err(Error::bad_input(format!(
                                "CSV record {rec_no} has an unterminated quoted field"
                            )))
                        }
                        Some(b'"') if bytes.get(i + 1) == Some(&b'"') => {
                            cell.push(b'"');
                            i += 2;
                        }
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(&b) => {
                            cell.push(b);
                            i += 1;
                        }
                    }
                }
                if i < n && bytes[i] != b',' && !is_term(bytes, i) {
                    return Err(Error::bad_input(format!(
                        "CSV record {rec_no} has a character after a closing quote"
                    )));
                }
            } else {
                let s = i;
                while i < n && bytes[i] != b',' && !is_term(bytes, i) {
                    i += 1;
                }
                cell.extend_from_slice(&bytes[s..i]);
            }
            // Splits happen only at ASCII bytes of valid UTF-8, so this does not fail in practice.
            cells.push(String::from_utf8(cell).map_err(|_| Error::bad_input("CSV input is not valid UTF-8"))?);
            if i < n && bytes[i] == b',' {
                i += 1;
                continue;
            }
            break;
        }
        let term = if i >= n {
            None
        } else if bytes[i] == b'\n' {
            i += 1;
            Some(Newline::Lf)
        } else {
            i += 2;
            Some(Newline::CrLf)
        };
        records.push(CsvRecord { start, end: i, cells, term });
    }

    let mut iter = records.into_iter();
    let header = iter.next().ok_or_else(|| Error::bad_input("CSV input has no header"))?;
    let width = header.cells.len();
    let mut seen = HashSet::new();
    if !header.cells.iter().all(|c| seen.insert(c.as_str())) {
        return Err(Error::bad_input("CSV header has a duplicate field name"));
    }
    let (mut lf, mut crlf) = (0usize, 0usize);
    let mut count = |t: Option<Newline>| match t {
        Some(Newline::Lf) => lf += 1,
        Some(Newline::CrLf) => crlf += 1,
        None => {}
    };
    count(header.term);
    let mut last_terminated = header.term.is_some();
    let mut ranges = Vec::new();
    let mut rows = Vec::new();
    for (r, rec) in iter.enumerate() {
        if rec.cells.len() != width {
            return Err(Error::bad_input(format!(
                "CSV record {} has {} fields, header has {}",
                r + 2,
                rec.cells.len(),
                width
            )));
        }
        count(rec.term);
        last_terminated = rec.term.is_some();
        ranges.push((rec.start, rec.end));
        rows.push(Row(header.cells.iter().cloned().zip(rec.cells.into_iter().map(Cell::Str)).collect()));
    }
    let newline = if crlf > lf { Newline::CrLf } else { Newline::Lf };
    Ok(Table {
        fields: header.cells,
        rows,
        style: Style::Csv(CsvStyle { src_len: n, header_end: header.end, records: ranges, newline, last_terminated }),
    })
}

fn csv_cell_text(c: &Cell) -> String {
    match c {
        Cell::Str(s) => s.clone(),
        Cell::Num { text, .. } => text.clone(),
        Cell::Bool(b) => b.to_string(),
        Cell::Null | Cell::Missing => String::new(),
        Cell::Opaque(v) => {
            let mut w = JsonWriter { out: Vec::new(), indent: None, nl: b"\n" };
            w.value(v, 0);
            String::from_utf8(w.out).unwrap_or_default()
        }
    }
}

/// Quote only when the text has `,` `"` CR LF or leading/trailing whitespace (ADR-0013).
fn write_csv_cell(out: &mut Vec<u8>, s: &str) {
    let needs = s.bytes().any(|b| matches!(b, b',' | b'"' | b'\r' | b'\n'))
        || s.chars().next().is_some_and(char::is_whitespace)
        || s.chars().next_back().is_some_and(char::is_whitespace);
    if !needs {
        out.extend_from_slice(s.as_bytes());
        return;
    }
    out.push(b'"');
    for b in s.bytes() {
        if b == b'"' {
            out.push(b'"');
        }
        out.push(b);
    }
    out.push(b'"');
}

fn serialize_csv(original: &[u8], table: &Table, st: &CsvStyle, ordered: &[&(usize, Row)]) -> Result<Vec<u8>, Error> {
    let nl = st.newline.bytes();
    let field_set: HashSet<&str> = table.fields.iter().map(String::as_str).collect();
    let mut out = Vec::with_capacity(original.len() + ordered.len() * 128);
    out.extend_from_slice(&original[..st.header_end]);
    let n_orig = st.records.len();
    let mut prev_terminated = n_orig > 0 || st.last_terminated;
    let mut last_was_insert = false;
    for_each_final(&table.rows, ordered, |fr| {
        match fr {
            FinalRow::Original(i, _) => {
                let (s, e) = st.records[i];
                out.extend_from_slice(&original[s..e]);
                prev_terminated = i + 1 < n_orig || st.last_terminated;
                last_was_insert = false;
            }
            FinalRow::Inserted(row) => {
                if row.0.keys().any(|k| !field_set.contains(k.as_str())) {
                    return Err(Error::bad_input("inserted row has a field that is not in the CSV header"));
                }
                if !prev_terminated {
                    out.extend_from_slice(nl);
                }
                for (j, f) in table.fields.iter().enumerate() {
                    if j > 0 {
                        out.push(b',');
                    }
                    let text = row.0.get(f.as_str()).map(csv_cell_text).unwrap_or_default();
                    write_csv_cell(&mut out, &text);
                }
                out.extend_from_slice(nl);
                prev_terminated = true;
                last_was_insert = true;
            }
        }
        Ok(())
    })?;
    // Keep the original's "no newline after the last record".
    if last_was_insert && !st.last_terminated {
        out.truncate(out.len() - nl.len());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn s(x: &str) -> Cell {
        Cell::Str(x.to_string())
    }

    fn row(pairs: &[(&str, Cell)]) -> Row {
        Row(pairs.iter().map(|(k, c)| (k.to_string(), c.clone())).collect())
    }

    fn canon_of_json(src: &str) -> String {
        let v: Value = serde_json::from_str(src).unwrap();
        String::from_utf8(canon_row(&row_from_json(&v).unwrap())).unwrap()
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    // AC1. JSON round trip, number text preserved
    #[test]
    fn ac1_json_round_trip_keeps_number_text() {
        let src = "[\n  {\n    \"id\": 1,\n    \"price\": 1.10,\n    \"w\": 512.0,\n    \"d\": -0.5,\n    \"big\": 100000000000000000000,\n    \"e\": 1e3,\n    \"s\": \"x\"\n  },\n  {\n    \"id\": 2,\n    \"price\": 2.00,\n    \"extra\": true\n  }\n]\n";
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        assert_eq!(t.fields, ["id", "price", "w", "d", "big", "e", "s", "extra"]);
        assert_eq!(t.rows[0].0["price"], Cell::Num { text: "1.10".into(), scale: 2 });
        assert_eq!(t.rows[0].0["w"], Cell::Num { text: "512.0".into(), scale: 1 });
        assert_eq!(t.rows[0].0["d"], Cell::Num { text: "-0.5".into(), scale: 1 });
        assert_eq!(t.rows[0].0["big"], Cell::Num { text: "100000000000000000000".into(), scale: 0 });
        assert!(matches!(t.rows[0].0["e"], Cell::Opaque(Value::Number(_))));
        assert_eq!(t.rows[1].0["w"], Cell::Missing);

        let out = serialize_with_inserts(src.as_bytes(), &t, &[]).unwrap();
        let t2 = parse_table(&out, Format::Json).unwrap();
        assert_eq!(t2.fields, t.fields);
        assert_eq!(t2.rows, t.rows);
        for needle in ["1.10", "512.0", "-0.5", "100000000000000000000", "2.00"] {
            assert!(contains(&out, needle.as_bytes()), "{needle}");
        }
        // Exponent normalization accepted (spec "숫자 텍스트 정책"): 1e3 -> 1e+3.
        assert!(contains(&out, b"\"e\": 1e+3"));
        assert!(!contains(&out, b"1e3"));
    }

    // AC2. Output style follows input style
    fn style_sample(indent: Option<&str>, nl: &str) -> String {
        let rows = [r#"{"a": 1, "b": "x", "c": [1, 2]}"#, r#"{"a": 2, "b": "y", "c": []}"#];
        let v: Vec<Value> = rows.iter().map(|r| serde_json::from_str(r).unwrap()).collect();
        let body = match indent {
            None => serde_json::to_string(&v).unwrap(),
            Some(ind) => {
                let mut buf = Vec::new();
                let fmt = serde_json::ser::PrettyFormatter::with_indent(ind.as_bytes());
                let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
                serde::Serialize::serialize(&v, &mut ser).unwrap();
                String::from_utf8(buf).unwrap()
            }
        };
        body.replace('\n', nl)
    }

    #[test]
    fn ac2_style_reproduced() {
        for (name, indent) in [("2 spaces", Some("  ")), ("4 spaces", Some("    ")), ("tab", Some("\t")), ("compact", None)] {
            for nl in ["\n", "\r\n"] {
                for trailing in [false, true] {
                    let mut src = style_sample(indent, nl);
                    if trailing {
                        src.push_str(nl);
                    }
                    let t = parse_table(src.as_bytes(), Format::Json).unwrap();
                    let out = String::from_utf8(serialize_with_inserts(src.as_bytes(), &t, &[]).unwrap()).unwrap();
                    let first3 = |x: &str| x.split('\n').take(3).map(str::to_string).collect::<Vec<_>>();
                    assert_eq!(first3(&out), first3(&src), "{name}");
                    // These inputs are already in the writer's layout, so the whole output matches.
                    assert_eq!(out, src, "{name} nl={nl:?} trailing={trailing}");
                }
            }
        }
        // BOM kept.
        let src = format!("\u{feff}{}", style_sample(Some("  "), "\n"));
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        let out = serialize_with_inserts(src.as_bytes(), &t, &[]).unwrap();
        assert_eq!(out, src.as_bytes());
    }

    #[test]
    fn json_inserts_follow_field_order_and_style() {
        let src = style_sample(Some("  "), "\n");
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        let ins = row(&[
            ("c", Cell::Opaque(serde_json::from_str("[3]").unwrap())),
            ("a", Cell::Num { text: "9.50".into(), scale: 2 }),
            ("b", Cell::Missing),
        ]);
        let out = serialize_with_inserts(src.as_bytes(), &t, &[(3, ins.clone()), (1, ins)]).unwrap();
        let out = String::from_utf8(out).unwrap();
        let t2 = parse_table(out.as_bytes(), Format::Json).unwrap();
        assert_eq!(t2.rows.len(), 4);
        assert_eq!(t2.rows[0], t.rows[0]);
        assert_eq!(t2.rows[2], t.rows[1]);
        assert!(out.contains("  {\n    \"a\": 9.50,\n    \"c\": [\n      3\n    ]\n  }"));
        // positions and original are validated
        let e = serialize_with_inserts(src.as_bytes(), &t, &[(5, Row::default())]).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
        let e = serialize_with_inserts(src.as_bytes(), &t, &[(0, Row::default()), (0, Row::default())]).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
        let e = serialize_with_inserts(b"[]", &t, &[]).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
        let bad = row(&[("a", Cell::Num { text: "1,5".into(), scale: 0 })]);
        let e = serialize_with_inserts(src.as_bytes(), &t, &[(0, bad)]).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
    }

    // AC3. CSV parse + splice
    #[test]
    fn ac3_csv_quotes_and_splice_crlf() {
        let src = "id,name,note\r\n1,\"Kim, J\",\"line1\r\nline2\"\r\n2,\"say \"\"hi\"\"\",plain\r\n3,x,y\r\n";
        let t = parse_table(src.as_bytes(), Format::Csv).unwrap();
        assert_eq!(t.fields, ["id", "name", "note"]);
        assert_eq!(t.rows.len(), 3);
        assert_eq!(t.rows[0].0["name"], s("Kim, J"));
        assert_eq!(t.rows[0].0["note"], s("line1\r\nline2"));
        assert_eq!(t.rows[1].0["name"], s("say \"hi\""));

        let a = row(&[("id", s("90")), ("name", s("Lee, K")), ("note", s("n"))]);
        let b = row(&[("id", s("91")), ("name", s(" pad")), ("note", s("q\"x"))]);
        let out = serialize_with_inserts(src.as_bytes(), &t, &[(1, a.clone()), (4, b.clone())]).unwrap();
        for rec in ["id,name,note\r\n", "1,\"Kim, J\",\"line1\r\nline2\"\r\n", "2,\"say \"\"hi\"\"\",plain\r\n", "3,x,y\r\n"] {
            assert!(contains(&out, rec.as_bytes()), "{rec:?}");
        }
        let expect = "id,name,note\r\n1,\"Kim, J\",\"line1\r\nline2\"\r\n90,\"Lee, K\",n\r\n2,\"say \"\"hi\"\"\",plain\r\n3,x,y\r\n91,\" pad\",\"q\"\"x\"\r\n";
        assert_eq!(String::from_utf8(out.clone()).unwrap(), expect);
        let t2 = parse_table(&out, Format::Csv).unwrap();
        assert_eq!(t2.rows[1], a);
        assert_eq!(t2.rows[4], b);
    }

    #[test]
    fn csv_lf_no_final_newline_and_bom() {
        let src = "\u{feff}a,b\n1,2\n3,4";
        let t = parse_table(src.as_bytes(), Format::Csv).unwrap();
        assert_eq!(t.fields, ["a", "b"]);
        let r = row(&[("a", s("x")), ("b", s("y"))]);
        let out = serialize_with_inserts(src.as_bytes(), &t, &[(2, r.clone())]).unwrap();
        assert_eq!(out, "\u{feff}a,b\n1,2\n3,4\nx,y".as_bytes());
        let out = serialize_with_inserts(src.as_bytes(), &t, &[(0, r.clone())]).unwrap();
        assert_eq!(out, "\u{feff}a,b\nx,y\n1,2\n3,4".as_bytes());
        // header only, no newline
        let t = parse_table(b"a,b", Format::Csv).unwrap();
        let out = serialize_with_inserts(b"a,b", &t, &[(0, r)]).unwrap();
        assert_eq!(out, b"a,b\nx,y");
        // zero inserts: identical bytes
        let t = parse_table(src.as_bytes(), Format::Csv).unwrap();
        assert_eq!(serialize_with_inserts(src.as_bytes(), &t, &[]).unwrap(), src.as_bytes());
        // dominant newline: 2 LF vs 1 CRLF -> LF
        let mixed = "a\r\n1\n2\n";
        let t = parse_table(mixed.as_bytes(), Format::Csv).unwrap();
        let out = serialize_with_inserts(mixed.as_bytes(), &t, &[(2, row(&[("a", s("z"))]))]).unwrap();
        assert_eq!(out, b"a\r\n1\n2\nz\n");
        // inserted field outside the header is rejected
        let e = serialize_with_inserts(mixed.as_bytes(), &t, &[(0, row(&[("q", s("z"))]))]).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
    }

    // AC4. Column count mismatch and other CSV errors
    #[test]
    fn ac4_csv_bad_input() {
        for bad in ["a,b\n1,2\n3\n", "a,b\n1,2,3\n", "a,b\n\"Z,1\n", "a,b\n\"Z\"Z,1\n", "a,a\n1,2\n", "", "\u{feff}"] {
            let e = parse_table(bad.as_bytes(), Format::Csv).unwrap_err();
            assert_eq!(e.code, ErrorCode::BadInput, "{bad:?}");
            assert!(!e.message.contains('Z'), "message must not quote data: {}", e.message);
            println!("ac4: {bad:?} -> {}", e.message);
        }
        let e = parse_table(b"a,b\n\xff,1\n", Format::Csv).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadInput);
    }

    // AC5. canon_row vectors
    #[test]
    fn ac5_canon_row_vectors() {
        assert_eq!(canon_of_json(r#"{"b":"x","a":1.50,"c":null}"#), r#"{"a":1.50,"b":"x","c":null}"#);
        assert_eq!(canon_of_json(r#"{"가":1,"z":2,"A":true,"나":false}"#), r#"{"A":true,"z":2,"가":1,"나":false}"#);
        assert!("z".as_bytes() < "가".as_bytes());
        assert_eq!(
            canon_of_json(r#"{"o":{"y":[1,{"b":2,"a":1.0}],"x":"q"},"e":[],"f":{}}"#),
            r#"{"e":[],"f":{},"o":{"x":"q","y":[1,{"a":1.0,"b":2}]}}"#
        );
        assert_eq!(canon_of_json(r#"{"n":1E3,"m":-0.0}"#), r#"{"m":-0.0,"n":1e+3}"#);

        let r = row(&[("k", s("a\"b\\c\u{1}\u{1f}\n\r\t\u{8}\u{c}\u{7f}한/"))]);
        assert_eq!(
            String::from_utf8(canon_row(&r)).unwrap(),
            "{\"k\":\"a\\\"b\\\\c\\u0001\\u001f\\n\\r\\t\\b\\f\u{7f}한/\"}"
        );
        // Missing omitted; Bool/Null/Num text as is
        let r = row(&[
            ("z", Cell::Missing),
            ("b", Cell::Bool(true)),
            ("a", Cell::Num { text: "512.00".into(), scale: 2 }),
            ("c", Cell::Null),
        ]);
        assert_eq!(canon_row(&r), br#"{"a":512.00,"b":true,"c":null}"#);
        // CSV rows are all strings
        let t = parse_table(b"b,a\n1.50,x\n", Format::Csv).unwrap();
        assert_eq!(canon_row(&t.rows[0]), br#"{"a":"x","b":"1.50"}"#);
        // JSON-parsed row gives the same bytes as row_from_json
        let t = parse_table(br#"[{"b":"x","a":1.50,"c":null}]"#, Format::Json).unwrap();
        assert_eq!(canon_row(&t.rows[0]), br#"{"a":1.50,"b":"x","c":null}"#);
    }

    #[test]
    fn nested_object_key_order_preserved_in_output() {
        let src = br#"[{"id":1,"o":{"z":1,"a":2}}]"#;
        let t = parse_table(src, Format::Json).unwrap();
        let out = serialize_with_inserts(src, &t, &[]).unwrap();
        assert!(contains(&out, br#""z":1,"a":2"#), "{}", String::from_utf8_lossy(&out));
        assert_eq!(out, src);
        assert_eq!(canon_row(&t.rows[0]), br#"{"id":1,"o":{"a":2,"z":1}}"#);
    }

    #[test]
    fn jstr_matches_serde_json_default_escape() {
        let mut all = String::new();
        for c in 0u32..0x80 {
            all.push(char::from_u32(c).unwrap());
        }
        all.push_str("가\u{2028}\u{10ffff}");
        let mut out = Vec::new();
        write_jstr(&mut out, &all);
        assert_eq!(out, serde_json::to_vec(&all).unwrap());
    }

    #[test]
    fn row_from_json_cells() {
        let v: Value = serde_json::from_str(r#"{"s":"x","n":12.340,"e":2E-3,"b":false,"z":null,"o":[1]}"#).unwrap();
        let r = row_from_json(&v).unwrap();
        assert_eq!(r.0["s"], s("x"));
        assert_eq!(r.0["n"], Cell::Num { text: "12.340".into(), scale: 3 });
        assert!(matches!(r.0["e"], Cell::Opaque(_)));
        assert_eq!(r.0["b"], Cell::Bool(false));
        assert_eq!(r.0["z"], Cell::Null);
        assert!(matches!(r.0["o"], Cell::Opaque(_)));
        assert_eq!(row_from_json(&Value::Null).unwrap_err().code, ErrorCode::BadInput);
    }

    // AC6. detect_format
    #[test]
    fn ac6_detect_format() {
        assert_eq!(detect_format(br#"[{"a":1}]"#), Format::Json);
        assert_eq!(detect_format(b"\xEF\xBB\xBF[{\"a\":1}]"), Format::Json);
        assert_eq!(detect_format(b"{}"), Format::Json);
        assert_eq!(parse_table(b"{}", Format::Json).unwrap_err().code, ErrorCode::BadInput);
        assert_eq!(parse_table(b"[1,2]", Format::Json).unwrap_err().code, ErrorCode::BadInput);
        assert_eq!(parse_table(b"[{\"a\":1},", Format::Json).unwrap_err().code, ErrorCode::BadInput);
        assert_eq!(detect_format(b"a,b\n1,2\n"), Format::Csv);
        assert_eq!(detect_format("이름,주소\r\n홍,하남\r\n".as_bytes()), Format::Csv);
        let t = parse_table(b"[]", Format::Json).unwrap();
        assert!(t.fields.is_empty() && t.rows.is_empty());
        assert_eq!(serialize_with_inserts(b"[]", &t, &[]).unwrap(), b"[]");
    }

    // AC7. 50k rows JSON (~3.6 MB) parse + serialize
    #[test]
    fn ac7_perf_50k_rows() {
        let mut src = String::from("[\n");
        for i in 0..50_000u32 {
            if i > 0 {
                src.push_str(",\n");
            }
            src.push_str(&format!(
                "  {{\n    \"id\": {i},\n    \"addr\": \"미사동 {}-{}\",\n    \"p\": {}.{:02}\n  }}",
                i % 997,
                i % 13,
                1000 + i % 5000,
                i % 100,
            ));
        }
        src.push_str("\n]\n");
        let start = std::time::Instant::now();
        let t = parse_table(src.as_bytes(), Format::Json).unwrap();
        let parsed = start.elapsed();
        let out = serialize_with_inserts(src.as_bytes(), &t, &[]).unwrap();
        let total = start.elapsed();
        println!(
            "ac7: input {} bytes, {} rows, parse {:?}, parse+serialize {:?}",
            src.len(),
            t.rows.len(),
            parsed,
            total
        );
        assert_eq!(out, src.as_bytes());
        assert!(src.len() > 3_500_000 && src.len() < 3_700_000, "size {}", src.len());
        if !cfg!(debug_assertions) {
            assert!(total.as_millis() < 500, "took {total:?}");
        }
    }

    // AC8. Random bytes: no panic
    #[test]
    fn ac8_random_bytes_no_panic() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (x >> 33) as u32
        };
        let alphabet = b"[]{},:\"\\\r\n \t0123456789.-+eEabc";
        let seeds: [&[u8]; 2] = [
            b"[\n  {\"a\": 1.50, \"b\": \"x\"},\n  {\"c\": [1, {\"d\": null}], \"a\": -0}\n]\n",
            b"a,b,c\r\n1,\"x,y\",\"q\"\"\"\r\n2,,\r\n",
        ];
        let (mut json_ok, mut csv_ok) = (0, 0);
        for case in 0..1000 {
            let bytes: Vec<u8> = if case % 3 == 2 {
                // mutate a valid seed: overwrite a few bytes, maybe truncate
                let mut b = seeds[(case / 3) % 2].to_vec();
                for _ in 0..(next() % 3) {
                    let at = (next() as usize) % b.len();
                    b[at] = alphabet[(next() as usize) % alphabet.len()];
                }
                if next() % 4 == 0 {
                    b.truncate((next() as usize) % b.len());
                }
                b
            } else {
                let len = (next() % 200) as usize;
                (0..len)
                    .map(|_| if case % 3 == 0 { next() as u8 } else { alphabet[(next() as usize) % alphabet.len()] })
                    .collect()
            };
            let _ = detect_format(&bytes);
            for f in [Format::Json, Format::Csv] {
                if let Ok(t) = parse_table(&bytes, f) {
                    match f {
                        Format::Json => json_ok += 1,
                        Format::Csv => csv_ok += 1,
                    }
                    for r in &t.rows {
                        let _ = canon_row(r);
                    }
                    let _ = serialize_with_inserts(&bytes, &t, &[]);
                    let ins: Row = Row(t.fields.iter().map(|k| (k.clone(), Cell::Str("v,\"".into()))).collect());
                    let _ = serialize_with_inserts(&bytes, &t, &[(t.rows.len(), ins)]);
                }
            }
        }
        println!("ac8: 1000 inputs, parsed ok: json {json_ok}, csv {csv_ok}");
    }

    #[test]
    fn json_number_check() {
        for ok in ["0", "-0", "1.50", "512", "1e+3", "2.5E-1"] {
            assert!(is_json_number(ok), "{ok}");
        }
        for bad in ["", "-", "01", "1.", ".5", "1e", "abc", "1 "] {
            assert!(!is_json_number(bad), "{bad}");
        }
    }
}
