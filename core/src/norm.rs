//! Value normalization for matching and canary collision avoidance.
//!
//! Spec: Fable_5_1/docs/protocol/canary-record-shape-v1.md §7.1, CORE-API §1 norm.rs.
//! Used by `canary` (`taken(f)`, §5.3) and by `check` (WP-04) so both compare
//! values the same way. Not used by `canon_row` (evidence-v1 §7.1 does not
//! normalize).

use unicode_normalization::UnicodeNormalization;

/// Whitespace whose runs collapse to one U+0020 (shape-v1 §7.1).
fn is_run_space(c: char) -> bool {
    matches!(c, '\u{0009}' | '\u{0020}' | '\u{00A0}' | '\u{3000}')
}

/// shape-v1 §7.1 string rule: Unicode NFC, trim both ends, collapse internal
/// whitespace runs (U+0009, U+0020, U+00A0, U+3000) to one U+0020, full-width
/// ASCII (U+FF01..U+FF5E) to half-width. Case is kept.
///
/// "Trim" removes Unicode White_Space (`char::is_whitespace`) at both ends,
/// which includes the four run characters.
pub fn normalize_text(s: &str) -> String {
    let nfc: String = s.nfc().collect();
    let trimmed = nfc.trim();
    let mut out = String::with_capacity(trimmed.len());
    let mut in_run = false;
    for c in trimmed.chars() {
        if is_run_space(c) {
            if !in_run {
                out.push(' ');
            }
            in_run = true;
            continue;
        }
        in_run = false;
        let c = match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            _ => c,
        };
        out.push(c);
    }
    out
}

/// shape-v1 §7.1 number rule: remove thousands separators `,` and whitespace,
/// then parse as a decimal `[+-]?digits(.digits)?`. Returns the canonical text
/// `-?digits(.digits)?`: leading zeros of the integer part removed (one `0`
/// kept), `+` dropped, fraction digits kept as written (scale is preserved,
/// `"1,200.00"` -> `"1200.00"`), and negative zero written without `-`.
/// No exponent, no `inf`/`nan`. Returns `None` if the text is not such a number.
pub fn normalize_number(s: &str) -> Option<String> {
    let cleaned: String = s.chars().filter(|&c| c != ',' && !c.is_whitespace()).collect();
    let (neg, body) = match cleaned.as_bytes().first()? {
        b'-' => (true, &cleaned[1..]),
        b'+' => (false, &cleaned[1..]),
        _ => (false, cleaned.as_str()),
    };
    let (int, frac) = match body.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (body, None),
    };
    if int.is_empty() || !int.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(f) = frac {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    let int = int.trim_start_matches('0');
    let int = if int.is_empty() { "0" } else { int };
    let zero = int == "0" && frac.is_none_or(|f| f.bytes().all(|b| b == b'0'));
    let mut out = String::with_capacity(body.len() + 1);
    if neg && !zero {
        out.push('-');
    }
    out.push_str(int);
    if let Some(f) = frac {
        out.push('.');
        out.push_str(f);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_nfd_to_nfc() {
        let nfd = "\u{1112}\u{1161}\u{11AB}\u{1102}\u{1161}\u{11B7}"; // 한남 in conjoining jamo
        assert_eq!(normalize_text(nfd), "한남");
        assert_eq!(normalize_text("e\u{0301}"), "\u{00E9}");
    }

    #[test]
    fn text_fullwidth_and_spaces() {
        assert_eq!(normalize_text("ＡＢＣ１２３－４"), "ABC123-4");
        assert_eq!(normalize_text("\u{FF01}\u{FF5E}"), "!~");
        assert_eq!(normalize_text("  하남시\t\u{00A0} 미사동\u{3000}\u{3000}592-1 \n"), "하남시 미사동 592-1");
        assert_eq!(normalize_text("a  b"), "a b");
        assert_eq!(normalize_text("Abc"), "Abc", "case is kept");
        assert_eq!(normalize_text(""), "");
        assert_eq!(normalize_text(" \u{3000} "), "");
    }

    #[test]
    fn numbers() {
        assert_eq!(normalize_number("1,200.00").as_deref(), Some("1200.00"));
        assert_eq!(normalize_number("1,234,567").as_deref(), Some("1234567"));
        assert_eq!(normalize_number(" 512.5 ").as_deref(), Some("512.5"));
        assert_eq!(normalize_number("-0.50").as_deref(), Some("-0.50"));
        assert_eq!(normalize_number("+7").as_deref(), Some("7"));
        assert_eq!(normalize_number("007").as_deref(), Some("7"));
        assert_eq!(normalize_number("-0.00").as_deref(), Some("0.00"));
        assert_eq!(normalize_number("1 200").as_deref(), Some("1200"));
        for bad in ["", "-", "1.", ".5", "1e3", "abc", "1.2.3", "inf", "NaN", "1-2"] {
            assert_eq!(normalize_number(bad), None, "{bad}");
        }
    }
}
