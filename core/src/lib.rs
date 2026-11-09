//! noreacore: platform-agnostic NoREA core.
//!
//! Pure logic only. No RNG, network, file I/O, key storage or clock
//! (CONTEXT.md invariant 2). Public API: Fable_5_1/docs/CORE-API.md.
//! Implemented: error, table (WP-01); norm, shape, canary (WP-02);
//! merkle, blob, sign, evidence (WP-03, vector tests/vectors/norea-evidence-v1.json).
//! Other modules are empty until their WP.

pub mod anchor;
pub mod blob;
pub mod canary;
pub mod check;
pub mod disclose;
pub mod error;
pub mod evidence;
pub mod merkle;
pub mod norm;
pub mod shape;
pub mod sign;
pub mod table;

pub use error::{Error, ErrorCode};

/// 32-byte key (K, seed, K_d, K_blob). CORE-API common section.
pub type Key32 = [u8; 32];

#[cfg(test)]
mod tests {
    /// WP-00 experiment for WP-01: with `arbitrary_precision`, does a parsed
    /// `serde_json::Value::Number` keep the original number text?
    #[test]
    fn arbitrary_precision_preserves_number_text() {
        let src = r#"[1, 1.0, 1.50, 330.5, -0.0, 1e3, 1E+3, 12345678901234567890123, 0.1000000000000000055511151231257827, -0, 1e-3, 1E-3, 1e03, 1.5E10, 0e0, 2.50e+2]"#;
        let v: serde_json::Value = serde_json::from_str(src).unwrap();
        let texts: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_number().unwrap().to_string())
            .collect();
        for t in &texts {
            println!("number text: {t}");
        }
        let out = serde_json::to_string(&v).unwrap();
        println!("re-serialized: {out}");
        assert_eq!(texts[2], "1.50");
        assert_eq!(texts[7], "12345678901234567890123");
        // Exponent is NOT preserved byte for byte: serde_json normalizes it (see WP-00 report).
        assert_eq!(texts[5], "1e+3");
        assert_eq!(texts[6], "1e+3");
    }
}
