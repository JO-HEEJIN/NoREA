//! Encrypted canary blob (AEAD) stored inside evidence.
//!
//! Spec: Fable_5_1/docs/protocol/evidence-v1.md §2 (K_blob), §7.3:
//!
//! ```text
//! K_blob     = HKDF-SHA256(salt=utf8("norea/canary-blob/v1"), ikm=K_d, info=marked_sha256_raw, L=32)
//! plaintext  = utf8("{\"rows\":[" + join(",", canon(canary_i)) + "],\"shape\":" + shape_json + "}")
//! AAD        = utf8("norea.evidence.v1\n" + dataset_id + "\n" + hex(marked_sha256))
//! nonce      = 12 x 0x00   (K_blob is unique per marked_sha256)
//! blob       = ct || tag = ChaCha20-Poly1305(K_blob, nonce, AAD, plaintext)   RFC 8439
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorCode};
use crate::evidence::{hex, EVIDENCE_SCHEMA};
use crate::table::{canon_row, row_from_json, Row};
use crate::Key32;

const BLOB_SALT: &[u8] = b"norea/canary-blob/v1";

/// K_blob (evidence-v1 §2). Wiped when the returned value drops.
pub fn derive_blob_key(k_d: &Key32, marked_sha256: &[u8; 32]) -> Zeroizing<Key32> {
    let hk = Hkdf::<Sha256>::new(Some(BLOB_SALT), k_d);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(marked_sha256, okm.as_mut()).expect("32 bytes is a valid HKDF-SHA256 length");
    okm
}

fn aad(dataset_id: &str, marked_sha256: &[u8; 32]) -> Vec<u8> {
    format!("{EVIDENCE_SCHEMA}\n{dataset_id}\n{}", hex(marked_sha256)).into_bytes()
}

fn cipher(k_d: &Key32, marked_sha256: &[u8; 32]) -> ChaCha20Poly1305 {
    let k_blob = derive_blob_key(k_d, marked_sha256);
    ChaCha20Poly1305::new_from_slice(k_blob.as_ref()).expect("K_blob is 32 bytes")
}

/// Plaintext bytes of §7.3.
fn plaintext(canaries: &[Row], shape_summary: &Value) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::new());
    p.extend_from_slice(b"{\"rows\":[");
    for (i, r) in canaries.iter().enumerate() {
        if i > 0 {
            p.push(b',');
        }
        p.extend_from_slice(&canon_row(r));
    }
    p.extend_from_slice(b"],\"shape\":");
    p.extend_from_slice(serde_json::to_string(shape_summary).expect("Value serializes").as_bytes());
    p.push(b'}');
    p
}

/// Encrypt the canary rows and shape summary. Returns `ct || tag`.
pub fn seal_blob(
    k_d: &Key32,
    dataset_id: &str,
    marked_sha256: &[u8; 32],
    canaries: &[Row],
    shape_summary: &Value,
) -> Vec<u8> {
    let pt = plaintext(canaries, shape_summary);
    let aad = aad(dataset_id, marked_sha256);
    cipher(k_d, marked_sha256)
        .encrypt(&Nonce::from([0u8; 12]), Payload { msg: &pt, aad: &aad })
        .expect("ChaCha20-Poly1305 encrypt only fails on > 256 GiB input")
}

/// Decrypt and parse a blob. Any failure (wrong key, AAD, tampering, bad
/// plaintext structure) is `BadBlob`.
pub fn open_blob(
    k_d: &Key32,
    dataset_id: &str,
    marked_sha256: &[u8; 32],
    blob: &[u8],
) -> Result<(Vec<Row>, Value), Error> {
    let bad = |m: &str| Error::new(ErrorCode::BadBlob, m);
    let aad = aad(dataset_id, marked_sha256);
    let pt = Zeroizing::new(
        cipher(k_d, marked_sha256)
            .decrypt(&Nonce::from([0u8; 12]), Payload { msg: blob, aad: &aad })
            .map_err(|_| bad("canary blob authentication failed"))?,
    );
    let v: Value = serde_json::from_slice(&pt).map_err(|_| bad("canary blob plaintext is not JSON"))?;
    let obj = v.as_object().ok_or_else(|| bad("canary blob plaintext is not an object"))?;
    let rows = obj
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("canary blob has no rows array"))?
        .iter()
        .map(|r| row_from_json(r).map_err(|_| bad("canary blob row is not an object")))
        .collect::<Result<Vec<Row>, Error>>()?;
    let shape = obj.get("shape").cloned().ok_or_else(|| bad("canary blob has no shape"))?;
    Ok((rows, shape))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::{mark, MarkOptions};
    use crate::merkle::{leaf_hash, merkle_root};
    use crate::table::Format;
    use sha2::Digest;

    const K_D: Key32 = [7u8; 32];
    const INPUT: &str = r#"[{"id":"P-013","addr":"하남시 미사동 1-1","area_m2":330.5,"x":null,"n":{"b":1e3,"a":[1.50]}},{"id":"P-027","addr":"하남시 미사동 2-7","area_m2":512.0},{"id":"P-102","addr":"하남시 망월동 15-3","area_m2":98.25},{"id":"P-245","addr":"광주시 역동 7-1","area_m2":1200.0},{"id":"P-318","addr":"하남시 미사동 3-2","area_m2":450.75},{"id":"P-406","addr":"하남시 망월동 8-9","area_m2":77.0}]"#;

    fn marked() -> (crate::canary::MarkOutput, [u8; 32]) {
        let out = mark(INPUT.as_bytes(), Format::Json, &K_D, &MarkOptions { n: 5, marker_fields: None, exclusions: vec![] })
            .unwrap();
        let h: [u8; 32] = Sha256::digest(&out.marked).into();
        (out, h)
    }

    /// AC3: round trip, AAD change, ciphertext bit flip, Merkle root recompute.
    #[test]
    fn ac3_seal_open() {
        let (out, h) = marked();
        let blob = seal_blob(&K_D, "ds/1", &h, &out.canaries, &out.shape_summary);
        let (rows, shape) = open_blob(&K_D, "ds/1", &h, &blob).unwrap();
        assert_eq!(shape, out.shape_summary);
        assert_eq!(rows.len(), out.canaries.len());
        let canon_in: Vec<Vec<u8>> = out.canaries.iter().map(canon_row).collect();
        let canon_out: Vec<Vec<u8>> = rows.iter().map(canon_row).collect();
        assert_eq!(canon_in, canon_out);
        let leaves = |c: &[Vec<u8>]| c.iter().enumerate().map(|(i, b)| leaf_hash(i as u32, b)).collect::<Vec<_>>();
        assert_eq!(merkle_root(&leaves(&canon_in)), merkle_root(&leaves(&canon_out)));

        assert_eq!(open_blob(&K_D, "ds/2", &h, &blob).unwrap_err().code, ErrorCode::BadBlob);
        let mut other_h = h;
        other_h[0] ^= 1;
        assert_eq!(open_blob(&K_D, "ds/1", &other_h, &blob).unwrap_err().code, ErrorCode::BadBlob);
        assert_eq!(open_blob(&[8u8; 32], "ds/1", &h, &blob).unwrap_err().code, ErrorCode::BadBlob);
        for pos in [0, blob.len() / 2, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[pos] ^= 0x01;
            assert_eq!(open_blob(&K_D, "ds/1", &h, &bad).unwrap_err().code, ErrorCode::BadBlob);
        }
        assert_eq!(open_blob(&K_D, "ds/1", &h, &blob[..10]).unwrap_err().code, ErrorCode::BadBlob);
        // Deterministic.
        assert_eq!(blob, seal_blob(&K_D, "ds/1", &h, &out.canaries, &out.shape_summary));
    }

    /// Opaque cells (exponent numbers, nested objects, keys out of order)
    /// survive the blob with identical canon bytes.
    #[test]
    fn opaque_canon_survives_blob() {
        let v: Value = serde_json::from_str(r#"{"z":{"b":1E+3,"a":[1.50,"\u0001"]},"a":-0.0,"m":null,"t":true}"#).unwrap();
        let row = row_from_json(&v).unwrap();
        let blob = seal_blob(&K_D, "d", &[1u8; 32], std::slice::from_ref(&row), &Value::Null);
        let (rows, _) = open_blob(&K_D, "d", &[1u8; 32], &blob).unwrap();
        assert_eq!(canon_row(&rows[0]), canon_row(&row));
    }
}
