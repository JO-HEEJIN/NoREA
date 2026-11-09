//! Merkle tree over canary leaves: leaf hash, root, audit path.
//!
//! Spec: Fable_5_1/docs/protocol/evidence-v1.md §7.2. Structure is RFC 9162
//! (Certificate Transparency Version 2.0, Laurie, Messeri, Stradling) §2.1:
//!
//! ```text
//! leaf(d)     = SHA-256(0x00 || d),  d_i = u32be(i) || utf8(canon(canary_i))
//! MTH([d])    = leaf(d)
//! MTH(D[0:n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest power of two < n
//! ```

use sha2::{Digest, Sha256};

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly smaller than `n` (n >= 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// `SHA-256(0x00 || u32be(index) || canon)`.
pub fn leaf_hash(index: u32, canon: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(index.to_be_bytes());
    h.update(canon);
    h.finalize().into()
}

/// MTH over already-hashed leaves. Panics if `leaves` is empty (v1 requires
/// canary_count >= 1; callers check that first).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "merkle_root needs at least one leaf");
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len());
    node(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
}

/// RFC 9162 §2.1.3.1 `PATH(m, D[n])`, leaf-to-root order:
///
/// ```text
/// PATH(0, {d[0]}) = {}
/// PATH(m, D_n) = PATH(m, D[0:k]) : MTH(D[k:n])      for m < k
/// PATH(m, D_n) = PATH(m - k, D[k:n]) : MTH(D[0:k])  for m >= k
/// ```
///
/// Returns an empty path when `index >= leaves.len()`.
pub fn audit_path(index: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if index < leaves.len() {
        path_into(index, leaves, &mut out);
    }
    out
}

fn path_into(m: usize, d: &[[u8; 32]], out: &mut Vec<[u8; 32]>) {
    if d.len() == 1 {
        return;
    }
    let k = split(d.len());
    if m < k {
        path_into(m, &d[..k], out);
        out.push(merkle_root(&d[k..]));
    } else {
        path_into(m - k, &d[k..], out);
        out.push(merkle_root(&d[..k]));
    }
}

/// RFC 9162 §2.1.3.2 "Verifying an Inclusion Proof", quoted:
///
/// ```text
/// 1. If leaf_index is greater than or equal to tree_size, then fail the proof verification.
/// 2. Set fn to leaf_index and sn to tree_size - 1.
/// 3. Set r to hash.
/// 4. For each value p in the inclusion_path array:
///    a. If sn is 0, then stop the iteration and fail the proof verification.
///    b. If LSB(fn) is set, or if fn is equal to sn, then:
///       i.  Set r to HASH(0x01 || p || r).
///       ii. If LSB(fn) is not set, then right-shift both fn and sn equally
///           until either LSB(fn) is set or fn is 0.
///       Otherwise: i. Set r to HASH(0x01 || r || p).
///    c. Finally, right-shift both fn and sn one time.
/// 5. Compare sn to 0. Compare r against the root_hash. If sn is equal to 0
///    and r and the root_hash are equal, then the log has proven the inclusion of hash.
/// ```
///
/// The proof binds to the count only through the path shape: a different
/// count with the same shape verifies too. Callers must pass the signed
/// `canary_count`.
pub fn verify_audit_path(index: u32, count: u32, leaf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    // 1.
    if index >= count {
        return false;
    }
    // 2., 3.
    let mut fn_ = index;
    let mut sn = count - 1;
    let mut r = *leaf;
    // 4.
    for p in path {
        // a.
        if sn == 0 {
            return false;
        }
        // b.
        if fn_ & 1 == 1 || fn_ == sn {
            r = node(p, &r);
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        // c.
        fn_ >>= 1;
        sn >>= 1;
    }
    // 5.
    sn == 0 && r == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(i as u32, format!("{{\"i\":{i}}}").as_bytes())).collect()
    }

    /// AC1: n = 1..9, every index round trips; tampering path / index / count fails.
    #[test]
    fn ac1_audit_path_round_trip_and_tamper() {
        let mut checked = 0;
        let mut same_shape_accepted = 0;
        for n in 1..=9usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for i in 0..n {
                let path = audit_path(i, &l);
                assert!(verify_audit_path(i as u32, n as u32, &l[i], &path, &root), "n={n} i={i}");
                checked += 1;
                for j in 0..path.len() {
                    let mut bad = path.clone();
                    bad[j][0] ^= 1;
                    assert!(!verify_audit_path(i as u32, n as u32, &l[i], &bad, &root), "path n={n} i={i} j={j}");
                }
                for other in 0..=n as u32 {
                    if other != i as u32 {
                        assert!(!verify_audit_path(other, n as u32, &l[i], &path, &root), "index n={n} i={i} other={other}");
                    }
                }
                // Count tampering. RFC 9162 §2.1.3.2 binds the proof to (root,
                // tree_size) only through the path shape: a different count with
                // the same left/right shape still verifies. That is why
                // canary_count is in the signed payload and verifiers must use
                // it. Here: every count whose path shape differs is rejected, and
                // the same-shape cases are counted (64, see WP-03 report).
                for c in 0..=10u32 {
                    if c == n as u32 {
                        continue;
                    }
                    let ok = verify_audit_path(i as u32, c, &l[i], &path, &root);
                    let shape_differs = c as usize <= i || {
                        let lc = leaves(c as usize);
                        audit_path(i, &lc).len() != path.len()
                    };
                    if shape_differs {
                        assert!(!ok, "count n={n} i={i} c={c}");
                    }
                    if ok {
                        same_shape_accepted += 1;
                    }
                }
                let mut long = path.clone();
                long.push([0u8; 32]);
                assert!(!verify_audit_path(i as u32, n as u32, &l[i], &long, &root), "long n={n} i={i}");
                if !path.is_empty() {
                    assert!(!verify_audit_path(i as u32, n as u32, &l[i], &path[..path.len() - 1], &root));
                }
                let mut wrong_leaf = l[i];
                wrong_leaf[31] ^= 1;
                assert!(!verify_audit_path(i as u32, n as u32, &wrong_leaf, &path, &root));
            }
        }
        assert_eq!(checked, 45);
        // Independent enumeration of the RFC algorithm (WP-03 report) gives 64
        // same-shape (n, i, c) cases for n = 1..9, c = 1..10, e.g. (3, 0, 4).
        assert_eq!(same_shape_accepted, 64);
        let l3 = leaves(3);
        assert!(verify_audit_path(0, 4, &l3[0], &audit_path(0, &l3), &merkle_root(&l3)));
    }

    /// AC2: known values from the formulas (RFC 9162 has no public vectors).
    #[test]
    fn ac2_known_values() {
        let l = leaves(3);
        assert_eq!(merkle_root(&l[..1]), l[0]);
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(l[0]);
        h.update(l[1]);
        let two: [u8; 32] = h.finalize().into();
        assert_eq!(merkle_root(&l[..2]), two);
        // n = 3: k = 2 -> H(0x01 || H(0x01||l0||l1) || l2)
        assert_eq!(merkle_root(&l), node(&two, &l[2]));
        // leaf = SHA-256(0x00 || u32be(i) || canon)
        let mut h = Sha256::new();
        h.update([0x00, 0, 0, 0, 7]);
        h.update(b"{}");
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(leaf_hash(7, b"{}"), want);
        assert!(audit_path(0, &l[..1]).is_empty());
        assert!(audit_path(5, &l).is_empty());
    }
}
