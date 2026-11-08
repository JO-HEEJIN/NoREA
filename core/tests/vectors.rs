//! Frozen-format guard + cross-platform test vectors.
//!
//! Skeleton. WP-03 fills this in and freezes tests/vectors/norea-evidence-v1.json.
//! If the frozen test fails later, the evidence format changed: stop and report,
//! do not "fix" the vector (CONTEXT.md invariant 1, ADR-0008).
//!
//! Regenerate (intentional, approved format change only):
//!   NOREA_WRITE_VECTORS=1 cargo test -p noreacore --test vectors
