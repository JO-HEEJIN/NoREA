//! norea-web: wasm-bindgen bindings for noreacore.
//!
//! Type conversion and zeroize only, no logic. Secrets arrive as `Vec<u8>`
//! and are zeroized after use (ADR-0012). The JS API list is
//! Fable_5_1/docs/CORE-API.md §2. WP-00 skeleton: no exports yet (WP-06).
