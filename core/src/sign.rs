//! ML-DSA-65 signing and verification, SIG_CTX.
//!
//! Spec: Fable_5_1/docs/protocol/evidence-v1.md §3, ADR-0003, ADR-0005.
//! Pure ML-DSA (FIPS 204), not HashML-DSA. The software signer is
//! deterministic. Hardware signers (Secure Enclave) may hedge; verification
//! is the same. Inherited from ProvGuard with the context string changed.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, ErrorCode};
use crate::Key32;

/// FIPS 204 context string (17 bytes). Part of the frozen format.
pub const SIG_CTX: &[u8] = b"norea/evidence/v1";

/// Software ML-DSA-65 signer (web/WASM, Windows, Android). The platform
/// generates and custodies the 32-byte seed; core never touches an RNG.
///
/// Wiped on drop: `SigningKey` and its expanded key implement
/// `ZeroizeOnDrop` because ml-dsa is built with its `zeroize` feature
/// (core/Cargo.toml). Without that feature their Drop impls do nothing.
pub struct SoftwareSigner {
    sk: SigningKey<MlDsa65>,
}

// All key material lives in `sk`, which is ZeroizeOnDrop.
impl ZeroizeOnDrop for SoftwareSigner {}

impl SoftwareSigner {
    pub fn from_seed(seed: &Key32) -> Self {
        let mut s = Seed::from(*seed);
        let sk = SigningKey::<MlDsa65>::from_seed(&s);
        s.zeroize();
        Self { sk }
    }

    /// Encoded verifying key, 1952 bytes.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.sk.verifying_key().encode().to_vec()
    }

    /// Deterministic ML-DSA-65 signature over `msg` with context SIG_CTX, 3309 bytes.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let sig = self
            .sk
            .expanded_key()
            .sign_deterministic(msg, SIG_CTX)
            .map_err(|_| Error::new(ErrorCode::BadSignature, "ML-DSA signing failed"))?;
        Ok(sig.encode().to_vec())
    }
}

/// `ML-DSA.Verify(vk, msg, sig, ctx=SIG_CTX)`. False on any malformed input.
pub fn verify(vk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_ctx(vk, msg, sig, SIG_CTX)
}

fn verify_ctx(vk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
    let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(vk) else { return false };
    let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(sig) else { return false };
    let Some(sig) = Signature::<MlDsa65>::decode(&enc_sig) else { return false };
    VerifyingKey::<MlDsa65>::decode(&enc_vk).verify_with_context(msg, ctx, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Key32 = [0x22; 32];

    fn assert_zod<T: ZeroizeOnDrop>(_: &T) {}

    /// AC4 (inherited): round trip, other key, other message, other context.
    #[test]
    fn ac4_sign_verify() {
        let s = SoftwareSigner::from_seed(&SEED);
        assert_zod(&s);
        let other = SoftwareSigner::from_seed(&[1u8; 32]);
        let vk = s.verifying_key_bytes();
        let sig = s.sign(b"payload").unwrap();
        assert_eq!(vk.len(), 1952);
        assert_eq!(sig.len(), 3309);
        assert_eq!(SIG_CTX.len(), 17);
        assert!(verify(&vk, b"payload", &sig));
        assert!(!verify(&other.verifying_key_bytes(), b"payload", &sig));
        assert!(!verify(&vk, b"payload2", &sig));
        assert!(!verify_ctx(&vk, b"payload", &sig, b"norea/evidence/v2"));
        assert!(!verify_ctx(&vk, b"payload", &sig, b""));
        // Signature under another context does not verify under SIG_CTX.
        let foreign = s.sk.expanded_key().sign_deterministic(b"payload", b"other").unwrap().encode().to_vec();
        assert!(!verify(&vk, b"payload", &foreign));
        // Malformed inputs.
        assert!(!verify(&vk[..100], b"payload", &sig));
        assert!(!verify(&vk, b"payload", &sig[..3308]));
        // Deterministic.
        assert_eq!(sig, s.sign(b"payload").unwrap());
        assert_eq!(vk, SoftwareSigner::from_seed(&SEED).verifying_key_bytes());
    }
}
