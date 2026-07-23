//! RFC 9380 `hash_to_field` for a single BLS12-381 `F_r` scalar.
//!
//! Spec §5.3/§5.6: the DLEQ Fiat-Shamir challenge is
//! `c = HashToScalar(transcript) mod r`, where `HashToScalar` is RFC 9380
//! `hash_to_field(msg, 1)` with `expand_message_xmd` over **SHA-256** and
//! `DST = DST_DLEQ`, reduced mod `r`. This is the RECOMMENDED / PROPOSED
//! construction (owner decision, OPEN §15 #22) — not frozen consensus bytes.
//!
//! `blstrs::Scalar` exposes no wide-reduction constructor (only canonical
//! `from_bytes_le`, which rejects values `>= r`), so we do the RFC 9380 reduction
//! ourselves: expand to `L = 48` uniform bytes and reduce the big-endian integer
//! mod `r` by Horner's method in the field. `L = ceil((ceil(log2 r) + 128) / 8) =
//! ceil((255 + 128)/8) = 48`.

use blstrs::Scalar;
use ff::Field;
use sha2::{Digest, Sha256};

/// RFC 9380 §5.2 security parameter for BLS12-381 `F_r`: `L = 48` bytes.
const L: usize = 48;

/// SHA-256 output size in bytes (`b_in_bytes`).
const B_IN_BYTES: usize = 32;

/// SHA-256 input block size in bytes (`s_in_bytes`).
const S_IN_BYTES: usize = 64;

/// RFC 9380 §5.3.1 `expand_message_xmd` instantiated with SHA-256.
///
/// Panics only on the documented out-of-range conditions (DST too long,
/// `ell > 255`), which cannot occur for the fixed short DSTs used here.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    assert!(dst.len() <= 255, "DST must be <= 255 bytes (RFC 9380)");
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(
        ell <= 255,
        "requested length too large for expand_message_xmd"
    );

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
    let mut msg_prime = Vec::with_capacity(S_IN_BYTES + msg.len() + 3 + dst_prime.len());
    msg_prime.extend_from_slice(&[0u8; S_IN_BYTES]); // Z_pad
    msg_prime.extend_from_slice(msg);
    msg_prime.extend_from_slice(&(len_in_bytes as u16).to_be_bytes()); // I2OSP(len, 2)
    msg_prime.push(0u8); // I2OSP(0, 1)
    msg_prime.extend_from_slice(&dst_prime);

    // b_0 = H(msg_prime)
    let b_0: [u8; B_IN_BYTES] = Sha256::digest(&msg_prime).into();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(b_0);
    hasher.update([1u8]);
    hasher.update(&dst_prime);
    let mut b_prev: [u8; B_IN_BYTES] = hasher.finalize().into();

    let mut uniform = Vec::with_capacity(ell * B_IN_BYTES);
    uniform.extend_from_slice(&b_prev);

    // b_i = H( strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime )
    for i in 2..=ell {
        let mut xored = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            xored[j] = b_0[j] ^ b_prev[j];
        }
        let mut hasher = Sha256::new();
        hasher.update(xored);
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        b_prev = hasher.finalize().into();
        uniform.extend_from_slice(&b_prev);
    }

    uniform.truncate(len_in_bytes);
    uniform
}

/// RFC 9380 `hash_to_field(msg, 1)` reduced mod `r`, with `DST` = `dst`.
///
/// Returns a single `blstrs::Scalar` uniformly distributed over `F_r`.
pub(crate) fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let uniform = expand_message_xmd(msg, dst, L);

    // OS2IP(uniform) mod r, big-endian, by Horner: acc = acc*256 + byte.
    let two_five_six = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for &byte in &uniform {
        acc = acc * two_five_six + Scalar::from(byte as u64);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 9380 Appendix K.1 — expand_message_xmd(SHA-256), DST =
    // "QUUX-V01-CS02-with-expander-SHA256-128". These are standard-fixed KATs
    // that pin our expand_message_xmd against the RFC.
    const RFC_DST: &[u8] = b"QUUX-V01-CS02-with-expander-SHA256-128";

    #[test]
    fn expand_message_xmd_rfc9380_empty_len32() {
        let out = expand_message_xmd(b"", RFC_DST, 32);
        assert_eq!(
            hex::encode(out),
            "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
        );
    }

    #[test]
    fn expand_message_xmd_rfc9380_abc_len32() {
        let out = expand_message_xmd(b"abc", RFC_DST, 32);
        assert_eq!(
            hex::encode(out),
            "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
        );
    }

    #[test]
    fn expand_message_xmd_rfc9380_abcdef0_len32() {
        let out = expand_message_xmd(b"abcdef0123456789", RFC_DST, 32);
        assert_eq!(
            hex::encode(out),
            "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"
        );
    }

    #[test]
    fn expand_message_xmd_multiblock_length_and_determinism() {
        // Exercises the multi-block (ell > 1) path used by hash_to_scalar (L=48).
        // Note: the requested length is bound into msg_prime, so outputs of
        // different lengths are NOT prefixes of one another — we only assert the
        // exact requested length and call-to-call determinism here.
        let a = expand_message_xmd(b"abc", RFC_DST, L);
        let b = expand_message_xmd(b"abc", RFC_DST, L);
        assert_eq!(a.len(), L);
        assert_eq!(a, b);
        let c = expand_message_xmd(b"abc", RFC_DST, 64);
        assert_eq!(c.len(), 64);
    }

    #[test]
    fn hash_to_scalar_is_deterministic_and_nonzero() {
        let a = hash_to_scalar(b"beacon-round-42", b"OMNINODE-DKG-DLEQ:v1:");
        let b = hash_to_scalar(b"beacon-round-42", b"OMNINODE-DKG-DLEQ:v1:");
        let c = hash_to_scalar(b"beacon-round-43", b"OMNINODE-DKG-DLEQ:v1:");
        assert_eq!(a, b, "same input -> same scalar");
        assert_ne!(a, c, "different input -> different scalar");
        assert_ne!(a, Scalar::ZERO);
    }
}
