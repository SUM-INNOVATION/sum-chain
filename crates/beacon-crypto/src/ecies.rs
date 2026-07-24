//! ECIES for scalar shares — HKDF-SHA-256 + ChaCha20-Poly1305 (spec §8).
//!
//! The DKG deal (`DkgDealV1`) carries, per recipient `j`, an ECIES ciphertext of
//! the **scalar** share `s_{ij} ∈ F_r`. This module implements the deterministic
//! seal/open per the BR1 security-design draft §8.2/§8.3/§8.9:
//!
//! * **KDF** — HKDF-SHA-256 (RFC 5869). `Extract` over the fixed public salt
//!   [`ECIES_HKDF_SALT`] and `IKM = serialize_G1(D_{ij})` (the 48-byte compressed
//!   ECDH secret); two `Expand` calls with distinct info labels
//!   ([`ECIES_AEAD_KEY_LABEL`] / [`ECIES_AEAD_NONCE_LABEL`]) each appended to the
//!   **entire** canonical context (§8.2). Both the AEAD key (32 B) and nonce (12 B)
//!   are HKDF outputs, so a fixed/zero nonce or a nonce derived from `D_{ij}` alone
//!   is never used (§8.5).
//! * **AEAD** — ChaCha20-Poly1305 (IETF 96-bit nonce, 16-byte tag). `aad` is the
//!   same canonical context bytes used as the HKDF `info` base (§8.4), binding
//!   `(protocol/version, chain_id, epoch, i, j, R_{ij}, EK_j)`.
//! * **Plaintext** — exactly 32 bytes, the canonical little-endian `F_r` encoding of
//!   the share; the ciphertext is exactly 48 bytes (`32 + 16` tag). After open, the
//!   32 plaintext bytes MUST decode as a canonical in-range scalar (`< r`), else the
//!   open is rejected (§8.2 post-decryption canonical-scalar check).
//!
//! **Determinism.** No nonce is transmitted: every party (dealer, recipient, and —
//! on complaint — every validator) re-derives the exact `(key, nonce)` from the
//! DLEQ-pinned `D_{ij}` plus the public context, so complaint adjudication (§6.1)
//! reproduces the decryption bit-for-bit. There is no RNG and no clock here.
//!
//! **Status.** The suite (HKDF-SHA-256 + ChaCha20-Poly1305) is `PROPOSED — OWNER
//! DECISION` (§8.2, §15 #25–#28), **not** ratified; only `G_enc = G1` and K-rotate
//! are ratified. The domain strings below are PROPOSED tags, not frozen consensus
//! bytes.

use crate::bls::{scalar_le_is_canonical, G1Point, G1_COMPRESSED_SIZE};
use crate::{BeaconCryptoError, Result};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Canonical-context protocol/version DST (spec §8.2): 25 ASCII bytes, unpadded.
pub const ECIES_CTX_DST: &[u8] = b"OMNINODE-DKG-ECIES:v1:ctx";

/// HKDF-Extract salt (spec §8.2/§8.9): 31 ASCII bytes, fixed and non-secret.
pub const ECIES_HKDF_SALT: &[u8] = b"OMNINODE-DKG-ECIES:v1:hkdf-salt";

/// HKDF-Expand info label for the AEAD key (spec §8.2): 8 ASCII bytes.
pub const ECIES_AEAD_KEY_LABEL: &[u8] = b"aead-key";

/// HKDF-Expand info label for the AEAD nonce (spec §8.2): 10 ASCII bytes.
pub const ECIES_AEAD_NONCE_LABEL: &[u8] = b"aead-nonce";

/// Plaintext width: the canonical LE `F_r` scalar share (spec §8.2), 32 bytes.
pub const ECIES_PLAINTEXT_LEN: usize = 32;

/// Ciphertext width: 32-byte ChaCha20-Poly1305 ciphertext ‖ 16-byte tag (§8.7).
pub const ECIES_CT_LEN: usize = 48;

/// AEAD key width (ChaCha20-Poly1305): 32 bytes.
const AEAD_KEY_LEN: usize = 32;
/// AEAD nonce width (ChaCha20-Poly1305 IETF): 12 bytes.
const AEAD_NONCE_LEN: usize = 12;

/// The canonical ECIES context (spec §8.2) that is bound identically as the HKDF
/// `info` base and as the AEAD `aad`. All seven mandated fields — protocol/version
/// DST, `chain_id`, `epoch`, dealer `i`, recipient `j`, carrier `R_{ij}`, recipient
/// key `EK_j` — are covered. `i`, `j` are the 0-based membership-snapshot indices
/// (the *identity* of dealer/recipient), never the evaluation point `x_j = j + 1`
/// (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EciesContext {
    /// Chain id (`u64_le`, the canonical `ChainId`).
    pub chain_id: u64,
    /// DKG epoch (`u64_le`).
    pub epoch: u64,
    /// Dealer index `i` (0-based, `u32_le`).
    pub dealer_i: u32,
    /// Recipient index `j` (0-based, `u32_le`).
    pub recipient_j: u32,
    /// ECIES carrier `R_{ij}` (validated compressed G1).
    pub r_ij: G1Point,
    /// Recipient encryption key `EK_j` (validated compressed G1).
    pub ek_j: G1Point,
}

impl EciesContext {
    /// Serialize `ECIES_CTX` exactly per spec §8.2 (145 bytes):
    /// `DST(25) ‖ u64_le(chain_id) ‖ u64_le(epoch) ‖ u32_le(i) ‖ u32_le(j) ‖
    ///  ser_G1(R_ij)(48) ‖ ser_G1(EK_j)(48)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b =
            Vec::with_capacity(ECIES_CTX_DST.len() + 8 + 8 + 4 + 4 + 2 * G1_COMPRESSED_SIZE);
        b.extend_from_slice(ECIES_CTX_DST);
        b.extend_from_slice(&self.chain_id.to_le_bytes());
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&self.dealer_i.to_le_bytes());
        b.extend_from_slice(&self.recipient_j.to_le_bytes());
        b.extend_from_slice(&self.r_ij.to_compressed());
        b.extend_from_slice(&self.ek_j.to_compressed());
        b
    }
}

/// Derive `(key, nonce)` from the ECDH secret `D_{ij}` and the canonical context via
/// HKDF-SHA-256 (spec §8.2/§8.9). `IKM = serialize_G1(D_{ij})`.
fn derive_key_nonce(
    d_ij: &G1Point,
    ctx_bytes: &[u8],
) -> (Zeroizing<[u8; AEAD_KEY_LEN]>, [u8; AEAD_NONCE_LEN]) {
    let ikm = d_ij.to_compressed();
    let hk = Hkdf::<Sha256>::new(Some(ECIES_HKDF_SALT), &ikm);

    let mut info_key = Vec::with_capacity(ctx_bytes.len() + ECIES_AEAD_KEY_LABEL.len());
    info_key.extend_from_slice(ctx_bytes);
    info_key.extend_from_slice(ECIES_AEAD_KEY_LABEL);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(&info_key, key.as_mut())
        .expect("32 <= 255*32, HKDF-Expand length valid");

    let mut info_nonce = Vec::with_capacity(ctx_bytes.len() + ECIES_AEAD_NONCE_LABEL.len());
    info_nonce.extend_from_slice(ctx_bytes);
    info_nonce.extend_from_slice(ECIES_AEAD_NONCE_LABEL);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    hk.expand(&info_nonce, &mut nonce)
        .expect("12 <= 255*32, HKDF-Expand length valid");

    (key, nonce)
}

/// ECIES **open** (spec §8, §6.1): decrypt `ct` under the key/nonce derived from the
/// ECDH secret `d_ij` and the canonical `ctx`, returning the 32-byte canonical LE
/// scalar share.
///
/// Errors:
/// * [`BeaconCryptoError::AeadOpenFailed`] — bad tag / wrong key / tampered
///   ciphertext (during adjudication this is `DISQUALIFY(i)`, §6.1);
/// * [`BeaconCryptoError::NonCanonicalScalar`] — a clean open whose 32 plaintext
///   bytes are `≥ r` (also `DISQUALIFY(i)`, §8.2/§8.8 rule 5).
pub fn ecies_open(
    d_ij: &G1Point,
    ctx: &EciesContext,
    ct: &[u8; ECIES_CT_LEN],
) -> Result<[u8; ECIES_PLAINTEXT_LEN]> {
    let ctx_bytes = ctx.to_bytes();
    let (key, nonce) = derive_key_nonce(d_ij, &ctx_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ct,
                aad: &ctx_bytes,
            },
        )
        .map_err(|_| BeaconCryptoError::AeadOpenFailed)?;

    // Fixed 32-byte plaintext (a correctly-formed share). Any other length is a
    // dealer fault surfaced as a canonical-scalar failure.
    if plaintext.len() != ECIES_PLAINTEXT_LEN {
        return Err(BeaconCryptoError::NonCanonicalScalar);
    }
    let mut share = [0u8; ECIES_PLAINTEXT_LEN];
    share.copy_from_slice(&plaintext);

    // Post-decryption canonical-scalar check (spec §8.2): reject `≥ r`.
    if !scalar_le_is_canonical(&share) {
        return Err(BeaconCryptoError::NonCanonicalScalar);
    }
    Ok(share)
}

/// ECIES **seal** (spec §8.2) — the deterministic counterpart of [`ecies_open`],
/// provided so the deterministic vectors (and a future dealer path) can build a
/// well-formed `ct_{ij}` without duplicating the KDF/AEAD construction. `share_le`
/// MUST be a canonical LE `F_r` scalar (`< r`), else [`BeaconCryptoError::
/// NonCanonicalScalar`].
pub fn ecies_seal(
    d_ij: &G1Point,
    ctx: &EciesContext,
    share_le: &[u8; ECIES_PLAINTEXT_LEN],
) -> Result<[u8; ECIES_CT_LEN]> {
    if !scalar_le_is_canonical(share_le) {
        return Err(BeaconCryptoError::NonCanonicalScalar);
    }
    let ctx_bytes = ctx.to_bytes();
    let (key, nonce) = derive_key_nonce(d_ij, &ctx_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: share_le,
                aad: &ctx_bytes,
            },
        )
        .map_err(|_| BeaconCryptoError::AeadOpenFailed)?;

    // 32-byte plaintext + 16-byte Poly1305 tag = 48 bytes, always.
    let mut out = [0u8; ECIES_CT_LEN];
    if ct.len() != ECIES_CT_LEN {
        return Err(BeaconCryptoError::AeadOpenFailed);
    }
    out.copy_from_slice(&ct);
    Ok(out)
}

/// Test-only: seal arbitrary 32 plaintext bytes **without** the canonical-scalar
/// guard, so the vectors can exercise [`ecies_open`]'s post-decryption
/// canonical-scalar rejection (spec §8.2) with a non-canonical (`≥ r`) plaintext —
/// which the production [`ecies_seal`] refuses to construct.
#[cfg(test)]
pub(crate) fn ecies_seal_raw_for_test(
    d_ij: &G1Point,
    ctx: &EciesContext,
    plaintext: &[u8; ECIES_PLAINTEXT_LEN],
) -> [u8; ECIES_CT_LEN] {
    let ctx_bytes = ctx.to_bytes();
    let (key, nonce) = derive_key_nonce(d_ij, &ctx_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &ctx_bytes,
            },
        )
        .expect("aead seal");
    let mut out = [0u8; ECIES_CT_LEN];
    out.copy_from_slice(&ct);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::SecretScalar;

    /// A fixed canonical (`< r`) 32-byte LE scalar seed (byte 31 = 0 ⇒ well below r).
    fn seed(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, out) in b.iter_mut().enumerate() {
            *out = tag.wrapping_add(i as u8).wrapping_mul(5).wrapping_add(3);
        }
        b[31] = 0;
        b
    }

    fn statement() -> (EciesContext, G1Point, [u8; 32]) {
        // Recipient encryption key EK_j = g1^{ek_j}; carrier R_ij = g1^{r_ij}.
        let ek = SecretScalar::from_bytes_le(&seed(0x11)).unwrap();
        let r = SecretScalar::from_bytes_le(&seed(0x22)).unwrap();
        let ek_pt = ek.public_g1();
        let r_pt = r.public_g1();
        // Two ECDH derivations must agree: D = R^{ek} = EK^{r}.
        let d_recip = ek.ecdh(&r_pt).unwrap();
        let d_dealer = r.ecdh(&ek_pt).unwrap();
        assert_eq!(d_recip, d_dealer, "ECDH secret must agree on both sides");
        let ctx = EciesContext {
            chain_id: 0x0102_0304_0506_0708,
            epoch: 7,
            dealer_i: 3,
            recipient_j: 4,
            r_ij: r_pt,
            ek_j: ek_pt,
        };
        (ctx, d_dealer, seed(0x33))
    }

    #[test]
    fn ecies_seal_open_roundtrip_and_ctx_len() {
        let (ctx, d, share) = statement();
        assert_eq!(
            ctx.to_bytes().len(),
            145,
            "ECIES_CTX is 145 bytes (spec §8.2)"
        );
        let ct = ecies_seal(&d, &ctx, &share).unwrap();
        assert_eq!(ct.len(), ECIES_CT_LEN);
        let recovered = ecies_open(&d, &ctx, &ct).unwrap();
        assert_eq!(recovered, share, "open recovers the sealed share");
        println!("KAT ECIES ct = {}", hex::encode(ct));
    }

    #[test]
    fn ecies_open_rejects_tamper_wrong_secret_and_wrong_context() {
        let (ctx, d, share) = statement();
        let ct = ecies_seal(&d, &ctx, &share).unwrap();

        // Tampered ciphertext (flip one body byte) ⇒ AEAD open fails.
        let mut bad = ct;
        bad[0] ^= 0x01;
        assert_eq!(
            ecies_open(&d, &ctx, &bad).unwrap_err(),
            BeaconCryptoError::AeadOpenFailed
        );

        // Wrong ECDH secret ⇒ wrong key ⇒ AEAD open fails.
        let d_wrong = SecretScalar::from_bytes_le(&seed(0x44))
            .unwrap()
            .public_g1();
        assert_eq!(
            ecies_open(&d_wrong, &ctx, &ct).unwrap_err(),
            BeaconCryptoError::AeadOpenFailed
        );

        // Wrong context (different epoch ⇒ different key/nonce + AAD) ⇒ open fails.
        let mut ctx2 = ctx.clone();
        ctx2.epoch = 8;
        assert_eq!(
            ecies_open(&d, &ctx2, &ct).unwrap_err(),
            BeaconCryptoError::AeadOpenFailed
        );
    }

    #[test]
    fn ecies_open_rejects_non_canonical_plaintext() {
        let (ctx, d, _share) = statement();
        // Seal a non-canonical (>= r) 32-byte plaintext via the test-only raw seal;
        // open must reject it at the post-decryption canonical-scalar check (§8.2).
        let non_canonical = [0xFFu8; 32];
        let ct = ecies_seal_raw_for_test(&d, &ctx, &non_canonical);
        assert_eq!(
            ecies_open(&d, &ctx, &ct).unwrap_err(),
            BeaconCryptoError::NonCanonicalScalar
        );
        // And the production seal refuses to build a non-canonical share at all.
        assert_eq!(
            ecies_seal(&d, &ctx, &non_canonical).unwrap_err(),
            BeaconCryptoError::NonCanonicalScalar
        );
    }
}
