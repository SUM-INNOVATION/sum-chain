//! Canonical signing carriers + beacon chaining messages (draft §2.4, §4.3, §12).
//!
//! ## Canonical wire types (finding 1 — mirrors removed)
//!
//! The signing carriers are now the **canonical** `sumchain_wire::beacon_wire`
//! types, re-exported here for one import site. An earlier revision mirrored them
//! locally because they had not yet merged to `main`; #164 landed them, so the
//! mirrors are deleted and the runtime consumes the frozen carriers directly. The
//! conformance test [`tests::canonical_carriers_are_the_wire_types`] proves there is
//! no semantic drift (field-for-field construction + canonical round-trip through the
//! frozen `sumchain-wire` codec).

pub use sumchain_wire::beacon_wire::{BeaconFinalizeV1, BeaconPartialV1, G2_LEN};

use sumchain_beacon_crypto::Signature;

// ---------------------------------------------------------------------------
// Beacon chaining domains (§12.1) — RATIFIED v1 consensus bytes.
// Owner-ratified 2026-09-01 (#127): spec banner + §15 decision table rows 17–19
// adopt the GENESIS/ROUND/OUT tags and their exact byte/preimage layouts as v1
// consensus bytes. KAT-locked in `tests::beacon_output_kat_ratified_v1`.
// Execution stays gate-closed (`beacon_enabled_from_height = None`).
// ---------------------------------------------------------------------------

/// Genesis-seed domain tag (§12.1). RATIFIED v1 consensus bytes (#127).
pub const BEACON_GENESIS_DST: &[u8] = b"OMNINODE-BEACON-GENESIS:v1:";
/// Round-message domain tag (§12.1). RATIFIED v1 consensus bytes (#127).
pub const BEACON_ROUND_DST: &[u8] = b"OMNINODE-BEACON-ROUND:v1:";
/// Beacon-output domain tag (§12.1). RATIFIED v1 consensus bytes (#127).
pub const BEACON_OUT_DST: &[u8] = b"OMNINODE-BEACON-OUT:v1:";

/// The chaining input to a round message (draft §12.1): the previous round's group
/// signature `Sigma_{r-1}`, or — for the first round — the genesis seed.
pub enum ChainInput<'a> {
    /// First round: the 32-byte genesis seed (from [`genesis_seed`]).
    GenesisSeed([u8; 32]),
    /// Subsequent rounds: the previous round's combined signature `Sigma_{r-1}`.
    Previous(&'a Signature),
}

/// Build the round message `m_r` exactly per draft §12.1:
/// `BEACON_ROUND_DST ‖ u64_le(chain_id) ‖ u64_le(epoch) ‖ u64_le(round) ‖
///  compress(Sigma_prev)` — where `compress(Sigma_prev)` is the genesis seed (32B)
/// for the first round, or the canonical compressed `Sigma_{r-1}` (96B) otherwise.
///
/// Binding `chain_id, epoch, round` prevents cross-chain / cross-epoch / cross-round
/// replay; chaining `Sigma_prev` makes each round depend on the whole prior history
/// (§10, §12). RATIFIED v1 consensus bytes (#127).
pub fn round_message(chain_id: u64, epoch: u64, round: u64, prev: &ChainInput) -> Vec<u8> {
    let mut m = Vec::with_capacity(BEACON_ROUND_DST.len() + 8 + 8 + 8 + G2_LEN);
    m.extend_from_slice(BEACON_ROUND_DST);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m.extend_from_slice(&round.to_le_bytes());
    match prev {
        ChainInput::GenesisSeed(seed) => m.extend_from_slice(seed),
        ChainInput::Previous(sig) => m.extend_from_slice(&sig.to_compressed()),
    }
    m
}

/// The genesis seed `Sigma_0_seed = BLAKE3(BEACON_GENESIS_DST ‖ u64_le(chain_id) ‖
/// genesis_params_hash)` (§12.1). RATIFIED v1 consensus bytes (#127).
pub fn genesis_seed(chain_id: u64, genesis_params_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(BEACON_GENESIS_DST);
    h.update(&chain_id.to_le_bytes());
    h.update(genesis_params_hash);
    *h.finalize().as_bytes()
}

/// The beacon output `beacon_r = BLAKE3(BEACON_OUT_DST ‖ u64_le(chain_id) ‖
/// u64_le(epoch) ‖ u64_le(round) ‖ compress(Sigma_r))` (§12.1). The output is a
/// deterministic function of the (unique) round signature `Sigma_r`.
/// RATIFIED v1 consensus bytes (#127); KAT-locked in `tests::beacon_output_kat_ratified_v1`.
pub fn beacon_output(chain_id: u64, epoch: u64, round: u64, sigma_r: &Signature) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(BEACON_OUT_DST);
    h.update(&chain_id.to_le_bytes());
    h.update(&epoch.to_le_bytes());
    h.update(&round.to_le_bytes());
    h.update(&sigma_r.to_compressed());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance: the runtime's signing carriers ARE the canonical
    /// `sumchain-wire` types (finding 1) — no local mirror, no drift. We build each
    /// carrier by field name and round-trip it through the frozen `sumchain-wire`
    /// codec (`try_encode` / `decode_exact`), proving the runtime and consensus agree
    /// on the exact bytes.
    #[test]
    fn canonical_carriers_are_the_wire_types() {
        let mut sig = [0u8; G2_LEN];
        sig[0] = 0x80; // compression set, infinity clear (structural-OK placeholder)

        let p = BeaconPartialV1 {
            chain_id: 0x0102_0304_0506_0708,
            epoch: 7,
            round: 3,
            j: 2,
            sigma_j: sig,
        };
        let p_bytes = p.try_encode().expect("partial encodes");
        assert_eq!(
            BeaconPartialV1::decode_exact(&p_bytes).unwrap(),
            p,
            "partial must round-trip through the frozen wire codec"
        );

        let f = BeaconFinalizeV1 {
            chain_id: 0x0102_0304_0506_0708,
            epoch: 7,
            round: 3,
            sigma_r: sig,
            witness: vec![0, 1],
        };
        let f_bytes = f.try_encode().expect("finalize encodes");
        assert_eq!(
            BeaconFinalizeV1::decode_exact(&f_bytes).unwrap(),
            f,
            "finalize must round-trip through the frozen wire codec"
        );
    }

    use sumchain_beacon_crypto::{SecretScalar, Signature};

    /// A real, valid G2 signature from a FIXED canonical scalar seed — no RNG, no
    /// synthetic stand-in bytes. Deterministic, so it is identical on x86_64 and
    /// aarch64 (both CI arches run this; `blst` ships tuned asm for both plus a
    /// portable fallback, all yielding the same canonical encoding).
    fn kat_signature() -> Signature {
        let mut sk_seed = [0x11u8; 32];
        sk_seed[31] = 0x00; // byte 31 is the LE MSB — force < r (canonical)
        let sk = SecretScalar::from_bytes_le(&sk_seed).expect("canonical scalar seed");
        sk.sign(b"OMNINODE-BR1-BEACON-OUTPUT-KAT/v1")
    }

    const KAT_CHAIN_ID: u64 = 0x0102_0304_0506_0708;
    const KAT_EPOCH: u64 = 7;
    const KAT_ROUND: u64 = 3;

    /// Byte-exact KAT for the RATIFIED v1 `beacon_output` (#127 §12.1) over a real
    /// signature: locks the exact domain tag, the little-endian field order, the
    /// canonical 96-byte G2 compression, the full preimage, and the final BLAKE3
    /// output. Any drift is a consensus-visible change to escalate, never re-bless.
    #[test]
    fn beacon_output_kat_ratified_v1() {
        let sig = kat_signature();

        // Canonical 96-byte compression, and it decodes back (subgroup + non-identity).
        let comp = sig.to_compressed();
        assert_eq!(comp.len(), 96, "G2 signature compresses to 96 bytes");
        assert!(
            Signature::from_compressed(&comp).is_ok(),
            "the compressed signature must be canonical"
        );

        let out = beacon_output(KAT_CHAIN_ID, KAT_EPOCH, KAT_ROUND, &sig);

        // Independent recomputation of the exact ratified preimage:
        // BEACON_OUT_DST ‖ u64_le(chain_id) ‖ u64_le(epoch) ‖ u64_le(round) ‖ compress(Sigma_r)
        let mut pre = Vec::new();
        pre.extend_from_slice(BEACON_OUT_DST);
        pre.extend_from_slice(&KAT_CHAIN_ID.to_le_bytes());
        pre.extend_from_slice(&KAT_EPOCH.to_le_bytes());
        pre.extend_from_slice(&KAT_ROUND.to_le_bytes());
        pre.extend_from_slice(&comp);
        assert_eq!(
            out,
            *blake3::hash(&pre).as_bytes(),
            "beacon_output must equal BLAKE3 of the ratified preimage"
        );

        // Frozen cross-arch regression vectors (b3sum / compression), NOT proofs.
        assert_eq!(
            hex::encode(comp),
            "b208df346c7cabeded73631e962cde964f9f551da77a344decb6e92b06ef4446ef21b525d96cba72acc0cd6c2d0ab4ba0e5f2b7b5c213e60c5e89a68692ed04cfeea1b25303a7bb456a11e7c627323248f284b0f43d560cf93d8bf875ae0619f",
            "compressed Sigma_r KAT drift (blst G2 encoding changed?)"
        );
        assert_eq!(
            hex::encode(out),
            "6904ae11981e78d560b34500bb42b1749085c45ed68c7a7bfe3d26f9e3e92104",
            "beacon_output KAT drift — escalate (consensus-visible)"
        );
    }

    /// Negative vectors: the ratified layout is sensitive to domain, field order,
    /// and endianness; and a non-canonical signature encoding is rejected before
    /// it can reach `beacon_output`.
    #[test]
    fn beacon_output_negatives() {
        let sig = kat_signature();
        let comp = sig.to_compressed();
        let good = beacon_output(KAT_CHAIN_ID, KAT_EPOCH, KAT_ROUND, &sig);

        let h = |parts: &[&[u8]]| -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            for p in parts {
                hasher.update(p);
            }
            *hasher.finalize().as_bytes()
        };
        let ci_le = KAT_CHAIN_ID.to_le_bytes();
        let ep_le = KAT_EPOCH.to_le_bytes();
        let rd_le = KAT_ROUND.to_le_bytes();

        // Wrong domain tag.
        assert_ne!(
            good,
            h(&[b"OMNINODE-BEACON-OUT:v2:", &ci_le, &ep_le, &rd_le, &comp])
        );
        // Wrong field order (chain_id/epoch swapped).
        assert_ne!(good, h(&[BEACON_OUT_DST, &ep_le, &ci_le, &rd_le, &comp]));
        // Wrong endianness (big-endian ints).
        assert_ne!(
            good,
            h(&[
                BEACON_OUT_DST,
                &KAT_CHAIN_ID.to_be_bytes(),
                &KAT_EPOCH.to_be_bytes(),
                &KAT_ROUND.to_be_bytes(),
                &comp,
            ])
        );
        // Non-canonical signature encoding is rejected at decode (all-0xFF is a
        // field element ≥ modulus with invalid flag bits) — it never reaches
        // beacon_output.
        assert!(Signature::from_compressed(&[0xFFu8; 96]).is_err());
    }
}
