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
// Beacon chaining domains (draft §12.1) — PROPOSED, not consensus.
// ---------------------------------------------------------------------------

/// Genesis-seed domain tag (draft §12.1). PROPOSED — not adopted.
pub const BEACON_GENESIS_DST: &[u8] = b"OMNINODE-BEACON-GENESIS:v1:";
/// Round-message domain tag (draft §12.1). PROPOSED — not adopted.
pub const BEACON_ROUND_DST: &[u8] = b"OMNINODE-BEACON-ROUND:v1:";
/// Beacon-output domain tag (draft §12.1). PROPOSED — not adopted.
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
/// (draft §10, §12). PROPOSED layout — not frozen consensus bytes.
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
/// genesis_params_hash)` (draft §12.1). PROPOSED layout.
pub fn genesis_seed(chain_id: u64, genesis_params_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(BEACON_GENESIS_DST);
    h.update(&chain_id.to_le_bytes());
    h.update(genesis_params_hash);
    *h.finalize().as_bytes()
}

/// The beacon output `beacon_r = BLAKE3(BEACON_OUT_DST ‖ u64_le(chain_id) ‖
/// u64_le(epoch) ‖ u64_le(round) ‖ compress(Sigma_r))` (draft §12.1). The output is a
/// deterministic function of the (unique) round signature `Sigma_r`. PROPOSED layout.
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
}
