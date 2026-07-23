//! Signing-phase carriers + beacon chaining messages (draft §2.4, §4.3, §12).
//!
//! ## Local mirrors of the not-yet-merged signing carriers
//!
//! The DKG **setup** carriers ([`RegisterBeaconKeyV1`], [`DkgDealV1`],
//! [`DkgComplaintV1`]) are already in `main`'s `sumchain-wire::beacon_wire` and are
//! consumed directly by the [`crate::dkg`] module. The **signing** carriers
//! `BeaconPartialV1` / `BeaconFinalizeV1` are **not yet in `main`** — they land with
//! #125 (they exist today only in the `w1b-125-close` branch). To stay self-contained
//! and buildable against `main`, this module mirrors their **exact field layout**
//! from that branch:
//!
//! * `BeaconPartialV1` — magic `b"BPRTv1\0"`, `LEN = 133`:
//!   `magic[7] · schema_version u16 · chain_id u64_le · epoch u64_le · round u64_le ·
//!    j u32_le · sigma_j G2[96]`.
//! * `BeaconFinalizeV1` — magic `b"BFNLv1\0"`, `BASE_LEN = 133` + witness:
//!   `magic[7] · schema_version u16 · chain_id u64_le · epoch u64_le · round u64_le ·
//!    Sigma_r G2[96] · witness_count u32_le · witness (count × u32_le)`.
//!
//! **Integration note.** When #125 merges these into `sumchain-wire`, delete these
//! mirrors and change [`crate::signing`] to consume
//! `sumchain_wire::beacon_wire::{BeaconPartialV1, BeaconFinalizeV1}` — the field
//! names here are chosen to match, so the swap is mechanical. The runtime operates on
//! the *decoded fields* (never re-encodes), so the byte codec staying in
//! `sumchain-wire` is correct; only the struct source moves.

use sumchain_beacon_crypto::{Signature, G2_COMPRESSED_SIZE};

/// Compressed G2 point width (bytes) — a partial / combined signature.
pub const G2_LEN: usize = G2_COMPRESSED_SIZE;

/// Per-round threshold-BLS partial signature (draft §2.4, §4.3). Mirror of the #125
/// `sumchain_wire::beacon_wire::BeaconPartialV1` (see module docs). `j` is the
/// 0-based membership-snapshot index; the evaluation point is `x_j = j + 1` (§3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconPartialV1 {
    /// Chain id (replay separation), `u64_le`.
    pub chain_id: u64,
    /// Beacon epoch, `u64_le`.
    pub epoch: u64,
    /// Beacon round within the epoch, `u64_le` (draft §12 `m_r`).
    pub round: u64,
    /// Participant index `j`, 0-based membership index, `u32_le`.
    pub j: u32,
    /// `sigma_j = H_{G2}(m_r)^{sk_j}` — canonical compressed G2 (96B).
    pub sigma_j: [u8; G2_LEN],
}

/// Per-round exactly-`T` Lagrange combine output (draft §4.3, §12). Mirror of the
/// #125 `sumchain_wire::beacon_wire::BeaconFinalizeV1` (see module docs).
///
/// **Distinct from DKG finalization (QUAL).** Determining `QUAL`/`PK_E` is a
/// deterministic state transition with no carrier ([`crate::dkg`]); this is the
/// per-round produced signing output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeaconFinalizeV1 {
    /// Chain id (replay separation), `u64_le`.
    pub chain_id: u64,
    /// Beacon epoch, `u64_le`.
    pub epoch: u64,
    /// Beacon round within the epoch, `u64_le`.
    pub round: u64,
    /// `Sigma_r` — combined round signature, canonical compressed G2 (96B).
    pub sigma_r: [u8; G2_LEN],
    /// Selected-contributor witness (draft §4.3 step 3): the 0-based membership
    /// indices of the exactly-`T` contributors, sorted ascending by `x_j`.
    pub witness: Vec<u32>,
}

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
