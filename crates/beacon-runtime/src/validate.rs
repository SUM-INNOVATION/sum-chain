//! Stateless crypto/structural validation of a single beacon carrier (the executor
//! seam's entry point — finding 7).
//!
//! [`validate_operation`] is what the #164 beacon executor seam invokes on the
//! gate-open path (after its crypto-free semantic precheck) to run the §2.2
//! subgroup/infinity + PoP + canonical-scalar + witness validation the seam
//! documented as "deferred to #127". It is **stateless** — it validates one carrier
//! against the epoch parameters without the accumulated DKG epoch state (the full
//! stateful DLEQ/AEAD adjudication + QUAL + signing lifecycle live in [`crate::dkg`]
//! / [`crate::signing`] / [`crate::rounds`], driven from persisted epoch state). It
//! performs the real curve/pairing checks, so wiring it makes the executor
//! genuinely reach the runtime. It mutates nothing.

use sumchain_beacon_crypto::{
    pop_verify, DleqProof, G1Point, Pop, PublicKey, Signature, SCALAR_SIZE,
};
use sumchain_wire::beacon_wire::BeaconOperation;

use crate::params::BeaconParams;

/// A stateless validation failure for one beacon carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// A G1/G2 field failed canonical / subgroup / infinity decode (draft §2.2).
    #[error("invalid group element (canonical/subgroup/infinity)")]
    InvalidElement,
    /// A `RegisterBeaconKeyV1` proof-of-possession did not verify (draft §2.3).
    #[error("proof-of-possession failed to verify")]
    PopInvalid,
    /// A deal's Feldman commitment count is not exactly `T` (draft §1.2/§4.3).
    #[error("commitment count != threshold T")]
    CommitmentCountMismatch,
    /// A DLEQ proof scalar (`c`/`z`) was non-canonical (`>= r`, draft §5.6).
    #[error("non-canonical DLEQ scalar")]
    NonCanonicalScalar,
    /// A finalize witness is not exactly `T` long (draft §4.3 step 3).
    #[error("finalize witness length != T")]
    WitnessNotExactlyT,
    /// A finalize witness is not strictly ascending (draft §4.1).
    #[error("finalize witness not strictly ascending")]
    WitnessNonCanonical,
    /// A finalize witness index is out of the membership range (`>= n`).
    #[error("finalize witness index >= n")]
    WitnessIndexOutOfRange,
}

/// Stateless crypto/structural validation of one beacon operation against `params`
/// (draft §2.2/§2.3/§4.3/§5.6). Returns `Ok(())` iff every field decodes canonically,
/// the PoP verifies, scalars are canonical, and the finalize witness is exactly-`T`,
/// strictly-ascending, and membership-bounded. Full stateful adjudication (DLEQ/AEAD
/// against the on-chain deal, QUAL, pairing-under-`PK_E`) is the runtime's stateful
/// path and is **not** performed here — this is the standalone-checkable surface the
/// executor seam runs before that path exists.
pub fn validate_operation(
    params: &BeaconParams,
    op: &BeaconOperation,
) -> Result<(), ValidationError> {
    match op {
        BeaconOperation::RegisterBeaconKey(k) => {
            let ek =
                G1Point::from_compressed(&k.ek_j).map_err(|_| ValidationError::InvalidElement)?;
            let pop = Pop::from_compressed(&k.pop).map_err(|_| ValidationError::InvalidElement)?;
            if !pop_verify(&PublicKey::from_g1_point(ek), &pop) {
                return Err(ValidationError::PopInvalid);
            }
            Ok(())
        }
        BeaconOperation::DkgDeal(d) => {
            if d.commitments.len() != params.t() as usize {
                return Err(ValidationError::CommitmentCountMismatch);
            }
            for c in &d.commitments {
                G1Point::from_compressed(c).map_err(|_| ValidationError::InvalidElement)?;
            }
            G1Point::from_compressed(&d.r_ij).map_err(|_| ValidationError::InvalidElement)?;
            Ok(())
        }
        BeaconOperation::DkgComplaint(c) => {
            G1Point::from_compressed(&c.r_ij).map_err(|_| ValidationError::InvalidElement)?;
            G1Point::from_compressed(&c.d_ij).map_err(|_| ValidationError::InvalidElement)?;
            let mut cz = [0u8; 2 * SCALAR_SIZE];
            cz[..SCALAR_SIZE].copy_from_slice(&c.dleq_c);
            cz[SCALAR_SIZE..].copy_from_slice(&c.dleq_z);
            DleqProof::from_bytes(&cz).map_err(|_| ValidationError::NonCanonicalScalar)?;
            Ok(())
        }
        BeaconOperation::BeaconPartial(p) => {
            Signature::from_compressed(&p.sigma_j).map_err(|_| ValidationError::InvalidElement)?;
            Ok(())
        }
        BeaconOperation::BeaconFinalize(f) => {
            if f.witness.len() != params.t() as usize {
                return Err(ValidationError::WitnessNotExactlyT);
            }
            if !f.witness.windows(2).all(|w| w[0] < w[1]) {
                return Err(ValidationError::WitnessNonCanonical);
            }
            for &idx in &f.witness {
                if idx >= params.n() {
                    return Err(ValidationError::WitnessIndexOutOfRange);
                }
            }
            Signature::from_compressed(&f.sigma_r).map_err(|_| ValidationError::InvalidElement)?;
            Ok(())
        }
    }
}
