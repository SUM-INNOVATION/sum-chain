//! Gate-closed signing phase (draft §2.4, §4.3, §12).
//!
//! After a successful DKG ([`crate::dkg::DkgOutcome::Success`]), a
//! [`QualifiedEpoch`] holds the qualified dealers' commitments and the epoch group
//! key `PK_E`. It derives each participant's verification key `vk_j`, verifies
//! per-round partial signatures, performs the exactly-`T` sorted Lagrange combine,
//! and verifies a round's finalize carrier. All pure crypto over the adapter; no
//! state mutation, no activation.

use sumchain_beacon_crypto::{
    aggregate_g1, combine, commitment_poly_eval, verify, verify_partial, G1Point, PartialSignature,
    PublicKey, Signature,
};

use crate::params::BeaconParams;
use crate::wire::{BeaconFinalizeV1, BeaconPartialV1};

/// The signing-phase view of a *successful* DKG epoch (draft §4.2/§4.3).
#[derive(Clone, Debug)]
pub struct QualifiedEpoch {
    chain_id: u64,
    epoch: u64,
    params: BeaconParams,
    group_key: PublicKey,
    /// Qualified dealers' commitment vectors, ascending by dealer index (§4.1).
    qual_commitments: Vec<(u32, Vec<G1Point>)>,
}

/// Why a partial signature was not accepted into a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PartialError {
    /// The partial's `chain_id`/`epoch` does not match this epoch.
    #[error("partial chain_id/epoch does not match this epoch")]
    WrongEpoch,
    /// `sigma_j` failed canonical / subgroup / infinity decode (draft §2.2).
    #[error("invalid partial signature encoding")]
    InvalidSignature,
    /// The per-participant verification key `vk_j` could not be derived (a degenerate
    /// aggregate, draft §2.2 infinity rule).
    #[error("could not derive vk_j")]
    NoVerificationKey,
}

/// Why a finalize carrier was rejected (draft §4.3, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalizeError {
    /// The finalize's `chain_id`/`epoch` does not match this epoch.
    #[error("finalize chain_id/epoch does not match this epoch")]
    WrongEpoch,
    /// The selected-contributor witness is not exactly the threshold `T` long
    /// (draft §4.3 step 3: `|selection| = T`, not `≥ T`).
    #[error("finalize witness length is not exactly T")]
    WitnessNotExactlyT,
    /// The witness is not strictly ascending — i.e. unsorted or contains a duplicate
    /// (draft §4.1/§4.3 canonical order).
    #[error("finalize witness is not strictly ascending")]
    WitnessNotCanonical,
    /// `Sigma_r` failed canonical / subgroup / infinity decode (draft §2.2).
    #[error("invalid combined signature encoding")]
    InvalidSignature,
    /// `Sigma_r` did not verify as a BLS signature under `PK_E` over `m_r` (draft §4.3).
    #[error("combined signature does not verify under PK_E")]
    SignatureInvalid,
}

impl QualifiedEpoch {
    /// Build the signing view from a successful DKG's qualified commitments + `PK_E`.
    /// Obtain `qual_commitments` from [`crate::dkg::DkgEpoch::qualified_commitments`]
    /// and `group_key` from the matching [`crate::dkg::DkgOutcome::Success`].
    pub fn new(
        chain_id: u64,
        epoch: u64,
        params: BeaconParams,
        group_key: PublicKey,
        qual_commitments: Vec<(u32, Vec<G1Point>)>,
    ) -> Self {
        QualifiedEpoch {
            chain_id,
            epoch,
            params,
            group_key,
            qual_commitments,
        }
    }

    /// The epoch group public key `PK_E`.
    pub fn group_key(&self) -> &PublicKey {
        &self.group_key
    }

    /// Derive participant `j`'s verification key (draft §2.4/§4.2):
    /// `vk_j = Σ_{i∈QUAL} Σ_k [x_j^k] · C_{i,k}`, with `x_j = j + 1` (§3).
    pub fn participant_vk(&self, j: u32) -> Result<PublicKey, PartialError> {
        let x_j = (j as u64) + 1;
        let mut terms = Vec::with_capacity(self.qual_commitments.len());
        for (_i, commitments) in &self.qual_commitments {
            let term = commitment_poly_eval(commitments, x_j)
                .map_err(|_| PartialError::NoVerificationKey)?;
            terms.push(term);
        }
        let vk = aggregate_g1(&terms).map_err(|_| PartialError::NoVerificationKey)?;
        Ok(PublicKey::from_g1_point(vk))
    }

    /// Verify one `BeaconPartialV1` against its derived `vk_j` over the round message
    /// `m_r` (draft §2.4). `m_r` is built by [`crate::wire::round_message`].
    pub fn verify_partial_carrier(
        &self,
        partial: &BeaconPartialV1,
        m_r: &[u8],
    ) -> Result<bool, PartialError> {
        if partial.chain_id != self.chain_id || partial.epoch != self.epoch {
            return Err(PartialError::WrongEpoch);
        }
        let sig = Signature::from_compressed(&partial.sigma_j)
            .map_err(|_| PartialError::InvalidSignature)?;
        let vk_j = self.participant_vk(partial.j)?;
        let x_j = (partial.j as u64) + 1;
        let ps = PartialSignature::new(x_j, sig);
        Ok(verify_partial(&vk_j, m_r, &ps))
    }

    /// Verify a batch of partials and **exactly-`T` sorted Lagrange combine** them
    /// (draft §4.3). Only partials that individually verify (§2.4) enter the
    /// interpolation (§4.3 step 1); the combine then selects exactly the first `T`
    /// after sorting ascending by `x_j`. Errors if fewer than `T` valid partials.
    pub fn combine_round(
        &self,
        partials: &[BeaconPartialV1],
        m_r: &[u8],
    ) -> Result<Signature, CombineError> {
        let mut valid: Vec<PartialSignature> = Vec::with_capacity(partials.len());
        for p in partials {
            // Skip any partial that does not verify — invalid partials must never
            // enter the interpolation (draft §4.3 step 1).
            match self.verify_partial_carrier(p, m_r) {
                Ok(true) => {
                    let sig = Signature::from_compressed(&p.sigma_j)
                        .expect("verify_partial_carrier already decoded sigma_j");
                    valid.push(PartialSignature::new((p.j as u64) + 1, sig));
                }
                Ok(false) | Err(_) => continue,
            }
        }
        if valid.len() < self.params.t as usize {
            return Err(CombineError::InsufficientValidPartials {
                need: self.params.t as usize,
                got: valid.len(),
            });
        }
        combine(&valid).map_err(CombineError::Crypto)
    }

    /// Verify a `BeaconFinalizeV1` (draft §4.3, §12): the witness is exactly `T`,
    /// strictly ascending (⇒ sorted + distinct, canonical §4.1), and `Sigma_r`
    /// verifies as a BLS signature under `PK_E` over `m_r`.
    pub fn verify_finalize(
        &self,
        finalize: &BeaconFinalizeV1,
        m_r: &[u8],
    ) -> Result<(), FinalizeError> {
        if finalize.chain_id != self.chain_id || finalize.epoch != self.epoch {
            return Err(FinalizeError::WrongEpoch);
        }
        if finalize.witness.len() != self.params.t as usize {
            return Err(FinalizeError::WitnessNotExactlyT);
        }
        if !finalize.witness.windows(2).all(|w| w[0] < w[1]) {
            return Err(FinalizeError::WitnessNotCanonical);
        }
        let sigma_r = Signature::from_compressed(&finalize.sigma_r)
            .map_err(|_| FinalizeError::InvalidSignature)?;
        if !verify(&self.group_key, m_r, &sigma_r) {
            return Err(FinalizeError::SignatureInvalid);
        }
        Ok(())
    }
}

/// Why a round combine failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CombineError {
    /// Fewer than `T` of the supplied partials individually verified (draft §4.3).
    #[error("insufficient valid partials: need {need}, got {got}")]
    InsufficientValidPartials {
        /// Threshold `T`.
        need: usize,
        /// Valid partials available.
        got: usize,
    },
    /// The adapter's exactly-`T` combine failed (e.g. duplicate evaluation point).
    #[error("combine failed: {0}")]
    Crypto(sumchain_beacon_crypto::BeaconCryptoError),
}
