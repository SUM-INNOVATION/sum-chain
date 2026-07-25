//! Gate-closed signing primitives (draft §2.4, §4.3, §12).
//!
//! After a successful DKG ([`crate::dkg::DkgOutcome::Success`]), a
//! [`QualifiedEpoch`] holds the qualified dealers' commitments and the epoch group
//! key `PK_E`. It derives each participant's verification key `vk_j`, verifies
//! per-round partial signatures (with authenticated actor binding), performs the
//! exactly-`T` sorted Lagrange combine, and verifies a round's finalize carrier
//! (exactly-`T`, canonical, membership-valid witness). All pure crypto over the
//! adapter; no state mutation, no activation. The multi-round chaining/state machine
//! that drives these lives in [`crate::rounds`].

use sumchain_beacon_crypto::{
    aggregate_g1, combine, commitment_poly_eval, verify, verify_partial, G1Point, PartialSignature,
    PublicKey, Signature,
};

use crate::context::{BeaconPhase, ContextError, ExecContext};
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
    /// An authenticated-binding / membership / phase / cutoff violation.
    #[error("context violation: {0}")]
    Context(ContextError),
    /// `sigma_j` failed canonical / subgroup / infinity decode (draft §2.2).
    #[error("invalid partial signature encoding")]
    InvalidSignature,
    /// The per-participant verification key `vk_j` could not be derived.
    #[error("could not derive vk_j")]
    NoVerificationKey,
}

impl From<ContextError> for PartialError {
    fn from(e: ContextError) -> Self {
        PartialError::Context(e)
    }
}

/// Why a finalize carrier was rejected (draft §4.3, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalizeError {
    /// An authenticated-binding / membership / phase violation.
    #[error("context violation: {0}")]
    Context(ContextError),
    /// The witness is not exactly the threshold `T` long (draft §4.3 step 3).
    #[error("finalize witness length is not exactly T")]
    WitnessNotExactlyT,
    /// The witness is not strictly ascending — unsorted or duplicate (draft §4.1).
    #[error("finalize witness is not strictly ascending")]
    WitnessNotCanonical,
    /// A witness index is not a valid membership index (`>= n`).
    #[error("finalize witness index out of membership range")]
    WitnessIndexOutOfRange,
    /// `Sigma_r` failed canonical / subgroup / infinity decode (draft §2.2).
    #[error("invalid combined signature encoding")]
    InvalidSignature,
    /// `Sigma_r` did not verify under `PK_E` over `m_r` (draft §4.3).
    #[error("combined signature does not verify under PK_E")]
    SignatureInvalid,
}

impl From<ContextError> for FinalizeError {
    fn from(e: ContextError) -> Self {
        FinalizeError::Context(e)
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

impl QualifiedEpoch {
    /// Build the signing view from a successful DKG's qualified commitments + `PK_E`.
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

    /// The chain id this epoch runs under.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    /// The beacon epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// The validated parameters.
    pub fn params(&self) -> &BeaconParams {
        &self.params
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

    /// Pure crypto verification of one partial against its derived `vk_j` over `m_r`
    /// (draft §2.4). No context binding — used inside the combine and by the
    /// authenticated [`accept_partial`](Self::accept_partial).
    pub fn verify_partial_sig(
        &self,
        partial: &BeaconPartialV1,
        m_r: &[u8],
    ) -> Result<bool, PartialError> {
        let sig = Signature::from_compressed(&partial.sigma_j)
            .map_err(|_| PartialError::InvalidSignature)?;
        let vk_j = self.participant_vk(partial.j)?;
        let x_j = (partial.j as u64) + 1;
        Ok(verify_partial(&vk_j, m_r, &PartialSignature::new(x_j, sig)))
    }

    /// Accept a partial under an authenticated context: enforce chain/epoch, signing
    /// phase, partial signer ↔ `j`, index `< n`, then the crypto verify.
    pub fn accept_partial(
        &self,
        ctx: &ExecContext,
        partial: &BeaconPartialV1,
        m_r: &[u8],
    ) -> Result<bool, PartialError> {
        ctx.check_chain_epoch(partial.chain_id, partial.epoch)?;
        ctx.check_phase(BeaconPhase::Signing)?;
        ctx.check_signer_is(partial.j)?; // partial signer ↔ j
        ctx.check_index(partial.j)?;
        self.verify_partial_sig(partial, m_r)
    }

    /// Verify a batch of partials and **exactly-`T` sorted Lagrange combine** them
    /// (draft §4.3). Only partials that individually verify (§2.4) enter the
    /// interpolation; the combine selects exactly the first `T` after sorting. Errors
    /// if fewer than `T` valid partials.
    pub fn combine_round(
        &self,
        partials: &[BeaconPartialV1],
        m_r: &[u8],
    ) -> Result<Signature, CombineError> {
        let mut valid: Vec<PartialSignature> = Vec::with_capacity(partials.len());
        for p in partials {
            match self.verify_partial_sig(p, m_r) {
                Ok(true) => {
                    let sig = Signature::from_compressed(&p.sigma_j)
                        .expect("verify_partial_sig already decoded sigma_j");
                    valid.push(PartialSignature::new((p.j as u64) + 1, sig));
                }
                Ok(false) | Err(_) => continue,
            }
        }
        if valid.len() < self.params.t() as usize {
            return Err(CombineError::InsufficientValidPartials {
                need: self.params.t() as usize,
                got: valid.len(),
            });
        }
        combine(&valid).map_err(CombineError::Crypto)
    }

    /// Verify a `BeaconFinalizeV1` under an authenticated context (draft §4.3, §12):
    /// signing phase; witness exactly `T`, strictly ascending (canonical §4.1), and
    /// every index a valid membership index; `Sigma_r` verifies under `PK_E` over
    /// `m_r`.
    pub fn verify_finalize(
        &self,
        ctx: &ExecContext,
        finalize: &BeaconFinalizeV1,
        m_r: &[u8],
    ) -> Result<(), FinalizeError> {
        ctx.check_chain_epoch(finalize.chain_id, finalize.epoch)?;
        ctx.check_phase(BeaconPhase::Signing)?;
        if finalize.witness.len() != self.params.t() as usize {
            return Err(FinalizeError::WitnessNotExactlyT);
        }
        if !finalize.witness.windows(2).all(|w| w[0] < w[1]) {
            return Err(FinalizeError::WitnessNotCanonical);
        }
        for &idx in &finalize.witness {
            if !ctx.membership.contains_index(idx) {
                return Err(FinalizeError::WitnessIndexOutOfRange);
            }
        }
        let sigma_r = Signature::from_compressed(&finalize.sigma_r)
            .map_err(|_| FinalizeError::InvalidSignature)?;
        if !verify(&self.group_key, m_r, &sigma_r) {
            return Err(FinalizeError::SignatureInvalid);
        }
        Ok(())
    }

    /// Crypto-only finalize check (no context) — used by [`crate::rounds`] once the
    /// round context has already been enforced by the caller. Same witness + pairing
    /// checks as [`verify_finalize`](Self::verify_finalize) minus the context guards.
    pub fn verify_finalize_sig(
        &self,
        finalize: &BeaconFinalizeV1,
        n: u32,
        m_r: &[u8],
    ) -> Result<Signature, FinalizeError> {
        if finalize.witness.len() != self.params.t() as usize {
            return Err(FinalizeError::WitnessNotExactlyT);
        }
        if !finalize.witness.windows(2).all(|w| w[0] < w[1]) {
            return Err(FinalizeError::WitnessNotCanonical);
        }
        for &idx in &finalize.witness {
            if idx >= n {
                return Err(FinalizeError::WitnessIndexOutOfRange);
            }
        }
        let sigma_r = Signature::from_compressed(&finalize.sigma_r)
            .map_err(|_| FinalizeError::InvalidSignature)?;
        if !verify(&self.group_key, m_r, &sigma_r) {
            return Err(FinalizeError::SignatureInvalid);
        }
        Ok(sigma_r)
    }
}
