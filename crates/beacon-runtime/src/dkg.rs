//! Gate-closed DKG **setup** state machine (draft §2.3, §4.2, §5, §6, §8).
//!
//! One [`DkgEpoch`] accumulates the on-chain epoch-setup facts — key registrations,
//! deals, and the objective verdicts of adjudicated complaints — and then
//! deterministically determines the qualified set `QUAL` and, on success, the epoch
//! group key `PK_E` ([`DkgEpoch::finalize`]). Every method is a pure function of
//! already-accepted on-chain data plus the crypto adapter; there is no vote, no
//! clock, and no RNG (draft §6.1 "a pure function of on-chain data").
//!
//! This mutates only the runtime's **own** in-memory epoch object; it flips no gate,
//! writes no chain state, and requires no activation (see the crate docs).

use std::collections::{BTreeMap, BTreeSet};

use sumchain_beacon_crypto::{
    aggregate_g1, dleq_verify, ecies_open, feldman_check, pop_verify, BeaconCryptoError,
    DleqContext, DleqProof, EciesContext, G1Point, Pop, PublicKey,
};
use sumchain_wire::beacon_wire::{DkgComplaintV1, DkgDealV1, RegisterBeaconKeyV1};

use crate::params::BeaconParams;

/// Static configuration for one beacon epoch's DKG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgConfig {
    /// Chain id — every carrier and transcript binds it (replay separation).
    pub chain_id: u64,
    /// The beacon epoch this DKG runs for.
    pub epoch: u64,
    /// Threshold / fault parameters (draft §1.2 — PROPOSED, see [`BeaconParams`]).
    pub params: BeaconParams,
}

/// Why a setup carrier was not accepted into the epoch state. All variants are
/// deterministic, objective, and carry no penalty by themselves (penalties are the
/// verdict of [`DkgEpoch::adjudicate`], not of a rejected submission).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// The carrier's `chain_id` or `epoch` does not match this DKG.
    #[error("carrier chain_id/epoch does not match this epoch")]
    WrongEpoch,
    /// A G1/G2 field failed the crypto adapter's canonical / subgroup / infinity
    /// decode (draft §2.2) — well-framed bytes, invalid crypto.
    #[error("invalid group element: {0}")]
    InvalidElement(BeaconCryptoError),
    /// A `RegisterBeaconKeyV1` proof-of-possession did not verify (draft §2.3).
    #[error("proof-of-possession failed to verify")]
    PopInvalid,
    /// A second, different registration for a validator index already keyed this
    /// epoch (K-rotate: one key per `(chain, validator, epoch)`, draft §11).
    #[error("duplicate key registration for this validator index")]
    DuplicateRegistration,
}

impl From<BeaconCryptoError> for SetupError {
    fn from(e: BeaconCryptoError) -> Self {
        SetupError::InvalidElement(e)
    }
}

/// The outcome of submitting a deal (draft §8.4 replay/duplication rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DealOutcome {
    /// A new, well-formed `(i, j)` deal record was accepted.
    Accepted,
    /// A byte-identical resubmission of an already-accepted `(i, j)` deal — dropped,
    /// no state effect (draft §8.4).
    Duplicate,
    /// A *different* deal for an already-seen `(i, j)` tuple, or a dealer whose
    /// commitment vector disagrees with its earlier deals — objective misconduct:
    /// the dealer is disqualified (draft §8.4 conflicting deal, §6.4).
    ConflictingDeal,
}

/// The four objective complaint verdicts (draft §6.1). Adjudication is deterministic
/// and idempotent; only the *first* adjudicated verdict for an `(i, j)` pair has
/// state effect ([`DkgEpoch::apply_complaint`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The complaint's DLEQ did not verify — the complaint is invalid and has **no
    /// effect on the dealer** (may be charged as spam; draft §6.1/§6.4).
    RejectComplaintMalformed,
    /// The ciphertext did not open under the DLEQ-proven secret, or opened to a
    /// non-canonical scalar — conclusive dealer misconduct, `DISQUALIFY(i)`
    /// (draft §6.1, §8.8 rule 5).
    Disqualify,
    /// The share opened and passed the Feldman check — the dealing was valid, so the
    /// complaint is false: `SLASH_FALSE_ACCUSER(j)` (draft §6.1/§6.4).
    SlashFalseAccuser,
    /// The share opened cleanly but failed the Feldman check — the dealing is
    /// invalid: `DISQUALIFY_AND_SLASH(i)` (draft §6.1).
    DisqualifyAndSlash,
}

/// A complaint that cannot be adjudicated because a referenced on-chain fact is
/// absent (not a verdict — there is nothing to decide).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotAdjudicable {
    /// No accepted deal exists for the complaint's `(i, j)` pair.
    #[error("no accepted deal for the complained (dealer, recipient) pair")]
    NoDeal,
    /// The recipient `j` has no registered encryption key this epoch.
    #[error("no registered encryption key for the recipient")]
    NoRecipientKey,
    /// The complaint's `chain_id`/`epoch` does not match this DKG.
    #[error("complaint chain_id/epoch does not match this epoch")]
    WrongEpoch,
}

/// Result of applying a complaint to the epoch state: the recomputed [`Verdict`] and
/// whether it changed state (idempotence — draft §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComplaintOutcome {
    /// The deterministic verdict (identical for every honest validator).
    pub verdict: Verdict,
    /// `false` if this `(i, j)` was already adjudicated — the verdict is recomputed
    /// but has no additional state effect (no double-jeopardy, draft §6.6).
    pub state_changed: bool,
}

/// A single accepted `(dealer i → recipient j)` deal record (the validated,
/// decoded form of a [`DkgDealV1`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct DealRecord {
    r_ij: G1Point,
    ct_ij: [u8; sumchain_beacon_crypto::ECIES_CT_LEN],
}

/// The result of DKG finalization (draft §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgOutcome {
    /// `|QUAL| ≥ Q_dkg`: the DKG succeeded. `qual` is the qualified dealer set sorted
    /// ascending by membership index (draft §4.1 canonical order); `group_key` is
    /// `PK_E = Σ_{i∈QUAL} C_{i,0}`.
    Success {
        /// Qualified dealer indices, ascending (canonical, draft §4.1).
        qual: Vec<u32>,
        /// The epoch group public key `PK_E` (draft §4.2).
        group_key: PublicKey,
    },
    /// `|QUAL| < Q_dkg`: the DKG **safe-halts**, producing no key (draft §4.2,
    /// Option-1). This is the correct, non-biased failure mode, never a fallback.
    SafeHalt {
        /// The number of qualified (non-disqualified) dealers.
        qualified: usize,
        /// The required `Q_dkg` threshold.
        required: usize,
    },
}

/// The gate-closed DKG **setup** epoch state machine.
#[derive(Clone, Debug)]
pub struct DkgEpoch {
    cfg: DkgConfig,
    /// Registered epoch encryption keys `EK_j`, by 0-based validator index `j`.
    keys: BTreeMap<u32, G1Point>,
    /// Each dealer's Feldman commitment vector `C_{i,*}` (its single polynomial).
    dealer_commitments: BTreeMap<u32, Vec<G1Point>>,
    /// Accepted deals, keyed by the `(dealer i, recipient j)` identity tuple.
    deals: BTreeMap<(u32, u32), DealRecord>,
    /// Dealers disqualified by an adjudicated verdict or a conflicting deal.
    disqualified: BTreeSet<u32>,
    /// Recipients slashed for a proven false accusation.
    false_accusers: BTreeSet<u32>,
    /// `(i, j)` pairs already adjudicated (for idempotence, draft §6.6).
    adjudicated: BTreeSet<(u32, u32)>,
}

impl DkgEpoch {
    /// Start an empty DKG epoch under `cfg`.
    pub fn new(cfg: DkgConfig) -> Self {
        DkgEpoch {
            cfg,
            keys: BTreeMap::new(),
            dealer_commitments: BTreeMap::new(),
            deals: BTreeMap::new(),
            disqualified: BTreeSet::new(),
            false_accusers: BTreeSet::new(),
            adjudicated: BTreeSet::new(),
        }
    }

    /// The static configuration for this epoch.
    pub fn config(&self) -> &DkgConfig {
        &self.cfg
    }

    /// The disqualified dealer set (draft §4.2 `QUAL` complement).
    pub fn disqualified(&self) -> &BTreeSet<u32> {
        &self.disqualified
    }

    /// The recipients slashed for false accusation (draft §6.4).
    pub fn false_accusers(&self) -> &BTreeSet<u32> {
        &self.false_accusers
    }

    // -- Setup phase ---------------------------------------------------------

    /// Process a `RegisterBeaconKeyV1` for validator `validator_index` (the tx
    /// signer's 0-based membership index, supplied by the enclosing envelope — the
    /// payload itself carries only chain/epoch/key/PoP, draft §11).
    ///
    /// Enforces the draft §2.3 registration checks the wire layer defers to #127:
    /// canonical/subgroup/infinity decode of `EK_j`, decode of the PoP, and
    /// `PopVerify` (pairing). Stores `EK_j` on success.
    pub fn register_key(
        &mut self,
        validator_index: u32,
        reg: &RegisterBeaconKeyV1,
    ) -> Result<(), SetupError> {
        if reg.chain_id != self.cfg.chain_id || reg.epoch != self.cfg.epoch {
            return Err(SetupError::WrongEpoch);
        }
        let ek = G1Point::from_compressed(&reg.ek_j)?;
        let pop = Pop::from_compressed(&reg.pop)?;
        if !pop_verify(&PublicKey::from_g1_point(ek), &pop) {
            return Err(SetupError::PopInvalid);
        }
        if let Some(existing) = self.keys.get(&validator_index) {
            // Idempotent re-registration of the identical key is a no-op; a different
            // key for the same validator this epoch is forbidden (K-rotate, §11).
            if *existing == ek {
                return Ok(());
            }
            return Err(SetupError::DuplicateRegistration);
        }
        self.keys.insert(validator_index, ek);
        Ok(())
    }

    /// The registered encryption key `EK_j` for validator `j`, if any.
    pub fn registered_key(&self, j: u32) -> Option<&G1Point> {
        self.keys.get(&j)
    }

    /// Process a `DkgDealV1`. Validates the commitments + carrier (canonical /
    /// subgroup / infinity, draft §2.2) and applies the §8.4 replay / conflicting-deal
    /// rules; a conflicting deal disqualifies the dealer.
    pub fn submit_deal(&mut self, deal: &DkgDealV1) -> Result<DealOutcome, SetupError> {
        if deal.chain_id != self.cfg.chain_id || deal.epoch != self.cfg.epoch {
            return Err(SetupError::WrongEpoch);
        }

        // Full crypto decode of every G1 field (the wire layer only flag-checked).
        let mut commitments = Vec::with_capacity(deal.commitments.len());
        for c in &deal.commitments {
            commitments.push(G1Point::from_compressed(c)?);
        }
        let r_ij = G1Point::from_compressed(&deal.r_ij)?;
        let key = (deal.dealer_i, deal.recipient_j);
        let record = DealRecord {
            r_ij,
            ct_ij: deal.ct_ij,
        };

        // §8.4 identity-tuple replay: at most one deal per (i, j).
        if let Some(existing) = self.deals.get(&key) {
            if *existing == record {
                return Ok(DealOutcome::Duplicate);
            }
            // Conflicting deal for the same tuple ⇒ objective misconduct.
            self.disqualified.insert(deal.dealer_i);
            return Ok(DealOutcome::ConflictingDeal);
        }

        // A dealer has ONE polynomial: all its deals must carry the same commitments.
        match self.dealer_commitments.get(&deal.dealer_i) {
            Some(existing) if *existing != commitments => {
                self.disqualified.insert(deal.dealer_i);
                return Ok(DealOutcome::ConflictingDeal);
            }
            Some(_) => {}
            None => {
                self.dealer_commitments.insert(deal.dealer_i, commitments);
            }
        }

        self.deals.insert(key, record);
        Ok(DealOutcome::Accepted)
    }

    // -- Complaint adjudication (draft §5, §6.1) -----------------------------

    /// Adjudicate a complaint — a **pure** function of on-chain data (draft §6.1). No
    /// state mutation; returns the deterministic [`Verdict`] every honest validator
    /// computes, or [`NotAdjudicable`] if a referenced fact is absent.
    ///
    /// Pipeline (draft §6.1, §9.1): DLEQ verify (§5.5) over the on-chain carrier and
    /// registered key ⇒ ECIES open of `ct_{ij}` under the DLEQ-pinned `D_{ij}` (§8) ⇒
    /// Feldman check of the recovered share (§6.2).
    pub fn adjudicate(&self, complaint: &DkgComplaintV1) -> Result<Verdict, NotAdjudicable> {
        if complaint.chain_id != self.cfg.chain_id || complaint.epoch != self.cfg.epoch {
            return Err(NotAdjudicable::WrongEpoch);
        }
        let deal = self
            .deals
            .get(&(complaint.i, complaint.j))
            .ok_or(NotAdjudicable::NoDeal)?;
        let commitments = self
            .dealer_commitments
            .get(&complaint.i)
            .ok_or(NotAdjudicable::NoDeal)?;
        let ek_j = *self
            .keys
            .get(&complaint.j)
            .ok_or(NotAdjudicable::NoRecipientKey)?;

        // The complaint's D_ij / (c, z) must pass §2.2 + canonical-scalar decode; an
        // undecodable statement/proof is a malformed complaint (§5.5 step 1, §6.1).
        let d_ij = match G1Point::from_compressed(&complaint.d_ij) {
            Ok(p) => p,
            Err(_) => return Ok(Verdict::RejectComplaintMalformed),
        };
        // The complaint must reference the deal's carrier R_ij (the authenticated,
        // dealer-signed one, draft §9.1); otherwise it does not correspond to the
        // on-chain deal and is malformed.
        if complaint.r_ij != deal.r_ij.to_compressed() {
            return Ok(Verdict::RejectComplaintMalformed);
        }
        let proof = {
            let mut cz = [0u8; 2 * sumchain_beacon_crypto::SCALAR_SIZE];
            cz[..sumchain_beacon_crypto::SCALAR_SIZE].copy_from_slice(&complaint.dleq_c);
            cz[sumchain_beacon_crypto::SCALAR_SIZE..].copy_from_slice(&complaint.dleq_z);
            match DleqProof::from_bytes(&cz) {
                Ok(p) => p,
                Err(_) => return Ok(Verdict::RejectComplaintMalformed),
            }
        };

        let dleq_ctx = DleqContext {
            chain_id: self.cfg.chain_id.to_le_bytes().to_vec(),
            epoch: self.cfg.epoch,
            dealer_index: complaint.i,
            recipient_index: complaint.j,
        };
        let h = G1Point::generator();
        // §5.5: DLEQ fail ⇒ REJECT_COMPLAINT_MALFORMED (no effect on the dealer).
        if !dleq_verify(&dleq_ctx, &h, &ek_j, &deal.r_ij, &d_ij, &proof) {
            return Ok(Verdict::RejectComplaintMalformed);
        }

        // §8: open ct_ij under the DLEQ-pinned D_ij. Open failure OR a non-canonical
        // recovered scalar ⇒ DISQUALIFY(i) (§6.1, §8.8 rule 5).
        let ecies_ctx = EciesContext {
            chain_id: self.cfg.chain_id,
            epoch: self.cfg.epoch,
            dealer_i: complaint.i,
            recipient_j: complaint.j,
            r_ij: deal.r_ij,
            ek_j,
        };
        let share = match ecies_open(&d_ij, &ecies_ctx, &deal.ct_ij) {
            Ok(s) => s,
            Err(BeaconCryptoError::AeadOpenFailed) | Err(BeaconCryptoError::NonCanonicalScalar) => {
                return Ok(Verdict::Disqualify)
            }
            // No other error is reachable from ecies_open; treat defensively as dealer
            // fault rather than panicking on an impossible variant.
            Err(_) => return Ok(Verdict::Disqualify),
        };

        // §6.2 Feldman: share consistent with commitments ⇒ the complaint was false;
        // inconsistent ⇒ the dealing is invalid.
        let x_j = (complaint.j as u64) + 1; // draft §3: x_j = j + 1
        match feldman_check(commitments, x_j, &share) {
            Ok(true) => Ok(Verdict::SlashFalseAccuser),
            Ok(false) => Ok(Verdict::DisqualifyAndSlash),
            Err(_) => Ok(Verdict::Disqualify),
        }
    }

    /// Adjudicate and **apply** a complaint's verdict to the epoch state, enforcing
    /// idempotence (draft §6.6): only the first verdict for an `(i, j)` pair mutates
    /// state; later duplicates recompute the identical verdict with no further effect.
    pub fn apply_complaint(
        &mut self,
        complaint: &DkgComplaintV1,
    ) -> Result<ComplaintOutcome, NotAdjudicable> {
        let verdict = self.adjudicate(complaint)?;
        let pair = (complaint.i, complaint.j);
        if self.adjudicated.contains(&pair) {
            return Ok(ComplaintOutcome {
                verdict,
                state_changed: false,
            });
        }
        self.adjudicated.insert(pair);
        match verdict {
            Verdict::RejectComplaintMalformed => {
                // No effect on the dealer; a malformed complaint changes no penalty
                // state (may be charged spam-fee by the executor — not modelled here).
                // Un-mark so a later, well-formed complaint on the same pair can still
                // be adjudicated with effect.
                self.adjudicated.remove(&pair);
                return Ok(ComplaintOutcome {
                    verdict,
                    state_changed: false,
                });
            }
            Verdict::Disqualify | Verdict::DisqualifyAndSlash => {
                self.disqualified.insert(complaint.i);
            }
            Verdict::SlashFalseAccuser => {
                self.false_accusers.insert(complaint.j);
            }
        }
        Ok(ComplaintOutcome {
            verdict,
            state_changed: true,
        })
    }

    // -- Finalization (draft §4.2) — deterministic, carrier-free ------------

    /// Determine `QUAL` and, on success, the epoch group key `PK_E` (draft §4.2).
    /// `QUAL` = dealers that dealt at least once and are not disqualified, sorted
    /// ascending (canonical, §4.1). Succeeds iff `|QUAL| ≥ Q_dkg`, else safe-halts.
    ///
    /// This is a **deterministic state transition, not a carrier** (there is no
    /// finalize-DKG transaction — every validator recomputes the identical result).
    pub fn finalize(&self) -> DkgOutcome {
        let mut qual: Vec<u32> = self
            .dealer_commitments
            .keys()
            .copied()
            .filter(|i| !self.disqualified.contains(i))
            .collect();
        qual.sort_unstable();

        let required = self.cfg.params.q_dkg as usize;
        if qual.len() < required {
            return DkgOutcome::SafeHalt {
                qualified: qual.len(),
                required,
            };
        }

        // PK_E = Σ_{i∈QUAL} C_{i,0} (constant terms, canonical QUAL order).
        let constants: Vec<G1Point> = qual.iter().map(|i| self.dealer_commitments[i][0]).collect();
        match aggregate_g1(&constants) {
            Ok(pk) => DkgOutcome::Success {
                qual,
                group_key: PublicKey::from_g1_point(pk),
            },
            // A group key summing to the identity is degenerate ⇒ safe-halt, never a
            // usable key (§2.2 infinity rule applied to PK_E).
            Err(_) => DkgOutcome::SafeHalt {
                qualified: qual.len(),
                required,
            },
        }
    }

    /// Test-only: force-disqualify a dealer, to drive QUAL safe-halt scenarios
    /// without crafting a full bad-deal + complaint for every dealer.
    #[cfg(test)]
    pub fn disqualify_for_test(&mut self, dealer: u32) {
        self.disqualified.insert(dealer);
    }

    /// The QUAL dealers' commitment vectors, ascending by dealer index — the input
    /// the signing phase needs to derive per-participant verification keys `vk_j`
    /// ([`crate::signing::QualifiedEpoch`]). `None` if the DKG did not succeed.
    pub fn qualified_commitments(&self) -> Option<Vec<(u32, Vec<G1Point>)>> {
        match self.finalize() {
            DkgOutcome::Success { qual, .. } => Some(
                qual.into_iter()
                    .map(|i| (i, self.dealer_commitments[&i].clone()))
                    .collect(),
            ),
            DkgOutcome::SafeHalt { .. } => None,
        }
    }
}
