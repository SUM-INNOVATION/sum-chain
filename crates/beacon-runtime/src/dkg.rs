//! Gate-closed DKG **setup** state machine (draft §2.3, §4.2, §5, §6, §8).
//!
//! One [`DkgEpoch`] accumulates the on-chain epoch-setup facts — key registrations,
//! deals, and the objective verdicts of adjudicated complaints — under an
//! **authenticated** [`ExecContext`] (signer identity, epoch membership snapshot,
//! phase, cutoffs), and then deterministically determines `QUAL` and, on success,
//! the epoch group key `PK_E` ([`DkgEpoch::finalize`]). Every method is a pure
//! function of already-accepted on-chain data plus the crypto adapter; there is no
//! vote, no clock, and no RNG (draft §6.1 "a pure function of on-chain data").
//!
//! This mutates only the runtime's **own** in-memory epoch object; it flips no gate,
//! writes no chain state, and requires no activation (see the crate docs).

use std::collections::{BTreeMap, BTreeSet};

use sumchain_beacon_crypto::{
    aggregate_g1, dleq_verify, ecies_open, feldman_check, pop_verify, BeaconCryptoError,
    DleqContext, DleqProof, EciesContext, G1Point, Pop, PublicKey,
};
use sumchain_wire::beacon_wire::{DkgComplaintV1, DkgDealV1, RegisterBeaconKeyV1};

use crate::context::{BeaconPhase, ContextError, ExecContext, ValidatorId};
use crate::params::BeaconParams;

/// Static configuration for one beacon epoch's DKG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DkgConfig {
    /// Chain id — every carrier and transcript binds it (replay separation).
    pub chain_id: u64,
    /// The beacon epoch this DKG runs for.
    pub epoch: u64,
    /// Validated threshold / fault parameters (draft §1.2/§7.4 — see [`BeaconParams`]).
    pub params: BeaconParams,
}

/// Why a setup carrier was not accepted into the epoch state. All variants are
/// deterministic and objective; penalties are the verdict of
/// [`DkgEpoch::adjudicate`] or an equivocation record, not of a rejected submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    /// An authenticated-binding / membership / phase / cutoff violation (draft §1.3,
    /// §8.2, §11) — the actor-binding checks #164 deferred.
    #[error("context violation: {0}")]
    Context(ContextError),
    /// The epoch membership snapshot size disagrees with the configured `n`.
    #[error("membership snapshot n={snapshot_n} != params n={params_n}")]
    MembershipSizeMismatch { snapshot_n: u32, params_n: u32 },
    /// A G1/G2 field failed the crypto adapter's canonical / subgroup / infinity
    /// decode (draft §2.2) — well-framed bytes, invalid crypto.
    #[error("invalid group element: {0}")]
    InvalidElement(BeaconCryptoError),
    /// A `RegisterBeaconKeyV1` proof-of-possession did not verify (draft §2.3).
    #[error("proof-of-possession failed to verify")]
    PopInvalid,
    /// The deal's Feldman commitment count is not exactly the threshold `T`
    /// (draft §1.2/§4.3 — each deal carries `T` commitments).
    #[error("commitment count {got} != threshold T={expected}")]
    CommitmentCountMismatch { got: usize, expected: u32 },
    /// A validated carrier could not be canonically re-encoded for evidence
    /// retention (should not occur for a decoded value).
    #[error("could not canonicalize carrier for evidence retention")]
    EvidenceEncode,
}

impl From<ContextError> for SetupError {
    fn from(e: ContextError) -> Self {
        SetupError::Context(e)
    }
}
impl From<BeaconCryptoError> for SetupError {
    fn from(e: BeaconCryptoError) -> Self {
        SetupError::InvalidElement(e)
    }
}

/// The outcome of a key registration (draft §11) — replay and equivocation are
/// **distinct events** (finding 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationOutcome {
    /// A fresh, PoP-valid key was accepted for this validator index.
    Accepted,
    /// A byte-identical re-registration of the already-accepted key — idempotent
    /// no-op (draft §11 keys are per `(chain, validator, epoch)`; replay is benign).
    DuplicateReplay,
    /// A **different** PoP-valid key for an already-keyed validator this epoch —
    /// objective key equivocation. The two conflicting signed records are RETAINED
    /// as evidence ([`KeyEquivocationEvidence`]); the first-included key stays
    /// authoritative (deterministic), and the equivocating validator is recorded.
    Equivocation(KeyEquivocationEvidence),
}

/// An **authenticated** reference to one signed carrier retained as equivocation
/// evidence (Item 3): the signer's epoch identity, the hash of its signed
/// transaction envelope (`tx_ref`), and the canonical carrier bytes. A stored
/// conflicting record is therefore individually attributable to a signed tx — not
/// merely an unsigned payload. (The envelope signature itself is verified by the
/// executor before the op reaches the runtime; the runtime retains the authenticated
/// `signer` + `tx_ref` that attribution produced.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecordRef {
    /// The authenticated signer identity (from the tx envelope).
    pub signer: ValidatorId,
    /// The 32-byte hash of the signed transaction envelope carrying this record.
    pub tx_ref: [u8; 32],
    /// The canonical carrier bytes the signed envelope carried.
    pub carrier: Vec<u8>,
}

/// Retained evidence of a key equivocation: the two conflicting **authenticated**
/// `RegisterBeaconKeyV1` records for the same validator index (draft §6.4, objective
/// misconduct). Each side carries the signer + tx envelope reference + canonical
/// bytes, so the evidence is individually attributable/authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEquivocationEvidence {
    /// The 0-based membership index that equivocated.
    pub validator_index: u32,
    /// The first (authoritative) authenticated registration.
    pub first: SignedRecordRef,
    /// The conflicting second authenticated registration.
    pub second: SignedRecordRef,
}

/// The outcome of submitting a deal (draft §8.4 replay/duplication rules).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DealOutcome {
    /// A new, well-formed `(i, j)` deal record was accepted.
    Accepted,
    /// A byte-identical resubmission of an already-accepted `(i, j)` deal — dropped,
    /// no state effect (draft §8.4).
    Duplicate,
    /// A *different* deal for an already-seen `(i, j)` tuple, or a dealer whose
    /// commitment vector disagrees with its earlier deals — objective misconduct:
    /// the dealer is disqualified and the two conflicting records are RETAINED as
    /// evidence ([`DealEquivocationEvidence`]) (draft §8.4, §6.4).
    ConflictingDeal(DealEquivocationEvidence),
}

/// Retained evidence of a conflicting deal: the two conflicting **authenticated**
/// `DkgDealV1` records sharing an identity (draft §8.4). Each side carries the signer
/// + tx envelope reference + canonical bytes (Item 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealEquivocationEvidence {
    /// The dealer index responsible.
    pub dealer_i: u32,
    /// The first (accepted) authenticated deal record.
    pub first: SignedRecordRef,
    /// The conflicting authenticated deal record.
    pub second: SignedRecordRef,
}

/// A rehydration failure (persisted rows → runtime). The only failure mode is a
/// persisted group element that no longer decodes under the §2.2 checks (corruption).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RehydrateError {
    /// A persisted G1 field failed canonical / subgroup / infinity decode.
    #[error("rehydrate: invalid persisted group element: {0}")]
    InvalidElement(BeaconCryptoError),
}

/// A read-only, persistable view of one accepted deal (Item 2 — the exact fields the
/// producer materializes into a store row). Points are canonical compressed bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealView {
    /// Dealer index `i`.
    pub dealer_i: u32,
    /// Recipient index `j`.
    pub recipient_j: u32,
    /// The dealer's Feldman commitments `C_{i,*}` (canonical compressed G1, 48B each).
    pub commitments: Vec<[u8; sumchain_beacon_crypto::G1_COMPRESSED_SIZE]>,
    /// ECIES carrier `R_{ij}` (canonical compressed G1, 48B).
    pub r_ij: [u8; sumchain_beacon_crypto::G1_COMPRESSED_SIZE],
    /// ECIES body `ct_{ij}` (48B).
    pub ct_ij: [u8; sumchain_beacon_crypto::ECIES_CT_LEN],
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
    /// non-canonical scalar — conclusive dealer misconduct, `DISQUALIFY(i)`.
    Disqualify,
    /// The share opened and passed Feldman — the dealing was valid, so the complaint
    /// is false: `SLASH_FALSE_ACCUSER(j)` (draft §6.1/§6.4).
    SlashFalseAccuser,
    /// The share opened cleanly but failed Feldman — the dealing is invalid:
    /// `DISQUALIFY_AND_SLASH(i)` (draft §6.1).
    DisqualifyAndSlash,
}

/// A complaint that cannot be adjudicated (draft §6.1) — either an authenticated
/// context violation, or a referenced on-chain fact is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdjudicateError {
    /// An authenticated-binding / membership / phase / cutoff violation.
    #[error("context violation: {0}")]
    Context(ContextError),
    /// No accepted deal exists for the complaint's `(i, j)` pair.
    #[error("no accepted deal for the complained (dealer, recipient) pair")]
    NoDeal,
    /// The recipient `j` has no registered encryption key this epoch.
    #[error("no registered encryption key for the recipient")]
    NoRecipientKey,
}

impl From<ContextError> for AdjudicateError {
    fn from(e: ContextError) -> Self {
        AdjudicateError::Context(e)
    }
}

/// Result of applying a complaint: the recomputed [`Verdict`] and whether it changed
/// state (idempotence — draft §6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComplaintOutcome {
    /// The deterministic verdict (identical for every honest validator).
    pub verdict: Verdict,
    /// `false` if this `(i, j)` was already adjudicated — recomputed, no new effect.
    pub state_changed: bool,
}

/// A registered epoch encryption key plus its **authenticated** signed-record
/// reference (signer + tx envelope hash + canonical bytes), retained so a later
/// equivocation can be proven and individually attributed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegisteredKey {
    ek: G1Point,
    record: SignedRecordRef,
}

/// A single accepted `(dealer i → recipient j)` deal record (validated), plus its
/// **authenticated** signed-record reference (retained for equivocation evidence).
#[derive(Clone, Debug, PartialEq, Eq)]
struct AcceptedDeal {
    r_ij: G1Point,
    ct_ij: [u8; sumchain_beacon_crypto::ECIES_CT_LEN],
    record: SignedRecordRef,
}

/// The result of DKG finalization (draft §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DkgOutcome {
    /// `|QUAL| ≥ Q_dkg`: the DKG succeeded. `qual` is ascending by membership index
    /// (draft §4.1); `group_key` is `PK_E = Σ_{i∈QUAL} C_{i,0}`.
    Success {
        /// Qualified dealer indices, ascending (canonical, draft §4.1).
        qual: Vec<u32>,
        /// The epoch group public key `PK_E` (draft §4.2).
        group_key: PublicKey,
    },
    /// `|QUAL| < Q_dkg`: the DKG **safe-halts**, producing no key (draft §4.2,
    /// Option-1) — the correct, non-biased failure mode, never a fallback.
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
    keys: BTreeMap<u32, RegisteredKey>,
    key_equivocations: Vec<KeyEquivocationEvidence>,
    dealer_commitments: BTreeMap<u32, Vec<G1Point>>,
    deals: BTreeMap<(u32, u32), AcceptedDeal>,
    deal_equivocations: Vec<DealEquivocationEvidence>,
    disqualified: BTreeSet<u32>,
    false_accusers: BTreeSet<u32>,
    adjudicated: BTreeSet<(u32, u32)>,
}

impl DkgEpoch {
    /// Start an empty DKG epoch under `cfg`.
    pub fn new(cfg: DkgConfig) -> Self {
        DkgEpoch {
            cfg,
            keys: BTreeMap::new(),
            key_equivocations: Vec::new(),
            dealer_commitments: BTreeMap::new(),
            deals: BTreeMap::new(),
            deal_equivocations: Vec::new(),
            disqualified: BTreeSet::new(),
            false_accusers: BTreeSet::new(),
            adjudicated: BTreeSet::new(),
        }
    }

    /// **Rehydrate** a DKG epoch from persisted state on restart (rows → runtime).
    /// The inverse of the store's materialization: `keys` are `(validator_index, EK_j
    /// compressed)`, `deals` are the persisted [`DealView`]s, and `disqualified` is
    /// the disqualified-dealer set. Group elements are re-decoded with the §2.2
    /// checks. Because the persisted rows do **not** carry the authenticated
    /// `SignedRecordRef` (signer + tx envelope hash) — only the essential consensus
    /// state — rehydrated records carry a NULL reference; a *new* equivocation in a
    /// later block still records a real reference for its own conflicting record, and
    /// `materialize` ignores the reference, so `materialize(rehydrate(rows)) == rows`
    /// exactly (the round-trip the per-block producer relies on).
    pub fn rehydrate(
        cfg: DkgConfig,
        keys: Vec<(u32, [u8; sumchain_beacon_crypto::G1_COMPRESSED_SIZE])>,
        deals: Vec<DealView>,
        disqualified: Vec<u32>,
    ) -> Result<Self, RehydrateError> {
        let null_ref = SignedRecordRef {
            signer: ValidatorId([0u8; 32]),
            tx_ref: [0u8; 32],
            carrier: Vec::new(),
        };
        let mut epoch = DkgEpoch::new(cfg);
        for (idx, ek) in keys {
            let ek = G1Point::from_compressed(&ek).map_err(RehydrateError::InvalidElement)?;
            epoch.keys.insert(
                idx,
                RegisteredKey {
                    ek,
                    record: null_ref.clone(),
                },
            );
        }
        for d in deals {
            let mut commitments = Vec::with_capacity(d.commitments.len());
            for c in &d.commitments {
                commitments
                    .push(G1Point::from_compressed(c).map_err(RehydrateError::InvalidElement)?);
            }
            let r_ij = G1Point::from_compressed(&d.r_ij).map_err(RehydrateError::InvalidElement)?;
            epoch
                .dealer_commitments
                .entry(d.dealer_i)
                .or_insert(commitments);
            epoch.deals.insert(
                (d.dealer_i, d.recipient_j),
                AcceptedDeal {
                    r_ij,
                    ct_ij: d.ct_ij,
                    record: null_ref.clone(),
                },
            );
        }
        for i in disqualified {
            epoch.disqualified.insert(i);
        }
        Ok(epoch)
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
    /// Retained key-equivocation evidence (draft §6.4).
    pub fn key_equivocations(&self) -> &[KeyEquivocationEvidence] {
        &self.key_equivocations
    }
    /// Retained conflicting-deal evidence (draft §8.4).
    pub fn deal_equivocations(&self) -> &[DealEquivocationEvidence] {
        &self.deal_equivocations
    }

    /// Enforce the invariant that the context's membership size equals `params.n`.
    fn check_membership_size(&self, ctx: &ExecContext) -> Result<(), SetupError> {
        let snap = ctx.membership.n();
        if snap != self.cfg.params.n() {
            return Err(SetupError::MembershipSizeMismatch {
                snapshot_n: snap,
                params_n: self.cfg.params.n(),
            });
        }
        Ok(())
    }

    // -- Setup phase ---------------------------------------------------------

    /// Process a `RegisterBeaconKeyV1` under an authenticated context (draft §2.3,
    /// §11). Enforces (before any crypto): chain/epoch match, setup phase, the signer
    /// being a member whose index equals the registrant's, register-before-cutoff.
    /// Then the §2.3 crypto: `EK_j` decode (canonical/subgroup/infinity), PoP decode,
    /// `PopVerify`. Replay vs equivocation is distinguished (finding 5).
    pub fn register_key(
        &mut self,
        ctx: &ExecContext,
        reg: &RegisterBeaconKeyV1,
    ) -> Result<RegistrationOutcome, SetupError> {
        self.check_membership_size(ctx)?;
        ctx.check_chain_epoch(reg.chain_id, reg.epoch)?;
        ctx.check_phase(BeaconPhase::Setup)?;
        // The signer must be the member the registration is *for* — its membership
        // index is the registrant's identity `j`.
        let validator_index = ctx
            .membership
            .index_of(&ctx.signer)
            .ok_or(ContextError::SignerNotMember)?;
        // Register-before-cutoff (draft §11 rule 3).
        if ctx.block_height > ctx.cutoffs.deal_cutoff {
            return Err(SetupError::Context(ContextError::CutoffViolation));
        }

        let ek = G1Point::from_compressed(&reg.ek_j)?;
        let pop = Pop::from_compressed(&reg.pop)?;
        if !pop_verify(&PublicKey::from_g1_point(ek), &pop) {
            return Err(SetupError::PopInvalid);
        }
        let raw = reg.try_encode().map_err(|_| SetupError::EvidenceEncode)?;
        // Authenticated record: signer + signed-tx-envelope hash + canonical bytes.
        let record = SignedRecordRef {
            signer: ctx.signer,
            tx_ref: ctx.tx_ref,
            carrier: raw,
        };

        match self.keys.get(&validator_index) {
            Some(existing) if existing.ek == ek => Ok(RegistrationOutcome::DuplicateReplay),
            Some(existing) => {
                // Distinct valid key for an already-keyed validator ⇒ equivocation.
                let evidence = KeyEquivocationEvidence {
                    validator_index,
                    first: existing.record.clone(),
                    second: record,
                };
                self.key_equivocations.push(evidence.clone());
                Ok(RegistrationOutcome::Equivocation(evidence))
            }
            None => {
                self.keys
                    .insert(validator_index, RegisteredKey { ek, record });
                Ok(RegistrationOutcome::Accepted)
            }
        }
    }

    // -- Persistable-state accessors (the PRODUCER materializes these into rows) --

    /// The accepted registered encryption keys as `(validator_index, EK_j
    /// compressed)`, ascending by index. The exact bytes the persistence layer
    /// materializes (Item 2).
    pub fn registered_keys(&self) -> Vec<(u32, [u8; sumchain_beacon_crypto::G1_COMPRESSED_SIZE])> {
        self.keys
            .iter()
            .map(|(idx, k)| (*idx, k.ek.to_compressed()))
            .collect()
    }

    /// The accepted deals as persistable views, ascending by `(dealer_i,
    /// recipient_j)`. `commitments` is the dealer's committed polynomial (repeated
    /// from `dealer_commitments`, so a deal row is self-contained).
    pub fn accepted_deals(&self) -> Vec<DealView> {
        self.deals
            .iter()
            .map(|((i, j), d)| DealView {
                dealer_i: *i,
                recipient_j: *j,
                commitments: self
                    .dealer_commitments
                    .get(i)
                    .map(|cs| cs.iter().map(|c| c.to_compressed()).collect())
                    .unwrap_or_default(),
                r_ij: d.r_ij.to_compressed(),
                ct_ij: d.ct_ij,
            })
            .collect()
    }

    /// The registered encryption key `EK_j` for validator `j`, if any.
    pub fn registered_key(&self, j: u32) -> Option<&G1Point> {
        self.keys.get(&j).map(|k| &k.ek)
    }

    /// Process a `DkgDealV1` under an authenticated context. Complete deal semantics
    /// (finding 4): chain/epoch match, setup phase, deal signer ↔ `dealer_i`, both
    /// indices `< n` (membership), cutoff, commitment count `== T`, canonical/subgroup
    /// decode of every G1 field, and the dealer's commitment vector IDENTICAL across
    /// all its recipients. Applies the §8.4 replay / conflicting-deal rules (with
    /// retained evidence).
    pub fn submit_deal(
        &mut self,
        ctx: &ExecContext,
        deal: &DkgDealV1,
    ) -> Result<DealOutcome, SetupError> {
        self.check_membership_size(ctx)?;
        ctx.check_chain_epoch(deal.chain_id, deal.epoch)?;
        ctx.check_phase(BeaconPhase::Setup)?;
        ctx.check_signer_is(deal.dealer_i)?; // deal signer ↔ dealer_i
        ctx.check_index(deal.dealer_i)?; // dealer membership (< n)
        ctx.check_index(deal.recipient_j)?; // recipient membership (< n)
        if ctx.block_height > ctx.cutoffs.deal_cutoff {
            return Err(SetupError::Context(ContextError::CutoffViolation));
        }
        // Commitment count == T (draft §1.2/§4.3).
        if deal.commitments.len() != self.cfg.params.t() as usize {
            return Err(SetupError::CommitmentCountMismatch {
                got: deal.commitments.len(),
                expected: self.cfg.params.t(),
            });
        }

        // Full crypto decode of every G1 field (the wire layer only flag-checked).
        let mut commitments = Vec::with_capacity(deal.commitments.len());
        for c in &deal.commitments {
            commitments.push(G1Point::from_compressed(c)?);
        }
        let r_ij = G1Point::from_compressed(&deal.r_ij)?;
        let raw = deal.try_encode().map_err(|_| SetupError::EvidenceEncode)?;
        let signed = SignedRecordRef {
            signer: ctx.signer,
            tx_ref: ctx.tx_ref,
            carrier: raw,
        };
        let key = (deal.dealer_i, deal.recipient_j);
        let record = AcceptedDeal {
            r_ij,
            ct_ij: deal.ct_ij,
            record: signed.clone(),
        };

        // §8.4 identity-tuple replay: at most one deal per (i, j).
        if let Some(existing) = self.deals.get(&key) {
            if existing.r_ij == record.r_ij && existing.ct_ij == record.ct_ij {
                return Ok(DealOutcome::Duplicate);
            }
            let evidence = DealEquivocationEvidence {
                dealer_i: deal.dealer_i,
                first: existing.record.clone(),
                second: signed,
            };
            self.deal_equivocations.push(evidence.clone());
            self.disqualified.insert(deal.dealer_i);
            return Ok(DealOutcome::ConflictingDeal(evidence));
        }

        // A dealer has ONE polynomial: all its deals must carry the same commitments.
        match self.dealer_commitments.get(&deal.dealer_i) {
            Some(existing) if *existing != commitments => {
                let first =
                    existing_deal_ref(&self.deals, deal.dealer_i).unwrap_or_else(|| signed.clone());
                let evidence = DealEquivocationEvidence {
                    dealer_i: deal.dealer_i,
                    first,
                    second: signed,
                };
                self.deal_equivocations.push(evidence.clone());
                self.disqualified.insert(deal.dealer_i);
                return Ok(DealOutcome::ConflictingDeal(evidence));
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

    /// Adjudicate a complaint under an authenticated context — a **pure** function of
    /// on-chain data (draft §6.1). Enforces (before crypto): chain/epoch, setup
    /// phase, complainant signer ↔ recipient `j`, both indices `< n`, complaint
    /// deadline. Then the DLEQ (§5.5) ⇒ ECIES-open (§8) ⇒ Feldman (§6.2) pipeline.
    pub fn adjudicate(
        &self,
        ctx: &ExecContext,
        complaint: &DkgComplaintV1,
    ) -> Result<Verdict, AdjudicateError> {
        ctx.check_chain_epoch(complaint.chain_id, complaint.epoch)?;
        ctx.check_phase(BeaconPhase::Setup)?;
        ctx.check_signer_is(complaint.j)?; // complainant ↔ recipient j
        ctx.check_index(complaint.i)?;
        ctx.check_index(complaint.j)?;
        if ctx.block_height > ctx.cutoffs.complaint_deadline {
            return Err(AdjudicateError::Context(ContextError::CutoffViolation));
        }

        let deal = self
            .deals
            .get(&(complaint.i, complaint.j))
            .ok_or(AdjudicateError::NoDeal)?;
        let commitments = self
            .dealer_commitments
            .get(&complaint.i)
            .ok_or(AdjudicateError::NoDeal)?;
        let ek_j = self
            .keys
            .get(&complaint.j)
            .map(|k| k.ek)
            .ok_or(AdjudicateError::NoRecipientKey)?;

        // The complaint's D_ij must pass §2.2 decode; else malformed (§5.5 step 1).
        let d_ij = match G1Point::from_compressed(&complaint.d_ij) {
            Ok(p) => p,
            Err(_) => return Ok(Verdict::RejectComplaintMalformed),
        };
        // Must reference the deal's authenticated carrier R_ij (draft §9.1).
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
        if !dleq_verify(&dleq_ctx, &h, &ek_j, &deal.r_ij, &d_ij, &proof) {
            return Ok(Verdict::RejectComplaintMalformed);
        }

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
            Err(_) => return Ok(Verdict::Disqualify),
        };

        let x_j = (complaint.j as u64) + 1; // draft §3: x_j = j + 1
        match feldman_check(commitments, x_j, &share) {
            Ok(true) => Ok(Verdict::SlashFalseAccuser),
            Ok(false) => Ok(Verdict::DisqualifyAndSlash),
            Err(_) => Ok(Verdict::Disqualify),
        }
    }

    /// Adjudicate and **apply** a complaint's verdict, enforcing idempotence
    /// (draft §6.6): only the first verdict for an `(i, j)` pair mutates state.
    pub fn apply_complaint(
        &mut self,
        ctx: &ExecContext,
        complaint: &DkgComplaintV1,
    ) -> Result<ComplaintOutcome, AdjudicateError> {
        let verdict = self.adjudicate(ctx, complaint)?;
        let pair = (complaint.i, complaint.j);
        if self.adjudicated.contains(&pair) {
            return Ok(ComplaintOutcome {
                verdict,
                state_changed: false,
            });
        }
        match verdict {
            Verdict::RejectComplaintMalformed => {
                // No effect; do not consume the pair (a later valid complaint on the
                // same pair may still adjudicate with effect).
                Ok(ComplaintOutcome {
                    verdict,
                    state_changed: false,
                })
            }
            Verdict::Disqualify | Verdict::DisqualifyAndSlash => {
                self.adjudicated.insert(pair);
                self.disqualified.insert(complaint.i);
                Ok(ComplaintOutcome {
                    verdict,
                    state_changed: true,
                })
            }
            Verdict::SlashFalseAccuser => {
                self.adjudicated.insert(pair);
                self.false_accusers.insert(complaint.j);
                Ok(ComplaintOutcome {
                    verdict,
                    state_changed: true,
                })
            }
        }
    }

    // -- Finalization (draft §4.2) — deterministic, carrier-free ------------

    /// Determine `QUAL` and, on success, the epoch group key `PK_E` (draft §4.2).
    /// `QUAL` = dealers that dealt at least once and are not disqualified, sorted
    /// ascending (§4.1). Succeeds iff `|QUAL| ≥ Q_dkg`, else safe-halts. A
    /// deterministic state transition, **not** a carrier.
    pub fn finalize(&self) -> DkgOutcome {
        let mut qual: Vec<u32> = self
            .dealer_commitments
            .keys()
            .copied()
            .filter(|i| !self.disqualified.contains(i))
            .collect();
        qual.sort_unstable();

        let required = self.cfg.params.q_dkg() as usize;
        if qual.len() < required {
            return DkgOutcome::SafeHalt {
                qualified: qual.len(),
                required,
            };
        }
        let constants: Vec<G1Point> = qual.iter().map(|i| self.dealer_commitments[i][0]).collect();
        match aggregate_g1(&constants) {
            Ok(pk) => DkgOutcome::Success {
                qual,
                group_key: PublicKey::from_g1_point(pk),
            },
            Err(_) => DkgOutcome::SafeHalt {
                qualified: qual.len(),
                required,
            },
        }
    }

    /// Test-only: force-disqualify a dealer, to drive QUAL safe-halt scenarios.
    #[cfg(test)]
    pub fn disqualify_for_test(&mut self, dealer: u32) {
        self.disqualified.insert(dealer);
    }

    /// The QUAL dealers' commitment vectors, ascending by dealer index — the input
    /// the signing phase needs to derive per-participant verification keys `vk_j`.
    /// `None` if the DKG did not succeed.
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

/// Fetch any accepted deal's authenticated record for dealer `i` (for cross-recipient
/// commitment-conflict evidence). Returns the first in canonical `(i, j)` order.
fn existing_deal_ref(
    deals: &BTreeMap<(u32, u32), AcceptedDeal>,
    dealer_i: u32,
) -> Option<SignedRecordRef> {
    deals
        .iter()
        .find(|((i, _j), _)| *i == dealer_i)
        .map(|(_, d)| d.record.clone())
}
