//! Proof Eligibility Registry — chain-side, register-only (v1).
//!
//! A governed registry of *proof profiles* eligible to be referenced on
//! mainnet. v1 is **register-only**: SUM Chain admits by exact proof-profile
//! identity match only. SUM Chain does not verify proof correctness for any
//! profile; OmniNode owns proof generation and verification correctness.
//!
//! The registry is **append-only**: records are never edited or deleted. A
//! state transition (`CandidateRefused` → `Active` → `Revoked`) is a new
//! record that supersedes the prior one *within the same* [`ProofProfileKey`].
//! Any field difference — including `backend_id`, `model_format`, or
//! `halo2_version` — is a *distinct profile* (the regeneration policy), so
//! superseding never crosses profile keys.
//!
//! v1 ships **mechanism-only**: [`REGISTRY`] is empty. The first
//! `Stage11dProductionFixedPointMlp` `CandidateRefused` record is a follow-up
//! once OmniNode delivers the evidence bundle (real `halo2_version`) and a
//! concrete governance `chain_team_review_ref` exists.
//!
//! This module is pure data + resolution helpers only: no tx type, no
//! verifier, no executor/mempool wiring, no economics. The activation gate
//! `proof_eligibility_enabled_from_height` is forward plumbing with **no
//! runtime consumer in v1** — see `docs/SUBPROTOCOLS/PROOF-ELIGIBILITY-REGISTRY.md`.

/// Verbatim statement every register-only proof profile carries.
pub const REGISTER_ONLY_DISCLAIMER: &str =
    "SUM Chain admits by exact proof-profile identity match only. SUM Chain does \
     not verify proof correctness for this profile; OmniNode owns proof \
     generation and verification correctness.";

/// Proof-system family. v1 has a single member; extensible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    Stage11dProductionFixedPointMlp,
}

impl ProofSystem {
    /// Stable identifier used at the RPC / docs boundary.
    pub fn as_str(self) -> &'static str {
        match self {
            ProofSystem::Stage11dProductionFixedPointMlp => "Stage11dProductionFixedPointMlp",
        }
    }
}

/// Eligibility state of a single registry record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityState {
    /// Dry-run: an observable candidate; proofs referencing it are refused.
    CandidateRefused,
    /// Eligible: proofs referencing the profile are admitted (subject to gate).
    Active,
    /// Withdrawn: proofs referencing the profile are refused.
    Revoked,
}

impl EligibilityState {
    /// Stable identifier used at the RPC / docs boundary.
    pub fn as_str(self) -> &'static str {
        match self {
            EligibilityState::CandidateRefused => "CandidateRefused",
            EligibilityState::Active => "Active",
            EligibilityState::Revoked => "Revoked",
        }
    }
}

/// The full proof-profile identity tuple. Superseding is valid ONLY within one
/// `ProofProfileKey`: any field difference (including `backend_id`,
/// `model_format`, `halo2_version`) is a distinct profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofProfileKey<'a> {
    pub proof_system: ProofSystem,
    pub backend_id: &'a str,
    pub model_format: &'a str,
    pub circuit_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub verification_key_hash: [u8; 32],
    pub halo2_version: &'a str,
}

/// One append-only governance record. Internal type: typed `[u8; 32]` hashes,
/// **no serde** (the RPC DTO owns serialization). Never edited or deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofEligibilityRecord {
    pub entry_id: u32,
    pub supersedes_entry_id: Option<u32>,
    pub proof_system: ProofSystem,
    pub backend_id: &'static str,
    pub model_format: &'static str,
    pub circuit_id: [u8; 32],
    pub model_hash: [u8; 32],
    pub verification_key_hash: [u8; 32],
    pub halo2_version: &'static str,
    pub eligibility_state: EligibilityState,
    pub state_reason: &'static str,
    pub chain_team_review_ref: &'static str,
    pub note: &'static str,
}

impl ProofEligibilityRecord {
    /// The full identity tuple this record describes.
    pub fn profile_key(&self) -> ProofProfileKey<'_> {
        ProofProfileKey {
            proof_system: self.proof_system,
            backend_id: self.backend_id,
            model_format: self.model_format,
            circuit_id: self.circuit_id,
            model_hash: self.model_hash,
            verification_key_hash: self.verification_key_hash,
            halo2_version: self.halo2_version,
        }
    }
}

/// v1 ships **mechanism-only**: NO records. The first governed record (a
/// `CandidateRefused` profile for `Stage11dProductionFixedPointMlp`) lands in a
/// follow-up PR once `halo2_version` and a concrete `chain_team_review_ref` are
/// real — no placeholders. See module docs.
pub const REGISTRY: &[ProofEligibilityRecord] = &[];

/// All registry records (full append-only history).
pub fn all_records() -> &'static [ProofEligibilityRecord] {
    REGISTRY
}

/// Is `rec` the current (non-superseded) head for its profile? `true` iff no
/// other record **with the same `ProofProfileKey`** supersedes it. Cross-key
/// `supersedes_entry_id` pointers are ignored (invalid by the registry
/// contract — a regenerated artifact is a brand-new profile, never a supersede).
pub fn is_current(records: &[ProofEligibilityRecord], rec: &ProofEligibilityRecord) -> bool {
    let key = rec.profile_key();
    !records
        .iter()
        .any(|other| other.profile_key() == key && other.supersedes_entry_id == Some(rec.entry_id))
}

/// Resolve the current (non-superseded) record for an exact `ProofProfileKey`,
/// if any. Considers only records whose full identity tuple equals `key`.
pub fn current_record<'a>(
    records: &'a [ProofEligibilityRecord],
    key: &ProofProfileKey,
) -> Option<&'a ProofEligibilityRecord> {
    records
        .iter()
        .find(|rec| rec.profile_key() == *key && is_current(records, rec))
}

/// Register-only admission: a profile is admissible ONLY if its current record
/// is `Active` AND the activation gate is open at `current_height`.
/// `CandidateRefused` / `Revoked` are refused by construction. (v1 has no
/// runtime caller; this is the resolver the future `Active` path will use.)
pub fn is_admissible(
    rec: &ProofEligibilityRecord,
    enabled_from_height: Option<u64>,
    current_height: u64,
) -> bool {
    matches!(rec.eligibility_state, EligibilityState::Active)
        && matches!(enabled_from_height, Some(h) if current_height >= h)
}
