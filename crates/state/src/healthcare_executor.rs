//! SRC-87X Healthcare & Regulated Membership Executor
//!
//! Transaction executor for:
//! - SRC-871: Provider/Plan Registry Profile
//! - SRC-872: Coverage & Membership Status
//! - SRC-874: Consent & Disclosure Envelope
//! - SRC-875: 87X Proof Profiles
//! - SRC-876: Prescription Standard (NON-TRANSFERABLE for controlled substances)

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    healthcare::{
        ConsentEnvelope, ConsentStatus, HealthcareOperation, HealthcareProofEnvelope,
        HealthcareTxData, MembershipRecord, MembershipStatus, Prescription, PrescriptionStatus,
        ProviderProfile, ProviderStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Healthcare operation execution
#[derive(Debug)]
pub struct HealthcareExecutionResult {
    pub success: bool,
    pub provider_id: Option<[u8; 32]>,
    pub membership_id: Option<[u8; 32]>,
    pub consent_id: Option<[u8; 32]>,
    pub prescription_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl HealthcareExecutionResult {
    pub fn success_with_provider(provider_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: Some(provider_id),
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_membership(membership_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: Some(membership_id),
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_consent(consent_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: Some(consent_id),
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_prescription(prescription_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: Some(prescription_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            provider_id: None,
            membership_id: None,
            consent_id: None,
            prescription_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Healthcare executor for SRC-87X transactions
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::healthcare_store` for the RPC server, which answers about
/// the canonical chain.
///
/// The `ChainParams` the old constructor took was `#[allow(dead_code)]` and
/// consulted by nothing; it left with the database handle.
pub struct HealthcareExecutor;

/// The activation decisions a Healthcare transaction executes under.
///
/// [`HealthcareExecutor::execute`] derives it from `ChainParams`;
/// [`HealthcareExecutor::execute_with_gates`] takes it directly, which is how a
/// test drives an ungated node and a gated node over the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HealthcareGates {
    /// The subsystem's authorization rules are enforced. ACTIVATION-AUDIT rows
    /// AU-1, AU-2, AU-4, AU-5, the revocation half of AU-3, and OV-18.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// A write arm reads the row it is about to change before it decides.
    /// ACTIVATION-AUDIT rows OV-17 and OV-20.
    pub state_precondition: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT AU-6 (= PR-6). Supersedes the retired presence check: no
    /// verifier exists in this tree, so the operation cannot be performed
    /// and must not report success.
    pub proof_unsupported: bool,
    /// A transaction's sizing inputs are bounded before the value they size is
    /// built: the payload before it is deserialized, and the accumulating row
    /// an arm would append to before it is decoded.
    /// ACTIVATION-AUDIT rows AL-8 and the Healthcare third of AL-12.
    pub allocation_bound: bool,
}

impl HealthcareGates {
    /// Every gate closed -- the release configuration today, because the field
    /// these read does not exist in `ChainParams`.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        state_precondition: false,
        proof_unsupported: false,
        allocation_bound: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        state_precondition: true,
        proof_unsupported: true,
        allocation_bound: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: HealthcareExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            state_precondition: HealthcareExecutor::state_precondition_gate_open(
                params,
                block_height,
            ),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
        }
    }

    /// The stored-row length limit this gate imposes, or `None` when closed.
    ///
    /// `None` is what the bounded callers below treat as "no limit", so a
    /// closed gate reads byte-for-byte what the unbounded binary read. The
    /// same spelling `AgreementGates::row_limit` and `DocClassGates::row_limit`
    /// use, reading the same constant, because it is the same rule.
    #[inline]
    pub fn row_limit(self) -> Option<usize> {
        self.allocation_bound
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
    }
}

impl HealthcareExecutor {
    /// The activation height for the Healthcare authorization rules.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-87X Healthcare authorization rules. Dormant by default (`None`
    /// /// -> never open). Below the gate `SupersedeConsent`, `FillPrescription`
    /// /// and `PartialFillPrescription` check NOTHING about the sender;
    /// /// `AddNetworkAffiliation` and `RemoveNetworkAffiliation` check no
    /// /// issuer; `IssuePrescription` never relates the sender to the named
    /// /// prescriber; a consent's subject can neither revoke it; and a
    /// /// prescription authorizing zero refills is fillable once more because
    /// /// its guard is a conjunction. At and above the gate each of those is
    /// /// enforced and the refused transaction is a `Failed` receipt. Activation
    /// /// is a consensus change -- it changes which transactions succeed, and
    /// /// receipts are folded into the state root -- and needs a coordinated
    /// /// validator upgrade.
    /// #[serde(default)]
    /// pub healthcare_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and every pinning test that records the gap still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.healthcare_authorization_enabled_from_height
    }

    /// Whether the Healthcare authorization rules are active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the Healthcare state-precondition rules.
    ///
    /// Reads `params.healthcare_state_precondition_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-17 and OV-20) `RenewMembership`
    /// sets `status = Active` whatever the status was -- reviving a membership
    /// that was suspended, terminated or cancelled, and bypassing
    /// `ReinstateMembership`, which is the operation with a status guard on it
    /// -- and the two removal arms write the row and the index whether or not
    /// the thing being removed was ever there. At and above it renewal refuses
    /// those three statuses, and a removal with nothing to remove writes
    /// nothing, exactly as its `contains`-guarded add mirror does.
    #[inline]
    fn state_precondition_activation(params: &ChainParams) -> Option<u64> {
        params.healthcare_state_precondition_enabled_from_height
    }

    /// Whether the Healthcare state-precondition rules are active at
    /// `block_height`.
    #[inline]
    pub fn state_precondition_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::state_precondition_activation(params), Some(h) if block_height >= h)
    }

    /// Who may fill or partially fill a prescription, at the gate.
    ///
    /// Three addresses, and only three, because those are the only addresses a
    /// `Prescription` actually carries. The pharmacy is a `PartyRef`, not an
    /// address (`crates/sumchain-wire/src/healthcare.rs`), so a pharmacy cannot
    /// be authorized from the row as it stands -- recorded rather than papered
    /// over, because a rule that pretends to check a pharmacy and does not is
    /// worse than one that says it cannot.
    ///
    ///   * the patient the prescription names;
    ///   * the account that issued it;
    ///   * the issuer of the prescriber's provider row.
    fn may_fill(
        view: &ExecutionView<'_, '_>,
        prescription: &Prescription,
        sender: &Address,
    ) -> Result<bool> {
        if prescription.patient_address == *sender || prescription.issuer_address == *sender {
            return Ok(true);
        }
        Ok(
            match Self::v_get_provider(view, &prescription.prescriber_provider_id)? {
                Some(p) => p.issuer_address == *sender,
                None => false,
            },
        )
    }

    /// A stored row longer than the bound, refused without being decoded.
    ///
    /// The Agreement and DocClass wording verbatim, and for the same reason
    /// they give: one phrasing across every family so the refusal is greppable,
    /// with the LENGTH in it, because the remedy for a row over the limit is
    /// not "retry".
    fn row_too_large(what: &str, bytes: usize) -> HealthcareExecutionResult {
        HealthcareExecutionResult::failure(format!(
            "{what} too large to modify: {bytes} bytes, limit {}",
            crate::MAX_ACCUMULATING_ROW_BYTES
        ))
    }

    /// Every provider-network-index row this registration would append to,
    /// checked against the bound before the first of them is decoded.
    ///
    /// ACTIVATION-AUDIT row AL-8. `v_put_provider` appends the provider id to
    /// one accumulating row per plan the profile names, so one registration
    /// does that `p` times and a row grown below the gate costs its own size
    /// several times over on every later registration naming the same plan.
    fn network_indexes_within_bound(
        view: &ExecutionView<'_, '_>,
        plan_ids: &[[u8; 32]],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        // No read AT ALL while the gate is closed, not merely no refusal: a
        // read here would touch a family the unremediated binary does not
        // touch until later in the arm, and this subsystem's corrupt-row
        // behaviour is pinned per family.
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        for plan_id in plan_ids {
            if let Some(bytes) = Self::v_network_index_row_len(view, plan_id)? {
                if bytes > max {
                    return Ok(Some(Self::row_too_large(
                        "Healthcare provider network index",
                        bytes,
                    )));
                }
            }
        }
        Ok(None)
    }

    /// The member-index row this membership would append to, checked against
    /// the bound before it is decoded. ACTIVATION-AUDIT row AL-8.
    fn member_index_within_bound(
        view: &ExecutionView<'_, '_>,
        member_nullifier: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_member_index_row_len(view, member_nullifier)? {
            Some(bytes) if bytes > max => {
                Ok(Some(Self::row_too_large("Healthcare member index", bytes)))
            }
            _ => Ok(None),
        }
    }

    /// The subject-consent-index row this consent would append to, checked
    /// against the bound before it is decoded. ACTIVATION-AUDIT row AL-8.
    fn subject_consent_index_within_bound(
        view: &ExecutionView<'_, '_>,
        subject_nullifier: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_subject_consent_index_row_len(view, subject_nullifier)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Healthcare subject consent index",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// Both prescription-index rows this prescription would append to, checked
    /// against the bound before either is decoded. ACTIVATION-AUDIT row AL-8.
    fn prescription_indexes_within_bound(
        view: &ExecutionView<'_, '_>,
        patient_nullifier: &[u8; 32],
        prescriber_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        if let Some(bytes) = Self::v_patient_rx_index_row_len(view, patient_nullifier)? {
            if bytes > max {
                return Ok(Some(Self::row_too_large(
                    "Healthcare patient prescription index",
                    bytes,
                )));
            }
        }
        if let Some(bytes) = Self::v_prescriber_rx_index_row_len(view, prescriber_id)? {
            if bytes > max {
                return Ok(Some(Self::row_too_large(
                    "Healthcare prescriber prescription index",
                    bytes,
                )));
            }
        }
        Ok(None)
    }

    /// The membership ROW this dependent would be appended INSIDE, checked
    /// against the bound before the row is decoded.
    ///
    /// ACTIVATION-AUDIT row AL-8, the first in-row case. Checked before the
    /// arm's own `v_get_membership`, not after it: the decode is the cost this
    /// bound exists to refuse, so a check that ran after the row was already
    /// decoded would refuse the write and pay for the read anyway.
    fn membership_row_within_bound(
        view: &ExecutionView<'_, '_>,
        membership_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_membership_row_len(view, membership_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Healthcare membership row",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// The prescription ROW this fill would be appended INSIDE, checked against
    /// the bound before the row is decoded. ACTIVATION-AUDIT row AL-8, the
    /// second in-row case; same placement reasoning as
    /// [`Self::membership_row_within_bound`], and it matters more here because
    /// `PartialFillPrescription` rebuilds this row twice.
    fn prescription_row_within_bound(
        view: &ExecutionView<'_, '_>,
        prescription_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<HealthcareExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_prescription_row_len(view, prescription_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Healthcare prescription row",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// Execute a Healthcare transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &HealthcareTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<HealthcareExecutionResult> {
        Self::execute_with_gates(
            view,
            sender,
            data,
            proposer,
            fee,
            block_height,
            block_timestamp,
            tx_index,
            tx_hash,
            HealthcareGates::from_params(params, block_height),
        )
    }

    /// Execute a Healthcare transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &HealthcareTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: HealthcareGates,
    ) -> Result<HealthcareExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);

        // ACTIVATION-AUDIT row AL-12, the Healthcare third. Every arm below
        // `bincode::deserialize`s `data.data` with no size or shape limit ahead
        // of it, and three of those arms store the deserialized struct
        // VERBATIM: `RegisterProvider` a `ProviderProfile` with its
        // `network_affiliations`, `IssueMembership` a `MembershipRecord` with
        // its `dependents`, `IssuePrescription` a `Prescription` with its
        // `fill_history`. That is the `CreateIdentityRoot` shape of AL-10 three
        // times over -- one transaction bounded only by `max_block_bytes`
        // decides how large the row every later arm decodes, appends to and
        // re-encodes is, and AL-8's two in-row accumulators rebuild the ENTIRE
        // record each time.
        //
        // This is a refusal, not an error, and the DocClass arm's reasoning
        // applies unchanged: below the gate an undecodable payload is `Err(..)`
        // and takes the whole block with it, and an oversized one that happens
        // to decode is admitted; above the gate an oversized payload is a
        // failed receipt in a valid block whether or not it would have decoded.
        // The refusal charges nothing and does not advance the nonce, because
        // every arm below deducts the fee itself and every pre-existing
        // `failure()` that fires before that deduction is already free.
        if gates.allocation_bound && data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(HealthcareExecutionResult::failure(format!(
                "Healthcare payload too large: {} bytes, limit {}",
                data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

        match data.operation {
            // =================================================================
            // SRC-871: Provider Registry Operations
            // =================================================================
            HealthcareOperation::RegisterProvider => {
                let provider: ProviderProfile = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_provider_exists(view, &provider.provider_id)? {
                    return Ok(HealthcareExecutionResult::failure("Provider already exists"));
                }

                // ACTIVATION-AUDIT row AL-8, the network-index family: one
                // append per affiliation the profile declares.
                if let Some(refusal) = Self::network_indexes_within_bound(
                    view,
                    &provider.network_affiliations,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let provider_id = provider.provider_id;
                Self::v_put_provider(view, &provider)?;
                debug!("Provider registered: {:?}", provider_id);
                Ok(HealthcareExecutionResult::success_with_provider(provider_id))
            }

            HealthcareOperation::UpdateProvider => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    provider_id: [u8; 32],
                    status: ProviderStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &update.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &update.provider_id,
                    update.status,
                    block_timestamp,
                )?;
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SuspendProvider => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    provider_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Provider suspended: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RevokeProvider => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    provider_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Provider revoked: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReactivateProvider => {
                #[derive(serde::Deserialize)]
                struct ReactivateData {
                    provider_id: [u8; 32],
                }
                let d: ReactivateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                if provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reactivate"));
                }

                if provider.status != ProviderStatus::Suspended && provider.status != ProviderStatus::Inactive {
                    return Ok(HealthcareExecutionResult::failure("Provider is not suspended or inactive"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_provider_status(
                    view,
                    &d.provider_id,
                    ProviderStatus::Active,
                    block_timestamp,
                )?;
                debug!("Provider reactivated: {:?}", d.provider_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::AddNetworkAffiliation => {
                #[derive(serde::Deserialize)]
                struct AffiliationData {
                    provider_id: [u8; 32],
                    plan_id: [u8; 32],
                }
                let d: AffiliationData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                // AU-4: the only guard below the gate is provider existence, so
                // a stranger moves any provider between plan networks.
                if gates.authorization && provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the provider's issuer can change its network affiliations",
                    ));
                }

                // ACTIVATION-AUDIT row AL-8, the network-index family again.
                if let Some(refusal) = Self::network_indexes_within_bound(
                    view,
                    std::slice::from_ref(&d.plan_id),
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_network_affiliation(view, &d.provider_id, &d.plan_id, block_timestamp)?;
                debug!(
                    "Network affiliation added: {:?} -> {:?}",
                    d.provider_id, d.plan_id
                );
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RemoveNetworkAffiliation => {
                #[derive(serde::Deserialize)]
                struct AffiliationData {
                    provider_id: [u8; 32],
                    plan_id: [u8; 32],
                }
                let d: AffiliationData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let provider = match Self::v_get_provider(view, &d.provider_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Provider not found")),
                };

                // AU-4: the only guard below the gate is provider existence, so
                // a stranger moves any provider between plan networks.
                if gates.authorization && provider.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the provider's issuer can change its network affiliations",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_network_affiliation(
                    view,
                    &d.provider_id,
                    &d.plan_id,
                    block_timestamp,
                    gates.state_precondition,
                )?;
                debug!("Network affiliation removed: {:?} -> {:?}", d.provider_id, d.plan_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-872: Membership Operations
            // =================================================================
            HealthcareOperation::IssueMembership => {
                let membership: MembershipRecord = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                // Verify provider exists
                if Self::v_get_provider(view, &membership.provider_id)?.is_none() {
                    return Ok(HealthcareExecutionResult::failure("Provider not found"));
                }

                if Self::v_membership_exists(view, &membership.membership_id)? {
                    return Ok(HealthcareExecutionResult::failure("Membership already exists"));
                }

                // ACTIVATION-AUDIT row AL-8, the member-index family.
                if let Some(refusal) = Self::member_index_within_bound(
                    view,
                    &membership.member_nullifier,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let membership_id = membership.membership_id;
                Self::v_put_membership(view, &membership)?;
                debug!("Membership issued: {:?}", membership_id);
                Ok(HealthcareExecutionResult::success_with_membership(membership_id))
            }

            HealthcareOperation::UpdateMembership => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    membership_id: [u8; 32],
                    status: MembershipStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    d.status,
                    block_timestamp,
                )?;
                debug!(
                    "Membership status updated: {:?} -> {:?}",
                    d.membership_id, d.status
                );
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RenewMembership => {
                #[derive(serde::Deserialize)]
                struct RenewData {
                    membership_id: [u8; 32],
                    new_expiry: Timestamp,
                }
                let d: RenewData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can renew"));
                }

                // OV-17: `v_renew_membership` writes `status = Active`
                // unconditionally, so below the gate a renewal is also an
                // un-suspension, an un-termination and an un-cancellation --
                // performed by an operation with no status guard at all, while
                // the operation that exists for exactly that, `ReinstateMembership`,
                // does have one and accepts only `Suspended`. A membership
                // terminated a transaction earlier is Active by the end of the
                // block. Refused before the fee, like `ReinstateMembership`'s
                // own status guard.
                if gates.state_precondition
                    && matches!(
                        membership.status,
                        MembershipStatus::Suspended
                            | MembershipStatus::Terminated
                            | MembershipStatus::Cancelled
                    )
                {
                    return Ok(HealthcareExecutionResult::failure(
                        "A suspended, terminated or cancelled membership cannot be renewed",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_renew_membership(view, &d.membership_id, d.new_expiry, block_timestamp)?;
                debug!("Membership renewed: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SuspendMembership => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    membership_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Membership suspended: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::TerminateMembership => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    membership_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can terminate"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Terminated,
                    block_timestamp,
                )?;
                debug!("Membership terminated: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReinstateMembership => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    membership_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can reinstate"));
                }

                if membership.status != MembershipStatus::Suspended {
                    return Ok(HealthcareExecutionResult::failure("Membership is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_membership_status(
                    view,
                    &d.membership_id,
                    MembershipStatus::Active,
                    block_timestamp,
                )?;
                debug!("Membership reinstated: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::AddDependent => {
                #[derive(serde::Deserialize)]
                struct DependentData {
                    membership_id: [u8; 32],
                    dependent_commitment: [u8; 32],
                }
                let d: DependentData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AL-8, the membership in-row case.
                // BEFORE the arm's own `v_get_membership`, because the decode
                // of the whole `MembershipRecord` is exactly the cost this
                // bound exists to refuse -- `v_add_dependent` then decodes and
                // re-encodes that same record a second and third time.
                if let Some(refusal) =
                    Self::membership_row_within_bound(view, &d.membership_id, gates.row_limit())?
                {
                    return Ok(refusal);
                }

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can add dependent"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_dependent(
                    view,
                    &d.membership_id,
                    d.dependent_commitment,
                    block_timestamp,
                )?;
                debug!("Dependent added to membership: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RemoveDependent => {
                #[derive(serde::Deserialize)]
                struct DependentData {
                    membership_id: [u8; 32],
                    dependent_commitment: [u8; 32],
                }
                let d: DependentData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let membership = match Self::v_get_membership(view, &d.membership_id)? {
                    Some(m) => m,
                    None => return Ok(HealthcareExecutionResult::failure("Membership not found")),
                };

                if membership.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can remove dependent"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_remove_dependent(
                    view,
                    &d.membership_id,
                    &d.dependent_commitment,
                    block_timestamp,
                    gates.state_precondition,
                )?;
                debug!("Dependent removed from membership: {:?}", d.membership_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-874: Consent Operations
            // =================================================================
            HealthcareOperation::GrantConsent => {
                let consent: ConsentEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_consent_exists(view, &consent.consent_id)? {
                    return Ok(HealthcareExecutionResult::failure("Consent already exists"));
                }

                // ACTIVATION-AUDIT row AL-8, the subject-consent family.
                if let Some(refusal) = Self::subject_consent_index_within_bound(
                    view,
                    &consent.subject_nullifier,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let consent_id = consent.consent_id;
                Self::v_put_consent(view, &consent)?;
                debug!("Consent granted: {:?}", consent_id);
                Ok(HealthcareExecutionResult::success_with_consent(consent_id))
            }

            HealthcareOperation::UpdateConsent => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    consent_id: [u8; 32],
                    status: ConsentStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let consent = match Self::v_get_consent(view, &d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                if consent.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_consent_status(view, &d.consent_id, d.status, block_timestamp)?;
                debug!("Consent status updated: {:?} -> {:?}", d.consent_id, d.status);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::RevokeConsent => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    consent_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let consent = match Self::v_get_consent(view, &d.consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Consent not found")),
                };

                // AU-3: below the gate `RevokeConsent` requires the issuer, so
                // the person the consent is ABOUT cannot withdraw it. At the
                // gate the subject may, as well as the issuer.
                let may_revoke = consent.issuer_address == *sender
                    || (gates.authorization && consent.subject_address == *sender);
                if !may_revoke {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the issuer or the subject can revoke",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_consent_status(
                    view,
                    &d.consent_id,
                    ConsentStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Consent revoked: {:?}", d.consent_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::SupersedeConsent => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_consent_id: [u8; 32],
                    new_consent: ConsentEnvelope,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let old = match Self::v_get_consent(view, &d.old_consent_id)? {
                    Some(c) => c,
                    None => return Ok(HealthcareExecutionResult::failure("Old consent not found")),
                };

                // AU-1: below the gate this arm checks NOTHING about the sender,
                // so any account marks any consent `Superseded` and stores a
                // replacement whose subject, recipient, scope and issuer all
                // come from its own payload. Three conditions at the gate: the
                // sender must be the old consent's issuer or its subject, the
                // replacement must keep the same issuer as the sender, and it
                // must be about the same subject -- otherwise supersession is a
                // way to re-point a consent at somebody else.
                if gates.authorization {
                    let may_supersede =
                        old.issuer_address == *sender || old.subject_address == *sender;
                    if !may_supersede {
                        return Ok(HealthcareExecutionResult::failure(
                            "Only the issuer or the subject can supersede a consent",
                        ));
                    }
                    if d.new_consent.issuer_address != *sender {
                        return Ok(HealthcareExecutionResult::failure(
                            "The replacement consent must be issued by the sender",
                        ));
                    }
                    if d.new_consent.subject_address != old.subject_address {
                        return Ok(HealthcareExecutionResult::failure(
                            "A supersession cannot change the subject of a consent",
                        ));
                    }
                }

                // ACTIVATION-AUDIT row AL-8, the subject-consent family: the
                // replacement's id is appended to the index of the subject the
                // REPLACEMENT names, which below the authorization gate need
                // not be the subject the old consent named.
                if let Some(refusal) = Self::subject_consent_index_within_bound(
                    view,
                    &d.new_consent.subject_nullifier,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_consent_status(
                    view,
                    &d.old_consent_id,
                    ConsentStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new consent
                let new_id = d.new_consent.consent_id;
                Self::v_put_consent(view, &d.new_consent)?;
                debug!("Consent superseded: {:?} -> {:?}", d.old_consent_id, new_id);
                Ok(HealthcareExecutionResult::success_with_consent(new_id))
            }

            // =================================================================
            // SRC-876: Prescription Operations
            // =================================================================
            HealthcareOperation::IssuePrescription => {
                let prescription: Prescription = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Issuer must be sender"));
                }

                // Verify prescriber provider exists
                let prescriber =
                    match Self::v_get_provider(view, &prescription.prescriber_provider_id)? {
                        Some(p) => p,
                        None => {
                            return Ok(HealthcareExecutionResult::failure(
                                "Prescriber provider not found",
                            ))
                        }
                    };

                // AU-5: below the gate the only sender check is against
                // `issuer_address`, which comes from this same payload, so
                // anyone who can register a provider issues prescriptions
                // naming any other registered provider as prescriber. At the
                // gate the sender must be the prescriber's own issuer.
                if gates.authorization && prescriber.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the prescriber provider's issuer can issue its prescriptions",
                    ));
                }

                if Self::v_prescription_exists(view, &prescription.prescription_id)? {
                    return Ok(HealthcareExecutionResult::failure("Prescription already exists"));
                }

                // ACTIVATION-AUDIT row AL-8, both prescription-index families:
                // one `IssuePrescription` appends to the patient index and the
                // prescriber index in the same transaction.
                if let Some(refusal) = Self::prescription_indexes_within_bound(
                    view,
                    &prescription.patient_nullifier,
                    &prescription.prescriber_provider_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                // ACTIVATION-AUDIT row OV-19. `UpdatePrescription` refuses to
                // move a controlled prescription into `TransferRequested`, and
                // that is the subsystem's ONLY rule about `is_controlled` --
                // SRC-876 calls itself "NON-TRANSFERABLE for controlled
                // substances" and `TransferRequested` is the only transfer
                // state there is. Below the gate the rule is enforced on the
                // path that MOVES a prescription and on no other, and this arm
                // stores the payload's `status` VERBATIM -- so the state the
                // guard exists to keep a controlled prescription out of is
                // reached by issuing it there in the first place, for one
                // `min_fee`, by the same issuer the guard would have refused.
                //
                // At and above the gate the creation path carries the same
                // check as the update path. Refused before the fee, like the
                // duplicate guard above it. Deliberately NOT a normalization of
                // `status` to `Active`: which initial states are lawful for a
                // prescription is a policy this tree does not state, and
                // inventing one here would refuse lawful `Pending` issuance to
                // close a hole that is about one state.
                if gates.state_precondition
                    && prescription.is_controlled
                    && prescription.status == PrescriptionStatus::TransferRequested
                {
                    return Ok(HealthcareExecutionResult::failure(
                        "Controlled substance prescriptions cannot be transferred",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let prescription_id = prescription.prescription_id;
                Self::v_put_prescription(view, &prescription)?;
                debug!("Prescription issued: {:?}", prescription_id);
                Ok(HealthcareExecutionResult::success_with_prescription(prescription_id))
            }

            HealthcareOperation::UpdatePrescription => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    prescription_id: [u8; 32],
                    status: PrescriptionStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can update"));
                }

                // Prevent transfer of controlled substances
                if prescription.is_controlled && d.status == PrescriptionStatus::TransferRequested {
                    return Ok(HealthcareExecutionResult::failure(
                        "Controlled substance prescriptions cannot be transferred"
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    d.status,
                    block_timestamp,
                )?;
                debug!("Prescription status updated: {:?} -> {:?}", d.prescription_id, d.status);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::FillPrescription => {
                #[derive(serde::Deserialize)]
                struct FillData {
                    prescription_id: [u8; 32],
                    fill_commitment: [u8; 32],
                }
                let d: FillData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AL-8, the prescription in-row case.
                // BEFORE the arm's own `v_get_prescription`, because the decode
                // of the whole `Prescription` is exactly the cost this bound
                // exists to refuse.
                if let Some(refusal) = Self::prescription_row_within_bound(
                    view,
                    &d.prescription_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                // AU-2: below the gate neither fill arm checks the sender at
                // all -- not patient, prescriber, pharmacy or issuer -- so a
                // stranger fills anyone's prescription, controlled substances
                // included.
                if gates.authorization && !Self::may_fill(view, &prescription, sender)? {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the patient, the prescriber's issuer or the issuer can fill",
                    ));
                }

                // OV-18: the inherited guard is a CONJUNCTION, so a prescription
                // authorizing zero refills whose status is still `Active` passes
                // it and is filled once more. At the gate either condition
                // refuses on its own.
                let no_fills_left = if gates.authorization {
                    prescription.refills_remaining == 0
                        || prescription.status != PrescriptionStatus::Active
                } else {
                    prescription.refills_remaining == 0
                        && prescription.status != PrescriptionStatus::Active
                };
                if no_fills_left {
                    return Ok(HealthcareExecutionResult::failure("No fills remaining"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_record_fill(view, &d.prescription_id, d.fill_commitment, block_timestamp)?;
                debug!("Prescription filled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::PartialFillPrescription => {
                #[derive(serde::Deserialize)]
                struct PartialFillData {
                    prescription_id: [u8; 32],
                    fill_commitment: [u8; 32],
                }
                let d: PartialFillData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // ACTIVATION-AUDIT row AL-8, the prescription in-row case, and
                // the arm that rebuilds the record TWICE in one transaction --
                // once in `v_add_fill_history` and once in
                // `v_update_prescription_status`. Checked before the arm's own
                // `v_get_prescription`, which is a third decode of the same
                // row.
                if let Some(refusal) = Self::prescription_row_within_bound(
                    view,
                    &d.prescription_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
                }

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if !prescription.is_valid(block_timestamp) {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not valid"));
                }

                // AU-2, the second arm.
                if gates.authorization && !Self::may_fill(view, &prescription, sender)? {
                    return Ok(HealthcareExecutionResult::failure(
                        "Only the patient, the prescriber's issuer or the issuer can fill",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Record partial fill (doesn't decrement refills)
                Self::v_add_fill_history(
                    view,
                    &d.prescription_id,
                    d.fill_commitment,
                    block_timestamp,
                )?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::PartiallyFilled,
                    block_timestamp,
                )?;
                debug!("Prescription partially filled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::CancelPrescription => {
                #[derive(serde::Deserialize)]
                struct CancelData {
                    prescription_id: [u8; 32],
                }
                let d: CancelData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can cancel"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::Cancelled,
                    block_timestamp,
                )?;
                debug!("Prescription cancelled: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::HoldPrescription => {
                #[derive(serde::Deserialize)]
                struct HoldData {
                    prescription_id: [u8; 32],
                }
                let d: HoldData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can hold"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::OnHold,
                    block_timestamp,
                )?;
                debug!("Prescription on hold: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            HealthcareOperation::ReleaseHold => {
                #[derive(serde::Deserialize)]
                struct ReleaseData {
                    prescription_id: [u8; 32],
                }
                let d: ReleaseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let prescription = match Self::v_get_prescription(view, &d.prescription_id)? {
                    Some(p) => p,
                    None => return Ok(HealthcareExecutionResult::failure("Prescription not found")),
                };

                if prescription.issuer_address != *sender {
                    return Ok(HealthcareExecutionResult::failure("Only issuer can release hold"));
                }

                if prescription.status != PrescriptionStatus::OnHold {
                    return Ok(HealthcareExecutionResult::failure("Prescription is not on hold"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_prescription_status(
                    view,
                    &d.prescription_id,
                    PrescriptionStatus::Active,
                    block_timestamp,
                )?;
                debug!("Prescription hold released: {:?}", d.prescription_id);
                Ok(HealthcareExecutionResult::success())
            }

            // =================================================================
            // SRC-875: Proof Operations
            // =================================================================
            HealthcareOperation::SubmitProof => {
                let proof: HealthcareProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_healthcare_proof_exists(view, &proof.proof_id)? {
                    return Ok(HealthcareExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_healthcare_proof(view, &proof)?;
                debug!("Healthcare proof submitted: {:?}", proof_id);
                Ok(HealthcareExecutionResult::success_with_proof(proof_id))
            }

            HealthcareOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-6 (= PR-6). Below the gate this arm reads no
                // payload and no proof and returns SUCCESS, so the chain reports a
                // verified proof for a proof it has never held, for a payload that
                // is not a proof id, and for proof bytes nothing has ever looked
                // at. At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Healthcare proofs exists in this tree --
                // nothing checks `proof_data` against `public_inputs`, there is no
                // proof system in the workspace, no verifying key anywhere, and no
                // wire type for a verification request -- and an operation that
                // cannot be performed must say so rather than succeed.
                //
                // The proof family is deliberately NOT consulted. Whether the named
                // proof is present is not a fact about whether it is valid, and
                // branching on it would restore the implication that a present
                // proof was checked. That is why the presence gate this replaces
                // is retired rather than kept beneath this one.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_unsupported {
                    return Ok(HealthcareExecutionResult::failure(
                        crate::VERIFY_PROOF_UNSUPPORTED,
                    ));
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Healthcare proof verification requested by: {}", sender);
                Ok(HealthcareExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    // `Arc` is used only by this module's fixtures. Importing it here rather
    // than at file scope keeps the normal build free of an unused import while
    // leaving the gated build exactly as it was.
    use std::sync::Arc;
    use sumchain_primitives::healthcare::{HealthcareIssuerClass, ProviderType};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_register_provider() {
        let (db, _dir, _state) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        let provider = ProviderProfile {
            provider_id: [10u8; 32],
            provider_commitment: [11u8; 32],
            provider_type: ProviderType::Hospital,
            jurisdiction_code: "US-CA".to_string(),
            public_reference: None,
            specialties_commitment: None,
            credentials_commitment: None,
            policy_id: [12u8; 32],
            issuer_class: HealthcareIssuerClass::HospitalSystem,
            issuer_address: sender,
            status: ProviderStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            registered_at_height: 100,
            network_affiliations: vec![],
            attachments: vec![],
        };

        let tx_data = HealthcareTxData {
            operation: HealthcareOperation::RegisterProvider,
            data: bincode::serialize(&provider).unwrap(),
            recipient: Address::ZERO,
        };

        let result = HealthcareExecutor::execute(
            view,
            &params,
            &sender,
            &tx_data,
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Register provider failed: {:?}", result.error);
        assert_eq!(result.provider_id, Some([10u8; 32]));

        // Read the CANDIDATE: this executor stages now, and a committed read
        // straight after `execute` would be asserting the defect this package
        // removed.
        let retrieved = HealthcareExecutor::v_get_provider(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA");
    }
}
