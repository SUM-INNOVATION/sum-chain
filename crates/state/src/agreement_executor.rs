//! SRC-84X Agreement & IP Executor
//!
//! Transaction executor for:
//! - SRC-841: Agreement Commitments
//! - SRC-842: Party Signatures
//! - SRC-843: Notary & Attestation
//! - SRC-844: IP Rights Actions
//! - SRC-845: Executor Links
//! - SRC-846: Agreement Proofs

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    agreement::{
        AgreementCommitment, AgreementOperation, AgreementProofEnvelope, AgreementStatus,
        AgreementTxData, AttestationPacket, AttestationStatus, ExecutorLink, ExecutorState,
        IpActionStatus, IpRightsAction, PartySignature,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Agreement operation execution
#[derive(Debug)]
pub struct AgreementExecutionResult {
    pub success: bool,
    pub agreement_id: Option<[u8; 32]>,
    pub signature_id: Option<[u8; 32]>,
    pub attestation_id: Option<[u8; 32]>,
    pub ip_action_id: Option<[u8; 32]>,
    pub link_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl AgreementExecutionResult {
    pub fn success_with_agreement(agreement_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: Some(agreement_id),
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_signature(signature_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: Some(signature_id),
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_attestation(attestation_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: Some(attestation_id),
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_ip_action(ip_action_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: Some(ip_action_id),
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_link(link_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: Some(link_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            agreement_id: None,
            signature_id: None,
            attestation_id: None,
            ip_action_id: None,
            link_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Agreement executor for SRC-84X transactions
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::agreement_store` for the RPC server.
pub struct AgreementExecutor;

/// The activation decisions an Agreement transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AgreementGates {
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT row TS-5.
    pub real_block_timestamp: bool,
    /// Signature rows and the parties' `signed` flags agree.
    /// ACTIVATION-AUDIT rows OV-28 and OV-29.
    pub signature_integrity: bool,
    /// `VerifyProof` refuses a payload that does not name a proof this
    /// subsystem holds. ACTIVATION-AUDIT row AU-12 (= PR-5).
    pub proof_presence: bool,
    /// An operation that writes nothing reports a failed receipt rather
    /// than a success one. ACTIVATION-AUDIT row OV-30.
    pub no_op_receipt: bool,
}

impl AgreementGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        real_block_timestamp: false,
        signature_integrity: false,
        proof_presence: false,
        no_op_receipt: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        real_block_timestamp: true,
        signature_integrity: true,
        proof_presence: true,
        no_op_receipt: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            signature_integrity: AgreementExecutor::signature_integrity_gate_open(
                params,
                block_height,
            ),
            proof_presence: crate::subsystem_proof_presence_gate_open(params, block_height),
            no_op_receipt: crate::subsystem_no_op_receipt_gate_open(params, block_height),
        }
    }
}

impl AgreementExecutor {
    /// The activation height for the Agreement signature-integrity rules.
    ///
    /// Reads `params.agreement_signature_integrity_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-28 and OV-29) a signature naming
    /// a party the agreement does not bind is stored anyway and rewrites the
    /// agreement row while flipping no flag, and `RevokeSignature` deletes the
    /// signature row and leaves the party's `signed` flag set. At and above it
    /// the signature must name a bound party, and revoking one clears that
    /// party's flag and walks an `Executed` agreement back to
    /// `PendingSignatures`.
    #[inline]
    fn signature_integrity_activation(params: &ChainParams) -> Option<u64> {
        params.agreement_signature_integrity_enabled_from_height
    }

    /// Whether the Agreement signature-integrity rules are active at
    /// `block_height`.
    #[inline]
    pub fn signature_integrity_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::signature_integrity_activation(params), Some(h) if block_height >= h)
    }

    /// Execute an Agreement transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &AgreementTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<AgreementExecutionResult> {
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
            AgreementGates::from_params(params, block_height),
        )
    }

    /// Execute an Agreement transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &AgreementTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: AgreementGates,
    ) -> Result<AgreementExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
        match data.operation {
            // SRC-841: Agreement Commitment Operations
            AgreementOperation::CommitAgreement => {
                let agreement: AgreementCommitment = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_agreement_exists(view, &agreement.agreement_id)? {
                    return Ok(AgreementExecutionResult::failure("Agreement already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let agreement_id = agreement.agreement_id;
                Self::v_put_agreement(view, &agreement)?;
                debug!("Agreement committed: {:?}", agreement_id);
                Ok(AgreementExecutionResult::success_with_agreement(agreement_id))
            }

            AgreementOperation::UpdateAgreement => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    agreement_id: [u8; 32],
                    status: AgreementStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_agreement(view, &update.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_agreement_status(
                    view,
                    &update.agreement_id,
                    update.status,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::TerminateAgreement | AgreementOperation::VoidAgreement => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    agreement_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_agreement(view, &d.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                let new_status = if data.operation == AgreementOperation::TerminateAgreement {
                    AgreementStatus::Terminated
                } else {
                    AgreementStatus::Voided
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_agreement_status(
                    view,
                    &d.agreement_id,
                    new_status,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::SupersedeAgreement => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_agreement_id: [u8; 32],
                    new_agreement: AgreementCommitment,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_agreement(view, &d.old_agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Old agreement not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_agreement_status(
                    view,
                    &d.old_agreement_id,
                    AgreementStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new agreement
                let new_id = d.new_agreement.agreement_id;
                Self::v_put_agreement(view, &d.new_agreement)?;
                debug!("Agreement superseded: {:?} -> {:?}", d.old_agreement_id, new_id);
                Ok(AgreementExecutionResult::success_with_agreement(new_id))
            }

            // SRC-842: Party Signature Operations
            AgreementOperation::SignAgreement => {
                let signature: PartySignature = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // Verify agreement exists
                if Self::v_get_agreement(view, &signature.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                if Self::v_signature_exists(view, &signature.signature_id)? {
                    return Ok(AgreementExecutionResult::failure("Signature already exists"));
                }

                // OV-28: below the gate a signature naming a party the agreement
                // does not bind is stored anyway, and `v_mark_party_signed`
                // rewrites the agreement row -- bumping `updated_at` -- while
                // matching nobody and flipping no flag. The signature family then
                // holds rows for parties the agreement has never heard of.
                if gates.signature_integrity {
                    let party_hash = signature.party_ref.as_hash();
                    let agreement = match Self::v_get_agreement(view, &signature.agreement_id)? {
                        Some(a) => a,
                        None => {
                            return Ok(AgreementExecutionResult::failure("Agreement not found"))
                        }
                    };
                    if !agreement
                        .parties
                        .iter()
                        .any(|p| p.party_ref.as_hash() == party_hash)
                    {
                        return Ok(AgreementExecutionResult::failure(
                            "Signer is not a party to this agreement",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                let sig_id = signature.signature_id;
                let agreement_id = signature.agreement_id;
                let party_hash = signature.party_ref.as_hash();

                Self::v_put_signature(view, &signature)?;
                Self::v_mark_party_signed(view, &agreement_id, &party_hash, block_timestamp)?;

                debug!("Agreement signed: {:?} by party {:?}", agreement_id, party_hash);
                Ok(AgreementExecutionResult::success_with_signature(sig_id))
            }

            AgreementOperation::RevokeSignature => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    signature_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let existing = match Self::v_get_signature(view, &d.signature_id)? {
                    Some(sig) => sig,
                    None => return Ok(AgreementExecutionResult::failure("Signature not found")),
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_delete_signature(view, &d.signature_id)?;
                // OV-29: below the gate the signature row goes and the party's
                // `signed` flag stays, so an agreement promoted to `Executed` by
                // that very signature stays `Executed` with the signature gone,
                // and nothing anywhere recomputes it.
                if gates.signature_integrity {
                    Self::v_unmark_party_signed(
                        view,
                        &existing.agreement_id,
                        &existing.party_ref.as_hash(),
                        block_timestamp,
                    )?;
                }
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::AddParty | AgreementOperation::RemoveParty => {
                // These would require updating agreement parties
                //
                // ACTIVATION-AUDIT row OV-30. That comment is the whole
                // implementation: below the gate this arm charges the fee,
                // advances the nonce and returns SUCCESS, having touched no
                // agreement and no party. At and above the gate it says so.
                //
                // A failed receipt, not an implementation: `AgreementCommitment`
                // defines no add-party or remove-party semantics, and inventing
                // one inside an executor would be a rule nobody set. Refused
                // before the deduct, where this file's other refusals return.
                if gates.no_op_receipt {
                    return Ok(AgreementExecutionResult::failure(
                        "AddParty and RemoveParty are not implemented and change no party",
                    ));
                }
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Party operation requested by: {}", sender);
                Ok(AgreementExecutionResult::success())
            }

            // SRC-843: Attestation Operations
            AgreementOperation::CreateAttestation => {
                let attestation: AttestationPacket = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if attestation.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_attestation_exists(view, &attestation.attestation_id)? {
                    return Ok(AgreementExecutionResult::failure("Attestation already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let att_id = attestation.attestation_id;
                Self::v_put_attestation(view, &attestation)?;
                debug!("Attestation created: {:?}", att_id);
                Ok(AgreementExecutionResult::success_with_attestation(att_id))
            }

            AgreementOperation::RevokeAttestation => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    attestation_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let att = match Self::v_get_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(AgreementExecutionResult::failure("Attestation not found")),
                };

                if att.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_attestation_status(
                    view,
                    &d.attestation_id,
                    AttestationStatus::Revoked,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::UpdateAttestationStatus => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    attestation_id: [u8; 32],
                    status: AttestationStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let att = match Self::v_get_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(AgreementExecutionResult::failure("Attestation not found")),
                };

                if att.issuer_address != *sender {
                    return Ok(AgreementExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_attestation_status(view, &d.attestation_id, d.status)?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-844: IP Rights Operations
            AgreementOperation::RecordIpAction => {
                let action: IpRightsAction = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_ip_action_exists(view, &action.action_id)? {
                    return Ok(AgreementExecutionResult::failure("IP action already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let action_id = action.action_id;
                Self::v_put_ip_action(view, &action)?;
                debug!("IP action recorded: {:?}", action_id);
                Ok(AgreementExecutionResult::success_with_ip_action(action_id))
            }

            AgreementOperation::UpdateIpAction | AgreementOperation::TerminateIpAction | AgreementOperation::RevokeIpAction => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    action_id: [u8; 32],
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_ip_action(view, &d.action_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("IP action not found"));
                }

                let new_status = match data.operation {
                    AgreementOperation::TerminateIpAction => IpActionStatus::Terminated,
                    AgreementOperation::RevokeIpAction => IpActionStatus::Revoked,
                    _ => IpActionStatus::Active,
                };

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_ip_action_status(view, &d.action_id, new_status)?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-845: Executor Link Operations
            AgreementOperation::LinkExecutor => {
                let link: ExecutorLink = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                // Verify agreement exists
                if Self::v_get_agreement(view, &link.agreement_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Agreement not found"));
                }

                if Self::v_executor_link_exists(view, &link.link_id)? {
                    return Ok(AgreementExecutionResult::failure("Executor link already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let link_id = link.link_id;
                Self::v_put_executor_link(view, &link)?;
                debug!("Executor linked: {:?}", link_id);
                Ok(AgreementExecutionResult::success_with_link(link_id))
            }

            AgreementOperation::ActivateExecutor => {
                #[derive(serde::Deserialize)]
                struct ActivateData {
                    link_id: [u8; 32],
                }
                let d: ActivateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let link = match Self::v_get_executor_link(view, &d.link_id)? {
                    Some(l) => l,
                    None => return Ok(AgreementExecutionResult::failure("Executor link not found")),
                };

                if link.state != ExecutorState::Draft {
                    return Ok(AgreementExecutionResult::failure("Can only activate draft executors"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Active,
                    block_timestamp,
                )?;
                debug!("Executor activated: {:?}", d.link_id);
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::PauseExecutor => {
                #[derive(serde::Deserialize)]
                struct PauseData {
                    link_id: [u8; 32],
                }
                let d: PauseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Paused,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::ResumeExecutor => {
                #[derive(serde::Deserialize)]
                struct ResumeData {
                    link_id: [u8; 32],
                }
                let d: ResumeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let link = match Self::v_get_executor_link(view, &d.link_id)? {
                    Some(l) => l,
                    None => return Ok(AgreementExecutionResult::failure("Executor link not found")),
                };

                if link.state != ExecutorState::Paused {
                    return Ok(AgreementExecutionResult::failure("Can only resume paused executors"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Active,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::TerminateExecutor => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    link_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Terminated,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            AgreementOperation::CompleteExecutor => {
                #[derive(serde::Deserialize)]
                struct CompleteData {
                    link_id: [u8; 32],
                }
                let d: CompleteData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_get_executor_link(view, &d.link_id)?.is_none() {
                    return Ok(AgreementExecutionResult::failure("Executor link not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_executor_state(
                    view,
                    &d.link_id,
                    ExecutorState::Completed,
                    block_timestamp,
                )?;
                Ok(AgreementExecutionResult::success())
            }

            // SRC-846: Proof Operations
            AgreementOperation::SubmitProof => {
                let proof: AgreementProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(AgreementExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Agreement proof submitted: {:?}", proof_id);
                Ok(AgreementExecutionResult::success_with_proof(proof_id))
            }

            AgreementOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-12 (= PR-5). Below the gate this arm reads no
                // payload and no proof, and reports success for a proof the chain
                // has never held. At and above it the payload must be the 32 bytes
                // of a proof id and that proof must be present. Presence is NOT
                // verification and this does not claim to be: nothing in this tree
                // checks `proof_data` against `public_inputs`. What it removes is
                // the false positive.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_presence {
                    let Some(proof_id) = crate::verify_proof_target(&data.data) else {
                        return Ok(AgreementExecutionResult::failure(format!(
                            "VerifyProof payload must be a {}-byte proof id, got {} bytes",
                            crate::PROOF_ID_BYTES,
                            data.data.len()
                        )));
                    };
                    if !Self::v_proof_exists(view, &proof_id)? {
                        return Ok(AgreementExecutionResult::failure("Proof not found"));
                    }
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Agreement proof verification requested by: {}", sender);
                Ok(AgreementExecutionResult::success())
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
    use sumchain_primitives::agreement::{
        AgreementRole, PartyBinding, PartyRef,
    };
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_commit_agreement() {
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

        let party1 = PartyBinding {
            party_ref: PartyRef::Commitment([2u8; 32]),
            role: AgreementRole::Buyer,
            signed: false,
            signed_at: None,
        };

        let agreement = AgreementCommitment {
            agreement_id: [10u8; 32],
            agreement_commitment: [11u8; 32],
            parties: vec![party1],
            jurisdiction_code: "US-DE".to_string(),
            effective_from: Some(1000),
            expiry: Some(2000),
            attachments: vec![],
            policy_id: [12u8; 32],
            status: AgreementStatus::Draft,
            created_at: 1000,
            updated_at: 1000,
            created_at_height: 100,
            supersedes: None,
        };

        let tx_data = AgreementTxData {
            operation: AgreementOperation::CommitAgreement,
            data: bincode::serialize(&agreement).unwrap(),
            recipient: Address::ZERO,
        };

        let result = AgreementExecutor::execute(
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

        assert!(result.success, "Commit agreement failed: {:?}", result.error);
        assert_eq!(result.agreement_id, Some([10u8; 32]));

        // Read the CANDIDATE: this executor stages now, and a committed read
        // straight after `execute` would be asserting the defect this package
        // removed.
        let retrieved = AgreementExecutor::v_get_agreement(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-DE");
    }
}
