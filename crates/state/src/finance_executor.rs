//! SRC-89X Finance & Banking Executor
//!
//! Transaction executor for:
//! - SRC-891: Financial Institution & Utility Issuer Profile
//! - SRC-892: Proof-of-Address Credential
//! - SRC-893: Bank Account Standing Credential
//! - SRC-894: KYC / AML Attestation
//! - SRC-895: 89X Proof Profiles

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    finance::{
        AccountStanding, AddressProof, BankStandingCredential, FinanceIssuerProfile,
        FinanceIssuerStatus, FinanceOperation, FinanceProofEnvelope, FinanceTxData,
        KycAttestation, KycStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Finance operation execution
#[derive(Debug)]
pub struct FinanceExecutionResult {
    pub success: bool,
    pub issuer_address: Option<Address>,
    pub address_proof_id: Option<[u8; 32]>,
    pub bank_standing_id: Option<[u8; 32]>,
    pub kyc_attestation_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl FinanceExecutionResult {
    pub fn success_with_issuer(issuer_address: Address) -> Self {
        Self {
            success: true,
            issuer_address: Some(issuer_address),
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_address_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: Some(proof_id),
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_bank_standing(credential_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: Some(credential_id),
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_kyc(attestation_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: Some(attestation_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            issuer_address: None,
            address_proof_id: None,
            bank_standing_id: None,
            kyc_attestation_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Finance executor for SRC-89X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::finance_store` for the
/// RPC server.
pub struct FinanceExecutor;

/// The activation decisions a Finance transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FinanceGates {
    /// The subsystem's issuer-standing rules are enforced. ACTIVATION-AUDIT
    /// rows AU-22, AU-23 and AU-25.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT AU-26 (= PR-4). Supersedes the retired presence check: no
    /// verifier exists in this tree, so the operation cannot be performed
    /// and must not report success.
    pub proof_unsupported: bool,
    /// A payload-chosen index key is bounded before it becomes a key.
    /// ACTIVATION-AUDIT row the Finance instance of AL-7.
    pub allocation_bound: bool,
}

impl FinanceGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        proof_unsupported: false,
        allocation_bound: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        proof_unsupported: true,
        allocation_bound: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: FinanceExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
        }
    }

    /// The stored-row length limit this gate imposes, or `None` when closed.
    ///
    /// `None` is what the bounded readers treat as "no limit", so a closed gate
    /// reads byte-for-byte what the unbounded reader read. The same spelling
    /// `AgreementGates::row_limit` and `DocClassGates::row_limit` use, reading
    /// the same constant, because it is the same rule.
    #[inline]
    pub fn row_limit(self) -> Option<usize> {
        self.allocation_bound
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
    }
}

impl FinanceExecutor {
    /// The activation height for the Finance issuer-standing rules.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-89X Finance issuer-standing rules. Dormant by default (`None` ->
    /// /// never open). Below the gate every update and revoke path checks only
    /// /// the address recorded ON THE ROW and never rereads the issuer
    /// /// registry, so an issuer that has been suspended or revoked keeps full
    /// /// control of everything it ever issued -- the creation paths DO check,
    /// /// so the asymmetry is exact. `UpdateIssuer` also accepts whatever
    /// /// status the sender asks for, `Active` from `Revoked` included, walking
    /// /// around the Suspended-only guard `ReactivateIssuer` exists to enforce.
    /// /// And `SubmitProof` has no authority check at all. At and above the
    /// /// gate each of those is enforced. Activation is a consensus change and
    /// /// needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub finance_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and every pinning test that records the gap still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.finance_authorization_enabled_from_height
    }

    /// Whether the Finance issuer-standing rules are active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// Is `sender` a registered issuer whose standing is still `Active`?
    ///
    /// The check the mutation paths never made. The creation paths make it
    /// inline; this is the same question asked of the same row.
    fn issuer_in_good_standing(view: &ExecutionView<'_, '_>, sender: &Address) -> Result<bool> {
        Ok(match Self::v_get_issuer(view, sender)? {
            Some(issuer) => issuer.status.is_active(),
            None => false,
        })
    }

    /// A stored index row longer than the bound, refused without being decoded.
    ///
    /// The DocClass and Agreement wording verbatim, and for the reason those
    /// give: one phrasing across every family so the refusal is greppable, with
    /// the LENGTH in it, because the remedy for a row over the limit is not
    /// "retry".
    fn row_too_large(what: &str, bytes: usize) -> FinanceExecutionResult {
        FinanceExecutionResult::failure(format!(
            "{what} too large to modify: {bytes} bytes, limit {}",
            crate::MAX_ACCUMULATING_ROW_BYTES
        ))
    }

    /// One accumulating index row, checked against the bound before anything
    /// decodes it.
    ///
    /// ACTIVATION-AUDIT row AL-4. Each of the subsystem's four index families
    /// holds one bincode list that `v_add_to_*` decodes in full, pushes one
    /// entry onto and re-encodes in full, before `view.put` charges the
    /// candidate a single byte. So the candidate ceiling bounds what a block
    /// may COMMIT and bounds nothing about what one transaction may ALLOCATE,
    /// which is the same sentence AL-2, AL-5, AL-10 and AL-11 make in four
    /// other subsystems.
    ///
    /// `None` -- a closed gate -- reads NOTHING, not merely refuses nothing: a
    /// read here would move a decode earlier than the unremediated binary
    /// reaches it.
    ///
    /// Checked before `v_deduct`, because every other refusal in these arms is
    /// checked there too -- a Finance refusal writes nothing at all, and a
    /// bound that charged for the refusal would be the one exception.
    /// `row_len` is a CLOSURE and not a value so that a closed gate performs no
    /// read at all -- see the paragraph above.
    fn index_row_within_bound(
        what: &str,
        max_bytes: Option<usize>,
        row_len: impl FnOnce() -> Result<Option<usize>>,
    ) -> Result<Option<FinanceExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        Ok(match row_len()? {
            Some(bytes) if bytes > max => Some(Self::row_too_large(what, bytes)),
            _ => None,
        })
    }

    /// Execute a Finance transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &FinanceTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<FinanceExecutionResult> {
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
            FinanceGates::from_params(params, block_height),
        )
    }

    /// Execute a Finance transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &FinanceTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: FinanceGates,
    ) -> Result<FinanceExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
        match data.operation {
            // =================================================================
            // SRC-891: Issuer Registry Operations
            // =================================================================
            FinanceOperation::RegisterIssuer => {
                let issuer: FinanceIssuerProfile = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if issuer.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_issuer_exists(view, &issuer.issuer_address)? {
                    return Ok(FinanceExecutionResult::failure("Issuer already exists"));
                }

                // ACTIVATION-AUDIT AL-7, the Finance instance. `FinanceIssuerProfile.jurisdiction_code` is free text from the
                // sender's own payload and becomes the raw KEY of
                // `cf::FINANCE_JURISDICTION_INDEX`, with no width check anywhere ahead of
                // the `put`. Below the gate one transaction writes a key of
                // most of `max_block_bytes`. At and above it the key is
                // bounded. Refused before the fee, like the duplicate guard
                // above it.
                if !crate::index_key_text_within_bound(
                    &issuer.jurisdiction_code,
                    gates.allocation_bound,
                ) {
                    return Ok(FinanceExecutionResult::failure(format!(
                        "Jurisdiction code too long: {} bytes, limit {}",
                        issuer.jurisdiction_code.len(),
                        crate::MAX_INDEX_KEY_TEXT_BYTES
                    )));
                }

                // ACTIVATION-AUDIT row AL-4, the jurisdiction half. The bound
                // above is on the KEY this code writes; this one is on the
                // VALUE it appends to, and they are independent: a short code
                // naming a row that has already accumulated a megabyte of
                // addresses passes the first and must not pass the second.
                if let Some(refusal) = Self::index_row_within_bound(
                    "Finance jurisdiction index",
                    gates.row_limit(),
                    || Self::v_jurisdiction_index_row_len(view, &issuer.jurisdiction_code),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let issuer_addr = issuer.issuer_address;
                Self::v_put_issuer(view, &issuer)?;
                debug!("Finance issuer registered: {}", issuer_addr);
                Ok(FinanceExecutionResult::success_with_issuer(issuer_addr))
            }

            FinanceOperation::UpdateIssuer => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    status: FinanceIssuerStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(FinanceExecutionResult::failure("Issuer not found")),
                };

                if issuer.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                // AU-22: below the gate this arm applies whatever status the
                // sender asks for, with no reference to the status the row
                // already holds -- `Active` from `Revoked` included. That walks
                // around the Suspended-only guard `ReactivateIssuer` exists to
                // enforce. At the gate `UpdateIssuer` may not restore `Active`
                // at all (that is `ReactivateIssuer`'s job, with its own guard)
                // and `Revoked` is terminal.
                if gates.authorization {
                    if issuer.status == FinanceIssuerStatus::Revoked {
                        return Ok(FinanceExecutionResult::failure(
                            "A revoked issuer's status is terminal",
                        ));
                    }
                    if update.status == FinanceIssuerStatus::Active
                        && issuer.status != FinanceIssuerStatus::Active
                    {
                        return Ok(FinanceExecutionResult::failure(
                            "Use ReactivateIssuer to restore an issuer to Active",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(view, sender, update.status, block_timestamp)?;
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::SuspendIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(FinanceExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Suspended,
                    block_timestamp,
                )?;
                debug!("Finance issuer suspended: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeIssuer => {
                if !Self::v_issuer_exists(view, sender)? {
                    return Ok(FinanceExecutionResult::failure("Issuer not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Revoked,
                    block_timestamp,
                )?;
                debug!("Finance issuer revoked: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::ReactivateIssuer => {
                let issuer = match Self::v_get_issuer(view, sender)? {
                    Some(i) => i,
                    None => return Ok(FinanceExecutionResult::failure("Issuer not found")),
                };

                if issuer.status != FinanceIssuerStatus::Suspended {
                    return Ok(FinanceExecutionResult::failure("Issuer is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_issuer_status(
                    view,
                    sender,
                    FinanceIssuerStatus::Active,
                    block_timestamp,
                )?;
                debug!("Finance issuer reactivated: {}", sender);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-892: Address Proof Operations
            // =================================================================
            FinanceOperation::CreateAddressProof => {
                let proof: AddressProof = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if proof.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_address_proof() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue address proofs"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_address_proof_exists(view, &proof.proof_id)? {
                    return Ok(FinanceExecutionResult::failure("Address proof already exists"));
                }

                // ACTIVATION-AUDIT row AL-4, the address-proof half.
                if let Some(refusal) = Self::index_row_within_bound(
                    "Finance subject address index",
                    gates.row_limit(),
                    || Self::v_subject_address_index_row_len(view, &proof.subject_ref),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_address_proof(view, &proof)?;
                debug!("Address proof created: {:?}", proof_id);
                Ok(FinanceExecutionResult::success_with_address_proof(proof_id))
            }

            FinanceOperation::UpdateAddressProof => {
                // For now, we only support updating via revoke and re-issue
                Ok(FinanceExecutionResult::failure("Update not supported, use revoke and re-issue"))
            }

            FinanceOperation::RevokeAddressProof => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    proof_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let proof = match Self::v_get_address_proof(view, &d.proof_id)? {
                    Some(p) => p,
                    None => return Ok(FinanceExecutionResult::failure("Address proof not found")),
                };

                if proof.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                // AU-23: below the gate this path checks only the address on
                // the row and never rereads the issuer registry, so a SUSPENDED
                // or REVOKED issuer keeps full control of everything it ever
                // issued. The creation paths do check; the asymmetry is the
                // defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_address_proof(view, &d.proof_id, d.revocation_ref, block_timestamp)?;
                debug!("Address proof revoked: {:?}", d.proof_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-893: Bank Standing Operations
            // =================================================================
            FinanceOperation::CreateBankStanding => {
                let credential: BankStandingCredential = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_bank_standing() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue bank standing credentials"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_bank_standing_exists(view, &credential.credential_id)? {
                    return Ok(FinanceExecutionResult::failure("Bank standing credential already exists"));
                }

                // ACTIVATION-AUDIT row AL-4, the bank-standing half.
                if let Some(refusal) = Self::index_row_within_bound(
                    "Finance subject bank index",
                    gates.row_limit(),
                    || Self::v_subject_bank_index_row_len(view, &credential.subject_ref),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let credential_id = credential.credential_id;
                Self::v_put_bank_standing(view, &credential)?;
                debug!("Bank standing credential created: {:?}", credential_id);
                Ok(FinanceExecutionResult::success_with_bank_standing(credential_id))
            }

            FinanceOperation::UpdateBankStanding => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    credential_id: [u8; 32],
                    standing: AccountStanding,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_bank_standing(view, &d.credential_id)? {
                    Some(c) => c,
                    None => return Ok(FinanceExecutionResult::failure("Bank standing credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                // AU-23: below the gate this path checks only the address on
                // the row and never rereads the issuer registry, so a SUSPENDED
                // or REVOKED issuer keeps full control of everything it ever
                // issued. The creation paths do check; the asymmetry is the
                // defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_bank_standing(view, &d.credential_id, d.standing, block_timestamp)?;
                debug!("Bank standing updated: {:?}", d.credential_id);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeBankStanding => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    credential_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let credential = match Self::v_get_bank_standing(view, &d.credential_id)? {
                    Some(c) => c,
                    None => return Ok(FinanceExecutionResult::failure("Bank standing credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                // AU-23: below the gate this path checks only the address on
                // the row and never rereads the issuer registry, so a SUSPENDED
                // or REVOKED issuer keeps full control of everything it ever
                // issued. The creation paths do check; the asymmetry is the
                // defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_bank_standing(
                    view,
                    &d.credential_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("Bank standing credential revoked: {:?}", d.credential_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-894: KYC Attestation Operations
            // =================================================================
            FinanceOperation::CreateKycAttestation => {
                let attestation: KycAttestation = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Issuer must be sender"));
                }

                // Verify issuer is registered and active
                match Self::v_get_issuer(view, sender)? {
                    Some(issuer) => {
                        if !issuer.status.is_active() {
                            return Ok(FinanceExecutionResult::failure("Issuer is not active"));
                        }
                        if !issuer.issuer_class.can_issue_kyc() {
                            return Ok(FinanceExecutionResult::failure("Issuer cannot issue KYC attestations"));
                        }
                    }
                    None => return Ok(FinanceExecutionResult::failure("Issuer not registered")),
                }

                if Self::v_kyc_attestation_exists(view, &attestation.attestation_id)? {
                    return Ok(FinanceExecutionResult::failure("KYC attestation already exists"));
                }

                // ACTIVATION-AUDIT row AL-4, the KYC half.
                if let Some(refusal) = Self::index_row_within_bound(
                    "Finance subject KYC index",
                    gates.row_limit(),
                    || Self::v_subject_kyc_index_row_len(view, &attestation.subject_ref),
                )? {
                    return Ok(refusal);
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let attestation_id = attestation.attestation_id;
                Self::v_put_kyc_attestation(view, &attestation)?;
                debug!("KYC attestation created: {:?}", attestation_id);
                Ok(FinanceExecutionResult::success_with_kyc(attestation_id))
            }

            FinanceOperation::UpdateKycAttestation => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    attestation_id: [u8; 32],
                    status: KycStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let attestation = match Self::v_get_kyc_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(FinanceExecutionResult::failure("KYC attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can update"));
                }

                // AU-23: below the gate this path checks only the address on
                // the row and never rereads the issuer registry, so a SUSPENDED
                // or REVOKED issuer keeps full control of everything it ever
                // issued. The creation paths do check; the asymmetry is the
                // defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_kyc_status(view, &d.attestation_id, d.status, block_timestamp)?;
                debug!("KYC attestation updated: {:?}", d.attestation_id);
                Ok(FinanceExecutionResult::success())
            }

            FinanceOperation::RevokeKycAttestation => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    attestation_id: [u8; 32],
                    revocation_ref: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let attestation = match Self::v_get_kyc_attestation(view, &d.attestation_id)? {
                    Some(a) => a,
                    None => return Ok(FinanceExecutionResult::failure("KYC attestation not found")),
                };

                if attestation.issuer_address != *sender {
                    return Ok(FinanceExecutionResult::failure("Only issuer can revoke"));
                }

                // AU-23: below the gate this path checks only the address on
                // the row and never rereads the issuer registry, so a SUSPENDED
                // or REVOKED issuer keeps full control of everything it ever
                // issued. The creation paths do check; the asymmetry is the
                // defect.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Issuer is not registered and active",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_revoke_kyc_attestation(
                    view,
                    &d.attestation_id,
                    d.revocation_ref,
                    block_timestamp,
                )?;
                debug!("KYC attestation revoked: {:?}", d.attestation_id);
                Ok(FinanceExecutionResult::success())
            }

            // =================================================================
            // SRC-895: Proof Operations
            // =================================================================
            FinanceOperation::SubmitProof => {
                let proof: FinanceProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(FinanceExecutionResult::failure("Proof already exists"));
                }

                // AU-25: below the gate the duplicate-id check is the ONLY
                // guard -- no issuer, no credential reference validation, no
                // signature -- so anyone who pays writes any proof envelope
                // into the family.
                if gates.authorization && !Self::issuer_in_good_standing(view, sender)? {
                    return Ok(FinanceExecutionResult::failure(
                        "Only a registered, active issuer can submit a proof",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Finance proof submitted: {:?}", proof_id);
                Ok(FinanceExecutionResult::success_with_proof(proof_id))
            }

            FinanceOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-26 (= PR-4). Below the gate this arm reads no
                // payload and no proof and returns SUCCESS, so the chain reports a
                // verified proof for a proof it has never held, for a payload that
                // is not a proof id, and for proof bytes nothing has ever looked
                // at. At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Finance proofs exists in this tree --
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
                    return Ok(FinanceExecutionResult::failure(
                        crate::VERIFY_PROOF_UNSUPPORTED,
                    ));
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Finance proof verification requested by: {}", sender);
                Ok(FinanceExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::finance::{AccountType, BalanceBracket, FinanceIssuerClass};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    fn sample_issuer(sender: Address) -> FinanceIssuerProfile {
        FinanceIssuerProfile {
            issuer_address: sender,
            issuer_class: FinanceIssuerClass::RegulatedBank,
            issuer_commitment: [2u8; 32],
            jurisdiction_code: "US-NY".to_string(),
            policy_id: [3u8; 32],
            status: FinanceIssuerStatus::Active,
            registered_at_height: 100,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn tx(operation: FinanceOperation, payload: &impl serde::Serialize) -> FinanceTxData {
        FinanceTxData {
            operation,
            data: bincode::serialize(payload).unwrap(),
            recipient: Address::ZERO,
        }
    }

    #[test]
    fn test_register_issuer() {
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

        let issuer = sample_issuer(sender);
        let result = FinanceExecutor::execute(
            view,
            &params,
            &sender,
            &tx(FinanceOperation::RegisterIssuer, &issuer),
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Register issuer failed: {:?}", result.error);
        assert_eq!(result.issuer_address, Some(sender));

        // Read the CANDIDATE: this executor stages now.
        let retrieved = FinanceExecutor::v_get_issuer(view, &sender)
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-NY");
    }

    #[test]
    fn test_create_bank_standing() {
        let (db, _dir, _state) = setup();
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);
        let params = ChainParams::default();

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

        FinanceExecutor::execute(
            view,
            &params,
            &sender,
            &tx(FinanceOperation::RegisterIssuer, &sample_issuer(sender)),
            &proposer,
            1000,
            100,
            1000000,
            0,
            Hash::default(),
        )
        .unwrap();

        let credential = BankStandingCredential {
            credential_id: [10u8; 32],
            subject_ref: [11u8; 32],
            holder_address: Address::new([0x30; 20]),
            account_commitment: [12u8; 32],
            bank_ref: [13u8; 32],
            account_type: AccountType::Checking,
            standing: AccountStanding::Good,
            tenure_commitment: [14u8; 32],
            balance_bracket: BalanceBracket::Bracket5,
            threshold_commitment: None,
            issuer_address: sender,
            issuer_class: FinanceIssuerClass::RegulatedBank,
            valid_from: 1000,
            expiry: 2000,
            policy_id: [15u8; 32],
            revocation_ref: None,
            created_at: 1000,
            updated_at: 1000,
        };

        let result = FinanceExecutor::execute(
            view,
            &params,
            &sender,
            &tx(FinanceOperation::CreateBankStanding, &credential),
            &proposer,
            1000,
            100,
            1000000,
            1,
            Hash::default(),
        )
        .unwrap();

        assert!(result.success, "Create bank standing failed: {:?}", result.error);
        assert_eq!(result.bank_standing_id, Some([10u8; 32]));

        let retrieved = FinanceExecutor::v_get_bank_standing(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.balance_bracket, BalanceBracket::Bracket5);
    }
}
