//! SRC-85X Legal & Benefits Executor
//!
//! Transaction executor for:
//! - SRC-851: Case/Docket Anchors
//! - SRC-852: Legal Process Events
//! - SRC-853: Court Orders/Judgments
//! - SRC-854: Government Benefit Determinations
//! - SRC-855: Legal Proofs

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    legal::{
        BenefitDetermination, BenefitStatus, CaseAnchor, CaseStatus, CourtOrder, LegalOperation,
        LegalProofEnvelope, LegalTxData, OrderStatus, ProcessEvent, ProcessEventStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

use crate::{Result, StateError, StateManager};

/// Result of Legal operation execution
#[derive(Debug)]
pub struct LegalExecutionResult {
    pub success: bool,
    pub case_id: Option<[u8; 32]>,
    pub event_id: Option<[u8; 32]>,
    pub order_id: Option<[u8; 32]>,
    pub benefit_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl LegalExecutionResult {
    pub fn success_with_case(case_id: [u8; 32]) -> Self {
        Self {
            success: true,
            case_id: Some(case_id),
            event_id: None,
            order_id: None,
            benefit_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_event(event_id: [u8; 32]) -> Self {
        Self {
            success: true,
            case_id: None,
            event_id: Some(event_id),
            order_id: None,
            benefit_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_order(order_id: [u8; 32]) -> Self {
        Self {
            success: true,
            case_id: None,
            event_id: None,
            order_id: Some(order_id),
            benefit_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_benefit(benefit_id: [u8; 32]) -> Self {
        Self {
            success: true,
            case_id: None,
            event_id: None,
            order_id: None,
            benefit_id: Some(benefit_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            case_id: None,
            event_id: None,
            order_id: None,
            benefit_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            case_id: None,
            event_id: None,
            order_id: None,
            benefit_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            case_id: None,
            event_id: None,
            order_id: None,
            benefit_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Legal executor for SRC-85X transactions.
///
/// No database handle, by construction: every operation takes the block's
/// `ExecutionView` and no `self`, so `self.db` is not something this file can
/// name. The committed twins stay in `sumchain_storage::legal_store` for the
/// RPC server, which answers about the canonical chain.
///
/// The `ChainParams` this type used to hold was `#[allow(dead_code)]` and read
/// by nothing; it went with the handle rather than being threaded through as a
/// parameter no operation consults.
pub struct LegalExecutor;

/// The activation decisions a Legal transaction executes under.
///
/// [`LegalExecutor::execute`] derives it from `ChainParams`;
/// [`LegalExecutor::execute_with_gates`] takes it directly, which is how a test
/// drives an ungated node and a gated node over the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegalGates {
    /// The subsystem's authority checks are enforced. ACTIVATION-AUDIT rows
    /// AU-13, AU-14, AU-15 and AU-16.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT AU-17 (= PR-3). Supersedes the retired presence check: no
    /// verifier exists in this tree, so the operation cannot be performed
    /// and must not report success.
    pub proof_unsupported: bool,
    /// A payload-chosen index key is bounded before it becomes a key.
    /// ACTIVATION-AUDIT row the Legal instance of AL-7.
    pub allocation_bound: bool,
    /// An operation that writes nothing reports a failed receipt rather
    /// than a success one. ACTIVATION-AUDIT row OV-6.
    pub no_op_receipt: bool,
}

impl LegalGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        proof_unsupported: false,
        allocation_bound: false,
        no_op_receipt: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        proof_unsupported: true,
        allocation_bound: true,
        no_op_receipt: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: LegalExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
            no_op_receipt: crate::subsystem_no_op_receipt_gate_open(params, block_height),
        }
    }
}

impl LegalExecutor {
    /// The activation height for the Legal authority checks.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-85X Legal authority checks. Dormant by default (`None` -> never
    /// /// open). Below the gate `ConsolidateCase` and `TransferCase` have no
    /// /// authority check at all, `SupersedeOrder` has neither an authority
    /// /// check nor a duplicate guard -- so a stranger overwrites a different
    /// /// existing order by reusing its id -- and `SupersedeEvent` does not
    /// /// verify that the replacement's case exists, leaving a dangling
    /// /// case-to-event index entry the attacker chose. At and above the gate
    /// /// each of those is enforced. Activation is a consensus change and needs
    /// /// a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub legal_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and every pinning test that records the gap still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.legal_authorization_enabled_from_height
    }

    /// Whether the Legal authority checks are active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// Execute a Legal transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &LegalTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<LegalExecutionResult> {
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
            LegalGates::from_params(params, block_height),
        )
    }

    /// Execute a Legal transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &LegalTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: LegalGates,
    ) -> Result<LegalExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
        match data.operation {
            // SRC-851: Case Anchor Operations
            LegalOperation::AnchorCase => {
                let case: CaseAnchor = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_case_exists(view, &case.case_id)? {
                    return Ok(LegalExecutionResult::failure("Case already exists"));
                }

                // ACTIVATION-AUDIT AL-7, the Legal instance. `CaseAnchor.jurisdiction_code` is free text from the
                // sender's own payload and becomes the raw KEY of
                // `cf::LEGAL_JURISDICTION_INDEX`, with no width check anywhere ahead of
                // the `put`. Below the gate one transaction writes a key of
                // most of `max_block_bytes`. At and above it the key is
                // bounded. Refused before the fee, like the duplicate guard
                // above it.
                if !crate::index_key_text_within_bound(
                    &case.jurisdiction_code,
                    gates.allocation_bound,
                ) {
                    return Ok(LegalExecutionResult::failure(format!(
                        "Jurisdiction code too long: {} bytes, limit {}",
                        case.jurisdiction_code.len(),
                        crate::MAX_INDEX_KEY_TEXT_BYTES
                    )));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let case_id = case.case_id;
                Self::v_put_case(view, &case)?;
                debug!("Case anchored: {:?}", case_id);
                Ok(LegalExecutionResult::success_with_case(case_id))
            }

            LegalOperation::UpdateCase => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    case_id: [u8; 32],
                    status: CaseStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &update.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(view, &update.case_id, update.status, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::CloseCase => {
                #[derive(serde::Deserialize)]
                struct CloseData {
                    case_id: [u8; 32],
                }
                let d: CloseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can close"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(view, &d.case_id, CaseStatus::Closed, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SealCase => {
                #[derive(serde::Deserialize)]
                struct SealData {
                    case_id: [u8; 32],
                }
                let d: SealData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can seal"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(view, &d.case_id, CaseStatus::Sealed, block_timestamp)?;
                debug!("Case sealed: {:?}", d.case_id);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::UnsealCase => {
                #[derive(serde::Deserialize)]
                struct UnsealData {
                    case_id: [u8; 32],
                }
                let d: UnsealData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.status != CaseStatus::Sealed {
                    return Ok(LegalExecutionResult::failure("Case is not sealed"));
                }

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can unseal"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(view, &d.case_id, CaseStatus::Active, block_timestamp)?;
                debug!("Case unsealed: {:?}", d.case_id);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::ConsolidateCase => {
                #[derive(serde::Deserialize)]
                struct ConsolidateData {
                    case_id: [u8; 32],
                    related_case_id: [u8; 32],
                }
                let d: ConsolidateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };
                let related = match Self::v_get_case(view, &d.related_case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Related case not found")),
                };

                // AU-13: below the gate the only guards are existence, so any
                // funded account attaches one stranger's case to another's and
                // moves the second to `Consolidated`. Both issuers are required
                // at the gate, because the operation changes both rows.
                // Contrast `CloseCase`, which has always checked.
                if gates.authorization
                    && (case.issuer_address != *sender || related.issuer_address != *sender)
                {
                    return Ok(LegalExecutionResult::failure(
                        "Only the issuer of both cases can consolidate them",
                    ));
                }

                // ACTIVATION-AUDIT row OV-6. `v_add_related_case` is
                // `contains`-gated: when the relation is already recorded it
                // skips the append AND the `updated_at` write, which lives
                // inside the same branch, so a repeated consolidation leaves
                // the primary case row byte-for-byte unchanged and still
                // reports success. At and above the gate it says so instead.
                //
                // Refused before the deduct, where this arm's existence guards
                // return.
                if gates.no_op_receipt && case.related_cases.contains(&d.related_case_id) {
                    return Ok(LegalExecutionResult::failure(
                        "Cases are already consolidated",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_add_related_case(view, &d.case_id, &d.related_case_id, block_timestamp)?;
                Self::v_update_case_status(
                    view,
                    &d.related_case_id,
                    CaseStatus::Consolidated,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::TransferCase => {
                #[derive(serde::Deserialize)]
                struct TransferData {
                    case_id: [u8; 32],
                }
                let d: TransferData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match Self::v_get_case(view, &d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                // AU-14: existence was the only guard.
                if gates.authorization && case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can transfer"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(
                    view,
                    &d.case_id,
                    CaseStatus::Transferred,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-852: Process Event Operations
            LegalOperation::RecordEvent => {
                let event: ProcessEvent = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if event.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                // Verify case exists
                if Self::v_get_case(view, &event.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                if Self::v_process_event_exists(view, &event.event_id)? {
                    return Ok(LegalExecutionResult::failure("Event already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let event_id = event.event_id;
                Self::v_put_process_event(view, &event)?;
                debug!("Process event recorded: {:?}", event_id);
                Ok(LegalExecutionResult::success_with_event(event_id))
            }

            LegalOperation::UpdateEvent => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    event_id: [u8; 32],
                    status: ProcessEventStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let event = match Self::v_get_process_event(view, &d.event_id)? {
                    Some(e) => e,
                    None => return Ok(LegalExecutionResult::failure("Event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_process_event_status(view, &d.event_id, d.status)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SupersedeEvent => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_event_id: [u8; 32],
                    new_event: ProcessEvent,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let old_event = match Self::v_get_process_event(view, &d.old_event_id)? {
                    Some(e) => e,
                    None => return Ok(LegalExecutionResult::failure("Old event not found")),
                };

                // AU-16: below the gate the replacement's case is never
                // checked, so a stranger's supersession creates a case-to-event
                // index entry under a case id it chose and that need not exist.
                // Contrast `RecordEvent`, which does read the case.
                if gates.authorization {
                    if old_event.issuer_address != *sender {
                        return Ok(LegalExecutionResult::failure("Only issuer can supersede"));
                    }
                    if Self::v_get_case(view, &d.new_event.case_id)?.is_none() {
                        return Ok(LegalExecutionResult::failure(
                            "The replacement event names a case that does not exist",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_process_event_status(
                    view,
                    &d.old_event_id,
                    ProcessEventStatus::Superseded,
                )?;

                // Store new event
                let new_id = d.new_event.event_id;
                Self::v_put_process_event(view, &d.new_event)?;
                debug!("Event superseded: {:?} -> {:?}", d.old_event_id, new_id);
                Ok(LegalExecutionResult::success_with_event(new_id))
            }

            LegalOperation::RevokeEvent => {
                #[derive(serde::Deserialize)]
                struct RevokeData {
                    event_id: [u8; 32],
                }
                let d: RevokeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let event = match Self::v_get_process_event(view, &d.event_id)? {
                    Some(e) => e,
                    None => return Ok(LegalExecutionResult::failure("Event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can revoke"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_process_event_status(
                    view,
                    &d.event_id,
                    ProcessEventStatus::Revoked,
                )?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-853: Court Order Operations
            LegalOperation::IssueOrder => {
                let order: CourtOrder = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                // Verify case exists
                if Self::v_get_case(view, &order.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                if Self::v_order_exists(view, &order.order_id)? {
                    return Ok(LegalExecutionResult::failure("Order already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let order_id = order.order_id;
                Self::v_put_order(view, &order)?;
                debug!("Order issued: {:?}", order_id);
                Ok(LegalExecutionResult::success_with_order(order_id))
            }

            LegalOperation::UpdateOrderStatus => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    order_id: [u8; 32],
                    status: OrderStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let order = match Self::v_get_order(view, &d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_order_status(view, &d.order_id, d.status, block_timestamp)?;
                debug!("Order status updated: {:?} -> {:?}", d.order_id, d.status);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::StayOrder => {
                #[derive(serde::Deserialize)]
                struct StayData {
                    order_id: [u8; 32],
                }
                let d: StayData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let order = match Self::v_get_order(view, &d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can stay"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_order_status(
                    view,
                    &d.order_id,
                    OrderStatus::Stayed,
                    block_timestamp,
                )?;
                debug!("Order stayed: {:?}", d.order_id);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::VacateOrder => {
                #[derive(serde::Deserialize)]
                struct VacateData {
                    order_id: [u8; 32],
                }
                let d: VacateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let order = match Self::v_get_order(view, &d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can vacate"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_order_status(
                    view,
                    &d.order_id,
                    OrderStatus::Vacated,
                    block_timestamp,
                )?;
                debug!("Order vacated: {:?}", d.order_id);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SupersedeOrder => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_order_id: [u8; 32],
                    new_order: CourtOrder,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let old_order = match Self::v_get_order(view, &d.old_order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Old order not found")),
                };

                // AU-15, both halves. Below the gate this arm has no authority
                // check AND no duplicate guard, so a stranger supersedes an
                // order and, by reusing an existing order's id for the
                // replacement, overwrites a different order in the same
                // transaction.
                if gates.authorization {
                    if old_order.issuer_address != *sender {
                        return Ok(LegalExecutionResult::failure("Only issuer can supersede"));
                    }
                    if d.new_order.issuer_address != *sender {
                        return Ok(LegalExecutionResult::failure(
                            "The replacement order must be issued by the sender",
                        ));
                    }
                    if d.new_order.order_id != d.old_order_id
                        && Self::v_get_order(view, &d.new_order.order_id)?.is_some()
                    {
                        return Ok(LegalExecutionResult::failure(
                            "The replacement order id is already in use",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_order_status(
                    view,
                    &d.old_order_id,
                    OrderStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new order
                let new_id = d.new_order.order_id;
                Self::v_put_order(view, &d.new_order)?;
                debug!("Order superseded: {:?} -> {:?}", d.old_order_id, new_id);
                Ok(LegalExecutionResult::success_with_order(new_id))
            }

            LegalOperation::ModifyOrder => {
                #[derive(serde::Deserialize)]
                struct ModifyData {
                    order_id: [u8; 32],
                }
                let d: ModifyData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let order = match Self::v_get_order(view, &d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can modify"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_order_status(
                    view,
                    &d.order_id,
                    OrderStatus::Modified,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-854: Benefit Determination Operations
            LegalOperation::DetermineBenefit => {
                let benefit: BenefitDetermination = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                if Self::v_benefit_exists(view, &benefit.benefit_id)? {
                    return Ok(LegalExecutionResult::failure("Benefit already exists"));
                }

                // ACTIVATION-AUDIT AL-7, the Legal benefit instance. `BenefitDetermination.jurisdiction_code` is free text from the
                // sender's own payload and becomes the raw KEY of
                // `cf::LEGAL_JURISDICTION_INDEX`, with no width check anywhere ahead of
                // the `put`. Below the gate one transaction writes a key of
                // most of `max_block_bytes`. At and above it the key is
                // bounded. Refused before the fee, like the duplicate guard
                // above it.
                if !crate::index_key_text_within_bound(
                    &benefit.jurisdiction_code,
                    gates.allocation_bound,
                ) {
                    return Ok(LegalExecutionResult::failure(format!(
                        "Jurisdiction code too long: {} bytes, limit {}",
                        benefit.jurisdiction_code.len(),
                        crate::MAX_INDEX_KEY_TEXT_BYTES
                    )));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let benefit_id = benefit.benefit_id;
                Self::v_put_benefit(view, &benefit)?;
                debug!("Benefit determined: {:?}", benefit_id);
                Ok(LegalExecutionResult::success_with_benefit(benefit_id))
            }

            LegalOperation::UpdateBenefitStatus => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    benefit_id: [u8; 32],
                    status: BenefitStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match Self::v_get_benefit(view, &d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_benefit_status(view, &d.benefit_id, d.status, block_timestamp)?;
                debug!("Benefit status updated: {:?} -> {:?}", d.benefit_id, d.status);
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::TerminateBenefit => {
                #[derive(serde::Deserialize)]
                struct TerminateData {
                    benefit_id: [u8; 32],
                }
                let d: TerminateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match Self::v_get_benefit(view, &d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can terminate"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_benefit_status(
                    view,
                    &d.benefit_id,
                    BenefitStatus::Terminated,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SuspendBenefit => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    benefit_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match Self::v_get_benefit(view, &d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_benefit_status(
                    view,
                    &d.benefit_id,
                    BenefitStatus::Suspended,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::ReinstateBenefit => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    benefit_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match Self::v_get_benefit(view, &d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can reinstate"));
                }

                if benefit.status != BenefitStatus::Suspended {
                    return Ok(LegalExecutionResult::failure("Benefit is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_benefit_status(
                    view,
                    &d.benefit_id,
                    BenefitStatus::Approved,
                    block_timestamp,
                )?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-855: Proof Operations
            LegalOperation::SubmitProof => {
                let proof: LegalProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_proof_exists(view, &proof.proof_id)? {
                    return Ok(LegalExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_proof(view, &proof)?;
                debug!("Legal proof submitted: {:?}", proof_id);
                Ok(LegalExecutionResult::success_with_proof(proof_id))
            }

            LegalOperation::VerifyProof => {
                // ACTIVATION-AUDIT AU-17 (= PR-3). Below the gate this arm reads no
                // payload and no proof and returns SUCCESS, so the chain reports a
                // verified proof for a proof it has never held, for a payload that
                // is not a proof id, and for proof bytes nothing has ever looked
                // at. At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Legal proofs exists in this tree --
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
                    return Ok(LegalExecutionResult::failure(
                        crate::VERIFY_PROOF_UNSUPPORTED,
                    ));
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Legal proof verification requested by: {}", sender);
                Ok(LegalExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use sumchain_primitives::legal::{CaseType, LegalIssuerClass};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_anchor_case() {
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

        let case = CaseAnchor {
            case_id: [10u8; 32],
            case_commitment: [11u8; 32],
            jurisdiction_code: "US-NY-SDNY".to_string(),
            case_type: Some(CaseType::Civil),
            public_reference: None,
            policy_id: [12u8; 32],
            issuer_class: LegalIssuerClass::LawFirm,
            issuer_address: sender,
            status: CaseStatus::Filed,
            created_at: 1000,
            updated_at: 1000,
            anchored_at_height: 100,
            related_cases: vec![],
        };

        let tx_data = LegalTxData {
            operation: LegalOperation::AnchorCase,
            data: bincode::serialize(&case).unwrap(),
            recipient: Address::ZERO,
        };

        let result = LegalExecutor::execute(
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

        assert!(result.success, "Anchor case failed: {:?}", result.error);
        assert_eq!(result.case_id, Some([10u8; 32]));

        // Read the CANDIDATE: this executor stages now.
        let retrieved = LegalExecutor::v_get_case(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-NY-SDNY");
    }
}
