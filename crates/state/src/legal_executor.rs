//! SRC-85X Legal & Benefits Executor
//!
//! Transaction executor for:
//! - SRC-851: Case/Docket Anchors
//! - SRC-852: Legal Process Events
//! - SRC-853: Court Orders/Judgments
//! - SRC-854: Government Benefit Determinations
//! - SRC-855: Legal Proofs

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    legal::{
        BenefitDetermination, BenefitStatus, CaseAnchor, CaseStatus, CourtOrder, LegalOperation,
        LegalProofEnvelope, LegalTxData, OrderStatus, ProcessEvent, ProcessEventStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use sumchain_storage::{Database, LegalStore};
use tracing::debug;

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

/// Legal executor for SRC-85X transactions
pub struct LegalExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl LegalExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute a Legal transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &LegalTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<LegalExecutionResult> {
        let store = LegalStore::new(&self.db);

        match data.operation {
            // SRC-851: Case Anchor Operations
            LegalOperation::AnchorCase => {
                let case: CaseAnchor = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                if store.cases().exists(&case.case_id)? {
                    return Ok(LegalExecutionResult::failure("Case already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let case_id = case.case_id;
                store.cases().put(&case)?;
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

                let case = match store.cases().get(&update.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().update_status(&update.case_id, update.status, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::CloseCase => {
                #[derive(serde::Deserialize)]
                struct CloseData {
                    case_id: [u8; 32],
                }
                let d: CloseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match store.cases().get(&d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can close"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().update_status(&d.case_id, CaseStatus::Closed, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SealCase => {
                #[derive(serde::Deserialize)]
                struct SealData {
                    case_id: [u8; 32],
                }
                let d: SealData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let case = match store.cases().get(&d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can seal"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().update_status(&d.case_id, CaseStatus::Sealed, block_timestamp)?;
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

                let case = match store.cases().get(&d.case_id)? {
                    Some(c) => c,
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                };

                if case.status != CaseStatus::Sealed {
                    return Ok(LegalExecutionResult::failure("Case is not sealed"));
                }

                if case.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can unseal"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().update_status(&d.case_id, CaseStatus::Active, block_timestamp)?;
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

                if store.cases().get(&d.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }
                if store.cases().get(&d.related_case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Related case not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().add_related_case(&d.case_id, &d.related_case_id, block_timestamp)?;
                store.cases().update_status(&d.related_case_id, CaseStatus::Consolidated, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::TransferCase => {
                #[derive(serde::Deserialize)]
                struct TransferData {
                    case_id: [u8; 32],
                }
                let d: TransferData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.cases().get(&d.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.cases().update_status(&d.case_id, CaseStatus::Transferred, block_timestamp)?;
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
                if store.cases().get(&event.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                if store.process_events().exists(&event.event_id)? {
                    return Ok(LegalExecutionResult::failure("Event already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let event_id = event.event_id;
                store.process_events().put(&event)?;
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

                let event = match store.process_events().get(&d.event_id)? {
                    Some(e) => e,
                    None => return Ok(LegalExecutionResult::failure("Event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.process_events().update_status(&d.event_id, d.status)?;
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

                if store.process_events().get(&d.old_event_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old event not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                // Mark old as superseded
                store.process_events().update_status(&d.old_event_id, ProcessEventStatus::Superseded)?;

                // Store new event
                let new_id = d.new_event.event_id;
                store.process_events().put(&d.new_event)?;
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

                let event = match store.process_events().get(&d.event_id)? {
                    Some(e) => e,
                    None => return Ok(LegalExecutionResult::failure("Event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can revoke"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.process_events().update_status(&d.event_id, ProcessEventStatus::Revoked)?;
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
                if store.cases().get(&order.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                if store.orders().exists(&order.order_id)? {
                    return Ok(LegalExecutionResult::failure("Order already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let order_id = order.order_id;
                store.orders().put(&order)?;
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

                let order = match store.orders().get(&d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.orders().update_status(&d.order_id, d.status, block_timestamp)?;
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

                let order = match store.orders().get(&d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can stay"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.orders().update_status(&d.order_id, OrderStatus::Stayed, block_timestamp)?;
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

                let order = match store.orders().get(&d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can vacate"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.orders().update_status(&d.order_id, OrderStatus::Vacated, block_timestamp)?;
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

                if store.orders().get(&d.old_order_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old order not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                // Mark old as superseded
                store.orders().update_status(&d.old_order_id, OrderStatus::Superseded, block_timestamp)?;

                // Store new order
                let new_id = d.new_order.order_id;
                store.orders().put(&d.new_order)?;
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

                let order = match store.orders().get(&d.order_id)? {
                    Some(o) => o,
                    None => return Ok(LegalExecutionResult::failure("Order not found")),
                };

                if order.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can modify"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.orders().update_status(&d.order_id, OrderStatus::Modified, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-854: Benefit Determination Operations
            LegalOperation::DetermineBenefit => {
                let benefit: BenefitDetermination = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Issuer must be sender"));
                }

                if store.benefits().exists(&benefit.benefit_id)? {
                    return Ok(LegalExecutionResult::failure("Benefit already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let benefit_id = benefit.benefit_id;
                store.benefits().put(&benefit)?;
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

                let benefit = match store.benefits().get(&d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.benefits().update_status(&d.benefit_id, d.status, block_timestamp)?;
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

                let benefit = match store.benefits().get(&d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can terminate"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.benefits().update_status(&d.benefit_id, BenefitStatus::Terminated, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::SuspendBenefit => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    benefit_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match store.benefits().get(&d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can suspend"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.benefits().update_status(&d.benefit_id, BenefitStatus::Suspended, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            LegalOperation::ReinstateBenefit => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    benefit_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let benefit = match store.benefits().get(&d.benefit_id)? {
                    Some(b) => b,
                    None => return Ok(LegalExecutionResult::failure("Benefit not found")),
                };

                if benefit.issuer_address != *sender {
                    return Ok(LegalExecutionResult::failure("Only issuer can reinstate"));
                }

                if benefit.status != BenefitStatus::Suspended {
                    return Ok(LegalExecutionResult::failure("Benefit is not suspended"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.benefits().update_status(&d.benefit_id, BenefitStatus::Approved, block_timestamp)?;
                Ok(LegalExecutionResult::success())
            }

            // SRC-855: Proof Operations
            LegalOperation::SubmitProof => {
                let proof: LegalProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.proofs().exists(&proof.proof_id)? {
                    return Ok(LegalExecutionResult::failure("Proof already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let proof_id = proof.proof_id;
                store.proofs().put(&proof)?;
                debug!("Legal proof submitted: {:?}", proof_id);
                Ok(LegalExecutionResult::success_with_proof(proof_id))
            }

            LegalOperation::VerifyProof => {
                // Verification is read-only - just record the request
                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                debug!("Legal proof verification requested by: {}", sender);
                Ok(LegalExecutionResult::success())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_legal_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = LegalExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_anchor_case() {
        let (db, _dir, state) = setup();
        let executor = LegalExecutor::new(db.clone(), ChainParams::default());

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&sender, 1_000_000_000_000).unwrap();

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
        };

        let result = executor.execute(
            &sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Anchor case failed: {:?}", result.error);
        assert_eq!(result.case_id, Some([10u8; 32]));

        // Verify storage
        let store = LegalStore::new(&db);
        let retrieved = store.cases().get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-NY-SDNY");
    }
}
