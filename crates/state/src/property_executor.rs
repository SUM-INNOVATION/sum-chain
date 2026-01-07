//! SRC-86X Property, Real Estate & Insurance Executor
//!
//! Transaction executor for:
//! - SRC-861: Asset Anchor (Property/Asset Identity)
//! - SRC-862: Title/Ownership State Event
//! - SRC-863: Encumbrance Standard (Lien/Mortgage/Leasehold)
//! - SRC-864: Insurance Coverage Standard
//! - SRC-865: Insurance Claim Lifecycle
//! - SRC-866: 86X Proof Profiles

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    property::{
        AssetAnchor, AssetStatus, ClaimStatus, CoverageStatus, Encumbrance, EncumbranceStatus,
        InsuranceClaim, InsuranceCoverage, PropertyOperation, PropertyProofEnvelope, PropertyTxData,
        TitleEvent, TitleEventStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use sumchain_storage::{Database, PropertyStore};
use tracing::debug;

use crate::{Result, StateError, StateManager};

/// Result of Property operation execution
#[derive(Debug)]
pub struct PropertyExecutionResult {
    pub success: bool,
    pub asset_id: Option<[u8; 32]>,
    pub title_event_id: Option<[u8; 32]>,
    pub encumbrance_id: Option<[u8; 32]>,
    pub coverage_id: Option<[u8; 32]>,
    pub claim_id: Option<[u8; 32]>,
    pub proof_id: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl PropertyExecutionResult {
    pub fn success_with_asset(asset_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: Some(asset_id),
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: None,
            claim_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_title_event(event_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: Some(event_id),
            encumbrance_id: None,
            coverage_id: None,
            claim_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_encumbrance(encumbrance_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: Some(encumbrance_id),
            coverage_id: None,
            claim_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_coverage(coverage_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: Some(coverage_id),
            claim_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_claim(claim_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: None,
            claim_id: Some(claim_id),
            proof_id: None,
            error: None,
        }
    }

    pub fn success_with_proof(proof_id: [u8; 32]) -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: None,
            claim_id: None,
            proof_id: Some(proof_id),
            error: None,
        }
    }

    pub fn success() -> Self {
        Self {
            success: true,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: None,
            claim_id: None,
            proof_id: None,
            error: None,
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            asset_id: None,
            title_event_id: None,
            encumbrance_id: None,
            coverage_id: None,
            claim_id: None,
            proof_id: None,
            error: Some(error.into()),
        }
    }
}

/// Property executor for SRC-86X transactions
pub struct PropertyExecutor {
    db: Arc<Database>,
    #[allow(dead_code)]
    params: ChainParams,
}

impl PropertyExecutor {
    pub fn new(db: Arc<Database>, params: ChainParams) -> Self {
        Self { db, params }
    }

    /// Execute a Property transaction
    pub fn execute(
        &self,
        sender: &Address,
        data: &PropertyTxData,
        state: &StateManager,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
    ) -> Result<PropertyExecutionResult> {
        let store = PropertyStore::new(&self.db);

        match data.operation {
            // =================================================================
            // SRC-861: Asset Anchor Operations
            // =================================================================
            PropertyOperation::AnchorAsset => {
                let asset: AssetAnchor = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Issuer must be sender"));
                }

                if store.assets().exists(&asset.asset_id)? {
                    return Ok(PropertyExecutionResult::failure("Asset already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let asset_id = asset.asset_id;
                store.assets().put(&asset)?;
                debug!("Asset anchored: {:?}", asset_id);
                Ok(PropertyExecutionResult::success_with_asset(asset_id))
            }

            PropertyOperation::UpdateAsset => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    asset_id: [u8; 32],
                    status: AssetStatus,
                }
                let update: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match store.assets().get(&update.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.assets().update_status(&update.asset_id, update.status, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::TransferAsset => {
                #[derive(serde::Deserialize)]
                struct TransferData {
                    asset_id: [u8; 32],
                }
                let d: TransferData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match store.assets().get(&d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can transfer"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.assets().update_status(&d.asset_id, AssetStatus::PendingTransfer, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::MergeAssets => {
                #[derive(serde::Deserialize)]
                struct MergeData {
                    primary_asset_id: [u8; 32],
                    secondary_asset_id: [u8; 32],
                }
                let d: MergeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.assets().get(&d.primary_asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Primary asset not found"));
                }
                if store.assets().get(&d.secondary_asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Secondary asset not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.assets().update_status(&d.secondary_asset_id, AssetStatus::Merged, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SubdivideAsset => {
                #[derive(serde::Deserialize)]
                struct SubdivideData {
                    asset_id: [u8; 32],
                }
                let d: SubdivideData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match store.assets().get(&d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can subdivide"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.assets().update_status(&d.asset_id, AssetStatus::Subdivided, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::DeregisterAsset => {
                #[derive(serde::Deserialize)]
                struct DeregisterData {
                    asset_id: [u8; 32],
                }
                let d: DeregisterData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match store.assets().get(&d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can deregister"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.assets().update_status(&d.asset_id, AssetStatus::Deregistered, block_timestamp)?;
                debug!("Asset deregistered: {:?}", d.asset_id);
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-862: Title Event Operations
            // =================================================================
            PropertyOperation::RecordTitleEvent => {
                let event: TitleEvent = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if event.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Issuer must be sender"));
                }

                // Verify asset exists
                if store.assets().get(&event.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if store.title_events().exists(&event.event_id)? {
                    return Ok(PropertyExecutionResult::failure("Title event already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let event_id = event.event_id;
                store.title_events().put(&event)?;
                debug!("Title event recorded: {:?}", event_id);
                Ok(PropertyExecutionResult::success_with_title_event(event_id))
            }

            PropertyOperation::UpdateTitleEvent => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    event_id: [u8; 32],
                    status: TitleEventStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let event = match store.title_events().get(&d.event_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Title event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.title_events().update_status(&d.event_id, d.status, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SupersedeTitleEvent => {
                #[derive(serde::Deserialize)]
                struct SupersedeData {
                    old_event_id: [u8; 32],
                    new_event: TitleEvent,
                }
                let d: SupersedeData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.title_events().get(&d.old_event_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Old event not found"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;

                // Mark old as superseded
                store.title_events().update_status(&d.old_event_id, TitleEventStatus::Superseded, block_timestamp)?;

                // Store new event
                let new_id = d.new_event.event_id;
                store.title_events().put(&d.new_event)?;
                debug!("Title event superseded: {:?} -> {:?}", d.old_event_id, new_id);
                Ok(PropertyExecutionResult::success_with_title_event(new_id))
            }

            PropertyOperation::VoidTitleEvent => {
                #[derive(serde::Deserialize)]
                struct VoidData {
                    event_id: [u8; 32],
                }
                let d: VoidData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let event = match store.title_events().get(&d.event_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Title event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can void"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.title_events().update_status(&d.event_id, TitleEventStatus::Voided, block_timestamp)?;
                debug!("Title event voided: {:?}", d.event_id);
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-863: Encumbrance Operations
            // =================================================================
            PropertyOperation::RecordEncumbrance => {
                let encumbrance: Encumbrance = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Issuer must be sender"));
                }

                // Verify asset exists
                if store.assets().get(&encumbrance.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if store.encumbrances().exists(&encumbrance.encumbrance_id)? {
                    return Ok(PropertyExecutionResult::failure("Encumbrance already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let encumbrance_id = encumbrance.encumbrance_id;
                store.encumbrances().put(&encumbrance)?;
                debug!("Encumbrance recorded: {:?}", encumbrance_id);
                Ok(PropertyExecutionResult::success_with_encumbrance(encumbrance_id))
            }

            PropertyOperation::UpdateEncumbrance => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    encumbrance_id: [u8; 32],
                    status: EncumbranceStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let encumbrance = match store.encumbrances().get(&d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.encumbrances().update_status(&d.encumbrance_id, d.status, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SubordinateEncumbrance => {
                #[derive(serde::Deserialize)]
                struct SubordinateData {
                    encumbrance_id: [u8; 32],
                }
                let d: SubordinateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let encumbrance = match store.encumbrances().get(&d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can subordinate"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.encumbrances().update_status(&d.encumbrance_id, EncumbranceStatus::Subordinated, block_timestamp)?;
                debug!("Encumbrance subordinated: {:?}", d.encumbrance_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ReleaseEncumbrance => {
                #[derive(serde::Deserialize)]
                struct ReleaseData {
                    encumbrance_id: [u8; 32],
                }
                let d: ReleaseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let encumbrance = match store.encumbrances().get(&d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can release"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.encumbrances().update_status(&d.encumbrance_id, EncumbranceStatus::Released, block_timestamp)?;
                debug!("Encumbrance released: {:?}", d.encumbrance_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ForecloseEncumbrance => {
                #[derive(serde::Deserialize)]
                struct ForecloseData {
                    encumbrance_id: [u8; 32],
                }
                let d: ForecloseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let encumbrance = match store.encumbrances().get(&d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can foreclose"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.encumbrances().update_status(&d.encumbrance_id, EncumbranceStatus::Foreclosed, block_timestamp)?;
                debug!("Encumbrance foreclosed: {:?}", d.encumbrance_id);
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-864: Insurance Coverage Operations
            // =================================================================
            PropertyOperation::IssueCoverage => {
                let coverage: InsuranceCoverage = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Issuer must be sender"));
                }

                // Verify asset exists
                if store.assets().get(&coverage.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if store.coverage().exists(&coverage.coverage_id)? {
                    return Ok(PropertyExecutionResult::failure("Coverage already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let coverage_id = coverage.coverage_id;
                store.coverage().put(&coverage)?;
                debug!("Coverage issued: {:?}", coverage_id);
                Ok(PropertyExecutionResult::success_with_coverage(coverage_id))
            }

            PropertyOperation::UpdateCoverage => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    coverage_id: [u8; 32],
                    status: CoverageStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match store.coverage().get(&d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.coverage().update_status(&d.coverage_id, d.status, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::RenewCoverage => {
                #[derive(serde::Deserialize)]
                struct RenewData {
                    coverage_id: [u8; 32],
                    new_expiry: Timestamp,
                }
                let d: RenewData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match store.coverage().get(&d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can renew"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.coverage().renew(&d.coverage_id, d.new_expiry, block_timestamp)?;
                debug!("Coverage renewed: {:?}", d.coverage_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::CancelCoverage => {
                #[derive(serde::Deserialize)]
                struct CancelData {
                    coverage_id: [u8; 32],
                }
                let d: CancelData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match store.coverage().get(&d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can cancel"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.coverage().update_status(&d.coverage_id, CoverageStatus::Cancelled, block_timestamp)?;
                debug!("Coverage cancelled: {:?}", d.coverage_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SuspendCoverage => {
                #[derive(serde::Deserialize)]
                struct SuspendData {
                    coverage_id: [u8; 32],
                }
                let d: SuspendData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match store.coverage().get(&d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can suspend"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.coverage().update_status(&d.coverage_id, CoverageStatus::Suspended, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ReinstateCoverage => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    coverage_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match store.coverage().get(&d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can reinstate"));
                }

                if coverage.status != CoverageStatus::Suspended {
                    return Ok(PropertyExecutionResult::failure("Coverage is not suspended"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.coverage().update_status(&d.coverage_id, CoverageStatus::Active, block_timestamp)?;
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-865: Insurance Claim Operations
            // =================================================================
            PropertyOperation::FileClaim => {
                let claim: InsuranceClaim = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Issuer must be sender"));
                }

                // Verify coverage exists
                if store.coverage().get(&claim.coverage_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Coverage not found"));
                }

                if store.claims().exists(&claim.claim_id)? {
                    return Ok(PropertyExecutionResult::failure("Claim already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let claim_id = claim.claim_id;
                store.claims().put(&claim)?;
                debug!("Claim filed: {:?}", claim_id);
                Ok(PropertyExecutionResult::success_with_claim(claim_id))
            }

            PropertyOperation::UpdateClaim => {
                #[derive(serde::Deserialize)]
                struct UpdateData {
                    claim_id: [u8; 32],
                    status: ClaimStatus,
                }
                let d: UpdateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().update_status(&d.claim_id, d.status, block_timestamp)?;
                debug!("Claim status updated: {:?} -> {:?}", d.claim_id, d.status);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ApproveClaim => {
                #[derive(serde::Deserialize)]
                struct ApproveData {
                    claim_id: [u8; 32],
                    approved_amount_commitment: [u8; 32],
                }
                let d: ApproveData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can approve"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().approve(&d.claim_id, d.approved_amount_commitment, block_timestamp)?;
                debug!("Claim approved: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::DenyClaim => {
                #[derive(serde::Deserialize)]
                struct DenyData {
                    claim_id: [u8; 32],
                }
                let d: DenyData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can deny"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().update_status(&d.claim_id, ClaimStatus::Denied, block_timestamp)?;
                debug!("Claim denied: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::PayClaim => {
                #[derive(serde::Deserialize)]
                struct PayData {
                    claim_id: [u8; 32],
                    paid_amount_commitment: [u8; 32],
                }
                let d: PayData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can pay"));
                }

                if !matches!(claim.status, ClaimStatus::Approved | ClaimStatus::PartiallyApproved) {
                    return Ok(PropertyExecutionResult::failure("Claim not approved"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().pay(&d.claim_id, d.paid_amount_commitment, block_timestamp)?;
                debug!("Claim paid: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::CloseClaim => {
                #[derive(serde::Deserialize)]
                struct CloseData {
                    claim_id: [u8; 32],
                }
                let d: CloseData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can close"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().update_status(&d.claim_id, ClaimStatus::Closed, block_timestamp)?;
                debug!("Claim closed: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ReopenClaim => {
                #[derive(serde::Deserialize)]
                struct ReopenData {
                    claim_id: [u8; 32],
                }
                let d: ReopenData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can reopen"));
                }

                if !matches!(claim.status, ClaimStatus::Closed | ClaimStatus::Denied) {
                    return Ok(PropertyExecutionResult::failure("Claim cannot be reopened"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().update_status(&d.claim_id, ClaimStatus::Reopened, block_timestamp)?;
                debug!("Claim reopened: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::WithdrawClaim => {
                #[derive(serde::Deserialize)]
                struct WithdrawData {
                    claim_id: [u8; 32],
                }
                let d: WithdrawData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let claim = match store.claims().get(&d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can withdraw"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                store.claims().update_status(&d.claim_id, ClaimStatus::Withdrawn, block_timestamp)?;
                debug!("Claim withdrawn: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-866: Proof Operations
            // =================================================================
            PropertyOperation::SubmitProof => {
                let proof: PropertyProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if store.proofs().exists(&proof.proof_id)? {
                    return Ok(PropertyExecutionResult::failure("Proof already exists"));
                }

                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                let proof_id = proof.proof_id;
                store.proofs().put(&proof)?;
                debug!("Property proof submitted: {:?}", proof_id);
                Ok(PropertyExecutionResult::success_with_proof(proof_id))
            }

            PropertyOperation::VerifyProof => {
                // Verification is read-only - just record the request
                state.deduct(sender, fee)?;
                state.credit(proposer, fee)?;
                state.increment_nonce(sender)?;
                debug!("Property proof verification requested by: {}", sender);
                Ok(PropertyExecutionResult::success())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::property::{AssetType, PropertyIssuerClass};
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Arc<Database>, TempDir, Arc<StateManager>) {
        let dir = TempDir::new().unwrap();
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(StateManager::new(db.clone(), 1));
        (db, dir, state)
    }

    #[test]
    fn test_property_executor_creation() {
        let (db, _dir, _state) = setup();
        let _executor = PropertyExecutor::new(db, ChainParams::default());
    }

    #[test]
    fn test_anchor_asset() {
        let (db, _dir, state) = setup();
        let executor = PropertyExecutor::new(db.clone(), ChainParams::default());

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        state.credit(&sender, 1_000_000_000_000).unwrap();

        let asset = AssetAnchor {
            asset_id: [10u8; 32],
            asset_commitment: [11u8; 32],
            asset_type: AssetType::SingleFamilyResidence,
            jurisdiction_code: "US-CA-LA".to_string(),
            public_reference: None,
            policy_id: [12u8; 32],
            issuer_class: PropertyIssuerClass::TitleCompany,
            issuer_address: sender,
            status: AssetStatus::Active,
            created_at: 1000,
            updated_at: 1000,
            anchored_at_height: 100,
            related_assets: vec![],
            attachments: vec![],
        };

        let tx_data = PropertyTxData {
            operation: PropertyOperation::AnchorAsset,
            data: bincode::serialize(&asset).unwrap(),
        };

        let result = executor.execute(
            &sender, &tx_data, &state, &proposer, 1000, 100, 1000000, 0, Hash::default(),
        ).unwrap();

        assert!(result.success, "Anchor asset failed: {:?}", result.error);
        assert_eq!(result.asset_id, Some([10u8; 32]));

        // Verify storage
        let store = PropertyStore::new(&db);
        let retrieved = store.assets().get(&[10u8; 32]).unwrap().unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA-LA");
    }
}
