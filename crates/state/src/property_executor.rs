//! SRC-86X Property, Real Estate & Insurance Executor
//!
//! Transaction executor for:
//! - SRC-861: Asset Anchor (Property/Asset Identity)
//! - SRC-862: Title/Ownership State Event
//! - SRC-863: Encumbrance Standard (Lien/Mortgage/Leasehold)
//! - SRC-864: Insurance Coverage Standard
//! - SRC-865: Insurance Claim Lifecycle
//! - SRC-866: 86X Proof Profiles

use sumchain_storage::exec_view::ExecutionView;

use sumchain_primitives::{
    property::{
        AssetAnchor, AssetStatus, ClaimStatus, CoverageStatus, Encumbrance, EncumbranceStatus,
        InsuranceClaim, InsuranceCoverage, PropertyOperation, PropertyProofEnvelope, PropertyTxData,
        TitleEvent, TitleEventStatus,
    },
    Address, Balance, BlockHeight, Hash, Timestamp,
};
use tracing::debug;

use sumchain_genesis::ChainParams;

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

/// Property executor for SRC-86X transactions.
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::property_store` for the RPC server, admission and the
/// operator paths.
pub struct PropertyExecutor;

/// The activation decisions a Property transaction executes under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PropertyGates {
    /// The subsystem's authority checks are enforced. ACTIVATION-AUDIT rows
    /// AU-30 and AU-31.
    pub authorization: bool,
    /// Executor-written timestamps are the block's, not a literal zero.
    /// ACTIVATION-AUDIT class 2.
    pub real_block_timestamp: bool,
}

impl PropertyGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: PropertyExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
        }
    }
}

impl PropertyExecutor {
    /// The activation height for the Property authority checks.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-86X Property authority checks. Dormant by default (`None` ->
    /// /// never open). Below the gate `MergeAssets` checks nothing about the
    /// /// sender, so any account merges two assets it did not issue and marks
    /// /// the secondary `Merged`; and `SupersedeTitleEvent` checks nothing
    /// /// either, so any account supersedes any title event and records a
    /// /// replacement naming itself. At and above the gate each is bound to the
    /// /// issuer recorded on the row it changes. Activation is a consensus
    /// /// change and needs a coordinated validator upgrade.
    /// #[serde(default)]
    /// pub property_authorization_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
    /// unchanged and `three_operations_check_no_authority_at_all` still passes.
    #[inline]
    fn authorization_activation(params: &ChainParams) -> Option<u64> {
        params.property_authorization_enabled_from_height
    }

    /// Whether the Property authority checks are active at `block_height`.
    #[inline]
    pub fn authorization_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::authorization_activation(params), Some(h) if block_height >= h)
    }

    /// Execute a Property transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        data: &PropertyTxData,
        proposer: &Address,
        fee: Balance,
        block_height: BlockHeight,
        block_timestamp: Timestamp,
        tx_index: u32,
        tx_hash: Hash,
    ) -> Result<PropertyExecutionResult> {
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
            PropertyGates::from_params(params, block_height),
        )
    }

    /// Execute a Property transaction with the activation decisions supplied
    /// directly. The seam the mixed-version tests use.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &PropertyTxData,
        proposer: &Address,
        fee: Balance,
        _block_height: BlockHeight,
        block_timestamp: Timestamp,
        _tx_index: u32,
        _tx_hash: Hash,
        gates: PropertyGates,
    ) -> Result<PropertyExecutionResult> {
        let block_timestamp =
            crate::effective_block_timestamp(block_timestamp, gates.real_block_timestamp);
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

                if Self::v_asset_exists(view, &asset.asset_id)? {
                    return Ok(PropertyExecutionResult::failure("Asset already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let asset_id = asset.asset_id;
                Self::v_put_asset(view, &asset)?;
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

                let asset = match Self::v_get_asset(view, &update.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_asset_status(
                    view,
                    &update.asset_id,
                    update.status,
                    block_timestamp,
                )?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::TransferAsset => {
                #[derive(serde::Deserialize)]
                struct TransferData {
                    asset_id: [u8; 32],
                }
                let d: TransferData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match Self::v_get_asset(view, &d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can transfer"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_asset_status(
                    view,
                    &d.asset_id,
                    AssetStatus::PendingTransfer,
                    block_timestamp,
                )?;
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

                let primary = match Self::v_get_asset(view, &d.primary_asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Primary asset not found")),
                };
                let secondary = match Self::v_get_asset(view, &d.secondary_asset_id)? {
                    Some(a) => a,
                    None => {
                        return Ok(PropertyExecutionResult::failure(
                            "Secondary asset not found",
                        ))
                    }
                };

                // AU-30: below the gate both guards are existence only, so any
                // account merges two assets it did not issue and marks the
                // secondary `Merged`. Both issuers are required at the gate,
                // because a merge is a statement about both rows.
                if gates.authorization
                    && (primary.issuer_address != *sender || secondary.issuer_address != *sender)
                {
                    return Ok(PropertyExecutionResult::failure(
                        "Only the issuer of both assets can merge them",
                    ));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_asset_status(
                    view,
                    &d.secondary_asset_id,
                    AssetStatus::Merged,
                    block_timestamp,
                )?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SubdivideAsset => {
                #[derive(serde::Deserialize)]
                struct SubdivideData {
                    asset_id: [u8; 32],
                }
                let d: SubdivideData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match Self::v_get_asset(view, &d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can subdivide"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_asset_status(
                    view,
                    &d.asset_id,
                    AssetStatus::Subdivided,
                    block_timestamp,
                )?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::DeregisterAsset => {
                #[derive(serde::Deserialize)]
                struct DeregisterData {
                    asset_id: [u8; 32],
                }
                let d: DeregisterData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let asset = match Self::v_get_asset(view, &d.asset_id)? {
                    Some(a) => a,
                    None => return Ok(PropertyExecutionResult::failure("Asset not found")),
                };

                if asset.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can deregister"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_asset_status(
                    view,
                    &d.asset_id,
                    AssetStatus::Deregistered,
                    block_timestamp,
                )?;
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
                if Self::v_get_asset(view, &event.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if Self::v_title_event_exists(view, &event.event_id)? {
                    return Ok(PropertyExecutionResult::failure("Title event already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let event_id = event.event_id;
                Self::v_put_title_event(view, &event)?;
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

                let event = match Self::v_get_title_event(view, &d.event_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Title event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_title_event_status(view, &d.event_id, d.status, block_timestamp)?;
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

                let old_event = match Self::v_get_title_event(view, &d.old_event_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Old event not found")),
                };

                // AU-31: below the gate existence is the only guard, so any
                // account supersedes any title event and records a replacement
                // naming ITSELF as issuer -- which is how a title history is
                // rewritten by a stranger in one transaction.
                if gates.authorization {
                    if old_event.issuer_address != *sender {
                        return Ok(PropertyExecutionResult::failure(
                            "Only issuer can supersede",
                        ));
                    }
                    if d.new_event.issuer_address != *sender {
                        return Ok(PropertyExecutionResult::failure(
                            "The replacement event must be issued by the sender",
                        ));
                    }
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;

                // Mark old as superseded
                Self::v_update_title_event_status(
                    view,
                    &d.old_event_id,
                    TitleEventStatus::Superseded,
                    block_timestamp,
                )?;

                // Store new event
                let new_id = d.new_event.event_id;
                Self::v_put_title_event(view, &d.new_event)?;
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

                let event = match Self::v_get_title_event(view, &d.event_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Title event not found")),
                };

                if event.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can void"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_title_event_status(
                    view,
                    &d.event_id,
                    TitleEventStatus::Voided,
                    block_timestamp,
                )?;
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
                if Self::v_get_asset(view, &encumbrance.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if Self::v_encumbrance_exists(view, &encumbrance.encumbrance_id)? {
                    return Ok(PropertyExecutionResult::failure("Encumbrance already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let encumbrance_id = encumbrance.encumbrance_id;
                Self::v_put_encumbrance(view, &encumbrance)?;
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

                let encumbrance = match Self::v_get_encumbrance(view, &d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_encumbrance_status(
                    view,
                    &d.encumbrance_id,
                    d.status,
                    block_timestamp,
                )?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::SubordinateEncumbrance => {
                #[derive(serde::Deserialize)]
                struct SubordinateData {
                    encumbrance_id: [u8; 32],
                }
                let d: SubordinateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let encumbrance = match Self::v_get_encumbrance(view, &d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can subordinate"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_encumbrance_status(
                    view,
                    &d.encumbrance_id,
                    EncumbranceStatus::Subordinated,
                    block_timestamp,
                )?;
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

                let encumbrance = match Self::v_get_encumbrance(view, &d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can release"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_encumbrance_status(
                    view,
                    &d.encumbrance_id,
                    EncumbranceStatus::Released,
                    block_timestamp,
                )?;
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

                let encumbrance = match Self::v_get_encumbrance(view, &d.encumbrance_id)? {
                    Some(e) => e,
                    None => return Ok(PropertyExecutionResult::failure("Encumbrance not found")),
                };

                if encumbrance.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can foreclose"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_encumbrance_status(
                    view,
                    &d.encumbrance_id,
                    EncumbranceStatus::Foreclosed,
                    block_timestamp,
                )?;
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
                if Self::v_get_asset(view, &coverage.asset_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Asset not found"));
                }

                if Self::v_coverage_exists(view, &coverage.coverage_id)? {
                    return Ok(PropertyExecutionResult::failure("Coverage already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let coverage_id = coverage.coverage_id;
                Self::v_put_coverage(view, &coverage)?;
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

                let coverage = match Self::v_get_coverage(view, &d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_coverage_status(view, &d.coverage_id, d.status, block_timestamp)?;
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

                let coverage = match Self::v_get_coverage(view, &d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can renew"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_renew_coverage(view, &d.coverage_id, d.new_expiry, block_timestamp)?;
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

                let coverage = match Self::v_get_coverage(view, &d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can cancel"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_coverage_status(
                    view,
                    &d.coverage_id,
                    CoverageStatus::Cancelled,
                    block_timestamp,
                )?;
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

                let coverage = match Self::v_get_coverage(view, &d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can suspend"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_coverage_status(
                    view,
                    &d.coverage_id,
                    CoverageStatus::Suspended,
                    block_timestamp,
                )?;
                Ok(PropertyExecutionResult::success())
            }

            PropertyOperation::ReinstateCoverage => {
                #[derive(serde::Deserialize)]
                struct ReinstateData {
                    coverage_id: [u8; 32],
                }
                let d: ReinstateData = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                let coverage = match Self::v_get_coverage(view, &d.coverage_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Coverage not found")),
                };

                if coverage.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can reinstate"));
                }

                if coverage.status != CoverageStatus::Suspended {
                    return Ok(PropertyExecutionResult::failure("Coverage is not suspended"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_coverage_status(
                    view,
                    &d.coverage_id,
                    CoverageStatus::Active,
                    block_timestamp,
                )?;
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
                if Self::v_get_coverage(view, &claim.coverage_id)?.is_none() {
                    return Ok(PropertyExecutionResult::failure("Coverage not found"));
                }

                if Self::v_claim_exists(view, &claim.claim_id)? {
                    return Ok(PropertyExecutionResult::failure("Claim already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let claim_id = claim.claim_id;
                Self::v_put_claim(view, &claim)?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can update"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_claim_status(view, &d.claim_id, d.status, block_timestamp)?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can approve"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_approve_claim(
                    view,
                    &d.claim_id,
                    d.approved_amount_commitment,
                    block_timestamp,
                )?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can deny"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_claim_status(
                    view,
                    &d.claim_id,
                    ClaimStatus::Denied,
                    block_timestamp,
                )?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can pay"));
                }

                if !matches!(claim.status, ClaimStatus::Approved | ClaimStatus::PartiallyApproved) {
                    return Ok(PropertyExecutionResult::failure("Claim not approved"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_pay_claim(view, &d.claim_id, d.paid_amount_commitment, block_timestamp)?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can close"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_claim_status(
                    view,
                    &d.claim_id,
                    ClaimStatus::Closed,
                    block_timestamp,
                )?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can reopen"));
                }

                if !matches!(claim.status, ClaimStatus::Closed | ClaimStatus::Denied) {
                    return Ok(PropertyExecutionResult::failure("Claim cannot be reopened"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_claim_status(
                    view,
                    &d.claim_id,
                    ClaimStatus::Reopened,
                    block_timestamp,
                )?;
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

                let claim = match Self::v_get_claim(view, &d.claim_id)? {
                    Some(c) => c,
                    None => return Ok(PropertyExecutionResult::failure("Claim not found")),
                };

                if claim.issuer_address != *sender {
                    return Ok(PropertyExecutionResult::failure("Only issuer can withdraw"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_claim_status(
                    view,
                    &d.claim_id,
                    ClaimStatus::Withdrawn,
                    block_timestamp,
                )?;
                debug!("Claim withdrawn: {:?}", d.claim_id);
                Ok(PropertyExecutionResult::success())
            }

            // =================================================================
            // SRC-866: Proof Operations
            // =================================================================
            PropertyOperation::SubmitProof => {
                let proof: PropertyProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;

                if Self::v_property_proof_exists(view, &proof.proof_id)? {
                    return Ok(PropertyExecutionResult::failure("Proof already exists"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                let proof_id = proof.proof_id;
                Self::v_put_property_proof(view, &proof)?;
                debug!("Property proof submitted: {:?}", proof_id);
                Ok(PropertyExecutionResult::success_with_proof(proof_id))
            }

            PropertyOperation::VerifyProof => {
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                debug!("Property proof verification requested by: {}", sender);
                Ok(PropertyExecutionResult::success())
            }
        }
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    // `Arc` is dead in the normal build now that the executor holds no
    // database handle, and alive here: these fixtures still open one. Imported
    // inside the gated module so neither build loses.
    use std::sync::Arc;
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
        let (_db, _dir, _state) = setup();
        // A unit struct: there is no `new`, and no database to hand it.
        let _executor = PropertyExecutor;
    }

    #[test]
    fn test_anchor_asset() {
        let (db, _dir, _state) = setup();
        // A block's candidate, opened here because a `#[test]` function
        // cannot take one as a parameter. An earlier scripted signature
        // rewrite added `view` to the parameter list of every test in this
        // module, which is not valid Rust; only the `cfg` gate kept it
        // out of sight.
        let mut overlay = sumchain_storage::overlay::ApplicationOverlay::new(&db, 1 << 20);
        let view = &mut sumchain_storage::exec_view::ExecutionView::new(&mut overlay);

        let sender = Address::new([1u8; 20]);
        let proposer = Address::new([99u8; 20]);
        StateManager::v_credit(view, &sender, 1_000_000_000_000).unwrap();

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

        let result = PropertyExecutor::execute(
            view,
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

        assert!(result.success, "Anchor asset failed: {:?}", result.error);
        assert_eq!(result.asset_id, Some([10u8; 32]));

        // Verify the candidate, which is where this now writes.
        let retrieved = PropertyExecutor::v_get_asset(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA-LA");
    }
}
