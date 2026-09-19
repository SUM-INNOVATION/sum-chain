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
    /// A payload-chosen index key is bounded before it becomes a key, the
    /// accumulating row under it is bounded before it is decoded, and the
    /// transaction payload is bounded before it is deserialized.
    /// ACTIVATION-AUDIT rows AL-6, AL-7 and the Property third of AL-12.
    pub allocation_bound: bool,
    /// `VerifyProof` refuses as UNSUPPORTED, for every payload.
    ///
    /// NO ACTIVATION-AUDIT ROW NAMES THIS ARM, and one row denies it exists:
    /// PR-7 reads "Property has no separate `VerifyProof`". It does --
    /// `PropertyOperation::VerifyProof = 51` decodes, dispatches, and below the
    /// gate is the same deduct/credit/increment/`success()` as the six arms the
    /// audit does name. The retired presence gate covered six of seven for that
    /// reason; this one covers all seven.
    pub proof_unsupported: bool,
    /// A transition consults the status of the row it changes: a row whose
    /// status is FINAL accepts no further operation.
    /// ACTIVATION-AUDIT row OV-21.
    pub state_precondition: bool,
    /// `MergeAssets` records the relationship it asserts, on both rows, and
    /// bounds the accumulating list it writes into.
    /// ACTIVATION-AUDIT row OV-22, the merge half.
    pub asset_relationship: bool,
    /// `SubmitProof` refuses as UNSUPPORTED, for every payload.
    /// ACTIVATION-AUDIT row AU-32. `PropertyProofEnvelope` carries no issuer
    /// address and Property has no issuer registry, so the arm has neither an
    /// address in the payload to check nor a registry to check it against.
    pub proof_submission_unsupported: bool,
}

impl PropertyGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        authorization: false,
        real_block_timestamp: false,
        allocation_bound: false,
        proof_unsupported: false,
        state_precondition: false,
        asset_relationship: false,
        proof_submission_unsupported: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        authorization: true,
        real_block_timestamp: true,
        allocation_bound: true,
        proof_unsupported: true,
        state_precondition: true,
        asset_relationship: true,
        proof_submission_unsupported: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: BlockHeight) -> Self {
        Self {
            authorization: PropertyExecutor::authorization_gate_open(params, block_height),
            real_block_timestamp: crate::subsystem_block_timestamp_gate_open(params, block_height),
            allocation_bound: crate::subsystem_allocation_bound_gate_open(params, block_height),
            proof_unsupported: crate::subsystem_proof_unsupported_gate_open(params, block_height),
            state_precondition: PropertyExecutor::state_precondition_gate_open(
                params,
                block_height,
            ),
            asset_relationship: PropertyExecutor::asset_relationship_gate_open(
                params,
                block_height,
            ),
            proof_submission_unsupported: PropertyExecutor::proof_submission_unsupported_gate_open(
                params,
                block_height,
            ),
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

    /// The stored asset-row limit the RELATIONSHIP write imposes, or `None`
    /// when that gate is closed.
    ///
    /// Deliberately not `row_limit` above, and deliberately reading a different
    /// gate. `related_assets` only becomes an accumulating list at
    /// `asset_relationship`, so the bound on it has to arrive with the write
    /// that creates it: an operator who opened the relationship gate alone and
    /// found the bound behind `subsystem_allocation_bound_enabled_from_height`
    /// would be running the one accumulating row in the tree that nothing
    /// bounds. Same constant, because it is the same kind of row.
    #[inline]
    pub fn related_row_limit(self) -> Option<usize> {
        self.asset_relationship
            .then_some(crate::MAX_ACCUMULATING_ROW_BYTES)
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

    /// The activation height for the Property state preconditions.
    ///
    /// Reads `params.property_state_precondition_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT row OV-21) only `ReinstateCoverage`,
    /// `PayClaim` and `ReopenClaim` guard on the state they read; every other
    /// transition applies from any prior status, so `UpdateAsset` returns a
    /// `Deregistered` asset to `Active`, a `Merged` asset is merged again, and
    /// a `Paid` claim is closed, reopened, re-approved and paid a second time.
    /// At and above it a row whose status is FINAL accepts no further
    /// operation, where final means the status a NAMED operation writes and
    /// that no named operation leaves.
    #[inline]
    fn state_precondition_activation(params: &ChainParams) -> Option<u64> {
        params.property_state_precondition_enabled_from_height
    }

    /// Whether the Property state preconditions are active at `block_height`.
    #[inline]
    pub fn state_precondition_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::state_precondition_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the Property merge relationship record.
    ///
    /// Reads `params.property_asset_relationship_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT row OV-22, the merge half) `MergeAssets`
    /// writes `AssetStatus::Merged` onto the secondary and nothing else: the
    /// primary row is never touched and `related_assets` stays empty on both.
    /// At and above it the merge links both rows, idempotently, and is refused
    /// before the fee when either stored row already exceeds
    /// `MAX_ACCUMULATING_ROW_BYTES`.
    #[inline]
    fn asset_relationship_activation(params: &ChainParams) -> Option<u64> {
        params.property_asset_relationship_enabled_from_height
    }

    /// Whether the Property merge relationship record is active at
    /// `block_height`.
    #[inline]
    pub fn asset_relationship_gate_open(params: &ChainParams, block_height: BlockHeight) -> bool {
        matches!(Self::asset_relationship_activation(params), Some(h) if block_height >= h)
    }

    /// A status a NAMED operation writes and that no named operation leaves.
    ///
    /// ACTIVATION-AUDIT row OV-21, and the definition the gate turns on. It is
    /// read off the arms rather than chosen here: `MergeAssets`,
    /// `SubdivideAsset` and `DeregisterAsset` each write one of these three and
    /// this subsystem offers no operation that writes an asset back out of one.
    ///
    /// `AssetStatus::Destroyed` and `Seized` are NOT here. Both read as
    /// endings, and neither is written by any named operation -- only by the
    /// free-form `UpdateAsset` -- so calling them final would be inventing a
    /// lifecycle inside an executor instead of enforcing the one the arms
    /// describe. `PendingTransfer` and `Encumbered` are live states by the same
    /// reading.
    #[inline]
    fn asset_status_is_final(status: AssetStatus) -> bool {
        matches!(
            status,
            AssetStatus::Merged | AssetStatus::Subdivided | AssetStatus::Deregistered
        )
    }

    /// `SupersedeTitleEvent` writes `Superseded` and `VoidTitleEvent` writes
    /// `Voided`; nothing writes a title event back out of either.
    #[inline]
    fn title_event_status_is_final(status: TitleEventStatus) -> bool {
        matches!(
            status,
            TitleEventStatus::Superseded | TitleEventStatus::Voided
        )
    }

    /// `ReleaseEncumbrance` writes `Released` and `ForecloseEncumbrance` writes
    /// `Foreclosed`; nothing writes an encumbrance back out of either.
    ///
    /// `Expired` and `Voided` are reachable only through `UpdateEncumbrance`
    /// and are not final here, for the reason `asset_status_is_final` gives.
    #[inline]
    fn encumbrance_status_is_final(status: EncumbranceStatus) -> bool {
        matches!(
            status,
            EncumbranceStatus::Released | EncumbranceStatus::Foreclosed
        )
    }

    /// `CancelCoverage` writes `Cancelled` and nothing writes a coverage back
    /// out of it.
    ///
    /// `Suspended` is deliberately NOT final: `ReinstateCoverage` is the named
    /// way out of it, which is the same fact that keeps it off this list and
    /// the reason that arm already carries a guard.
    #[inline]
    fn coverage_status_is_final(status: CoverageStatus) -> bool {
        matches!(status, CoverageStatus::Cancelled)
    }

    /// `PayClaim` writes `Paid` and `WithdrawClaim` writes `Withdrawn`; nothing
    /// writes a claim back out of either.
    ///
    /// `Closed` and `Denied` are deliberately NOT final: `ReopenClaim` is the
    /// named way out of both, and its existing guard names exactly those two.
    /// `Paid` being final is what breaks the pay-close-reopen-approve-pay cycle
    /// that walks around `PayClaim`'s own guard.
    #[inline]
    fn claim_status_is_final(status: ClaimStatus) -> bool {
        matches!(status, ClaimStatus::Paid | ClaimStatus::Withdrawn)
    }

    /// The refusal a final row returns. One phrasing across all five families,
    /// with the STATUS in it, because the remedy for a final row is never
    /// "retry" -- it is a different row.
    fn row_is_final(what: &str, status: impl std::fmt::Debug) -> PropertyExecutionResult {
        PropertyExecutionResult::failure(format!(
            "{what} is {status:?}, which is final: no further operation applies to it"
        ))
    }

    /// The stored asset row this merge would append to, checked against the
    /// bound before it is decoded.
    ///
    /// ACTIVATION-AUDIT row OV-22 -- and row AL-6, which is why the check is
    /// here at all. The same shape as the five index bounds above and the same
    /// reason: a caller that wants to refuse an oversized row must know its
    /// size WITHOUT paying for the decode.
    fn asset_row_within_bound(
        view: &ExecutionView<'_, '_>,
        asset_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_asset_row_len(view, asset_id)? {
            Some(bytes) if bytes > max => {
                Ok(Some(Self::row_too_large("Property asset row", bytes)))
            }
            _ => Ok(None),
        }
    }

    /// The activation height for the Property proof-submission refusal.
    ///
    /// Reads `params.property_proof_submission_unsupported_enabled_from_height`,
    /// and nothing else. `None` -- the default, and what a genesis written
    /// before the field existed resolves to -- closes the gate, so a node
    /// executes exactly what it executed before the field was declared.
    ///
    /// ACTIVATION-AUDIT row AU-32. Below the gate `SubmitProof` verifies
    /// nothing about the proof and checks nothing about the sender; its sole
    /// guard is a duplicate id. At and above it the arm returns a FAILED
    /// receipt carrying [`crate::PROPERTY_PROOF_SUBMISSION_UNSUPPORTED`],
    /// before the deduct.
    ///
    /// Its own height, and not `subsystem_proof_unsupported_enabled_from_height`,
    /// because they are different rules about different arms: that gate is
    /// about a verifier this tree does not have, this one about an issuer this
    /// subsystem does not record. An operator must be able to sequence them,
    /// and a reader of either receipt must be able to tell which claim was
    /// refused.
    #[inline]
    fn proof_submission_unsupported_activation(params: &ChainParams) -> Option<u64> {
        params.property_proof_submission_unsupported_enabled_from_height
    }

    /// Whether the Property proof-submission refusal is active at
    /// `block_height`.
    #[inline]
    pub fn proof_submission_unsupported_gate_open(
        params: &ChainParams,
        block_height: BlockHeight,
    ) -> bool {
        matches!(Self::proof_submission_unsupported_activation(params), Some(h) if block_height >= h)
    }

    /// A stored index row longer than the bound, refused without being decoded.
    ///
    /// The Agreement and DocClass wording verbatim, and for the same reason
    /// they give: one phrasing across every family so the refusal is greppable,
    /// with the LENGTH in it, because the remedy for a row over the limit is
    /// not "retry".
    fn row_too_large(what: &str, bytes: usize) -> PropertyExecutionResult {
        PropertyExecutionResult::failure(format!(
            "{what} too large to modify: {bytes} bytes, limit {}",
            crate::MAX_ACCUMULATING_ROW_BYTES
        ))
    }

    /// The jurisdiction-index row this anchor would append to, checked against
    /// the bound before it is decoded.
    ///
    /// ACTIVATION-AUDIT row AL-6, and the family AL-7 already bounds the KEY
    /// of. The two halves are independent and both are needed:
    /// `MAX_INDEX_KEY_TEXT_BYTES` bounds how wide one key may be,
    /// `MAX_ACCUMULATING_ROW_BYTES` bounds how large the value under it may
    /// grow -- an attacker refused by the first still reaches the second by
    /// reusing one short, lawful code. Exactly the pairing Finance's
    /// jurisdiction index already carries.
    fn jurisdiction_index_within_bound(
        view: &ExecutionView<'_, '_>,
        jurisdiction: &str,
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        // No read AT ALL while the gate is closed, not merely no refusal: a
        // read here would touch a family the unremediated binary does not
        // touch until later in the arm, and this subsystem's corrupt-row
        // behaviour is pinned per family.
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_jurisdiction_index_row_len(view, jurisdiction)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Property jurisdiction index",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// The asset-title-index row this event would append to, checked against
    /// the bound before it is decoded. ACTIVATION-AUDIT row AL-6.
    fn asset_title_index_within_bound(
        view: &ExecutionView<'_, '_>,
        asset_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_asset_title_index_row_len(view, asset_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Property asset title index",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// The asset-encumbrance-index row this encumbrance would append to,
    /// checked against the bound before it is decoded. ACTIVATION-AUDIT row
    /// AL-6.
    fn asset_encumbrance_index_within_bound(
        view: &ExecutionView<'_, '_>,
        asset_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_asset_encumbrance_index_row_len(view, asset_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Property asset encumbrance index",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// The asset-coverage-index row this coverage would append to, checked
    /// against the bound before it is decoded. ACTIVATION-AUDIT row AL-6.
    fn asset_coverage_index_within_bound(
        view: &ExecutionView<'_, '_>,
        asset_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_asset_coverage_index_row_len(view, asset_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Property asset coverage index",
                bytes,
            ))),
            _ => Ok(None),
        }
    }

    /// The coverage-claim-index row this claim would append to, checked
    /// against the bound before it is decoded. ACTIVATION-AUDIT row AL-6.
    fn coverage_claim_index_within_bound(
        view: &ExecutionView<'_, '_>,
        coverage_id: &[u8; 32],
        max_bytes: Option<usize>,
    ) -> Result<Option<PropertyExecutionResult>> {
        let Some(max) = max_bytes else {
            return Ok(None);
        };
        match Self::v_coverage_claim_index_row_len(view, coverage_id)? {
            Some(bytes) if bytes > max => Ok(Some(Self::row_too_large(
                "Property coverage claim index",
                bytes,
            ))),
            _ => Ok(None),
        }
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

        // ACTIVATION-AUDIT row AL-12, the Property third. Every arm below
        // `bincode::deserialize`s `data.data` with no size or shape limit ahead
        // of it, and `AssetAnchor`, `TitleEvent`, `Encumbrance`,
        // `InsuranceCoverage` and `InsuranceClaim` are all stored VERBATIM, so
        // the row a later operation must decode, modify and re-encode is
        // whatever one payload bounded only by `max_block_bytes` declared.
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
            return Ok(PropertyExecutionResult::failure(format!(
                "Property payload too large: {} bytes, limit {}",
                data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

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

                // ACTIVATION-AUDIT AL-7. `AssetAnchor.jurisdiction_code` is free text from the
                // sender's own payload and becomes the raw KEY of
                // `cf::PROPERTY_JURISDICTION_INDEX`, with no width check anywhere ahead of
                // the `put`. Below the gate one transaction writes a key of
                // most of `max_block_bytes`. At and above it the key is
                // bounded. Refused before the fee, like the duplicate guard
                // above it.
                if !crate::index_key_text_within_bound(
                    &asset.jurisdiction_code,
                    gates.allocation_bound,
                ) {
                    return Ok(PropertyExecutionResult::failure(format!(
                        "Jurisdiction code too long: {} bytes, limit {}",
                        asset.jurisdiction_code.len(),
                        crate::MAX_INDEX_KEY_TEXT_BYTES
                    )));
                }

                // ACTIVATION-AUDIT row AL-6, the jurisdiction family. The KEY
                // bound directly above and this VALUE bound are independent: a
                // short, lawful code still names a row that grows by one
                // 32-byte id per anchor forever, and every later anchor under
                // that code decodes, appends to and re-encodes the whole of it.
                if let Some(refusal) = Self::jurisdiction_index_within_bound(
                    view,
                    &asset.jurisdiction_code,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. The free-form status write. Below the gate
                // it is the un-deregister, the un-merge and the un-subdivide this
                // subsystem otherwise has no operation for.
                if gates.state_precondition && Self::asset_status_is_final(asset.status) {
                    return Ok(Self::row_is_final("Asset", asset.status));
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

                // ACTIVATION-AUDIT row OV-21. A deregistered or merged asset cannot begin
                // a transfer.
                if gates.state_precondition && Self::asset_status_is_final(asset.status) {
                    return Ok(Self::row_is_final("Asset", asset.status));
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

                // ACTIVATION-AUDIT row OV-21. A merge is a statement about BOTH rows, so
                // both are checked. An asset already merged into something else cannot
                // absorb a third, and one that was absorbed cannot be absorbed again.
                if gates.state_precondition && Self::asset_status_is_final(primary.status) {
                    return Ok(Self::row_is_final("Primary asset", primary.status));
                }

                if gates.state_precondition && Self::asset_status_is_final(secondary.status) {
                    return Ok(Self::row_is_final("Secondary asset", secondary.status));
                }

                // ACTIVATION-AUDIT row OV-22, and row AL-6 which is why the
                // bound travels with the write rather than behind the
                // allocation height. At this gate the two rows below stop
                // being fixed-size records and start accumulating one 32-byte
                // id per merge, decoded and re-encoded whole each time. Both
                // are checked, because both are written. Refused before the
                // fee, like the two guards above it.
                for id in [&d.primary_asset_id, &d.secondary_asset_id] {
                    if let Some(refusal) =
                        Self::asset_row_within_bound(view, id, gates.related_row_limit())?
                    {
                        return Ok(refusal);
                    }
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

                // ACTIVATION-AUDIT row OV-22, the merge half. Below the gate
                // the line above is the WHOLE of what a merge does: the
                // primary row is never written and `related_assets` -- the
                // field `AssetAnchor` carries "for subdivisions, mergers" --
                // stays empty on both sides, so the merge is unreadable from
                // either row afterwards. At and above it each row names the
                // other. The status write comes first and the links second, so
                // a reader that sees `Merged` never sees it without the link
                // in the same candidate.
                if gates.asset_relationship {
                    Self::v_add_related_asset(
                        view,
                        &d.primary_asset_id,
                        &d.secondary_asset_id,
                        block_timestamp,
                    )?;
                    Self::v_add_related_asset(
                        view,
                        &d.secondary_asset_id,
                        &d.primary_asset_id,
                        block_timestamp,
                    )?;
                }

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

                // ACTIVATION-AUDIT row OV-21. A subdivided asset is not subdivided again,
                // and a deregistered one is not subdivided at all.
                if gates.state_precondition && Self::asset_status_is_final(asset.status) {
                    return Ok(Self::row_is_final("Asset", asset.status));
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

                // ACTIVATION-AUDIT row OV-21. Deregistering a row that is already final
                // rewrites its ending.
                if gates.state_precondition && Self::asset_status_is_final(asset.status) {
                    return Ok(Self::row_is_final("Asset", asset.status));
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

                // ACTIVATION-AUDIT row AL-6, the asset-title family.
                if let Some(refusal) =
                    Self::asset_title_index_within_bound(view, &event.asset_id, gates.row_limit())?
                {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. The free-form status write again: below the
                // gate it un-voids and un-supersedes a title event, which is how a history
                // is rewritten without `SupersedeTitleEvent` ever being called.
                if gates.state_precondition && Self::title_event_status_is_final(event.status) {
                    return Ok(Self::row_is_final("Title event", event.status));
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

                // ACTIVATION-AUDIT row OV-21. A superseded event is not superseded twice
                // -- that forks the history into two replacements of one event -- and a
                // voided one has no standing left to supersede.
                if gates.state_precondition && Self::title_event_status_is_final(old_event.status) {
                    return Ok(Self::row_is_final("Title event", old_event.status));
                }

                // ACTIVATION-AUDIT row AL-6, the asset-title family: a
                // supersession appends the replacement's id to the index of
                // the asset the REPLACEMENT names.
                if let Some(refusal) = Self::asset_title_index_within_bound(
                    view,
                    &d.new_event.asset_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. A voided or superseded event is already out
                // of the history.
                if gates.state_precondition && Self::title_event_status_is_final(event.status) {
                    return Ok(Self::row_is_final("Title event", event.status));
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

                // ACTIVATION-AUDIT row AL-6, the asset-encumbrance family.
                if let Some(refusal) = Self::asset_encumbrance_index_within_bound(
                    view,
                    &encumbrance.asset_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. The free-form status write: below the gate a
                // released lien becomes `Active` again.
                if gates.state_precondition && Self::encumbrance_status_is_final(encumbrance.status)
                {
                    return Ok(Self::row_is_final("Encumbrance", encumbrance.status));
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

                // ACTIVATION-AUDIT row OV-21. Priority between a released lien and a live
                // one is not a question.
                if gates.state_precondition && Self::encumbrance_status_is_final(encumbrance.status)
                {
                    return Ok(Self::row_is_final("Encumbrance", encumbrance.status));
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

                // ACTIVATION-AUDIT row OV-21. A released lien is not released twice, and a
                // foreclosed one has already had its remedy.
                if gates.state_precondition && Self::encumbrance_status_is_final(encumbrance.status)
                {
                    return Ok(Self::row_is_final("Encumbrance", encumbrance.status));
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

                // ACTIVATION-AUDIT row OV-21. Foreclosing a RELEASED lien is the sharp
                // one: it takes a remedy on a debt the row itself records as satisfied.
                if gates.state_precondition && Self::encumbrance_status_is_final(encumbrance.status)
                {
                    return Ok(Self::row_is_final("Encumbrance", encumbrance.status));
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

                // ACTIVATION-AUDIT row AL-6, the asset-coverage family.
                if let Some(refusal) = Self::asset_coverage_index_within_bound(
                    view,
                    &coverage.asset_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. The free-form status write, and the way
                // around `ReinstateCoverage`: below the gate it sets a `Cancelled`
                // coverage back to `Active` without ever meeting the `Suspended`
                // requirement that operation exists to impose.
                if gates.state_precondition && Self::coverage_status_is_final(coverage.status) {
                    return Ok(Self::row_is_final("Coverage", coverage.status));
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

                // ACTIVATION-AUDIT row OV-21. A cancelled policy is not renewed; it is re-
                // issued.
                if gates.state_precondition && Self::coverage_status_is_final(coverage.status) {
                    return Ok(Self::row_is_final("Coverage", coverage.status));
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

                // ACTIVATION-AUDIT row OV-21. Cancelling a cancelled coverage rewrites its
                // `updated_at` and says nothing.
                if gates.state_precondition && Self::coverage_status_is_final(coverage.status) {
                    return Ok(Self::row_is_final("Coverage", coverage.status));
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

                // ACTIVATION-AUDIT row OV-21. Suspending a cancelled coverage would make
                // it eligible for `ReinstateCoverage`, which is the same walk-around from
                // the other side.
                if gates.state_precondition && Self::coverage_status_is_final(coverage.status) {
                    return Ok(Self::row_is_final("Coverage", coverage.status));
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

                // ACTIVATION-AUDIT row AL-6, the coverage-claim family.
                if let Some(refusal) = Self::coverage_claim_index_within_bound(
                    view,
                    &claim.coverage_id,
                    gates.row_limit(),
                )? {
                    return Ok(refusal);
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

                // ACTIVATION-AUDIT row OV-21. The free-form status write, and the first
                // step of the cycle: below the gate it sets a `Paid` claim back to
                // `Approved`, and `PayClaim`'s own guard then admits it and pays it AGAIN.
                if gates.state_precondition && Self::claim_status_is_final(claim.status) {
                    return Ok(Self::row_is_final("Claim", claim.status));
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

                // ACTIVATION-AUDIT row OV-21. Approving a paid claim is the second half of
                // the double payment.
                if gates.state_precondition && Self::claim_status_is_final(claim.status) {
                    return Ok(Self::row_is_final("Claim", claim.status));
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

                // ACTIVATION-AUDIT row OV-21. A paid claim cannot be denied after the
                // fact.
                if gates.state_precondition && Self::claim_status_is_final(claim.status) {
                    return Ok(Self::row_is_final("Claim", claim.status));
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

                // ACTIVATION-AUDIT row OV-21. `Paid` is final and `Closed` is not, so
                // closing a paid claim is the step that makes it reopenable -- which is
                // the cycle's route around `ReopenClaim`'s guard as well.
                if gates.state_precondition && Self::claim_status_is_final(claim.status) {
                    return Ok(Self::row_is_final("Claim", claim.status));
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

                // ACTIVATION-AUDIT row OV-21. A paid claim cannot be withdrawn, and a
                // withdrawn one is already gone.
                if gates.state_precondition && Self::claim_status_is_final(claim.status) {
                    return Ok(Self::row_is_final("Claim", claim.status));
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
                // ACTIVATION-AUDIT row AU-32. Below the gate this arm checks
                // NOTHING about the sender and nothing about the proof: its
                // only guard is a duplicate id, and the profile, the policy
                // ids, the subject nullifier, the validity window and the
                // proof bytes are all written from the payload verbatim. Any
                // funded account writes any row into the Property proof family,
                // about any subject it names.
                //
                // At and above the gate it refuses as UNSUPPORTED. There is
                // nothing to authorize against: `PropertyProofEnvelope` carries
                // no issuer address, and Property has no issuer registry at all
                // -- no `v_get_issuer` exists in this file or in
                // `property_view.rs`, and no `ChainParams` field names a
                // Property registrar.
                //
                // And nothing downstream is stranded, which is what decided it.
                // The only consumer of a row this arm writes is the
                // `VerifyProof` arm below, and that arm already refuses as
                // UNSUPPORTED under
                // `subsystem_proof_unsupported_enabled_from_height`. A
                // submission at this height therefore stores a row nothing can
                // read back for any purpose, so refusing it removes an
                // unauthenticated write and takes no capability with it.
                //
                // Refused before the deduct and before the decode, where this
                // arm's own duplicate refusal returns.
                if gates.proof_submission_unsupported {
                    return Ok(PropertyExecutionResult::failure(
                        crate::PROPERTY_PROOF_SUBMISSION_UNSUPPORTED,
                    ));
                }

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
                // NO ACTIVATION-AUDIT ROW NAMES THIS ARM. PR-7 states "Property
                // has no separate `VerifyProof`", which is false: this is it, it
                // is reachable (`verify_proof_succeeds_for_a_proof_that_does_not_exist`
                // in `property_routing.rs` drives it through `execute_tx`), and
                // below the gate it is the same three statements as the six arms
                // the audit does name -- deduct, credit, increment, SUCCESS, with
                // the payload never read.
                //
                // At and above the gate it refuses as UNSUPPORTED, for every
                // payload: no verifier for Property proofs exists in this tree --
                // nothing checks `proof_data` against `public_inputs`, there is no
                // proof system in the workspace, no verifying key anywhere, and no
                // wire type for a verification request -- and an operation that
                // cannot be performed must say so rather than succeed.
                //
                // Refused BEFORE the deduct, which is where the sibling
                // `SubmitProof` arm's duplicate-id refusal returns, so a refused
                // proof operation costs the same in both.
                if gates.proof_unsupported {
                    return Ok(PropertyExecutionResult::failure(
                        crate::VERIFY_PROOF_UNSUPPORTED,
                    ));
                }
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
        let params = ChainParams::default();

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
            recipient: Address::ZERO,
        };

        let result = PropertyExecutor::execute(
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

        assert!(result.success, "Anchor asset failed: {:?}", result.error);
        assert_eq!(result.asset_id, Some([10u8; 32]));

        // Verify the candidate, which is where this now writes.
        let retrieved = PropertyExecutor::v_get_asset(view, &[10u8; 32])
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.jurisdiction_code, "US-CA-LA");
    }
}
