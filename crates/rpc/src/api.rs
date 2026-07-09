//! RPC API trait definition using jsonrpsee.

use jsonrpsee::proc_macros::rpc;

use crate::metrics::MetricsSnapshot;
use crate::policy_account_types::{
    BuildCancelProposalRequest, BuildCreateAccountRequest, BuildExecuteProposalRequest,
    BuildSubmitProposalRequest, PolicyAccountInfo, PolicyBuildResponse, ProposalInfo,
};
use crate::governance_types::{
    GovAssetInfo, GovBuildCancelProposalRequest, GovBuildCastEquityVoteRequest,
    GovBuildCastNativeVoteRequest, GovBuildCastVoteRequest, GovBuildCreateProposalRequest,
    GovBuildExecuteProposalRequest, GovBuildRegisterEquityClassRequest,
    GovBuildRegisterQualifyingAssetRequest, GovBuildResponse, GovEquityClassVotingInfo,
    GovProposalInfo, GovQualifyingAssetInfo, GovTallyInfo, GovVoteInfo, GovVotingPowerInfo,
};
use crate::inference_settlement_types::{
    ClaimableRewardInfo, InferenceClaimInfo, InferenceConsistencyReport, InferenceDisputeInfo,
    InferenceSessionInfo, InferenceVerifierInfo, OmniBuildAddVerifierBondRequest,
    OmniBuildClaimRewardRequest, OmniBuildFundSessionRequest, OmniBuildOpenDisputeRequest,
    OmniBuildOpenSessionRequest, OmniBuildRefundSessionRequest, OmniBuildRegisterVerifierRequest,
    OmniBuildResolveDisputeRequest, OmniBuildVerifierBondActionRequest, OmniSettlementBuildResponse,
};
use crate::types::{
    AddressLabelsInfo, ProtocolReserveInfo, ServiceGrantEligibilityInfo, ServiceGrantInfo,
    SupplyBuildRequest, SupplyInfo,
    TaxClaimTypeInfo, TaxIssuerInfo, TaxPolicyInfo, ExecutorLinkInfo, AssetInfo, FinanceIssuerInfo,
    CaseInfo, HealthcareProviderInfo,
    EquityControllerConfigInfo, EquityEntityInfo, EquityShareClassInfo,
    AccountInfo, BlockHeightInfo, BlockInfo, ContractCallResult, ContractInfo,
    CreateEmploymentCredentialRequest,
    CreateEmploymentCredentialResponse, DelegationRpcInfo, DelegatorSummary, DocClassConfigInfo,
    DocClassCredentialInfo, DocClassIdentityInfo, DocClassIssuerInfo, DocClassSummary,
    EmploymentCredentialInfo, EmploymentIssuerInfo, EmploymentSummary, EmploymentVerificationResult,
    ArchiveUnbondingInfo, AssignmentCoverageV2, ChainParamsInfo, EpochInfo, FinalityInfo, GasEstimateResult, HealthResponse, IncomeAttestationInfo, NodeRecordInfo, PushableFileInfoV2, StorageBuildReassignChunksV2Request, StorageBuildResponse, StorageFileInfoV2, TxStatusV2,
    InboxFilterInfo, IssueAcademicCredentialRequest, IssueAcademicCredentialResponse,
    MessageDataInfo, MessageEventInfo, MessagingConfigInfo, MessagingQuotaInfo,
    NftCollectionInfo, NftOwnerTokens, NftTokenInfo, NodeInfo, P2pStats, PendingPaymentInfo,
    PublicKeyInfo, ReceiptInfo, RegisterAcademicIssuerRequest, RegisterAcademicIssuerResponse,
    RegisterEmploymentIssuerRequest, RegisterEmploymentIssuerResponse,
    RevokeAcademicCredentialRequest, RevokeAcademicCredentialResponse,
    RevokeEmploymentCredentialRequest, RevokeEmploymentCredentialResponse,
    RpcPeerInfo, SendTxResponse, SlashingRecordRpcInfo, SlashingSummary, SpamReportInfo,
    SponsoredRegistrationRequest, SponsoredRegistrationResponse, StakingParamsInfo, StakingSummary,
    StakingValidatorInfo, SubmitSponsoredMessageRequest, TokenHoldings, TokenInfo, TokenMintersInfo,
    TransactionHistoryResponse, TransactionInfo, UnbondingDelegationRpcInfo,
    ValidatorDelegationSummary, ValidatorSetInfo, ValidatorSetRpcInfo, ValidatorSigningRpcInfo,
    ViewCallRequest,
    InferenceAttestationInfo, InferenceAttestationSponsorInfo, InferenceAttestationStatusInfo,
    AssessmentInfo, CatalogContentRefInfo, CatalogEntryInfo, EnrollmentLinkInfo,
    GradeRecordInfo, OfferingInfo, SubmissionReceiptInfo,
};

/// SUM Chain RPC API
#[rpc(server, client)]
pub trait SumChainApi {
    /// Get chain ID
    #[method(name = "chain_id")]
    async fn chain_id(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block
    #[method(name = "get_latest_block")]
    async fn get_latest_block(&self) -> Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by height
    #[method(name = "get_block_by_height")]
    async fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by hash
    #[method(name = "get_block_by_hash")]
    async fn get_block_by_hash(
        &self,
        hash: String,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account balance
    #[method(name = "get_balance")]
    async fn get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account nonce
    #[method(name = "get_nonce")]
    async fn get_nonce(&self, address: String) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account info
    #[method(name = "get_account")]
    async fn get_account(
        &self,
        address: String,
    ) -> Result<AccountInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Send raw transaction (hex encoded)
    #[method(name = "send_raw_transaction")]
    async fn send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction by hash
    #[method(name = "get_transaction")]
    async fn get_transaction(
        &self,
        tx_hash: String,
    ) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction receipt
    #[method(name = "get_receipt")]
    async fn get_receipt(
        &self,
        tx_hash: String,
    ) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Health check
    #[method(name = "health")]
    async fn health(&self) -> Result<HealthResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transaction count in mempool
    #[method(name = "pending_tx_count")]
    async fn pending_tx_count(&self) -> Result<usize, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block number (Ethereum-compatible, hex format)
    #[method(name = "eth_blockNumber")]
    async fn eth_block_number(&self) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get balance in hex format (Ethereum-compatible)
    #[method(name = "eth_getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SUM Chain Native Aliases (sum_* prefix for brand consistency)
    // These mirror the unprefixed methods but with sum_ prefix
    // ========================================================================

    /// Get block number (SUM native alias)
    #[method(name = "sum_blockNumber")]
    async fn sum_block_number(&self) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get latest block (SUM native alias)
    #[method(name = "sum_getLatestBlock")]
    async fn sum_get_latest_block(&self) -> Result<BlockInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get block by height (SUM native alias)
    #[method(name = "sum_getBlockByHeight")]
    async fn sum_get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account balance (SUM native alias)
    #[method(name = "sum_getBalance")]
    async fn sum_get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get account nonce (SUM native alias)
    #[method(name = "sum_getNonce")]
    async fn sum_get_nonce(&self, address: String) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Resolve public registry labels for a single address (issue #64). A
    /// read-only **point lookup** across the address-keyed public registries
    /// (DocClass / Employment issuer names; Tax / Finance issuer roles; node
    /// role) — no enumeration, no private data, no writes. Returns the raw
    /// address plus any labels and a deterministic `primary_label`; empty labels
    /// and `null` primary when the address is in no public registry. This is a
    /// **current** registry view, not a historical-at-tx-height assertion.
    #[method(name = "sum_resolveAddressLabels")]
    async fn sum_resolve_address_labels(
        &self,
        address: String,
    ) -> Result<AddressLabelsInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Send raw transaction (SUM native alias)
    #[method(name = "sum_sendRawTransaction")]
    async fn sum_send_raw_transaction(
        &self,
        raw_tx: String,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction by hash (SUM native alias)
    #[method(name = "sum_getTransaction")]
    async fn sum_get_transaction(
        &self,
        tx_hash: String,
    ) -> Result<Option<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction receipt (SUM native alias)
    #[method(name = "sum_getReceipt")]
    async fn sum_get_receipt(
        &self,
        tx_hash: String,
    ) -> Result<Option<ReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transactions (SUM native alias)
    #[method(name = "sum_getPendingTransactions")]
    async fn sum_get_pending_transactions(&self) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a single `InferenceAttestation` record for `(session_id, verifier_address)`.
    /// Returns `None` if no attestation has been committed for that pair.
    /// OmniNode Stage 6 / chain Phase 4.
    #[method(name = "sum_getInferenceAttestation")]
    async fn sum_get_inference_attestation(
        &self,
        session_id: String,
        verifier_address: String,
    ) -> Result<Option<InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List every verifier's `InferenceAttestation` for a given session.
    /// Returns an empty vec if no attestations exist. Used by OmniNode
    /// coordinators to determine quorum.
    #[method(name = "sum_listInferenceAttestations")]
    async fn sum_list_inference_attestations(
        &self,
        session_id: String,
    ) -> Result<Vec<InferenceAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Additive sponsor metadata for a **sponsored (v2)** inference attestation
    /// (issue #95). Returns `null` for v1 direct attestations and for absent
    /// attestations. Point lookup by `(session_id, verifier_address)` only — no
    /// sponsor-wide reverse lookup. Never affects settlement, which pays the
    /// verifier regardless of sponsorship.
    #[method(name = "sum_getInferenceAttestationSponsor")]
    async fn sum_get_inference_attestation_sponsor(
        &self,
        session_id: String,
        verifier_address: String,
    ) -> Result<Option<InferenceAttestationSponsorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the chain-side status of an `InferenceAttestation` tx by hash.
    /// Four states (`submitted`, `included`, `finalized`, `failed`) plus
    /// `unknown` for unrecognized hashes. `Dropped` is not tracked in
    /// v1 — see `crates/rpc/src/types.rs::InferenceAttestationStatusInfo`.
    #[method(name = "sum_getInferenceAttestationStatus")]
    async fn sum_get_inference_attestation_status(
        &self,
        tx_hash: String,
    ) -> Result<InferenceAttestationStatusInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned **sponsored** (v2) inference attestation tx (issue #79).
    /// No keys — the returned unsigned tx is signed offline by the sponsor/payer
    /// (`from`); the verifier is carried in the envelope. The canonical attestation
    /// remains verifier-keyed for dedup, storage, and settlement.
    #[method(name = "sum_buildSponsoredInferenceAttestation")]
    async fn sum_build_sponsored_inference_attestation(
        &self,
        request: crate::types::SponsoredAttestationBuildRequest,
    ) -> Result<crate::types::SponsoredAttestationBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    // ── OmniNode Inference Settlement (issue #61) — reads ───────────────────
    /// Get a session's settlement record, or `null` if none.
    #[method(name = "omninode_getInferenceSession")]
    async fn omninode_get_inference_session(
        &self,
        session_id: String,
    ) -> Result<Option<InferenceSessionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all paid reward claims for a session.
    #[method(name = "omninode_getInferenceClaims")]
    async fn omninode_get_inference_claims(
        &self,
        session_id: String,
    ) -> Result<Vec<InferenceClaimInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all dispute records for a session.
    #[method(name = "omninode_getInferenceDisputes")]
    async fn omninode_get_inference_disputes(
        &self,
        session_id: String,
    ) -> Result<Vec<InferenceDisputeInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Whether a verifier can currently claim a session's reward (and when).
    #[method(name = "omninode_getClaimableReward")]
    async fn omninode_get_claimable_reward(
        &self,
        session_id: String,
        verifier: String,
    ) -> Result<ClaimableRewardInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Consistency landscape for a session (issue #77): attestations grouped by
    /// the full digest tuple `(model_hash, manifest_root, response_hash,
    /// proof_root)`, with per-group total and currently-eligible counts.
    #[method(name = "omninode_getInferenceConsistency")]
    async fn omninode_get_inference_consistency(
        &self,
        session_id: String,
    ) -> Result<InferenceConsistencyReport, jsonrpsee::types::ErrorObjectOwned>;

    /// Verifier bond record (issue #78): bond amount, status, unbonding timers.
    /// Returns `None` if the verifier has never registered a bond.
    #[method(name = "omninode_getVerifier")]
    async fn omninode_get_verifier(
        &self,
        verifier: String,
    ) -> Result<Option<InferenceVerifierInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ── OmniNode Inference Settlement (issue #61) — unsigned-tx builders ─────
    #[method(name = "omninode_buildOpenInferenceSession")]
    async fn omninode_build_open_inference_session(
        &self,
        request: OmniBuildOpenSessionRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildFundInferenceSession")]
    async fn omninode_build_fund_inference_session(
        &self,
        request: OmniBuildFundSessionRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildClaimInferenceReward")]
    async fn omninode_build_claim_inference_reward(
        &self,
        request: OmniBuildClaimRewardRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildOpenInferenceDispute")]
    async fn omninode_build_open_inference_dispute(
        &self,
        request: OmniBuildOpenDisputeRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildResolveInferenceDispute")]
    async fn omninode_build_resolve_inference_dispute(
        &self,
        request: OmniBuildResolveDisputeRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildRefundInferenceSession")]
    async fn omninode_build_refund_inference_session(
        &self,
        request: OmniBuildRefundSessionRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    // ── Verifier bonding (issue #78) — unsigned-tx builders ─────
    #[method(name = "omninode_buildRegisterVerifier")]
    async fn omninode_build_register_verifier(
        &self,
        request: OmniBuildRegisterVerifierRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildAddVerifierBond")]
    async fn omninode_build_add_verifier_bond(
        &self,
        request: OmniBuildAddVerifierBondRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildBeginVerifierUnbond")]
    async fn omninode_build_begin_verifier_unbond(
        &self,
        request: OmniBuildVerifierBondActionRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "omninode_buildWithdrawVerifierBond")]
    async fn omninode_build_withdraw_verifier_bond(
        &self,
        request: OmniBuildVerifierBondActionRequest,
    ) -> Result<OmniSettlementBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    // ── SRC-817/818 Education suite — read-only RPC (Phase 4) ──
    // All ids/commitments are `0x`+hex strings. Student lookup is ONLY
    // by `student_commitment` (never a raw address). List methods are
    // bounded (default 256, capped at MAX_EDU_LIST_LIMIT=256). Reads
    // work regardless of the education activation gate state.

    #[method(name = "src817_getCatalogEntry")]
    async fn src817_get_catalog_entry(
        &self,
        catalog_id: String,
    ) -> Result<Option<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src817_getCatalogContent")]
    async fn src817_get_catalog_content(
        &self,
        catalog_id: String,
    ) -> Result<Vec<CatalogContentRefInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src817_listCatalogsByInstitution")]
    async fn src817_list_catalogs_by_institution(
        &self,
        institution_id: String,
        limit: Option<u32>,
    ) -> Result<Vec<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src817_listCatalogsByCode")]
    async fn src817_list_catalogs_by_code(
        &self,
        department: String,
        course_code: String,
        limit: Option<u32>,
    ) -> Result<Vec<CatalogEntryInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_getOffering")]
    async fn src818_get_offering(
        &self,
        offering_id: String,
    ) -> Result<Option<OfferingInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_listOfferingsByCatalog")]
    async fn src818_list_offerings_by_catalog(
        &self,
        catalog_id: String,
        limit: Option<u32>,
    ) -> Result<Vec<OfferingInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_listAssessments")]
    async fn src818_list_assessments(
        &self,
        offering_id: String,
        limit: Option<u32>,
    ) -> Result<Vec<AssessmentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_getAssessment")]
    async fn src818_get_assessment(
        &self,
        offering_id: String,
        assessment_id: String,
    ) -> Result<Option<AssessmentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_getEnrollmentLink")]
    async fn src818_get_enrollment_link(
        &self,
        offering_id: String,
        student_commitment: String,
    ) -> Result<Option<EnrollmentLinkInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_getSubmissionReceipt")]
    async fn src818_get_submission_receipt(
        &self,
        offering_id: String,
        assessment_id: String,
        student_commitment: String,
        attempt: u16,
    ) -> Result<Option<SubmissionReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_listSubmissionsByStudentCommitment")]
    async fn src818_list_submissions_by_student_commitment(
        &self,
        student_commitment: String,
        limit: Option<u32>,
    ) -> Result<Vec<SubmissionReceiptInfo>, jsonrpsee::types::ErrorObjectOwned>;

    #[method(name = "src818_getGradeRecord")]
    async fn src818_get_grade_record(
        &self,
        offering_id: String,
        assessment_id: String,
        student_commitment: String,
    ) -> Result<Option<GradeRecordInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validators (SUM native alias)
    #[method(name = "sum_getValidators")]
    async fn sum_get_validators(&self) -> Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending transactions from mempool
    #[method(name = "get_pending_transactions")]
    async fn get_pending_transactions(&self) -> Result<Vec<TransactionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get current validator set
    #[method(name = "get_validators")]
    async fn get_validators(&self) -> Result<ValidatorSetInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get multiple blocks in a range
    #[method(name = "get_blocks")]
    async fn get_blocks(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<BlockInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get node metrics
    #[method(name = "get_metrics")]
    async fn get_metrics(&self) -> Result<MetricsSnapshot, jsonrpsee::types::ErrorObjectOwned>;

    /// Get node info (version, network, etc.)
    #[method(name = "node_info")]
    async fn node_info(&self) -> Result<NodeInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get finality information
    #[method(name = "get_finality")]
    async fn get_finality(&self) -> Result<FinalityInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a block at a given height is finalized
    #[method(name = "is_block_finalized")]
    async fn is_block_finalized(&self, height: u64) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the live consensus parameters this node is using. SNIP V2 Phase 2.
    ///
    /// Returns the actual `ChainParams` from the node's live config, NOT
    /// hardcoded library defaults — so SNIP clients can read
    /// `assignment_replication_factor`, `max_chunk_count_per_file`, etc.
    /// at runtime instead of baking them in. If a future chain config tunes
    /// any of these values, SNIP picks them up without a client release.
    ///
    /// Flat wire shape (no nested `staking`/`messaging`/`docclass` sub-configs)
    /// since SNIP V2 clients don't use those. Additive; new fields can be
    /// appended without breaking existing clients.
    ///
    /// Includes `omninode_enabled_from_height` (`null` when OmniNode is
    /// disabled, `0` on the local-mirror preset, future block on a live
    /// chain) so OmniNode clients can read the activation gate at runtime
    /// the same way SNIP reads `v2_enabled_from_height`.
    #[method(name = "chain_getChainParams")]
    async fn chain_get_chain_params(
        &self,
    ) -> Result<ChainParamsInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Canonical-supply report (800B correction): initial/current canonical
    /// supply, live accounted account supply, burned supply, ProtocolReserve
    /// remaining, outstanding grants, migration id/status, governance mint
    /// total, and `automatic_emissions_enabled` (always `false`).
    #[method(name = "chain_getSupplyInfo")]
    async fn chain_get_supply_info(
        &self,
    ) -> Result<SupplyInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// ProtocolReserve pool balances. `null` before the supply correction has
    /// applied (the reserve does not exist yet).
    #[method(name = "chain_getProtocolReserve")]
    async fn chain_get_protocol_reserve(
        &self,
    ) -> Result<Option<ProtocolReserveInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Service-grant ledger record for `(address, service_kind)`; `null` when
    /// no grant exists. `service_kind` ∈ `validator|archive|compute`.
    #[method(name = "chain_getServiceGrant")]
    async fn chain_get_service_grant(
        &self,
        address: String,
        service_kind: String,
    ) -> Result<Option<ServiceGrantInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Service-grant eligibility snapshot: verifiable milestone counters, the
    /// claiming gate state, and genesis-validator exclusion. Read-only; the
    /// authoritative check happens at claim execution.
    #[method(name = "chain_getServiceGrantEligibility")]
    async fn chain_get_service_grant_eligibility(
        &self,
        address: String,
        service_kind: String,
    ) -> Result<ServiceGrantEligibilityInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned `ClaimServiceGrant` transaction (no keys; sign
    /// offline, submit via `sum_sendRawTransaction`).
    #[method(name = "chain_buildClaimServiceGrant")]
    async fn chain_build_claim_service_grant(
        &self,
        request: SupplyBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned `UnlockServiceGrant` transaction (no keys).
    #[method(name = "chain_buildUnlockServiceGrant")]
    async fn chain_build_unlock_service_grant(
        &self,
        request: SupplyBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the chain's current block height. SNIP V2 Ask 8 (Phase 0b).
    ///
    /// `finality` selector: `Some("finalized")` returns the finalized height
    /// (safe for expiry calculations under PoA reorgs); `None` or
    /// `Some("latest")` returns the head height. The return value's
    /// `finality` field echoes which view was returned.
    #[method(name = "chain_getBlockHeight")]
    async fn chain_get_block_height(
        &self,
        finality: Option<String>,
    ) -> Result<BlockHeightInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the inclusion / finality status of a transaction by hash.
    /// SNIP V2 Ask 11 (Phase 0b).
    ///
    /// Returns one of: `Unknown` (never seen), `Pending` (in mempool),
    /// `Included { block_height }` (in a block, not finalized),
    /// `Finalized { block_height }` (finalized per consensus mode —
    /// depth=3 under PoA, depth=0 under BFT), or `Failed { ... }`.
    /// `Dropped` is reserved but not currently returned.
    #[method(name = "chain_getTransactionStatus")]
    async fn chain_get_transaction_status(
        &self,
        tx_hash: String,
    ) -> Result<TxStatusV2, jsonrpsee::types::ErrorObjectOwned>;

    /// Get list of connected peers
    #[method(name = "get_peers")]
    async fn get_peers(&self) -> Result<Vec<RpcPeerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get P2P network statistics
    #[method(name = "get_p2p_stats")]
    async fn get_p2p_stats(&self) -> Result<P2pStats, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // NFT (SUM-721) Endpoints
    // ========================================================================

    /// Get NFT collection by ID
    #[method(name = "nft_getCollection")]
    async fn nft_get_collection(
        &self,
        collection_id: String,
    ) -> Result<Option<NftCollectionInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get NFT token by collection ID and token ID
    #[method(name = "nft_getToken")]
    async fn nft_get_token(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<Option<NftTokenInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all tokens owned by an address
    #[method(name = "nft_getTokensByOwner")]
    async fn nft_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> Result<NftOwnerTokens, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all token IDs in a collection
    #[method(name = "nft_getTokensInCollection")]
    async fn nft_get_tokens_in_collection(
        &self,
        collection_id: String,
    ) -> Result<Vec<u64>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the number of tokens owned by an address
    #[method(name = "nft_balanceOf")]
    async fn nft_balance_of(
        &self,
        owner: String,
    ) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the owner of a specific token
    #[method(name = "nft_ownerOf")]
    async fn nft_owner_of(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a token exists
    #[method(name = "nft_tokenExists")]
    async fn nft_token_exists(
        &self,
        collection_id: String,
        token_id: u64,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-20 Token Endpoints
    // ========================================================================

    /// Get SRC-20 token by ID
    #[method(name = "token_getToken")]
    async fn token_get_token(
        &self,
        token_id: String,
    ) -> Result<Option<TokenInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get SRC-20 token balance for an address
    #[method(name = "token_balanceOf")]
    async fn token_balance_of(
        &self,
        token_id: String,
        owner: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all SRC-20 tokens held by an address
    #[method(name = "token_getTokensByOwner")]
    async fn token_get_tokens_by_owner(
        &self,
        owner: String,
    ) -> Result<TokenHoldings, jsonrpsee::types::ErrorObjectOwned>;

    /// Get SRC-20 token allowance
    #[method(name = "token_allowance")]
    async fn token_allowance(
        &self,
        token_id: String,
        owner: String,
        spender: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get total supply of an SRC-20 token
    #[method(name = "token_totalSupply")]
    async fn token_total_supply(
        &self,
        token_id: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an SRC-20 token exists
    #[method(name = "token_exists")]
    async fn token_exists(
        &self,
        token_id: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the registered minters of a single SRC-20 token (token-scoped).
    ///
    /// Returns the token owner (implicit minter) plus explicitly registered
    /// minter addresses, read from public token config. This is deliberately
    /// token-scoped: there is no address→tokens ("what can this address mint")
    /// endpoint — that would be a broader address-profiling surface and is out
    /// of scope by design.
    #[method(name = "token_getMinters")]
    async fn token_get_minters(
        &self,
        token_id: String,
    ) -> Result<Option<TokenMintersInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Smart Contract (SUMC) Endpoints
    // ========================================================================

    /// Get contract info by address
    #[method(name = "contract_getContract")]
    async fn contract_get_contract(
        &self,
        address: String,
    ) -> Result<Option<ContractInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is a contract
    #[method(name = "contract_isContract")]
    async fn contract_is_contract(
        &self,
        address: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Execute a view call (read-only, no state changes)
    #[method(name = "contract_call")]
    async fn contract_call(
        &self,
        request: ViewCallRequest,
    ) -> Result<ContractCallResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Estimate gas for a contract call
    #[method(name = "contract_estimateGas")]
    async fn contract_estimate_gas(
        &self,
        request: ViewCallRequest,
    ) -> Result<GasEstimateResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract code hash
    #[method(name = "contract_getCodeHash")]
    async fn contract_get_code_hash(
        &self,
        address: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract storage at a specific key
    #[method(name = "contract_getStorageAt")]
    async fn contract_get_storage_at(
        &self,
        address: String,
        key: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get contract balance
    #[method(name = "contract_getBalance")]
    async fn contract_get_balance(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Staking Endpoints
    // ========================================================================

    /// Get staking validator by public key (hex)
    #[method(name = "staking_getValidator")]
    async fn staking_get_validator(
        &self,
        pubkey: String,
    ) -> Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all staking validators
    #[method(name = "staking_getValidators")]
    async fn staking_get_validators(
        &self,
    ) -> Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active staking validators only
    #[method(name = "staking_getActiveValidators")]
    async fn staking_get_active_validators(
        &self,
    ) -> Result<Vec<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get staking summary (totals and parameters)
    #[method(name = "staking_getSummary")]
    async fn staking_get_summary(
        &self,
    ) -> Result<StakingSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get staking parameters
    #[method(name = "staking_getParams")]
    async fn staking_get_params(
        &self,
    ) -> Result<StakingParamsInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get total staked amount
    #[method(name = "staking_getTotalStake")]
    async fn staking_get_total_stake(
        &self,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator by address (base58)
    #[method(name = "staking_getValidatorByAddress")]
    async fn staking_get_validator_by_address(
        &self,
        address: String,
    ) -> Result<Option<StakingValidatorInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Delegation Endpoints
    // ========================================================================

    /// Get delegation info for a delegator to a specific validator
    #[method(name = "delegation_getDelegation")]
    async fn delegation_get_delegation(
        &self,
        delegator: String,
        validator_pubkey: String,
    ) -> Result<Option<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all delegations for a delegator
    #[method(name = "delegation_getDelegationsByDelegator")]
    async fn delegation_get_delegations_by_delegator(
        &self,
        delegator: String,
    ) -> Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all delegations to a validator
    #[method(name = "delegation_getDelegationsByValidator")]
    async fn delegation_get_delegations_by_validator(
        &self,
        validator_pubkey: String,
    ) -> Result<Vec<DelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get delegator summary (total delegated, rewards, unbonding)
    #[method(name = "delegation_getDelegatorSummary")]
    async fn delegation_get_delegator_summary(
        &self,
        delegator: String,
    ) -> Result<DelegatorSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get unbonding delegations for a delegator
    #[method(name = "delegation_getUnbondingDelegations")]
    async fn delegation_get_unbonding_delegations(
        &self,
        delegator: String,
    ) -> Result<Vec<UnbondingDelegationRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator delegation summary (total delegated, delegator count)
    #[method(name = "delegation_getValidatorDelegationSummary")]
    async fn delegation_get_validator_delegation_summary(
        &self,
        validator_pubkey: String,
    ) -> Result<ValidatorDelegationSummary, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Slashing Endpoints
    // ========================================================================

    /// Get slashing records for a validator
    #[method(name = "slashing_getRecords")]
    async fn slashing_get_records(
        &self,
        validator_pubkey: String,
    ) -> Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator signing info (liveness tracking)
    #[method(name = "slashing_getSigningInfo")]
    async fn slashing_get_signing_info(
        &self,
        validator_pubkey: String,
    ) -> Result<Option<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all signing info for all validators
    #[method(name = "slashing_getAllSigningInfo")]
    async fn slashing_get_all_signing_info(
        &self,
    ) -> Result<Vec<ValidatorSigningRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get slashing summary (totals across all validators)
    #[method(name = "slashing_getSummary")]
    async fn slashing_get_summary(
        &self,
    ) -> Result<SlashingSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a validator is tombstoned (permanently jailed)
    #[method(name = "slashing_isTombstoned")]
    async fn slashing_is_tombstoned(
        &self,
        validator_pubkey: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get recent slashing records across all validators
    #[method(name = "slashing_getRecentRecords")]
    async fn slashing_get_recent_records(
        &self,
        limit: u32,
    ) -> Result<Vec<SlashingRecordRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Validator Set Endpoints
    // ========================================================================

    /// Get current epoch info
    #[method(name = "epoch_getInfo")]
    async fn epoch_get_info(
        &self,
    ) -> Result<EpochInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get current active validator set
    #[method(name = "validatorSet_getCurrent")]
    async fn validator_set_get_current(
        &self,
    ) -> Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get validator set for a specific epoch
    #[method(name = "validatorSet_getByEpoch")]
    async fn validator_set_get_by_epoch(
        &self,
        epoch: u64,
    ) -> Result<Option<ValidatorSetRpcInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the proposer for a given height
    #[method(name = "validatorSet_getProposer")]
    async fn validator_set_get_proposer(
        &self,
        height: u64,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-201 Messaging Endpoints
    // ========================================================================

    /// Get messaging configuration
    #[method(name = "messaging_getConfig")]
    async fn messaging_get_config(
        &self,
    ) -> Result<MessagingConfigInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's messaging quota
    #[method(name = "messaging_getQuota")]
    async fn messaging_get_quota(
        &self,
        address: String,
    ) -> Result<MessagingQuotaInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get recipient's inbox filter
    #[method(name = "messaging_getInboxFilter")]
    async fn messaging_get_inbox_filter(
        &self,
        address: String,
    ) -> Result<Option<InboxFilterInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get messages for a recipient (by recipient hash)
    #[method(name = "messaging_getMessages")]
    async fn messaging_get_messages(
        &self,
        recipient_hash: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get messages sent by an address
    #[method(name = "messaging_getSentMessages")]
    async fn messaging_get_sent_messages(
        &self,
        sender: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a specific message by transaction hash (for debugging)
    #[method(name = "messaging_getMessageByTxHash")]
    async fn messaging_get_message_by_tx_hash(
        &self,
        tx_hash: String,
    ) -> Result<Option<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all messages in a specific block (for debugging)
    #[method(name = "messaging_getMessagesInBlock")]
    async fn messaging_get_messages_in_block(
        &self,
        block_height: u64,
        limit: Option<u32>,
    ) -> Result<Vec<MessageEventInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the encrypted message data for a specific message by transaction hash
    #[method(name = "messaging_getMessageData")]
    async fn messaging_get_message_data(
        &self,
        tx_hash: String,
    ) -> Result<Option<MessageDataInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get pending payment by message ID
    #[method(name = "messaging_getPendingPayment")]
    async fn messaging_get_pending_payment(
        &self,
        message_id: String,
    ) -> Result<Option<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all pending payments for a recipient
    #[method(name = "messaging_getPendingPayments")]
    async fn messaging_get_pending_payments(
        &self,
        recipient: String,
    ) -> Result<Vec<PendingPaymentInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's trust stake
    #[method(name = "messaging_getTrustStake")]
    async fn messaging_get_trust_stake(
        &self,
        address: String,
    ) -> Result<String, jsonrpsee::types::ErrorObjectOwned>;

    /// Get sender's spam score
    #[method(name = "messaging_getSpamScore")]
    async fn messaging_get_spam_score(
        &self,
        address: String,
    ) -> Result<SpamReportInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is a contact of another
    #[method(name = "messaging_isContact")]
    async fn messaging_is_contact(
        &self,
        owner: String,
        contact: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an address is blocked by another
    #[method(name = "messaging_isBlocked")]
    async fn messaging_is_blocked(
        &self,
        owner: String,
        sender: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Submit a sponsored message (meta-transaction)
    #[method(name = "messaging_submitSponsored")]
    async fn messaging_submit_sponsored(
        &self,
        request: SubmitSponsoredMessageRequest,
    ) -> Result<SendTxResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Register public key with gas sponsorship (no balance required)
    /// This allows new users to register for SUMail without needing any Koppa
    #[method(name = "messaging_registerSponsored")]
    async fn messaging_register_sponsored(
        &self,
        request: SponsoredRegistrationRequest,
    ) -> Result<SponsoredRegistrationResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get registered public key for an address
    #[method(name = "account_getPublicKey")]
    async fn account_get_public_key(
        &self,
        address: String,
    ) -> Result<Option<PublicKeyInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the X25519 encryption pubkey registered for an account.
    /// SNIP V2 Ask 3 (Phase 0b checkpoint 2).
    ///
    /// Returns `Some(hex-encoded 32-byte Montgomery U-coordinate)` if the
    /// account has registered an encryption pubkey via
    /// `NodeRegistryOperationV2::RegisterEncryptionKey`, else `None`.
    /// Hex is `0x`-prefixed, lowercase.
    ///
    /// Distinct from `account_getPublicKey`, which returns the SRC-201 messaging
    /// public key (Ed25519). The two are stored in separate column families and
    /// serve different purposes; SNIP recipients must register an X25519 key
    /// before anyone can share a Private file with them.
    #[method(name = "account_getEncryptionPublicKey")]
    async fn account_get_encryption_public_key(
        &self,
        address: String,
    ) -> Result<Option<String>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // SRC-80X/81X DocClass Endpoints
    // ========================================================================

    /// Get DocClass configuration
    #[method(name = "docclass_getConfig")]
    async fn docclass_get_config(
        &self,
    ) -> Result<DocClassConfigInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get DocClass summary statistics
    #[method(name = "docclass_getSummary")]
    async fn docclass_get_summary(
        &self,
    ) -> Result<DocClassSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get identity root by ID (hex)
    #[method(name = "docclass_getIdentity")]
    async fn docclass_get_identity(
        &self,
        identity_id: String,
    ) -> Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get identity root by controller address
    #[method(name = "docclass_getIdentityByController")]
    async fn docclass_get_identity_by_controller(
        &self,
        controller: String,
    ) -> Result<Option<DocClassIdentityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credential by ID (hex)
    #[method(name = "docclass_getCredential")]
    async fn docclass_get_credential(
        &self,
        credential_id: String,
    ) -> Result<Option<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credentials by subject commitment (hex)
    #[method(name = "docclass_getCredentialsBySubject")]
    async fn docclass_get_credentials_by_subject(
        &self,
        subject_commitment: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get credentials by issuer address
    #[method(name = "docclass_getCredentialsByIssuer")]
    async fn docclass_get_credentials_by_issuer(
        &self,
        issuer: String,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if a credential is valid (not revoked, not expired)
    #[method(name = "docclass_isCredentialValid")]
    async fn docclass_is_credential_valid(
        &self,
        credential_id: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// Get issuer by address
    #[method(name = "docclass_getIssuer")]
    async fn docclass_get_issuer(
        &self,
        address: String,
    ) -> Result<Option<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all registered issuers
    #[method(name = "docclass_getIssuers")]
    async fn docclass_get_issuers(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get issuers by jurisdiction
    #[method(name = "docclass_getIssuersByJurisdiction")]
    async fn docclass_get_issuers_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> Result<Vec<DocClassIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-82X Tax registry reads (issue #26 — administrative registries only;
    // no subject-keyed proofs/disclosures/events are exposed).
    // =========================================================================

    /// Get a Tax claim-type registry entry by its identifier.
    #[method(name = "tax_getClaimType")]
    async fn tax_get_claim_type(
        &self,
        claim_type: String,
    ) -> Result<Option<TaxClaimTypeInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all Tax claim-type registry entries.
    #[method(name = "tax_listClaimTypes")]
    async fn tax_list_claim_types(
        &self,
    ) -> Result<Vec<TaxClaimTypeInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a Tax issuer by base address.
    #[method(name = "tax_getIssuer")]
    async fn tax_get_issuer(
        &self,
        address: String,
    ) -> Result<Option<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active Tax issuers.
    #[method(name = "tax_getActiveIssuers")]
    async fn tax_get_active_issuers(
        &self,
    ) -> Result<Vec<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List Tax issuers of a given class (e.g. "TaxAuthority", "BankBroker").
    #[method(name = "tax_getIssuersByClass")]
    async fn tax_get_issuers_by_class(
        &self,
        tax_class: String,
    ) -> Result<Vec<TaxIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a Tax policy by its hex policy id.
    #[method(name = "tax_getPolicy")]
    async fn tax_get_policy(
        &self,
        policy_id: String,
    ) -> Result<Option<TaxPolicyInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all Tax policies.
    #[method(name = "tax_listPolicies")]
    async fn tax_list_policies(
        &self,
    ) -> Result<Vec<TaxPolicyInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-83X Equity registry reads (issue #26 — entity / share-class /
    // controller-config registries only; no holder/ownership/proof data).
    // =========================================================================

    /// Get an entity profile by subject id (hex).
    #[method(name = "equity_getEntity")]
    async fn equity_get_entity(
        &self,
        subject_id: String,
    ) -> Result<Option<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active entity profiles.
    #[method(name = "equity_getActiveEntities")]
    async fn equity_get_active_entities(
        &self,
    ) -> Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List entities by organization type (e.g. "Corporation", "LLC", "DAO").
    #[method(name = "equity_getEntitiesByOrgType")]
    async fn equity_get_entities_by_org_type(
        &self,
        org_type: String,
    ) -> Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List entities a controller address controls.
    #[method(name = "equity_getEntitiesByController")]
    async fn equity_get_entities_by_controller(
        &self,
        controller: String,
    ) -> Result<Vec<EquityEntityInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a share class by class id (hex).
    #[method(name = "equity_getShareClass")]
    async fn equity_get_share_class(
        &self,
        class_id: String,
    ) -> Result<Option<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active share classes.
    #[method(name = "equity_getActiveShareClasses")]
    async fn equity_get_active_share_classes(
        &self,
    ) -> Result<Vec<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List share classes issued by an entity (issuer subject id, hex).
    #[method(name = "equity_getShareClassesByIssuer")]
    async fn equity_get_share_classes_by_issuer(
        &self,
        issuer_subject: String,
    ) -> Result<Vec<EquityShareClassInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the class-level controller config by class id (hex).
    #[method(name = "equity_getControllerConfig")]
    async fn equity_get_controller_config(
        &self,
        class_id: String,
    ) -> Result<Option<EquityControllerConfigInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-84X Agreement executor-link registry reads (issue #26 — executor
    // links only; no commitments, parties, signatures, attestations, IP
    // actions, proofs, events, or off-chain content).
    // =========================================================================

    /// Get an executor link by link id (hex).
    #[method(name = "agreement_getExecutorLink")]
    async fn agreement_get_executor_link(
        &self,
        link_id: String,
    ) -> Result<Option<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List executor links bound to an agreement (agreement id, hex).
    #[method(name = "agreement_getExecutorLinksByAgreement")]
    async fn agreement_get_executor_links_by_agreement(
        &self,
        agreement_id: String,
    ) -> Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List executor links for an executor contract address.
    #[method(name = "agreement_getExecutorLinksByExecutor")]
    async fn agreement_get_executor_links_by_executor(
        &self,
        executor_address: String,
    ) -> Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active executor links.
    #[method(name = "agreement_getActiveExecutorLinks")]
    async fn agreement_get_active_executor_links(
        &self,
    ) -> Result<Vec<ExecutorLinkInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-86X Property asset-anchor registry reads (issue #26 — asset anchors
    // only; no title events, encumbrances, coverage, claims, proofs, events,
    // party identities, off-chain content, or amounts).
    // =========================================================================

    /// Get an asset anchor by asset id (hex).
    #[method(name = "property_getAsset")]
    async fn property_get_asset(
        &self,
        asset_id: String,
    ) -> Result<Option<AssetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active asset anchors.
    #[method(name = "property_getActiveAssets")]
    async fn property_get_active_assets(
        &self,
    ) -> Result<Vec<AssetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List asset anchors registered in a jurisdiction (e.g. "US-CA-LA").
    #[method(name = "property_getAssetsByJurisdiction")]
    async fn property_get_assets_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> Result<Vec<AssetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-89X Finance issuer-registry reads (issue #26 — institution issuer
    // profiles only; no address proofs, bank-standing, KYC attestations,
    // proofs, events, subject/holder records, or by-subject queries).
    // =========================================================================

    /// Get a finance issuer profile by issuer address.
    #[method(name = "finance_getIssuer")]
    async fn finance_get_issuer(
        &self,
        issuer_address: String,
    ) -> Result<Option<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active finance issuer profiles.
    #[method(name = "finance_getActiveIssuers")]
    async fn finance_get_active_issuers(
        &self,
    ) -> Result<Vec<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List finance issuer profiles registered in a jurisdiction (e.g. "US").
    #[method(name = "finance_getIssuersByJurisdiction")]
    async fn finance_get_issuers_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> Result<Vec<FinanceIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-85X Legal case-anchor registry reads (issue #26 — case/docket anchors
    // only; no case_type/public_reference/related_cases, no process events,
    // court orders, benefit determinations, proofs, events, or by-case/subject
    // queries. Sealed cases are never returned.
    // =========================================================================

    /// Get a case anchor by case id (hex). Returns None for sealed cases.
    #[method(name = "legal_getCase")]
    async fn legal_get_case(
        &self,
        case_id: String,
    ) -> Result<Option<CaseInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List open (Filed/Active) case anchors. Sealed cases are excluded.
    #[method(name = "legal_getActiveCases")]
    async fn legal_get_active_cases(
        &self,
    ) -> Result<Vec<CaseInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List case anchors registered in a jurisdiction (e.g. "US-NY-SDNY").
    /// Sealed cases are excluded.
    #[method(name = "legal_getCasesByJurisdiction")]
    async fn legal_get_cases_by_jurisdiction(
        &self,
        jurisdiction: String,
    ) -> Result<Vec<CaseInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-871 Healthcare institutional provider registry reads (issue #41 —
    // organizational providers only, restricted by an explicit allowlist of
    // provider types; no memberships, consents, prescriptions, proofs, events,
    // or member/patient/subject data; no by-network query).
    // =========================================================================

    /// Get an institutional provider by provider id (hex). Returns None for
    /// non-allowlisted (e.g. individual-clinician) provider types.
    #[method(name = "healthcare_getInstitutionalProvider")]
    async fn healthcare_get_institutional_provider(
        &self,
        provider_id: String,
    ) -> Result<Option<HealthcareProviderInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List active institutional providers (allowlisted organizational types).
    #[method(name = "healthcare_getActiveInstitutionalProviders")]
    async fn healthcare_get_active_institutional_providers(
        &self,
    ) -> Result<Vec<HealthcareProviderInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // On-chain governance v1 (issue #50) — unsigned-tx builders (no private
    // keys) + reads. Governance is dormant by default; reads are gate-agnostic
    // and return stored data / empty. See docs/specs/GOVERNANCE-V1.md.
    // =========================================================================

    /// Build an unsigned create-proposal transaction to sign and broadcast.
    #[method(name = "gov_buildCreateProposal")]
    async fn gov_build_create_proposal(
        &self,
        request: GovBuildCreateProposalRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned cast-vote transaction to sign and broadcast.
    #[method(name = "gov_buildCastVote")]
    async fn gov_build_cast_vote(
        &self,
        request: GovBuildCastVoteRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned execute-proposal transaction to sign and broadcast.
    #[method(name = "gov_buildExecuteProposal")]
    async fn gov_build_execute_proposal(
        &self,
        request: GovBuildExecuteProposalRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned cancel-proposal transaction to sign and broadcast.
    /// The proposer (bond returned) or the council (bond burned) may cancel
    /// while the proposal is Created/Voting.
    #[method(name = "gov_buildCancelProposal")]
    async fn gov_build_cancel_proposal(
        &self,
        request: GovBuildCancelProposalRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a proposal by id (hex).
    #[method(name = "gov_getProposal")]
    async fn gov_get_proposal(
        &self,
        proposal_id: String,
    ) -> Result<Option<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all proposals.
    #[method(name = "gov_listProposals")]
    async fn gov_list_proposals(
        &self,
    ) -> Result<Vec<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List proposals currently in the voting state.
    #[method(name = "gov_listActiveProposals")]
    async fn gov_list_active_proposals(
        &self,
    ) -> Result<Vec<GovProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Tally a proposal from its frozen snapshot + cast votes.
    #[method(name = "gov_getTally")]
    async fn gov_get_tally(
        &self,
        proposal_id: String,
    ) -> Result<Option<GovTallyInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a voter's vote on a proposal (hex id, address).
    #[method(name = "gov_getVote")]
    async fn gov_get_vote(
        &self,
        proposal_id: String,
        voter: String,
    ) -> Result<Option<GovVoteInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a holder's frozen snapshot voting power for a proposal.
    #[method(name = "gov_getVotingPower")]
    async fn gov_get_voting_power(
        &self,
        proposal_id: String,
        holder: String,
    ) -> Result<Option<GovVotingPowerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all registered governance assets (with status + effective height).
    #[method(name = "gov_listEligibleAssets")]
    async fn gov_list_eligible_assets(
        &self,
    ) -> Result<Vec<GovAssetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ── Governance v2: native-Koppa eligibility (#91) ────────────────────────

    /// Build an unsigned register-qualifying-asset tx (#91, validator-quorum).
    #[method(name = "gov_buildRegisterQualifyingAsset")]
    async fn gov_build_register_qualifying_asset(
        &self,
        request: GovBuildRegisterQualifyingAssetRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned native-eligibility vote tx (#91; reuses the CastVote
    /// payload path — weight is 1 per eligible address).
    #[method(name = "gov_buildCastNativeVote")]
    async fn gov_build_cast_native_vote(
        &self,
        request: GovBuildCastNativeVoteRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Whether `address` is in a native proposal's frozen eligibility snapshot.
    #[method(name = "gov_getNativeEligibility")]
    async fn gov_get_native_eligibility(
        &self,
        proposal_id: String,
        address: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    /// List the native-eligibility qualifying SRC-20 registry (#91).
    #[method(name = "gov_listQualifyingAssets")]
    async fn gov_list_qualifying_assets(
        &self,
    ) -> Result<Vec<GovQualifyingAssetInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ── Governance v2: SRC-833 controller-attested equity vote (#92) ─────────

    /// Build an unsigned register-equity-class tx (#92, validator-quorum).
    #[method(name = "gov_buildRegisterEquityClass")]
    async fn gov_build_register_equity_class(
        &self,
        request: GovBuildRegisterEquityClassRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned controller-attested equity vote tx (#92). Carries the
    /// holder commitment / shares / merkle path / controller pubkey+signature as
    /// DATA — no private keys.
    #[method(name = "gov_buildCastEquityVote")]
    async fn gov_build_cast_equity_vote(
        &self,
        request: GovBuildCastEquityVoteRequest,
    ) -> Result<GovBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// SRC-833 equity-class voting metadata (#92): chain-derived balances root,
    /// votes-per-share, voting flag. Never a holder→balance table.
    #[method(name = "gov_getEquityClassVoting")]
    async fn gov_get_equity_class_voting(
        &self,
        class_id: String,
    ) -> Result<Option<GovEquityClassVotingInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Check if an issuer can issue a specific subcode in a jurisdiction
    #[method(name = "docclass_canIssue")]
    async fn docclass_can_issue(
        &self,
        issuer: String,
        subcode: u16,
        jurisdiction: String,
    ) -> Result<bool, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Transaction History Endpoints
    // ========================================================================

    /// Get transactions by address (both sent and received)
    /// Returns transactions with pagination support
    #[method(name = "sum_getTransactionsByAddress")]
    async fn sum_get_transactions_by_address(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transactions sent by an address
    #[method(name = "sum_getTransactionsBySender")]
    async fn sum_get_transactions_by_sender(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transactions received by an address
    #[method(name = "sum_getTransactionsByRecipient")]
    async fn sum_get_transactions_by_recipient(
        &self,
        address: String,
        limit: Option<u32>,
        offset: Option<u64>,
    ) -> Result<TransactionHistoryResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get transaction count for an address
    #[method(name = "sum_getTransactionCount")]
    async fn sum_get_transaction_count(
        &self,
        address: String,
    ) -> Result<u64, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment & HR Endpoints
    // =========================================================================

    /// Get employment issuer by address (SRC-881)
    #[method(name = "employment_getIssuer")]
    async fn employment_get_issuer(
        &self,
        issuer_address: String,
    ) -> Result<Option<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List all active employment issuers
    #[method(name = "employment_listIssuers")]
    async fn employment_list_issuers(
        &self,
    ) -> Result<Vec<EmploymentIssuerInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credential by ID (SRC-882)
    #[method(name = "employment_getCredential")]
    async fn employment_get_credential(
        &self,
        employment_id: String,
    ) -> Result<Option<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credentials by employee reference
    #[method(name = "employment_getCredentialsByEmployee")]
    async fn employment_get_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active employment credentials by employee reference
    #[method(name = "employment_getActiveCredentialsByEmployee")]
    async fn employment_get_active_credentials_by_employee(
        &self,
        employee_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment credentials by employer reference
    #[method(name = "employment_getCredentialsByEmployer")]
    async fn employment_get_credentials_by_employer(
        &self,
        employer_ref: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Verify if an employee is currently employed by a specific employer
    #[method(name = "employment_verifyEmployment")]
    async fn employment_verify_employment(
        &self,
        employee_ref: String,
        employer_ref: String,
    ) -> Result<EmploymentVerificationResult, jsonrpsee::types::ErrorObjectOwned>;

    /// Get employment summary for an employee
    #[method(name = "employment_getSummary")]
    async fn employment_get_summary(
        &self,
        employee_ref: String,
    ) -> Result<EmploymentSummary, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestation by ID (SRC-883)
    #[method(name = "employment_getIncomeAttestation")]
    async fn employment_get_income_attestation(
        &self,
        attestation_id: String,
    ) -> Result<Option<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestations by subject reference
    #[method(name = "employment_getIncomeAttestationsBySubject")]
    async fn employment_get_income_attestations_by_subject(
        &self,
        subject_ref: String,
    ) -> Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment - Address-based queries (token ownership)
    // =========================================================================

    /// Get employment credentials by employee wallet address
    #[method(name = "employment_getCredentialsByEmployeeAddress")]
    async fn employment_get_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get active employment credentials by employee wallet address
    #[method(name = "employment_getActiveCredentialsByEmployeeAddress")]
    async fn employment_get_active_credentials_by_employee_address(
        &self,
        employee_address: String,
    ) -> Result<Vec<EmploymentCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get income attestations by holder wallet address
    #[method(name = "employment_getIncomeAttestationsByHolderAddress")]
    async fn employment_get_income_attestations_by_holder_address(
        &self,
        holder_address: String,
    ) -> Result<Vec<IncomeAttestationInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-88X Employment Write Operations (Token-gated access)
    // =========================================================================

    /// Register as an employment issuer (SRC-881)
    /// Requires signing the transaction with issuer's private key
    #[method(name = "employment_registerIssuer")]
    async fn employment_register_issuer(
        &self,
        request: RegisterEmploymentIssuerRequest,
    ) -> Result<RegisterEmploymentIssuerResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Create an employment credential (SRC-882)
    /// Requires the caller to be a registered issuer
    #[method(name = "employment_createCredential")]
    async fn employment_create_credential(
        &self,
        request: CreateEmploymentCredentialRequest,
    ) -> Result<CreateEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Revoke an employment credential (SRC-882)
    /// Requires the caller to be the original issuer of the credential
    #[method(name = "employment_revokeCredential")]
    async fn employment_revoke_credential(
        &self,
        request: RevokeEmploymentCredentialRequest,
    ) -> Result<RevokeEmploymentCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // SRC-81X Academic Credential Write Operations
    // =========================================================================

    /// Register as an academic issuer (educational institution)
    /// Requires signing the transaction with issuer's private key
    /// Requires stake amount (>= 1000 Ϙ)
    #[method(name = "docclass_registerAcademicIssuer")]
    async fn docclass_register_academic_issuer(
        &self,
        request: RegisterAcademicIssuerRequest,
    ) -> Result<RegisterAcademicIssuerResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Issue an academic credential (SRC-810/811/812)
    /// Requires the caller to be a registered academic issuer
    /// Subcodes: 810=Transcript, 811=Diploma, 812=Enrollment
    #[method(name = "docclass_issueAcademicCredential")]
    async fn docclass_issue_academic_credential(
        &self,
        request: IssueAcademicCredentialRequest,
    ) -> Result<IssueAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Revoke an academic credential (SRC-810/811/812)
    /// Requires the caller to be the original issuer of the credential
    #[method(name = "docclass_revokeAcademicCredential")]
    async fn docclass_revoke_academic_credential(
        &self,
        request: RevokeAcademicCredentialRequest,
    ) -> Result<RevokeAcademicCredentialResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get academic credentials by holder address
    /// Returns all academic credentials (810/811/812) owned by the given address
    #[method(name = "docclass_getAcademicCredentialsByHolder")]
    async fn docclass_get_academic_credentials_by_holder(
        &self,
        holder_address: String,
    ) -> Result<Vec<DocClassCredentialInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // Policy Account Methods (Group Governance)
    // =========================================================================

    /// Build an unsigned create-policy-account transaction.
    ///
    /// Returns unsigned transaction material (bincode hex + signing hash). The
    /// server never sees a private key; the client signs and submits via
    /// `sum_sendRawTransaction`.
    #[method(name = "policy_buildCreateAccount")]
    async fn policy_build_create_account(
        &self,
        request: BuildCreateAccountRequest,
    ) -> Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get policy account information by ID
    #[method(name = "policy_getAccount")]
    async fn policy_get_account(
        &self,
        policy_account_id: String,
    ) -> Result<PolicyAccountInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// Get policy account by controlled address
    #[method(name = "policy_getAccountByAddress")]
    async fn policy_get_account_by_address(
        &self,
        address: String,
    ) -> Result<Option<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List policy accounts where the address is a member
    #[method(name = "policy_listMemberAccounts")]
    async fn policy_list_member_accounts(
        &self,
        member_address: String,
    ) -> Result<Vec<PolicyAccountInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned submit-proposal transaction.
    #[method(name = "policy_buildSubmitProposal")]
    async fn policy_build_submit_proposal(
        &self,
        request: BuildSubmitProposalRequest,
    ) -> Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned execute-proposal transaction.
    #[method(name = "policy_buildExecuteProposal")]
    async fn policy_build_execute_proposal(
        &self,
        request: BuildExecuteProposalRequest,
    ) -> Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned cancel-proposal transaction (proposer only).
    #[method(name = "policy_buildCancelProposal")]
    async fn policy_build_cancel_proposal(
        &self,
        request: BuildCancelProposalRequest,
    ) -> Result<PolicyBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Get proposal information by ID
    #[method(name = "policy_getProposal")]
    async fn policy_get_proposal(
        &self,
        proposal_id: String,
    ) -> Result<ProposalInfo, jsonrpsee::types::ErrorObjectOwned>;

    /// List all proposals for a policy account
    #[method(name = "policy_listProposals")]
    async fn policy_list_proposals(
        &self,
        policy_account_id: String,
    ) -> Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// List pending proposals for a policy account
    #[method(name = "policy_listPendingProposals")]
    async fn policy_list_pending_proposals(
        &self,
        policy_account_id: String,
    ) -> Result<Vec<ProposalInfo>, jsonrpsee::types::ErrorObjectOwned>;

    // ========================================================================
    // Storage Metadata Methods
    // ========================================================================

    /// Get storage file metadata and access list by merkle root
    #[method(name = "storage_getAccessList")]
    async fn storage_get_access_list(
        &self,
        merkle_root: String,
    ) -> Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all active storage challenges assigned to a specific node
    #[method(name = "storage_getActiveChallenges")]
    async fn storage_get_active_challenges(
        &self,
        node_address: String,
    ) -> Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get all files with a non-zero fee pool (the storage market)
    #[method(name = "storage_getFundedFiles")]
    async fn storage_get_funded_files(
        &self,
    ) -> Result<Vec<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get a node's registry record (stake, role, status)
    #[method(name = "storage_getNodeRecord")]
    async fn storage_get_node_record(
        &self,
        node_address: String,
    ) -> Result<Option<serde_json::Value>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get an archive node's pending stake-unbonding record (issue #20).
    ///
    /// Returns `None` if the operator has no unbonding in progress (never
    /// started, or already withdrawn). See [`ArchiveUnbondingInfo`] for the
    /// wire shape; withdrawal via `WithdrawUnbonded` is permitted once chain
    /// height reaches `unlock_height`.
    #[method(name = "storage_getArchiveUnbonding")]
    async fn storage_get_archive_unbonding(
        &self,
        operator_address: String,
    ) -> Result<Option<ArchiveUnbondingInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get full V2 file metadata with a paginated access-list window.
    /// SNIP V2 Phase 1c (plan v3.2 §4, Ask 6).
    ///
    /// `access_offset` indexes into the file's `access_list`; `access_limit`
    /// caps the returned window (default 256, hard cap 1024). The total
    /// access-list size is returned in `access_total`. For Public files the
    /// `encrypted_key_bundle` field of every entry is JSON `null`; for Private
    /// files it's the `0x`-prefixed hex of the 80-byte bundle.
    ///
    /// Returns `None` if the file is not registered.
    #[method(name = "storage_getFileInfoV2")]
    async fn storage_get_file_info_v2(
        &self,
        merkle_root: String,
        access_offset: Option<u32>,
        access_limit: Option<u32>,
    ) -> Result<Option<StorageFileInfoV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// List V2 files in a "pushable" lifecycle (Pending or Active);
    /// Abandoned files are excluded. SNIP V2 Phase 1c (plan v3.2 §4, Ask 9).
    ///
    /// Used by archive nodes as a warm-cache source: when a push request
    /// arrives, the archive can decide locally whether the file is known
    /// without per-push RPC chatter. `Pending` means still ramping up;
    /// `Active` means a resync push (the activation race rule from Ask 14).
    ///
    /// Paginated (offset/limit) so a hosted endpoint can serve a registry
    /// of arbitrary size without unbounded response bodies. Files are
    /// returned in `merkle_root` lexicographic order — stable under
    /// concurrent appends, **eventually-consistent** under concurrent
    /// lifecycle transitions (a file moving Pending→Active stays in the
    /// list with its new lifecycle; one moving to Abandoned drops). Default
    /// `limit = 256`, hard cap `1024`. Callers paginate with
    /// `offset += returned.len()`.
    #[method(name = "storage_getPushableFilesV2")]
    async fn storage_get_pushable_files_v2(
        &self,
        offset: Option<u32>,
        limit: Option<u32>,
    ) -> Result<Vec<PushableFileInfoV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get coverage state for a Pending V2 file. SNIP V2 Phase 1b (plan v3.2 §4).
    ///
    /// Returns popcount summaries + a paginated window of missing chunk indices
    /// — never raw `Vec<u32>` per archive. Owners poll until `can_activate_now`
    /// is true; archives use `per_archive[i].assigned_count` to know what to push.
    ///
    /// `missing_offset` is a **chunk-index lower bound** (not an offset into the
    /// filtered missing list). Pagination is stable under concurrent
    /// `AcceptAssignmentV2` writes — the next call uses
    /// `missing_offset = last_returned_index + 1`.
    #[method(name = "storage_getAssignmentCoverageV2")]
    async fn storage_get_assignment_coverage_v2(
        &self,
        merkle_root: String,
        missing_offset: Option<u32>,
        missing_limit: Option<u32>,
    ) -> Result<Option<AssignmentCoverageV2>, jsonrpsee::types::ErrorObjectOwned>;

    /// Get the active-archive-node set as snapshotted at the largest stored
    /// height `≤ height`. SNIP V2 Ask 15 (Phase 0b checkpoint 2b).
    ///
    /// Lookup semantics (plan v3 §5.3):
    /// - For `height == 0` or `height` < first post-genesis change → returns
    ///   the genesis snapshot (empty array unless genesis pre-loaded archives,
    ///   which it doesn't today).
    /// - For `height` between two snapshot heights, returns the snapshot at
    ///   the earlier height — assignments captured then are stable per the
    ///   "no reassignment" rule.
    /// - For `height` > head height, returns the most recent snapshot
    ///   (no Err — saves a round-trip for clients querying near head).
    ///
    /// Each entry is a [`NodeRecordInfo`]: base58 `address`, role/status as
    /// strings, `staked_balance` as a native `u64`, `registered_at` as block
    /// height. Wire shape locked by JSON-shape tests in the server crate.
    #[method(name = "storage_getActiveNodesAtHeight")]
    async fn storage_get_active_nodes_at_height(
        &self,
        height: u64,
    ) -> Result<Vec<NodeRecordInfo>, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned owner-triggered `ReassignChunksV2` tx (issue #80).
    /// **No-key builder** — no signing, no execution, no owner/gate check beyond
    /// decoding `merkle_root`; the executor stays authoritative. Returns the
    /// hex-encoded unsigned `TransactionV2` + signing hash for the client to sign
    /// and broadcast via `sum_sendRawTransaction`. The output decodes to
    /// `TxPayload::StorageMetadataV2(StorageMetadataOperationV2::ReassignChunksV2)`.
    #[method(name = "storage_buildReassignChunksV2")]
    async fn storage_build_reassign_chunks_v2(
        &self,
        request: StorageBuildReassignChunksV2Request,
    ) -> Result<StorageBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    // =========================================================================
    // No-key unsigned-transaction builders (issue #89)
    //
    // One builder per family, taking a tagged operation request. Each assembles
    // an unsigned `TransactionV2` and returns hex bytes + signing hash. **No
    // private keys, no signing, no submit, no execution, no authorization** — the
    // client signs `signing_hash` locally and submits via `sum_sendRawTransaction`.
    // Authority checks stay in the executor.
    // =========================================================================

    /// Build an unsigned SRC-20 token tx for one operation (issue #89).
    /// No-key: no signing/execution/authorization. Decodes to `TxPayload::Token`.
    #[method(name = "token_buildTransaction")]
    async fn token_build_transaction(
        &self,
        request: crate::types::TokenBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned SUM-721 NFT tx for one operation (issue #89).
    /// No-key: no signing/execution/authorization. Decodes to `TxPayload::Nft`.
    #[method(name = "nft_buildTransaction")]
    async fn nft_build_transaction(
        &self,
        request: crate::types::NftBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned staking tx for one operation (issue #89).
    /// No-key: no signing/execution/authorization. Decodes to `TxPayload::Staking`.
    #[method(name = "staking_buildTransaction")]
    async fn staking_build_transaction(
        &self,
        request: crate::types::StakingBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;

    /// Build an unsigned node-registry tx for one operation (issue #89).
    /// No-key: no signing/execution/authorization. Decodes to
    /// `TxPayload::NodeRegistry` (or `NodeRegistryV2` for `RegisterEncryptionKey`).
    #[method(name = "nodeRegistry_buildTransaction")]
    async fn node_registry_build_transaction(
        &self,
        request: crate::types::NodeRegistryBuildRequest,
    ) -> Result<crate::types::TxBuildResponse, jsonrpsee::types::ErrorObjectOwned>;
}
