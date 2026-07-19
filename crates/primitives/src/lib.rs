//! # SUM Chain Primitives
//!
//! Core types and data structures for the SUM Chain blockchain.
//! This crate provides fundamental building blocks used throughout the chain.

// Types that stay ABOVE the wire leaf — blocks, receipts, and the
// inference-attestation Ed25519 verification / receipt-bound status
// classification layer (which bind `SignedTransaction`/`Receipt`).
pub mod block;
pub mod inference_attestation;
pub mod receipt;

// The on-chain wire formats now live in the `sumchain-wire` leaf crate
// (sum-chain #124 / W1a). Re-export each moved module here so every existing
// `sumchain_primitives::<module>::…` path resolves unchanged; the crate-root
// type re-exports below flow through these.
pub use sumchain_wire::{
    address, agreement, docclass, education, employment, equity, finance, governance, hash,
    healthcare, inference_settlement, legal, messaging, node_registry, policy_account, property,
    staking, storage_metadata, supply, tax, token_ops, transaction, validator_authority,
};

pub use address::Address;
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub use receipt::{Receipt, TxStatus};
pub use governance::GovernanceParams;
pub use validator_authority::ValidatorApproval;
pub use staking::{
    AddStakeData, ClaimDelegationRewardsData, CreateValidatorData, DelegateData, DelegationInfo,
    DoubleSignEvidence, DowntimeEvidence, EvidenceType, SlashingRecord, StakingOperation,
    StakingParams, StakingTxData, SubmitEvidenceData, UnbondingDelegation, UndelegateData,
    UnstakeData, UpdateValidatorData, ValidatorInfo, ValidatorSet, ValidatorSetEntry,
    ValidatorSigningInfo, ValidatorStatus, WithdrawUnbondedData,
};
pub use messaging::{
    validate_message_format, AttachmentType, BlockSenderData, ClaimPaymentData, ContactData,
    ContentType, ExternalProtocol, FundRegistryData, InboxFilter, MessageEvent, MessageFlags,
    MessageHeader, MessagingOperation, MessagingTxData, PendingPayment, QuotaInfo,
    RegisteredPublicKey, RegisterPublicKeyData, ReportSpamData, SendMessageData,
    SendMessageWithPaymentData, SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData,
    SetMinTrustStakeData, SetSponsorshipEnabledData, SpamReport, SponsoredMessage,
    StakeForTrustData, UnstakeData as MessagingUnstakeData, UpdatePublicKeyData,
    DEFAULT_DAILY_QUOTA, DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE,
    SRC201_HEADER_SIZE, SRC201_KDF_CONTEXT, SRC201_MAGIC, SRC201_NONCE_SIZE, SRC201_TAG_SIZE,
    SRC201_VERSION,
};
pub use transaction::{
    NftOperation, NftTxData, SignedTransaction, TokenOperation, TokenTxData, Transaction,
    TransactionV2, TxInner, TxPayload, TxType,
};
pub use docclass::{
    AcademicCredential, CredentialAttribute, CredentialId, CredentialMetadata, DocClassEvent,
    DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData,
    DocSubcode, EligibilityAttestation, EligibilityType, IdentityKey, IdentityRoot, IdentityStatus,
    IssuerKey, KeyPurpose, KeyType, RevocationReason, RevocationRecord, RevocationStatus,
    ServiceEndpoint, ZkProofInputs, generate_commitment, generate_credential_id, generate_nullifier,
    generate_subject_commitment,
};
pub use tax::{
    TaxClaimTypeEntry, TaxIssuerClass, TaxIssuer, TaxPolicy, TaxPolicyTemplate,
    TaxProofEnvelope, TaxDisclosureEnvelope, TaxEvent, TaxOperation, TaxTxData,
    TaxRiskLevel, TaxIssuerStatus, TaxVerificationResult, EncryptionAlgorithm,
    IssuerRequirements, QuorumRule, ClaimTypeStatus,
};
pub use equity::{
    EntityProfile, OrgType, GovernanceAction, GovernanceActionType, EquityToken, ShareClassType,
    EquityControllerConfig, ControllerModel, LockupInfo, CorporateAction, CorporateActionType,
    OwnershipSnapshot, OwnershipProofEnvelope, EquityEvent, EquityOperation, EquityTxData,
    VestingSchedule, TradingWindow, EntityStatus, TokenStatus, CorporateActionStatus,
    GovernanceActionStatus, OwnershipProofType, StockSplitParams, DividendDeclareParams,
};
pub use agreement::{
    AgreementCommitment, AgreementEvent, AgreementOperation, AgreementProofEnvelope,
    AgreementProofProfile, AgreementProofType, AgreementRole, AgreementStatus, AgreementTxData,
    AttachmentRef, AttestationIssuerClass, AttestationPacket, AttestationStatus, AttestationTarget,
    AttestationType, EncryptionAlgorithm as AgreementEncryptionAlgorithm, EncryptionMeta,
    ExecutorLink, ExecutorState, IpActionStatus, IpActionType, IpAssetType, IpRightsAction,
    PartyBinding, PartyRef, PartySignature, SignatureType,
};
pub use legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType, CourtOrder,
    LegalEvent, LegalIssuerClass, LegalOperation, LegalProofEnvelope, LegalProofProfile,
    LegalProofType, LegalTxData, OrderStatus, OrderType, ProcessEvent, ProcessEventStatus,
    ProcessEventType,
};
pub use property::{
    AssetAnchor, AssetId, AssetStatus, AssetType, ClaimId, ClaimStatus, ClaimType, CoverageId,
    CoverageStatus, CoverageType, Encumbrance, EncumbranceId, EncumbranceStatus, EncumbranceType,
    InsuranceClaim, InsuranceCoverage, PriorityPosition, PropertyEvent, PropertyIssuerClass,
    PropertyOperation, PropertyProofEnvelope, PropertyProofProfile, PropertyProofType,
    PropertyTxData, TitleEvent, TitleEventId, TitleEventStatus, TitleEventType,
};
pub use healthcare::{
    ConsentEnvelope, ConsentId, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareEvent, HealthcareIssuerClass, HealthcareOperation, HealthcareProofEnvelope,
    HealthcareProofProfile, HealthcareProofType, HealthcareTxData, MembershipId, MembershipRecord,
    MembershipStatus, MembershipType, NetworkStatus, Prescription, PrescriptionId,
    PrescriptionStatus, PrescriptionType, ProviderId, ProviderProfile, ProviderStatus, ProviderType,
};
pub use employment::{
    EmploymentCredential, EmploymentEvent, EmploymentId, EmploymentIssuerClass,
    EmploymentIssuerProfile, EmploymentOperation, EmploymentProofEnvelope, EmploymentProofProfile,
    EmploymentProofType, EmploymentRiskLevel, EmploymentStatus, EmploymentTxData, EmploymentType,
    IncomeAttestation, IncomeAttestationId, IncomeBracket, IncomePeriod, IssuerStatus as EmploymentIssuerStatus,
};
pub use finance::{
    AccountStanding, AccountType, AddressProof, AddressProofId, AddressProofType, AmlRisk,
    BalanceBracket, BankStandingCredential, BankStandingId, FinanceEvent, FinanceIssuerClass,
    FinanceIssuerProfile, FinanceIssuerStatus, FinanceOperation, FinanceProofEnvelope,
    FinanceProofProfile, FinanceProofType, FinanceRiskLevel, FinanceTxData, KycAttestation,
    KycAttestationId, KycLevel, KycStatus,
};
pub use node_registry::{
    ArchiveUnbondingRecord, NodeRecord, NodeRegistryOperation, NodeRegistryOperationV2,
    NodeRegistryTxData, NodeRegistryV2TxData, NodeRole, NodeStatus,
};
pub use inference_settlement::{
    ClaimInferenceRewardRequest, FundInferenceSessionRequest, InferenceClaim, InferenceClaimStatus,
    InferenceDispute, InferenceDisputeStatus, InferenceSession, InferenceSessionStatus,
    InferenceSettlementOperation, InferenceSettlementTxData, InferenceVerifierRecord,
    InferenceVerifierStatus, OpenInferenceDisputeRequest, OpenInferenceSessionRequest,
    RefundInferenceSessionRequest, ResolveInferenceDisputeRequest,
};
pub use storage_metadata::{
    assigned_archives, assigned_archives_presorted, assignment_score,
    is_archive_assigned_to_chunk, AccessEntryV2,
    EncryptedKeyBundleV2, FileLifecycleV2, FileVisibilityV2, StorageChallenge, StorageMetadata,
    StorageMetadataOperation, StorageMetadataOperationV2, StorageMetadataTxData, StorageMetadataV2,
    StorageMetadataV2TxData, CHALLENGE_INTERVAL_BLOCKS, CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS,
    CHUNK_SIZE, SLASH_PERCENTAGE, SNIP_V2_ASSIGNMENT_CONTEXT,
};
pub use policy_account::{
    ActionClass, ApprovalThreshold, MemberApproval, PolicyAccount, PolicyAccountId,
    PolicyAccountOperation, PolicyAccountStatus, PolicyAccountTxData, PolicyConfig, PolicyMember,
    PolicyNonce, PolicyProfile, PolicyRule, Proposal, ProposalId, ProposalStatus,
    MAX_APPROVALS, MAX_CUSTOM_RULES, MAX_MEMBERS, MAX_PROPOSAL_PAYLOAD_SIZE,
};

// Shared scalar type aliases and the wire error type were moved into the
// `sumchain-wire` leaf; keep re-exporting them from the crate root so
// `sumchain_primitives::{ChainId, BlockHeight, Nonce, Balance, Timestamp,
// Result, PrimitiveError}` paths are unchanged.
pub use sumchain_wire::{
    Balance, BlockHeight, ChainId, Nonce, PrimitiveError, Result, Timestamp,
};
