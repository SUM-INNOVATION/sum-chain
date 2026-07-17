//! # SUM Chain Wire (W1a leaf)
//!
//! Byte-frozen on-chain wire formats for SUM Chain, extracted verbatim from
//! `sumchain-primitives` (sum-chain #124 / W1a). This crate is the single home
//! of the encoding/decoding surface: addresses, hashes, transactions, and every
//! subprotocol payload, all serialized with **bincode 1.3 default config**
//! (u32-LE enum variant tags). Signing hashes are `blake3(bincode(tx))`.
//!
//! This is a **leaf**: it depends on no signature-verification, state, RPC,
//! consensus, storage, or networking crate, and NOT on `sumchain-primitives`.
//! Semantic verification (Ed25519 attestation checks, receipt-bound status
//! classification, blocks) stays ABOVE the leaf in `sumchain-primitives`.
//!
//! The wire shapes here are contract-frozen: any change to enum variant order,
//! struct field order/width, or bincode config is a wire break. See the golden
//! fixtures in `crates/primitives/tests/` (they exercise these types through the
//! `sumchain-primitives` re-exports and must stay byte-identical).
//!
//! ## B0-PRE candidate-neutral wire types ([`b0`])
//!
//! The [`b0`] module adds the frozen B0-PRE candidate-neutral wire family,
//! reproduced byte-for-byte from the out-of-workspace `b0-pre-validator` reference
//! (copied, never linked): [`b0::object_commitment::ObjectCommitmentV1`] (80 B),
//! the input/output manifests, [`b0::derived_input::DerivedInputV1`] (350 B),
//! [`b0::statement::R0ComputationStatementV2`] (996 B), the guest-program
//! allowlist, and the verifier-material manifest — plus two **new** production
//! proof types, [`b0::partial_proof::PartialComputeProofV1`] (137 B) and
//! [`b0::proof_envelope::ProductionProofEnvelopeV1`] (235 B). These are strictly
//! additive: they introduce no transaction ordinal and change no existing 0.1.1
//! bytes.

#![forbid(unsafe_code)]

pub mod address;
pub mod agreement;
pub mod b0;
pub mod docclass;
pub mod education;
pub mod employment;
pub mod equity;
pub mod finance;
pub mod governance;
pub mod hash;
pub mod healthcare;
pub mod inference_attestation;
pub mod inference_settlement;
pub mod legal;
pub mod messaging;
pub mod node_registry;
pub mod policy_account;
pub mod property;
pub mod staking;
pub mod supply;
pub mod storage_metadata;
pub mod tax;
pub mod token_ops;
pub mod transaction;
pub mod validator_authority;

pub use address::Address;
pub use hash::Hash;
pub use governance::GovernanceParams;
pub use validator_authority::ValidatorApproval;

// B0-PRE candidate-neutral wire types (also reachable under the `b0` namespace).
pub use b0::allowlist::{GuestProgramAllowlistV1, GuestProgramEntryV1};
pub use b0::derived_input::DerivedInputV1;
pub use b0::manifest::{InputManifestV1, OutputManifestV1};
pub use b0::object_commitment::ObjectCommitmentV1;
pub use b0::partial_proof::PartialComputeProofV1;
pub use b0::proof_envelope::{
    allowlist_membership, shared_binding_ok, MembershipError, ProductionProofEnvelopeV1,
};
pub use b0::statement::R0ComputationStatementV2;
pub use b0::verifier_material::VerifierMaterialManifestV1;
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
    assigned_archives, assigned_archives_presorted, is_archive_assigned_to_chunk, AccessEntryV2,
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

/// Chain ID type - identifies the network
pub type ChainId = u64;

/// Block height type
pub type BlockHeight = u64;

/// Nonce type for transactions
pub type Nonce = u64;

/// Balance/amount type - u128 supports large values
pub type Balance = u128;

/// Timestamp in milliseconds since Unix epoch
pub type Timestamp = u64;

/// Common result type for wire operations
pub type Result<T> = std::result::Result<T, PrimitiveError>;

/// Errors that can occur in wire encoding/decoding operations
#[derive(Debug, thiserror::Error)]
pub enum PrimitiveError {
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    #[error("Invalid length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },

    #[error("Invalid base58 encoding: {0}")]
    InvalidBase58(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid address checksum")]
    InvalidChecksum,
}
