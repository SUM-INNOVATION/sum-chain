//! # SUM Chain Primitives
//!
//! Core types and data structures for the SUM Chain blockchain.
//! This crate provides fundamental building blocks used throughout the chain.

pub mod address;
pub mod agreement;
pub mod block;
pub mod docclass;
pub mod equity;
pub mod hash;
pub mod legal;
pub mod messaging;
pub mod receipt;
pub mod staking;
pub mod tax;
pub mod transaction;

pub use address::Address;
pub use block::{Block, BlockHeader};
pub use hash::Hash;
pub use receipt::{Receipt, TxStatus};
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
    MessageHeader, MessagingOperation, MessagingTxData, PendingPayment, QuotaInfo, ReportSpamData,
    SendMessageData, SendMessageWithPaymentData, SetDailyQuotaData, SetInboxFilterData,
    SetMaxMessageSizeData, SetMinTrustStakeData, SetSponsorshipEnabledData, SpamReport,
    SponsoredMessage, StakeForTrustData, UnstakeData as MessagingUnstakeData,
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

/// Common result type for primitives
pub type Result<T> = std::result::Result<T, PrimitiveError>;

/// Errors that can occur in primitive operations
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
