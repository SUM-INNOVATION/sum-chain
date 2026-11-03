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
//!
//! ## Cargo features
//!
//! `std` (default) is the whole crate. With `default-features = false` the crate
//! is `no_std` + `alloc` (sum-chain #312) and has only [`Address`],
//! [`AddressText`], [`Hash`](struct@Hash), the scalar aliases, [`Result`] and
//! [`PrimitiveError`], and from [`inference_attestation`] the digest, its
//! canonical bytes and signing input, `DOMAIN_TAG`, `MAX_SESSION_ID_BYTES`,
//! `AttestationError` and `verifier_address`. Without `std` there are no serde
//! derives, and the error types implement `Debug` only. Every other module needs
//! `std`. See the README's "Cargo features" section.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod address;
#[cfg(feature = "std")]
pub mod agreement;
#[cfg(feature = "std")]
pub mod b0;
#[cfg(feature = "std")]
pub mod beacon_schedule;
#[cfg(feature = "std")]
pub mod beacon_wire;
#[cfg(feature = "std")]
pub mod compute_pool_graph;
#[cfg(feature = "std")]
pub mod compute_pool_params;
#[cfg(feature = "std")]
pub mod compute_pool_wire;
#[cfg(feature = "std")]
pub mod docclass;
#[cfg(feature = "std")]
pub mod education;
#[cfg(feature = "std")]
pub mod employment;
#[cfg(feature = "std")]
pub mod equity;
#[cfg(feature = "std")]
pub mod finance;
#[cfg(feature = "std")]
pub mod governance;
pub mod hash;
#[cfg(feature = "std")]
pub mod healthcare;
pub mod inference_attestation;
#[cfg(feature = "std")]
pub mod inference_settlement;
#[cfg(feature = "std")]
pub mod legal;
#[cfg(feature = "std")]
pub mod messaging;
#[cfg(feature = "std")]
pub mod node_registry;
#[cfg(feature = "std")]
pub mod policy_account;
#[cfg(feature = "std")]
pub mod property;
#[cfg(feature = "std")]
pub mod proposer;
#[cfg(feature = "std")]
pub mod registry_ingress;
#[cfg(feature = "std")]
pub mod registry_wire;
#[cfg(feature = "std")]
pub mod staking;
#[cfg(feature = "std")]
pub mod supply;
#[cfg(feature = "std")]
pub mod storage_metadata;
#[cfg(feature = "std")]
pub mod tax;
#[cfg(feature = "std")]
pub mod token_ops;
#[cfg(feature = "std")]
pub mod transaction;
#[cfg(feature = "std")]
pub mod validator_authority;

pub use address::{Address, AddressText};
pub use hash::Hash;
#[cfg(feature = "std")]
pub use governance::GovernanceParams;
#[cfg(feature = "std")]
pub use validator_authority::ValidatorApproval;

// B0-PRE candidate-neutral wire types (also reachable under the `b0` namespace).
#[cfg(feature = "std")]
pub use b0::allowlist::{GuestProgramAllowlistV1, GuestProgramEntryV1};
#[cfg(feature = "std")]
pub use b0::derived_input::DerivedInputV1;
#[cfg(feature = "std")]
pub use b0::manifest::{InputManifestV1, OutputManifestV1};
#[cfg(feature = "std")]
pub use b0::object_commitment::ObjectCommitmentV1;
#[cfg(feature = "std")]
pub use b0::partial_proof::PartialComputeProofV1;
#[cfg(feature = "std")]
pub use b0::proof_envelope::{
    allowlist_membership, shared_binding_ok, MembershipError, ProductionProofEnvelopeV1,
};
#[cfg(feature = "std")]
pub use b0::statement::R0ComputationStatementV2;
#[cfg(feature = "std")]
pub use b0::verifier_material::VerifierMaterialManifestV1;

// BR1 beacon DKG + K-rotate W1b wire carriers (#125). Dormant / pre-ratification;
// deliberately NOT registered in `TxType`/`TxPayload` (see the module docs). The
// top-level 28/29 band + beacon-local `0xBE__` op namespace are reservations only.
#[cfg(feature = "std")]
pub use beacon_wire::{
    BeaconFinalizeV1, BeaconOperation, BeaconPartialV1, BeaconWireOp, DkgComplaintV1, DkgDealV1,
    RegisterBeaconKeyV1, BEACON_OP_NAMESPACE, C1_COMPUTE_POOL_TXTYPE_RESERVED, CT_LEN, G1_LEN,
    G2_LEN, POP_LEN, SCALAR_LEN, W1B_BEACON_DKG_TXTYPE, W1B_BEACON_SIGN_TXTYPE,
};
#[cfg(feature = "std")]
pub use staking::{
    AddStakeData, ClaimDelegationRewardsData, CreateValidatorData, DelegateData, DelegationInfo,
    DoubleSignEvidence, DowntimeEvidence, EvidenceType, SlashingRecord, StakingOperation,
    StakingParams, StakingTxData, SubmitEvidenceData, UnbondingDelegation, UndelegateData,
    UnstakeData, UpdateValidatorData, ValidatorInfo, ValidatorSet, ValidatorSetEntry,
    ValidatorSigningInfo, ValidatorStatus, WithdrawUnbondedData,
};
#[cfg(feature = "std")]
pub use messaging::{
    sponsored_register_v1_signing_preimage, validate_message_format, AttachmentType,
    BlockSenderData, ClaimPaymentData, ContactData, ContentType, ExternalProtocol, FundRegistryData,
    InboxFilter, MessageEvent, MessageFlags, MessageHeader, MessagingOperation, MessagingTxData,
    PendingPayment, QuotaInfo, RegisterPublicKeySponsoredV1Data, RegisteredPublicKey,
    RegisterPublicKeyData, ReportSpamData, SendMessageData, SendMessageWithPaymentData,
    SetDailyQuotaData, SetInboxFilterData, SetMaxMessageSizeData, SetMinTrustStakeData,
    SetSponsorshipEnabledData, SpamReport, SponsoredMessage, StakeForTrustData,
    UnstakeData as MessagingUnstakeData, UpdatePublicKeyData, DEFAULT_DAILY_QUOTA,
    DEFAULT_MAX_MESSAGE_SIZE, DEFAULT_MIN_TRUST_STAKE, SPONSORED_REGISTER_V1_PREIMAGE_LEN,
    SPONSORED_REGISTER_V1_TAG, SRC201_HEADER_SIZE, SRC201_KDF_CONTEXT, SRC201_MAGIC,
    SRC201_NONCE_SIZE, SRC201_TAG_SIZE, SRC201_VERSION,
};
#[cfg(feature = "std")]
pub use transaction::{
    BeaconTxData, NftOperation, NftTxData, SignedTransaction, TokenOperation, TokenTxData,
    Transaction, TransactionV2, TxInner, TxPayload, TxType,
};
#[cfg(feature = "std")]
pub use docclass::{
    AcademicCredential, CredentialAttribute, CredentialId, CredentialMetadata, DocClassEvent,
    DocClassIssuer, DocClassIssuerStatus, DocClassIssuerType, DocClassOperation, DocClassTxData,
    DocSubcode, EligibilityAttestation, EligibilityType, IdentityKey, IdentityRoot, IdentityStatus,
    IssuerKey, KeyPurpose, KeyType, RevocationReason, RevocationRecord, RevocationStatus,
    ServiceEndpoint, ZkProofInputs, generate_commitment, generate_credential_id, generate_nullifier,
    generate_subject_commitment,
};
#[cfg(feature = "std")]
pub use tax::{
    TaxClaimTypeEntry, TaxIssuerClass, TaxIssuer, TaxPolicy, TaxPolicyTemplate,
    TaxProofEnvelope, TaxDisclosureEnvelope, TaxEvent, TaxOperation, TaxTxData,
    TaxRiskLevel, TaxIssuerStatus, TaxVerificationResult, EncryptionAlgorithm,
    IssuerRequirements, QuorumRule, ClaimTypeStatus,
};
#[cfg(feature = "std")]
pub use equity::{
    EntityProfile, OrgType, GovernanceAction, GovernanceActionType, EquityToken, ShareClassType,
    EquityControllerConfig, ControllerModel, LockupInfo, CorporateAction, CorporateActionType,
    OwnershipSnapshot, OwnershipProofEnvelope, EquityEvent, EquityOperation, EquityTxData,
    VestingSchedule, TradingWindow, EntityStatus, TokenStatus, CorporateActionStatus,
    GovernanceActionStatus, OwnershipProofType, StockSplitParams, DividendDeclareParams,
};
#[cfg(feature = "std")]
pub use agreement::{
    AgreementCommitment, AgreementEvent, AgreementOperation, AgreementProofEnvelope,
    AgreementProofProfile, AgreementProofType, AgreementRole, AgreementStatus, AgreementTxData,
    AttachmentRef, AttestationIssuerClass, AttestationPacket, AttestationStatus, AttestationTarget,
    AttestationType, EncryptionAlgorithm as AgreementEncryptionAlgorithm, EncryptionMeta,
    ExecutorLink, ExecutorState, IpActionStatus, IpActionType, IpAssetType, IpRightsAction,
    PartyBinding, PartyRef, PartySignature, SignatureType,
};
#[cfg(feature = "std")]
pub use legal::{
    BenefitDetermination, BenefitStatus, BenefitType, CaseAnchor, CaseStatus, CaseType, CourtOrder,
    LegalEvent, LegalIssuerClass, LegalOperation, LegalProofEnvelope, LegalProofProfile,
    LegalProofType, LegalTxData, OrderStatus, OrderType, ProcessEvent, ProcessEventStatus,
    ProcessEventType,
};
#[cfg(feature = "std")]
pub use property::{
    AssetAnchor, AssetId, AssetStatus, AssetType, ClaimId, ClaimStatus, ClaimType, CoverageId,
    CoverageStatus, CoverageType, Encumbrance, EncumbranceId, EncumbranceStatus, EncumbranceType,
    InsuranceClaim, InsuranceCoverage, PriorityPosition, PropertyEvent, PropertyIssuerClass,
    PropertyOperation, PropertyProofEnvelope, PropertyProofProfile, PropertyProofType,
    PropertyTxData, TitleEvent, TitleEventId, TitleEventStatus, TitleEventType,
};
#[cfg(feature = "std")]
pub use healthcare::{
    ConsentEnvelope, ConsentId, ConsentStatus, ConsentType, CoverageTier, DisclosureScope,
    HealthcareEvent, HealthcareIssuerClass, HealthcareOperation, HealthcareProofEnvelope,
    HealthcareProofProfile, HealthcareProofType, HealthcareTxData, MembershipId, MembershipRecord,
    MembershipStatus, MembershipType, NetworkStatus, Prescription, PrescriptionId,
    PrescriptionStatus, PrescriptionType, ProviderId, ProviderProfile, ProviderStatus, ProviderType,
};
#[cfg(feature = "std")]
pub use employment::{
    EmploymentCredential, EmploymentEvent, EmploymentId, EmploymentIssuerClass,
    EmploymentIssuerProfile, EmploymentOperation, EmploymentProofEnvelope, EmploymentProofProfile,
    EmploymentProofType, EmploymentRiskLevel, EmploymentStatus, EmploymentTxData, EmploymentType,
    IncomeAttestation, IncomeAttestationId, IncomeBracket, IncomePeriod, IssuerStatus as EmploymentIssuerStatus,
};
#[cfg(feature = "std")]
pub use finance::{
    AccountStanding, AccountType, AddressProof, AddressProofId, AddressProofType, AmlRisk,
    BalanceBracket, BankStandingCredential, BankStandingId, FinanceEvent, FinanceIssuerClass,
    FinanceIssuerProfile, FinanceIssuerStatus, FinanceOperation, FinanceProofEnvelope,
    FinanceProofProfile, FinanceProofType, FinanceRiskLevel, FinanceTxData, KycAttestation,
    KycAttestationId, KycLevel, KycStatus,
};
#[cfg(feature = "std")]
pub use node_registry::{
    ArchiveUnbondingRecord, NodeRecord, NodeRegistryOperation, NodeRegistryOperationV2,
    NodeRegistryTxData, NodeRegistryV2TxData, NodeRole, NodeStatus,
};
#[cfg(feature = "std")]
pub use inference_settlement::{
    ClaimInferenceRewardRequest, FundInferenceSessionRequest, InferenceClaim, InferenceClaimStatus,
    InferenceDispute, InferenceDisputeStatus, InferenceSession, InferenceSessionStatus,
    InferenceSettlementOperation, InferenceSettlementTxData, InferenceVerifierRecord,
    InferenceVerifierStatus, OpenInferenceDisputeRequest, OpenInferenceSessionRequest,
    RefundInferenceSessionRequest, ResolveInferenceDisputeRequest,
};
#[cfg(feature = "std")]
pub use storage_metadata::{
    assigned_archives, assigned_archives_presorted, assignment_score,
    is_archive_assigned_to_chunk, AccessEntryV2,
    EncryptedKeyBundleV2, FileLifecycleV2, FileVisibilityV2, StorageChallenge, StorageMetadata,
    StorageMetadataOperation, StorageMetadataOperationV2, StorageMetadataTxData, StorageMetadataV2,
    StorageMetadataV2TxData, CHALLENGE_INTERVAL_BLOCKS, CHALLENGE_REWARD, CHALLENGE_TTL_BLOCKS,
    CHUNK_SIZE, SLASH_PERCENTAGE, SNIP_V2_ASSIGNMENT_CONTEXT,
};
#[cfg(feature = "std")]
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
pub type Result<T> = core::result::Result<T, PrimitiveError>;

/// Errors that can occur in wire encoding/decoding operations
///
/// With `std` it implements `Display` and `std::error::Error` (through
/// `thiserror`); without `std` it implements `Debug` only.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum PrimitiveError {
    #[cfg_attr(feature = "std", error("Invalid hex string: {0}"))]
    InvalidHex(alloc::string::String),

    #[cfg_attr(feature = "std", error("Invalid length: expected {expected}, got {got}"))]
    InvalidLength { expected: usize, got: usize },

    #[cfg_attr(feature = "std", error("Invalid base58 encoding: {0}"))]
    InvalidBase58(alloc::string::String),

    #[cfg_attr(feature = "std", error("Serialization error: {0}"))]
    SerializationError(alloc::string::String),

    #[cfg_attr(feature = "std", error("Invalid address checksum"))]
    InvalidChecksum,
}
