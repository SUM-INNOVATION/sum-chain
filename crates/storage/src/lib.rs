//! # SUM Chain Storage
//!
//! Persistent key-value storage for SUM Chain using RocksDB.
//! Provides schemas for blocks, state, transactions, and receipts.

pub mod agreement_store;
pub mod db;
pub mod docclass_store;
pub mod employment_store;
pub mod equity_store;
pub mod finance_store;
pub mod governance_store;
pub mod healthcare_store;
pub mod journal;
pub mod legal_store;
pub mod messaging_store;
pub mod nft_store;
pub mod candidate;
pub mod exec_view;
pub mod overlay;
pub mod page;
pub mod policy_account_store;
pub mod property_store;
pub mod pruner;
pub mod schema;
pub mod tax_store;

pub use db::{cf, BackupInfo, Database, DatabaseConfig};
pub use page::{
    paged_resolve, paged_scan, PageSpec, PAGE_DEFAULT, PAGE_MAX, PAGE_OFFSET_MAX,
};
pub use docclass_store::{
    CredentialStore, DocClassEventStore, DocClassIssuerStore, DocClassStore, EligibilityStore,
    IdentityRootStore, RevocationStore,
};
pub use equity_store::{
    equity_balances_root, equity_balances_root_and_proof, equity_merkle_leaf, equity_merkle_verify,
    CorporateActionStore, EntityProfileStore, EquityBalanceStore, EquityControllerStore,
    EquityEventStore, EquityStore, EquityTokenStore, GovernanceActionStore, OwnershipProofStore,
    OwnershipSnapshotStore,
};
pub use journal::{
    ActivationSource, AfterImage, ApplicationJournal, JournalActivation, JournalEntry,
    JournalRequirement, Preimage,
};
pub use messaging_store::{BackfillStats, MessagingStore, MESSAGING_LIST_DEFAULT, MESSAGING_LIST_MAX};
pub use pruner::{DbStats, PruneStats, Pruner, PrunerConfig};
pub use schema::{
    contract_cf_kind, BlockStore, ContractMutation, ContractStateDiff,
    CONTRACT_STATE_DIFF_DOMAIN, DelegationStore, IssuerData, IssuerStore, NftCollectionData,
    NftStore, NftTokenData, ReceiptStore, SlashingStore, Src20TokenData, StakingStore, StateStore,
    StateDiff, TokenStore, TxIndexEntry, TxIndexStore, TxStore, ValidatorSetStore,
};
pub use tax_store::{
    TaxClaimTypeStore, TaxDisclosureStore, TaxEventStore, TaxIssuerStore, TaxPolicyStore,
    TaxProofStore, TaxStore,
};
pub use agreement_store::{
    AgreementCommitmentStore, AgreementEventStore, AgreementProofStore, AgreementStore,
    AttestationStore, ExecutorLinkStore, IpActionStore, SignatureStore,
};
pub use legal_store::{
    BenefitStore, CaseStore, LegalEventStore, LegalProofStore, LegalStore, OrderStore,
    ProcessEventStore,
};
pub use property_store::{
    AssetStore, ClaimStore, CoverageStore, EncumbranceStore, PropertyEventStore,
    PropertyProofStore, PropertyStore, TitleEventStore,
};
pub use healthcare_store::{
    ConsentStore, HealthcareEventStore, HealthcareProofStore, HealthcareStore, MembershipStore,
    PrescriptionStore, ProviderStore,
};
pub use employment_store::{
    EmploymentCredentialStore, EmploymentEmployeeSummary, EmploymentEventStore,
    EmploymentIssuerStore, EmploymentProofStore, EmploymentStore, IncomeAttestationStore,
};
pub use finance_store::{
    AddressProofStore, BankStandingStore, FinanceEventStore, FinanceIssuerStore, FinanceProofStore,
    FinanceStore, KycAttestationStore,
};
pub use policy_account_store::{PolicyAccountStorage, PolicyAccountStore, ProposalStore};
pub use governance_store::{EquityClassRoot, GovStore, QualifyingAsset};

use thiserror::Error;

/// Storage errors
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("RocksDB error: {0}")]
    RocksDb(#[from] rocksdb::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Database not initialized")]
    NotInitialized,

    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// One transaction's own logical write set crossed the per-transaction
    /// bound its overlay scope was opened with.
    ///
    /// A distinct variant rather than an `InvalidData` string because the
    /// caller has to TELL THE TWO CEILINGS APART and act differently on each.
    /// Crossing the BLOCK ceiling means this block cannot be evaluated at all;
    /// crossing the per-transaction bound means this TRANSACTION cannot, and
    /// the block survives it as a failed receipt. Distinguishing them by
    /// matching on the message text would make the refusal semantics depend on
    /// a format string, which is the sort of coupling that survives review and
    /// then breaks silently when somebody rewords an error.
    #[error(
        "transaction exceeded its {limit} logical byte write-set bound \
         (would reach {would_reach}); one transaction's charge is bounded \
         independently of the block's"
    )]
    TransactionWriteSetExceeded { limit: u64, would_reach: u64 },

    /// The BLOCK's logical write set crossed the candidate ceiling.
    ///
    /// The message is word-for-word the `InvalidData` string this used to be
    /// formatted into, because `crates/state/tests/block_write_set_ceiling.rs`
    /// asserts on that text as the proof that a refusal came from the ceiling
    /// and not from something else that happens to fail at this size. What the
    /// variant adds is a TYPE, so the block executor can recognise this refusal
    /// without reading a format string — it needs to, because it has to tell
    /// the proposer WHICH transaction crossed it.
    #[error(
        "overlay exceeded its {limit} logical byte limit (would reach {would_reach}); \
         the candidate branch is too large to evaluate in memory"
    )]
    OverlayLimitExceeded { limit: u64, would_reach: u64 },
}

pub type Result<T> = std::result::Result<T, StorageError>;
