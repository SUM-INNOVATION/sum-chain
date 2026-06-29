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
pub mod healthcare_store;
pub mod legal_store;
pub mod messaging_store;
pub mod policy_account_store;
pub mod property_store;
pub mod pruner;
pub mod schema;
pub mod tax_store;

pub use db::{cf, BackupInfo, Database, DatabaseConfig};
pub use docclass_store::{
    CredentialStore, DocClassEventStore, DocClassIssuerStore, DocClassStore, EligibilityStore,
    IdentityRootStore, RevocationStore,
};
pub use equity_store::{
    CorporateActionStore, EntityProfileStore, EquityBalanceStore, EquityControllerStore,
    EquityEventStore, EquityStore, EquityTokenStore, GovernanceActionStore, OwnershipProofStore,
    OwnershipSnapshotStore,
};
pub use messaging_store::{BackfillStats, MessagingStore, MESSAGING_LIST_DEFAULT, MESSAGING_LIST_MAX};
pub use pruner::{DbStats, PruneStats, Pruner, PrunerConfig};
pub use schema::{
    BlockStore, DelegationStore, IssuerData, IssuerStore, NftCollectionData, NftStore,
    NftTokenData, ReceiptStore, SlashingStore, Src20TokenData, StakingStore, StateStore,
    TokenStore, TxIndexEntry, TxIndexStore, TxStore, ValidatorSetStore,
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
    EmploymentCredentialStore, EmploymentEventStore, EmploymentIssuerStore, EmploymentProofStore,
    EmploymentStore, IncomeAttestationStore,
};
pub use finance_store::{
    AddressProofStore, BankStandingStore, FinanceEventStore, FinanceIssuerStore, FinanceProofStore,
    FinanceStore, KycAttestationStore,
};
pub use policy_account_store::{PolicyAccountStorage, PolicyAccountStore, ProposalStore};

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
}

pub type Result<T> = std::result::Result<T, StorageError>;
