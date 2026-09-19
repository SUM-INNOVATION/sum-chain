//! # SUM Chain State
//!
//! State management and transaction execution for SUM Chain.
//! Handles account balances, nonces, and transaction application.

pub mod account_root;
pub mod agreement_executor;
pub mod agreement_view;
pub mod beacon_executor;
pub mod beacon_manager;
pub mod beacon_store;
pub mod cache;
pub mod compute_pool;
pub mod compute_pool_manager;
pub mod compute_pool_store;
pub mod contract_executor;
pub mod docclass_executor;
pub mod docclass_view;
pub mod education_executor;
pub mod employment_executor;
pub mod employment_view;
pub mod equity_executor;
pub mod equity_view;
pub mod executor;
pub mod supply;
pub mod finance_executor;
pub mod finance_view;
pub mod governance_executor;
pub mod governance_view;
pub mod healthcare_executor;
pub mod healthcare_view;
pub mod inference_attestation_executor;
pub mod inference_settlement_executor;
pub mod legal_executor;
pub mod legal_view;
pub mod mempool;
pub mod messaging_executor;
pub mod messaging_view;
pub mod nft_executor;
pub mod nft_view;
pub mod node_registry;
pub mod policy_account_executor;
pub mod policy_account_view;
pub mod property_executor;
pub mod property_view;
pub mod protocol_digest;
pub mod reorg_undo;
pub mod schema_validator;
pub mod snapshot;
pub mod staking_executor;
pub mod staking_view;
pub mod state;
pub mod storage_metadata;
pub mod tax_executor;
pub mod tax_view;
pub mod token_executor;
pub mod token_view;
pub mod validator_quorum;

/// The activation height for the executor-written block timestamp.
///
/// **This is a seam for a `ChainParams` field that does not exist yet.**
/// `crates/genesis/**` belongs to another track, so the field cannot be added
/// from here. The field this function must read, once that track adds it, is:
///
/// ```text
/// /// Executor-written block timestamps. Dormant by default (`None` -> never
/// /// open). Below the gate every dispatch arm for DocClass, Tax, Agreement,
/// /// Legal, Property, Healthcare, Employment and Finance passes a literal `0`
/// /// where the block timestamp belongs, so every `created_at`, `updated_at`
/// /// and `revoked_at` those subsystems write is zero -- and Healthcare's
/// /// `Prescription::is_valid` is therefore evaluated at time zero, so an
/// /// expired prescription is fillable forever and one with a non-zero
/// /// `effective_from` can never be filled at all. At and above the gate each
/// /// arm passes `block.header.timestamp`. Activation is a consensus change --
/// /// it changes the bytes of every row those subsystems write -- and needs a
/// /// coordinated validator upgrade.
/// #[serde(default)]
/// pub subsystem_block_timestamp_enabled_from_height: Option<u64>,
/// ```
///
/// One field for eight subsystems, because it is one rule: the timestamp the
/// executor writes is the block's. Splitting it per subsystem would let a chain
/// hold half its rows at zero and half at a real time, which is worse than
/// either end.
///
/// Until it exists this returns `None`, which is exactly what an absent
/// `#[serde(default)] Option<u64>` resolves to, so production behaviour is
/// unchanged and every `..._is_always_zero` pinning test still passes.
#[inline]
fn subsystem_block_timestamp_activation(params: &sumchain_genesis::ChainParams) -> Option<u64> {
    params.subsystem_block_timestamp_enabled_from_height
}

/// Whether executor-written block timestamps are real at `block_height`.
#[inline]
pub fn subsystem_block_timestamp_gate_open(
    params: &sumchain_genesis::ChainParams,
    block_height: u64,
) -> bool {
    matches!(subsystem_block_timestamp_activation(params), Some(h) if block_height >= h)
}

/// The timestamp a subsystem executor writes, given the gate.
///
/// Below the gate it is the literal `0` the dispatch arms used to pass; at and
/// above it, the block's own timestamp. Written once, here, so that the eight
/// subsystems cannot drift apart on the question.
#[inline]
pub fn effective_block_timestamp(block_timestamp: u64, gate_open: bool) -> u64 {
    if gate_open {
        block_timestamp
    } else {
        0
    }
}

/// The activation height for the executor-written transaction index.
///
/// Reads `params.subsystem_tx_index_enabled_from_height`.
///
/// Its own field, NOT `subsystem_block_timestamp_enabled_from_height`. Both
/// defects are a literal `0` handed to the same executors by the same dispatch,
/// which is the whole reason to check: they are not one rule. The timestamp gate
/// changes what a row SAYS, in eight subsystems, and moves every time-dependent
/// validity rule with it — a prescription that was fillable forever stops being
/// so. This gate changes what KEY a row lands at, in the two families keyed by
/// the transaction index, and therefore how many rows a block writes at all.
/// Opening it grows the candidate write set, which has a ceiling that refuses a
/// block rather than truncating it, so this is consensus-visible even though
/// nothing reads these rows back. Two different blast radii; an operator must be
/// able to take one without the other.
#[inline]
fn subsystem_tx_index_activation(params: &sumchain_genesis::ChainParams) -> Option<u64> {
    params.subsystem_tx_index_enabled_from_height
}

/// Whether subsystem event rows are keyed by their real transaction index at
/// `block_height`.
#[inline]
pub fn subsystem_tx_index_gate_open(
    params: &sumchain_genesis::ChainParams,
    block_height: u64,
) -> bool {
    matches!(subsystem_tx_index_activation(params), Some(h) if block_height >= h)
}

/// The transaction index a subsystem executor keys its event rows by.
///
/// Below the gate it is the literal `0` both dispatch arms used to pass, so
/// every event in a block collides at one key and the family keeps the last one
/// — reproduced exactly, because a dormant gate must be indistinguishable from
/// the unremediated binary. At and above it, the transaction's own index within
/// its block. Written once, here, so the two dispatch arms cannot drift apart on
/// the question the way they already did on the timestamp.
#[inline]
pub fn effective_tx_index(tx_index: u32, gate_open: bool) -> u32 {
    if gate_open {
        tx_index
    } else {
        0
    }
}

/// The activation height for bounding a transaction's sizing inputs before the
/// value they size is built.
///
/// Reads `params.subsystem_allocation_bound_enabled_from_height`.
///
/// ACTIVATION-AUDIT rows AL-9, AL-10 and AL-11. Below the gate an accumulating
/// structure is read, decoded in full, appended to and re-encoded in full
/// before `view.put` charges a byte against the candidate ceiling, and the
/// payload driving it is decoded with no length check ahead of it. The ceiling
/// therefore bounds what a block may COMMIT and bounds nothing about what one
/// refused transaction may ALLOCATE — which matters because the release ceiling
/// is `CANDIDATE_LIMIT_SCAFFOLD`, `1 << 30`, and not the 4,096 or 8,192 bytes
/// the `*_index_allocation` files measured against.
/// `crates/state/tests/release_ceiling_allocation.rs` measures the release
/// configuration instead.
///
/// ONE field for DocClass and NFT because it is one rule at one seam: bound the
/// input before building the value. A partial activation leaves the cheapest
/// vector open — an attacker refused by the DocClass bound moves to the NFT one
/// — so there is no configuration in which an operator wants one and not the
/// other. This is the `subsystem_block_timestamp_enabled_from_height` argument,
/// not the `subsystem_tx_index_enabled_from_height` one: the blast radius is
/// identical on both sides (a previously-admitted oversized transaction becomes
/// a failed one), so there is nothing to sequence.
#[inline]
fn subsystem_allocation_bound_activation(params: &sumchain_genesis::ChainParams) -> Option<u64> {
    params.subsystem_allocation_bound_enabled_from_height
}

/// Whether a transaction's sizing inputs are bounded at `block_height`.
#[inline]
pub fn subsystem_allocation_bound_gate_open(
    params: &sumchain_genesis::ChainParams,
    block_height: u64,
) -> bool {
    matches!(subsystem_allocation_bound_activation(params), Some(h) if block_height >= h)
}

/// The activation height for the no-op receipt rule.
///
/// Reads `params.subsystem_no_op_receipt_enabled_from_height`, and nothing
/// else. `None` -- the default, and what a genesis written before the field
/// existed resolves to -- closes the gate, so a node executes exactly what it
/// executed before the field was declared.
///
/// ACTIVATION-AUDIT rows OV-6, OV-25 and OV-30. Below the gate three arms in
/// three subsystems charge the fee, advance the nonce and return a SUCCESS
/// receipt having changed no row the operation names: Legal `ConsolidateCase`
/// repeated on a pair already consolidated, DocClass `UpdateCredential` (which
/// writes nothing at all, on any input), and Agreement `AddParty` /
/// `RemoveParty` (whose body is the fee and `success()`). At and above the gate
/// each returns a failed receipt.
///
/// **This is a failed receipt, not an implementation.** It does not make
/// `AddParty` add a party or `UpdateCredential` update a credential: those need
/// an operation semantics the subsystems do not define. What it removes is the
/// receipt that claims an absent effect happened.
///
/// ONE field for three subsystems, on the
/// `subsystem_block_timestamp_enabled_from_height` argument: one rule about
/// what a receipt means, the same blast radius on all three sides, and nothing
/// to sequence.
#[inline]
fn subsystem_no_op_receipt_activation(params: &sumchain_genesis::ChainParams) -> Option<u64> {
    params.subsystem_no_op_receipt_enabled_from_height
}

/// Whether the no-op receipt rule is active at `block_height`.
#[inline]
pub fn subsystem_no_op_receipt_gate_open(
    params: &sumchain_genesis::ChainParams,
    block_height: u64,
) -> bool {
    matches!(subsystem_no_op_receipt_activation(params), Some(h) if block_height >= h)
}

/// The activation height for the `VerifyProof` presence check.
///
/// Reads `params.subsystem_proof_presence_enabled_from_height`, and nothing
/// else. `None` -- the default, and what a genesis written before the field
/// existed resolves to -- closes the gate, so a node executes exactly what it
/// executed before the field was declared.
///
/// ACTIVATION-AUDIT rows AU-6, AU-12, AU-17, AU-20, AU-26 and AU-29 (= PR-1 to
/// PR-6). Below the gate all six `VerifyProof` arms are the same three
/// statements -- deduct, credit, increment -- followed by `success()`, with the
/// payload never read, so the operation reports a verified proof for a proof id
/// the chain has never seen and for a payload that is not an id at all. At and
/// above the gate the payload must be exactly [`PROOF_ID_BYTES`] bytes and name
/// a proof present in that subsystem's proof family, or the arm returns a
/// failed receipt before the deduct -- which is where the sibling `SubmitProof`
/// arm's "Proof already exists" refusal returns too, so the fee treatment of a
/// refused proof operation stays uniform within each subsystem.
///
/// **Presence is not verification, and this gate does not claim otherwise.** It
/// removes the false positives; the rows stay open on the half that needs a
/// request payload type and an actual verifier.
///
/// ONE field for six subsystems, on the
/// `subsystem_block_timestamp_enabled_from_height` argument rather than the
/// per-subsystem authorization one: the six bodies are character-for-character
/// identical, the rule is one sentence, and the blast radius is the same on
/// both sides (a success receipt becomes a failed one). There is no
/// configuration in which an operator wants `VerifyProof` to mean one thing in
/// Legal and another in Finance.
#[inline]
fn subsystem_proof_presence_activation(params: &sumchain_genesis::ChainParams) -> Option<u64> {
    params.subsystem_proof_presence_enabled_from_height
}

/// Whether the `VerifyProof` presence check is active at `block_height`.
#[inline]
pub fn subsystem_proof_presence_gate_open(
    params: &sumchain_genesis::ChainParams,
    block_height: u64,
) -> bool {
    matches!(subsystem_proof_presence_activation(params), Some(h) if block_height >= h)
}

/// The width of a subsystem proof id, in bytes.
///
/// Read only where [`subsystem_proof_presence_gate_open`] said yes. Every
/// subsystem's `ProofId` is `[u8; 32]`, and a `VerifyProof` payload that is not
/// exactly this long cannot name one.
pub const PROOF_ID_BYTES: usize = 32;

/// The proof id a gated `VerifyProof` payload names, if it names one.
///
/// `None` for any payload that is not exactly [`PROOF_ID_BYTES`] bytes. Written
/// once, here, so six subsystems cannot drift apart on what a `VerifyProof`
/// payload is the way they would if each parsed it itself.
#[inline]
pub fn verify_proof_target(payload: &[u8]) -> Option<[u8; PROOF_ID_BYTES]> {
    <[u8; PROOF_ID_BYTES]>::try_from(payload).ok()
}

/// The longest subsystem transaction payload that may be decoded, in bytes.
///
/// Read only where [`subsystem_allocation_bound_gate_open`] said yes. Four times
/// `ChainParams::max_metadata_bytes`'s default of 16,384, which is the chain's
/// own existing statement of how large one operator-supplied blob may be. It is
/// a binary constant and not a `ChainParams` field on purpose: the activation
/// digest covers `Option<u64>` gates and nothing else, so a configurable limit
/// would be a consensus-relevant number two validators could hold different
/// values of with nothing to compare. The height is coordinated; the limit ships
/// in the reviewed binary.
pub const MAX_SUBSYSTEM_PAYLOAD_BYTES: usize = 65_536;

/// The longest payload-supplied text that may become a column-family KEY, in
/// bytes.
///
/// Read only where [`subsystem_allocation_bound_gate_open`] said yes.
///
/// ACTIVATION-AUDIT row AL-7, and the same shape in two subsystems the audit
/// does not name. Three column families are keyed by the raw UTF-8 of a
/// `jurisdiction_code` the sender writes into its own payload, with no length
/// or character validation anywhere ahead of the `put`:
///
///   * `cf::PROPERTY_JURISDICTION_INDEX` from `AssetAnchor.jurisdiction_code`
///     (`crates/state/src/property_view.rs`, key builder
///     `crates/storage/src/property_store.rs::jurisdiction_index_key`) — AL-7;
///   * `cf::LEGAL_JURISDICTION_INDEX` from `CaseAnchor.jurisdiction_code` and
///     `BenefitDetermination.jurisdiction_code`;
///   * `cf::FINANCE_JURISDICTION_INDEX` from
///     `FinanceIssuerProfile.jurisdiction_code`.
///
/// AL-7 is the one row in its class where attacker control reaches the KEY
/// SPACE rather than a value: one transaction bounded only by
/// `max_block_bytes` writes a key of most of two megabytes, and every read of
/// that family then carries it. The Legal and Finance instances are the same
/// defect at the same seam and were found while closing AL-7; they are bounded
/// here rather than left, because activating the Property bound alone would
/// close the cheapest vector and leave two identical ones open, which is the
/// argument this gate's doc comment already makes for DocClass and NFT.
///
/// 64 bytes. An ISO 3166-2 subdivision code is at most six characters and the
/// tree's own fixtures use `"US-NY"` and `"US"`, so this is an order of
/// magnitude of headroom over any real value and still a bound. A binary
/// constant rather than a `ChainParams` field for the reason
/// [`MAX_SUBSYSTEM_PAYLOAD_BYTES`] gives: the activation digest covers
/// `Option<u64>` gates and nothing else.
///
/// A row already keyed past this bound when the gate opens — there is no way
/// to have one except by writing it below the gate — is untouched: reads still
/// find it, and only a NEW anchor naming an over-long code is refused.
pub const MAX_INDEX_KEY_TEXT_BYTES: usize = 64;

/// Whether `text` may be used as a column-family key at this gate setting.
///
/// Always true below the gate, which is byte-for-byte the unremediated binary.
#[inline]
pub fn index_key_text_within_bound(text: &str, gate_open: bool) -> bool {
    !gate_open || text.len() <= MAX_INDEX_KEY_TEXT_BYTES
}

/// The longest STORED encoding of an accumulating row that may be decoded, in
/// bytes.
///
/// Read only where [`subsystem_allocation_bound_gate_open`] said yes. Checked
/// against the bytes the view returned, before they are handed to a decoder, so
/// the refusal costs one length comparison rather than a decode.
///
/// Bounding the row's BYTES subsumes bounding its entry count: every entry costs
/// at least its own encoding, so a 1 MiB row holds at most about 42,000
/// twenty-five-byte entries and the linear `contains`/`find` scans of
/// ACTIVATION-AUDIT row AL-11 are bounded by the same constant that bounds
/// AL-10. Two limits would be two things to keep consistent for no more safety.
///
/// A row already past this limit when the gate opens — there is no way to have
/// one except by writing it below the gate — becomes unmodifiable rather than
/// unreadable: the mutating operations refuse it with a failed receipt, reads
/// are untouched. A row may also overshoot by at most one payload, because the
/// check refuses the NEXT operation rather than the one that crossed.
pub const MAX_ACCUMULATING_ROW_BYTES: usize = 1_048_576;

pub use agreement_executor::{AgreementExecutionResult, AgreementExecutor, AgreementGates};
pub use cache::{CacheStats, CachedAccount, StateCache};
pub use contract_executor::{ContractCallResult, ContractDeployResult, ContractExecutorState, ContractEvent, ContractMetadata};
pub use docclass_executor::{
    docclass_stake_escrow_address, DocClassExecutionResult, DocClassExecutor, DocClassGates,
};
pub use docclass_view::BoundedRow;
pub use employment_executor::{EmploymentExecutionResult, EmploymentExecutor, EmploymentGates};
pub use equity_executor::{EquityExecutionResult, EquityExecutor};
pub use executor::{BlockExecutor, TxExecutionResult};
pub use finance_executor::{FinanceExecutionResult, FinanceExecutor, FinanceGates};
pub use healthcare_executor::{HealthcareExecutionResult, HealthcareExecutor, HealthcareGates};
pub use legal_executor::{LegalExecutionResult, LegalExecutor, LegalGates};
pub use mempool::{Mempool, MempoolConfig, MempoolStats};
pub use messaging_executor::{MessagingExecutionResult, MessagingExecutor};
pub use nft_executor::{NftExecutionResult, NftExecutor, NftGates, MAX_NFT_BATCH_MINT_REQUESTS};
pub use node_registry::{NodeRegistryExecutionResult, NodeRegistryExecutor};
pub use policy_account_executor::{PolicyAccountExecutionResult, PolicyAccountExecutor};
pub use storage_metadata::{
    ArchivePerEntry, CoverageSummaryV2, StorageMetadataExecutionResult, StorageMetadataExecutor,
    StorageMetadataV2ExecutionResult, MAX_ASSIGNED_COUNT_CHUNK_COUNT,
};
pub use property_executor::{PropertyExecutionResult, PropertyExecutor, PropertyGates};
pub use schema_validator::{SchemaValidator, SchemaValidatorConfig, ValidationResult};
pub use snapshot::{
    sync_capability, usable_reorg_depth, RestoreResult, Snapshot, SnapshotHeader, SnapshotManager,
    SnapshotSyncConfig, SyncCapability,
};
pub use staking_executor::{StakingExecutionResult, StakingExecutor};
pub use state::StateManager;
pub use tax_executor::{TaxExecutionResult, TaxExecutor, TaxGates};
pub use token_executor::{TokenExecutionResult, TokenExecutor};

// Type alias for convenience (used by executors)
pub type State = StateManager;

use thiserror::Error;

/// State errors
#[derive(Debug, Error)]
pub enum StateError {
    #[error("Storage error: {0}")]
    Storage(#[from] sumchain_storage::StorageError),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    #[error("Invalid chain ID: expected {expected}, got {got}")]
    InvalidChainId { expected: u64, got: u64 },

    #[error("Fee too low: minimum {minimum}, got {got}")]
    FeeTooLow { minimum: u128, got: u128 },

    #[error("Signer mismatch: tx from {from}, signed by {signer}")]
    SignerMismatch { from: String, signer: String },

    #[error("Transaction already exists")]
    TxAlreadyExists,

    #[error("Mempool full")]
    MempoolFull,

    /// OmniNode `InferenceAttestation` subprotocol is not yet active at the
    /// current block height — `omninode_enabled_from_height` is either
    /// `None` or in the future. Mempool admission rejects with this so
    /// pre-activation txs never enter the mempool.
    #[error("OmniNode InferenceAttestation subprotocol not activated at this height")]
    OmniNodeNotActivated,

    /// Mempool already has an in-flight `InferenceAttestation` for the
    /// same `(session_id, verifier_address)` pair, OR the canonical
    /// `INFERENCE_ATTESTATIONS` column family already records a finalized
    /// attestation for that pair. Either case = duplicate; the tx is
    /// rejected at admission and never reaches the executor.
    #[error("Duplicate InferenceAttestation for this (session_id, verifier) pair")]
    DuplicateInferenceAttestation,

    /// SRC-817/818 Education suite not activated at the current chain
    /// height (`education_enabled_from_height` is `None` or in the
    /// future). Mempool admission rejects pre-activation education txs;
    /// no receipt is produced (admission only).
    #[error("Education suite not activated at this height")]
    EducationNotActivated,

    /// BR1 randomness-beacon subprotocol (#125) is not active: the
    /// `beacon_enabled_from_height` gate is `None`/in the future (and is
    /// fail-closed pending BR1 #127). Beacon payloads (`BeaconSetup` /
    /// `BeaconSigning`) are deterministically rejected at mempool admission so a
    /// gate-closed beacon tx never enters the mempool; no receipt (admission only).
    /// The executor independently rejects any beacon tx that reaches execution
    /// (`crate::beacon_executor`) with the generic `Failed(0)` receipt, mutating no
    /// beacon state (no beacon-specific receipt code is frozen).
    #[error("Beacon subprotocol not activated at this height")]
    BeaconNotActivated,

    /// C1/ComputePool subprotocol is gate-closed (`compute_pool_enabled_from_height`
    /// = None by default, fail-closed pending #130). ComputePool payloads
    /// (`TxPayload::ComputePool`) are deterministically rejected at mempool admission
    /// so a gate-closed ComputePool tx never enters the mempool; no receipt
    /// (admission only). The executor independently rejects any ComputePool tx that
    /// reaches execution with the generic `Failed(0)` receipt, mutating no state
    /// (no ComputePool-specific receipt code is frozen).
    #[error("ComputePool subprotocol not activated at this height")]
    ComputePoolNotActivated,

    /// An education record with the same identity is already in-flight
    /// in the mempool, OR already committed in a Phase 2 education CF.
    /// Rejected at admission; no receipt (admission only).
    #[error("Duplicate education record (in-flight or committed)")]
    DuplicateEducationRecord,

    /// Education tx failed a cheap admission precheck (oversize payload,
    /// undecodable/unsupported op, or a structural prerequisite such as
    /// a missing/inactive catalog or missing enrollment). Rejected at
    /// admission; no receipt — the executor remains authoritative for
    /// txs that pass admission.
    #[error("Invalid education transaction: {0}")]
    InvalidEducationTransaction(String),

    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    #[error("Genesis error: {0}")]
    Genesis(String),

    #[error("NFT error: {0}")]
    NftError(String),

    #[error("Contract error: {0}")]
    ContractError(String),

    #[error("Policy account error: {0}")]
    PolicyAccountError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// The scan feeding the account-state commitment yielded an address that
    /// was not strictly greater than the previous one.
    ///
    /// The commitment is an ascending-address fold, so the order is part of the
    /// value. Folding an out-of-order scan anyway would produce a different,
    /// perfectly plausible digest and a silent chain split; this fails the block
    /// instead. Unreachable through RocksDB or the overlay's merged iterator,
    /// both of which yield keys in ascending order — which is exactly why the
    /// assumption is worth checking rather than commenting.
    #[error("account-state commitment: scan out of order (previous {previous}, got {got})")]
    AccountScanOutOfOrder { previous: String, got: String },

    /// The account commitment was activated at or below the historical
    /// root-compatibility cutoff.
    ///
    /// At or below that height `accept_imported` ADOPTS a mismatching header
    /// root instead of refusing the block, so an activation inside the window
    /// makes a mixed-version disagreement invisible: both sides publish the
    /// proposer's root over state they do not share. The commitment exists to
    /// make that impossible, so the configuration is refused rather than run.
    #[error(
        "account_root_enabled_from_height = {height} is at or below the legacy \
         root-compatibility cutoff {cutoff}; a mismatch there is force-adopted, \
         not refused, so activating inside the window would split the network \
         silently"
    )]
    AccountRootActivationInsideLegacyWindow { height: u64, cutoff: u64 },

    /// `ChainParams::validate` refused the pair.
    ///
    /// Distinct from the three `AccountRootActivation*` variants: those are the
    /// rules that need chain constants `sumchain-genesis` cannot see. This one
    /// carries the loader's own message, so a caller can tell which layer
    /// refused without parsing prose.
    #[error("chain activation parameters are inconsistent: {0}")]
    ActivationParams(String),

    /// The account commitment was activated without a PINNED application-journal
    /// height.
    ///
    /// `application_journal_enabled_from_height == None` means "observed from
    /// this node's own chain", which is a node-local answer: two nodes can hold
    /// different boundaries and neither is wrong. The account digest is folded
    /// into the state root, so the guarantee that a reverted block's account
    /// rows can be restored has to be chain-defined, not per-node. Refused.
    #[error(
        "account_root_enabled_from_height = {height} requires a PINNED \
         application_journal_enabled_from_height; `None` means \
         observed-from-this-node's-chain, which is node-local, and a commitment \
         folded into the state root cannot rest on a per-node boundary"
    )]
    AccountRootActivationWithoutPinnedJournal { height: u64 },

    /// The account commitment activates before the journal can cover a full
    /// reorg horizon below it.
    ///
    /// Covers both failures: a journal height ABOVE the account height (there is
    /// a band where the root commits to account rows no journal can restore),
    /// and a journal height close enough below it that a reorg from just above
    /// the account activation can walk back past where records begin.
    #[error(
        "account_root_enabled_from_height = {account} requires \
         application_journal_enabled_from_height <= {account} - {horizon}, but it \
         is {journal}: a reorg at the activation height may walk {horizon} blocks \
         back, and the root commits to account rows the journal cannot restore \
         below {journal}"
    )]
    AccountRootActivationOutrunsJournal {
        account: u64,
        journal: u64,
        horizon: u64,
    },
}

pub type Result<T> = std::result::Result<T, StateError>;

impl From<sumc_runtime::RuntimeError> for StateError {
    fn from(e: sumc_runtime::RuntimeError) -> Self {
        StateError::ContractError(e.to_string())
    }
}
