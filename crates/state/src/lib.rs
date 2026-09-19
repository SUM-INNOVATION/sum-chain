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
/// is [`MAX_BLOCK_WRITE_SET_BYTES`], `1 << 28`, and not the 4,096 or 8,192 bytes
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

/// The largest logical write set one block may buffer, in bytes.
///
/// This is the ceiling `BlockExecutor::execute_block` gives its candidate. It
/// replaces `CANDIDATE_LIMIT_SCAFFOLD`, whose own doc comment said it was
/// scaffolding, that the real ceiling was "a versioned consensus parameter
/// derived from measured write sets", and that it "must be replaced before
/// publication".
///
/// It decides BLOCK APPLICABILITY, which is why it is consensus-relevant:
/// `ApplicationOverlay::stage` refuses the write that would cross it, the
/// refusal leaves `execute_tx` as an `Err`, `execute_block`'s transaction loop
/// propagates it with `?`, and `PoaEngine::do_import_block` therefore rejects
/// the whole block. A binary with a larger value applies a block its peers
/// refuse. It is folded into [`protocol_digest::consensus_limits`] for exactly
/// that reason.
///
/// # Why a versioned binary constant and not a `ChainParams` field
///
/// A ceiling is not the dormant-gate pattern. Every `*_enabled_from_height`
/// field defaults to `None` because ACTIVATING it changes behaviour; this must
/// have a working value from the first block, so the question is what value,
/// not when. That is an argument for configuring it, and it is answered by
/// looking at what would then compare it. `Genesis::activation_digest` folds
/// `chain_id`, `genesis_time`, the validator set, the allocations and
/// `ChainParams::activation_heights` — every `Option<u64>` gate — and nothing
/// else. No digest anywhere covers `max_block_bytes`, `min_fee` or any other
/// plain `ChainParams` field, and [`protocol_digest::consensus_limits`] takes no
/// `Genesis`, so it cannot fold one either. A plain `ChainParams` field for this
/// number would therefore be a value that decides whether a block is applicable
/// and that NOTHING in the tree compares between two validators: the exact
/// hazard `protocol_digest` exists to close, reintroduced one level up. The
/// three sibling limits above make the same choice for the same reason, and
/// `protocol_digest`'s module doc completes the argument: the fix is not to make
/// such a value configurable, it is to make it comparable.
///
/// The cost is stated rather than hidden: a chain that raises
/// `max_block_bytes` or `max_txs_per_block` far beyond this repository's
/// `genesis.json` must rebuild rather than edit a config file.
/// `block_write_set_ceiling.rs` reads those two fields out of `genesis.json` and
/// fails if the derivation's inputs have moved, so the rebuild is demanded by a
/// test rather than remembered.
///
/// # Derivation
///
/// Every figure below is labelled MEASURED (a test in this tree prints it),
/// RECORDED (a number this repository already states elsewhere) or ASSUMED (a
/// judgement, made here, with its reasoning visible). Arithmetic on measured
/// points is labelled DERIVED.
///
/// MEASURED — `crates/state/tests/release_ceiling_allocation.rs`, from a
/// counting global allocator that reports churn, PEAK LIVE and largest single
/// allocation separately. One `AddKey` against a committed row of R bytes, at
/// R = 1, 4, 16 and 64 MiB:
///
///   * peak LIVE memory is 4.00 x R at every one of the four points, linear
///     across six doublings;
///   * the overlay charges 2.00 x R against this ceiling, because `put` charges
///     the new value AND the captured pre-image.
///
/// Peak live, not cumulative churn: the same window churns 5.00 x R, and
/// sizing against churn overstates footprint.
///
/// MEASURED — `crates/storage/tests/application_journal.rs`
/// (`journal_bytes_are_charged_against_the_candidate_ceiling`): a pre-image N
/// bytes larger raises the minimum publishing ceiling by exactly 2N — N for the
/// overlay's capture, N for the application journal's copy, both charged
/// against this same number. The journal is inside the ceiling, not beside it.
///
/// MEASURED — `crates/consensus/tests/reorg_execution.rs`
/// (`journal_bytes_per_block_are_measured_against_real_published_blocks`): the
/// journal's marginal cost is about 87 bytes per transaction, so a full
/// 1,000-transaction block journals about 87 KB. Journal framing is not the
/// binding term.
///
/// MEASURED — `crates/state/tests/block_write_set_ceiling.rs`: what a full
/// block at this repository's own declared limits actually charges. That test
/// reads `max_block_bytes` and `max_txs_per_block` from `genesis.json`
/// (2,000,000 and 1,000 — NOT `ChainParams::default()`, which differs) and
/// publishes a block at each of them:
///
///   * the transaction-count bound, 1,000 transfers to 1,000 DISTINCT
///     recipients: 72,363 bytes of execution charge, a 55,274-byte journal
///     record;
///   * the block-bytes bound, ~1.9 MB of `CreateIdentityRoot` payload:
///     1,903,881 bytes of execution charge, a 1,219-byte journal record.
///
/// Distinct recipients on purpose: the overlay charges a key and its pre-image
/// once per DISTINCT key, so 1,000 transfers to one address charge three
/// account rows and report a write set two hundred times smaller than the bound
/// they claim to measure.
///
/// With the publication allowance that test states — four times
/// `max_block_bytes`, covering the block record, the duplicate transaction
/// rows, the receipts, the indexes, the legacy diffs and the journal, each of
/// which is a new key bounded by the block's own size — the worse of the two
/// blocks costs about 9.9 MB, and this ceiling clears it by 27x.
///
/// DERIVED — from the two measured factors. The largest single row a block can
/// still commit is R_max = C/2, because `put` charges value plus pre-image.
/// During the transaction that commits it, peak live is 4.00 x R_max, of which
/// 2.00 x R_max is the overlay's own retained charge; the transient excess is
/// therefore 2.00 x R_max = C. With the overlay itself at its limit, one
/// block's peak live application memory is about
///
/// ```text
/// C + 2.00 x (C/2)  =  2C
/// ```
///
/// RECORDED — the validator memory envelope. This repository states three
/// figures and they do not agree, so the binding one is used and the others are
/// named. `deploy/kubernetes/statefulset.yaml` and the three
/// `statefulset-validator-*.yaml` files set `limits.memory: "4Gi"` on every
/// validator pod: a cgroup limit, enforced by the kernel with an OOM kill, and
/// the only one of the three that is machine-checked rather than prose.
/// `docs/architecture/performance-guide.md` targets `Memory usage < 2 GB` for
/// the whole node and separately recommends 32 GB for a production validator;
/// that table carries no date, no provenance and no measurement command, and it
/// predates the overlay accounting it would have to be reconciled with.
/// `tools/b0-pre-validator/src/consts.rs` pins a 4 GiB verification reference
/// envelope and explicitly disclaims being a hardware minimum. Nothing in the
/// tree derives a memory budget from the protocol's own limits; the capacity
/// work in `docs/lane-a/JOURNAL-CONTRACT.md` §12 models DISK only.
///
/// ASSUMED — one block's execution may claim at most one eighth of the 4 GiB
/// cgroup limit, 512 MiB. The reasoning, stated so it can be disagreed with: a
/// validator inside that 4 GiB is also holding RocksDB's block cache and
/// memtables, a mempool, p2p buffers and the node's own steady state, which the
/// performance guide puts at about 1.5 GB; the remaining headroom has to absorb
/// importing one block while producing another, and a compaction landing during
/// both. A single block taking a quarter of that headroom is the line drawn
/// here. It is a judgement, not a measurement, and it is the one number in this
/// derivation that a reviewer with better data should move.
///
/// DERIVED — 2C <= 512 MiB gives C <= 256 MiB, and
///
/// ```text
/// C = 1 << 28 = 268,435,456 bytes
/// ```
///
/// Worst-case peak live for one block is then 512 MiB: 12.5% of the enforced
/// cgroup limit. The scaffold it replaces implied 2 GiB — 50% of the same
/// limit, and more than the whole node's stated steady-state target — for a
/// single block, which is why the scaffold could not survive its own doc
/// comment.
///
/// # What this ceiling does NOT establish, and what would
///
/// It is a SAFETY bound. It is not a sufficiency bound, and no value of this
/// constant could be, which is the finding worth carrying forward.
///
/// A block's write set is not bounded by the block's size. Read-modify-write
/// charges the pre-image of a row the block does not carry: one ~100-byte
/// `AddKey` against a committed 1 MiB row charges 2 MiB. A 2,000,000-byte block
/// holds 1,000 such transactions comfortably, so a block of entirely VALID
/// transactions can charge about 2 GiB even with
/// [`MAX_ACCUMULATING_ROW_BYTES`] active — and below that gate, which is the
/// production default, row size is bounded by nothing except this ceiling, so
/// the bound is self-referential. No ceiling that a validator can survive is
/// large enough to admit that block. The replaced 1 GiB scaffold did not admit
/// it either; lowering the ceiling changes how many such transactions fit, not
/// whether the class exists.
///
/// Erring low is the correct direction, because the two failure modes are not
/// symmetric. Too low: `execute_block` returns the same `Err` on every
/// validator, the block is refused identically everywhere, and the next
/// proposer's slot proceeds — deterministic, and visible. Too high: the
/// validator with less memory is OOM-killed while the one with more follows the
/// chain, which is a split decided by hardware rather than by rules.
///
/// What is missing is a bound on the write set ONE TRANSACTION may charge, so
/// that `max_block_bytes` actually bounds a block's write set. That is not this
/// constant's to fix and cannot be measured into existence: it is a rule that
/// does not exist yet, and it belongs to whoever owns
/// `subsystem_allocation_bound_enabled_from_height` and the block producer in
/// `crates/consensus/src/poa.rs`, which builds blocks without simulating what
/// they will charge.
pub const MAX_BLOCK_WRITE_SET_BYTES: u64 = 1 << 28;

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
