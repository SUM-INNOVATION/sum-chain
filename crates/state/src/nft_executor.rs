//! NFT Transaction Executor
//!
//! Handles execution of SUM-721 NFT operations including:
//! - Collection creation
//! - Token minting (standard and document)
//! - Transfers, approvals, burns
//! - Metadata updates
//!
//! ## Security Features
//!
//! - **Per-byte storage pricing**: Metadata size affects transaction fees to prevent state bloat
//! - **Issuer registry**: Only registered issuers can mint certified document NFTs
//! - **Metadata size limits**: Maximum metadata size enforced per chain params

use sumchain_storage::exec_view::ExecutionView;

use sumchain_genesis::ChainParams;
use sumchain_nft::collection::CollectionId;
use sumchain_nft::ops::{
    CreateCollectionData, NftApproveData, NftBatchMintData, NftMintData,
    NftTransferCollectionOwnershipData, NftTransferData, NftUpdateCollectionConfigData,
};
use sumchain_primitives::{Address, Balance, NftOperation, NftTxData};
use sumchain_storage::{NftCollectionData, NftTokenData};
use tracing::{debug, info, warn};

use crate::{Result, StateError, StateManager};

/// The largest number of tokens one `BatchMint` may name.
///
/// Read only where the allocation-bound gate is open. The loop that services a
/// batch rebuilds the owner index and the collection index once per request, so
/// the transaction's cost is quadratic in this number: at 512 the owner index is
/// rebuilt 512 times at an average of 256 forty-byte entries, about five
/// megabytes of churn, and at the 2,000,000-byte block limit with no bound at
/// all it is tens of gigabytes.
///
/// A binary constant rather than a `ChainParams` field, for the reason given on
/// `MAX_SUBSYSTEM_PAYLOAD_BYTES`: the activation digest covers `Option<u64>`
/// gates and nothing else, so a configurable limit is a consensus-relevant
/// number with nothing to compare it against.
pub const MAX_NFT_BATCH_MINT_REQUESTS: usize = 512;

/// Result of executing an NFT operation
#[derive(Debug)]
pub struct NftExecutionResult {
    /// Whether the operation succeeded
    pub success: bool,
    /// Collection ID (for create/mint operations)
    pub collection_id: Option<[u8; 32]>,
    /// Token ID (for mint operations)
    pub token_id: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
    /// What the executor actually moved out of the sender's balance, as the
    /// receipt should report it.
    ///
    /// ACTIVATION-AUDIT row OV-9. `0` below the charged-receipt gate whatever
    /// happened, which is the number the block executor has always written;
    /// at and above it, the fee `deduct_fee` took, or `0` for the one refusal
    /// that never reached `deduct_fee`'s writes.
    pub fee_charged: Balance,
}

impl NftExecutionResult {
    fn success() -> Self {
        Self {
            success: true,
            collection_id: None,
            token_id: None,
            error: None,
            fee_charged: 0,
        }
    }

    fn success_with_collection(collection_id: [u8; 32]) -> Self {
        Self {
            success: true,
            collection_id: Some(collection_id),
            token_id: None,
            error: None,
            fee_charged: 0,
        }
    }

    fn success_with_token(collection_id: [u8; 32], token_id: u64) -> Self {
        Self {
            success: true,
            collection_id: Some(collection_id),
            token_id: Some(token_id),
            error: None,
            fee_charged: 0,
        }
    }

    fn failure(error: String) -> Self {
        Self {
            success: false,
            collection_id: None,
            token_id: None,
            error: Some(error),
            fee_charged: 0,
        }
    }

    /// Stamp what the fee actually did, once the caller knows.
    ///
    /// Every constructor above leaves it `0` deliberately: an arm has no way to
    /// know whether `deduct_fee` ran, and a default that guessed would be the
    /// OV-9 defect written the other way round.
    fn charging(mut self, fee_charged: Balance) -> Self {
        self.fee_charged = fee_charged;
        self
    }
}

/// NFT Executor for processing NFT transactions.
/// No database handle, by construction.
///
/// Every operation takes the block's `ExecutionView` and no `self`, so
/// `self.db` is not something this file can name: a committed write here is a
/// compile error rather than a review finding. The committed twins stay in
/// `sumchain_storage::schema` for the RPC server.
///
/// `ChainParams` travels as a parameter for the same reason. It used to ride on
/// the receiver beside the database handle, and the only way to be sure the
/// handle is gone is for there to be no receiver at all.
pub struct NftExecutor;

/// The activation decisions an NFT transaction executes under.
///
/// [`NftExecutor::execute`] derives it from `ChainParams`;
/// [`NftExecutor::execute_with_gates`] takes it directly, which is how a test
/// drives an ungated node and a gated node over the same transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NftGates {
    /// A block-level denial becomes a charged `Failed` receipt.
    /// ACTIVATION-AUDIT NFT receipt-failure row.
    pub receipt_failure: bool,
    /// An approval or a metadata rewrite answers to the token's owner, its
    /// `locked` flag and its collection.
    /// ACTIVATION-AUDIT rows OV-12, OV-13 and OV-14.
    pub token_authority: bool,
    /// A transaction's sizing inputs are checked against a limit BEFORE the
    /// value they size is built: an oversized payload is refused before it is
    /// decoded, and a `BatchMint` naming more than
    /// [`MAX_NFT_BATCH_MINT_REQUESTS`] tokens is refused before the loop that
    /// rebuilds the owner index once per request. ACTIVATION-AUDIT row AL-9.
    pub allocation_bound: bool,
    /// The arms that write metadata or a collection config apply the rules the
    /// CREATION arms apply. ACTIVATION-AUDIT rows OV-10 and the first half of
    /// RY-2.
    pub update_path_parity: bool,
    /// A failed NFT receipt reports the fee the executor actually took.
    /// ACTIVATION-AUDIT row OV-9.
    pub charged_receipt: bool,
    /// The two token indexes empty the same way: emptying either DELETES its
    /// row. ACTIVATION-AUDIT row OV-15.
    pub index_symmetry: bool,
    /// A collection id mixes the sender's account nonce into its preimage, so
    /// the block clock is no longer its only nonce. ACTIVATION-AUDIT row CI-1.
    pub collection_id_nonce: bool,
    /// A collection creation carrying a non-zero `royalty_bps` is refused,
    /// because no transfer on this chain pays one. ACTIVATION-AUDIT row RY-1.
    pub unpayable_royalty_refused: bool,
}

impl NftGates {
    /// Every gate closed -- the release configuration today.
    pub const CLOSED: Self = Self {
        receipt_failure: false,
        token_authority: false,
        allocation_bound: false,
        update_path_parity: false,
        charged_receipt: false,
        index_symmetry: false,
        collection_id_nonce: false,
        unpayable_royalty_refused: false,
    };

    /// Every gate open. For the gated half of a mixed-version test.
    pub const OPEN: Self = Self {
        receipt_failure: true,
        token_authority: true,
        allocation_bound: true,
        update_path_parity: true,
        charged_receipt: true,
        index_symmetry: true,
        collection_id_nonce: true,
        unpayable_royalty_refused: true,
    };

    /// Derive the decisions from the chain's parameters at `block_height`.
    pub fn from_params(params: &ChainParams, block_height: u64) -> Self {
        Self {
            receipt_failure: NftExecutor::receipt_failure_gate_open(params, block_height),
            token_authority: NftExecutor::token_authority_gate_open(params, block_height),
            allocation_bound: NftExecutor::allocation_bound_gate_open(params, block_height),
            update_path_parity: NftExecutor::update_path_parity_gate_open(params, block_height),
            charged_receipt: NftExecutor::charged_receipt_gate_open(params, block_height),
            index_symmetry: NftExecutor::index_symmetry_gate_open(params, block_height),
            collection_id_nonce: NftExecutor::collection_id_nonce_gate_open(params, block_height),
            unpayable_royalty_refused: NftExecutor::unpayable_royalty_refused_gate_open(
                params,
                block_height,
            ),
        }
    }
}

impl NftExecutor {
    /// Get current timestamp in milliseconds (now uses block timestamp for determinism)
    fn now_ms(block_timestamp: u64) -> u64 {
        block_timestamp
    }

    /// The activation height for bounding a transaction's sizing inputs.
    ///
    /// Reads `params.subsystem_allocation_bound_enabled_from_height` through
    /// `crate::subsystem_allocation_bound_gate_open`, which is the same field
    /// the DocClass bound reads. ACTIVATION-AUDIT row AL-9.
    ///
    /// Not its own field. The DocClass and NFT bounds are one rule at one seam
    /// -- check the size before building the value -- with the same blast radius
    /// on both sides, and an attacker refused by one simply uses the other. The
    /// argument is spelled out on the field itself in `crates/genesis/src/lib.rs`.
    #[inline]
    fn allocation_bound_gate_open(params: &ChainParams, block_height: u64) -> bool {
        crate::subsystem_allocation_bound_gate_open(params, block_height)
    }

    /// The activation height for the NFT receipt-failure rule.
    ///
    /// **This is a seam for a `ChainParams` field that does not exist yet.**
    /// `crates/genesis/**` belongs to another track, so the field cannot be
    /// added from here. The field this function must read, once that track adds
    /// it, is:
    ///
    /// ```text
    /// /// SRC-721 receipt-failure rule. Dormant by default (`None` -> never
    /// /// open). Below the gate, an NFT operation naming an absent collection
    /// /// or token, carrying an undecodable payload, carrying an out-of-range
    /// /// royalty, or draining the sender's balance inside the block, returns
    /// /// `Err(StateError::BlockValidation)` and makes the whole block
    /// /// unexecutable. At and above the gate the same conditions produce a
    /// /// `Failed` receipt that charges the sender and leaves the block valid.
    /// /// Activation is a consensus change and needs a coordinated validator
    /// /// upgrade: two nodes that disagree about this height disagree about
    /// /// whether a block exists at all.
    /// #[serde(default)]
    /// pub nft_receipt_failure_enabled_from_height: Option<u64>,
    /// ```
    ///
    /// Until it exists this returns `None`, which is exactly what an absent
    /// `#[serde(default)] Option<u64>` resolves to, so the production behaviour
    /// is bit-identical to the behaviour before this change: the gate is closed
    /// and the `Err` still propagates. The gated side is not dead, though — it
    /// is reachable through [`NftExecutor::execute_with_gate`], which is what
    /// the mixed-version tests drive.
    #[inline]
    fn receipt_failure_activation(params: &ChainParams) -> Option<u64> {
        params.nft_receipt_failure_enabled_from_height
    }

    /// Whether the NFT receipt-failure rule is active at `block_height`.
    #[inline]
    fn receipt_failure_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::receipt_failure_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the NFT token-authority rules.
    ///
    /// Reads `params.nft_token_authority_enabled_from_height`, and nothing else.
    /// `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-12, OV-13 and OV-14):
    ///
    ///   * `UpdateMetadata` accepts the token's CREATOR, which never changes, so
    ///     the minter rewrites the metadata of a token it sold;
    ///   * `locked` is consulted by transfer and burn only, so a locked token is
    ///     still approvable and its metadata still rewritable;
    ///   * `Approve` never reads the collection, so an approval is recorded on a
    ///     token in a collection that forbids transfers.
    ///
    /// At and above it a metadata rewrite requires the current owner, a locked
    /// token refuses both, and an approval refuses a non-transferable
    /// collection.
    #[inline]
    fn token_authority_activation(params: &ChainParams) -> Option<u64> {
        params.nft_token_authority_enabled_from_height
    }

    /// Whether the NFT token-authority rules are active at `block_height`.
    #[inline]
    pub fn token_authority_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::token_authority_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the NFT update-path parity rules.
    ///
    /// Reads `params.nft_update_path_parity_enabled_from_height`, and nothing
    /// else. `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT rows OV-10 and the first half of RY-2):
    ///
    ///   * `execute_mint` enforces `max_metadata_bytes` and charges
    ///     `storage_fee_per_byte`; `UpdateMetadata` and `BatchMint` enforce
    ///     neither, although both of those values are SET in the release
    ///     `genesis.json`;
    ///   * collection creation zeroes `royalty_recipient` when `royalty_bps` is
    ///     zero, and `UpdateCollectionConfig` sets one anyway.
    ///
    /// At and above it the two metadata arms apply the mint's two rules and
    /// `UpdateCollectionConfig` refuses a recipient for a royalty of zero.
    ///
    /// This does NOT make a royalty payable: RY-1 is untouched, and so is the
    /// half of RY-2 that observes the config payload has no `new_royalty_bps`.
    #[inline]
    fn update_path_parity_activation(params: &ChainParams) -> Option<u64> {
        params.nft_update_path_parity_enabled_from_height
    }

    /// Whether the NFT update-path parity rules are active at `block_height`.
    #[inline]
    pub fn update_path_parity_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::update_path_parity_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the NFT charged-receipt rule.
    ///
    /// Reads `params.nft_charged_receipt_enabled_from_height`, and nothing
    /// else. `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT row OV-9) every failed NFT receipt
    /// reports `fee_paid: 0`, although `deduct_fee` runs before the dispatch
    /// match and has already debited the sender, credited the proposer and
    /// advanced the nonce. At and above it the receipt reports the fee that was
    /// taken -- still zero for an insufficient balance, where the zero is true.
    #[inline]
    fn charged_receipt_activation(params: &ChainParams) -> Option<u64> {
        params.nft_charged_receipt_enabled_from_height
    }

    /// Whether the NFT charged-receipt rule is active at `block_height`.
    #[inline]
    pub fn charged_receipt_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::charged_receipt_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the NFT index-symmetry rule.
    ///
    /// Reads `params.nft_index_symmetry_enabled_from_height`, and nothing else.
    /// `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT row OV-15) emptying an owner's token
    /// list DELETES its row and emptying a collection's token list WRITES an
    /// empty one, so the two families disagree about what "no entries" looks
    /// like and the empty rows are never collected. At and above it both
    /// delete.
    #[inline]
    fn index_symmetry_activation(params: &ChainParams) -> Option<u64> {
        params.nft_index_symmetry_enabled_from_height
    }

    /// Whether the NFT index-symmetry rule is active at `block_height`.
    #[inline]
    pub fn index_symmetry_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::index_symmetry_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the NFT collection-id nonce rule.
    ///
    /// Reads `params.nft_collection_id_nonce_enabled_from_height`, and nothing
    /// else. `None` -- the default, and what a genesis written before the field
    /// existed resolves to -- closes the gate, so a node executes exactly what
    /// it executed before the field was declared.
    ///
    /// Below the gate (ACTIVATION-AUDIT row CI-1) a collection id is
    /// `hash(sender || name || block_timestamp)`, so two blocks sharing a
    /// timestamp give one sender one id for one name and the second creation is
    /// refused as a duplicate. At and above it the sender's account nonce joins
    /// the preimage.
    #[inline]
    fn collection_id_nonce_activation(params: &ChainParams) -> Option<u64> {
        params.nft_collection_id_nonce_enabled_from_height
    }

    /// Whether the NFT collection-id nonce rule is active at `block_height`.
    #[inline]
    pub fn collection_id_nonce_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::collection_id_nonce_activation(params), Some(h) if block_height >= h)
    }

    /// The activation height for the unpayable-royalty refusal.
    ///
    /// Reads `params.nft_unpayable_royalty_refused_enabled_from_height`, and
    /// nothing else. `None` -- the default, and what a genesis written before
    /// the field existed resolves to -- closes the gate, so a node executes
    /// exactly what it executed before the field was declared.
    ///
    /// ACTIVATION-AUDIT row RY-1. Below the gate `royalty_bps` and
    /// `royalty_recipient` are stored from the payload, published over
    /// JSON-RPC by `nft_getCollection`, and read by no execution path:
    /// `execute_transfer` and `v_transfer_token` move a token and no balance at
    /// all. A marketplace is told a royalty exists that this chain has no code
    /// to pay. At and above the gate a creation whose `royalty_bps` is non-zero
    /// returns a FAILED receipt carrying
    /// [`crate::UNPAYABLE_ROYALTY_UNSUPPORTED`]; a collection with no royalty
    /// is created exactly as before.
    ///
    /// **Why refusal and not payment.** A transfer carries no consideration.
    /// Adding a price field would not be enough either: a `Transfer` is signed
    /// by the SELLER and names the buyer, while `SignedTransaction` carries one
    /// signature checked against `from`, so a price alone would authorise
    /// debiting an account whose holder signed nothing. Paying a royalty needs
    /// a two-sided order, a standing listing or an escrowed bid -- a new wire
    /// type and, for two of the three, a new state family. That is a protocol,
    /// and not something an executor may decide.
    #[inline]
    fn unpayable_royalty_refused_activation(params: &ChainParams) -> Option<u64> {
        params.nft_unpayable_royalty_refused_enabled_from_height
    }

    /// Whether the unpayable-royalty refusal is active at `block_height`.
    #[inline]
    pub fn unpayable_royalty_refused_gate_open(params: &ChainParams, block_height: u64) -> bool {
        matches!(Self::unpayable_royalty_refused_activation(params), Some(h) if block_height >= h)
    }

    /// The errors the receipt-failure rule converts into a `Failed` receipt.
    ///
    /// Deliberately narrow. Storage and encoding errors are node-local faults
    /// and must still abort the block; only the conditions an ordinary sender
    /// chooses from its own payload are converted.
    fn as_receipt_failure(err: &StateError) -> Option<String> {
        match err {
            StateError::BlockValidation(msg) => Some(msg.clone()),
            StateError::InsufficientBalance {
                required,
                available,
            } => Some(format!(
                "Insufficient balance: required {}, available {}",
                required, available
            )),
            _ => None,
        }
    }

    /// Execute an NFT operation from transaction data.
    ///
    /// Reads the receipt-failure activation height out of `params` and
    /// dispatches through [`Self::execute_with_gate`].
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        block_height: u64,
    ) -> Result<NftExecutionResult> {
        Self::execute_with_gates(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            NftGates::from_params(params, block_height),
        )
    }

    /// Execute an NFT operation with the receipt-failure gate supplied directly.
    ///
    /// The seam the mixed-version tests use. `receipt_failure_gate_open` is the
    /// only thing that differs between a node below the activation height and a
    /// node at or above it, so driving both values through one entry point is
    /// what makes the divergence observable rather than asserted.
    ///
    /// Every error site inside the operation bodies fires strictly before that
    /// body's first write — verified site by site — so converting the error at
    /// this boundary cannot leave a half-applied operation in the overlay. The
    /// fee is the one exception, and it is deducted deliberately: it is
    /// deducted at `:execute_ungated` before the match, which is the same
    /// position the pre-existing `failure()` guards already charge from.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gate(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        receipt_failure_gate_open: bool,
    ) -> Result<NftExecutionResult> {
        Self::execute_with_gates(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            NftGates {
                receipt_failure: receipt_failure_gate_open,
                ..NftGates::CLOSED
            },
        )
    }

    /// Execute an NFT operation with every activation decision supplied
    /// directly.
    ///
    /// The superset of [`Self::execute_with_gate`], which named only the
    /// receipt-failure decision because it was the only one. Two more arrived
    /// from two directions and both are separate heights: token authority (rows
    /// OV-12, OV-13 and OV-14) changes which transactions inside a valid block
    /// succeed, where receipt-failure changes whether a block EXISTS at all;
    /// and the allocation bound (row AL-9) is one rule shared with DocClass.
    ///
    /// `execute_with_gate` is kept as the one-gate spelling so every
    /// mixed-version test written against the receipt-failure gate still drives
    /// the seam it was written for. It supplies `token_authority: false` and
    /// `allocation_bound: false`, which is that binary's behaviour.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_with_gates(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        let receipt_failure_gate_open = gates.receipt_failure;
        let outcome = Self::execute_ungated(
            view,
            params,
            sender,
            nft_data,
            proposer,
            fee,
            block_timestamp,
            gates,
        );

        let err = match outcome {
            Ok(result) => return Ok(result),
            Err(err) => err,
        };

        if !receipt_failure_gate_open {
            return Err(err);
        }

        let Some(message) = Self::as_receipt_failure(&err) else {
            return Err(err);
        };

        // An insufficient-balance refusal never reached `deduct_fee`'s writes,
        // so nothing advanced the sender's nonce. Advance it here, or the
        // refused transaction stays replayable at the same nonce while still
        // occupying a receipt slot in the block.
        // ACTIVATION-AUDIT row OV-9. An insufficient balance is the ONE refusal
        // that reaches here without `deduct_fee` having written anything, so it
        // is the one whose receipt may honestly say zero. Every other error
        // arrived from an arm BELOW the deduction and its fee is spent.
        let charged = if matches!(err, StateError::InsufficientBalance { .. }) {
            let mut sender_account = StateManager::v_get_account(view, sender)?;
            sender_account.nonce += 1;
            StateManager::v_put_account(view, sender, &sender_account)?;
            0
        } else {
            Self::receipt_fee(fee, gates)
        };

        warn!(
            "NFT {:?} refused with a receipt rather than aborting the block: {}",
            nft_data.operation, message
        );
        Ok(NftExecutionResult::failure(message).charging(charged))
    }

    /// What a receipt may report for a transaction whose `deduct_fee` ran.
    ///
    /// ACTIVATION-AUDIT row OV-9, and the whole of the gate: below it this is
    /// `0` whatever the sender paid, which is the number the block executor has
    /// written since the subsystem existed, so a closed gate leaves every
    /// receipt byte-for-byte as it was.
    #[inline]
    fn receipt_fee(fee: Balance, gates: NftGates) -> Balance {
        if gates.charged_receipt {
            fee
        } else {
            0
        }
    }

    /// The fee, then the operation bodies, with no receipt-failure gate
    /// applied.
    ///
    /// The deduction is here and the bodies are in [`Self::execute_after_fee`],
    /// so "everything below this point has already paid" is a function boundary
    /// rather than a comment. ACTIVATION-AUDIT row OV-9 is exactly the cost of
    /// that being a comment: every `Ok` this returns describes a transaction
    /// whose fee is spent, and the receipt said otherwise for as long as
    /// nothing carried the number back out.
    #[allow(clippy::too_many_arguments)]
    fn execute_ungated(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        proposer: &Address,
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        Self::deduct_fee(view, sender, fee, proposer)?;
        let charged = Self::receipt_fee(fee, gates);
        let result =
            Self::execute_after_fee(view, params, sender, nft_data, fee, block_timestamp, gates)?;
        Ok(result.charging(charged))
    }

    /// The operation bodies. The fee is already taken when this runs, and
    /// `proposer` is deliberately not a parameter: the only thing this executor
    /// ever paid a proposer was that fee.
    #[allow(clippy::too_many_arguments)]
    fn execute_after_fee(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        nft_data: &NftTxData,
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        // ACTIVATION-AUDIT row AL-9, and the NFT half of AL-12. Every arm below
        // opens with `bincode::deserialize(&nft_data.data)` and no length check
        // ahead of it. One check here rather than one per arm, for the reason
        // the DocClass dispatch gives: the arms are many and the rule is one.
        //
        // AFTER the fee deduction, deliberately. Every pre-existing refusal in
        // this executor charges the sender -- the deduction is the first thing
        // `execute_ungated` does and every `failure()` below it returns having
        // paid -- and an unpaid refusal would be the cheaper transaction to
        // spam, which is the opposite of the point.
        if gates.allocation_bound && nft_data.data.len() > crate::MAX_SUBSYSTEM_PAYLOAD_BYTES {
            return Ok(NftExecutionResult::failure(format!(
                "NFT payload too large: {} bytes, limit {}",
                nft_data.data.len(),
                crate::MAX_SUBSYSTEM_PAYLOAD_BYTES
            )));
        }

        match nft_data.operation {
            NftOperation::CreateCollection => Self::execute_create_collection(
                view,
                sender,
                &nft_data.data,
                block_timestamp,
                gates.collection_id_nonce,
                gates.unpayable_royalty_refused,
            ),
            NftOperation::Mint => Self::execute_mint(
                view,
                params,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                false,
                fee,
                block_timestamp,
            ),
            NftOperation::MintDocument => Self::execute_mint(
                view,
                params,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                true,
                fee,
                block_timestamp,
            ),
            NftOperation::BatchMint => Self::execute_batch_mint(
                view,
                params,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                fee,
                block_timestamp,
                gates,
            ),
            NftOperation::Transfer => Self::execute_transfer(
                view,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
            ),
            NftOperation::Approve => Self::execute_approve(
                view,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
                gates.token_authority,
            ),
            NftOperation::SetApprovalForAll => {
                // For simplicity, we don't implement operator approvals in MVP
                Ok(NftExecutionResult::failure(
                    "SetApprovalForAll not yet implemented".to_string(),
                ))
            }
            NftOperation::Burn => Self::execute_burn(
                view,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                gates.index_symmetry,
            ),
            NftOperation::UpdateMetadata => Self::execute_update_metadata(
                view,
                params,
                sender,
                &nft_data.collection_id,
                nft_data.token_id,
                &nft_data.data,
                fee,
                gates,
            ),
            NftOperation::TransferCollectionOwnership => Self::execute_transfer_collection(
                view,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
            ),
            NftOperation::UpdateCollectionConfig => Self::execute_update_collection_config(
                view,
                sender,
                &nft_data.collection_id,
                &nft_data.data,
                gates,
            ),
            NftOperation::LockToken => {
                Self::execute_lock_token(view, sender, &nft_data.collection_id, nft_data.token_id)
            }
            NftOperation::UnlockToken => {
                Self::execute_unlock_token(view, sender, &nft_data.collection_id, nft_data.token_id)
            }
        }
    }

    /// Deduct fee from sender and credit to proposer
    fn deduct_fee(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        fee: Balance,
        proposer: &Address,
    ) -> Result<()> {
        if fee == 0 {
            return Ok(());
        }

        let sender_balance = StateManager::v_get_balance(view, sender)?;
        if sender_balance < fee {
            return Err(StateError::InsufficientBalance {
                required: fee,
                available: sender_balance,
            });
        }

        // Debit sender
        let mut sender_account = StateManager::v_get_account(view, sender)?;
        sender_account.balance = sender_account.balance.saturating_sub(fee);
        sender_account.nonce += 1;
        StateManager::v_put_account(view, sender, &sender_account)?;

        // Credit proposer
        if !proposer.is_zero() {
            let mut proposer_account = StateManager::v_get_account(view, proposer)?;
            proposer_account.balance = proposer_account.balance.saturating_add(fee);
            StateManager::v_put_account(view, proposer, &proposer_account)?;
        }

        Ok(())
    }

    /// Create a new NFT collection
    fn execute_create_collection(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        data: &[u8],
        block_timestamp: u64,
        collection_id_nonce: bool,
        unpayable_royalty_refused: bool,
    ) -> Result<NftExecutionResult> {
        // Deserialize collection creation data
        // Shared wire struct (issue #89)
        let create_data: CreateCollectionData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid collection data: {}", e)))?;

        // Validate config
        create_data
            .config
            .validate()
            .map_err(|e| StateError::BlockValidation(format!("Invalid config: {}", e)))?;

        // ACTIVATION-AUDIT row RY-1. Below the gate the two royalty fields are
        // stored from the payload, returned to anybody who asks by
        // `nft_getCollection`, and consulted by NOTHING: neither
        // `execute_transfer` nor `v_transfer_token` moves a balance, so the
        // chain publishes a royalty it has no code to pay.
        //
        // At and above the gate a creation that asks for a royalty is refused,
        // and the reason names ROYALTY ENFORCEMENT as unsupported rather than
        // the number as invalid -- the number is fine, the payment is what
        // does not exist. A collection with `royalty_bps == 0` is unaffected,
        // and the zeroing rule just below still applies to it, so this gate
        // takes no capability away from a creator who was not being promised
        // one.
        //
        // Refused AFTER `validate()` so that a malformed config is still
        // reported as malformed, and before the id is computed, so a refused
        // creation consumes no collection id.
        //
        // Creation is the only place this can be enforced, and that is a fact
        // about the wire rather than a choice: `NftUpdateCollectionConfigData`
        // carries no `new_royalty_bps` at all (RY-2's second half), so
        // `royalty_bps` can never be changed after creation, and a recipient on
        // a zero-royalty collection is already refused by
        // `nft_update_path_parity_enabled_from_height`. Collections created
        // BELOW this height keep what they recorded: a gate changes what a node
        // does next, not what a chain has already written.
        if unpayable_royalty_refused && create_data.config.royalty_bps != 0 {
            return Ok(NftExecutionResult::failure(
                crate::UNPAYABLE_ROYALTY_UNSUPPORTED.to_string(),
            ));
        }

        // Generate collection ID
        //
        // ACTIVATION-AUDIT row CI-1. Below the gate the block timestamp is the
        // WHOLE nonce, so the id is a function of (sender, name, clock) and two
        // blocks that share a timestamp hand one sender one id for one name.
        // The second creation is then refused as `Collection already exists`,
        // naming a collection the sender does not have and cannot get.
        //
        // At and above the gate the sender's account nonce joins the preimage.
        // `deduct_fee` has already incremented it, so two creations in one
        // block see two values; it is consensus state read from the same view
        // the transaction executes against, so every node computes the same id;
        // and it is strictly increasing per sender, so the clock no longer has
        // to advance for the id to.
        let nonce = Self::now_ms(block_timestamp);
        let collection_id = if collection_id_nonce {
            let account_nonce = StateManager::v_get_nonce(view, sender)?;
            CollectionId::new_with_account_nonce(sender, &create_data.name, nonce, account_nonce)
        } else {
            CollectionId::new(sender, &create_data.name, nonce)
        };

        // Check if collection already exists
        if Self::v_collection_exists(view, collection_id.as_bytes())? {
            return Ok(NftExecutionResult::failure(
                "Collection already exists".to_string(),
            ));
        }

        // Create collection data
        let collection_data = NftCollectionData {
            name: create_data.name.clone(),
            symbol: create_data.symbol,
            description: create_data.description,
            owner: *sender,
            max_supply: create_data.config.max_supply,
            total_supply: 0,
            next_token_id: 1,
            transferable: create_data.config.transferable,
            burnable: create_data.config.burnable,
            metadata_updatable: create_data.config.metadata_updatable,
            owner_only_minting: create_data.config.owner_only_minting,
            royalty_bps: create_data.config.royalty_bps,
            royalty_recipient: if create_data.config.royalty_bps > 0 {
                create_data.config.royalty_recipient
            } else {
                Address::ZERO
            },
            base_uri: create_data.base_uri,
            created_at: Self::now_ms(block_timestamp),
        };

        Self::v_put_collection(view, collection_id.as_bytes(), &collection_data)?;

        info!(
            "Created NFT collection '{}' with ID {}",
            create_data.name, collection_id
        );

        Ok(NftExecutionResult::success_with_collection(
            *collection_id.as_bytes(),
        ))
    }

    /// Mint a new token
    #[allow(clippy::too_many_arguments)]
    fn execute_mint(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        is_document: bool,
        fee: Balance,
        block_timestamp: u64,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check minting permission
        if collection.owner_only_minting && collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Only collection owner can mint".to_string(),
            ));
        }

        // Check max supply
        if collection.max_supply > 0 && collection.total_supply >= collection.max_supply {
            return Ok(NftExecutionResult::failure("Max supply reached".to_string()));
        }

        // Deserialize mint data
        // Shared wire struct (issue #89)
        let mint_data: NftMintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid mint data: {}", e)))?;

        // Security: Validate metadata size
        let metadata_size = mint_data.metadata.len();
        if !params.validate_metadata_size(metadata_size) {
            return Ok(NftExecutionResult::failure(format!(
                "Metadata too large: {} bytes exceeds maximum of {} bytes",
                metadata_size, params.max_metadata_bytes
            )));
        }

        // Security: Validate storage fee (per-byte pricing)
        let required_fee = params.calculate_nft_storage_fee(metadata_size);
        if fee < required_fee {
            return Ok(NftExecutionResult::failure(format!(
                "Insufficient storage fee: {} required for {} bytes of metadata, got {}",
                required_fee, metadata_size, fee
            )));
        }

        // Security: For document minting, verify issuer is registered
        if is_document {
            let current_time = Self::now_ms(block_timestamp);

            if !Self::v_can_mint_documents(view, sender, None, current_time)? {
                warn!(
                    "Unauthorized document minting attempt by {} - not a registered issuer",
                    sender
                );
                return Ok(NftExecutionResult::failure(
                    "Sender is not a registered document issuer. Only verified issuers can mint certified documents.".to_string(),
                ));
            }

            debug!(
                "Verified issuer {} for document minting",
                sender
            );
        }

        let token_id = collection.next_token_id;

        // Create token data
        let token_data = NftTokenData {
            collection_id: *collection_id,
            token_id,
            owner: mint_data.to,
            creator: *sender,
            metadata: mint_data.metadata,
            is_document,
            uri_type: mint_data.uri_type,
            uri_value: mint_data.uri_value,
            approved: None,
            locked: false,
            transfer_count: 0,
            minted_at: Self::now_ms(block_timestamp),
        };

        // Store token
        Self::v_put_token(view, collection_id, token_id, &token_data)?;

        // Update indices
        Self::v_add_to_owner_index(view, &mint_data.to, collection_id, token_id)?;
        Self::v_add_to_collection_index(view, collection_id, token_id)?;

        // Update collection
        collection.total_supply += 1;
        collection.next_token_id += 1;
        Self::v_put_collection(view, collection_id, &collection)?;

        debug!(
            "Minted token {} in collection {:?} to {} (metadata: {} bytes, fee: {})",
            token_id,
            hex::encode(collection_id),
            mint_data.to,
            metadata_size,
            fee
        );

        Ok(NftExecutionResult::success_with_token(*collection_id, token_id))
    }

    /// Batch mint tokens
    #[allow(clippy::too_many_arguments)]
    fn execute_batch_mint(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        fee: Balance,
        block_timestamp: u64,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check minting permission
        if collection.owner_only_minting && collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Only collection owner can mint".to_string(),
            ));
        }

        // Deserialize batch mint data
        // Shared wire struct (issue #89)
        let batch_data: NftBatchMintData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid batch data: {}", e)))?;

        let count = batch_data.requests.len() as u64;

        // Check max supply
        if collection.max_supply > 0 && collection.total_supply + count > collection.max_supply {
            return Ok(NftExecutionResult::failure(
                "Batch would exceed max supply".to_string(),
            ));
        }

        // ACTIVATION-AUDIT row AL-9. The loop below calls
        // `v_add_to_owner_index` and `v_add_to_collection_index` once per
        // request, and each of those reads an accumulating index, appends one
        // entry and re-encodes the WHOLE of it. So the work this one
        // transaction does is QUADRATIC in a count the payload declares: with
        // `n` requests the owner index is rebuilt `n` times at an average size
        // of `n/2` entries. The count is checked here, before the first
        // rebuild, rather than being discovered when the candidate ceiling
        // refuses the write partway through -- by which time the quadratic work
        // has already been done and the whole block is unexecutable.
        if gates.allocation_bound && count as usize > MAX_NFT_BATCH_MINT_REQUESTS {
            return Ok(NftExecutionResult::failure(format!(
                "BatchMint of {count} tokens exceeds the limit of \
                 {MAX_NFT_BATCH_MINT_REQUESTS}"
            )));
        }

        // ACTIVATION-AUDIT row OV-10. `execute_mint` checks every token's
        // metadata against `max_metadata_bytes` and requires the fee to cover
        // `storage_fee_per_byte`; this arm, which writes the same field on any
        // number of tokens, checks neither. Both values are SET in the release
        // `genesis.json`.
        //
        // The fee is charged against the batch's TOTAL metadata bytes rather
        // than per request, which is what one mint of the same number of bytes
        // costs: `calculate_nft_storage_fee` is `min_fee` plus per-byte, so
        // summing per request would charge `min_fee` `n` times for a single
        // transaction. Each request's own metadata is still checked against the
        // size limit individually, because the limit is a per-row bound.
        if gates.update_path_parity {
            let mut total_metadata_bytes = 0usize;
            for request in &batch_data.requests {
                let size = request.metadata.len();
                if !params.validate_metadata_size(size) {
                    return Ok(NftExecutionResult::failure(format!(
                        "Metadata too large: {} bytes exceeds maximum of {} bytes",
                        size, params.max_metadata_bytes
                    )));
                }
                total_metadata_bytes = total_metadata_bytes.saturating_add(size);
            }
            let required_fee = params.calculate_nft_storage_fee(total_metadata_bytes);
            if fee < required_fee {
                return Ok(NftExecutionResult::failure(format!(
                    "Insufficient storage fee: {} required for {} bytes of metadata, got {}",
                    required_fee, total_metadata_bytes, fee
                )));
            }
        }

        let first_token_id = collection.next_token_id;

        for (i, request) in batch_data.requests.iter().enumerate() {
            let token_id = first_token_id + i as u64;

            let token_data = NftTokenData {
                collection_id: *collection_id,
                token_id,
                owner: request.to,
                creator: *sender,
                metadata: request.metadata.clone(),
                is_document: false,
                uri_type: "onchain".to_string(),
                uri_value: None,
                approved: None,
                locked: false,
                transfer_count: 0,
                minted_at: Self::now_ms(block_timestamp),
            };

            Self::v_put_token(view, collection_id, token_id, &token_data)?;
            Self::v_add_to_owner_index(view, &request.to, collection_id, token_id)?;
            Self::v_add_to_collection_index(view, collection_id, token_id)?;
        }

        // Update collection
        collection.total_supply += count;
        collection.next_token_id += count;
        Self::v_put_collection(view, collection_id, &collection)?;

        info!(
            "Batch minted {} tokens in collection {:?}",
            count,
            hex::encode(collection_id)
        );

        Ok(NftExecutionResult::success_with_token(
            *collection_id,
            first_token_id,
        ))
    }

    /// Transfer a token
    fn execute_transfer(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.transferable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow transfers".to_string(),
            ));
        }

        // Get token
        let token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership or approval
        let is_owner = token.owner == *sender;
        let is_approved = token.approved.as_ref() == Some(sender);

        if !is_owner && !is_approved {
            return Ok(NftExecutionResult::failure(
                "Not owner or approved".to_string(),
            ));
        }

        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Deserialize recipient
        // Shared wire struct (issue #89)
        let transfer_data: NftTransferData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        // Execute transfer
        Self::v_transfer_token(
            view,
            collection_id,
            token_id,
            &token.owner,
            &transfer_data.to,
        )?;

        debug!(
            "Transferred token {}:{} from {} to {}",
            hex::encode(collection_id),
            token_id,
            token.owner,
            transfer_data.to
        );

        Ok(NftExecutionResult::success())
    }

    /// Approve an address to transfer a token
    fn execute_approve(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
        token_authority_gate_open: bool,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // OV-14: below the gate this arm never reads the collection, so an
        // approval is recorded on a token in a collection that forbids
        // transfers -- an approval to do a thing the collection does not allow.
        // OV-13: `locked` is read by transfer and burn only, so a locked token
        // is still approvable. Both are the same question the transfer arm
        // already asks, asked here too.
        if token_authority_gate_open {
            let collection = Self::v_get_collection(view, collection_id)?
                .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;
            if !collection.transferable {
                return Ok(NftExecutionResult::failure(
                    "Collection does not allow transfers".to_string(),
                ));
            }
            if token.locked {
                return Ok(NftExecutionResult::failure("Token is locked".to_string()));
            }
        }

        // Deserialize approval data
        // Shared wire struct (issue #89)
        let approve_data: NftApproveData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid approve data: {}", e)))?;

        token.approved = approve_data.approved;
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Set approval for token {}:{} to {:?}",
            hex::encode(collection_id),
            token_id,
            approve_data.approved
        );

        Ok(NftExecutionResult::success())
    }

    /// Burn a token
    fn execute_burn(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        index_symmetry: bool,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.burnable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow burns".to_string(),
            ));
        }

        // Get token
        let token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        // Check if locked
        if token.locked {
            return Ok(NftExecutionResult::failure("Token is locked".to_string()));
        }

        // Burn token
        Self::v_burn_token(view, collection_id, token_id, &token.owner, index_symmetry)?;

        info!(
            "Burned token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Update token metadata
    #[allow(clippy::too_many_arguments)]
    fn execute_update_metadata(
        view: &mut ExecutionView<'_, '_>,
        params: &ChainParams,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
        data: &[u8],
        fee: Balance,
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        let token_authority_gate_open = gates.token_authority;
        // Get collection
        let collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        if !collection.metadata_updatable {
            return Ok(NftExecutionResult::failure(
                "Collection does not allow metadata updates".to_string(),
            ));
        }

        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Only owner or creator can update
        //
        // OV-12: `creator` is stamped at mint and never changes, so below the
        // gate the minter rewrites the metadata of a token it sold, for the life
        // of the token. OV-13: `locked` is read by transfer and burn only, so a
        // locked token's metadata is still rewritable. At and above the gate the
        // current owner, and nobody else, may rewrite, and a locked token
        // refuses.
        if token_authority_gate_open {
            if token.owner != *sender {
                return Ok(NftExecutionResult::failure("Not token owner".to_string()));
            }
            if token.locked {
                return Ok(NftExecutionResult::failure("Token is locked".to_string()));
            }
        } else if token.owner != *sender && token.creator != *sender {
            return Ok(NftExecutionResult::failure(
                "Not owner or creator".to_string(),
            ));
        }

        // ACTIVATION-AUDIT row OV-10. Below the gate this arm takes `data`
        // verbatim as the new metadata -- undecoded, with no size limit and no
        // per-byte fee -- while `execute_mint` checks both against the same
        // `ChainParams` values, which the release `genesis.json` sets.
        //
        // Checked here rather than at the top of the arm so that the pre-existing
        // ownership and lock refusals keep firing first: they are the more
        // specific answer and were the answer before this gate existed.
        if gates.update_path_parity {
            let metadata_size = data.len();
            if !params.validate_metadata_size(metadata_size) {
                return Ok(NftExecutionResult::failure(format!(
                    "Metadata too large: {} bytes exceeds maximum of {} bytes",
                    metadata_size, params.max_metadata_bytes
                )));
            }
            let required_fee = params.calculate_nft_storage_fee(metadata_size);
            if fee < required_fee {
                return Ok(NftExecutionResult::failure(format!(
                    "Insufficient storage fee: {} required for {} bytes of metadata, got {}",
                    required_fee, metadata_size, fee
                )));
            }
        }

        // Update metadata
        token.metadata = data.to_vec();
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Updated metadata for token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Transfer collection ownership
    fn execute_transfer_collection(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize new owner
        // Shared wire struct (issue #89)
        let transfer_data: NftTransferCollectionOwnershipData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid transfer data: {}", e)))?;

        collection.owner = transfer_data.new_owner;
        Self::v_put_collection(view, collection_id, &collection)?;

        info!(
            "Transferred collection {:?} ownership to {}",
            hex::encode(collection_id),
            transfer_data.new_owner
        );

        Ok(NftExecutionResult::success())
    }

    /// Update collection config
    fn execute_update_collection_config(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        data: &[u8],
        gates: NftGates,
    ) -> Result<NftExecutionResult> {
        // Get collection
        let mut collection = Self::v_get_collection(view, collection_id)?
            .ok_or_else(|| StateError::BlockValidation("Collection not found".to_string()))?;

        // Check ownership
        if collection.owner != *sender {
            return Ok(NftExecutionResult::failure(
                "Not collection owner".to_string(),
            ));
        }

        // Deserialize config update
        // Shared wire struct (issue #89)
        let update_data: NftUpdateCollectionConfigData = bincode::deserialize(data)
            .map_err(|e| StateError::BlockValidation(format!("Invalid config data: {}", e)))?;

        // ACTIVATION-AUDIT row RY-2, first half. Creation zeroes
        // `royalty_recipient` when `royalty_bps` is zero
        // (`execute_create_collection`); this arm has no such rule and sets one
        // anyway, so a collection that pays nothing carries a recipient the
        // RPC reports (`nft_getCollection`). At and above the gate the update
        // arm applies the creation arm's rule.
        //
        // A refusal rather than creation's silent zero, deliberately: a silent
        // zero here would be a paid no-op, which is the OV-30 shape this audit
        // files as a defect of its own. What the gate closes is the ASYMMETRY,
        // and telling the sender is the better side of it.
        //
        // The SECOND half of RY-2 is untouched and is not closable here:
        // `NftUpdateCollectionConfigData` has no `new_royalty_bps` field at
        // all, so a royalty still cannot be changed after creation. That is a
        // wire change.
        if let Some(recipient) = update_data.new_royalty_recipient {
            if gates.update_path_parity && collection.royalty_bps == 0 {
                return Ok(NftExecutionResult::failure(
                    "Collection pays no royalty, so it takes no royalty recipient".to_string(),
                ));
            }
            collection.royalty_recipient = recipient;
        }
        if let Some(uri) = update_data.new_base_uri {
            collection.base_uri = Some(uri);
        }

        Self::v_put_collection(view, collection_id, &collection)?;

        debug!(
            "Updated config for collection {:?}",
            hex::encode(collection_id)
        );

        Ok(NftExecutionResult::success())
    }

    /// Lock a token
    fn execute_lock_token(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if token.locked {
            return Ok(NftExecutionResult::failure(
                "Token already locked".to_string(),
            ));
        }

        token.locked = true;
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Locked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }

    /// Unlock a token
    fn execute_unlock_token(
        view: &mut ExecutionView<'_, '_>,
        sender: &Address,
        collection_id: &[u8; 32],
        token_id: u64,
    ) -> Result<NftExecutionResult> {
        // Get token
        let mut token = Self::v_get_token(view, collection_id, token_id)?
            .ok_or_else(|| StateError::BlockValidation("Token not found".to_string()))?;

        // Check ownership
        if token.owner != *sender {
            return Ok(NftExecutionResult::failure("Not token owner".to_string()));
        }

        if !token.locked {
            return Ok(NftExecutionResult::failure("Token not locked".to_string()));
        }

        token.locked = false;
        Self::v_put_token(view, collection_id, token_id, &token)?;

        debug!(
            "Unlocked token {}:{}",
            hex::encode(collection_id),
            token_id
        );

        Ok(NftExecutionResult::success())
    }
}

// FIXME: tests reference primitives fields removed during schema migration; gated until updated.
#[cfg(all(test, feature = "legacy_tests"))]
mod tests {
    use super::*;
    use sumchain_nft::collection::CollectionConfig;
    use sumchain_storage::candidate::CandidateExecution;
    use sumchain_storage::Database;
    use tempfile::TempDir;

    fn setup() -> (Database, ChainParams, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        let params = ChainParams::default();
        (db, params, dir)
    }

    #[test]
    fn test_create_collection() {
        let (db, _params, _dir) = setup();

        let sender = Address::from_hex("0x0000000000000000000000000000000000000001").unwrap();

        // Create collection data
        #[derive(serde::Serialize)]
        struct CreateData {
            name: String,
            symbol: String,
            description: String,
            config: CollectionConfig,
            base_uri: Option<String>,
        }

        let create_data = CreateData {
            name: "Test Collection".to_string(),
            symbol: "TEST".to_string(),
            description: "A test collection".to_string(),
            config: CollectionConfig::default(),
            base_uri: None,
        };

        let data = bincode::serialize(&create_data).unwrap();

        // The executor stages into a block candidate, so this opens one. It is
        // never published: the collection is read back through the candidate.
        let mut candidate = CandidateExecution::new(&db, 1 << 30);
        let mut view = candidate.view();

        let result =
            NftExecutor::execute_create_collection(&mut view, &sender, &data, 1_000_000_000)
                .unwrap();

        assert!(result.success);
        assert!(result.collection_id.is_some());

        // Verify collection exists
        let collection_id = result.collection_id.unwrap();
        let collection = NftExecutor::v_get_collection(&view, &collection_id)
            .unwrap()
            .unwrap();
        assert_eq!(collection.name, "Test Collection");
        assert_eq!(collection.symbol, "TEST");
        assert_eq!(collection.owner, sender);
    }
}
