//! Candidate execution as a typestate: execute, accept, then — and only then —
//! publish.
//!
//! The overlay makes a candidate branch abandonable. It does not, by itself,
//! make acceptance mandatory: anything holding the overlay could convert it into
//! a batch whenever it liked. That is the failure this module removes.
//!
//! ```text
//! CandidateExecution  --view()-->  ExecutionView   (execute here)
//!         |
//!    finish_execution(computed_root)     <- binds execution's own accumulator
//!         |
//!   ExecutedCandidate
//!         |
//!    accept_produced(&block) | accept_imported(&block)
//!         |
//!         +-- Err  -> the candidate is CONSUMED and dropped: rollback
//!         |
//!         +-- Ok   -> AcceptedCandidate --publish(transition)--> committed
//! ```
//!
//! [`ApplicationOverlay::into_batch`] is crate-private, so [`AcceptedCandidate`]
//! is the only way to reach a publishable batch from outside this crate. An
//! UNACCEPTED candidate cannot publish: there is no expression that produces a
//! batch from one, so the ordering is carried by the types rather than by a
//! comment asking callers to remember.
//!
//! Acceptance takes `self` by value. A rejection therefore does not merely
//! refuse publication: it destroys the candidate, and since the overlay never
//! wrote anything, that is a complete rollback with nothing to undo.
//!
//! Execution helpers receive `&mut ExecutionView` and never the candidate, so
//! nothing reachable from execution can accept or publish.
//!
//! # Acceptance cannot be handed a root
//!
//! An earlier version exposed `verify(computed, expected)` taking two
//! caller-supplied hashes, so `verify(h, h)` succeeded. Replacing it with a
//! single `computed` parameter was not enough either: a caller could still pass
//! `block.header.state_root` and manufacture acceptance without using
//! execution's result at all.
//!
//! So the accumulator is BOUND rather than supplied.
//! [`CandidateExecution::finish_execution`] is the only exit from execution and
//! carries the computed root into [`ExecutedCandidate`]; the acceptance methods
//! take only `&Block`. There is no `Hash` parameter for a caller to fill in.
//!
use sumchain_primitives::{Block, BlockHeight, Hash, Receipt};

use crate::db::{cf, Database};
use crate::exec_view::ExecutionView;
use crate::overlay::ApplicationOverlay;
use crate::{Result, StorageError};

/// A block being executed against buffered state. Nothing here has touched the
/// database.
pub struct CandidateExecution<'db> {
    overlay: ApplicationOverlay<'db>,
}

impl<'db> CandidateExecution<'db> {
    /// Begin executing a candidate against `db`, buffering up to `limit`
    /// logical write-set bytes.
    ///
    /// `limit` is explicit because it is a versioned consensus parameter derived
    /// from measured write sets — a ceiling that can refuse a write participates
    /// in deciding whether a block is applicable. It is not defaulted here.
    pub fn new(db: &'db Database, limit: u64) -> Self {
        Self {
            overlay: ApplicationOverlay::new(db, limit),
        }
    }

    /// The handle execution reads and writes through.
    pub fn view(&mut self) -> ExecutionView<'_, 'db> {
        ExecutionView::new(&mut self.overlay)
    }

    /// Logical write-set bytes buffered so far.
    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.overlay.is_empty()
    }

    /// Conclude execution, binding everything it produced to the candidate.
    ///
    /// This is the only way to leave `CandidateExecution`, and the subject, the
    /// accumulator, the receipts and all four journals travel with the buffered
    /// writes from here on.
    ///
    /// It is `pub` because `sumchain-state` calls it across a crate boundary, so
    /// visibility cannot confine it to one call site. What confines it is the
    /// source guard in `execution_boundary.rs`, which fails on a second call
    /// site, together with `BlockExecution` being opaque so a candidate can only
    /// reach a caller through `execute_block`. Neither is a language-level
    /// guarantee, and this comment says so rather than letting the shape imply
    /// one. Acceptance and publication therefore take no artifacts: a caller
    /// cannot hand them a root, a receipt set, or a journal, and in particular
    /// cannot substitute artifacts from somewhere other than this execution.
    ///
    /// Binding the receipts matters beyond their hashes. Pairing each receipt to
    /// its transaction by hash catches a reordered or missing set, but not an
    /// altered `status` or `fee_paid` — and those are hashed into the
    /// accumulator, so a substituted set publishes receipts that disagree with
    /// the root the same block committed to.
    pub fn finish_execution(
        self,
        subject: ExecutionSubject,
        computed_root: Hash,
        receipts: Vec<Receipt>,
        journals: BlockJournals,
    ) -> ExecutedCandidate<'db> {
        ExecutedCandidate {
            overlay: self.overlay,
            subject,
            computed_root,
            receipts,
            journals,
        }
    }
}

/// A candidate whose execution is complete, carrying everything it produced.
///
/// The accumulator, receipts and journals are bound, not supplied. Nothing
/// downstream accepts them as parameters.
pub struct ExecutedCandidate<'db> {
    overlay: ApplicationOverlay<'db>,
    /// The block this execution was performed for.
    subject: ExecutionSubject,
    computed_root: Hash,
    receipts: Vec<Receipt>,
    journals: BlockJournals,
}

impl<'db> ExecutedCandidate<'db> {
    /// The accumulator execution produced.
    pub fn computed_root(&self) -> Hash {
        self.computed_root
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// The journals execution produced. READ-ONLY, like [`receipts`](Self::receipts):
    /// a shared reference can be inspected but not substituted, so a caller
    /// cannot swap in an undo record for a block it did not execute.
    pub fn journals(&self) -> &BlockJournals {
        &self.journals
    }

    /// The receipts execution produced. READ-ONLY: a shared slice cannot be
    /// substituted, only inspected. Exists so the not-yet-migrated PoA paths can
    /// still write receipts directly until publication is wired.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Check the bound receipts pair with the block's transactions.
    ///
    /// `RECEIPTS` is keyed by transaction hash, so a mispaired set writes a
    /// receipt under a transaction it does not describe, and the row looks
    /// perfectly well-formed afterwards.
    /// The block presented at acceptance must be the block that was executed.
    fn check_subject(&self, block: &Block) -> Result<()> {
        let presented = ExecutionSubject::of(block)?;
        if let Some(field) = self.subject.first_difference(&presented) {
            return Err(StorageError::InvalidData(format!(
                "block {} at height {} differs from the block this candidate was \
                 executed for, in its {field}; refusing to publish an execution \
                 against a different block",
                block.hash(),
                block.height()
            )));
        }
        Ok(())
    }

    fn check_receipts(&self, block: &Block) -> Result<()> {
        let txs = &block.transactions;
        if self.receipts.len() != txs.len() {
            return Err(StorageError::InvalidData(format!(
                "block {} at height {} has {} transactions but execution bound {} \
                 receipts; a canonical transition carries exactly one per transaction",
                block.hash(),
                block.height(),
                txs.len(),
                self.receipts.len()
            )));
        }
        for (i, (tx, receipt)) in txs.iter().zip(self.receipts.iter()).enumerate() {
            let expected = tx.hash();
            if receipt.tx_hash != expected {
                return Err(StorageError::InvalidData(format!(
                    "receipt {i} describes transaction {} but block {} carries {} at that \
                     position; receipts must pair with transactions in block order",
                    receipt.tx_hash,
                    block.hash(),
                    expected
                )));
            }
        }
        Ok(())
    }

    /// Accept a candidate the node PRODUCED.
    ///
    /// The proposer computes the accumulator and writes it into the header it is
    /// about to sign, so there is no independent value to check it against — a
    /// comparison here is of a number with itself. This is acceptance by
    /// construction, and the evidence says so: [`Acceptance::Produced`], never
    /// `ExactRoot`.
    pub fn accept_produced<'a>(self, block: &'a Block) -> Result<AcceptedCandidate<'db, 'a>> {
        if block.header.state_root != self.computed_root {
            return Err(StorageError::InvalidData(format!(
                "producer bug: block {} at height {} carries header root {} but its own \
                 execution produced {}; refusing to publish",
                block.hash(),
                block.height(),
                block.header.state_root,
                self.computed_root
            )));
        }
        self.check_subject(block)?;
        self.check_receipts(block)?;
        let accumulator = self.computed_root;
        Ok(self.into_accepted(block, accumulator, Acceptance::Produced))
    }

    /// Accept — or reject — a candidate the node IMPORTED.
    ///
    /// Both sides of the comparison are owned here: the expected root is read
    /// from `block.header.state_root`, the computed root was bound at execution
    /// completion. The caller supplies only the block.
    ///
    /// The cutoff is internal. A caller-supplied height, or worse a boolean,
    /// would let any call site opt into force-adoption.
    pub fn accept_imported<'a>(self, block: &'a Block) -> Result<AcceptedCandidate<'db, 'a>> {
        self.check_subject(block)?;
        self.check_receipts(block)?;
        let header = block.header.state_root;
        let computed = self.computed_root;
        let height = block.height();

        if computed == header {
            return Ok(self.into_accepted(block, computed, Acceptance::ExactRoot));
        }
        if height <= LEGACY_ROOT_COMPATIBILITY_HEIGHT {
            // Adopt the header's root so the accumulator stays aligned for the
            // next block, exactly as the existing PoA path does. NOT a
            // verification.
            return Ok(self.into_accepted(
                block,
                header,
                Acceptance::LegacyCompatibility { computed, header },
            ));
        }
        Err(StorageError::InvalidData(format!(
            "state root mismatch at height {height}: header={header}, computed={computed}; \
             discarding the candidate without publishing"
        )))
    }

    fn into_accepted<'a>(
        self,
        block: &'a Block,
        accumulator: Hash,
        acceptance: Acceptance,
    ) -> AcceptedCandidate<'db, 'a> {
        AcceptedCandidate {
            overlay: self.overlay,
            accumulator,
            block,
            acceptance,
            receipts: self.receipts,
            journals: self.journals,
        }
    }
}

/// The block an execution was performed FOR, normalized.
///
/// Binding the accumulator, receipts and journals proves they came from an
/// execution. It does not prove they came from an execution of THIS block: a
/// candidate executed for block A could be accepted against a block B that
/// keeps A's transactions and computed root while changing its height, parent,
/// timestamp or proposer. Every one of those is consensus-relevant, and the
/// resulting publication would store B's header beside A's state.
///
/// So the subject is captured before execution and compared at acceptance.
///
/// Covers every header field and the exact transaction bytes in order. Excludes
/// exactly two, both derived AFTER the execution being described:
///
/// * `state_root` — computed by the execution itself; on the produce path the
///   proposer writes it into the header afterwards, so requiring it to match
///   here would make the subject uncapturable before execution.
/// * `proposer_sig` — applied after the root is filled in.
///
/// Transactions are bound by a domain-separated commitment rather than by a copy
/// of their bytes. An earlier version kept a `Vec<Vec<u8>>` of every serialized
/// transaction — a second copy of the block's entire payload, held outside the
/// overlay's checked limit, which is the same unaccounted duplication removed
/// from the publication path. The commitment is 32 bytes regardless of block
/// size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSubject {
    parent_hash: Hash,
    height: BlockHeight,
    timestamp: u64,
    tx_root: Hash,
    proposer_pubkey: [u8; 32],
    /// Domain-separated commitment over the canonical serialization of the whole
    /// transaction vector. Binds count, order, contents and signatures together,
    /// because all of them are inside that serialization.
    transactions: Hash,
}

/// Domain separator for the transaction commitment.
///
/// Without it the digest is just "blake3 of some bincode", and a value computed
/// over a different structure that happens to serialize identically would
/// collide with it. The tag makes the commitment mean this and nothing else.
const SUBJECT_TX_DOMAIN: &[u8] = b"sumchain.execution_subject.transactions.v1";

impl ExecutionSubject {
    /// Capture the subject of an execution about to be performed for `block`.
    ///
    /// The transaction vector is serialized STRAIGHT INTO the hasher —
    /// `blake3::Hasher` implements `io::Write` — so no intermediate buffer of
    /// the block's payload is ever allocated. No `to_bytes()`, no `collect()`,
    /// no block-sized temporary.
    pub fn of(block: &Block) -> Result<Self> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SUBJECT_TX_DOMAIN);
        bincode::serialize_into(&mut hasher, &block.transactions)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        Ok(Self {
            parent_hash: block.header.parent_hash,
            height: block.header.height,
            timestamp: block.header.timestamp,
            tx_root: block.header.tx_root,
            proposer_pubkey: block.header.proposer_pubkey,
            transactions: Hash::new(*hasher.finalize().as_bytes()),
        })
    }

    /// The first field that differs, so an error names the discrepancy instead
    /// of saying only "mismatch".
    fn first_difference(&self, other: &Self) -> Option<&'static str> {
        if self.height != other.height {
            return Some("height");
        }
        if self.parent_hash != other.parent_hash {
            return Some("parent hash");
        }
        if self.timestamp != other.timestamp {
            return Some("timestamp");
        }
        if self.proposer_pubkey != other.proposer_pubkey {
            return Some("proposer");
        }
        if self.tx_root != other.tx_root {
            return Some("transaction root");
        }
        if self.transactions != other.transactions {
            // One commitment covers count, order, bytes and signatures; which of
            // them changed is not recoverable from the digest, and saying so is
            // better than naming a specific cause the digest cannot identify.
            return Some("transactions (count, order, contents or signatures)");
        }
        None
    }
}

/// The historical compatibility window. A mismatch at or below this height is
/// force-adopted rather than refused.
///
/// A consensus rule, reproduced unchanged from PoA so both acceptance paths can
/// share one publisher. This module does not decide whether it should exist —
/// the P1 design replaces it with an exact allowlist of verified canonical
/// records. Until that lands, removing or widening it here would be a consensus
/// change.
pub const LEGACY_ROOT_COMPATIBILITY_HEIGHT: BlockHeight = 496_720;

/// Why a candidate was accepted. Distinct variants because they are not the same
/// claim, and collapsing them would let a force-adopted mismatch be reported as
/// a verified root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acceptance {
    /// This node produced the block; the header root is what its own execution
    /// computed. Acceptance by construction, not by comparison.
    Produced,
    /// An imported block whose header root equals the computed root.
    ExactRoot,
    /// An imported block at or below [`LEGACY_ROOT_COMPATIBILITY_HEIGHT`] whose
    /// roots disagree. The HEADER's root is published. A compatibility
    /// allowance, not a verification.
    LegacyCompatibility { computed: Hash, header: Hash },
}

impl Acceptance {
    /// Whether the published accumulator was actually checked against execution.
    pub fn is_verified(&self) -> bool {
        matches!(self, Acceptance::ExactRoot)
    }
}

/// One block's undo journal for one state family.
///
/// `NothingToUndo` is a positive statement, not an omission: the block mutated
/// nothing in that family. A variant rather than an empty slice, because an
/// empty `Vec` is indistinguishable from a caller who forgot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    Recorded(Vec<u8>),
    NothingToUndo,
}

/// All four per-block undo journals.
///
/// A struct with four required fields rather than four parameters: every family
/// must be named, so a block cannot silently omit one, and the set travels as a
/// unit from execution to publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockJournals {
    pub account: JournalRecord,
    pub contract: JournalRecord,
    pub compute_pool: JournalRecord,
    pub beacon: JournalRecord,
}

/// A candidate accepted for publication, carrying the evidence for why and every
/// artifact its execution produced.
///
/// Named for what it is. The earlier name, `VerifiedCandidate`, would have been
/// a lie for the legacy branch: a force-adopted mismatch is accepted, not
/// verified, and a type that says otherwise makes the dishonesty invisible at
/// every call site.
pub struct AcceptedCandidate<'db, 'a> {
    overlay: ApplicationOverlay<'db>,
    accumulator: Hash,
    block: &'a Block,
    acceptance: Acceptance,
    receipts: Vec<Receipt>,
    journals: BlockJournals,
}

impl std::fmt::Debug for AcceptedCandidate<'_, '_> {
    /// Omits the overlay: a buffered write set is block-controlled and large,
    /// and a panic message is not the place for it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedCandidate")
            .field("block_hash", &self.block.hash())
            .field("height", &self.block.height())
            .field("accumulator", &self.accumulator)
            .field("acceptance", &self.acceptance)
            .finish_non_exhaustive()
    }
}

impl<'db, 'a> AcceptedCandidate<'db, 'a> {
    /// The accumulator that will be published — the computed root, except on the
    /// legacy branch where it is the header's.
    pub fn accumulator(&self) -> Hash {
        self.accumulator
    }

    pub fn acceptance(&self) -> &Acceptance {
        &self.acceptance
    }

    pub fn block_hash(&self) -> Hash {
        self.block.hash()
    }

    pub fn height(&self) -> BlockHeight {
        self.block.height()
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Publish this candidate as the canonical chain state.
    ///
    /// THE ONLY publication function, and it takes no artifacts. Every record it
    /// writes is derived from the block and the receipts and journals bound at
    /// execution completion, so there is no parameter through which a caller
    /// could substitute a different outcome, fee, or undo record.
    ///
    /// Writes the COMPLETE canonical set in one batch: state rows, block by hash
    /// and by height, every transaction, every receipt, both address indexes,
    /// all four journals, and the latest-head metadata. Records are staged
    /// through the overlay, so block-derived rows are charged against the same
    /// logical ceiling as execution's, and conversion to a RocksDB batch happens
    /// only once every one has been accepted.
    pub fn publish(mut self) -> Result<()> {
        let block = self.block;
        let block_hash = block.hash();
        let height = block.height();

        // ── stage every canonical record through the overlay ────────────────
        self.overlay
            .put(cf::BLOCKS, block_hash.as_bytes(), &block.to_bytes())?;
        self.overlay.put(
            cf::BLOCK_HEIGHT,
            &height.to_be_bytes(),
            block_hash.as_bytes(),
        )?;

        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let tx_index = u32::try_from(tx_index).map_err(|_| {
                StorageError::InvalidData("transaction index exceeds u32".to_string())
            })?;
            let tx_hash = tx.hash();
            self.overlay
                .put(cf::TRANSACTIONS, tx_hash.as_bytes(), &tx.to_bytes())?;
            self.overlay.put(
                cf::TX_BY_SENDER,
                &crate::schema::TxIndexStore::sender_key(&tx.sender(), height, tx_index),
                tx_hash.as_bytes(),
            )?;
            // Conditional, matching `index_transaction`'s own `if let Some`.
            if let Some(recipient) = tx.recipient() {
                self.overlay.put(
                    cf::TX_BY_RECIPIENT,
                    &crate::schema::TxIndexStore::recipient_key(&recipient, height, tx_index),
                    tx_hash.as_bytes(),
                )?;
            }
        }

        // `Receipt::to_bytes`, the same call `ReceiptStore::put` makes.
        // Re-deriving the encoding would duplicate the contract and let the two
        // drift apart silently.
        for receipt in &self.receipts {
            self.overlay.put(
                cf::RECEIPTS,
                receipt.tx_hash.as_bytes(),
                &receipt.to_bytes(),
            )?;
        }

        let jkey = crate::schema::journal_key(height, &block_hash);
        for (cf_name, record) in [
            (cf::STATE_DIFFS, &self.journals.account),
            (cf::CONTRACT_STATE_DIFFS, &self.journals.contract),
            (cf::COMPUTE_POOL_STATE_DIFFS, &self.journals.compute_pool),
            (cf::BEACON_STATE_DIFFS, &self.journals.beacon),
        ] {
            if let JournalRecord::Recorded(bytes) = record {
                self.overlay.put(cf_name, &jkey, bytes)?;
            }
        }

        self.overlay.put(
            cf::META,
            crate::schema::meta_keys::LATEST_BLOCK_HASH,
            block_hash.as_bytes(),
        )?;
        self.overlay.put(
            cf::META,
            crate::schema::meta_keys::LATEST_BLOCK_HEIGHT,
            &height.to_be_bytes(),
        )?;

        self.overlay.into_batch()?.commit()?;

        // ── only now, with the commit durable, report the adoption ───────────
        //
        // After the commit, never before. A warning emitted at acceptance would
        // announce that a block's header root was adopted even when staging or
        // the commit then failed and nothing was published — an operator reading
        // logs would believe unverified state had entered the chain when it had
        // not. One line per published block, carrying both roots so the
        // divergence is recoverable.
        if let Acceptance::LegacyCompatibility { computed, header } = &self.acceptance {
            tracing::warn!(
                height,
                block = %block_hash,
                computed_root = %computed,
                published_root = %header,
                cutoff = LEGACY_ROOT_COMPATIBILITY_HEIGHT,
                "published a block whose computed root does not match its header, under the \
                 historical compatibility allowance; the header's root was adopted and this \
                 block's state is NOT verified"
            );
        }
        Ok(())
    }
}
