//! Candidate execution as a typestate: execute, verify, then — and only then —
//! publish.
//!
//! The overlay makes a candidate branch abandonable. It does not, by itself,
//! make verification mandatory: anything holding the overlay can convert it into
//! a batch whenever it likes, including before comparing the computed state root
//! against the header's. That is the failure this module removes.
//!
//! ```text
//! CandidateExecution  --view()-->  ExecutionView   (execute here)
//!         |
//!      verify(computed, expected)
//!         |
//!         +-- Err  -> the candidate is CONSUMED and dropped: rollback
//!         |
//!         +-- Ok   -> VerifiedCandidate --into_batch()--> WriteBatch
//! ```
//!
//! [`ApplicationOverlay::into_batch`] is crate-private, so [`VerifiedCandidate`]
//! is the only way to reach a publishable batch from outside this crate. A
//! caller cannot publish an unverified candidate because there is no expression
//! that produces one — the ordering is carried by the types, not by a comment
//! asking callers to remember.
//!
//! [`CandidateExecution::verify`] takes `self` by value. A mismatch therefore
//! does not merely refuse publication: it destroys the candidate, and since the
//! overlay never wrote anything, that is a complete rollback with nothing to
//! undo.
//!
//! Execution helpers receive `&mut ExecutionView` and never the candidate, so
//! nothing reachable from execution can verify or publish.
//!
//! # There is no two-operand comparison
//!
//! An earlier version exposed `verify(computed, expected)`. That call proved a
//! comparison had occurred and nothing else: `verify(h, h)` was well-typed and
//! succeeded, so a caller could read the header, pass its root as both sides,
//! and satisfy every type in the chain while verifying nothing.
//!
//! [`CandidateExecution::verify_for_block`] is the only verification path. It
//! takes the block and reads the expected root from `block.header.state_root`
//! itself, so there is no second operand to supply. The forgeable form was
//! deleted rather than hidden — a crate-private version would still have been
//! reachable from every future caller inside this crate.

use sumchain_primitives::{Block, BlockHeight, Hash};

use crate::db::{cf, Database};
use crate::exec_view::ExecutionView;
use crate::overlay::ApplicationOverlay;
use crate::{Result, StorageError};

/// A block being executed against buffered state. Nothing here has touched the
/// database.
pub struct CandidateExecution<'db> {
    overlay: ApplicationOverlay<'db>,
}

/// A candidate whose computed state root matched the expected one. The only
/// type that can produce a publishable batch.
pub struct VerifiedCandidate<'db> {
    overlay: ApplicationOverlay<'db>,
    root: Hash,
    block_hash: Hash,
    height: BlockHeight,
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

    /// Verify a candidate against the block it was executed for.
    ///
    /// The expected root is read from `block.header.state_root` here, not
    /// received, so a caller has no second operand to supply. `computed` must
    /// come from execution; that it does is the orchestration entry point's
    /// responsibility, and is why this is the only public verification path.
    ///
    /// The resulting candidate remembers which block it belongs to, so
    /// publication can refuse a transition describing a different one.
    pub fn verify_for_block(
        self,
        block: &Block,
        computed: Hash,
    ) -> Result<VerifiedCandidate<'db>> {
        let declared = block.header.state_root;
        if computed != declared {
            return Err(StorageError::InvalidData(format!(
                "candidate state root mismatch for block {} at height {}: computed \
                 {computed}, header declares {declared}; discarding without publishing",
                block.hash(),
                block.height()
            )));
        }
        Ok(VerifiedCandidate {
            overlay: self.overlay,
            root: computed,
            block_hash: block.hash(),
            height: block.height(),
        })
    }
}

impl<'db> VerifiedCandidate<'db> {
    /// The verified root, for the caller to record alongside the published state.
    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Publish this candidate as the canonical chain state.
    ///
    /// Takes a complete [`CanonicalTransition`]. There is no partial form and no
    /// builder: the previous design recorded which *methods* had been called,
    /// which `with_journals(&[])` and `with_head(&[])` satisfied while supplying
    /// nothing, and let the accumulator be written to an arbitrary column family
    /// and key. Those are not mistakes a reviewer reliably catches, so the type
    /// no longer permits them.
    pub fn publish(self, transition: CanonicalTransition) -> Result<()> {
        if transition.block_hash != self.block_hash {
            return Err(StorageError::InvalidData(format!(
                "transition describes block {} but the verified candidate is block {}",
                transition.block_hash, self.block_hash
            )));
        }
        if transition.height != self.height {
            return Err(StorageError::InvalidData(format!(
                "transition is at height {} but the verified candidate is at height {}",
                transition.height, self.height
            )));
        }
        if transition.accumulator != self.root {
            return Err(StorageError::InvalidData(format!(
                "transition accumulator {} does not match the verified root {}",
                transition.accumulator, self.root
            )));
        }

        let mut batch = self.overlay.into_batch()?;

        // Journal keys are derived here, from the transition's own block, so a
        // caller cannot write an undo record under a key nothing will look for.
        let jkey = crate::schema::journal_key(transition.height, &transition.block_hash);
        for (cf_name, record) in [
            (cf::STATE_DIFFS, &transition.account_journal),
            (cf::CONTRACT_STATE_DIFFS, &transition.contract_journal),
            (cf::COMPUTE_POOL_STATE_DIFFS, &transition.compute_pool_journal),
            (cf::BEACON_STATE_DIFFS, &transition.beacon_journal),
        ] {
            match record {
                JournalRecord::Recorded(bytes) => batch.put(cf_name, &jkey, bytes)?,
                // Explicitly empty: this block mutated nothing in that family, so
                // there is nothing to unwind. Distinct from "no journal was
                // supplied", which is now unrepresentable.
                JournalRecord::NothingToUndo => {}
            }
        }

        batch.put(cf::META, ACCUMULATOR_KEY, transition.accumulator.as_bytes())?;
        batch.put(cf::META, ACTIVATION_VERSION_KEY, &transition.activation_version.to_be_bytes())?;
        batch.put(
            cf::META,
            crate::schema::meta_keys::LATEST_BLOCK_HASH,
            transition.block_hash.as_bytes(),
        )?;
        batch.put(
            cf::META,
            crate::schema::meta_keys::LATEST_BLOCK_HEIGHT,
            &transition.height.to_be_bytes(),
        )?;
        batch.put(cf::BLOCKS, transition.block_hash.as_bytes(), &transition.block_bytes)?;

        batch.commit()
    }
}

/// Where the chained accumulator lives. Fixed, not caller-chosen.
pub const ACCUMULATOR_KEY: &[u8] = b"state_accumulator";
/// Where the activation version lives. Fixed, not caller-chosen.
pub const ACTIVATION_VERSION_KEY: &[u8] = b"activation_version";

/// One block's undo journal for one state family.
///
/// `NothingToUndo` is a positive statement, not an omission: the block mutated
/// nothing in that family. Making it a variant rather than an empty slice is the
/// point — an empty `Vec` is indistinguishable from a caller who forgot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecord {
    Recorded(Vec<u8>),
    NothingToUndo,
}

/// A complete canonical state transition.
///
/// Every field is private and there is one constructor taking all of them, so a
/// partially-specified transition cannot be built. Column families and keys are
/// derived internally from the block; callers supply records, never locations.
pub struct CanonicalTransition {
    block_hash: Hash,
    height: BlockHeight,
    block_bytes: Vec<u8>,
    accumulator: Hash,
    activation_version: u32,
    account_journal: JournalRecord,
    contract_journal: JournalRecord,
    compute_pool_journal: JournalRecord,
    beacon_journal: JournalRecord,
}

impl CanonicalTransition {
    /// Describe the transition `block` produces.
    ///
    /// All four journals are required as explicit values. A family that changed
    /// nothing is `JournalRecord::NothingToUndo`, which is a statement; there is
    /// no way to simply not mention it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block: &Block,
        block_bytes: Vec<u8>,
        accumulator: Hash,
        activation_version: u32,
        account_journal: JournalRecord,
        contract_journal: JournalRecord,
        compute_pool_journal: JournalRecord,
        beacon_journal: JournalRecord,
    ) -> Self {
        Self {
            block_hash: block.hash(),
            height: block.height(),
            block_bytes,
            accumulator,
            activation_version,
            account_journal,
            contract_journal,
            compute_pool_journal,
            beacon_journal,
        }
    }

    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }
    pub fn height(&self) -> BlockHeight {
        self.height
    }
    pub fn accumulator(&self) -> Hash {
        self.accumulator
    }
}
