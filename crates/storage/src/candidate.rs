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

    /// Conclude execution, binding the accumulator it produced to the candidate.
    ///
    /// This is the ONLY way to leave `CandidateExecution`, and the computed root
    /// travels with the buffered writes from here on. Acceptance therefore has
    /// no `Hash` parameter: a caller cannot hand it a number, and in particular
    /// cannot hand it the header's own root, which is how an earlier version of
    /// this API could be made to accept anything.
    pub fn finish_execution(self, computed_root: Hash) -> ExecutedCandidate<'db> {
        ExecutedCandidate {
            overlay: self.overlay,
            computed_root,
        }
    }
}

/// A candidate whose execution is complete, carrying the accumulator execution
/// produced.
///
/// The root is bound, not supplied. Every acceptance decision below compares the
/// block's header against THIS value, and nothing else can be substituted.
pub struct ExecutedCandidate<'db> {
    overlay: ApplicationOverlay<'db>,
    computed_root: Hash,
}

impl<'db> ExecutedCandidate<'db> {
    /// The accumulator execution produced.
    pub fn computed_root(&self) -> Hash {
        self.computed_root
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Accept a candidate the node PRODUCED.
    ///
    /// The proposer computes the accumulator and writes it into the header it is
    /// about to sign, so there is no independent value to check it against — a
    /// comparison here is of a number with itself. This is acceptance by
    /// construction, and the evidence says so: [`Acceptance::Produced`], never
    /// `ExactRoot`.
    ///
    /// The equality is still asserted, because a header disagreeing with the
    /// execution that produced it means the producer is broken, and publishing
    /// would propagate the break.
    pub fn accept_produced(self, block: &Block) -> Result<AcceptedCandidate<'db>> {
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
        Ok(AcceptedCandidate {
            overlay: self.overlay,
            accumulator: self.computed_root,
            block_hash: block.hash(),
            height: block.height(),
            acceptance: Acceptance::Produced,
        })
    }

    /// Accept — or reject — a candidate the node IMPORTED.
    ///
    /// Both sides of the comparison are owned here: the expected root is read
    /// from `block.header.state_root`, and the computed root was bound by
    /// [`CandidateExecution::finish_execution`]. The caller supplies only the
    /// block.
    ///
    /// Three outcomes, distinguished by the returned evidence:
    ///
    /// * roots equal  -> [`Acceptance::ExactRoot`]
    /// * mismatch at or below [`LEGACY_ROOT_COMPATIBILITY_HEIGHT`] ->
    ///   [`Acceptance::LegacyCompatibility`], publishing the HEADER's
    ///   accumulator, preserving existing PoA behaviour exactly
    /// * mismatch above it -> the candidate is consumed and rejected
    ///
    /// The cutoff is internal. A caller-supplied height, or worse a boolean,
    /// would let any call site opt into force-adoption.
    pub fn accept_imported(self, block: &Block) -> Result<AcceptedCandidate<'db>> {
        let header = block.header.state_root;
        let computed = self.computed_root;
        let height = block.height();

        if computed == header {
            return Ok(AcceptedCandidate {
                overlay: self.overlay,
                accumulator: computed,
                block_hash: block.hash(),
                height,
                acceptance: Acceptance::ExactRoot,
            });
        }

        if height <= LEGACY_ROOT_COMPATIBILITY_HEIGHT {
            // Preserves pre-existing behaviour: adopt the header's root so the
            // accumulator stays aligned for the next block. NOT a verification.
            return Ok(AcceptedCandidate {
                overlay: self.overlay,
                accumulator: header,
                block_hash: block.hash(),
                height,
                acceptance: Acceptance::LegacyCompatibility { computed, header },
            });
        }

        Err(StorageError::InvalidData(format!(
            "state root mismatch at height {height}: header={header}, computed={computed}; \
             discarding the candidate without publishing"
        )))
    }
}

/// The historical compatibility window. A mismatch at or below this height is
/// force-adopted rather than refused.
///
/// This is a consensus rule, reproduced here unchanged from PoA so that both
/// acceptance paths can share one publisher. It is not new, and this module does
/// not decide whether it should exist — the P1 design replaces it with an exact
/// allowlist of verified canonical records. Until that lands, removing or
/// widening it here would be a consensus change.
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
    /// roots disagree. The HEADER's root is published. This is a compatibility
    /// allowance, not a verification.
    LegacyCompatibility { computed: Hash, header: Hash },
}

impl Acceptance {
    /// Whether the published accumulator was actually checked against execution.
    pub fn is_verified(&self) -> bool {
        matches!(self, Acceptance::ExactRoot)
    }
}

/// A candidate accepted for publication, carrying the evidence for why.
///
/// Named for what it is. The earlier name, `VerifiedCandidate`, would have been
/// a lie for the legacy branch: a force-adopted mismatch is accepted, not
/// verified, and a type that says otherwise makes the dishonesty invisible at
/// every call site.
impl std::fmt::Debug for AcceptedCandidate<'_> {
    /// Deliberately omits the overlay: a candidate's buffered write set can be
    /// large and block-controlled, and a panic message is not the place for it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptedCandidate")
            .field("block_hash", &self.block_hash)
            .field("height", &self.height)
            .field("accumulator", &self.accumulator)
            .field("acceptance", &self.acceptance)
            .finish_non_exhaustive()
    }
}

pub struct AcceptedCandidate<'db> {
    overlay: ApplicationOverlay<'db>,
    accumulator: Hash,
    block_hash: Hash,
    height: BlockHeight,
    acceptance: Acceptance,
}

impl<'db> AcceptedCandidate<'db> {
    /// The accumulator that will be published — the computed root, except on the
    /// legacy branch where it is the header's.
    pub fn accumulator(&self) -> Hash {
        self.accumulator
    }

    pub fn acceptance(&self) -> &Acceptance {
        &self.acceptance
    }

    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Publish this candidate as the canonical chain state.
    ///
    /// THE ONLY publication function. Both acceptance paths — produced and
    /// imported, including the legacy compatibility branch — converge here, so
    /// there is exactly one place where buffered state becomes canonical and
    /// exactly one set of completeness rules to satisfy.
    ///
    /// Takes a complete [`CanonicalTransition`]: state rows, all four journals,
    /// accumulator, activation version and canonical-head metadata, in one
    /// batch. There is no partial form and no builder.
    pub fn publish(self, transition: CanonicalTransition) -> Result<()> {
        if transition.block_hash != self.block_hash {
            return Err(StorageError::InvalidData(format!(
                "transition describes block {} but the accepted candidate is block {}",
                transition.block_hash, self.block_hash
            )));
        }
        if transition.height != self.height {
            return Err(StorageError::InvalidData(format!(
                "transition is at height {} but the accepted candidate is at height {}",
                transition.height, self.height
            )));
        }
        if transition.accumulator != self.accumulator {
            return Err(StorageError::InvalidData(format!(
                "transition accumulator {} does not match the accepted accumulator {}",
                transition.accumulator, self.accumulator
            )));
        }

        // Bounded diagnostic: one line per legacy-branch publication, carrying
        // both roots so the divergence is recoverable from logs. Deliberately
        // not per-row and not repeated — this fires once per block, and only in
        // the compatibility window.
        if let Acceptance::LegacyCompatibility { computed, header } = &self.acceptance {
            tracing::warn!(
                height = self.height,
                block = %self.block_hash,
                computed_root = %computed,
                published_root = %header,
                cutoff = LEGACY_ROOT_COMPATIBILITY_HEIGHT,
                "publishing a block whose computed root does not match its header, under the \
                 historical compatibility allowance; the header's root is adopted and this \
                 block's state is NOT verified"
            );
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
                JournalRecord::NothingToUndo => {}
            }
        }

        batch.put(cf::META, ACCUMULATOR_KEY, transition.accumulator.as_bytes())?;
        batch.put(
            cf::META,
            ACTIVATION_VERSION_KEY,
            &transition.activation_version.to_be_bytes(),
        )?;
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
        batch.put(
            cf::BLOCKS,
            transition.block_hash.as_bytes(),
            &transition.block_bytes,
        )?;

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
