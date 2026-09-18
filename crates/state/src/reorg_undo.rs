//! The CONSUMER half of the application-journal contract.
//!
//! A reorg unwinds abandoned blocks by replaying their journals backwards. This
//! module is the part that does the replaying, written against the narrowest
//! shape it can be written against, so that the producer — whatever encoding it
//! settles on — can be substituted without touching any of this.
//!
//! # The shape this depends on
//!
//! Exactly one thing: a journal is a per-block sequence of
//!
//! ```text
//! (column family, key, value BEFORE the block, what the block LEFT)
//! ```
//!
//! addressed by `(height, BLOCK HASH)`. `before` is an `Option<Vec<u8>>` so
//! "absent before" and "had value V before" are different values rather than the
//! same empty slice; what the block left is an [`ExpectedAfter`], because one
//! producer stores the post-image in full and the other stores a tag over it,
//! and both answer the only question asked of them. That is [`UndoRecord`], and
//! [`BranchJournal`] is the whole of what a producer must implement.
//!
//! Nothing in this module's CORE decodes a journal or knows a wire format.
//! [`SubsystemJournals`] is an adapter over the four per-subsystem journals,
//! [`ApplicationJournalReader`] reads and decodes the generic application
//! journal, and [`ActivatedJournal`] composes them by height.
//!
//! # Why the block HASH and not the height
//!
//! Issue #253. Two blocks can exist at one height — that is the entire reason a
//! reorg exists — so a journal addressed by height alone has the second one
//! overwrite the first's undo record. The reorg then reverts the block it is
//! ADOPTING and leaves the block it is abandoning permanently applied. Every
//! lookup here passes the hash, and a producer that ignores it is not
//! implementing this contract.
//!
//! # Current-value validation
//!
//! Before writing `before` back, this checks that what is there right now is
//! `after` — the value the journal says the block left. If it is not, the undo
//! is being applied to state it was not derived from, and "restoring" it would
//! write a value that was never correct at any point in the chain's history. It
//! is refused instead, with [`UndoRefusal::CurrentValueMismatch`] naming the
//! column family, the key, and both values.
//!
//! The check has to see the unwind's own earlier writes, not just the database.
//! A branch-wide unwind is staged into ONE batch, so nothing it has staged is
//! visible through `db.get` until the commit; a second block's record for the
//! same key would then be validated against the pre-unwind value and spuriously
//! refused. [`StagedView`] keeps the staged values beside the batch and is
//! consulted first — the same overlay-first discipline execution uses, for the
//! same reason.
//!
//! # Ordering
//!
//! **Newest block first**, always. A branch whose blocks N and N+1 both write K
//! and is unwound oldest-first lands on N's post-value rather than the
//! ancestor's, so this one is not negotiable for any producer.
//!
//! **Within a block**, it depends on what the producer's records ARE, and the
//! producer says which in [`JournalHeader::ordering`]:
//!
//! * [`EntryOrdering::NetByKey`] — one entry per `(cf, key)`, first pre-image
//!   and final value. Order is then immaterial, because no two entries of the
//!   block can interact. [`stage_branch_unwind`] PROVES the uniqueness before
//!   relying on it; a duplicate is [`UndoRefusal::DuplicateJournalKey`].
//! * [`EntryOrdering::ApplicationOrder`] — an append log that may hold a key
//!   twice. Replayed last-first, because undoing two writes to one key in
//!   forward order leaves the intermediate value. This is what the four legacy
//!   per-subsystem journals are (`ContractStateDiff` in
//!   `revert_block_state_diffs` already replays in reverse for this reason).
//!
//! That distinction is the resolution of a real disagreement between the two
//! halves of this design: the producer proves a total `(cf, key)` sort and has
//! no application order to give, while this consumer was originally written
//! demanding one. Neither was wrong about its own side. The uniqueness invariant
//! is what makes the demand unnecessary, and stating it as a checked declaration
//! rather than an assumption is what keeps a future append-log producer from
//! silently inheriting the wrong rule.
//!
//! # What this module does NOT do
//!
//! It stages, and only stages. [`stage_branch_unwind`] and [`stage_head_reset`]
//! both take a BORROWED batch and neither commits: the caller puts the state
//! restore, the journal deletions, the de-indexing and the head move into one
//! atomic write, which is what gives an interrupted unwind a single resting
//! state instead of two. Nothing here commits a batch, opens one, or writes to
//! the database outside the caller's — which is also why `execution_boundary.rs`
//! finds no direct-mutation syntax in this file to count.

use std::collections::BTreeMap;

use sumchain_primitives::{Block, BlockHeight, Hash};
use sumchain_storage::db::{Database, WriteBatch};
use sumchain_storage::journal::{
    ActivationSource, JournalActivation, JournalRequirement, Preimage as StoragePreimage,
};
use sumchain_storage::schema::{ContractStateDiff, StateStore};
use sumchain_storage::{cf, StorageError};

/// What the journal says the block LEFT at a key, in whichever form its producer
/// stored it.
///
/// Two forms, because the two producers made different and both-defensible
/// choices, and collapsing them would mean one of them lying:
///
/// * [`ExpectedAfter::Exact`] — the value itself. The four legacy per-subsystem
///   journals store the post-image in full, so the check is a byte comparison.
/// * [`ExpectedAfter::Tagged`] — a domain-separated 8-byte digest over
///   `(family, key, value)`. The generic application journal stores this, on the
///   argument that a before-image must be RESTORED exactly while an after-image
///   only has to be RECOGNISED.
///
/// The consumer does not care which: both answer the only question it asks —
/// "does this row still hold what the block left?" — and both answer it about
/// the row's CURRENT committed (or staged) value, which is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedAfter {
    /// The block left exactly this. `None` = the block deleted the key.
    Exact(Option<Vec<u8>>),
    /// The block left a value with this tag. `AfterImage::Absent` = deleted.
    Tagged(sumchain_storage::journal::AfterImage),
}

impl ExpectedAfter {
    /// Whether `current` is what the block left.
    ///
    /// `cf` and `key` are arguments rather than fields because the tag binds
    /// them: a digest recomputed under a different family or key does not match,
    /// which is what stops a tag being transplanted between entries.
    pub fn matches(&self, cf: &str, key: &[u8], current: Option<&[u8]>) -> bool {
        match self {
            ExpectedAfter::Exact(v) => v.as_deref() == current,
            ExpectedAfter::Tagged(tag) => {
                &sumchain_storage::journal::AfterImage::of(cf, key, current) == tag
            }
        }
    }

    /// A short rendering for an error message. Never the whole value: a
    /// journalled value is block-controlled and can be large.
    pub fn describe(&self) -> String {
        match self {
            ExpectedAfter::Exact(v) => describe(v),
            ExpectedAfter::Tagged(sumchain_storage::journal::AfterImage::Absent) => {
                "absent (by tag)".to_string()
            }
            ExpectedAfter::Tagged(sumchain_storage::journal::AfterImage::Digest(d)) => {
                format!("a value tagged {}", hex::encode(d))
            }
        }
    }
}

/// One journalled mutation, normalized away from whatever encoded it.
///
/// `before` is an `Option`: `None` means the key did not exist. Collapsing that
/// into an empty vector is the defect this type exists to avoid — an undo that
/// cannot express "delete a key that was not there before" turns an abandoned
/// creation into a permanent zero row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoRecord {
    /// Column family the row lives in.
    pub cf: String,
    /// Raw row key.
    pub key: Vec<u8>,
    /// Value before the block applied this mutation. `None` = absent.
    pub before: Option<Vec<u8>>,
    /// What the block left, so the undo can be checked against the state it is
    /// about to overwrite.
    ///
    /// A journal that records only `before` can be replayed but never validated,
    /// and an unvalidatable undo is one that cannot tell restoration from
    /// corruption.
    pub after: ExpectedAfter,
}

/// What a journal SAYS it is, independently of where it was filed.
///
/// A journal addressed by `(height, block hash)` is safe from the #253 defect
/// only while the addressing is right. Addressing is a key, and a key can be
/// wrong: a producer bug, a partially-migrated store, a row copied between
/// databases. The record must therefore also CARRY its own identity, so a reader
/// can check that the journal it received is the journal it asked for rather
/// than trusting the shelf it was on.
///
/// `version` exists so the format can change across an activation boundary
/// without ambiguity about which reader applies. A reader that does not know a
/// version refuses it; it never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHeader {
    pub height: BlockHeight,
    pub block_hash: Hash,
    pub version: u32,
    /// What the producer claims about the SHAPE of its record list. See
    /// [`EntryOrdering`] — this is the field that settles what "replay order"
    /// means for this journal, and the unwind VALIDATES the claim rather than
    /// taking it.
    pub ordering: EntryOrdering,
}

/// The ordering contract a producer's record list satisfies.
///
/// # Why this is a field and not a convention
///
/// The two sides of this design arrived at different answers and each was right
/// about its own producer. The generic application journal proves a TOTAL SORT
/// over `(cf, key)` and has no notion of application order to offer: its entries
/// come from an overlay pre-image map, one per key, already collapsed. The four
/// legacy per-subsystem journals are append logs and CAN hold two records for
/// one key inside one block, so for them the reverse of application order is the
/// only correct replay.
///
/// Reconciling those by picking one and asserting it for both would have been a
/// silent bug in whichever producer it did not describe. What actually
/// reconciles them is the UNIQUENESS INVARIANT, stated here and checked by
/// [`stage_branch_unwind`]:
///
/// > If a block's records hold at most one entry per `(cf, key)`, then no two
/// > records of that block can interact, so every order over them replays to the
/// > same state, and a deterministic `(cf, key)` order is sufficient.
///
/// So a producer declares which case it is in, and the unwind holds it to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryOrdering {
    /// **One net entry per `(cf, key)`**: first pre-image, final value, in
    /// ascending `(cf, key)` order.
    ///
    /// The unwind VALIDATES the uniqueness — a duplicate is
    /// [`UndoRefusal::DuplicateJournalKey`], not a merge — and having validated
    /// it, may replay the entries in any order it likes. This is the generic
    /// application journal.
    NetByKey,
    /// **Application order**, possibly with a key repeated inside one block.
    ///
    /// The unwind must replay these LAST-FIRST, because undoing two writes to
    /// one key in forward order leaves the intermediate value. This is what the
    /// four legacy per-subsystem journals are, and it is the pre-activation
    /// path only.
    ApplicationOrder,
}

/// Journal format versions this reader understands.
///
/// Refusing an unknown version is the whole of downgrade safety. Once a store
/// holds journals written at a version above this, an older reader must stop
/// rather than decode what it can: a partially-understood undo record applied to
/// state is worse than no undo at all, because it looks like it worked.
pub const SUPPORTED_JOURNAL_VERSIONS: &[u32] = &[
    // 0 — the unversioned per-subsystem journals. They carry no version field
    // on the wire; `SubsystemJournals` reports 0 for them, which is a statement
    // about what this tree writes today and not a field it reads back. See that
    // type's documentation.
    0, // 1 — the generic application journal. `ApplicationJournalReader` reports
    // this by reading `FORMAT_VERSION_V1` OUT of the record, so an unimplemented
    // version reaches here as the number the record actually carries.
    1,
];

/// What a journal lookup found. The three cases are distinct on purpose.
///
/// `Absent` and `Unreadable` must never collapse into one: a block that mutated
/// nothing legitimately has no journal, while a journal that exists and will not
/// decode is a corrupt node, and treating the second as the first silently skips
/// an undo that was required.
#[derive(Debug, Clone)]
pub enum JournalLookup {
    /// No journal row for this block. [`MissingJournalPolicy`] decides whether
    /// that is legal.
    Absent,
    /// A journal, decoded. May legitimately be empty — `records: []` with a
    /// header present is the POSITIVE statement that the block mutated nothing,
    /// which is a different claim from `Absent`.
    Present {
        header: JournalHeader,
        records: Vec<UndoRecord>,
    },
    /// A journal row exists and could not be turned into records — truncated,
    /// undecodable, or carrying a tag this reader does not understand.
    Unreadable(String),
}

/// What to do about a block on the abandoned branch that has NO journal.
///
/// Absence is not one condition. On a chain whose history predates the journal
/// format, a block legitimately has none and there is nothing to undo that the
/// node could have recorded. On a chain where the format is active, absence is a
/// damaged database, and unwinding past it leaves that block's effects applied
/// under a chain that no longer contains it — silently, forever.
///
/// So the policy is explicit and the caller must state it. There is no default:
/// a default here would be a consensus-relevant decision made by whichever call
/// site forgot to think about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingJournalPolicy {
    /// A journal is REQUIRED from `height` onward. At or above it, absence
    /// halts the unwind. Below it, absence is tolerated as pre-activation
    /// history, counted in [`UnwindReport::tolerated_absences`] and logged —
    /// and the block's effects stay applied, which is why it is counted.
    RequiredFrom(BlockHeight),
    /// Absence is tolerated at EVERY height, counted and logged.
    ///
    /// This is the PRE-ACTIVATION policy, and nothing else. It is correct for a
    /// database with no generic-journal history at all — every block in it was
    /// published by a binary that wrote only the four per-subsystem journals,
    /// which write no row for a block that mutated nothing in their family, so
    /// "mutated nothing" and "record lost" really are the same zero bytes there
    /// and halting would refuse every reorg over an empty block.
    ///
    /// It is NOT correct anywhere the generic journal is active. That journal
    /// writes a record for every block it publishes, including a zero-entry one,
    /// so absence carries information again and
    /// [`MissingJournalPolicy::RequiredFrom`] is the policy — see
    /// [`MissingJournalPolicy::from_activation`], which is how the production
    /// path picks between them rather than by a call site's judgement.
    ToleratedEverywhere,
}

impl MissingJournalPolicy {
    /// The policy a node's own journal history implies.
    ///
    /// `RequiredFrom(boundary)` whenever this database has journal history, so
    /// every block at or above the boundary must produce a record and a missing
    /// one halts. `ToleratedEverywhere` only when the boundary is unestablished
    /// — a database that holds no generic journal at all, which is pre-journal
    /// history end to end.
    ///
    /// Derived rather than chosen, so the answer cannot vary between the reorg
    /// driver, a rollback tool and a test.
    pub fn from_activation(activation: &JournalActivation) -> Self {
        match activation.boundary() {
            Some(b) => MissingJournalPolicy::RequiredFrom(b),
            None => MissingJournalPolicy::ToleratedEverywhere,
        }
    }

    fn tolerates(&self, height: BlockHeight) -> bool {
        match self {
            MissingJournalPolicy::RequiredFrom(from) => height < *from,
            MissingJournalPolicy::ToleratedEverywhere => true,
        }
    }
}

/// The producer side of the contract, reduced to what an unwind needs.
///
/// Two methods, both addressed by `(height, block hash)`. An implementation that
/// can answer them is usable by every part of this module regardless of how it
/// stores anything.
pub trait BranchJournal {
    /// This block's header and records.
    ///
    /// The header's [`JournalHeader::ordering`] says what the record list is,
    /// and the unwind holds the producer to it:
    ///
    /// * [`EntryOrdering::NetByKey`] — at most one record per `(cf, key)`, each
    ///   carrying the value at the START of the block and the value the block
    ///   finally left. Order among records is then immaterial, and
    ///   [`stage_branch_unwind`] proves the uniqueness before relying on that.
    /// * [`EntryOrdering::ApplicationOrder`] — records in the order the block
    ///   applied them, a key possibly appearing more than once. The unwind
    ///   replays them last-first; a producer that returns these in an
    ///   unspecified or unstable order makes the unwind's result unspecified
    ///   too.
    ///
    /// A producer that can collapse to net entries should say
    /// [`EntryOrdering::NetByKey`] and be checked, rather than say
    /// [`EntryOrdering::ApplicationOrder`] and be trusted.
    fn lookup(&self, height: BlockHeight, block_hash: &Hash) -> JournalLookup;

    /// The `(column family, key)` rows that hold this block's journal, so the
    /// unwind can delete them in the same batch that consumes them.
    ///
    /// Returning rows that do not exist is harmless; failing to return one that
    /// does leaves an undo record for a block that is no longer on any chain.
    fn rows(&self, height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)>;
}

/// Why an unwind refused. Every variant is a refusal to write, not a warning.
#[derive(Debug, thiserror::Error)]
pub enum UndoRefusal {
    /// The row does not currently hold what the journal says the block left
    /// there. The undo was derived from a state this node is not in.
    #[error(
        "refusing to undo block {block} at height {height}: column family {cf} key {key} \
         currently holds {found}, but its journal says the block left {expected} there; \
         this undo was not derived from the state it is being applied to"
    )]
    CurrentValueMismatch {
        height: BlockHeight,
        block: Hash,
        cf: String,
        key: String,
        expected: String,
        found: String,
    },

    /// A block on the abandoned branch has no journal at all.
    #[error(
        "refusing to unwind block {block} at height {height}: it has no undo journal, so \
         its effect on state cannot be reversed"
    )]
    MissingJournal { height: BlockHeight, block: Hash },

    /// A journal exists and cannot be read.
    #[error(
        "refusing to unwind block {block} at height {height}: its undo journal could not be \
         read ({reason})"
    )]
    UnreadableJournal {
        height: BlockHeight,
        block: Hash,
        reason: String,
    },

    /// The journal decoded, and says it belongs to a different block.
    ///
    /// Addressing by `(height, block hash)` is not enough on its own: a key can
    /// be wrong. This is the record disagreeing with the shelf it was on, and it
    /// is refused rather than reconciled — there is no way to know which of the
    /// two is right.
    #[error(
        "refusing to undo block {block} at height {height}: its journal says it belongs to \
         block {record_block} at height {record_height}; a journal filed under one block and \
         describing another cannot be applied to either"
    )]
    JournalIdentityMismatch {
        height: BlockHeight,
        block: Hash,
        record_height: BlockHeight,
        record_block: Hash,
    },

    /// The journal is at a format version this reader does not understand.
    ///
    /// Refused, never partially decoded. See [`SUPPORTED_JOURNAL_VERSIONS`].
    #[error(
        "refusing to undo block {block} at height {height}: its journal is format version \
         {version}, and this reader understands only {supported:?}; a partially-understood \
         undo record is worse than none, because applying it looks like it worked"
    )]
    UnsupportedJournalVersion {
        height: BlockHeight,
        block: Hash,
        version: u32,
        supported: &'static [u32],
    },

    /// The journal declared [`EntryOrdering::NetByKey`] and holds two records
    /// for one `(cf, key)`.
    ///
    /// Refused, never merged. The declaration is what licenses the unwind to
    /// stop caring about replay order; a record list that breaks it is one whose
    /// correct replay order is unknown, and picking either record's pre-image
    /// would be picking one at random. Post-activation this is a corrupt or
    /// foreign record, which is a halt for the same reason
    /// [`UndoRefusal::UnreadableJournal`] is.
    #[error(
        "refusing to undo block {block} at height {height}: its journal declares one net \
         entry per (column family, key) and holds two for {cf} key {key}; a record list \
         that breaks that invariant has no knowable replay order, and merging the two \
         would pick one pre-image at random"
    )]
    DuplicateJournalKey {
        height: BlockHeight,
        block: Hash,
        cf: String,
        key: String,
    },

    /// The abandoned branch reaches BELOW this chain's journal activation
    /// boundary while also holding blocks at or above it.
    ///
    /// The activation boundary is an irreversible checkpoint. See
    /// [`crosses_activation_checkpoint`] for why a crossing unwind cannot be
    /// made correct with the records that exist below the boundary, and why it
    /// is refused whole rather than run per block.
    #[error(
        "refusing to unwind a branch that crosses this chain's application-journal \
         activation boundary {boundary}: the branch spans heights {lowest}..={highest}, so \
         part of it would be unwound from the four legacy per-subsystem journals, which do \
         not cover every column family a block writes (`cf::SUPPLY` is restorable from none \
         of them). Unwinding it would leave abandoned application state applied under a \
         chain that no longer contains the blocks that wrote it, and would do so silently. \
         The activation boundary is an irreversible checkpoint: a reorg may not cross it"
    )]
    CrossesActivationCheckpoint {
        boundary: BlockHeight,
        lowest: BlockHeight,
        highest: BlockHeight,
    },

    #[error("storage error during unwind: {0}")]
    Storage(#[from] StorageError),
}

/// Whether unwinding `branch` would cross this chain's activation boundary, and
/// the refusal if it would.
///
/// # The policy, and the argument for it
///
/// Below the boundary the only undo records a block has are the four legacy
/// per-subsystem journals, and those are KNOWINGLY incomplete: they cover
/// account and contract rows (plus the two dormant subsystems) and nothing else,
/// so a family like `cf::SUPPLY` is restorable from none of them. That is a
/// pre-existing fact about pre-journal history, and §7.1 of the contract leaves
/// it alone for a reorg that stays wholly below the boundary — such a chain is
/// running entirely under the old rules and this work changes nothing about it.
///
/// A CROSSING unwind is different, and choosing the record per block does not
/// fix it. The per-block classification (`ActivatedJournal`) answers "which
/// record governs this block"; it cannot answer "what restores the families no
/// record covers". So a branch that starts above the boundary and continues
/// below it unwinds its upper blocks completely and its lower blocks partially,
/// commits both in one batch, and reports success. The rows the lower blocks
/// wrote into uncovered families stay applied under a chain that no longer
/// contains those blocks — silently, and with the head already moved.
///
/// The two available policies were:
///
/// 1. **Backfill** complete generic journals across the supported pre-activation
///    reorg window, or
/// 2. **Checkpoint**: the activation block is irreversible and a reorg may not
///    cross it.
///
/// Backfill is not implementable here, and not merely expensive. A generic
/// journal is the set of PRE-IMAGES of the keys a block wrote, captured by the
/// overlay while that block executed. For a block published before the upgrade
/// those pre-images were never captured, and reconstructing them means
/// re-executing the block from the state that preceded it — which is the state
/// the node would have to rewind to in order to get it, using the undo data the
/// backfill is trying to manufacture. The only non-circular way to obtain it is
/// to replay the chain from genesis into a fresh database, which is a RESYNC;
/// and a resynced node's journal history starts at genesis, so its boundary is
/// the bottom of its chain and there is nothing left to cross. Backfill
/// therefore collapses into either "impossible" or "resync", and shipping a
/// half-built version of it would be shipping the appearance of a guarantee.
///
/// The checkpoint is implementable as a refusal that happens before a single
/// row is staged, it is loud, and it is SELF-EXTINGUISHING: `plan_reorg` bounds
/// the ancestor walk at `sumchain_consensus::poa::MAX_REORG_WALK` (4,096), so
/// once a node is 4,096 blocks past its boundary no plan it will ever build can
/// reach below it, and the restriction stops binding without anybody doing
/// anything. Finality shortens that window further, since `plan_reorg` already
/// refuses to walk below the finalized height. What it costs is a bounded
/// availability window immediately after an upgrade, in which a deep reorg
/// across the upgrade height is refused and the operator resyncs. What it buys
/// is that the alternative — silently retaining abandoned application state —
/// is unreachable.
///
/// # What counts as crossing
///
/// The branch must hold a block at or above the boundary AND a block below it.
/// A branch wholly at or above is §7.2 and is fully covered by generic records.
/// A branch wholly below is §7.1: the chain has not activated over that range at
/// all — the shape an operator gets by pinning a boundary above the current head
/// — and the legacy behaviour is left exactly as it was.
///
/// Under [`MissingJournalPolicy::ToleratedEverywhere`] there is no boundary to
/// cross: the database holds no generic journal history at all, every block in
/// it is pre-journal, and nothing here applies.
pub fn crosses_activation_checkpoint(
    branch: &[Block],
    missing: MissingJournalPolicy,
) -> Option<UndoRefusal> {
    let boundary = match missing {
        MissingJournalPolicy::RequiredFrom(b) => b,
        MissingJournalPolicy::ToleratedEverywhere => return None,
    };
    let lowest = branch.iter().map(|b| b.height()).min()?;
    let highest = branch.iter().map(|b| b.height()).max()?;
    if lowest < boundary && highest >= boundary {
        return Some(UndoRefusal::CrossesActivationCheckpoint {
            boundary,
            lowest,
            highest,
        });
    }
    None
}

/// What an unwind staged, for logging and for tests that assert it did work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnwindReport {
    /// Blocks whose journals were consumed.
    pub blocks: u64,
    /// Records replayed.
    pub records: u64,
    /// Current-value checks performed. Equals `records` — it is reported
    /// separately so a test can assert validation was not skipped, rather than
    /// inferring it from the absence of a failure.
    pub checks: u64,
    /// Blocks whose journal was ABSENT and whose absence the policy tolerated.
    ///
    /// Each one is a block whose effects on state were NOT undone. A switch with
    /// a non-zero count here has not fully unwound its abandoned branch, and a
    /// caller that treats it as if it had is asserting something that was not
    /// checked.
    pub tolerated_absences: u64,
}

/// Database reads that see this unwind's own staged writes.
///
/// A branch-wide unwind is one batch, so `db.get` returns pre-unwind values for
/// the whole of it. Validating the second block's record for a key against a
/// value the first block's record already replaced would refuse a correct
/// unwind. This shadows the database with what has been staged so far.
struct StagedView<'a> {
    db: &'a Database,
    staged: BTreeMap<(String, Vec<u8>), Option<Vec<u8>>>,
}

impl<'a> StagedView<'a> {
    fn new(db: &'a Database) -> Self {
        Self {
            db,
            staged: BTreeMap::new(),
        }
    }

    fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        // `BTreeMap` cannot be probed with a borrowed pair without allocating a
        // key, and the alternative — a nested map — buys nothing at the sizes a
        // single reorg reaches.
        match self.staged.get(&(cf_name.to_string(), key.to_vec())) {
            Some(v) => Ok(v.clone()),
            None => self.db.get(cf_name, key),
        }
    }

    fn stage(
        &mut self,
        batch: &mut WriteBatch<'_>,
        cf_name: &str,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<(), StorageError> {
        match value {
            Some(v) => batch.put(cf_name, key, v)?,
            None => batch.delete(cf_name, key)?,
        }
        self.staged.insert(
            (cf_name.to_string(), key.to_vec()),
            value.map(|v| v.to_vec()),
        );
        Ok(())
    }
}

/// Render a value for an error message: length plus a short hex prefix, never
/// the whole row. A journal value is block-controlled and can be large, and an
/// error is not the place for it.
fn describe(v: &Option<Vec<u8>>) -> String {
    match v {
        None => "absent".to_string(),
        Some(b) if b.len() <= 16 => format!("{} bytes ({})", b.len(), hex::encode(b)),
        Some(b) => format!("{} bytes ({}…)", b.len(), hex::encode(&b[..16])),
    }
}

/// Stage the complete unwind of `branch` into `batch`.
///
/// `branch` is the abandoned blocks in ANCESTOR-TO-HEAD order — the order
/// `ReorgPlan::old_branch` uses. They are unwound newest-first; within each
/// block, records are replayed last-first.
///
/// Refuses before staging anything it cannot justify. On `Err` the caller must
/// DROP the batch: a refusal partway through has already staged earlier
/// records, and committing them would apply a partial unwind — precisely the
/// torn state this whole design exists to make unreachable. Dropping a
/// `WriteBatch` writes nothing, so the refusal costs exactly nothing.
///
/// Every block on the branch must have a journal. A block with none cannot be
/// reversed, and continuing past it would leave its effects applied under a
/// chain that no longer contains it.
///
/// A branch that CROSSES this chain's journal activation boundary is refused
/// outright, before anything is read or staged — the boundary is an
/// irreversible checkpoint. See [`crosses_activation_checkpoint`] for the
/// argument, and for why choosing the record per block does not make a crossing
/// unwind correct.
pub fn stage_branch_unwind(
    db: &Database,
    batch: &mut WriteBatch<'_>,
    branch: &[Block],
    journal: &dyn BranchJournal,
    missing: MissingJournalPolicy,
) -> Result<UnwindReport, UndoRefusal> {
    // The activation boundary is an irreversible checkpoint. Checked FIRST, over
    // the whole branch, before a single record is read: a crossing unwind cannot
    // be made correct block by block, so it is refused whole rather than started
    // and abandoned partway. See `crosses_activation_checkpoint`.
    if let Some(refusal) = crosses_activation_checkpoint(branch, missing) {
        return Err(refusal);
    }

    let mut view = StagedView::new(db);
    let mut report = UnwindReport::default();

    // Newest block first. See the module header: oldest-first leaves the
    // intermediate value for any key more than one block touched.
    for block in branch.iter().rev() {
        let height = block.height();
        let hash = block.hash();

        let (header, records) = match journal.lookup(height, &hash) {
            JournalLookup::Present { header, records } => (header, records),
            JournalLookup::Absent => {
                if !missing.tolerates(height) {
                    return Err(UndoRefusal::MissingJournal {
                        height,
                        block: hash,
                    });
                }
                // Tolerated, and said out loud. This block's effects on state
                // stay applied under a chain that no longer contains it, which
                // is a fact about the node, not a detail.
                tracing::warn!(
                    height,
                    block = %hash,
                    "unwinding past a block with no undo journal: its effects on state are \
                     NOT reverted, and remain applied under a chain that no longer contains it"
                );
                report.tolerated_absences += 1;
                continue;
            }
            JournalLookup::Unreadable(reason) => {
                return Err(UndoRefusal::UnreadableJournal {
                    height,
                    block: hash,
                    reason,
                })
            }
        };

        // ── the journal must agree with the block it was asked for ──────────
        //
        // Addressing by hash is not enough on its own, because addressing is a
        // key and a key can be wrong. Checked before a single record is read.
        if header.height != height || header.block_hash != hash {
            return Err(UndoRefusal::JournalIdentityMismatch {
                height,
                block: hash,
                record_height: header.height,
                record_block: header.block_hash,
            });
        }
        if !SUPPORTED_JOURNAL_VERSIONS.contains(&header.version) {
            return Err(UndoRefusal::UnsupportedJournalVersion {
                height,
                block: hash,
                version: header.version,
                supported: SUPPORTED_JOURNAL_VERSIONS,
            });
        }

        // ── the ordering declaration is checked, not taken ───────────────────
        //
        // A producer claiming `NetByKey` is claiming the property that lets this
        // loop stop caring about replay order. It is verified here, before a
        // single record is applied, so the licence and the thing it licenses
        // cannot come apart. `ApplicationOrder` makes no such claim and gets no
        // such check — it is replayed last-first instead, below.
        if header.ordering == EntryOrdering::NetByKey {
            let mut seen: BTreeMap<(&str, &[u8]), ()> = BTreeMap::new();
            for record in &records {
                if seen
                    .insert((record.cf.as_str(), record.key.as_slice()), ())
                    .is_some()
                {
                    return Err(UndoRefusal::DuplicateJournalKey {
                        height,
                        block: hash,
                        cf: record.cf.clone(),
                        key: hex::encode(&record.key),
                    });
                }
            }
        }

        // Last record first. For `ApplicationOrder` that is load-bearing: two
        // writes to one key inside a block undo correctly only in reverse. For
        // `NetByKey` it is immaterial — the uniqueness check above just proved
        // no two records of this block touch the same key — and it costs
        // nothing to use one loop for both.
        for record in records.iter().rev() {
            let current = view.get(&record.cf, &record.key)?;
            report.checks += 1;
            if !record
                .after
                .matches(&record.cf, &record.key, current.as_deref())
            {
                return Err(UndoRefusal::CurrentValueMismatch {
                    height,
                    block: hash,
                    cf: record.cf.clone(),
                    key: hex::encode(&record.key),
                    expected: record.after.describe(),
                    found: describe(&current),
                });
            }
            view.stage(batch, &record.cf, &record.key, record.before.as_deref())?;
            report.records += 1;
        }

        // The journal rows themselves, deleted in the same batch that consumed
        // them. A journal that outlives the block it describes is an undo record
        // for a block on no chain.
        for (cf_name, key) in journal.rows(height, &hash) {
            batch.delete(&cf_name, &key)?;
        }
        report.blocks += 1;
    }

    Ok(report)
}

/// Stage the chain-head metadata that names `ancestor`.
///
/// Separate from the state restore only in name: callers put both in one batch,
/// and that is the whole crash-recovery argument. The head pointer is the only
/// durable record of which block's state the database holds, so it must become
/// visible in the same atomic write as the state it names. Written in either
/// order within a batch, since a batch has no interior.
pub fn stage_head_reset(batch: &mut WriteBatch<'_>, ancestor: &Block) -> Result<(), StorageError> {
    use sumchain_storage::schema::meta_keys;
    batch.put(
        cf::META,
        meta_keys::LATEST_BLOCK_HASH,
        ancestor.hash().as_bytes(),
    )?;
    batch.put(
        cf::META,
        meta_keys::LATEST_BLOCK_HEIGHT,
        &ancestor.height().to_be_bytes(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// An implementation over the journals that exist today.
// ─────────────────────────────────────────────────────────────────────────────

/// [`BranchJournal`] over the four per-subsystem revert journals the publisher
/// writes today: account, contract, compute-pool and beacon.
///
/// This is an ADAPTER, not the contract, and it is the PRE-ACTIVATION producer.
/// [`ActivatedJournal`] uses it for blocks below the activation boundary, where
/// these four journals are the only undo record a block has, and uses
/// [`ApplicationJournalReader`] at and above it. It is also still the right
/// thing to drive a test whose subject is these four journals — their corruption
/// reporting, their per-hash addressing, and the measured gap between what they
/// cover and what a block writes.
///
/// The four are concatenated in a fixed family order, and each family's records
/// keep the order its own journal stored them in. That is the ordering the
/// unwind reverses; see [`BranchJournal::lookup`].
///
/// Absence is per-family: a block that touched only accounts has no contract
/// journal, and that is [`JournalLookup::Present`] with the account records, not
/// [`JournalLookup::Absent`]. `Absent` here means no family had one.
pub struct SubsystemJournals<'a> {
    db: &'a Database,
}

impl<'a> SubsystemJournals<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }
}

impl BranchJournal for SubsystemJournals<'_> {
    fn lookup(&self, height: BlockHeight, block_hash: &Hash) -> JournalLookup {
        let store = StateStore::new(self.db);
        let mut out = Vec::new();
        let mut any = false;

        // ── accounts ────────────────────────────────────────────────────────
        match store.get_state_diff(height, block_hash) {
            Err(e) => return JournalLookup::Unreadable(format!("account journal: {e}")),
            Ok(None) => {}
            Ok(Some(diff)) => {
                any = true;
                for (addr, before, after) in &diff.changes {
                    let encoded_before = match before
                        .as_ref()
                        .map(sumchain_storage::schema::encode_account)
                    {
                        Some(Err(e)) => {
                            return JournalLookup::Unreadable(format!(
                                "account journal: pre-image for {addr} will not encode: {e}"
                            ))
                        }
                        Some(Ok(b)) => Some(b),
                        None => None,
                    };
                    let encoded_after = match sumchain_storage::schema::encode_account(after) {
                        Ok(b) => b,
                        Err(e) => {
                            return JournalLookup::Unreadable(format!(
                                "account journal: post-image for {addr} will not encode: {e}"
                            ))
                        }
                    };
                    out.push(UndoRecord {
                        cf: cf::STATE.to_string(),
                        key: StateStore::account_key(addr),
                        before: encoded_before,
                        after: ExpectedAfter::Exact(Some(encoded_after)),
                    });
                }
            }
        }

        // ── contracts ───────────────────────────────────────────────────────
        match store.get_contract_state_diff(height, block_hash) {
            Err(e) => return JournalLookup::Unreadable(format!("contract journal: {e}")),
            Ok(None) => {}
            Ok(Some(diff)) => {
                any = true;
                for record in &diff.records {
                    let Some(cf_name) = ContractStateDiff::cf_name(record.cf_kind) else {
                        return JournalLookup::Unreadable(format!(
                            "contract journal: unknown cf_kind {}",
                            record.cf_kind
                        ));
                    };
                    out.push(UndoRecord {
                        cf: cf_name.to_string(),
                        key: record.key.clone(),
                        before: record.old.clone(),
                        after: ExpectedAfter::Exact(record.new.clone()),
                    });
                }
            }
        }

        // ── compute pool (dormant) ──────────────────────────────────────────
        match self.db.get(
            cf::COMPUTE_POOL_STATE_DIFFS,
            &journal_row_key(height, block_hash),
        ) {
            Err(e) => return JournalLookup::Unreadable(format!("compute-pool journal: {e}")),
            Ok(None) => {}
            Ok(Some(bytes)) => {
                match crate::compute_pool_store::ComputePoolStateDiff::decode(&bytes) {
                    Err(e) => {
                        return JournalLookup::Unreadable(format!("compute-pool journal: {e}"))
                    }
                    Ok(diff) => {
                        any = true;
                        for record in &diff.records {
                            out.push(UndoRecord {
                                cf: cf::COMPUTE_POOL_STATE.to_string(),
                                key: record.key.clone(),
                                before: record.old.clone(),
                                after: ExpectedAfter::Exact(record.new.clone()),
                            });
                        }
                    }
                }
            }
        }

        // ── beacon (dormant) ────────────────────────────────────────────────
        match self
            .db
            .get(cf::BEACON_STATE_DIFFS, &journal_row_key(height, block_hash))
        {
            Err(e) => return JournalLookup::Unreadable(format!("beacon journal: {e}")),
            Ok(None) => {}
            Ok(Some(bytes)) => match crate::beacon_store::BeaconStateDiff::decode(&bytes) {
                Err(e) => return JournalLookup::Unreadable(format!("beacon journal: {e}")),
                Ok(diff) => {
                    any = true;
                    for record in &diff.records {
                        out.push(UndoRecord {
                            cf: cf::BEACON_STATE.to_string(),
                            key: record.key.clone(),
                            before: record.old.clone(),
                            after: ExpectedAfter::Exact(record.new.clone()),
                        });
                    }
                }
            },
        }

        if any {
            JournalLookup::Present {
                // Echoed from the KEY, not read back from the record.
                //
                // The four per-subsystem journals carry no identity and no
                // version on the wire: `(height, block_hash)` lives only in the
                // row key, so this adapter can only report what it looked up,
                // and the identity check in `stage_branch_unwind` is a tautology
                // for this producer. Saying that here is the point — the check
                // is real for any producer that puts the fields IN the record,
                // and this one is declared as not yet doing so.
                header: JournalHeader {
                    height,
                    block_hash: *block_hash,
                    version: 0,
                    // Append logs, four of them concatenated. A block that
                    // writes one contract key twice leaves two records here, so
                    // this producer cannot claim `NetByKey` and does not.
                    ordering: EntryOrdering::ApplicationOrder,
                },
                records: out,
            }
        } else {
            JournalLookup::Absent
        }
    }

    fn rows(&self, height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
        subsystem_journal_rows(height, block_hash)
    }
}

/// The `(column family, key)` rows the publisher writes this block's four
/// per-subsystem journals to.
///
/// Free, and public, because it is the answer to "which rows on disk hold this
/// block's undo record" for THIS node's storage format, independently of which
/// journal implementation a reorg is driven by. A journal that is built by some
/// other means still has to consume the rows the publisher actually wrote, or
/// they outlive the block they describe.
///
/// Includes the pre-#253 height-only key alongside the hash-addressed one, so a
/// journal written by an older binary cannot survive the unwind that consumed
/// it. Mirrors `revert_block_state_diffs`.
pub fn subsystem_journal_rows(height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
    let hashed = journal_row_key(height, block_hash);
    let legacy = height.to_be_bytes().to_vec();
    let mut out = Vec::with_capacity(8);
    for family in [
        cf::STATE_DIFFS,
        cf::CONTRACT_STATE_DIFFS,
        cf::COMPUTE_POOL_STATE_DIFFS,
        cf::BEACON_STATE_DIFFS,
    ] {
        out.push((family.to_string(), hashed.clone()));
        out.push((family.to_string(), legacy.clone()));
    }
    out
}

fn journal_row_key(height: BlockHeight, block_hash: &Hash) -> Vec<u8> {
    sumchain_storage::schema::journal_key(height, block_hash)
}

// ─────────────────────────────────────────────────────────────────────────────
// The generic application journal, read from disk and replayed.
// ─────────────────────────────────────────────────────────────────────────────

/// [`BranchJournal`] over the REAL encoded application journal.
///
/// This is not an adapter over an oracle and not a shape the tests invented: it
/// reads `cf::APPLICATION_JOURNAL`, hands the bytes to
/// [`sumchain_storage::journal::ApplicationJournal::decode_for`] — magic,
/// format version, `(height, block hash)` identity, canonical `(cf, key)` order,
/// framing, trailing bytes, all of it — and turns the decoded entries into
/// [`UndoRecord`]s. Every refusal the record format defines therefore reaches
/// the unwind as [`JournalLookup::Unreadable`], which is a halt.
///
/// # Absence is classified, not guessed
///
/// Lookup goes through [`JournalActivation::load_for_revert`], the single
/// function the producer and this consumer share:
///
/// * present → decoded and validated;
/// * absent at or above the boundary → an ERROR, surfaced as `Unreadable` so the
///   unwind halts with the producer's own message rather than as `Absent`, which
///   a tolerant policy could swallow;
/// * absent below the boundary → `Absent`, and the policy decides.
///
/// The third case is the only silence and it is bounded by a height this
/// database establishes. It is also unreachable through [`ActivatedJournal`],
/// which never asks this reader about a pre-activation block in the first place.
pub struct ApplicationJournalReader<'a> {
    db: &'a Database,
    activation: JournalActivation,
}

impl<'a> ApplicationJournalReader<'a> {
    pub fn new(db: &'a Database, activation: JournalActivation) -> Self {
        Self { db, activation }
    }

    pub fn activation(&self) -> JournalActivation {
        self.activation
    }
}

impl BranchJournal for ApplicationJournalReader<'_> {
    fn lookup(&self, height: BlockHeight, block_hash: &Hash) -> JournalLookup {
        match self.activation.load_for_revert(self.db, height, block_hash) {
            Err(e) => JournalLookup::Unreadable(format!("application journal: {e}")),
            Ok(None) => JournalLookup::Absent,
            Ok(Some(journal)) => {
                let records = journal
                    .entries()
                    .iter()
                    .map(|e| UndoRecord {
                        cf: e.cf().to_string(),
                        key: e.key().to_vec(),
                        before: match e.before() {
                            StoragePreimage::Absent => None,
                            StoragePreimage::Value(v) => Some(v.clone()),
                        },
                        after: ExpectedAfter::Tagged(e.after().clone()),
                    })
                    .collect();
                JournalLookup::Present {
                    header: JournalHeader {
                        height: journal.height(),
                        block_hash: journal.block_hash(),
                        // Read back OUT OF THE RECORD, not echoed from the key.
                        // `decode_for` has already refused a record whose stored
                        // identity disagrees with the key it was read under, so
                        // the identity check in `stage_branch_unwind` is a second
                        // reading of the same fields rather than a tautology —
                        // which is the difference between this producer and the
                        // four legacy ones.
                        version: u32::from(journal.format_version()),
                        // The producer sorts by `(cf, key)` over an entry set
                        // that admits each pair once, and `decode_for` refuses a
                        // record whose entries are not strictly increasing. The
                        // claim is checked again by the unwind.
                        ordering: EntryOrdering::NetByKey,
                    },
                    records,
                }
            }
        }
    }

    fn rows(&self, height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
        application_journal_rows(height, block_hash)
    }
}

/// The `(column family, key)` row holding one block's generic application
/// journal.
///
/// Free and public for the same reason [`subsystem_journal_rows`] is: "which
/// rows on disk hold this block's undo record" is a fact about this node's
/// storage format, independent of which journal implementation drives a given
/// unwind. A journal row that outlives the block it describes is an undo record
/// for a block on no chain.
pub fn application_journal_rows(height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
    vec![(
        cf::APPLICATION_JOURNAL.to_string(),
        sumchain_storage::schema::journal_key(height, block_hash),
    )]
}

// ─────────────────────────────────────────────────────────────────────────────
// Precedence: which journal governs which block.
// ─────────────────────────────────────────────────────────────────────────────

/// The production [`BranchJournal`]: the generic application journal at and
/// above the activation boundary, the four legacy per-subsystem journals below
/// it, and **never both for one block**.
///
/// # The precedence rule, stated
///
/// The contract left this open (§7.2, open point 1) because the producer could
/// not settle it: both records restore pre-images for overlapping families, and
/// whether applying both is safe depends on an audit of what each legacy diff
/// covers. This is the consumer's answer, and it does not need that audit,
/// because it never applies both.
///
/// * **Below the boundary** — `PreActivation`. The block was published by a
///   binary that wrote no generic journal. The legacy journals are the only undo
///   record there is, so they are used, exactly as before this branch. An absent
///   one is tolerated by the policy and counted.
/// * **At or above the boundary** — `Required`. The generic journal is
///   AUTHORITATIVE and MANDATORY. It is derived from the overlay's pre-images,
///   so it covers every family the block wrote — including the ones the four
///   legacy journals were always missing — and there is no family for which
///   consulting a legacy diff could add information. A missing, corrupt,
///   mis-keyed, duplicate-keyed or identity-mismatched record HALTS the unwind.
///
/// Applying both would be, at best, redundant: the two restore the same
/// pre-image for a key both cover, so the second write is a no-op. It would also
/// be unjustified — "at best" is not a proof, and proving it would need the
/// audit the contract says nobody has done. Choosing per block needs no such
/// proof, so that is what this does.
///
/// # Crossing the boundary
///
/// Per BLOCK, not per reorg. The classification is a function of one height, and
/// a range spanning the boundary is simply a sequence of per-block answers. The
/// unwind runs head-first, so it walks from the required region into the
/// fallback region, never the reverse.
///
/// # Journal rows
///
/// [`BranchJournal::rows`] returns BOTH families' rows at every height. That is
/// deliberate and is not "applying both": it deletes undo data rather than
/// applying it. A post-activation block has legacy rows too — the publisher
/// still writes them — and leaving them behind would leave undo records for
/// blocks on no chain. Deleting a row that does not exist is a no-op.
pub struct ActivatedJournal<'a> {
    application: ApplicationJournalReader<'a>,
    legacy: SubsystemJournals<'a>,
    activation: JournalActivation,
}

impl<'a> ActivatedJournal<'a> {
    pub fn new(db: &'a Database, activation: JournalActivation) -> Self {
        Self {
            application: ApplicationJournalReader::new(db, activation),
            legacy: SubsystemJournals::new(db),
            activation,
        }
    }

    /// Resolve the boundary against `db` and build the journal, from the chain's
    /// own configured activation rule.
    pub fn resolve(db: &'a Database, source: ActivationSource) -> Result<Self, StorageError> {
        Ok(Self::new(db, JournalActivation::resolve(db, source)?))
    }

    pub fn activation(&self) -> JournalActivation {
        self.activation
    }

    /// The missing-journal policy this activation implies. Pass it to
    /// [`stage_branch_unwind`] beside this journal; the two must agree, and
    /// deriving both from one `JournalActivation` is how they are made to.
    pub fn policy(&self) -> MissingJournalPolicy {
        MissingJournalPolicy::from_activation(&self.activation)
    }

    /// Which journal governs `height`. Public so a caller can report it.
    pub fn governing(&self, height: BlockHeight) -> JournalRequirement {
        self.activation.requirement_at(height)
    }
}

impl BranchJournal for ActivatedJournal<'_> {
    fn lookup(&self, height: BlockHeight, block_hash: &Hash) -> JournalLookup {
        match self.activation.requirement_at(height) {
            JournalRequirement::Required => self.application.lookup(height, block_hash),
            JournalRequirement::PreActivation => self.legacy.lookup(height, block_hash),
        }
    }

    fn rows(&self, height: BlockHeight, block_hash: &Hash) -> Vec<(String, Vec<u8>)> {
        let mut rows = application_journal_rows(height, block_hash);
        rows.extend(subsystem_journal_rows(height, block_hash));
        rows
    }
}
