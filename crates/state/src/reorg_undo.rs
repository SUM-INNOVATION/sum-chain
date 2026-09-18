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
//! (column family, key, value BEFORE the block, value AFTER the block)
//! ```
//!
//! addressed by `(height, BLOCK HASH)`, with `Option<Vec<u8>>` on both sides so
//! "absent before" and "had value V before" are different values rather than the
//! same empty slice. That is [`UndoRecord`], and [`BranchJournal`] is the whole
//! of what a producer must implement. Nothing here decodes a journal, knows its
//! wire format, or assumes bincode: [`SubsystemJournals`] is one implementation
//! over the four journals that exist today, and a generic application journal is
//! another.
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
//! Newest block first; within a block, last record first. Both matter, and both
//! are the reverse of the order the mutations were applied. A block that writes
//! key K twice journals two records, and undoing them in forward order leaves
//! the intermediate value; a branch whose blocks N and N+1 both write K and is
//! unwound oldest-first leaves N's post-value rather than the ancestor's. The
//! existing per-subsystem revert already replays a single block's records in
//! reverse (`ContractStateDiff` in `revert_block_state_diffs`); this extends the
//! same rule to the branch.
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
use sumchain_storage::schema::{ContractStateDiff, StateStore};
use sumchain_storage::{cf, StorageError};

/// One journalled mutation, normalized away from whatever encoded it.
///
/// `before` and `after` are both `Option`: `None` means the key did not exist.
/// Collapsing that into an empty vector is the defect this type exists to avoid
/// — an undo that cannot express "delete a key that was not there before" turns
/// an abandoned creation into a permanent zero row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoRecord {
    /// Column family the row lives in.
    pub cf: String,
    /// Raw row key.
    pub key: Vec<u8>,
    /// Value before the block applied this mutation. `None` = absent.
    pub before: Option<Vec<u8>>,
    /// Value after the block applied this mutation. `None` = deleted.
    ///
    /// Present so the undo can be checked against the state it is about to
    /// overwrite. A journal that records only `before` can be replayed but never
    /// validated, and an unvalidatable undo is one that cannot tell restoration
    /// from corruption.
    pub after: Option<Vec<u8>>,
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
    0, // 1 — the generic application journal, once it lands.
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
    /// This is what the current storage format forces, and it is a weakness
    /// rather than a choice. The publisher writes no row at all for
    /// `JournalRecord::NothingToUndo`, so "this block mutated nothing" and "this
    /// block's undo record is missing" are the same bytes on disk — zero of
    /// them. Until the producer writes a POSITIVE nothing-to-undo record, no
    /// reader can tell the two apart, and halting on absence would refuse every
    /// reorg over an empty block.
    ToleratedEverywhere,
}

impl MissingJournalPolicy {
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
    /// This block's header and records, IN THE ORDER THE BLOCK APPLIED THEM.
    ///
    /// The unwind reverses them, so a producer that returns them in an
    /// unspecified or unstable order makes the unwind's result unspecified too.
    /// Sorting by key is NOT sufficient and is not what this asks for: two
    /// mutations of one key inside a block are distinguishable only by their
    /// application order.
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

    #[error("storage error during unwind: {0}")]
    Storage(#[from] StorageError),
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
pub fn stage_branch_unwind(
    db: &Database,
    batch: &mut WriteBatch<'_>,
    branch: &[Block],
    journal: &dyn BranchJournal,
    missing: MissingJournalPolicy,
) -> Result<UnwindReport, UndoRefusal> {
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

        // Last record first, for the same reason the blocks run newest-first.
        for record in records.iter().rev() {
            let current = view.get(&record.cf, &record.key)?;
            report.checks += 1;
            if current != record.after {
                return Err(UndoRefusal::CurrentValueMismatch {
                    height,
                    block: hash,
                    cf: record.cf.clone(),
                    key: hex::encode(&record.key),
                    expected: describe(&record.after),
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
/// This is an ADAPTER, not the contract. It exists so the unwind above can be
/// exercised against the real publication path before a generic application
/// journal lands, and so that when one does, the difference is one type.
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
                        after: Some(encoded_after),
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
                        after: record.new.clone(),
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
                                after: record.new.clone(),
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
                            after: record.new.clone(),
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
