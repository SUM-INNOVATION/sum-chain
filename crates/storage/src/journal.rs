//! The generic application journal: one block's undo record, derived from the
//! overlay's PRE-IMAGES rather than hand-written per subsystem.
//!
//! # Why this exists
//!
//! Every application write a block makes goes through [`crate::exec_view::ExecutionView`]
//! into an [`ApplicationOverlay`], and the overlay captures the pre-image of
//! every key the first time that key is written. That capture is already the
//! complete undo material for the block — for every column family, including
//! ones nobody has thought about yet — and it is produced by the write path
//! itself, so it cannot fall behind the subsystems it describes.
//!
//! What existed before were four per-subsystem revert journals (`StateDiff`,
//! `ContractStateDiff`, `ComputePoolStateDiff`, `BeaconStateDiff`), each
//! assembled by hand in the subsystem that owns it. A hand-maintained undo
//! record has exactly one failure mode and it is silent: a new write lands in a
//! family nobody added to the diff, the journal still looks well-formed, and the
//! omission is discovered by a reorg deleting or resurrecting a row. This module
//! has no list to fall behind, because it has no list.
//!
//! # Coverage is derived, not declared
//!
//! [`ApplicationOverlay::journal_entries`] walks the pre-image map. Whatever
//! family that map contains is journalled; there is no allowlist, no
//! `match` on a family name, and no place a new family could be forgotten. The
//! coverage test in `crates/storage/tests/application_journal.rs` iterates
//! [`crate::db::ALL_CFS`] — every family the database opens — writes one row
//! through an [`crate::exec_view::ExecutionView`] into each, and requires the
//! family to appear in the published journal. It passes for a family added
//! tomorrow without that test being edited.
//!
//! # Determinism
//!
//! The serialized bytes are a pure function of the block's write set. Entries
//! are sorted by `(column family, key)`, which is a TOTAL order over them: a
//! family name appears once (it is a `HashMap` key), and within a family a key
//! appears once (it is a `BTreeMap` key), so no two entries share a sort key and
//! the sort has no ties to break. Nothing about `HashMap` iteration order,
//! insertion order or thread scheduling survives the sort. `decode_for` re-checks
//! the order, so a record that is not in canonical form is refused rather than
//! silently accepted as a second valid encoding of the same content.
//!
//! # Charging
//!
//! The encoded journal is staged through the overlay by
//! [`crate::candidate::AcceptedCandidate::publish`], exactly like every other
//! record that block publishes. `ApplicationOverlay::stage` measures it and
//! compares against the candidate's ceiling, so a block cannot buy unbounded
//! undo data for free — and because staging happens before `into_batch`, a
//! refusal aborts publication with nothing committed.
//!
//! # Keying
//!
//! `(height, block hash)`, via [`crate::schema::journal_key`] — the same key
//! shape the four legacy journals now use. Issue #253 exists because two of
//! them key by height ALONE, so two competing blocks at one height name the same
//! row and the second import destroys the first's undo record. Here the hash is
//! not optional and not a parameter: `publish` derives both halves of the key
//! from the one `&Block` it holds, and the record repeats them inside its own
//! header, so [`ApplicationJournal::decode_for`] refuses a record that does not
//! match the key it was read under.

use std::collections::BTreeSet;

use sumchain_primitives::{BlockHeight, Hash};

use crate::db::{Database, WriteBatch};
use crate::{Result, StorageError};

/// Record magic. Present so a truncated or foreign value is refused at byte 0
/// rather than being parsed into a plausible-looking entry list.
const MAGIC: &[u8; 5] = b"SUMAJ";

/// The only record format this binary can produce.
///
/// Encoded in every record so a reader knows which parser applies without
/// inferring it from length or context. A reader that does not know a version
/// REFUSES the record; see [`ApplicationJournal::decode_for`]. That is the
/// downgrade refusal: an old binary meeting a newer record stops, rather than
/// skipping the record and reverting a block with no undo data.
pub const FORMAT_VERSION_V1: u16 = 1;

/// Domain separator for the after-image tag.
///
/// Without it the tag is "blake3 of some bytes", and a digest computed over some
/// other structure that happens to serialize the same way would satisfy the
/// consumer's pre-revert check.
const AFTER_DOMAIN: &[u8] = b"sumchain.application_journal.after.v1";

/// Truncated-digest width for the after-image tag. Eight bytes is a consistency
/// check against a node's own committed state, not a security boundary: it
/// catches a journal applied to the wrong state, not an adversary constructing a
/// collision, and the record is node-local so there is no adversary to construct
/// one.
const AFTER_TAG_LEN: usize = 8;

fn invalid(msg: impl Into<String>) -> StorageError {
    StorageError::InvalidData(msg.into())
}

/// What a key held BEFORE the block wrote it.
///
/// `Absent` is a positive statement and the whole reason a `Vec<u8>` is not
/// enough: undoing a block that CREATED a key must DELETE it, and an empty
/// value is a legitimate stored value in several families here, so "no bytes"
/// cannot stand in for "no row". The distinction is on the wire as a tag byte,
/// not as a convention about length.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Preimage {
    /// The key did not exist. Undo DELETES it.
    Absent,
    /// The key held these exact bytes. Undo restores them.
    Value(Vec<u8>),
}

/// What the block left at the key, as a tag rather than a copy.
///
/// The before-image must be restorable exactly, so it is stored in full. The
/// after-image only has to be RECOGNISED — a consumer about to revert wants to
/// know that the row it is overwriting is still the one this block wrote — so a
/// domain-separated digest is enough and costs eight bytes instead of the value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AfterImage {
    /// The block DELETED the key: nothing should be there now.
    Absent,
    /// The block left a value with this tag.
    Digest([u8; AFTER_TAG_LEN]),
}

impl AfterImage {
    /// The tag for a committed value, or `Absent` for a missing row.
    ///
    /// The family and key are hashed in, length-prefixed, so a tag cannot be
    /// transplanted from one entry to another and still verify.
    pub fn of(cf: &str, key: &[u8], value: Option<&[u8]>) -> Self {
        match value {
            None => AfterImage::Absent,
            Some(v) => {
                let mut h = blake3::Hasher::new();
                h.update(AFTER_DOMAIN);
                h.update(&(cf.len() as u64).to_be_bytes());
                h.update(cf.as_bytes());
                h.update(&(key.len() as u64).to_be_bytes());
                h.update(key);
                h.update(&(v.len() as u64).to_be_bytes());
                h.update(v);
                let full = h.finalize();
                let mut tag = [0u8; AFTER_TAG_LEN];
                tag.copy_from_slice(&full.as_bytes()[..AFTER_TAG_LEN]);
                AfterImage::Digest(tag)
            }
        }
    }
}

/// One key's undo record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct JournalEntry {
    /// Ordered first, so `(cf, key)` is the sort key without a custom `Ord`.
    cf: String,
    key: Vec<u8>,
    before: Preimage,
    after: AfterImage,
}

impl JournalEntry {
    pub(crate) fn new(cf: String, key: Vec<u8>, before: Preimage, after: AfterImage) -> Self {
        Self {
            cf,
            key,
            before,
            after,
        }
    }

    pub fn cf(&self) -> &str {
        &self.cf
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// What the key held before the block. See [`Preimage`].
    pub fn before(&self) -> &Preimage {
        &self.before
    }

    /// What the block left, as a tag. See [`AfterImage`].
    pub fn after(&self) -> &AfterImage {
        &self.after
    }
}

/// One block's complete application undo record.
///
/// Carries its own `(height, block hash)` so a record can be checked against the
/// key it was read under, and its own format version so a reader knows whether
/// it is entitled to parse it at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationJournal {
    format_version: u16,
    height: BlockHeight,
    block_hash: Hash,
    /// Sorted by `(cf, key)`, strictly increasing. Every constructor in this
    /// module establishes that, and `decode_for` re-checks it.
    entries: Vec<JournalEntry>,
}

impl ApplicationJournal {
    /// Bind a derived entry list to the block it describes.
    ///
    /// Crate-private, and the only production caller is
    /// [`crate::candidate::AcceptedCandidate::publish`], which takes `height`
    /// and `block_hash` from the single `&Block` it holds. There is no public
    /// expression that pairs an arbitrary entry list with an arbitrary block.
    ///
    /// # The uniqueness invariant, declared and checked
    ///
    /// A journal holds **one net entry per `(cf, key)`**: the pre-image is the
    /// value at the START of the block and the after-image is the value the
    /// block finally left, however many times execution wrote that key in
    /// between. That is what the overlay produces — its pre-image map is
    /// `HashMap<String, BTreeMap<Vec<u8>, _>>`, which admits each `(cf, key)`
    /// once — and it is the property the CONSUMER needs, because it is what
    /// makes "replay order" a non-question. With at most one entry per key no
    /// two entries of one block can interact, so any deterministic order over
    /// them yields the same state, and ascending `(cf, key)` is that order.
    ///
    /// The invariant is therefore not left to the shape of the producing type.
    /// It is validated HERE, at the single point where entries become a journal,
    /// and re-validated by [`Self::decode_for`] on the way back in. A duplicate
    /// is an ERROR rather than a last-writer-wins merge: two entries for one key
    /// mean the derivation lost track of which pre-image came first, and a
    /// journal that cannot say that cannot undo the block.
    pub(crate) fn bind(
        height: BlockHeight,
        block_hash: Hash,
        mut entries: Vec<JournalEntry>,
    ) -> Result<Self> {
        entries.sort();
        for pair in entries.windows(2) {
            if pair[0].cf == pair[1].cf && pair[0].key == pair[1].key {
                return Err(invalid(format!(
                    "application journal for block {block_hash} at height {height}: two \
                     entries for column family {} key {}. A journal holds one NET entry \
                     per (cf, key) — first pre-image, final value — so a duplicate means \
                     the derivation lost which pre-image came first; refusing to publish \
                     a record that cannot say what the block started from",
                    pair[0].cf,
                    hex::encode(&pair[0].key)
                )));
            }
        }
        Ok(Self {
            format_version: FORMAT_VERSION_V1,
            height,
            block_hash,
            entries,
        })
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn block_hash(&self) -> Hash {
        self.block_hash
    }

    pub fn entries(&self) -> &[JournalEntry] {
        &self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every column family this block touched, derived from the entries.
    pub fn column_families(&self) -> BTreeSet<&str> {
        self.entries.iter().map(|e| e.cf.as_str()).collect()
    }

    /// The canonical serialization.
    ///
    /// Fixed-width big-endian lengths, explicit tag bytes, entries in
    /// `(cf, key)` order. Identical block content produces identical bytes; see
    /// the module's Determinism section for why the order is total.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(self.block_hash.as_bytes());
        out.extend_from_slice(&(self.entries.len() as u64).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&(e.cf.len() as u64).to_be_bytes());
            out.extend_from_slice(e.cf.as_bytes());
            out.extend_from_slice(&(e.key.len() as u64).to_be_bytes());
            out.extend_from_slice(&e.key);
            match &e.before {
                Preimage::Absent => out.push(0),
                Preimage::Value(v) => {
                    out.push(1);
                    out.extend_from_slice(&(v.len() as u64).to_be_bytes());
                    out.extend_from_slice(v);
                }
            }
            match &e.after {
                AfterImage::Absent => out.push(0),
                AfterImage::Digest(tag) => {
                    out.push(1);
                    out.extend_from_slice(tag);
                }
            }
        }
        Ok(out)
    }

    /// Parse a record read under `journal_key(height, block_hash)`.
    ///
    /// Strict on every axis, and loud on every failure. A journal that is
    /// truncated, carries a version this binary does not implement, is not in
    /// canonical order, has trailing bytes, or describes a different block is an
    /// ERROR — never a shorter entry list, never an empty journal, never a
    /// skipped record. Silently degrading any of those turns a missing undo
    /// record into a successful-looking revert that leaves rows behind.
    pub fn decode_for(bytes: &[u8], height: BlockHeight, block_hash: &Hash) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let magic = r.take(MAGIC.len())?;
        if magic != MAGIC {
            return Err(invalid(
                "application journal: bad magic; this is not a journal record",
            ));
        }
        let format_version = r.u16()?;
        if format_version != FORMAT_VERSION_V1 {
            return Err(invalid(format!(
                "application journal: record format version {format_version} is not \
                 implemented by this binary (it writes and reads version \
                 {FORMAT_VERSION_V1}); refusing rather than reverting a block whose \
                 undo record it cannot read"
            )));
        }
        let stored_height = r.u64()?;
        let stored_hash = Hash::from_slice(r.take(Hash::SIZE)?)
            .map_err(|e| invalid(format!("application journal: block hash: {e}")))?;
        if stored_height != height || stored_hash != *block_hash {
            return Err(invalid(format!(
                "application journal read under ({height}, {block_hash}) describes \
                 ({stored_height}, {stored_hash}); refusing to revert one block with \
                 another block's undo record"
            )));
        }

        let count = r.u64()?;
        let mut entries: Vec<JournalEntry> = Vec::new();
        for i in 0..count {
            let cf_len = r.u64()?;
            let cf = String::from_utf8(r.take(usize_of(cf_len)?)?.to_vec())
                .map_err(|e| invalid(format!("application journal: entry {i} family: {e}")))?;
            let key_len = r.u64()?;
            let key = r.take(usize_of(key_len)?)?.to_vec();
            let before = match r.u8()? {
                0 => Preimage::Absent,
                1 => {
                    let len = r.u64()?;
                    Preimage::Value(r.take(usize_of(len)?)?.to_vec())
                }
                t => {
                    return Err(invalid(format!(
                        "application journal: entry {i} has before-tag {t}; only 0 \
                         (absent) and 1 (value) are defined"
                    )))
                }
            };
            let after = match r.u8()? {
                0 => AfterImage::Absent,
                1 => {
                    let mut tag = [0u8; AFTER_TAG_LEN];
                    tag.copy_from_slice(r.take(AFTER_TAG_LEN)?);
                    AfterImage::Digest(tag)
                }
                t => {
                    return Err(invalid(format!(
                        "application journal: entry {i} has after-tag {t}; only 0 \
                         (absent) and 1 (digest) are defined"
                    )))
                }
            };
            if let Some(prev) = entries.last() {
                if (prev.cf.as_str(), prev.key.as_slice()) >= (cf.as_str(), key.as_slice()) {
                    return Err(invalid(format!(
                        "application journal: entry {i} is not strictly after its \
                         predecessor; the record is not in canonical order, so its \
                         bytes are not the bytes this block's content produces"
                    )));
                }
            }
            entries.push(JournalEntry::new(cf, key, before, after));
        }
        if !r.is_exhausted() {
            return Err(invalid(format!(
                "application journal: {} trailing byte(s) after {count} entries",
                r.remaining()
            )));
        }

        Ok(Self {
            format_version,
            height,
            block_hash: *block_hash,
            entries,
        })
    }

    /// Check the database still holds what this block LEFT, for every key the
    /// block touched.
    ///
    /// The check a consumer performs before applying a preimage. A mismatch
    /// means the rows this journal describes have moved on — another block was
    /// applied on top, or an earlier unwind half-ran — and applying the
    /// preimages would overwrite state this journal knows nothing about. The
    /// answer is to refuse the whole unwind, which is why this returns `Err`
    /// naming the first divergent key rather than a count or a filtered entry
    /// list.
    pub fn check_current_matches_after(&self, db: &Database) -> Result<()> {
        for e in &self.entries {
            let current = db.get(&e.cf, &e.key)?;
            let observed = AfterImage::of(&e.cf, &e.key, current.as_deref());
            if observed != e.after {
                return Err(invalid(format!(
                    "application journal for block {} at height {}: column family \
                     {} key {} no longer holds what the block left; refusing to \
                     apply any preimage from this journal",
                    self.block_hash,
                    self.height,
                    e.cf,
                    hex::encode(&e.key)
                )));
            }
        }
        Ok(())
    }

    /// One atomic batch that restores every key this block touched.
    ///
    /// `Absent` becomes a DELETE and `Value` becomes a PUT — the distinction the
    /// pre-image tag exists to carry. Building a batch rather than writing
    /// leaves the caller free to fold this into a larger reorg batch and to
    /// decide when, or whether, it commits.
    pub fn undo_batch<'d>(&self, db: &'d Database) -> Result<WriteBatch<'d>> {
        let mut batch = db.batch();
        self.undo_into(&mut batch)?;
        Ok(batch)
    }

    /// Append this journal's restores to an existing batch.
    pub fn undo_into(&self, batch: &mut WriteBatch<'_>) -> Result<()> {
        for e in &self.entries {
            match &e.before {
                Preimage::Absent => batch.delete(&e.cf, &e.key)?,
                Preimage::Value(v) => batch.put(&e.cf, &e.key, v)?,
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ACTIVATION
// ═══════════════════════════════════════════════════════════════════════════

/// Where the journal boundary comes from.
///
/// Deliberately NOT an `Option<BlockHeight>` whose `None` means "off". A journal
/// that is never written cannot undo anything, and a gate defaulting to `None`
/// is how the compute-pool and beacon journals ended up never written in
/// production. There is no variant here that disables the journal: the WRITE
/// side is ungated entirely — [`crate::candidate::AcceptedCandidate::publish`]
/// writes a record for every block it publishes, with no gate to leave unset —
/// and this enum only decides from which height a MISSING record is an error
/// rather than ordinary pre-journal history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationSource {
    /// Derive the boundary from the chain's own journal column family: the
    /// lowest height for which a record exists.
    ///
    /// The production rule, and the reason no governance number is needed. A
    /// node that upgrades at height H publishes journals from H upward, so the
    /// lowest stored height IS the height at which this node's journal history
    /// begins — and it is right across an upgrade without anyone choosing it,
    /// where a hardcoded height would either demand journals for blocks an older
    /// binary published or leave a window in which nothing is required.
    ObservedFromChain,
    /// A boundary fixed by configuration, for a deployment that wants every node
    /// to agree on where journal history starts rather than each observing its
    /// own.
    ///
    /// Chain-configurable rather than chain-consensus: these records are
    /// node-local, never hashed into a block, so two nodes disagreeing about the
    /// boundary cannot fork. What a pin buys is an operator-visible, uniform
    /// answer to "from when must a revert find a journal".
    Pinned(BlockHeight),
}

impl ActivationSource {
    /// The rule a node runs, from its own genesis parameter.
    ///
    /// `ChainParams::application_journal_enabled_from_height` is the generic
    /// application journal's OWN activation gate — its own field, its own
    /// semantics, and deliberately not `compute_pool_enabled_from_height` or
    /// `beacon_enabled_from_height`, which gate two dormant consensus subsystems
    /// and stay closed. Opening this one changes no block's contents: the
    /// records are node-local, so it moves only the height from and above which
    /// a REVERT must find one.
    ///
    /// * `None` — [`ActivationSource::ObservedFromChain`]. The default and the
    ///   production rule. There is no "off" here: the write side is ungated, so
    ///   the first block this binary publishes establishes the boundary, and
    ///   every block from there up is required to have a record.
    /// * `Some(h)` — [`ActivationSource::Pinned`]. For a deployment that wants
    ///   every node to answer "from when is a journal required" with the same
    ///   number rather than with its own upgrade height.
    ///
    /// `sumchain-storage` does not depend on `sumchain-genesis`, so the field
    /// arrives as the `Option<BlockHeight>` it is and the translation lives
    /// here, at one site, rather than at each caller.
    pub fn from_configured_height(configured: Option<BlockHeight>) -> Self {
        match configured {
            Some(h) => ActivationSource::Pinned(h),
            None => ActivationSource::ObservedFromChain,
        }
    }
}

/// The resolved boundary: the height at and above which a journal MUST exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalActivation {
    source: ActivationSource,
    /// `None` means no record exists anywhere, so no height has journal history
    /// yet. That is an OBSERVATION about the database, not a configuration that
    /// can be left unset: it stops being `None` the moment the first block
    /// publishes, which is every block this binary publishes.
    boundary: Option<BlockHeight>,
}

/// What a missing journal means at a given height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRequirement {
    /// At or above the boundary. A missing journal is an ERROR, and the revert
    /// halts. There is no defined way to unwind a post-activation block without
    /// its undo record, and proceeding would leave the rows it wrote in place
    /// while the chain claims they are gone.
    Required,
    /// Below the boundary, or no boundary established. This block was published
    /// before this database had journal history, so absence is expected and the
    /// consumer falls back to the four legacy per-subsystem journals.
    PreActivation,
}

impl JournalActivation {
    /// Resolve the boundary against `db`.
    pub fn resolve(db: &Database, source: ActivationSource) -> Result<Self> {
        let configured = match source {
            ActivationSource::Pinned(h) => Some(h),
            ActivationSource::ObservedFromChain => lowest_journal_height(db)?,
        };
        // A snapshot restore or fast sync leaves canonical state and NO undo
        // history below the height it restored at — journals are node-local and
        // are not transmitted. The floor it stamps raises the boundary, because
        // nothing below it is reversible by any record this database holds. See
        // `UNDO_HISTORY_FLOOR_META_KEY`.
        //
        // `floor + 1` and not `floor`: the restored block itself is the last one
        // the node did not journal, so the first reversible height is the one
        // above it.
        let boundary = match (configured, undo_history_floor(db)?) {
            (c, None) => c,
            (None, Some(f)) => Some(f.saturating_add(1)),
            (Some(c), Some(f)) => Some(c.max(f.saturating_add(1))),
        };
        Ok(Self { source, boundary })
    }

    pub fn source(&self) -> ActivationSource {
        self.source
    }

    /// The height at and above which a journal must exist, or `None` when this
    /// database holds no journal at all.
    pub fn boundary(&self) -> Option<BlockHeight> {
        self.boundary
    }

    pub fn requirement_at(&self, height: BlockHeight) -> JournalRequirement {
        match self.boundary {
            Some(b) if height >= b => JournalRequirement::Required,
            _ => JournalRequirement::PreActivation,
        }
    }

    /// The activation a chain has when its boundary is PINNED by configuration.
    ///
    /// [`Self::resolve`] is the production entry point and needs a database for
    /// the [`ActivationSource::ObservedFromChain`] case. A pinned boundary needs
    /// no database — `resolve` ignores it for that variant — so this names that
    /// case directly, for a caller that has a configured height and no handle.
    ///
    /// It is not a way around the classification: the value it produces answers
    /// [`Self::requirement_at`] the same way any other does, and a boundary
    /// pinned above the head is the ordinary "this chain has not activated the
    /// generic journal yet" configuration rather than a bypass.
    pub fn pinned(boundary: BlockHeight) -> Self {
        Self {
            source: ActivationSource::Pinned(boundary),
            boundary: Some(boundary),
        }
    }

    /// How many blocks below `head_height` this node holds GENERIC undo history
    /// for — the depth over which it can restore every column family a block
    /// wrote, rather than only the families the four legacy per-subsystem
    /// journals happen to cover.
    ///
    /// `head_height - boundary + 1`, or `0` when the boundary is unestablished
    /// or above the head.
    ///
    /// # Why a node can have canonical state and no undo history
    ///
    /// The journal is NODE-LOCAL. It is never hashed into a block, never folded
    /// into a state root, and never sent over the wire, which is what makes it
    /// free to change format without a consensus event. The same property means
    /// a node that arrives by SNAPSHOT RESTORE or FAST SYNC receives canonical
    /// state and NO journals: it holds height H and can revert nothing at all.
    /// Its `ObservedFromChain` boundary is then the first height it publishes
    /// itself, and this function counts upward from there.
    ///
    /// So `UNDO_RETENTION_FLOOR = 4_096` — the pruner's promise not to delete
    /// undo data inside the reorg horizon — says nothing about a node that has
    /// only produced 200 blocks since a restore. That node's honest depth is
    /// 200, not 4,096, and the floor cannot raise it: retention is a promise not
    /// to DISCARD history, never a claim to HAVE it.
    pub fn restorable_depth(&self, head_height: BlockHeight) -> u64 {
        match self.boundary {
            Some(b) if head_height >= b => head_height - b + 1,
            _ => 0,
        }
    }

    /// The deepest reorg this node may honestly advertise and perform:
    /// [`Self::restorable_depth`] capped at the engine's own walk limit.
    ///
    /// `engine_max` is a parameter because `sumchain-storage` sits below
    /// `sumchain-consensus` and cannot name `poa::MAX_REORG_WALK`; the consensus
    /// side passes it and pins the two together in its own test.
    ///
    /// # This is not an advertisement to be maintained separately
    ///
    /// It is a READING of the rule the unwind already enforces.
    /// `sumchain_state::reorg_undo::crosses_activation_checkpoint` refuses any
    /// branch reaching below the boundary while holding blocks at or above it,
    /// so a reorg deeper than this number does not quietly do the wrong thing —
    /// it is refused. This function exists so a node can SAY the number (to an
    /// operator, to a peer, to a metric) before it is asked to prove it, rather
    /// than discovering it at the refusal.
    ///
    /// # What a snapshot / fast-sync implementation owes
    ///
    /// `crates/state/src/snapshot.rs` is not this module's to change, and this
    /// is the requirement it must meet, stated so it can be checked:
    ///
    /// 1. A restored node MUST NOT report, advertise or configure a reorg depth
    ///    greater than this value. Immediately after a restore it is `0`.
    /// 2. There is no way to import undo history with a snapshot, because
    ///    journals are not transmitted and a pre-image cannot be derived from a
    ///    post-state. The only way a restored node accumulates undo history is
    ///    by PUBLISHING blocks itself, one journal per block.
    /// 3. A restored node therefore reaches the engine's full horizon exactly
    ///    `engine_max` blocks after the restore point, and not before. Until
    ///    then its usable depth is the number of blocks it has published.
    /// 4. The restore point itself is a hard floor: nothing below it is
    ///    revertible by any record this node holds, which is the same statement
    ///    the activation checkpoint makes about the activation height.
    pub fn advertisable_reorg_depth(&self, head_height: BlockHeight, engine_max: u64) -> u64 {
        self.restorable_depth(head_height).min(engine_max)
    }

    /// The journal for a block about to be reverted, or a defined answer for its
    /// absence.
    ///
    /// The single function both the producer and the reorg consumer agree on, so
    /// "what happens when the journal is missing" has one implementation rather
    /// than one per call site.
    ///
    /// * present  — decoded and validated against the key it was read under;
    ///   a record that disagrees, is truncated, is out of canonical order or
    ///   carries an unimplemented version is an ERROR, never a shorter journal.
    /// * absent, at or above the boundary — ERROR. The revert halts.
    /// * absent, below the boundary — `Ok(None)`: pre-journal history, and the
    ///   consumer falls back to the legacy per-subsystem journals.
    ///
    /// The third case is the only silence, and it is bounded by a height the
    /// database itself establishes.
    pub fn load_for_revert(
        &self,
        db: &Database,
        height: BlockHeight,
        block_hash: &Hash,
    ) -> Result<Option<ApplicationJournal>> {
        let key = crate::schema::journal_key(height, block_hash);
        match db.get(crate::db::cf::APPLICATION_JOURNAL, &key)? {
            Some(bytes) => Ok(Some(ApplicationJournal::decode_for(
                &bytes, height, block_hash,
            )?)),
            None => match self.requirement_at(height) {
                JournalRequirement::PreActivation => Ok(None),
                JournalRequirement::Required => Err(invalid(format!(
                    "no application journal for block {block_hash} at height {height}, \
                     which is at or above this chain's journal boundary ({}); refusing \
                     to revert a block whose undo record is missing rather than \
                     unwinding part of it and reporting success",
                    self.boundary
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "unestablished".to_string())
                ))),
            },
        }
    }
}

/// The lowest height for which this database holds a journal.
///
/// The journal key is height big-endian then the block hash, and RocksDB
/// iterates in byte order, so the FIRST key is the lowest height. One seek, not
/// a scan.
fn lowest_journal_height(db: &Database) -> Result<Option<BlockHeight>> {
    let mut it = db.iter(crate::db::cf::APPLICATION_JOURNAL)?;
    let Some((key, _)) = it.next() else {
        return Ok(None);
    };
    if key.len() < 8 {
        return Err(invalid(format!(
            "application journal key is {} byte(s); every key is an 8-byte \
             big-endian height followed by a 32-byte block hash",
            key.len()
        )));
    }
    let mut h = [0u8; 8];
    h.copy_from_slice(&key[..8]);
    Ok(Some(u64::from_be_bytes(h)))
}

/// The highest record format version stored in this database.
///
/// Reads the version field of every stored record — a one-off scan of the
/// journal column family, meant for a startup check rather than a hot path. The
/// field sits at a fixed offset directly after the magic, so nothing is decoded
/// beyond seven bytes per record.
pub fn highest_stored_format_version(db: &Database) -> Result<Option<u16>> {
    let mut highest: Option<u16> = None;
    for (key, value) in db.iter(crate::db::cf::APPLICATION_JOURNAL)? {
        if value.len() < MAGIC.len() + 2 || &value[..MAGIC.len()] != MAGIC {
            return Err(invalid(format!(
                "application journal at key {} is not a journal record; refusing to \
                 report a version watermark over data this binary cannot parse",
                hex::encode(&key)
            )));
        }
        let v = u16::from_be_bytes([value[MAGIC.len()], value[MAGIC.len() + 1]]);
        highest = Some(highest.map_or(v, |h: u16| h.max(v)));
    }
    Ok(highest)
}

/// Refuse to run against history this binary cannot read.
///
/// The downgrade check. Once a newer binary has written post-activation records
/// in a format this one does not implement, this one cannot revert those blocks
/// — and finding that out during a reorg is finding it out too late, with the
/// chain already committed to unwinding. Called at startup, it turns a silent
/// future failure into a refusal to start.
pub fn refuse_downgrade(db: &Database) -> Result<()> {
    validate_startup(db).map(|_| ())
}

// ═══════════════════════════════════════════════════════════════════════════
// PERSISTED FORMAT STATE, AND THE STARTUP GATE
// ═══════════════════════════════════════════════════════════════════════════

/// `META` key holding the height a snapshot restore or fast sync left this
/// database at — the floor below which it holds NO undo history of any kind.
///
/// # Why this row exists, and who writes it
///
/// The application journal is node-local: never hashed into a block, never
/// folded into a state root, never sent over the wire. That is what makes the
/// format free to change without a consensus event, and it has a consequence —
/// **a snapshot cannot carry undo history.** A restored node receives canonical
/// state at some height and no journals, generic or legacy, for anything below
/// it. It can reverse nothing until it has published blocks of its own.
///
/// `ObservedFromChain` alone cannot see that. On a freshly restored database the
/// journal family is empty, so the observed boundary is unestablished, which is
/// indistinguishable from a genuine pre-journal chain — and a pre-journal chain
/// legitimately unwinds from the four legacy per-subsystem journals, which a
/// restored node does not have either.
///
/// This row removes the ambiguity, and it is the seam between the two halves of
/// the work: **the restore path writes it** (see
/// [`record_undo_history_floor`] and [`stage_undo_history_floor`]), and
/// everything that reads an activation honours it.
/// [`JournalActivation::resolve`] raises the boundary to `floor + 1`, so the
/// checkpoint (§7.3), the advertised depth (§13) and the planner's depth
/// refusal all bind without any further plumbing.
///
/// # This is the ONLY row that records the fact
///
/// A previous prototype recorded the same fact twice: this key, and
/// `snapshot/imported_at` under a separate `snapshot_meta` module with its own
/// encoding, its own decode failure and its own (non-monotone) write rule. Two
/// rows for one fact merge without conflict and are wrong together — a restore
/// that writes one and not the other leaves the journal boundary and the
/// advertised history depth disagreeing about the same node, and nothing in
/// either module can detect the disagreement because neither knows the other
/// exists.
///
/// They are collapsed here. There is one key, one encoding, one decode failure
/// and one write rule, and every consumer — the activation boundary, the
/// startup gate, the reorg planner's depth refusal, and the sync-capability
/// report an RPC serves — reads this row. Neither prototype shipped, so there
/// is NO dual write, NO read fallback and NO migration: a database that somehow
/// holds the old key is a database this binary has never written, and the old
/// key is simply ignored.
pub const UNDO_HISTORY_FLOOR_META_KEY: &[u8] = b"application_journal/undo_history_floor";

/// The height a restore left this database at, if one did.
pub fn undo_history_floor(db: &Database) -> Result<Option<BlockHeight>> {
    match db.get(crate::db::cf::META, UNDO_HISTORY_FLOOR_META_KEY)? {
        None => Ok(None),
        Some(v) if v.len() == 8 => {
            let mut h = [0u8; 8];
            h.copy_from_slice(&v);
            Ok(Some(u64::from_be_bytes(h)))
        }
        Some(v) => Err(invalid(format!(
            "the undo-history floor row is {} byte(s); it is an 8-byte big-endian block \
             height, and a row of any other width means something other than this binary \
             wrote it. This node cannot establish what history it holds and must not \
             serve any",
            v.len()
        ))),
    }
}

/// Record that this database was populated by a snapshot restore or fast sync
/// that left it at `height`, with no undo history below that point.
///
/// **This is the function a restore path must call**, in the same batch that
/// makes the restored state durable if it can, and before the node serves or
/// imports anything if it cannot. Calling it is what stops the node claiming a
/// reorg depth it cannot honour.
///
/// Monotone: a later restore may only raise the floor. Lowering it would claim
/// undo history the node never acquired.
pub fn record_undo_history_floor(db: &Database, height: BlockHeight) -> Result<()> {
    let mut batch = db.batch();
    if !stage_undo_history_floor(db, &mut batch, height)? {
        return Ok(());
    }
    batch.commit()
}

/// Stage the floor into a batch the CALLER commits — the form a restore path
/// must use.
///
/// # Why a staging form exists at all
///
/// [`record_undo_history_floor`] is a write of its own, so a restore that
/// imports state and then calls it has a window between the two. A crash in
/// that window leaves a database holding restored state at height `h` with NO
/// floor recorded, which is precisely the shape this row exists to rule out:
/// the journal family is empty, the boundary reads as unestablished, and the
/// node treats every height below `h` as pre-activation history it may unwind
/// from legacy diffs it does not have. The restore succeeded and the node is
/// wrong about itself, with nothing left to notice it.
///
/// Staging removes the window. The floor goes into the SAME [`WriteBatch`] as
/// the restored rows, RocksDB commits a batch atomically, and the two facts are
/// exactly as durable as each other: either the node holds restored state and
/// knows its floor, or it holds neither.
///
/// Returns whether anything was staged. `false` means the recorded floor is
/// already at or above `height` and the batch was left untouched — monotone,
/// for the same reason [`record_undo_history_floor`] is: lowering the floor
/// would claim undo history the node never acquired.
///
/// The monotonicity check reads `db` as it is NOW, so a caller must not stage
/// two floors into one batch and expect the second to see the first. A restore
/// stages one.
pub fn stage_undo_history_floor(
    db: &Database,
    batch: &mut WriteBatch<'_>,
    height: BlockHeight,
) -> Result<bool> {
    if let Some(existing) = undo_history_floor(db)? {
        if height <= existing {
            return Ok(false);
        }
    }
    batch.put(
        crate::db::cf::META,
        UNDO_HISTORY_FLOOR_META_KEY,
        &height.to_be_bytes(),
    )?;
    Ok(true)
}

/// `META` key holding the highest record format version this database has ever
/// had written into it.
///
/// # Why a persisted row and not only the scan
///
/// [`highest_stored_format_version`] derives the watermark from the records
/// themselves, which is exact while the records are there. Pruning removes
/// records (§7.4 of the contract, and [`crate::pruner`]), and a pruned database
/// can reach a state where the newest surviving record is older than the newest
/// record ever written — or where the family is empty entirely. At that point
/// the scan says "nothing", and a downgrade that the records would have refused
/// becomes silently permitted.
///
/// This row does not get pruned. It is stamped by every publish, in the SAME
/// batch as the block, so it is exactly as durable as the chain it describes,
/// and it is monotone by construction: a binary only ever writes its own
/// version, and an older binary never gets far enough to write anything because
/// this gate stops it first.
pub const FORMAT_HIGH_WATER_META_KEY: &[u8] = b"application_journal/format_high_water";

/// The value every publish stamps into [`FORMAT_HIGH_WATER_META_KEY`].
pub(crate) fn format_high_water_stamp() -> [u8; 2] {
    FORMAT_VERSION_V1.to_be_bytes()
}

/// The persisted high-water version, or `None` on a database that has never
/// published a block through a binary that stamps it.
pub fn persisted_format_high_water(db: &Database) -> Result<Option<u16>> {
    match db.get(crate::db::cf::META, FORMAT_HIGH_WATER_META_KEY)? {
        None => Ok(None),
        Some(v) if v.len() == 2 => Ok(Some(u16::from_be_bytes([v[0], v[1]]))),
        Some(v) => Err(invalid(format!(
            "the application-journal format high-water row is {} byte(s); it is a \
             2-byte big-endian format version, and a row of any other width means \
             something other than this binary wrote it",
            v.len()
        ))),
    }
}

/// What the startup gate found. Returned rather than logged, so a caller can
/// report it and a test can assert on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFormatState {
    /// The record format this binary implements.
    pub binary_version: u16,
    /// The stamped watermark, which survives pruning.
    pub persisted: Option<u16>,
    /// The watermark derived from the records present right now.
    pub scanned: Option<u16>,
    /// The height at and above which a revert must find a journal, observed
    /// from this database.
    pub observed_boundary: Option<BlockHeight>,
    /// The recorded undo-history floor — the height a snapshot restore or fast
    /// sync left this database at, below which it holds no undo records of any
    /// kind. `None` on a node that executed every block it holds.
    ///
    /// Read at startup and not merely at the first reorg, because it is the one
    /// fact that distinguishes a restored database from a genuine pre-journal
    /// chain: both have an empty journal family, and only one of them may fall
    /// back to the legacy per-subsystem diffs. A node that never reads it at
    /// boot cannot say what it holds until something asks it to prove it.
    pub undo_history_floor: Option<BlockHeight>,
}

impl JournalFormatState {
    /// The version this database must be read at: the higher of the two
    /// watermarks. `None` only on a database with no journal history at all.
    pub fn effective_high_water(&self) -> Option<u16> {
        match (self.persisted, self.scanned) {
            (None, s) => s,
            (p, None) => p,
            (Some(p), Some(s)) => Some(p.max(s)),
        }
    }
}

/// The startup gate: refuse to run against journal history this binary cannot
/// read, and report the format state to the caller.
///
/// # The operational rule this enforces
///
/// **Once a node has published a block under a record format, it must not be
/// downgraded to a binary that implements an older one.** The prohibition is
/// operational, not merely advisory, because the failure it prevents is silent
/// and late: an old binary meeting a new record has no way to unwind the blocks
/// that record describes, and it discovers that during a reorg, with the chain
/// already committed to unwinding. The only safe recovery from that position is
/// to resync.
///
/// Two watermarks, and the gate takes the higher:
///
/// * the **scan** ([`highest_stored_format_version`]) — exact over the records
///   that are present;
/// * the **stamp** ([`persisted_format_high_water`]) — survives pruning, so a
///   database whose newer records have aged out still refuses the downgrade.
///
/// A database where the stamp is absent but records exist is not treated as a
/// fault. That is the legitimate shape of a database published by a binary
/// before stamping existed, and the scan still covers it.
///
/// Called from the node's boot sequence (`sumchain_node::node::Node::new`,
/// immediately after the database is opened and before state, consensus or RPC
/// are constructed), so the refusal happens before anything can act on history
/// it cannot revert.
pub fn validate_startup(db: &Database) -> Result<JournalFormatState> {
    let state = JournalFormatState {
        binary_version: FORMAT_VERSION_V1,
        persisted: persisted_format_high_water(db)?,
        scanned: highest_stored_format_version(db)?,
        observed_boundary: lowest_journal_height(db)?,
        undo_history_floor: undo_history_floor(db)?,
    };
    if let Some(v) = state.effective_high_water() {
        if v > FORMAT_VERSION_V1 {
            return Err(invalid(format!(
                "this database holds application journals in record format version {v} \
                 (stamped: {:?}, present in records: {:?}), and this binary implements \
                 version {FORMAT_VERSION_V1}. It cannot revert a block written by the \
                 newer binary, so it refuses to start rather than discovering that \
                 during a reorg. Downgrading a node that has published under a newer \
                 record format is prohibited; recover by running the newer binary, or \
                 by resyncing this node from an empty database.",
                state.persisted, state.scanned
            )));
        }
    }
    Ok(state)
}

fn usize_of(n: u64) -> Result<usize> {
    usize::try_from(n).map_err(|_| {
        invalid(format!(
            "application journal: length {n} exceeds this platform"
        ))
    })
}

/// A cursor that cannot read past the end.
///
/// Every `take` is bounds-checked and reports how much was wanted, so a
/// truncated record fails with the position rather than panicking on a slice.
struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Reader<'b> {
    fn new(bytes: &'b [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'b [u8]> {
        let end = self.at.checked_add(n).ok_or_else(|| {
            invalid("application journal: read length overflowed the cursor".to_string())
        })?;
        if end > self.bytes.len() {
            return Err(invalid(format!(
                "application journal is truncated: wanted {n} byte(s) at offset {} \
                 but the record is {} byte(s) long",
                self.at,
                self.bytes.len()
            )));
        }
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn is_exhausted(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    fn entry(cf: &str, key: &[u8], before: Preimage) -> JournalEntry {
        JournalEntry::new(
            cf.to_string(),
            key.to_vec(),
            before,
            AfterImage::of(cf, key, Some(b"after")),
        )
    }

    /// The sort key is TOTAL over a derived entry set: no two entries can share
    /// `(cf, key)`, because the overlay stores one pre-image per key per family.
    /// A sort with no ties has one result, whatever order it started in.
    #[test]
    fn the_sort_key_is_total_over_the_entries_of_one_block() {
        let entries = vec![
            entry("b", b"k2", Preimage::Absent),
            entry("a", b"k9", Preimage::Value(b"x".to_vec())),
            entry("b", b"k1", Preimage::Absent),
            entry("a", b"k1", Preimage::Absent),
        ];
        let j = ApplicationJournal::bind(7, h(1), entries).unwrap();
        let keys: Vec<_> = j
            .entries()
            .iter()
            .map(|e| (e.cf().to_string(), e.key().to_vec()))
            .collect();

        let mut seen = BTreeSet::new();
        for k in &keys {
            assert!(
                seen.insert(k.clone()),
                "duplicate sort key {k:?}: not total"
            );
        }
        assert!(
            keys.windows(2).all(|w| w[0] < w[1]),
            "entries must be strictly increasing: {keys:?}"
        );
    }

    /// Two entry lists with the same content in different orders encode to the
    /// same bytes. This is the property the whole record rests on.
    #[test]
    fn insertion_order_does_not_reach_the_bytes() {
        let mk = |order: [usize; 4]| {
            let pool = [
                entry("zeta", b"\xff", Preimage::Value(b"v".to_vec())),
                entry("alpha", b"\x00", Preimage::Absent),
                entry("alpha", b"\x01", Preimage::Value(Vec::new())),
                entry("beta", b"\x00", Preimage::Absent),
            ];
            let entries = order.iter().map(|i| pool[*i].clone()).collect();
            ApplicationJournal::bind(4, h(2), entries)
                .unwrap()
                .encode()
                .unwrap()
        };
        assert_eq!(mk([0, 1, 2, 3]), mk([3, 2, 1, 0]));
        assert_eq!(mk([0, 1, 2, 3]), mk([2, 0, 3, 1]));
    }

    /// An empty value is not an absent key. Both round-trip, and they differ.
    #[test]
    fn absent_before_and_empty_value_before_are_different_records() {
        let absent =
            ApplicationJournal::bind(1, h(3), vec![entry("cf", b"k", Preimage::Absent)]).unwrap();
        let empty = ApplicationJournal::bind(
            1,
            h(3),
            vec![entry("cf", b"k", Preimage::Value(Vec::new()))],
        )
        .unwrap();
        assert_ne!(absent.encode().unwrap(), empty.encode().unwrap());

        let back = ApplicationJournal::decode_for(&absent.encode().unwrap(), 1, &h(3)).unwrap();
        assert_eq!(*back.entries()[0].before(), Preimage::Absent);
        let back = ApplicationJournal::decode_for(&empty.encode().unwrap(), 1, &h(3)).unwrap();
        assert_eq!(*back.entries()[0].before(), Preimage::Value(Vec::new()));
    }

    #[test]
    fn a_record_refuses_the_wrong_block() {
        let j =
            ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]).unwrap();
        let bytes = j.encode().unwrap();
        assert!(ApplicationJournal::decode_for(&bytes, 5, &h(4)).is_ok());

        let wrong_hash = ApplicationJournal::decode_for(&bytes, 5, &h(9)).unwrap_err();
        assert!(wrong_hash
            .to_string()
            .contains("another block's undo record"));
        let wrong_height = ApplicationJournal::decode_for(&bytes, 6, &h(4)).unwrap_err();
        assert!(wrong_height
            .to_string()
            .contains("another block's undo record"));
    }

    #[test]
    fn truncation_at_every_length_is_an_error_not_a_short_journal() {
        let j = ApplicationJournal::bind(
            5,
            h(4),
            vec![
                entry("cf", b"k", Preimage::Value(b"old".to_vec())),
                entry("df", b"k", Preimage::Absent),
            ],
        )
        .unwrap();
        let bytes = j.encode().unwrap();
        for cut in 0..bytes.len() {
            assert!(
                ApplicationJournal::decode_for(&bytes[..cut], 5, &h(4)).is_err(),
                "a record truncated to {cut} byte(s) must be refused, not parsed"
            );
        }
        assert!(ApplicationJournal::decode_for(&bytes, 5, &h(4)).is_ok());
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let j =
            ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]).unwrap();
        let mut bytes = j.encode().unwrap();
        bytes.push(0);
        let err = ApplicationJournal::decode_for(&bytes, 5, &h(4)).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn an_unimplemented_format_version_is_refused_rather_than_guessed() {
        let j =
            ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]).unwrap();
        let mut bytes = j.encode().unwrap();
        // The version field sits directly after the magic.
        bytes[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&2u16.to_be_bytes());
        let err = ApplicationJournal::decode_for(&bytes, 5, &h(4)).unwrap_err();
        assert!(
            err.to_string().contains("not implemented by this binary"),
            "{err}"
        );
    }

    #[test]
    fn bad_magic_is_refused_at_byte_zero() {
        let err =
            ApplicationJournal::decode_for(b"not a journal record at all", 0, &h(0)).unwrap_err();
        assert!(err.to_string().contains("bad magic"), "{err}");
    }

    /// A record whose entries are out of order is not a second valid encoding of
    /// the same block: it is refused, so "identical content, identical bytes"
    /// holds in both directions.
    #[test]
    fn a_non_canonically_ordered_record_is_refused() {
        let a = entry("aa", b"k", Preimage::Absent);
        let b = entry("bb", b"k", Preimage::Absent);
        let good = ApplicationJournal::bind(1, h(5), vec![a.clone(), b.clone()]).unwrap();
        let bytes = good.encode().unwrap();
        assert!(ApplicationJournal::decode_for(&bytes, 1, &h(5)).is_ok());

        // Re-encode by hand in the wrong order, bypassing `bind`'s sort.
        let swapped = ApplicationJournal {
            format_version: FORMAT_VERSION_V1,
            height: 1,
            block_hash: h(5),
            entries: vec![b, a],
        };
        let err = ApplicationJournal::decode_for(&swapped.encode().unwrap(), 1, &h(5)).unwrap_err();
        assert!(err.to_string().contains("canonical order"), "{err}");
    }

    /// One net entry per `(cf, key)` is an invariant, not a hope.
    ///
    /// The overlay cannot produce a duplicate — its pre-image map is keyed by
    /// `(family, key)` — so this reaches `bind` only through a future derivation
    /// that lost the invariant. It is refused there rather than merged, because
    /// a merge would have to pick one of two pre-images and neither is knowably
    /// the one the block started from. That refusal is what lets the CONSUMER
    /// stop caring about replay order: with at most one entry per key, any
    /// deterministic order over the entries produces the same state.
    #[test]
    fn a_duplicate_cf_key_pair_is_refused_rather_than_merged() {
        let err = ApplicationJournal::bind(
            3,
            h(7),
            vec![
                entry("cf", b"k", Preimage::Absent),
                entry("cf", b"k", Preimage::Value(b"other".to_vec())),
            ],
        )
        .unwrap_err();
        assert!(err.to_string().contains("one NET entry per"), "{err}");

        // Same key, different family: not a duplicate.
        assert!(ApplicationJournal::bind(
            3,
            h(7),
            vec![
                entry("cf_a", b"k", Preimage::Absent),
                entry("cf_b", b"k", Preimage::Absent),
            ],
        )
        .is_ok());
    }

    /// The after tag binds the family and the key, so a tag cannot be moved
    /// between entries and still verify.
    #[test]
    fn the_after_tag_binds_its_family_and_key() {
        let v = Some(&b"same value"[..]);
        assert_ne!(
            AfterImage::of("cf_a", b"k", v),
            AfterImage::of("cf_b", b"k", v)
        );
        assert_ne!(
            AfterImage::of("cf", b"k1", v),
            AfterImage::of("cf", b"k2", v)
        );
        assert_eq!(AfterImage::of("cf", b"k", None), AfterImage::Absent);
    }
}
