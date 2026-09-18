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
    pub(crate) fn bind(
        height: BlockHeight,
        block_hash: Hash,
        mut entries: Vec<JournalEntry>,
    ) -> Self {
        entries.sort();
        Self {
            format_version: FORMAT_VERSION_V1,
            height,
            block_hash,
            entries,
        }
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
        let boundary = match source {
            ActivationSource::Pinned(h) => Some(h),
            ActivationSource::ObservedFromChain => lowest_journal_height(db)?,
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
    match highest_stored_format_version(db)? {
        Some(v) if v > FORMAT_VERSION_V1 => Err(invalid(format!(
            "this database holds application journals in record format version {v}, \
             and this binary implements version {FORMAT_VERSION_V1}. It cannot revert \
             a block written by the newer binary, so it refuses to start rather than \
             discovering that during a reorg."
        ))),
        _ => Ok(()),
    }
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
        let j = ApplicationJournal::bind(7, h(1), entries);
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
            ApplicationJournal::bind(4, h(2), entries).encode().unwrap()
        };
        assert_eq!(mk([0, 1, 2, 3]), mk([3, 2, 1, 0]));
        assert_eq!(mk([0, 1, 2, 3]), mk([2, 0, 3, 1]));
    }

    /// An empty value is not an absent key. Both round-trip, and they differ.
    #[test]
    fn absent_before_and_empty_value_before_are_different_records() {
        let absent = ApplicationJournal::bind(1, h(3), vec![entry("cf", b"k", Preimage::Absent)]);
        let empty = ApplicationJournal::bind(
            1,
            h(3),
            vec![entry("cf", b"k", Preimage::Value(Vec::new()))],
        );
        assert_ne!(absent.encode().unwrap(), empty.encode().unwrap());

        let back = ApplicationJournal::decode_for(&absent.encode().unwrap(), 1, &h(3)).unwrap();
        assert_eq!(*back.entries()[0].before(), Preimage::Absent);
        let back = ApplicationJournal::decode_for(&empty.encode().unwrap(), 1, &h(3)).unwrap();
        assert_eq!(*back.entries()[0].before(), Preimage::Value(Vec::new()));
    }

    #[test]
    fn a_record_refuses_the_wrong_block() {
        let j = ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]);
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
        );
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
        let j = ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]);
        let mut bytes = j.encode().unwrap();
        bytes.push(0);
        let err = ApplicationJournal::decode_for(&bytes, 5, &h(4)).unwrap_err();
        assert!(err.to_string().contains("trailing"), "{err}");
    }

    #[test]
    fn an_unimplemented_format_version_is_refused_rather_than_guessed() {
        let j = ApplicationJournal::bind(5, h(4), vec![entry("cf", b"k", Preimage::Absent)]);
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
        let good = ApplicationJournal::bind(1, h(5), vec![a.clone(), b.clone()]);
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
