//! Stored retention trackers for #129: a DORMANT seam that keeps trackers,
//! their reverse indexes and the recompute cursor as ordinary application
//! state, over the kernels in [`crate::compute_pool`].
//!
//! Nothing reads or writes retention state through this module. No other
//! module of any crate names it, and `tests/retention_tracker_store_dormant.rs`
//! fails if that changes. The pool gate is refused at genesis load, so no
//! tracker exists on any chain; this module changes no execution path and no
//! state root.
//!
//! # What it provides
//!
//! The storage half of #129 scopes (3), (5) and (6), and only that half:
//!
//! | id | obligation | how it holds | tests in `tests/retention_tracker_store.rs` |
//! |----|------------|--------------|------------------------------------------------|
//! | R1 | A row lands only when its block is published, in the same batch, and never otherwise. | Every write takes an [`ExecutionView`]; nothing makes one from a [`Database`]. `AcceptedCandidate::publish` commits the overlay in one batch. | `r1_*` |
//! | R2 | Undoing a block restores every tracker, index and cursor row it wrote, exactly. | The generic application journal's pre-images. This module has no unwind code. | `r2_*` |
//! | R3 | Competing blocks never share rows; a branch switch moves retention state in the one adoption batch. | Overlays and `BranchState` layers keep siblings apart; `build_adoption_batch` adopts. | `r3_*` |
//! | R4 | Every read fails closed: missing when required, present when absent, truncated, extended, of another version, under another key, out of canonical order or with a count that disagrees is an error, never "no tracker". | Fixed-width codecs that repeat their own key, checked before use. | `r4_*` |
//! | R5 | Every write states what it expects and checks it first: start refuses a tracked key, replace and remove refuse an unknown one, and none overwrites a row it cannot decode. A refused write stages nothing. | Every check runs before the first staged write. | `r5_*` |
//! | R6 | The stored indexes answer exactly what the in-memory kernel [`crate::compute_pool::RetentionReverseIndex`] answers for the same operations, including its refusals and its per-tracker and per-job bounds. | The same [`ReverseIndexLimits`] check; the same job-entry arithmetic. | `r6_*` |
//! | R7 | Rows stay in their own namespaces. | [`Namespaces::check`] refuses a layout outside the database's families, in a family a committed digest folds in full, overlapping the account range, or with two kinds whose prefixes overlap. | `r7_*` |
//!
//! # What is deliberately NOT decided here
//!
//! * **The tracker key's derivation** (#129 scope (3)): it includes
//!   `file_assignment_epoch_commitment`, which depends on D-E. A
//!   [`TrackerKey`] is taken as given.
//! * **What `height` means (D-H) and which epochs count (D-E).** The epochs and
//!   archives a tracker is indexed under, and the dependency generations it
//!   records, are the caller's.
//! * **`R_job`, where it is fixed, and whether 0 is refused there.** Stored as
//!   given; 0 is not refused here.
//! * **Whether `since` carries over a reassignment.** `since` and
//!   `last_computed_height` are stored as given.
//! * **The per-archive `status_generation`** (#129 scope (1)). Generations
//!   are stored as the caller recorded them; nothing here reads a current one.
//! * **Every limit.** [`ReverseIndexLimits`] is an argument of every call that
//!   can grow the indexes; no value is chosen.
//! * **Where rows live.** The family and prefix of each row kind come from an
//!   injected [`RetentionLayout`], which has no production implementation, and
//!   no column family is added.
//! * **Commitment.** Rows are uncommitted application state. Folding them into
//!   the state root would be a separate, gated decision; see [`Namespaces`].
//!
//! # Row formats (version 1, big-endian)
//!
//! Every value repeats the logical key it belongs under, so a row copied under
//! another key is refused. Optional heights are a flag byte (0 none, 1 some)
//! and a `u64` that must be 0 when the flag is 0. Lists are in strictly
//! ascending order, so every accepted value has one encoding.
//!
//! ```text
//! tracker state  key: prefix ‖ tracker(32)
//!   "SRTS" ‖ v ‖ tracker(32) ‖ r_job u32 ‖ chunk_count u32 ‖ since(1+8)
//!   ‖ last_computed(1+8) ‖ n u32 ‖ n × (archive(20) ‖ generation u64)
//! index record   key: prefix ‖ tracker(32)
//!   "SRIX" ‖ v ‖ tracker(32) ‖ job(32) ‖ file_root(32) ‖ r_job u32
//!   ‖ interval_version u32 ‖ chunk_count u32 ‖ e u32 ‖ e × epoch u64
//!   ‖ a u32 ‖ a × archive(20)                                   (e >= 1)
//! archive member key: prefix ‖ archive(20) ‖ tracker(32)
//!   "SRAM" ‖ v ‖ archive(20) ‖ tracker(32)
//! file member    key: prefix ‖ file_root(32) ‖ tracker(32) ‖ epoch u64
//!   "SRFM" ‖ v ‖ file_root(32) ‖ tracker(32) ‖ epoch u64 ‖ r_job u32
//!   ‖ interval_version u32
//! job member     key: prefix ‖ job(32) ‖ tracker(32)
//!   "SRJM" ‖ v ‖ job(32) ‖ tracker(32)
//! job entries    key: prefix ‖ job(32)
//!   "SRJE" ‖ v ‖ job(32) ‖ entries u64                          (entries >= 1)
//! cursor         key: prefix
//!   "SRCU" ‖ v ‖ flag u8 ‖ tracker(32)               (tracker zero if flag 0)
//! ```

use std::collections::BTreeSet;

use sumchain_primitives::{Address, Hash};
use sumchain_storage::db::{cf, Database, ALL_CFS};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::schema::ACCOUNT_KEY_PREFIX;
use sumchain_storage::StorageError;

use crate::compute_pool::{
    FileIndexEntry, JobId, PoolError, RecomputeCursor, ReverseIndexLimits, TrackerIndexRecord,
    TrackerKey,
};

/// The only row version this binary writes or reads.
pub const VERSION: u16 = 1;

const TRACKER_MAGIC: [u8; 4] = *b"SRTS";
const INDEX_MAGIC: [u8; 4] = *b"SRIX";
const ARCHIVE_MAGIC: [u8; 4] = *b"SRAM";
const FILE_MAGIC: [u8; 4] = *b"SRFM";
const JOB_MAGIC: [u8; 4] = *b"SRJM";
const JOB_ENTRIES_MAGIC: [u8; 4] = *b"SRJE";
const CURSOR_MAGIC: [u8; 4] = *b"SRCU";

/// Families a committed digest folds in full. A row there would change the
/// state root as soon as that digest's gate opens.
const FOLDED_IN_FULL: &[&str] = &[cf::COMPUTE_POOL_STATE, cf::BEACON_STATE];

/// The kinds of row this seam stores. Each has its own namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RowKind {
    TrackerState,
    IndexRecord,
    ArchiveMember,
    FileMember,
    JobMember,
    JobEntries,
    Cursor,
}

impl RowKind {
    pub const ALL: [RowKind; 7] = [
        RowKind::TrackerState,
        RowKind::IndexRecord,
        RowKind::ArchiveMember,
        RowKind::FileMember,
        RowKind::JobMember,
        RowKind::JobEntries,
        RowKind::Cursor,
    ];
}

/// Where each kind of row lives: a family and a key prefix.
///
/// Injected so that this seam freezes no family or key. No production
/// implementation exists. A production layout must also keep every prefix
/// out of every range another subsystem writes or scans in that family;
/// [`Namespaces::check`] refuses the overlaps it can see (the account range in
/// `STATE`, the families a committed digest folds in full), but it cannot
/// know every subsystem's keys, so disjointness is the layout's obligation.
pub trait RetentionLayout {
    fn namespace(&self, kind: RowKind) -> (&'static str, Vec<u8>);
}

/// A layout that has passed [`Namespaces::check`]. Every operation takes one,
/// so an unchecked layout cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Namespaces {
    entries: Vec<(RowKind, &'static str, Vec<u8>)>,
}

impl Namespaces {
    /// Check `layout` and keep its namespaces. Refused:
    /// * a family the database does not open (this seam adds none);
    /// * a family a committed digest folds in full;
    /// * an empty prefix;
    /// * in `STATE`, a prefix that overlaps the account range (either is a
    ///   prefix of the other);
    /// * two kinds in one family whose prefixes overlap.
    pub fn check(layout: &(impl RetentionLayout + ?Sized)) -> Result<Self, TrackerStoreError> {
        let entries: Vec<(RowKind, &'static str, Vec<u8>)> = RowKind::ALL
            .iter()
            .map(|&kind| {
                let (family, prefix) = layout.namespace(kind);
                (kind, family, prefix)
            })
            .collect();
        let overlap = |a: &[u8], b: &[u8]| a.starts_with(b) || b.starts_with(a);
        for (kind, family, prefix) in &entries {
            let refuse = |why: String| Err(TrackerStoreError::Layout { kind: *kind, why });
            if !ALL_CFS.contains(family) {
                return refuse(format!("family {family} is not one the database opens"));
            }
            if FOLDED_IN_FULL.contains(family) {
                return refuse(format!(
                    "family {family} is folded in full into a committed digest"
                ));
            }
            if prefix.is_empty() {
                return refuse("the prefix is empty".to_string());
            }
            if *family == cf::STATE && overlap(prefix, ACCOUNT_KEY_PREFIX) {
                return refuse("the prefix overlaps the account range in STATE".to_string());
            }
        }
        for (i, (kind, family, prefix)) in entries.iter().enumerate() {
            for (other, other_family, other_prefix) in &entries[i + 1..] {
                if family == other_family && overlap(prefix, other_prefix) {
                    return Err(TrackerStoreError::Layout {
                        kind: *kind,
                        why: format!("its prefix overlaps {other:?}'s in family {family}"),
                    });
                }
            }
        }
        Ok(Self { entries })
    }

    fn of(&self, kind: RowKind) -> (&'static str, &[u8]) {
        let (_, family, prefix) = self
            .entries
            .iter()
            .find(|(k, _, _)| *k == kind)
            .expect("every kind is checked");
        (family, prefix)
    }

    fn key(&self, kind: RowKind, parts: &[&[u8]]) -> (&'static str, Vec<u8>) {
        let (family, prefix) = self.of(kind);
        let mut key = prefix.to_vec();
        for part in parts {
            key.extend_from_slice(part);
        }
        (family, key)
    }
}

/// Whether a row must exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Required,
    Absent,
}

/// Why a stored value was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("{len} bytes, shorter than the {need}-byte minimum")]
    Truncated { len: usize, need: usize },
    #[error("does not begin with its magic")]
    BadMagic,
    #[error("has version {found}; this binary reads only version {VERSION}")]
    UnsupportedVersion { found: u16 },
    #[error("names another key than the one it is stored under")]
    KeyMismatch,
    #[error("is {actual} bytes where its counts require {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("has an optional-height flag {flag}, or a value under a zero flag")]
    BadOption { flag: u8 },
    #[error("lists {what} out of strictly ascending order")]
    NotCanonical { what: &'static str },
    #[error("has a {what} of zero, which is never stored")]
    Zero { what: &'static str },
    #[error("has {count} {what}, more than its u32 count field holds")]
    TooMany { what: &'static str, count: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum TrackerStoreError {
    #[error("retention tracker store: {0}")]
    Storage(#[from] StorageError),
    #[error("retention tracker store: {0}")]
    Pool(#[from] PoolError),
    #[error("retention tracker store: the {kind:?} row is refused: {source}")]
    Record { kind: RowKind, source: RecordError },
    #[error("retention tracker store: a {kind:?} row is stored under a key of {len} bytes")]
    MalformedKey { kind: RowKind, len: usize },
    #[error("retention tracker store: a {kind:?} row is required and none is stored")]
    Missing { kind: RowKind },
    #[error("retention tracker store: no {kind:?} row is expected, but one is stored")]
    Unexpected { kind: RowKind },
    #[error("retention tracker store: the tracker state and index disagree on {what}")]
    Mismatch { what: &'static str },
    #[error("retention tracker store: layout refused for {kind:?}: {why}")]
    Layout { kind: RowKind, why: String },
}

fn refused(kind: RowKind) -> impl Fn(RecordError) -> TrackerStoreError {
    move |source| TrackerStoreError::Record { kind, source }
}

// ── Reading rows ───────────────────────────────────────────────────────────

/// `(key, value)` rows, in key order.
pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Something rows can be read from: a block's execution view (its own writes,
/// then the branch layer or committed state) or the committed database.
pub trait RowSource {
    fn get_row(&self, cf: &str, key: &[u8]) -> sumchain_storage::Result<Option<Vec<u8>>>;
    /// Every row whose key starts with `prefix`, in key order. A read error
    /// ends the scan with that error; it never truncates it.
    fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> sumchain_storage::Result<Rows>;
}

impl RowSource for ExecutionView<'_, '_> {
    fn get_row(&self, cf: &str, key: &[u8]) -> sumchain_storage::Result<Option<Vec<u8>>> {
        self.get(cf, key)
    }

    fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> sumchain_storage::Result<Rows> {
        let mut out = Vec::new();
        for entry in self.iter_from(cf, prefix)? {
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key, value));
        }
        Ok(out)
    }
}

impl RowSource for Database {
    fn get_row(&self, cf: &str, key: &[u8]) -> sumchain_storage::Result<Option<Vec<u8>>> {
        self.get(cf, key)
    }

    fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> sumchain_storage::Result<Rows> {
        let mut out = Vec::new();
        for entry in self.iter_checked_from(cf, Some(prefix))? {
            let (key, value) = entry?;
            if !key.starts_with(prefix) {
                break;
            }
            out.push((key.to_vec(), value.to_vec()));
        }
        Ok(out)
    }
}

// ── Codec helpers ──────────────────────────────────────────────────────────

struct Reader<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl<'b> Reader<'b> {
    /// Check magic and version; the caller has checked the minimum length.
    fn open(bytes: &'b [u8], magic: [u8; 4], min: usize) -> Result<Self, RecordError> {
        if bytes.len() < min {
            return Err(RecordError::Truncated {
                len: bytes.len(),
                need: min,
            });
        }
        if bytes[..4] != magic {
            return Err(RecordError::BadMagic);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != VERSION {
            return Err(RecordError::UnsupportedVersion { found: version });
        }
        Ok(Self { bytes, at: 6 })
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        let out: [u8; N] = self.bytes[self.at..self.at + N]
            .try_into()
            .expect("length checked before reading");
        self.at += N;
        out
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.take())
    }

    fn opt_u64(&mut self) -> Result<Option<u64>, RecordError> {
        let flag = self.take::<1>()[0];
        let value = self.u64();
        match (flag, value) {
            (0, 0) => Ok(None),
            (1, v) => Ok(Some(v)),
            (flag, _) => Err(RecordError::BadOption { flag }),
        }
    }

    /// Require exactly `expected` bytes in total.
    fn expect_len(&self, expected: usize) -> Result<(), RecordError> {
        if self.bytes.len() != expected {
            return Err(RecordError::LengthMismatch {
                expected,
                actual: self.bytes.len(),
            });
        }
        Ok(())
    }
}

fn header(magic: [u8; 4]) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&VERSION.to_be_bytes());
    out
}

fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => {
            out.push(0);
            out.extend_from_slice(&0u64.to_be_bytes());
        }
        Some(v) => {
            out.push(1);
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

fn count_u32(what: &'static str, count: usize) -> Result<u32, RecordError> {
    u32::try_from(count).map_err(|_| RecordError::TooMany { what, count })
}

/// `needed` bytes from `at`, refusing a count whose bytes would overflow or
/// run past the value.
fn span(at: usize, count: u32, width: usize, len: usize) -> Result<usize, RecordError> {
    let bytes = (count as usize)
        .checked_mul(width)
        .and_then(|b| b.checked_add(at))
        .ok_or(RecordError::LengthMismatch {
            expected: usize::MAX,
            actual: len,
        })?;
    if bytes > len {
        return Err(RecordError::LengthMismatch {
            expected: bytes,
            actual: len,
        });
    }
    Ok(bytes)
}

// ── Tracker state (#129 scope (3)) ─────────────────────────────────────────

/// What one tracker stores (#129 scope (3)): `R_job`, `chunk_count`, the
/// recorded `(archive, generation)` dependencies, `coverage_satisfied_since_height`
/// and `last_computed_height`, all as the caller computed them.
///
/// The dependencies are kept in ascending archive order, one entry per
/// archive: a list naming an archive twice cannot come from a valid recompute
/// ([`crate::compute_pool::retention_tracker_dirty`] reads it as Dirty), so it
/// is refused here rather than stored. An empty list is a valid, stored state,
/// distinct from no tracker at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerState {
    key: TrackerKey,
    r_job: u32,
    chunk_count: u32,
    dependency_generations: Vec<(Address, u64)>,
    coverage_satisfied_since_height: Option<u64>,
    last_computed_height: Option<u64>,
}

const TRACKER_FIXED: usize = 6 + 32 + 4 + 4 + 9 + 9 + 4;
const GENERATION_LEN: usize = 20 + 8;

impl TrackerState {
    pub fn new(
        key: TrackerKey,
        r_job: u32,
        chunk_count: u32,
        mut dependency_generations: Vec<(Address, u64)>,
        coverage_satisfied_since_height: Option<u64>,
        last_computed_height: Option<u64>,
    ) -> Result<Self, RecordError> {
        count_u32("dependency generations", dependency_generations.len())?;
        dependency_generations.sort_by(|a, b| a.0.cmp(&b.0));
        if dependency_generations.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(RecordError::NotCanonical {
                what: "dependency archives",
            });
        }
        Ok(Self {
            key,
            r_job,
            chunk_count,
            dependency_generations,
            coverage_satisfied_since_height,
            last_computed_height,
        })
    }

    pub fn key(&self) -> TrackerKey {
        self.key
    }

    pub fn r_job(&self) -> u32 {
        self.r_job
    }

    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// The recorded dependencies, in ascending archive order.
    pub fn dependency_generations(&self) -> &[(Address, u64)] {
        &self.dependency_generations
    }

    pub fn coverage_satisfied_since_height(&self) -> Option<u64> {
        self.coverage_satisfied_since_height
    }

    pub fn last_computed_height(&self) -> Option<u64> {
        self.last_computed_height
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = header(TRACKER_MAGIC);
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&self.r_job.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        put_opt_u64(&mut out, self.coverage_satisfied_since_height);
        put_opt_u64(&mut out, self.last_computed_height);
        let n = u32::try_from(self.dependency_generations.len()).expect("checked by new");
        out.extend_from_slice(&n.to_be_bytes());
        for (archive, generation) in &self.dependency_generations {
            out.extend_from_slice(archive.as_bytes());
            out.extend_from_slice(&generation.to_be_bytes());
        }
        out
    }

    /// Decode a state stored under `key`, or refuse it.
    pub fn decode_for(bytes: &[u8], key: &TrackerKey) -> Result<Self, RecordError> {
        let mut r = Reader::open(bytes, TRACKER_MAGIC, TRACKER_FIXED)?;
        if &r.take::<32>() != key.as_bytes() {
            return Err(RecordError::KeyMismatch);
        }
        let r_job = r.u32();
        let chunk_count = r.u32();
        let since = r.opt_u64()?;
        let last = r.opt_u64()?;
        let n = r.u32();
        let end = span(r.at, n, GENERATION_LEN, bytes.len())?;
        r.expect_len(end)?;
        let mut generations = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let archive = Address::new(r.take());
            let generation = r.u64();
            if generations
                .last()
                .is_some_and(|(prev, _): &(Address, u64)| *prev >= archive)
            {
                return Err(RecordError::NotCanonical {
                    what: "dependency archives",
                });
            }
            generations.push((archive, generation));
        }
        Ok(Self {
            key: *key,
            r_job,
            chunk_count,
            dependency_generations: generations,
            coverage_satisfied_since_height: since,
            last_computed_height: last,
        })
    }
}

// ── Index record (#129 scope (6)) ──────────────────────────────────────────

const INDEX_FIXED: usize = 6 + 32 + 32 + 32 + 4 + 4 + 4 + 4;

/// The stored form of a [`TrackerIndexRecord`], under its tracker key.
pub fn encode_index_record(
    key: &TrackerKey,
    record: &TrackerIndexRecord,
) -> Result<Vec<u8>, RecordError> {
    let epochs = count_u32("epochs", record.epochs.len())?;
    let archives = count_u32("archives", record.archives.len())?;
    if epochs == 0 {
        return Err(RecordError::Zero {
            what: "epoch count",
        });
    }
    let mut out = header(INDEX_MAGIC);
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(record.job_id.as_bytes());
    out.extend_from_slice(record.file_root.as_bytes());
    out.extend_from_slice(&record.r_job.to_be_bytes());
    out.extend_from_slice(&record.interval_version.to_be_bytes());
    out.extend_from_slice(&record.chunk_count.to_be_bytes());
    out.extend_from_slice(&epochs.to_be_bytes());
    for epoch in &record.epochs {
        out.extend_from_slice(&epoch.to_be_bytes());
    }
    out.extend_from_slice(&archives.to_be_bytes());
    for archive in &record.archives {
        out.extend_from_slice(archive.as_bytes());
    }
    Ok(out)
}

/// Decode an index record stored under `key`, or refuse it.
pub fn decode_index_record(
    bytes: &[u8],
    key: &TrackerKey,
) -> Result<TrackerIndexRecord, RecordError> {
    let mut r = Reader::open(bytes, INDEX_MAGIC, INDEX_FIXED)?;
    if &r.take::<32>() != key.as_bytes() {
        return Err(RecordError::KeyMismatch);
    }
    let job_id = JobId::from_bytes(r.take());
    let file_root = Hash::new(r.take());
    let r_job = r.u32();
    let interval_version = r.u32();
    let chunk_count = r.u32();
    let e = r.u32();
    if e == 0 {
        return Err(RecordError::Zero {
            what: "epoch count",
        });
    }
    // The archive count follows the epochs; it must be inside the value.
    let after_epochs = span(r.at, e, 8, bytes.len())?;
    if after_epochs + 4 > bytes.len() {
        return Err(RecordError::LengthMismatch {
            expected: after_epochs + 4,
            actual: bytes.len(),
        });
    }
    let mut epochs = BTreeSet::new();
    let mut prev: Option<u64> = None;
    for _ in 0..e {
        let epoch = r.u64();
        if prev.is_some_and(|p| p >= epoch) {
            return Err(RecordError::NotCanonical { what: "epochs" });
        }
        prev = Some(epoch);
        epochs.insert(epoch);
    }
    let a = r.u32();
    let end = span(r.at, a, 20, bytes.len())?;
    r.expect_len(end)?;
    let mut archives = BTreeSet::new();
    let mut prev: Option<Address> = None;
    for _ in 0..a {
        let archive = Address::new(r.take());
        if prev.is_some_and(|p| p >= archive) {
            return Err(RecordError::NotCanonical { what: "archives" });
        }
        prev = Some(archive);
        archives.insert(archive);
    }
    Ok(TrackerIndexRecord {
        job_id,
        file_root,
        r_job,
        interval_version,
        chunk_count,
        epochs,
        archives,
    })
}

// ── Member, job-entries and cursor rows ────────────────────────────────────

fn encode_marker(magic: [u8; 4], echo: &[&[u8]]) -> Vec<u8> {
    let mut out = header(magic);
    for part in echo {
        out.extend_from_slice(part);
    }
    out
}

fn decode_marker(bytes: &[u8], magic: [u8; 4], echo: &[&[u8]]) -> Result<(), RecordError> {
    let len = 6 + echo.iter().map(|p| p.len()).sum::<usize>();
    let r = Reader::open(bytes, magic, len)?;
    r.expect_len(len)?;
    let mut at = 6;
    for part in echo {
        if &bytes[at..at + part.len()] != *part {
            return Err(RecordError::KeyMismatch);
        }
        at += part.len();
    }
    Ok(())
}

fn encode_file_member(file_root: &[u8; 32], entry: &FileIndexEntry) -> Vec<u8> {
    let mut out = encode_marker(
        FILE_MAGIC,
        &[
            file_root,
            entry.tracker_key.as_bytes(),
            &entry.epoch.to_be_bytes(),
        ],
    );
    out.extend_from_slice(&entry.r_job.to_be_bytes());
    out.extend_from_slice(&entry.interval_version.to_be_bytes());
    out
}

fn decode_file_member(
    bytes: &[u8],
    file_root: &[u8; 32],
    tracker: &TrackerKey,
    epoch: u64,
) -> Result<FileIndexEntry, RecordError> {
    let len = 6 + 32 + 32 + 8 + 4 + 4;
    let mut r = Reader::open(bytes, FILE_MAGIC, len)?;
    r.expect_len(len)?;
    if &r.take::<32>() != file_root || &r.take::<32>() != tracker.as_bytes() || r.u64() != epoch {
        return Err(RecordError::KeyMismatch);
    }
    Ok(FileIndexEntry {
        tracker_key: *tracker,
        r_job: r.u32(),
        interval_version: r.u32(),
        epoch,
    })
}

fn encode_job_entries(job: &JobId, entries: u64) -> Vec<u8> {
    encode_marker(JOB_ENTRIES_MAGIC, &[job.as_bytes(), &entries.to_be_bytes()])
}

fn decode_job_entries(bytes: &[u8], job: &JobId) -> Result<u64, RecordError> {
    let len = 6 + 32 + 8;
    let mut r = Reader::open(bytes, JOB_ENTRIES_MAGIC, len)?;
    r.expect_len(len)?;
    if &r.take::<32>() != job.as_bytes() {
        return Err(RecordError::KeyMismatch);
    }
    match r.u64() {
        0 => Err(RecordError::Zero {
            what: "job entry count",
        }),
        n => Ok(n),
    }
}

fn encode_cursor(cursor: &RecomputeCursor) -> Vec<u8> {
    let mut out = header(CURSOR_MAGIC);
    match cursor.last() {
        None => {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
        }
        Some(key) => {
            out.push(1);
            out.extend_from_slice(key.as_bytes());
        }
    }
    out
}

fn decode_cursor(bytes: &[u8]) -> Result<RecomputeCursor, RecordError> {
    let len = 6 + 1 + 32;
    let mut r = Reader::open(bytes, CURSOR_MAGIC, len)?;
    r.expect_len(len)?;
    let flag = r.take::<1>()[0];
    let key: [u8; 32] = r.take();
    match flag {
        0 if key == [0u8; 32] => Ok(RecomputeCursor::start()),
        1 => Ok(RecomputeCursor::after(TrackerKey::from_bytes(key))),
        flag => Err(RecordError::BadOption { flag }),
    }
}

// ── Reads ──────────────────────────────────────────────────────────────────

fn present_or<T>(
    kind: RowKind,
    presence: Presence,
    bytes: Option<Vec<u8>>,
    decode: impl FnOnce(&[u8]) -> Result<T, RecordError>,
) -> Result<Option<T>, TrackerStoreError> {
    match (presence, bytes) {
        (Presence::Absent, None) => Ok(None),
        (Presence::Absent, Some(_)) => Err(TrackerStoreError::Unexpected { kind }),
        (Presence::Required, None) => Err(TrackerStoreError::Missing { kind }),
        (Presence::Required, Some(b)) => decode(&b).map(Some).map_err(refused(kind)),
    }
}

/// A tracker's stored state, refusing anything `presence` does not allow.
pub fn tracker_state(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    key: &TrackerKey,
    presence: Presence,
) -> Result<Option<TrackerState>, TrackerStoreError> {
    let (family, row) = ns.key(RowKind::TrackerState, &[key.as_bytes()]);
    present_or(
        RowKind::TrackerState,
        presence,
        rows.get_row(family, &row)?,
        |b| TrackerState::decode_for(b, key),
    )
}

/// A tracker's stored index record, refusing anything `presence` does not
/// allow.
pub fn index_record(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    key: &TrackerKey,
    presence: Presence,
) -> Result<Option<TrackerIndexRecord>, TrackerStoreError> {
    let (family, row) = ns.key(RowKind::IndexRecord, &[key.as_bytes()]);
    present_or(
        RowKind::IndexRecord,
        presence,
        rows.get_row(family, &row)?,
        |b| decode_index_record(b, key),
    )
}

/// Scan one bucket: every row under `prefix ‖ bucket`, each with a key of
/// exactly `suffix_len` more bytes. A key of another length is refused.
fn bucket(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    kind: RowKind,
    bucket: &[u8],
    suffix_len: usize,
) -> Result<Rows, TrackerStoreError> {
    let (family, prefix) = ns.key(kind, &[bucket]);
    let found = rows.scan_prefix(family, &prefix)?;
    for (key, _) in &found {
        if key.len() != prefix.len() + suffix_len {
            return Err(TrackerStoreError::MalformedKey {
                kind,
                len: key.len(),
            });
        }
    }
    Ok(found
        .into_iter()
        .map(|(key, value)| (key[prefix.len()..].to_vec(), value))
        .collect())
}

/// Trackers indexed under `archive`, in key order.
pub fn trackers_for_archive(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    archive: &Address,
) -> Result<Vec<TrackerKey>, TrackerStoreError> {
    let mut out = Vec::new();
    for (suffix, value) in bucket(rows, ns, RowKind::ArchiveMember, archive.as_bytes(), 32)? {
        decode_marker(&value, ARCHIVE_MAGIC, &[archive.as_bytes(), &suffix])
            .map_err(refused(RowKind::ArchiveMember))?;
        out.push(TrackerKey::from_bytes(suffix.try_into().expect("32 bytes")));
    }
    Ok(out)
}

/// File-index entries under `file_root`, in the kernel's order.
pub fn file_entries(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    file_root: &Hash,
) -> Result<Vec<FileIndexEntry>, TrackerStoreError> {
    let mut out = Vec::new();
    for (suffix, value) in bucket(rows, ns, RowKind::FileMember, file_root.as_bytes(), 40)? {
        let tracker = TrackerKey::from_bytes(suffix[..32].try_into().expect("32 bytes"));
        let epoch = u64::from_be_bytes(suffix[32..].try_into().expect("8 bytes"));
        out.push(
            decode_file_member(&value, file_root.as_bytes(), &tracker, epoch)
                .map_err(refused(RowKind::FileMember))?,
        );
    }
    Ok(out)
}

/// Trackers indexed under `job_id`, in key order.
pub fn trackers_for_job(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    job_id: &JobId,
) -> Result<Vec<TrackerKey>, TrackerStoreError> {
    let mut out = Vec::new();
    for (suffix, value) in bucket(rows, ns, RowKind::JobMember, job_id.as_bytes(), 32)? {
        decode_marker(&value, JOB_MAGIC, &[job_id.as_bytes(), &suffix])
            .map_err(refused(RowKind::JobMember))?;
        out.push(TrackerKey::from_bytes(suffix.try_into().expect("32 bytes")));
    }
    Ok(out)
}

/// The reverse-index entries `job_id` occupies, as the cap counts them. 0 when
/// the job has no trackers (no row is stored then).
pub fn job_entry_count(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    job_id: &JobId,
) -> Result<u64, TrackerStoreError> {
    let (family, row) = ns.key(RowKind::JobEntries, &[job_id.as_bytes()]);
    match rows.get_row(family, &row)? {
        None => Ok(0),
        Some(bytes) => decode_job_entries(&bytes, job_id).map_err(refused(RowKind::JobEntries)),
    }
}

/// The trackers one block's changes reach, each once, in key order.
pub fn affected_trackers(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    changed_archives: &[Address],
    changed_files: &[Hash],
) -> Result<BTreeSet<TrackerKey>, TrackerStoreError> {
    let mut out = BTreeSet::new();
    for archive in changed_archives {
        out.extend(trackers_for_archive(rows, ns, archive)?);
    }
    for file_root in changed_files {
        out.extend(
            file_entries(rows, ns, file_root)?
                .into_iter()
                .map(|e| e.tracker_key),
        );
    }
    Ok(out)
}

/// The stored recompute cursor, or `None` if none was ever stored. Which of
/// those a caller treats as "start" is the caller's.
pub fn recompute_cursor(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
) -> Result<Option<RecomputeCursor>, TrackerStoreError> {
    let (family, row) = ns.key(RowKind::Cursor, &[]);
    match rows.get_row(family, &row)? {
        None => Ok(None),
        Some(bytes) => decode_cursor(&bytes)
            .map(Some)
            .map_err(refused(RowKind::Cursor)),
    }
}

// ── Writes (execution view only) ───────────────────────────────────────────

fn file_member_entries(key: &TrackerKey, record: &TrackerIndexRecord) -> Vec<FileIndexEntry> {
    record
        .epochs
        .iter()
        .map(|&epoch| FileIndexEntry {
            tracker_key: *key,
            r_job: record.r_job,
            interval_version: record.interval_version,
            epoch,
        })
        .collect()
}

fn stage_members(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    key: &TrackerKey,
    record: &TrackerIndexRecord,
) -> Result<(), TrackerStoreError> {
    let (family, row) = ns.key(
        RowKind::JobMember,
        &[record.job_id.as_bytes(), key.as_bytes()],
    );
    view.put(
        family,
        &row,
        &encode_marker(JOB_MAGIC, &[record.job_id.as_bytes(), key.as_bytes()]),
    )?;
    for entry in file_member_entries(key, record) {
        let (family, row) = ns.key(
            RowKind::FileMember,
            &[
                record.file_root.as_bytes(),
                key.as_bytes(),
                &entry.epoch.to_be_bytes(),
            ],
        );
        view.put(
            family,
            &row,
            &encode_file_member(record.file_root.as_bytes(), &entry),
        )?;
    }
    for archive in &record.archives {
        let (family, row) = ns.key(
            RowKind::ArchiveMember,
            &[archive.as_bytes(), key.as_bytes()],
        );
        view.put(
            family,
            &row,
            &encode_marker(ARCHIVE_MAGIC, &[archive.as_bytes(), key.as_bytes()]),
        )?;
    }
    Ok(())
}

fn unstage_members(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    key: &TrackerKey,
    record: &TrackerIndexRecord,
    keep: Option<&TrackerIndexRecord>,
) -> Result<(), TrackerStoreError> {
    if keep.is_none() {
        let (family, row) = ns.key(
            RowKind::JobMember,
            &[record.job_id.as_bytes(), key.as_bytes()],
        );
        view.delete(family, &row)?;
    }
    for &epoch in &record.epochs {
        if keep.is_some_and(|k| k.epochs.contains(&epoch)) {
            continue;
        }
        let (family, row) = ns.key(
            RowKind::FileMember,
            &[
                record.file_root.as_bytes(),
                key.as_bytes(),
                &epoch.to_be_bytes(),
            ],
        );
        view.delete(family, &row)?;
    }
    for archive in &record.archives {
        if keep.is_some_and(|k| k.archives.contains(archive)) {
            continue;
        }
        let (family, row) = ns.key(
            RowKind::ArchiveMember,
            &[archive.as_bytes(), key.as_bytes()],
        );
        view.delete(family, &row)?;
    }
    Ok(())
}

fn stage_job_entries(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    job: &JobId,
    entries: u64,
) -> Result<(), TrackerStoreError> {
    let (family, row) = ns.key(RowKind::JobEntries, &[job.as_bytes()]);
    if entries == 0 {
        view.delete(family, &row)?;
    } else {
        view.put(family, &row, &encode_job_entries(job, entries))?;
    }
    Ok(())
}

/// The job's entry total once `record` takes the place of `replaced` of its
/// entries, refused over the cap: the kernel's arithmetic, over the stored
/// count.
fn job_total_with(
    current: u64,
    record: &TrackerIndexRecord,
    replaced: u64,
    cap: u64,
) -> Result<u64, TrackerStoreError> {
    let entries = record
        .entry_count()
        .and_then(|added| current.checked_sub(replaced)?.checked_add(added))
        .ok_or(PoolError::Overflow("reverse-index entries"))?;
    if entries > cap {
        return Err(PoolError::ReverseIndexCapExceeded { entries, cap }.into());
    }
    Ok(entries)
}

fn check_state_matches(
    state: &TrackerState,
    record: &TrackerIndexRecord,
) -> Result<(), TrackerStoreError> {
    if state.r_job != record.r_job {
        return Err(TrackerStoreError::Mismatch { what: "r_job" });
    }
    if state.chunk_count != record.chunk_count {
        return Err(TrackerStoreError::Mismatch {
            what: "chunk_count",
        });
    }
    Ok(())
}

/// Start tracking `key` (#129 scope (6), "insertion at tracking start"): its
/// state, its index record, every reverse-index row and the job's entry count,
/// in the block's write set.
///
/// Refused, staging nothing, as the in-memory kernel refuses: a key already
/// tracked ([`PoolError::RetentionTrackerAlreadyIndexed`]), no epoch, a bound
/// in `limits` broken, the job over `limits.max_entries_per_job`. Also refused:
/// a state row already stored for the key, a state whose `r_job` or
/// `chunk_count` differs from the record's, and any undecodable row it would
/// replace.
pub fn start_tracking(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    state: &TrackerState,
    record: &TrackerIndexRecord,
    limits: &ReverseIndexLimits,
) -> Result<(), TrackerStoreError> {
    let key = state.key;
    // A stored row is decoded before it is reported, so an undecodable one is
    // refused as such and never mistaken for a tracked key.
    let (family, row) = ns.key(RowKind::IndexRecord, &[key.as_bytes()]);
    if let Some(bytes) = view.get(family, &row)? {
        decode_index_record(&bytes, &key).map_err(refused(RowKind::IndexRecord))?;
        return Err(PoolError::RetentionTrackerAlreadyIndexed.into());
    }
    let (family, row) = ns.key(RowKind::TrackerState, &[key.as_bytes()]);
    if let Some(bytes) = view.get(family, &row)? {
        TrackerState::decode_for(&bytes, &key).map_err(refused(RowKind::TrackerState))?;
        return Err(TrackerStoreError::Unexpected {
            kind: RowKind::TrackerState,
        });
    }
    if record.epochs.is_empty() {
        return Err(PoolError::RetentionTrackerWithoutEpoch.into());
    }
    limits.check_tracker(record)?;
    check_state_matches(state, record)?;
    let current = job_entry_count(&*view, ns, &record.job_id)?;
    let total = job_total_with(current, record, 0, limits.max_entries_per_job)?;
    let index_bytes = encode_index_record(&key, record).map_err(refused(RowKind::IndexRecord))?;

    let (family, row) = ns.key(RowKind::IndexRecord, &[key.as_bytes()]);
    view.put(family, &row, &index_bytes)?;
    let (family, row) = ns.key(RowKind::TrackerState, &[key.as_bytes()]);
    view.put(family, &row, &state.encode())?;
    stage_members(view, ns, &key, record)?;
    stage_job_entries(view, ns, &record.job_id, total)
}

/// Replace a tracker's epochs and archives (an epoch or reassignment update);
/// its job, file, `R_job`, chunk count and interval version are kept, as the
/// kernel keeps them. Rows the new shape no longer needs are deleted and new
/// ones written, in the block's write set.
///
/// Refused, staging nothing: an unknown key
/// ([`PoolError::UnknownRetentionTracker`]), no epoch, a bound broken, the job
/// over its cap, an undecodable stored row.
pub fn replace_dependencies(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    key: &TrackerKey,
    epochs: BTreeSet<u64>,
    archives: BTreeSet<Address>,
    limits: &ReverseIndexLimits,
) -> Result<(), TrackerStoreError> {
    let old = required_index(&*view, ns, key)?;
    let new = TrackerIndexRecord {
        epochs,
        archives,
        ..old.clone()
    };
    if new.epochs.is_empty() {
        return Err(PoolError::RetentionTrackerWithoutEpoch.into());
    }
    limits.check_tracker(&new)?;
    let old_count = old
        .entry_count()
        .ok_or(PoolError::Overflow("reverse-index entries"))?;
    let current = job_entry_count(&*view, ns, &old.job_id)?;
    let total = job_total_with(current, &new, old_count, limits.max_entries_per_job)?;
    let index_bytes = encode_index_record(key, &new).map_err(refused(RowKind::IndexRecord))?;

    unstage_members(view, ns, key, &old, Some(&new))?;
    stage_members(view, ns, key, &new)?;
    let (family, row) = ns.key(RowKind::IndexRecord, &[key.as_bytes()]);
    view.put(family, &row, &index_bytes)?;
    stage_job_entries(view, ns, &new.job_id, total)
}

fn required_index(
    rows: &(impl RowSource + ?Sized),
    ns: &Namespaces,
    key: &TrackerKey,
) -> Result<TrackerIndexRecord, TrackerStoreError> {
    match index_record(rows, ns, key, Presence::Required) {
        Ok(Some(record)) => Ok(record),
        Ok(None) => unreachable!("a Required read returns a row or an error"),
        Err(TrackerStoreError::Missing { .. }) => Err(PoolError::UnknownRetentionTracker.into()),
        Err(other) => Err(other),
    }
}

/// Stop tracking `key` (at settlement, incomplete, cancel or
/// reprovision-supersede): delete its state, index record and every
/// reverse-index row, and reduce its job's entry count, deleting that row when
/// it reaches 0. Returns what the tracker had indexed.
///
/// Refused, staging nothing: an unknown key, a missing or undecodable state
/// row, an undecodable job-entry row.
pub fn stop_tracking(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    key: &TrackerKey,
) -> Result<TrackerIndexRecord, TrackerStoreError> {
    let record = required_index(&*view, ns, key)?;
    tracker_state(&*view, ns, key, Presence::Required)?;
    let count = record
        .entry_count()
        .ok_or(PoolError::Overflow("reverse-index entries"))?;
    let current = job_entry_count(&*view, ns, &record.job_id)?;
    let remaining = current
        .checked_sub(count)
        .ok_or(TrackerStoreError::Mismatch {
            what: "job entry count",
        })?;

    unstage_members(view, ns, key, &record, None)?;
    let (family, row) = ns.key(RowKind::IndexRecord, &[key.as_bytes()]);
    view.delete(family, &row)?;
    let (family, row) = ns.key(RowKind::TrackerState, &[key.as_bytes()]);
    view.delete(family, &row)?;
    stage_job_entries(view, ns, &record.job_id, remaining)?;
    Ok(record)
}

/// Replace a tracked key's state (a recompute's result), returning the state
/// it replaces. Refused, staging nothing: an untracked key, a state whose
/// `r_job` or `chunk_count` differs from the stored record's, an undecodable
/// stored row.
pub fn update_state(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    state: &TrackerState,
) -> Result<TrackerState, TrackerStoreError> {
    let record = required_index(&*view, ns, &state.key)?;
    let replaced = tracker_state(&*view, ns, &state.key, Presence::Required)?
        .expect("a Required read returns a row or an error");
    check_state_matches(state, &record)?;
    let (family, row) = ns.key(RowKind::TrackerState, &[state.key.as_bytes()]);
    view.put(family, &row, &state.encode())?;
    Ok(replaced)
}

/// Store the recompute cursor. Refused, staging nothing, if the stored one
/// cannot be decoded.
pub fn store_cursor(
    view: &mut ExecutionView<'_, '_>,
    ns: &Namespaces,
    cursor: &RecomputeCursor,
) -> Result<(), TrackerStoreError> {
    recompute_cursor(&*view, ns)?;
    let (family, row) = ns.key(RowKind::Cursor, &[]);
    view.put(family, &row, &encode_cursor(cursor))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tk(b: u8) -> TrackerKey {
        TrackerKey::from_bytes([b; 32])
    }

    fn addr(b: u8) -> Address {
        Address::new([b; 20])
    }

    fn state() -> TrackerState {
        TrackerState::new(
            tk(7),
            3,
            4,
            vec![(addr(2), 9), (addr(1), 5)],
            Some(100),
            None,
        )
        .unwrap()
    }

    fn index() -> TrackerIndexRecord {
        TrackerIndexRecord {
            job_id: JobId::from_bytes([0x10; 32]),
            file_root: Hash::new([0x20; 32]),
            r_job: 3,
            interval_version: 1,
            chunk_count: 4,
            epochs: [5u64, 6].into_iter().collect(),
            archives: [addr(1), addr(2)].into_iter().collect(),
        }
    }

    #[test]
    fn the_tracker_state_layout_is_fixed_and_round_trips() {
        let s = state();
        let bytes = s.encode();
        let mut want = b"SRTS".to_vec();
        want.extend_from_slice(&[0, 1]);
        want.extend_from_slice(&[7; 32]);
        want.extend_from_slice(&3u32.to_be_bytes());
        want.extend_from_slice(&4u32.to_be_bytes());
        want.push(1);
        want.extend_from_slice(&100u64.to_be_bytes());
        want.push(0);
        want.extend_from_slice(&0u64.to_be_bytes());
        want.extend_from_slice(&2u32.to_be_bytes());
        want.extend_from_slice(&[1; 20]);
        want.extend_from_slice(&5u64.to_be_bytes());
        want.extend_from_slice(&[2; 20]);
        want.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(bytes, want);
        assert_eq!(TrackerState::decode_for(&bytes, &tk(7)).unwrap(), s);
    }

    #[test]
    fn the_index_record_round_trips_and_refuses_a_foreign_key() {
        let bytes = encode_index_record(&tk(7), &index()).unwrap();
        assert_eq!(decode_index_record(&bytes, &tk(7)).unwrap(), index());
        assert_eq!(
            decode_index_record(&bytes, &tk(8)),
            Err(RecordError::KeyMismatch)
        );
    }

    #[test]
    fn every_truncation_and_extension_of_each_value_is_refused() {
        let values: Vec<(&str, Vec<u8>)> = vec![
            ("state", state().encode()),
            ("index", encode_index_record(&tk(7), &index()).unwrap()),
        ];
        for (what, bytes) in values {
            for cut in 0..bytes.len() {
                let ok = match what {
                    "state" => TrackerState::decode_for(&bytes[..cut], &tk(7)).is_ok(),
                    _ => decode_index_record(&bytes[..cut], &tk(7)).is_ok(),
                };
                assert!(!ok, "{what} cut at {cut} accepted");
            }
            for extra in [1usize, 7, 8, 20, 28] {
                let mut long = bytes.clone();
                long.resize(long.len() + extra, 0);
                let ok = match what {
                    "state" => TrackerState::decode_for(&long, &tk(7)).is_ok(),
                    _ => decode_index_record(&long, &tk(7)).is_ok(),
                };
                assert!(!ok, "{what} extended by {extra} accepted");
            }
        }
    }

    #[test]
    fn unknown_versions_and_foreign_magic_are_refused() {
        let bytes = state().encode();
        for v in [0u16, 2, u16::MAX] {
            let mut b = bytes.clone();
            b[4..6].copy_from_slice(&v.to_be_bytes());
            assert_eq!(
                TrackerState::decode_for(&b, &tk(7)),
                Err(RecordError::UnsupportedVersion { found: v })
            );
        }
        let mut b = bytes.clone();
        b[0] ^= 0xFF;
        assert_eq!(
            TrackerState::decode_for(&b, &tk(7)),
            Err(RecordError::BadMagic)
        );
    }

    #[test]
    fn a_count_that_disagrees_with_the_body_is_refused_without_allocating() {
        let bytes = state().encode();
        let at = TRACKER_FIXED - 4;
        for n in [0u32, 1, 3, u32::MAX] {
            let mut b = bytes.clone();
            b[at..at + 4].copy_from_slice(&n.to_be_bytes());
            assert!(
                matches!(
                    TrackerState::decode_for(&b, &tk(7)),
                    Err(RecordError::LengthMismatch { .. })
                ),
                "count {n}"
            );
        }
    }

    #[test]
    fn non_canonical_and_impossible_values_are_refused() {
        // Duplicate archives are refused at construction.
        assert!(
            TrackerState::new(tk(1), 1, 1, vec![(addr(1), 1), (addr(1), 2)], None, None).is_err()
        );
        // Descending archives in stored bytes.
        let mut b = state().encode();
        let first = TRACKER_FIXED;
        let second = first + GENERATION_LEN;
        let (x, y) = (
            b[first..first + 20].to_vec(),
            b[second..second + 20].to_vec(),
        );
        b[first..first + 20].copy_from_slice(&y);
        b[second..second + 20].copy_from_slice(&x);
        assert!(matches!(
            TrackerState::decode_for(&b, &tk(7)),
            Err(RecordError::NotCanonical { .. })
        ));
        // A value under a zero option flag, and a flag of 2.
        let mut b = state().encode();
        let last_flag = 6 + 32 + 4 + 4 + 9;
        b[last_flag + 8] = 1;
        assert_eq!(
            TrackerState::decode_for(&b, &tk(7)),
            Err(RecordError::BadOption { flag: 0 })
        );
        b[last_flag] = 2;
        assert_eq!(
            TrackerState::decode_for(&b, &tk(7)),
            Err(RecordError::BadOption { flag: 2 })
        );
        // An index record with no epoch is never written or read.
        let mut no_epoch = index();
        no_epoch.epochs.clear();
        assert!(encode_index_record(&tk(7), &no_epoch).is_err());
        // Job entries of 0 and a cursor flag of 2.
        assert!(decode_job_entries(
            &encode_job_entries(&JobId::from_bytes([1; 32]), 0),
            &JobId::from_bytes([1; 32])
        )
        .is_err());
        let mut c = encode_cursor(&RecomputeCursor::after(tk(3)));
        c[6] = 2;
        assert!(decode_cursor(&c).is_err());
        let mut c = encode_cursor(&RecomputeCursor::start());
        c[7] = 1;
        assert!(decode_cursor(&c).is_err());
    }

    #[test]
    fn an_empty_dependency_list_is_a_state_distinct_from_none() {
        let empty = TrackerState::new(tk(4), 0, 0, vec![], None, None).unwrap();
        let back = TrackerState::decode_for(&empty.encode(), &tk(4)).unwrap();
        assert_eq!(back, empty);
        assert!(back.dependency_generations().is_empty());
    }
}
