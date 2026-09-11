//! Application overlay: buffered writes with overlay-first reads.
//!
//! Execution needs to run a *candidate* branch and find out whether it is valid
//! before any of it reaches canonical state. Today it cannot: `execute_block`
//! writes straight through to RocksDB per transaction, so by the time a state
//! root is computed the writes are already committed and a rejected branch has
//! already mutated the node. That is what makes a reorg destructive — the node
//! must damage the chain it is on to evaluate the chain it might switch to.
//!
//! [`ApplicationOverlay`] buffers writes in memory and serves reads from the
//! buffer first, falling through to the database. Execution against an overlay
//! is therefore side-effect-free until [`ApplicationOverlay::into_batch`] turns
//! it into a single ordinary [`WriteBatch`] — which callers must do only after
//! execution AND root verification have both succeeded.
//!
//! # Why not `WriteBatchWithIndex`
//!
//! RocksDB has a batch type with exactly these semantics. It is not reachable:
//! the `rocksdb` 0.22.0 Rust crate exports only
//! `WriteBatchWithTransaction<const TRANSACTION: bool>` (with
//! `WriteBatch = WriteBatchWithTransaction<false>`), and `WriteBatchWithIndex`
//! appears **nowhere** in its `src/` — it exists only in the vendored C++
//! headers under `librocksdb-sys`. Reaching it would mean hand-writing unsafe
//! bindings to a private FFI surface, which is not a trade worth making for an
//! ordered map. This module implements the semantics in safe Rust instead.
//!
//! # Iteration
//!
//! Merged iteration is the part that cannot be skipped. An overlay honoured by
//! point reads but not by iteration is worse than no overlay: a `get` and a scan
//! would disagree within a single block, so code that lists a set and then reads
//! its members would observe a state no instant ever held.
//!
//! Iteration BORROWS the buffered map. It does not copy it: materialising the
//! overlay into a temporary would double its footprint behind the accounting's
//! back, and would do so infallibly — the one allocation the ceiling could not
//! refuse.
//!
//! Errors are propagated, never dropped. The database's own iterators end in
//! `.filter_map(|r| r.ok())`, which silently truncates a scan at the first read
//! error and is indistinguishable from a short collection; this module iterates
//! over `Result` and surfaces the failure.
//!
//! # Accounting
//!
//! [`ApplicationOverlay::logical_bytes`] is **deterministic logical write-set
//! accounting**: the key and value bytes of buffered writes plus captured
//! pre-images, and nothing else. It deliberately excludes allocator overhead,
//! `BTreeMap` node overhead, and per-allocation padding, so it is a pure
//! function of what was written and two nodes executing one block compute the
//! same number. It is therefore **not** a residency or RSS bound, and must not
//! be described as one — real memory use is strictly higher by an amount this
//! module does not attempt to model.
//!
//! ## What the limit does and does not bound
//!
//! The limit is enforced before this module owns any copy: the new value is
//! measured through a borrowed slice, and the pre-image through a pinned
//! RocksDB slice, so an oversized write is refused before either is
//! materialised into an application buffer. Every owned buffer is then built
//! with `try_reserve_exact`, so an allocation failure is reported rather than
//! aborting the process.
//!
//! That is the whole of the guarantee, and it is worth being exact about where
//! it stops:
//!
//! * RocksDB may materialise or decompress a block internally before handing
//!   back the pinned slice. That memory is inside RocksDB, is not counted here,
//!   and is not prevented by refusing the write afterwards.
//! * `BTreeMap` and `HashMap` node allocation is not fallible through their
//!   safe APIs — inserting can abort on allocation failure and there is no
//!   `try_insert`. This overhead IS influenced by block contents, through the
//!   number of distinct keys a block writes, so it is not independent of the
//!   input. It is uncounted, but it is indirectly bounded: every distinct key
//!   charges at least its own length plus its pre-image against the logical
//!   limit, so the limit caps how many entries can exist, and the column-family
//!   set is fixed at open time and cannot grow with block contents. Node
//!   overhead is therefore a bounded multiple of an already-bounded entry
//!   count — not an independent quantity, and not an unbounded one.
//! * The accounting excludes allocator overhead and padding by design, so real
//!   process memory is strictly higher than `logical_bytes`.
//!
//! So: this prevents unbounded *application-owned* copies driven by block
//! contents. It is not an allocator-level or process-level memory guarantee,
//! and must not be presented as one.
//!
//! Every mutation is transactional. The complete new total is computed and
//! validated before any of `logical_bytes`, `preimages` or `writes` is touched,
//! so a refused operation leaves the overlay byte-identical. Anything less makes
//! the ceiling itself a source of corruption: a write rejected halfway would
//! leave the accounting short, or a pre-image captured for a write that never
//! happened.

use std::collections::{btree_map, BTreeMap, HashMap};
use std::sync::OnceLock;

use crate::db::{Database, WriteBatch};
use crate::{Result, StorageError};

/// A buffered mutation. `Delete` is distinct from absence: a key deleted in the
/// overlay must read as missing even though the database still holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Put(Vec<u8>),
    Delete,
}

impl Op {
    fn value_len(&self) -> usize {
        match self {
            Op::Put(v) => v.len(),
            Op::Delete => 0,
        }
    }
}

/// Shared empty map, so iterating a column family with no buffered writes needs
/// neither an allocation nor a special case in the merge loop.
fn empty_writes() -> &'static BTreeMap<Vec<u8>, Op> {
    static EMPTY: OnceLock<BTreeMap<Vec<u8>, Op>> = OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

fn to_u64(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| {
        StorageError::InvalidData("overlay accounting: length exceeds u64".to_string())
    })
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| {
        StorageError::InvalidData("overlay accounting: addition overflowed u64".to_string())
    })
}

/// Subtraction that treats underflow as the invariant violation it is.
///
/// Reaching this means the accounted total disagrees with the buffered writes,
/// which is a bug in this module — not a condition to paper over with a
/// saturating subtract that would silently desynchronise the counter from
/// reality and leave the ceiling meaningless.
fn sub(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b).ok_or_else(|| {
        StorageError::InvalidData(
            "overlay accounting invariant violated: charged total is smaller than the \
             entry being replaced"
                .to_string(),
        )
    })
}

/// A mutation described by BORROWED data, for the validation phase.
///
/// The owned [`Op`] is built only after the limit has approved it. Constructing
/// `Op::Put(value.to_vec())` at the call site and validating afterwards would
/// mean the allocation the limit exists to refuse had already happened.
#[derive(Debug, Clone, Copy)]
enum OpRef<'v> {
    Put(&'v [u8]),
    Delete,
}

impl OpRef<'_> {
    fn value_len(&self) -> usize {
        match self {
            OpRef::Put(v) => v.len(),
            OpRef::Delete => 0,
        }
    }
}

/// Copy `src` into a fresh `Vec` using a fallible reservation.
///
/// `to_vec()` aborts the process on allocation failure. Every buffer this
/// module owns is sized from data whose length it has already approved, so a
/// failure here should be reported to the caller, not taken as fatal.
fn try_copy(src: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(src.len()).map_err(|e| {
        StorageError::InvalidData(format!(
            "overlay could not allocate {} bytes: {e}",
            src.len()
        ))
    })?;
    out.extend_from_slice(src);
    Ok(out)
}

/// Buffered writes over a [`Database`], with overlay-first reads.
pub struct ApplicationOverlay<'a> {
    db: &'a Database,
    /// Per-CF buffered writes, ordered so iteration can merge against RocksDB's
    /// own ordering without an extra sort.
    writes: HashMap<String, BTreeMap<Vec<u8>, Op>>,
    /// Pre-image captured the FIRST time a key is written, per CF.
    ///
    /// `None` records "this key did not exist", which is the distinction an
    /// undo journal needs and which a plain read cannot express for account
    /// rows. Captured once: a second write to the same key must not overwrite
    /// the original pre-image with an intermediate value.
    preimages: HashMap<String, BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    /// See the module's Accounting section. Logical write-set bytes only.
    logical_bytes: u64,
    limit: u64,
}

impl<'a> ApplicationOverlay<'a> {
    /// Create an overlay bounded by `limit` logical write-set bytes.
    ///
    /// `limit` has no default on purpose. A ceiling that can refuse a write
    /// participates in deciding whether a block is applicable, so it belongs to
    /// the versioned consensus parameters and must be derived from measured
    /// write sets — not invented here. Production construction must pass the
    /// consensus value; tests pass an explicit fixture.
    pub fn new(db: &'a Database, limit: u64) -> Self {
        Self {
            db,
            writes: HashMap::new(),
            preimages: HashMap::new(),
            logical_bytes: 0,
            limit,
        }
    }

    /// Deterministic logical write-set bytes. NOT a residency or RSS bound —
    /// see the module's Accounting section.
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Number of buffered writes across all column families.
    pub fn len(&self) -> usize {
        self.writes.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn has_preimage(&self, cf: &str, key: &[u8]) -> bool {
        self.preimages.get(cf).is_some_and(|m| m.contains_key(key))
    }

    /// Stage one buffered mutation transactionally.
    ///
    /// Everything fallible happens before anything observable changes: the
    /// database read for the pre-image, every length conversion, the whole
    /// accounting computation and the limit check. Only once a valid new total
    /// exists are `logical_bytes`, `preimages` and `writes` updated together.
    fn stage(&mut self, cf: &str, key: &[u8], op: OpRef<'_>) -> Result<()> {
        let needs_preimage = !self.has_preimage(cf, key);

        let key_len = to_u64(key.len())?;
        let new_value_len = to_u64(op.value_len())?;

        // Phase 1 — measure and approve, owning nothing.
        //
        // The pre-image is read PINNED: `get_pinned` hands back a slice
        // borrowed from RocksDB's block cache, so its length is known before
        // any copy of it exists. Reading it with `get` would allocate the whole
        // value first and only then ask whether it was affordable.
        let pinned = if needs_preimage {
            Some(self.db.get_pinned(cf, key)?)
        } else {
            None
        };

        let mut next = self.logical_bytes;
        if let Some(pin) = &pinned {
            let prior_len = to_u64(pin.as_ref().map_or(0, |p| p.len()))?;
            next = add(next, add(key_len, prior_len)?)?;
        }
        match self.writes.get(cf).and_then(|m| m.get(key)) {
            Some(existing) => {
                // Replacing a buffered entry: the key is already charged.
                next = sub(next, to_u64(existing.value_len())?)?;
                next = add(next, new_value_len)?;
            }
            None => next = add(next, add(key_len, new_value_len)?)?,
        }

        if next > self.limit {
            return Err(StorageError::InvalidData(format!(
                "overlay exceeded its {} logical byte limit (would reach {next}); \
                 the candidate branch is too large to evaluate in memory",
                self.limit
            )));
        }

        // Phase 2 — build every owned buffer fallibly, still mutating nothing.
        //
        // All of these can fail; none of them may leave the overlay changed. The
        // pinned slice is copied here and dropped immediately after, so the
        // cache block is not held beyond the copy.
        let owned_preimage: Option<Option<Vec<u8>>> = match &pinned {
            Some(Some(p)) => Some(Some(try_copy(p)?)),
            Some(None) => Some(None),
            None => None,
        };
        drop(pinned);

        // Two independently-owned keys, both built fallibly HERE. The commit
        // section below must not allocate: cloning one key into the second map
        // would be an infallible, block-sized allocation made after mutation has
        // already begun, and `or_default()` on the pre-image map would itself
        // have mutated the map before that clone was even evaluated.
        let owned_preimage_key = if needs_preimage {
            Some(try_copy(key)?)
        } else {
            None
        };
        let owned_write_key = try_copy(key)?;
        let owned_op = match op {
            OpRef::Put(v) => Op::Put(try_copy(v)?),
            OpRef::Delete => Op::Delete,
        };
        let owned_cf_for_pre = if owned_preimage.is_some() {
            Some(try_copy(cf.as_bytes()).and_then(|b| {
                String::from_utf8(b).map_err(|e| {
                    StorageError::InvalidData(format!("column family name is not utf-8: {e}"))
                })
            })?)
        } else {
            None
        };
        let owned_cf_for_write = try_copy(cf.as_bytes()).and_then(|b| {
            String::from_utf8(b).map_err(|e| {
                StorageError::InvalidData(format!("column family name is not utf-8: {e}"))
            })
        })?;

        // ── commit point ───────────────────────────────────────────────────
        //
        // Nothing above this line mutated the overlay, and nothing below this
        // line allocates anything block-sized: every owned buffer was built
        // fallibly above and is moved into place here. The one allocation that
        // remains is `BTreeMap`/`HashMap` node insertion, which is not fallible
        // through their safe APIs — there is no `try_insert`, and insertion can
        // abort on allocation failure.
        //
        // That overhead is per-entry, and entry count does depend on block
        // contents. It is bounded only indirectly: each distinct key charges at
        // least its length plus its pre-image against the logical limit, so the
        // limit caps the entry count, and the CF set is fixed at open time. What
        // this ordering protects against is the direct, unbounded case — a copy
        // sized by a single value the block chose.
        if let (Some(pre), Some(cf_owned), Some(pre_key)) =
            (owned_preimage, owned_cf_for_pre, owned_preimage_key)
        {
            self.preimages
                .entry(cf_owned)
                .or_default()
                .insert(pre_key, pre);
        }
        self.writes
            .entry(owned_cf_for_write)
            .or_default()
            .insert(owned_write_key, owned_op);
        self.logical_bytes = next;
        Ok(())
    }

    /// Buffer a write.
    pub fn put(&mut self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.stage(cf, key, OpRef::Put(value))
    }

    /// Buffer a delete.
    pub fn delete(&mut self, cf: &str, key: &[u8]) -> Result<()> {
        self.stage(cf, key, OpRef::Delete)
    }

    /// Overlay-first point read.
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.writes.get(cf).and_then(|m| m.get(key)) {
            Some(Op::Put(v)) => Ok(Some(v.clone())),
            Some(Op::Delete) => Ok(None),
            None => self.db.get(cf, key),
        }
    }

    /// Whether `key` is present, honouring buffered deletes.
    pub fn contains(&self, cf: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get(cf, key)?.is_some())
    }

    /// The pre-image captured for `key`, if it has been written in this overlay.
    ///
    /// `Some(None)` means "written, and it did not exist before" — the case an
    /// undo journal must record as a deletion rather than a zero row.
    pub fn preimage(&self, cf: &str, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        self.preimages.get(cf).and_then(|m| m.get(key))
    }

    /// Every captured pre-image for a column family, in key order.
    pub fn preimages_for(&self, cf: &str) -> impl Iterator<Item = (&Vec<u8>, &Option<Vec<u8>>)> {
        self.preimages.get(cf).into_iter().flat_map(BTreeMap::iter)
    }

    /// Merged forward iteration from the start of the column family.
    pub fn iter<'o>(&'o self, cf: &str) -> Result<MergedIter<'o>> {
        self.merged(cf, None)
    }

    /// Merged forward iteration from the first key `>= start`.
    pub fn iter_from<'o>(&'o self, cf: &str, start: &[u8]) -> Result<MergedIter<'o>> {
        self.merged(cf, Some(start))
    }

    /// Merged prefix iteration.
    ///
    /// This deliberately reproduces RocksDB's prefix-overrun behaviour rather
    /// than bounding the scan: `prefix_iterator_cf` seeks to `prefix` and then
    /// keeps yielding, so it can return keys beyond the prefix, and callers in
    /// this repository are written against that. The overlay side therefore also
    /// starts at `prefix` and continues, so both sides overrun identically and
    /// adding the overlay does not silently change any existing caller's result.
    pub fn prefix_iter<'o>(&'o self, cf: &str, prefix: &[u8]) -> Result<MergedIter<'o>> {
        self.merged(cf, Some(prefix))
    }

    fn merged<'o>(&'o self, cf: &str, start: Option<&[u8]>) -> Result<MergedIter<'o>> {
        let base = self.db.iter_checked_from(cf, start)?;
        // The closure is NOT redundant, whatever clippy says: `empty_writes`
        // returns `&'static`, and passing the function item makes
        // `unwrap_or_else` unify the borrow with `'static`, forcing `'o:
        // 'static` and failing to compile. The closure lets the `'static`
        // reference coerce down to `'o`.
        #[allow(clippy::redundant_closure)]
        let map = self.writes.get(cf).unwrap_or_else(|| empty_writes());
        // Borrowed range — no copy of the buffered write set.
        let overlay = match start {
            Some(s) => map.range::<[u8], _>((
                std::ops::Bound::Included(s),
                std::ops::Bound::Unbounded,
            )),
            None => map.range::<[u8], _>((
                std::ops::Bound::Unbounded,
                std::ops::Bound::Unbounded,
            )),
        };
        Ok(MergedIter {
            base: base.peekable(),
            overlay: overlay.peekable(),
            done: false,
        })
    }

    /// Convert the buffered writes into one ordinary atomic [`WriteBatch`].
    ///
    /// Consumes the overlay and targets the database the overlay read from.
    /// Taking a `&Database` argument here would let a caller build a batch for
    /// one database out of pre-images read from another — the resulting writes
    /// would be internally consistent and completely wrong.
    ///
    /// Call this ONLY after execution and root verification have both succeeded.
    /// Until it is called — and until the batch is committed — nothing this
    /// overlay buffered has touched canonical state, so abandoning the overlay
    /// is a complete and side-effect-free rollback of the candidate branch.
    pub fn into_batch(self) -> Result<WriteBatch<'a>> {
        let mut batch = self.db.batch();
        // Deterministic order: column families sorted by name, keys in order
        // within each. The resulting batch is then a pure function of the
        // buffered writes, so two nodes applying the same block emit the same
        // batch.
        let mut cfs: Vec<&String> = self.writes.keys().collect();
        cfs.sort();
        for cf in cfs {
            for (key, op) in &self.writes[cf] {
                match op {
                    Op::Put(v) => batch.put(cf, key, v)?,
                    Op::Delete => batch.delete(cf, key)?,
                }
            }
        }
        Ok(batch)
    }
}

/// Merged overlay + database iterator.
///
/// Yields `Result`, so a read error stops the scan loudly instead of truncating
/// it into a short, plausible-looking result. Borrows the overlay's buffered map
/// rather than copying it.
pub struct MergedIter<'o> {
    base: std::iter::Peekable<crate::db::CheckedIter<'o>>,
    overlay: std::iter::Peekable<btree_map::Range<'o, Vec<u8>, Op>>,
    done: bool,
}

impl Iterator for MergedIter<'_> {
    type Item = Result<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            // Surface a base read error immediately, and stop: continuing past
            // one would produce a scan that silently skipped rows.
            if let Some(Err(_)) = self.base.peek() {
                self.done = true;
                return match self.base.next() {
                    Some(Err(e)) => Some(Err(e)),
                    _ => None,
                };
            }

            let base_key: Option<&[u8]> = match self.base.peek() {
                Some(Ok((k, _))) => Some(k.as_ref()),
                _ => None,
            };
            let ov_key: Option<&[u8]> = self.overlay.peek().map(|(k, _)| k.as_slice());

            enum Take {
                Base,
                Overlay,
                Both,
                Stop,
            }
            let take = match (base_key, ov_key) {
                (None, None) => Take::Stop,
                (Some(_), None) => Take::Base,
                (None, Some(_)) => Take::Overlay,
                (Some(bk), Some(ok)) => match ok.cmp(bk) {
                    std::cmp::Ordering::Less => Take::Overlay,
                    std::cmp::Ordering::Equal => Take::Both,
                    std::cmp::Ordering::Greater => Take::Base,
                },
            };

            match take {
                Take::Stop => {
                    self.done = true;
                    return None;
                }
                Take::Base => {
                    return match self.base.next() {
                        Some(Ok((k, v))) => Some(Ok((k.into_vec(), v.into_vec()))),
                        _ => {
                            self.done = true;
                            None
                        }
                    }
                }
                Take::Overlay | Take::Both => {
                    if matches!(take, Take::Both) {
                        let _ = self.base.next(); // overlay shadows the row
                    }
                    let (k, op) = self.overlay.next().expect("peeked");
                    match op {
                        Op::Put(v) => return Some(Ok((k.clone(), v.clone()))),
                        Op::Delete => continue, // deleted: skip, do not emit
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::cf;
    use tempfile::TempDir;

    /// Fixture ceiling. Deliberately a test constant: the production limit is a
    /// versioned consensus parameter and this module invents no default.
    const TEST_LIMIT: u64 = 1 << 20;

    fn db() -> (Database, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let db = Database::open_default(dir.path()).expect("open db");
        (db, dir)
    }

    fn collect(it: MergedIter<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
        it.map(|r| r.expect("no read error")).collect()
    }

    #[test]
    fn a_buffered_write_is_visible_to_reads_but_not_to_the_database() {
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"k", b"v").unwrap();

        assert_eq!(ov.get(cf::STATE, b"k").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(
            d.get(cf::STATE, b"k").unwrap(),
            None,
            "the candidate write must not have reached canonical state"
        );
    }

    #[test]
    fn a_buffered_delete_hides_a_row_that_is_still_on_disk() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"v").unwrap();
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.delete(cf::STATE, b"k").unwrap();

        assert_eq!(ov.get(cf::STATE, b"k").unwrap(), None);
        assert!(!ov.contains(cf::STATE, b"k").unwrap());
        assert_eq!(
            d.get(cf::STATE, b"k").unwrap().as_deref(),
            Some(&b"v"[..]),
            "the delete is buffered, not applied"
        );
    }

    #[test]
    fn iteration_and_point_reads_agree_on_writes_deletes_and_overwrites() {
        let (d, _g) = db();
        d.put(cf::STATE, b"a", b"1").unwrap();
        d.put(cf::STATE, b"b", b"2").unwrap();
        d.put(cf::STATE, b"d", b"4").unwrap();

        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"b", b"overwritten").unwrap(); // shadow
        ov.delete(cf::STATE, b"d").unwrap(); // hide
        ov.put(cf::STATE, b"c", b"3").unwrap(); // insert between

        let seen = collect(ov.iter(cf::STATE).unwrap());
        let keys: Vec<&[u8]> = seen.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, vec![&b"a"[..], &b"b"[..], &b"c"[..]], "ordered merge");
        assert_eq!(seen[1].1, b"overwritten".to_vec());

        // The property that matters: a scan and a point read cannot disagree.
        for (k, v) in &seen {
            assert_eq!(ov.get(cf::STATE, k).unwrap().as_ref(), Some(v));
        }
        assert_eq!(ov.get(cf::STATE, b"d").unwrap(), None);
    }

    #[test]
    fn repeated_overwrites_keep_the_first_preimage() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"original").unwrap();
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"k", b"first").unwrap();
        ov.put(cf::STATE, b"k", b"second").unwrap();

        assert_eq!(
            ov.preimage(cf::STATE, b"k"),
            Some(&Some(b"original".to_vec())),
            "an intermediate value must never replace the original pre-image"
        );
        assert_eq!(ov.get(cf::STATE, b"k").unwrap().unwrap(), b"second".to_vec());
    }

    #[test]
    fn a_preimage_records_absence_distinctly_from_an_empty_value() {
        let (d, _g) = db();
        d.put(cf::STATE, b"present", b"").unwrap(); // present, zero-length
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"present", b"x").unwrap();
        ov.put(cf::STATE, b"absent", b"x").unwrap();

        assert_eq!(ov.preimage(cf::STATE, b"present"), Some(&Some(Vec::new())));
        assert_eq!(
            ov.preimage(cf::STATE, b"absent"),
            Some(&None),
            "absence must be representable, not flattened to an empty value"
        );
    }

    #[test]
    fn iter_from_seeks_and_merges() {
        let (d, _g) = db();
        for k in [b"a", b"c", b"e"] {
            d.put(cf::STATE, k, b"db").unwrap();
        }
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"b", b"ov").unwrap();
        ov.put(cf::STATE, b"d", b"ov").unwrap();

        let keys: Vec<Vec<u8>> = collect(ov.iter_from(cf::STATE, b"b").unwrap())
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            vec![b"b".to_vec(), b"c".to_vec(), b"d".to_vec(), b"e".to_vec()],
            "seek must skip 'a' and still interleave both sides"
        );
    }

    #[test]
    fn byte_accounting_is_deterministic_and_charges_preimages() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"0123456789").unwrap(); // 10-byte pre-image

        let mut a = ApplicationOverlay::new(&d, TEST_LIMIT);
        a.put(cf::STATE, b"k", b"xy").unwrap();
        let first = a.logical_bytes();

        let mut b = ApplicationOverlay::new(&d, TEST_LIMIT);
        b.put(cf::STATE, b"k", b"xy").unwrap();
        assert_eq!(first, b.logical_bytes(), "same writes must charge the same");

        // key(1) + preimage(10) + key(1) + value(2)
        assert_eq!(first, 14);
    }

    #[test]
    fn the_limit_is_enforced_rather_than_saturating() {
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::new(&d, 16);
        ov.put(cf::STATE, b"k", &[0u8; 8]).unwrap();
        let err = ov
            .put(cf::STATE, b"k2", &[0u8; 64])
            .expect_err("must refuse to exceed the ceiling");
        assert!(
            err.to_string().contains("limit"),
            "error must name the limit: {err}"
        );
    }

    #[test]
    fn into_batch_is_the_only_thing_that_reaches_the_database() {
        let (d, _g) = db();
        d.put(cf::STATE, b"gone", b"v").unwrap();
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        ov.put(cf::STATE, b"new", b"v").unwrap();
        ov.delete(cf::STATE, b"gone").unwrap();

        assert_eq!(d.get(cf::STATE, b"new").unwrap(), None);
        ov.into_batch().unwrap().commit().unwrap();

        assert_eq!(d.get(cf::STATE, b"new").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(d.get(cf::STATE, b"gone").unwrap(), None);
    }

    #[test]
    fn dropping_an_overlay_is_a_complete_rollback() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"canonical").unwrap();
        {
            let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
            ov.put(cf::STATE, b"k", b"candidate").unwrap();
            ov.put(cf::STATE, b"other", b"candidate").unwrap();
            ov.delete(cf::STATE, b"k").unwrap();
            // dropped without into_batch — the candidate branch is abandoned
        }
        assert_eq!(
            d.get(cf::STATE, b"k").unwrap().as_deref(),
            Some(&b"canonical"[..]),
            "abandoning a candidate must leave canonical state byte-identical"
        );
        assert_eq!(d.get(cf::STATE, b"other").unwrap(), None);
    }

    // ── Transactionality: a refused operation must change nothing ──────────
    //
    // These exist because the first version of this module mutated as it went:
    // it subtracted the previous charge before adding the replacement, and it
    // inserted the pre-image before the write was charged. Both left the
    // overlay altered by an operation that returned `Err` — the ceiling itself
    // becoming a source of corruption.

    /// A snapshot of everything externally observable, for exact comparison.
    fn snapshot(ov: &ApplicationOverlay<'_>) -> (u64, usize, Vec<(String, Vec<u8>)>) {
        let mut pre: Vec<(String, Vec<u8>)> = ov
            .preimages
            .iter()
            .flat_map(|(cf, m)| m.keys().map(move |k| (cf.clone(), k.clone())))
            .collect();
        pre.sort();
        (ov.logical_bytes(), ov.len(), pre)
    }

    #[test]
    fn a_rejected_repeated_overwrite_leaves_accounting_untouched() {
        let (d, _g) = db();
        // Room for the first write, not for a much larger replacement.
        let mut ov = ApplicationOverlay::new(&d, 64);
        ov.put(cf::STATE, b"k", &[0u8; 32]).unwrap();
        let before = snapshot(&ov);

        ov.put(cf::STATE, b"k", &[0u8; 4096])
            .expect_err("replacement must be refused");

        assert_eq!(
            snapshot(&ov),
            before,
            "a refused overwrite must leave the overlay byte-identical; \
             subtracting the old charge before the new one is accepted loses bytes"
        );
        assert_eq!(
            ov.get(cf::STATE, b"k").unwrap().unwrap().len(),
            32,
            "the original buffered value must survive"
        );
    }

    #[test]
    fn a_rejected_first_write_leaves_no_captured_preimage() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"original").unwrap();
        let mut ov = ApplicationOverlay::new(&d, 8);
        let before = snapshot(&ov);

        ov.put(cf::STATE, b"k", &[0u8; 4096])
            .expect_err("write must be refused");

        assert_eq!(
            snapshot(&ov),
            before,
            "a refused first write must not leave a pre-image behind"
        );
        assert_eq!(
            ov.preimage(cf::STATE, b"k"),
            None,
            "no pre-image may be recorded for a write that did not happen"
        );
    }

    #[test]
    fn combined_length_arithmetic_cannot_overflow_silently() {
        // `to_u64`/`add` are the guards; exercise them directly, since
        // allocating usize::MAX bytes to test through `put` is impossible.
        assert!(add(u64::MAX, 1).is_err(), "addition must be checked");
        assert!(add(u64::MAX - 1, 2).is_err());
        assert_eq!(add(2, 3).unwrap(), 5);
        assert!(
            sub(1, 2).is_err(),
            "underflow is an invariant violation, not something to saturate"
        );
        assert_eq!(sub(5, 2).unwrap(), 3);
        assert_eq!(to_u64(7).unwrap(), 7);
    }

    /// Regression guard, not a detector — and the distinction is worth stating.
    ///
    /// A cloning implementation would still pass this: copying the write set
    /// changes neither the entry count nor the accounting field. What actually
    /// prevents the copy is the type — [`MergedIter`] holds a
    /// `btree_map::Range<'o, _, _>`, a borrow of the overlay's own map, so a
    /// whole-overlay duplicate cannot be constructed without changing that
    /// field. This test pins the observable behaviour around it.
    #[test]
    fn iterator_construction_does_not_duplicate_the_overlay() {
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::new(&d, TEST_LIMIT);
        for i in 0..64u8 {
            ov.put(cf::STATE, &[i], &[i; 64]).unwrap();
        }
        let charged = ov.logical_bytes();
        let buffered = ov.len();

        // Constructing (and draining) iterators must not allocate a second copy
        // of the write set, and must not disturb the accounting.
        for _ in 0..8 {
            let n = ov.iter(cf::STATE).unwrap().count();
            assert_eq!(n, buffered);
            let _ = ov.iter_from(cf::STATE, &[32]).unwrap().count();
            let _ = ov.prefix_iter(cf::STATE, &[0]).unwrap().count();
        }
        assert_eq!(ov.logical_bytes(), charged, "iteration must not charge");
        assert_eq!(ov.len(), buffered);
    }

    /// Also structural rather than detected: `into_batch(self)` takes no
    /// database, so there is no expression that aims an overlay's writes at a
    /// database other than the one its pre-images were read from. This test
    /// pins that the signature keeps that property.
    #[test]
    fn a_batch_targets_the_overlays_own_database() {
        let (d1, _g1) = db();
        let (d2, _g2) = db();
        d1.put(cf::STATE, b"k", b"from-d1").unwrap();

        let mut ov = ApplicationOverlay::new(&d1, TEST_LIMIT);
        ov.put(cf::STATE, b"k", b"candidate").unwrap();
        // `into_batch` takes no database argument, so there is no way to aim
        // these writes at d2. It commits where the pre-images came from.
        ov.into_batch().unwrap().commit().unwrap();

        assert_eq!(
            d1.get(cf::STATE, b"k").unwrap().as_deref(),
            Some(&b"candidate"[..])
        );
        assert_eq!(
            d2.get(cf::STATE, b"k").unwrap(),
            None,
            "an unrelated database must be untouched"
        );
    }

    // ── Allocation refusal: measure before owning ─────────────────────────
    //
    // The point of these is the ORDER of operations. An implementation that
    // builds `Op::Put(value.to_vec())` at the call site, or reads the pre-image
    // with `get` instead of `get_pinned`, has already made the allocation by
    // the time the limit refuses the write — so the limit bounds nothing.

    /// End-state guard only. This asserts the overlay is unchanged after a
    /// refusal; it does NOT prove the value went unmeasured-before-copied — a
    /// copy-then-discard implementation passes it unchanged. The ordering is
    /// instrumented in `tests/overlay_allocation.rs`, which counts allocations.
    #[test]
    fn an_oversized_new_value_is_refused() {
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::new(&d, 128);
        let before = snapshot(&ov);

        // Far beyond the ceiling. Refused on measurement of the borrowed slice.
        let huge = vec![0u8; 8 * 1024 * 1024];
        let err = ov
            .put(cf::STATE, b"k", &huge)
            .expect_err("must be refused, not copied then refused");
        assert!(err.to_string().contains("limit"), "{err}");

        assert_eq!(
            snapshot(&ov),
            before,
            "a refused oversized write must leave the overlay byte-identical"
        );
        assert!(ov.is_empty());
    }

    /// End-state guard only, as above; the pinned read is instrumented in
    /// `tests/overlay_allocation.rs`.
    #[test]
    fn an_oversized_persisted_preimage_is_refused() {
        let (d, _g) = db();
        // A large value already on disk; writing over it must charge its length
        // as the pre-image, and be refused before that pre-image is copied out.
        let big = vec![7u8; 4 * 1024 * 1024];
        d.put(cf::STATE, b"k", &big).unwrap();

        let mut ov = ApplicationOverlay::new(&d, 1024);
        let before = snapshot(&ov);

        let err = ov
            .put(cf::STATE, b"k", b"tiny")
            .expect_err("the pre-image alone exceeds the ceiling");
        assert!(err.to_string().contains("limit"), "{err}");

        assert_eq!(snapshot(&ov), before, "overlay must be byte-identical");
        assert_eq!(
            ov.preimage(cf::STATE, b"k"),
            None,
            "no pre-image may be retained for a refused write"
        );
        assert_eq!(
            d.get(cf::STATE, b"k").unwrap().unwrap().len(),
            big.len(),
            "and the database is untouched"
        );
    }

    #[test]
    fn a_refused_write_does_not_abort_the_process() {
        // Both refusals above return `Err`. That they are errors rather than
        // aborts is the property `try_reserve_exact` buys over `to_vec`: the
        // node reports that a candidate branch is too large and keeps running,
        // instead of dying and taking the canonical chain's availability with
        // it.
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::new(&d, 64);
        assert!(ov.put(cf::STATE, b"k", &vec![0u8; 1 << 20]).is_err());
        // Still usable afterwards.
        ov.put(cf::STATE, b"s", b"ok").unwrap();
        assert_eq!(ov.get(cf::STATE, b"s").unwrap().unwrap(), b"ok".to_vec());
    }
}
