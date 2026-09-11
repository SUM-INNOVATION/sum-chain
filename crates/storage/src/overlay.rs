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
//! Errors are propagated, never dropped. The database's own iterators end in
//! `.filter_map(|r| r.ok())`, which silently truncates a scan at the first read
//! error and is indistinguishable from a short collection; this module iterates
//! over `Result` and surfaces the failure.

use std::collections::{btree_map, BTreeMap, HashMap};

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
    /// Deterministic byte accounting. Counts key and value bytes of buffered
    /// writes plus captured pre-images, so the number depends only on what was
    /// written — never on allocator behaviour or map capacity.
    bytes: u64,
    limit: u64,
}

/// Default ceiling on overlay residency: 512 MiB.
pub const DEFAULT_OVERLAY_LIMIT_BYTES: u64 = 512 * 1024 * 1024;

impl<'a> ApplicationOverlay<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self::with_limit(db, DEFAULT_OVERLAY_LIMIT_BYTES)
    }

    pub fn with_limit(db: &'a Database, limit: u64) -> Self {
        Self {
            db,
            writes: HashMap::new(),
            preimages: HashMap::new(),
            bytes: 0,
            limit,
        }
    }

    /// Bytes currently accounted to this overlay.
    pub fn bytes_used(&self) -> u64 {
        self.bytes
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

    /// Add `n` to the accounted total, failing closed on overflow or over-limit.
    ///
    /// `checked_add` rather than saturating: a saturating counter silently stops
    /// growing and the ceiling stops meaning anything, which is the failure mode
    /// this accounting exists to prevent.
    fn charge(&mut self, n: usize) -> Result<()> {
        let n = n as u64;
        let next = self.bytes.checked_add(n).ok_or_else(|| {
            StorageError::InvalidData("overlay byte accounting overflowed u64".to_string())
        })?;
        if next > self.limit {
            return Err(StorageError::InvalidData(format!(
                "overlay exceeded its {} byte limit (would reach {next}); \
                 the candidate branch is too large to evaluate in memory",
                self.limit
            )));
        }
        self.bytes = next;
        Ok(())
    }

    /// Capture the pre-image for `key` if this is its first write in the overlay.
    fn capture_preimage(&mut self, cf: &str, key: &[u8]) -> Result<()> {
        if self
            .preimages
            .get(cf)
            .is_some_and(|m| m.contains_key(key))
        {
            return Ok(()); // already captured; keep the ORIGINAL
        }
        let prior = self.db.get(cf, key)?;
        let charge = key.len() + prior.as_ref().map_or(0, Vec::len);
        self.charge(charge)?;
        self.preimages
            .entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), prior);
        Ok(())
    }

    /// Buffer a write.
    pub fn put(&mut self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.capture_preimage(cf, key)?;
        let entry = self.writes.entry(cf.to_string()).or_default();
        // A repeated overwrite replaces the buffered value; charge only the
        // delta so repeatedly writing one key cannot inflate the total.
        let previous_len = entry.get(key).map(Op::value_len);
        match previous_len {
            Some(prev) => {
                self.bytes = self.bytes.saturating_sub(prev as u64);
                self.charge(value.len())?;
            }
            None => self.charge(key.len() + value.len())?,
        }
        self.writes
            .get_mut(cf)
            .expect("entry just inserted")
            .insert(key.to_vec(), Op::Put(value.to_vec()));
        Ok(())
    }

    /// Buffer a delete.
    pub fn delete(&mut self, cf: &str, key: &[u8]) -> Result<()> {
        self.capture_preimage(cf, key)?;
        let entry = self.writes.entry(cf.to_string()).or_default();
        if let Some(prev) = entry.get(key).map(Op::value_len) {
            self.bytes = self.bytes.saturating_sub(prev as u64);
        } else {
            self.charge(key.len())?;
        }
        self.writes
            .get_mut(cf)
            .expect("entry just inserted")
            .insert(key.to_vec(), Op::Delete);
        Ok(())
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
        self.merged(cf, Some(start.to_vec()))
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
        self.merged(cf, Some(prefix.to_vec()))
    }

    fn merged<'o>(&'o self, cf: &str, start: Option<Vec<u8>>) -> Result<MergedIter<'o>> {
        let base = self.db.iter_checked_from(cf, start.as_deref())?;
        let overlay: Vec<(Vec<u8>, Op)> = match self.writes.get(cf) {
            Some(m) => match &start {
                Some(s) => m
                    .range::<[u8], _>((std::ops::Bound::Included(s.as_slice()), std::ops::Bound::Unbounded))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                None => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            },
            None => Vec::new(),
        };
        Ok(MergedIter {
            base: base.peekable(),
            overlay: overlay.into_iter().peekable(),
            done: false,
        })
    }

    /// Convert the buffered writes into one ordinary atomic [`WriteBatch`].
    ///
    /// Call this ONLY after execution and root verification have both succeeded.
    /// Until it is called — and until the batch is committed — nothing this
    /// overlay buffered has touched canonical state, so abandoning the overlay
    /// is a complete and side-effect-free rollback of the candidate branch.
    pub fn into_batch(self, db: &'a Database) -> Result<WriteBatch<'a>> {
        let mut batch = db.batch();
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
/// it into a short, plausible-looking result.
pub struct MergedIter<'o> {
    base: std::iter::Peekable<Box<dyn Iterator<Item = Result<(Box<[u8]>, Box<[u8]>)>> + 'o>>,
    overlay: std::iter::Peekable<std::vec::IntoIter<(Vec<u8>, Op)>>,
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

            let base_key = self.base.peek().and_then(|r| match r {
                Ok((k, _)) => Some(k.as_ref().to_vec()),
                Err(_) => None,
            });
            let ov_key = self.overlay.peek().map(|(k, _)| k.clone());

            match (base_key, ov_key) {
                (None, None) => {
                    self.done = true;
                    return None;
                }
                (Some(_), None) => {
                    let (k, v) = match self.base.next() {
                        Some(Ok(kv)) => kv,
                        _ => {
                            self.done = true;
                            return None;
                        }
                    };
                    return Some(Ok((k.into_vec(), v.into_vec())));
                }
                (None, Some(_)) => {
                    let (k, op) = self.overlay.next().expect("peeked");
                    match op {
                        Op::Put(v) => return Some(Ok((k, v))),
                        Op::Delete => continue, // deleted: skip, do not emit
                    }
                }
                (Some(bk), Some(ok)) => {
                    if ok < bk {
                        let (k, op) = self.overlay.next().expect("peeked");
                        match op {
                            Op::Put(v) => return Some(Ok((k, v))),
                            Op::Delete => continue,
                        }
                    } else if ok == bk {
                        // Overlay shadows the database row.
                        let _ = self.base.next();
                        let (k, op) = self.overlay.next().expect("peeked");
                        match op {
                            Op::Put(v) => return Some(Ok((k, v))),
                            Op::Delete => continue,
                        }
                    } else {
                        let (k, v) = match self.base.next() {
                            Some(Ok(kv)) => kv,
                            _ => {
                                self.done = true;
                                return None;
                            }
                        };
                        return Some(Ok((k.into_vec(), v.into_vec())));
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
        let mut ov = ApplicationOverlay::new(&d);
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
        let mut ov = ApplicationOverlay::new(&d);
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

        let mut ov = ApplicationOverlay::new(&d);
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
        let mut ov = ApplicationOverlay::new(&d);
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
        let mut ov = ApplicationOverlay::new(&d);
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
        let mut ov = ApplicationOverlay::new(&d);
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

        let mut a = ApplicationOverlay::new(&d);
        a.put(cf::STATE, b"k", b"xy").unwrap();
        let first = a.bytes_used();

        let mut b = ApplicationOverlay::new(&d);
        b.put(cf::STATE, b"k", b"xy").unwrap();
        assert_eq!(first, b.bytes_used(), "same writes must charge the same");

        // key(1) + preimage(10) + key(1) + value(2)
        assert_eq!(first, 14);
    }

    #[test]
    fn the_limit_is_enforced_rather_than_saturating() {
        let (d, _g) = db();
        let mut ov = ApplicationOverlay::with_limit(&d, 16);
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
        let mut ov = ApplicationOverlay::new(&d);
        ov.put(cf::STATE, b"new", b"v").unwrap();
        ov.delete(cf::STATE, b"gone").unwrap();

        assert_eq!(d.get(cf::STATE, b"new").unwrap(), None);
        ov.into_batch(&d).unwrap().commit().unwrap();

        assert_eq!(d.get(cf::STATE, b"new").unwrap().as_deref(), Some(&b"v"[..]));
        assert_eq!(d.get(cf::STATE, b"gone").unwrap(), None);
    }

    #[test]
    fn dropping_an_overlay_is_a_complete_rollback() {
        let (d, _g) = db();
        d.put(cf::STATE, b"k", b"canonical").unwrap();
        {
            let mut ov = ApplicationOverlay::new(&d);
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
}
