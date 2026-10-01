//! Branch state: the exact application state at a historical fork parent, plus
//! a replacement branch's speculative writes, as an ordered override layer over
//! the committed database (#269).
//!
//! # Why a layer and not a checkpoint
//!
//! A replacement branch forks at an ancestor `F` below the canonical head `C`.
//! Its first block must execute against the state that existed after `F`, and
//! the committed database holds the state after `C`. A RocksDB checkpoint
//! captures only the CURRENT state, so it cannot stand in for `F`. What can is
//! the generic application journal: every canonical block in `(F, C]` recorded,
//! for every key it wrote, the exact value that key held before it — the
//! pre-image, with absence distinguished from an empty value. Layering those
//! pre-images over the committed database, newest block first so that the
//! earliest pre-image for a key is the one that survives, reproduces `F`
//! exactly for every key any of those blocks touched; every other key never
//! changed and is read from the database as it is.
//!
//! # What makes a reconstruction trustworthy
//!
//! [`BranchState::restore_parent`] refuses to layer a journal unless, for every
//! key it describes, the value the layer currently presents is the value the
//! journal says its block LEFT. Restoring newest first, the presented value for
//! block `k`'s keys is exactly the state after `k`, so the check proves the
//! journal describes the state it is being unwound from: a corrupt record, a
//! record for another block, or a database that moved on since the record was
//! written is refused rather than layered. The record's own `(height, hash)` is
//! checked against the block it is loaded for by
//! [`crate::journal::ApplicationJournal::decode_for`] before it gets here.
//!
//! # Speculative writes
//!
//! Once the parent is reconstructed, each replacement block executes in its own
//! [`crate::overlay::ApplicationOverlay`] whose reads fall through to this
//! layer, and after it is accepted its net writes are [`absorbed`] here so the
//! next block reads them. Nothing in this module writes to the database: the
//! only way any of it reaches canonical storage is the single adoption batch
//! built from [`BranchState::entries`] after the whole branch has been validated.
//!
//! [`absorbed`]: BranchState::absorb_net_writes
//!
//! # Bounds
//!
//! Every byte held is charged against an explicit local limit. Exceeding it is a
//! [`StorageError::BranchStateLimitExceeded`]: a statement about this node's
//! resources, never about the branch's validity, so a caller must treat it as a
//! local fail-stop and not as a reason to reject the branch.

use std::collections::{btree_map, BTreeMap, HashMap};

use crate::db::{CheckedEntry, CheckedIter, Database};
use crate::journal::{AfterImage, ApplicationJournal, Preimage};
use crate::{Result, StorageError};

/// The reconstructed parent state plus the branch's own writes, over the
/// committed database.
///
/// `None` in the layer is a positive statement that the key does not exist at
/// this point of the branch — a tombstone that hides a row the database still
/// holds — and is distinct from the key being absent from the layer, which
/// means "read the database".
#[derive(Debug, Default)]
pub struct BranchState {
    layer: HashMap<String, BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    /// Key plus value bytes held in `layer`.
    bytes: u64,
    limit: u64,
    /// Pre-image bytes restored from journals (part of `bytes`), reported for
    /// measurement.
    restored_bytes: u64,
    /// Journals layered, newest first.
    restored_blocks: u64,
    /// Blocks absorbed.
    absorbed_blocks: u64,
}

/// One key's value at a point of a branch: column family, key, and the value
/// (`None` for deleted).
pub type LayerEntry<'a> = (&'a str, &'a [u8], Option<&'a [u8]>);

fn entry_len(key: &[u8], value: Option<&[u8]>) -> u64 {
    key.len() as u64 + value.map_or(0, |v| v.len() as u64)
}

impl BranchState {
    /// An empty layer — the committed database itself — holding at most
    /// `limit` key-plus-value bytes.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Key-plus-value bytes held.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The limit `bytes` may not exceed.
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Pre-image bytes restored from journals.
    pub fn restored_bytes(&self) -> u64 {
        self.restored_bytes
    }

    /// Number of journals layered.
    pub fn restored_blocks(&self) -> u64 {
        self.restored_blocks
    }

    /// Number of speculative blocks absorbed.
    pub fn absorbed_blocks(&self) -> u64 {
        self.absorbed_blocks
    }

    /// Number of keys the layer overrides.
    pub fn len(&self) -> usize {
        self.layer.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.layer.values().all(BTreeMap::is_empty)
    }

    /// The layer's own answer for `key`: `Some(Some(v))` a value, `Some(None)`
    /// a tombstone, `None` "not overridden — read the database".
    pub fn get_override(&self, cf: &str, key: &[u8]) -> Option<Option<&[u8]>> {
        self.layer
            .get(cf)
            .and_then(|m| m.get(key))
            .map(|v| v.as_deref())
    }

    /// The value at this point of the branch.
    pub fn get(&self, db: &Database, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.get_override(cf, key) {
            Some(v) => Ok(v.map(<[u8]>::to_vec)),
            None => db.get(cf, key),
        }
    }

    /// Set `key` to `value` (`None` deletes), charging the difference.
    fn set(&mut self, cf: &str, key: &[u8], value: Option<&[u8]>) -> Result<()> {
        let old = self
            .layer
            .get(cf)
            .and_then(|m| m.get(key))
            .map(|v| entry_len(key, v.as_deref()));
        let new = entry_len(key, value);
        let next = self
            .bytes
            .checked_sub(old.unwrap_or(0))
            .and_then(|b| b.checked_add(new))
            .ok_or_else(|| {
                StorageError::InvalidData("branch state accounting overflowed".to_string())
            })?;
        if next > self.limit {
            return Err(StorageError::BranchStateLimitExceeded {
                limit: self.limit,
                would_reach: next,
            });
        }
        self.layer
            .entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), value.map(<[u8]>::to_vec));
        self.bytes = next;
        Ok(())
    }

    /// Layer one canonical block's pre-images, unwinding the presented state
    /// from "after that block" to "before it".
    ///
    /// Call newest block first, from the canonical head down to the block just
    /// above the fork parent. Refuses — and leaves the layer as it was — unless
    /// every key the journal describes currently presents exactly what the
    /// journal says its block left there. See the module documentation.
    pub fn restore_parent(&mut self, db: &Database, journal: &ApplicationJournal) -> Result<()> {
        // Verify the whole record before layering any of it.
        for e in journal.entries() {
            let current = self.get(db, e.cf(), e.key())?;
            if AfterImage::of(e.cf(), e.key(), current.as_deref()) != *e.after() {
                return Err(StorageError::InvalidData(format!(
                    "application journal for block {} at height {}: column family {} key {} \
                     does not present what that block left there; refusing to reconstruct a \
                     fork parent from a record that does not describe this state",
                    journal.block_hash(),
                    journal.height(),
                    e.cf(),
                    hex::encode(e.key())
                )));
            }
        }
        for e in journal.entries() {
            let before = match e.before() {
                Preimage::Absent => None,
                Preimage::Value(v) => Some(v.as_slice()),
            };
            let held_before = self.bytes;
            self.set(e.cf(), e.key(), before)?;
            self.restored_bytes = self
                .restored_bytes
                .saturating_add(self.bytes.saturating_sub(held_before));
        }
        self.restored_blocks += 1;
        Ok(())
    }

    /// Absorb one accepted speculative block's net writes, so the next block of
    /// the branch reads them.
    pub fn absorb_net_writes<'w>(
        &mut self,
        writes: impl IntoIterator<Item = (&'w str, &'w [u8], Option<&'w [u8]>)>,
    ) -> Result<()> {
        for (cf, key, value) in writes {
            self.set(cf, key, value)?;
        }
        self.absorbed_blocks += 1;
        Ok(())
    }

    /// Every overridden key and the value it holds at this point of the branch,
    /// column families in name order and keys in order — the deterministic
    /// order the adoption batch is built in.
    pub fn entries(&self) -> Vec<LayerEntry<'_>> {
        let mut cfs: Vec<&String> = self.layer.keys().collect();
        cfs.sort();
        let mut out = Vec::new();
        for cf in cfs {
            for (k, v) in &self.layer[cf] {
                out.push((cf.as_str(), k.as_slice(), v.as_deref()));
            }
        }
        out
    }

    /// Ordered forward iteration over the committed database with this layer
    /// applied: overrides shadow database rows and tombstones hide them.
    ///
    /// Reproduces RocksDB's prefix-overrun behaviour exactly as
    /// [`crate::overlay::ApplicationOverlay::prefix_iter`] does: both sides start
    /// at `start` and keep going.
    pub fn iter_checked_from<'a>(
        &'a self,
        db: &'a Database,
        cf: &str,
        start: Option<&[u8]>,
    ) -> Result<CheckedIter<'a>> {
        let base = db.iter_checked_from(cf, start)?;
        let range: btree_map::Range<'a, Vec<u8>, Option<Vec<u8>>> = match self.layer.get(cf) {
            Some(map) => match start {
                Some(s) => {
                    map.range::<[u8], _>((std::ops::Bound::Included(s), std::ops::Bound::Unbounded))
                }
                None => map.range::<[u8], _>(..),
            },
            None => empty_layer().range::<[u8], _>(..),
        };
        Ok(Box::new(LayerIter {
            base: base.peekable(),
            layer: range.peekable(),
            done: false,
        }))
    }
}

fn empty_layer() -> &'static BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    static EMPTY: std::sync::OnceLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>> =
        std::sync::OnceLock::new();
    EMPTY.get_or_init(BTreeMap::new)
}

/// Database rows merged with a branch layer, in key order.
struct LayerIter<'a> {
    base: std::iter::Peekable<CheckedIter<'a>>,
    layer: std::iter::Peekable<btree_map::Range<'a, Vec<u8>, Option<Vec<u8>>>>,
    done: bool,
}

impl Iterator for LayerIter<'_> {
    type Item = CheckedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            // A read error ends the scan loudly rather than truncating it.
            if let Some(Err(_)) = self.base.peek() {
                self.done = true;
                return self.base.next();
            }
            let base_key: Option<&[u8]> = match self.base.peek() {
                Some(Ok((k, _))) => Some(k.as_ref()),
                _ => None,
            };
            let layer_key: Option<&[u8]> = self.layer.peek().map(|(k, _)| k.as_slice());
            let (take_base, take_layer) = match (base_key, layer_key) {
                (None, None) => {
                    self.done = true;
                    return None;
                }
                (Some(_), None) => (true, false),
                (None, Some(_)) => (false, true),
                (Some(b), Some(l)) => match l.cmp(b) {
                    std::cmp::Ordering::Less => (false, true),
                    std::cmp::Ordering::Equal => (true, true),
                    std::cmp::Ordering::Greater => (true, false),
                },
            };
            if take_layer {
                if take_base {
                    let _ = self.base.next(); // the layer shadows the row
                }
                let (k, v) = self.layer.next().expect("peeked");
                match v {
                    Some(v) => {
                        return Some(Ok((
                            k.clone().into_boxed_slice(),
                            v.clone().into_boxed_slice(),
                        )))
                    }
                    None => continue, // tombstone: hidden
                }
            }
            return self.base.next();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::cf;
    use tempfile::TempDir;

    fn db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        (Database::open_default(dir.path()).unwrap(), dir)
    }

    fn rows(it: CheckedIter<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
        it.map(|r| r.map(|(k, v)| (k.into_vec(), v.into_vec())))
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn overrides_and_tombstones_shadow_the_database_in_point_reads_and_scans() {
        let (db, _d) = db();
        for k in [b"a", b"b", b"c"] {
            db.put(cf::STATE, k, b"db").unwrap();
        }
        let mut b = BranchState::new(1 << 20);
        b.set(cf::STATE, b"b", None).unwrap();
        b.set(cf::STATE, b"c", Some(b"layer")).unwrap();
        b.set(cf::STATE, b"d", Some(b"new")).unwrap();
        assert_eq!(b.get(&db, cf::STATE, b"a").unwrap(), Some(b"db".to_vec()));
        assert_eq!(b.get(&db, cf::STATE, b"b").unwrap(), None);
        assert_eq!(
            b.get(&db, cf::STATE, b"c").unwrap(),
            Some(b"layer".to_vec())
        );
        assert_eq!(
            rows(b.iter_checked_from(&db, cf::STATE, None).unwrap()),
            vec![
                (b"a".to_vec(), b"db".to_vec()),
                (b"c".to_vec(), b"layer".to_vec()),
                (b"d".to_vec(), b"new".to_vec()),
            ]
        );
        assert_eq!(
            rows(b.iter_checked_from(&db, cf::STATE, Some(b"c")).unwrap()).len(),
            2
        );
        // Nothing reached the database.
        assert_eq!(db.get(cf::STATE, b"b").unwrap(), Some(b"db".to_vec()));
        assert_eq!(db.get(cf::STATE, b"d").unwrap(), None);
    }

    #[test]
    fn the_limit_is_a_typed_local_refusal() {
        let mut b = BranchState::new(5);
        assert!(b.set(cf::STATE, b"k", Some(b"1234")).is_ok());
        match b.set(cf::STATE, b"j", Some(b"x")) {
            Err(StorageError::BranchStateLimitExceeded { limit, would_reach }) => {
                assert_eq!((limit, would_reach), (5, 7));
            }
            other => panic!("expected a limit refusal, got {other:?}"),
        }
        // Replacing a value is charged as the difference.
        assert!(b.set(cf::STATE, b"k", Some(b"12")).is_ok());
        assert_eq!(b.bytes(), 3);
    }
}
