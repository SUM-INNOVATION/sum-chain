//! The only handle block execution is given to state.
//!
//! [`ExecutionView`] is a concrete type wrapping an [`ApplicationOverlay`]. It
//! is deliberately NOT a trait implemented by both the overlay and [`Database`].
//!
//! A shared trait is the obvious design and the wrong one here. It would make
//! `&Database` and `&ApplicationOverlay` interchangeable at every execution call
//! site, so passing the committed handle into block execution would remain a
//! well-typed mistake — exactly the mistake this work exists to make
//! impossible. One accidental `&self.db` in a new executor method and the block
//! writes straight through again, with nothing at the type level to notice.
//!
//! With a concrete view, execution code names `ExecutionView` in its
//! signatures. There is no impl that produces one from a `Database`, so a
//! committed handle cannot be substituted: the mistake stops being expressible
//! rather than merely discouraged.
//!
//! # Scope
//!
//! Everything reachable from block execution — point reads, scans, writes and
//! deletes — goes through here. Reads see the block's own earlier writes, which
//! is what makes execution correct against a candidate branch rather than
//! against the parent's state.
//!
//! The view holds a mutable borrow of the overlay for its lifetime, so the
//! overlay cannot be committed or inspected while execution is in progress. When
//! execution finishes, the caller still holds the overlay and decides — after
//! verifying the state root — whether to convert it into a batch or drop it.

use crate::overlay::{ApplicationOverlay, MergedIter};
use crate::Result;

/// The execution boundary. Block execution reads and writes only through this.
pub struct ExecutionView<'v, 'db> {
    overlay: &'v mut ApplicationOverlay<'db>,
}

impl<'v, 'db> ExecutionView<'v, 'db> {
    /// Open a view over `overlay` for the duration of one block's execution.
    pub fn new(overlay: &'v mut ApplicationOverlay<'db>) -> Self {
        Self { overlay }
    }

    /// Point read, honouring this block's own earlier writes and deletes.
    pub fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.overlay.get(cf, key)
    }

    pub fn contains(&self, cf: &str, key: &[u8]) -> Result<bool> {
        self.overlay.contains(cf, key)
    }

    /// Buffer a write. Nothing reaches the database here.
    pub fn put(&mut self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        self.overlay.put(cf, key, value)
    }

    /// Buffer a delete.
    pub fn delete(&mut self, cf: &str, key: &[u8]) -> Result<()> {
        self.overlay.delete(cf, key)
    }

    /// Merged scan from the start of a column family.
    ///
    /// Overlay-aware, so a scan and a point read cannot disagree within a block.
    /// Yields `Result`: a read error ends the scan loudly rather than truncating
    /// it into a short, plausible-looking result that execution would then
    /// commit to a state root.
    pub fn iter(&self, cf: &str) -> Result<MergedIter<'_>> {
        self.overlay.iter(cf)
    }

    /// Merged scan from the first key `>= start`.
    pub fn iter_from(&self, cf: &str, start: &[u8]) -> Result<MergedIter<'_>> {
        self.overlay.iter_from(cf, start)
    }

    /// Merged prefix scan, reproducing RocksDB's prefix-overrun behaviour.
    pub fn prefix_iter(&self, cf: &str, prefix: &[u8]) -> Result<MergedIter<'_>> {
        self.overlay.prefix_iter(cf, prefix)
    }

    /// The pre-image captured for `key`, if this block has written it.
    ///
    /// `Some(None)` means the key did not exist before this block — the case an
    /// undo journal must record as a deletion rather than a zero row.
    pub fn preimage(&self, cf: &str, key: &[u8]) -> Option<&Option<Vec<u8>>> {
        self.overlay.preimage(cf, key)
    }

    /// Every pre-image captured for a column family, in key order. This is the
    /// material an undo journal is built from.
    pub fn preimages_for(&self, cf: &str) -> impl Iterator<Item = (&Vec<u8>, &Option<Vec<u8>>)> {
        self.overlay.preimages_for(cf)
    }

    /// Logical write-set bytes buffered so far. Not a residency bound; see
    /// [`crate::overlay`].
    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Whether this block has written anything.
    pub fn is_empty(&self) -> bool {
        self.overlay.is_empty()
    }
}
