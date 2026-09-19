//! One bounded-page primitive for the whole-family registry readers.
//!
//! The readers this serves — `list_all`, `list_active`, `get_all`, and the
//! index-driven `get_by_*` family — each built one `Vec` holding every row of a
//! column family and handed it to a caller. Over JSON-RPC that is a response
//! whose size is chosen by whoever last wrote to the chain, not by the caller
//! and not by the node.
//!
//! These readers are **outside consensus**. No transaction's validity depends
//! on them and no state root folds them, so a node that pages and a node that
//! does not still agree about every block. That is why the bound is applied
//! here directly rather than behind an activation height: there is no
//! divergence to coordinate.
//!
//! # What a page bounds, and what it does not
//!
//! A [`PageSpec`] is a window over the rows a reader would have RETURNED, not
//! over the rows it touches. That distinction is the honest part:
//!
//! * The **response** is bounded absolutely: at most `limit` rows come back.
//! * **Peak result allocation** is bounded: at most `limit` decoded rows are
//!   held at once, against one row per family member before. For the readers
//!   this audit names that is the allocation the caller controls.
//! * **Iteration** is bounded only for an unfiltered reader ([`paged_scan`]
//!   with a `keep` that accepts everything stops after `offset + limit` rows).
//!   A filtered reader still walks the family, and an index-driven reader still
//!   point-reads the skipped entries, because neither has an index that can
//!   seek to the Nth match. That cost is unchanged, not made worse, and it is
//!   written down here rather than claimed away.
//!
//! # Ordering
//!
//! [`paged_scan`] yields rows in RocksDB key order, which is a total order over
//! the family and is the same on every call that sees the same rows.
//! [`paged_resolve`] yields rows in the order the index vector stores them,
//! which is insertion order and likewise stable. Two calls with the same
//! `offset` therefore see the same window, and a page boundary is a defined
//! position rather than an artefact of iteration order.

use crate::db::Database;
use crate::Result;

/// Rows returned when the caller asks for no page size at all.
///
/// An existing caller that passes nothing gets this — a valid, useful answer
/// rather than an error, which is the whole point of having a default.
pub const PAGE_DEFAULT: usize = 100;

/// The largest page any caller may ask for.
///
/// A request above this is REFUSED by the RPC layer, not clamped down to it.
/// A silent clamp makes a truncated answer indistinguishable from a complete
/// one, which is the confusion `-32003` exists to prevent for history and that
/// this limit prevents for breadth.
pub const PAGE_MAX: usize = 1000;

/// The furthest into a family a caller may page.
///
/// Offset paging costs work proportional to the offset — the skipped rows are
/// still walked. Capping the offset caps that work. Like [`PAGE_MAX`], a
/// request above it is refused rather than clamped.
pub const PAGE_OFFSET_MAX: usize = 1_000_000;

/// A half-open window `[offset, offset + limit)` over a reader's results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSpec {
    offset: usize,
    limit: usize,
}

impl PageSpec {
    /// A window with no validation. The RPC layer validates against
    /// [`PAGE_MAX`] and [`PAGE_OFFSET_MAX`] before constructing one; callers
    /// inside the node that already know their bound may build one directly.
    pub const fn new(offset: usize, limit: usize) -> Self {
        Self { offset, limit }
    }

    /// The first [`PAGE_DEFAULT`] rows — what a caller who asks for nothing
    /// gets.
    pub const fn first() -> Self {
        Self::new(0, PAGE_DEFAULT)
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Rows that must be produced before the page can be complete. Used to
    /// stop iteration for unfiltered readers.
    const fn horizon(&self) -> usize {
        self.offset.saturating_add(self.limit)
    }
}

impl Default for PageSpec {
    fn default() -> Self {
        Self::first()
    }
}

/// Walk `cf` in key order, decode each row, keep the ones `keep` accepts, and
/// return the `page` window of those.
///
/// Iteration stops the instant the page is full, so an unfiltered scan reads
/// `offset + limit` rows and no more. Read errors PROPAGATE — [`Database::iter`]
/// ends in `.filter_map(|r| r.ok())`, which would turn a mid-scan read failure
/// into a short page, and a short page is now a legitimate result that a caller
/// must be able to trust.
pub fn paged_scan<T, D, K>(
    db: &Database,
    cf: &str,
    page: PageSpec,
    decode: D,
    keep: K,
) -> Result<Vec<T>>
where
    D: Fn(&[u8]) -> Result<T>,
    K: Fn(&T) -> bool,
{
    let mut out = Vec::new();
    if page.limit == 0 {
        return Ok(out);
    }
    let horizon = page.horizon();
    let mut matched = 0usize;
    for entry in db.iter_checked_from(cf, None)? {
        let (_key, value) = entry?;
        let row = decode(&value)?;
        if !keep(&row) {
            continue;
        }
        if matched >= page.offset {
            out.push(row);
        }
        matched += 1;
        if matched >= horizon {
            break;
        }
    }
    Ok(out)
}

/// Resolve `ids` through `get`, keep the ones `keep` accepts, and return the
/// `page` window of those.
///
/// Point-reads stop the instant the page is full. The index vector itself is
/// decoded whole by the caller before this runs — that is one row, and bounding
/// it is a different problem from this one.
pub fn paged_resolve<I, T, G, K>(ids: &[I], page: PageSpec, get: G, keep: K) -> Result<Vec<T>>
where
    G: Fn(&I) -> Result<Option<T>>,
    K: Fn(&T) -> bool,
{
    let mut out = Vec::new();
    if page.limit == 0 {
        return Ok(out);
    }
    let horizon = page.horizon();
    let mut matched = 0usize;
    for id in ids {
        let Some(row) = get(id)? else {
            // A dangling index entry is skipped without consuming a page
            // position, so a stale index shortens nothing.
            continue;
        };
        if !keep(&row) {
            continue;
        }
        if matched >= page.offset {
            out.push(row);
        }
        matched += 1;
        if matched >= horizon {
            break;
        }
    }
    Ok(out)
}
