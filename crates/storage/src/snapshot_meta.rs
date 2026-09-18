//! The one row that says what history this node holds — reached by the names a
//! snapshot restore still calls it by.
//!
//! # What this module used to be, and why it is no longer that
//!
//! It used to own a second `META` row, `snapshot/imported_at`, with its own
//! encoding, its own decode failure and its own last-write-wins rule. The
//! journal owned a first one, `application_journal/undo_history_floor`, with a
//! different encoding path and a monotone rule. **Both recorded the same fact**:
//! the earliest height for which this node has usable generic undo history, and
//! therefore the floor below which it can neither unwind nor serve state.
//!
//! Two rows for one fact do not conflict — they diverge. A restore path that
//! writes one and forgets the other, or writes them in two steps and crashes
//! between, leaves a node whose journal boundary and whose advertised history
//! depth describe different databases, and neither module can detect it because
//! neither knows the other exists. A `git merge` cannot detect it either: the
//! two keys are in two files and merge cleanly while being wrong together.
//!
//! So the row is now exactly one:
//! [`crate::journal::UNDO_HISTORY_FLOOR_META_KEY`], written through
//! [`crate::journal::stage_undo_history_floor`] (inside the restore's own
//! batch) or [`crate::journal::record_undo_history_floor`] (standalone), and
//! read through [`crate::journal::undo_history_floor`]. There is no dual write,
//! no read fallback and no migration: neither prototype shipped, so
//! `snapshot/imported_at` is not a legacy format, it is a key this binary has
//! never written and does not read.
//!
//! # Why the old names still resolve
//!
//! The call sites are in `crates/state/src/snapshot.rs`, which belongs to
//! another track and is not edited from here. These three re-exports are the
//! bridge until it moves, and they are re-exports and not wrappers on purpose:
//! there is no second key, no second encoding and no second write rule behind
//! them, so a caller reaching the row by either name reaches the same row with
//! the same semantics. `crates/storage/tests/application_journal.rs`'s
//! `one_row_records_the_history_floor_under_every_name_that_reaches_it` pins
//! that, so the bridge cannot quietly become a second implementation again.
//!
//! The required follow-up, stated so it can be checked: `snapshot.rs` should
//! call `journal::stage_undo_history_floor` inside the batch that makes the
//! restored account rows durable, drop its `SNAPSHOT_IMPORT_META_KEY`
//! re-export, and read the floor through `journal::undo_history_floor`. At that
//! point this module has no callers and should be deleted outright.

/// The single `META` key recording this node's undo-history floor.
///
/// Identical to [`crate::journal::UNDO_HISTORY_FLOOR_META_KEY`] — the same
/// constant, not a copy of its bytes.
pub use crate::journal::UNDO_HISTORY_FLOOR_META_KEY as SNAPSHOT_IMPORT_META_KEY;

/// Record a restore at `height`. See
/// [`crate::journal::record_undo_history_floor`].
///
/// Monotone, where the row this replaced was last-write-wins. Monotone is the
/// correct rule for the fact being recorded: the floor is "the lowest height
/// this node can reverse", and no import ever LOWERS that — an import into a
/// database that already holds deeper history would be claiming undo records it
/// did not receive, because a snapshot cannot carry any.
pub use crate::journal::record_undo_history_floor as record_snapshot_import;

/// The recorded floor, or `None` if nothing ever set one. See
/// [`crate::journal::undo_history_floor`].
///
/// `None` is the PERMISSIVE answer — no restriction on history, no restriction
/// on reorg depth — and it is correct for a node that executed every block it
/// holds. That is exactly why an unreadable value must not resolve to it, and
/// does not: a malformed row is an error whose text says what follows from it.
pub use crate::journal::undo_history_floor as snapshot_import_height;
