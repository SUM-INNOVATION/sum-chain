//! What a state-snapshot import did to this database.
//!
//! One `META` row, read and written through typed accessors rather than by
//! hand. It sits beside [`crate::journal::FORMAT_HIGH_WATER_META_KEY`] and
//! exists for the same reason: the consequences of something that happened once,
//! outside block execution, have to survive the process that did it.
//!
//! A node seeded from a state snapshot holds canonical state at some height and
//! **no undo records at or below it**, and cannot reconstruct historical state
//! below it either — the blocks are not there, and if they were, replaying them
//! is the sync the import avoided. Both facts bound what the node may advertise
//! and what it may serve. Held only in the value an import returned, they would
//! be lost at the next restart, and the node would go back to claiming a reorg
//! horizon over blocks it has no records for.
//!
//! # Why this is a module and not a `db.put` at the call site
//!
//! The write is not block execution — there is no candidate and no block to
//! abandon — so it does not belong on an `ExecutionView`. What it does belong in
//! is the storage layer, with its key, its encoding and its decode failure in
//! one place. A hand-rolled `db.put(cf::META, b"…", &h.to_be_bytes())` at the
//! caller spreads the format across two crates and leaves the "what if it is
//! unreadable" question to whoever reads it next.

use crate::db::cf;
use crate::db::Database;
use crate::{Result, StorageError};
use sumchain_primitives::BlockHeight;

/// `META` key holding the height a state snapshot was imported at.
///
/// Namespaced like the journal's format watermark, so the `META` family stays
/// readable as a set of named facts rather than a bag of keys.
pub const SNAPSHOT_IMPORT_META_KEY: &[u8] = b"snapshot/imported_at";

/// Record that a snapshot was imported at `height`.
///
/// Idempotent, and last-write-wins: a database imported into twice is described
/// by the most recent import, which is the one that determines what state it now
/// holds.
pub fn record_snapshot_import(db: &Database, height: BlockHeight) -> Result<()> {
    db.put(cf::META, SNAPSHOT_IMPORT_META_KEY, &height.to_be_bytes())
}

/// The height a snapshot was imported at, or `None` if none ever was.
///
/// `None` is the PERMISSIVE answer — no restriction on history, no restriction
/// on reorg depth — and it is correct for a node that executed every block it
/// holds. That is exactly why an unreadable value must not resolve to it: a
/// database that WAS imported into, whose record cannot be decoded, would
/// otherwise start claiming history it does not have. So a malformed value is an
/// error, and the error says what follows from it.
pub fn snapshot_import_height(db: &Database) -> Result<Option<BlockHeight>> {
    let Some(raw) = db.get(cf::META, SNAPSHOT_IMPORT_META_KEY)? else {
        return Ok(None);
    };
    let bytes: [u8; 8] = raw.as_slice().try_into().map_err(|_| {
        StorageError::InvalidData(format!(
            "the recorded snapshot import height is {} bytes, not 8; this node cannot \
             establish what history it holds and must not serve any",
            raw.len()
        ))
    })?;
    Ok(Some(u64::from_be_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (Database, TempDir) {
        let dir = TempDir::new().unwrap();
        let db = Database::open_default(dir.path()).unwrap();
        (db, dir)
    }

    #[test]
    fn an_untouched_database_reports_no_import() {
        let (db, _dir) = db();
        assert_eq!(snapshot_import_height(&db).unwrap(), None);
    }

    #[test]
    fn the_height_round_trips_and_the_last_import_wins() {
        let (db, _dir) = db();
        record_snapshot_import(&db, 496_721).unwrap();
        assert_eq!(snapshot_import_height(&db).unwrap(), Some(496_721));

        // A database imported into twice is described by the most recent import:
        // that is the one that decided what state it now holds.
        record_snapshot_import(&db, 500_000).unwrap();
        assert_eq!(snapshot_import_height(&db).unwrap(), Some(500_000));
    }

    /// A malformed record is an error, not an absence.
    ///
    /// Absence means "no restriction", which is the permissive answer. Resolving
    /// a corrupt value to it would let an imported node serve history it does
    /// not have — the exact failure this row exists to prevent.
    #[test]
    fn a_malformed_record_does_not_read_as_never_imported() {
        let (db, _dir) = db();
        for bad in [vec![], vec![0u8; 3], vec![0u8; 9]] {
            db.put(cf::META, SNAPSHOT_IMPORT_META_KEY, &bad).unwrap();
            let err = snapshot_import_height(&db)
                .expect_err("a malformed height must not resolve to `None`")
                .to_string();
            assert!(
                err.contains("must not serve any"),
                "the error must say what follows from it: {err}"
            );
        }
    }
}
