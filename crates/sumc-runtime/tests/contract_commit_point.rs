//! The runtime cannot write to the database during execution.
//!
//! Contracts are the one subsystem the closure ledger cannot police. Its
//! manifest keys writes to a caller in `crates/state`, and contract rows are
//! written from `sumc-runtime`, which `classify_all` marks `Library` by
//! location — so those writes were never in the ledger and their removal cannot
//! show up as rows leaving it. The two contract arms carried an explicit
//! exception saying exactly that.
//!
//! What can be checked is the seam. `ContractStorage` reaches the database
//! only through `ContractStorageBackend`, and after the migration it calls only
//! the READ half of that trait. This file pins that, at the source level, the
//! way the raw-syntax ratchet next door pins `db.put` in `crates/state/src`.
//!
//! It is a source check and carries the same honesty: it proves the calls named
//! here are absent, not that no write is possible by some shape it does not
//! know. What makes it worth having is that the shapes it names are the only
//! ones that existed.

use std::path::Path;

/// The backend methods that reach the database to WRITE.
const WRITE_SURFACE: &[&str] = &[
    "write",
    "delete",
    "commit",
    "store_code",
    "delete_code",
    "store_metadata",
    "delete_metadata",
];

/// The backend methods that only read.
const READ_SURFACE: &[&str] = &["read", "exists", "get_code", "get_metadata"];

fn storage_source() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/storage.rs");
    std::fs::read_to_string(p).expect("read storage.rs")
}

/// Strip line comments so prose naming a forbidden call is not mistaken for one.
///
/// The doc comment on `commit` describes the `backend.commit(&ops)` this
/// migration removed. Reading comments as code would make that sentence fail
/// the guard, and deleting the sentence to satisfy a checker would remove the
/// record of why the call is gone.
fn code_only(src: &str) -> String {
    src.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `ContractStorage` never calls the backend's write surface.
///
/// This is what the contract migration amounts to: the buffer stayed, the
/// journal stayed, and the path from that buffer to RocksDB was cut. The
/// operations are handed to the caller, which stages them into the block's
/// candidate.
#[test]
fn contract_storage_never_writes_through_the_backend() {
    let code = code_only(&storage_source());
    let mut found = Vec::new();
    for m in WRITE_SURFACE {
        let needle = format!("backend.{m}(");
        if code.contains(&needle) {
            found.push(needle);
        }
    }
    assert!(
        found.is_empty(),
        "`ContractStorage` reaches the database to write: {found:?}. During block \
         execution a contract write must be queued for the caller to stage into \
         the candidate, not applied. If this is a new backend method that only \
         reads, add it to READ_SURFACE; if it writes, it does not belong here."
    );
}

/// ...and it still calls the read surface, so the check above is not vacuous.
///
/// A guard that passes because the backend is unused entirely would say nothing.
#[test]
fn contract_storage_still_reads_through_the_backend() {
    let code = code_only(&storage_source());
    let reads: Vec<&&str> = READ_SURFACE
        .iter()
        .filter(|m| code.contains(&format!("backend.{m}(")))
        .collect();
    assert!(
        !reads.is_empty(),
        "`ContractStorage` no longer reads through the backend either, so the \
         write-surface check above is satisfied by absence rather than by the \
         migration. One of these must remain: {READ_SURFACE:?}"
    );
}

/// The guard detects a reintroduced write.
#[test]
fn the_guard_detects_a_reintroduced_write() {
    let fixture = r#"
        impl ContractStorage {
            pub fn commit(&self) -> Result<()> {
                self.backend.commit(&ops)?;
                Ok(())
            }
        }
    "#;
    let code = code_only(fixture);
    assert!(
        WRITE_SURFACE
            .iter()
            .any(|m| code.contains(&format!("backend.{m}("))),
        "the scan must find a write it is given"
    );
}

/// A forbidden call named in PROSE is not a call.
#[test]
fn a_write_named_in_a_comment_is_not_a_write() {
    let fixture = r#"
        /// This used to end in `backend.commit(&ops)` — a WriteBatch against
        /// RocksDB, executed while the block was still being built.
        pub fn commit(&self) -> Result<()> { Ok(()) }
    "#;
    let code = code_only(fixture);
    assert!(
        !WRITE_SURFACE
            .iter()
            .any(|m| code.contains(&format!("backend.{m}("))),
        "a comment describing the removed call must not read as the call"
    );
}
