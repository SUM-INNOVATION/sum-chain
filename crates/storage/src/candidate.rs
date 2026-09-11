//! Candidate execution as a typestate: execute, verify, then — and only then —
//! publish.
//!
//! The overlay makes a candidate branch abandonable. It does not, by itself,
//! make verification mandatory: anything holding the overlay can convert it into
//! a batch whenever it likes, including before comparing the computed state root
//! against the header's. That is the failure this module removes.
//!
//! ```text
//! CandidateExecution  --view()-->  ExecutionView   (execute here)
//!         |
//!      verify(computed, expected)
//!         |
//!         +-- Err  -> the candidate is CONSUMED and dropped: rollback
//!         |
//!         +-- Ok   -> VerifiedCandidate --into_batch()--> WriteBatch
//! ```
//!
//! [`ApplicationOverlay::into_batch`] is crate-private, so [`VerifiedCandidate`]
//! is the only way to reach a publishable batch from outside this crate. A
//! caller cannot publish an unverified candidate because there is no expression
//! that produces one — the ordering is carried by the types, not by a comment
//! asking callers to remember.
//!
//! [`CandidateExecution::verify`] takes `self` by value. A mismatch therefore
//! does not merely refuse publication: it destroys the candidate, and since the
//! overlay never wrote anything, that is a complete rollback with nothing to
//! undo.
//!
//! Execution helpers receive `&mut ExecutionView` and never the candidate, so
//! nothing reachable from execution can verify or publish.

use sumchain_primitives::Hash;

use crate::db::{Database, WriteBatch};
use crate::exec_view::ExecutionView;
use crate::overlay::ApplicationOverlay;
use crate::{Result, StorageError};

/// A block being executed against buffered state. Nothing here has touched the
/// database.
pub struct CandidateExecution<'db> {
    overlay: ApplicationOverlay<'db>,
}

/// A candidate whose computed state root matched the expected one. The only
/// type that can produce a publishable batch.
pub struct VerifiedCandidate<'db> {
    overlay: ApplicationOverlay<'db>,
    root: Hash,
}

impl<'db> CandidateExecution<'db> {
    /// Begin executing a candidate against `db`, buffering up to `limit`
    /// logical write-set bytes.
    ///
    /// `limit` is explicit because it is a versioned consensus parameter derived
    /// from measured write sets — a ceiling that can refuse a write participates
    /// in deciding whether a block is applicable. It is not defaulted here.
    pub fn new(db: &'db Database, limit: u64) -> Self {
        Self {
            overlay: ApplicationOverlay::new(db, limit),
        }
    }

    /// The handle execution reads and writes through.
    pub fn view(&mut self) -> ExecutionView<'_, 'db> {
        ExecutionView::new(&mut self.overlay)
    }

    /// Logical write-set bytes buffered so far.
    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.overlay.is_empty()
    }

    /// Compare the computed state root against the expected one.
    ///
    /// Consumes the candidate either way. On mismatch the overlay is dropped
    /// with it, and because the overlay never wrote anything, the canonical
    /// database is already byte-identical — the rollback is the absence of a
    /// commit, not an undo.
    pub fn verify(self, computed: Hash, expected: Hash) -> Result<VerifiedCandidate<'db>> {
        if computed != expected {
            return Err(StorageError::InvalidData(format!(
                "candidate state root mismatch: computed {computed}, header declares \
                 {expected}; discarding the candidate without publishing"
            )));
        }
        Ok(VerifiedCandidate {
            overlay: self.overlay,
            root: computed,
        })
    }
}

impl<'db> VerifiedCandidate<'db> {
    /// The verified root, for the caller to record alongside the published state.
    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn logical_bytes(&self) -> u64 {
        self.overlay.logical_bytes()
    }

    /// Everything this candidate wrote, as one atomic batch.
    ///
    /// The caller adds canonical-head and accumulator metadata to this same
    /// batch before committing, so state rows, journals, head and accumulator
    /// become visible together or not at all.
    pub fn into_batch(self) -> Result<WriteBatch<'db>> {
        self.overlay.into_batch()
    }
}
