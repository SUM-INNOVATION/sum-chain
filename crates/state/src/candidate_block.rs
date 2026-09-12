//! The production entry point for executing a candidate block.
//!
//! [`sumchain_storage::candidate::CandidateExecution::verify_computed_root`]
//! compares two hashes a caller hands it. That is a mechanism, not a proof:
//! `verify_computed_root(h, h)` is well-typed and succeeds, and nothing in that
//! signature establishes that the "computed" side was produced by executing
//! anything. A caller who reads the header, passes its root as both operands,
//! and publishes has satisfied every type in the chain while verifying nothing.
//!
//! [`execute_candidate_block`] removes that shape. It accepts the **block** and
//! nothing else hash-shaped: it runs execution itself, takes the accumulator
//! from execution's own return value, and compares it against
//! `block.header.state_root` internally. The caller supplies neither operand and
//! cannot reach the comparison. Passing a header root as both sides is not
//! something the API permits a caller to express.
//!
//! # THIS IS SCAFFOLDING. IT IS NOT PUBLIC, AND MUST NOT BECOME PUBLIC YET.
//!
//! [`execute_candidate_block`] currently creates a candidate and then never
//! opens [`CandidateExecution::view`]. It calls the existing committed executor,
//! which writes through its own `Database` handles, and then verifies an overlay
//! that is empty because nothing was ever written to it. The verification is
//! real; the isolation is absent. A rejected candidate has already mutated
//! canonical state by the time its root is compared.
//!
//! Exporting this would be worse than not having it: callers would reasonably
//! read "candidate execution" as meaning a rejected block leaves no trace, and
//! it does not. It stays `pub(crate)` until every execution path takes an
//! `ExecutionView` — the migration tracked by the 36 remaining sites in
//! `tests/execution_boundary.rs`.
//!
//! What it does establish today is the SHAPE: the block goes in, the accumulator
//! comes out of execution, and the comparison happens here where no caller can
//! reach it.

use sumchain_primitives::{Block, Hash};
use sumchain_storage::candidate::VerifiedCandidate;

use crate::executor::BlockExecutor;
use crate::{Result, StateError};

/// Execute `block` as a candidate and verify its accumulator against its own
/// header.
///
/// The candidate's write-set ceiling is owned by `execute_block`, which creates
/// the candidate. It is currently a scaffold constant and must become the
/// versioned consensus parameter before publication.
///
/// Returns a [`VerifiedCandidate`], the only type from which canonical
/// publication can begin.
pub(crate) fn execute_candidate_block<'db>(
    executor: &'db BlockExecutor,
    block: &Block,
    parent_state_root: Hash,
    active_validator_pubkeys: &[[u8; 32]],
) -> Result<VerifiedCandidate<'db>> {
    // Execution produces the accumulator. It is never supplied by the caller,
    // and the caller never sees it before the comparison.
    let execution = executor.execute_block(block, parent_state_root, active_validator_pubkeys)?;

    // The expected root is read from the header inside `verify_for_block`, so
    // it is never a value this function could substitute.
    execution
        .candidate
        .verify_for_block(block, execution.computed_root)
        .map_err(|e| {
            StateError::InvalidOperation(format!(
                "candidate block {} at height {} rejected: {e}",
                block.hash(),
                block.height()
            ))
        })
}

/// The accumulator a block declares. For diagnostics only; it is NOT an input
/// to verification.
pub(crate) fn declared_root(block: &Block) -> Hash {
    block.header.state_root
}
