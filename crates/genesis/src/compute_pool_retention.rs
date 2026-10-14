//! C-RETENTION (issue #129) parameter relations: a pure validator.
//!
//! The owner ratified two things for #129's parameters: they are **injected**
//! (never compiled in), and every combination is checked by **strict
//! relational validation** before it may be used. This module is that
//! validator, and nothing more. It holds no value, reads no genesis field,
//! reads no budget constant and is called by no execution path, so execution,
//! state roots and receipts are unchanged by it. Its callers are genesis
//! validation and the compute-pool activation check, both in
//! [`crate::compute_pool_retention_inputs`], which decides where each input
//! comes from.
//!
//! # Relations (owner decision packet 2026-09-29, §6)
//!
//! | # | relation | where |
//! |---|---|---|
//! | 1 | `output_availability_blocks >= 2 × CHALLENGE_INTERVAL_BLOCKS` | [`validate_retention_relations`] |
//! | 2 | `output_availability_blocks > finality_depth` | [`validate_retention_relations`] |
//! | 3 | `max_retention_updates_per_block <= ⌊B / t_recompute⌋`, `t_recompute > 0` | [`validate_retention_relations`] |
//! | 4 | `max_reverse_index_entries >= max_retention_files_per_job × (1 + E_max × (1 + R_max × C_ret))` | [`validate_retention_relations`] |
//! | 5 | `max_retention_files_per_job >= job_max_retention_files` per admitted job | `sumchain_state::compute_pool::validate_retention_within_cap` (existing) |
//!
//! Relation 1's floor is at least one complete proof-of-retrievability round
//! after coverage starts, allowing misalignment. In relation 3, `B` is the
//! per-block budget. The B0-FINAL rule gives 300 ms per block on the reference
//! host (10 % of block time), but it is taken here as an argument. `t_recompute`
//! is the measured p99 of one tracker recompute at the per-job file cap.
//! Relation 4 is stated in its sound form; see "Relation 4" below.
//!
//! # Relation 4
//!
//! A retention tracker occupies one reverse-index entry for its job, one file
//! entry per epoch it is indexed under, and one archive entry per archive in
//! its dependency set ([`retention_tracker_entry_bound`]). The ratified text,
//! `max_retention_files_per_job × (2 + R_max)`, counts one epoch and `R_max`
//! archives per file. That holds only for a file whose chunks all sit on the
//! same `R_max` archives, such as a one-chunk file: rendezvous assignment
//! places each of a file's `C` chunks on its own top-`R` archives, so one epoch
//! can involve up to `R × C` distinct archives, and under the union reading
//! of D-E a tracker is indexed under every assignment epoch. The ratified form
//! is the case `C_ret = 1, E_max = 1` of the sound form.
//!
//! The bound per tracker rests on facts the chain enforces, and on three
//! invariants the retention path must enforce before activation:
//!
//! * an archive counts for a file in an epoch only if `AcceptAssignmentV2`
//!   accepted its bit for a chunk assigned to it in that epoch (enforced);
//! * the assignment places each chunk on at most `assignment_replication_factor`
//!   archives (enforced), and **`R_max` must bound that factor for every epoch
//!   a tracked file is indexed under** (to enforce);
//! * **`C_ret` must bound the chunk count of every file admitted to
//!   retention** (to enforce; `max_chunk_count_per_file`, 1,048,576 by
//!   default, is enforced but would size the index at over three million
//!   entries per file);
//! * **`E_max` must bound the epochs a tracker is indexed under** (to enforce):
//!   1 under the latest-assignment reading of D-E; under the union reading,
//!   1 plus a reassignment limit enforced for tracked files.
//!
//! The snapshot size `N` would tighten the archive count to `min(N, R × C)`,
//! but nothing bounds `N`, so it is not used. With the three invariants and
//! relation 5, no admitted job can need more entries than this relation
//! provides; the state kernel refuses any tracker that breaks them.
//!
//! # Open, and deliberately not decided here
//!
//! * **Production values.** None of the inputs has a value in this
//!   repository. `output_availability_blocks` is an owner duration choice.
//! * **`t_recompute` and the per-block cap.** `max_retention_updates_per_block`
//!   comes from a measurement run that has not happened.
//! * **`R_max`.** The ratified text names it without defining it, so it is an
//!   explicit argument. Whether it means the chain's
//!   `assignment_replication_factor`, a separate cap, or something else is an
//!   open owner decision.
//! * **Where the values live.** Four inputs are `ComputePoolParamsV1` fields
//!   (issue #215) and `finality_depth` is `ChainParams::finality_depth`. The
//!   remaining three have no source; see
//!   [`crate::compute_pool_retention_inputs`].
//!
//! # Zero
//!
//! Zero is handled only as the relations imply. `t_recompute = 0` is refused
//! because relation 3 divides by it. Any other zero is accepted when the
//! relations hold.

use sumchain_primitives::CHALLENGE_INTERVAL_BLOCKS;
use thiserror::Error;

/// Every input to relations 1–4, injected by the caller. No field has a
/// default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionRelationInputs {
    /// Blocks a tracker must hold full-R coverage before `RetentionSatisfied`.
    pub output_availability_blocks: u64,
    /// The chain's finality depth, in blocks.
    pub finality_depth: u64,
    /// Bound on Dirty trackers recomputed per block.
    pub max_retention_updates_per_block: u64,
    /// Per-block budget `B`, in nanoseconds (B0-FINAL: 300 ms on the
    /// reference host).
    pub per_block_budget_ns: u64,
    /// Measured p99 of one tracker recompute, in nanoseconds.
    pub t_recompute_p99_ns: u64,
    /// Per-job retention-file cap.
    pub max_retention_files_per_job: u64,
    /// Reverse-index entry cap.
    pub max_reverse_index_entries: u64,
    /// `R_max`: the bound on the assignment replication factor over a
    /// tracked file's indexed epochs (module docs, "Relation 4").
    pub r_max: u64,
    /// `C_ret`: the bound on the chunk count of a file admitted to retention.
    pub retention_chunk_cap: u64,
    /// `E_max`: the bound on the epochs one tracker is indexed under.
    pub max_indexed_epochs: u64,
}

/// The reverse-index entries one retention tracker can occupy:
/// `1 + epochs × (1 + r × chunks)`.
///
/// One job entry; for each epoch it is indexed under, one file entry and at
/// most `r × chunks` archive entries (an archive counts only for chunks
/// assigned to it, and each chunk is assigned to at most `r` archives). `None`
/// if that overflows `u64`.
pub fn retention_tracker_entry_bound(r: u64, chunks: u64, epochs: u64) -> Option<u64> {
    r.checked_mul(chunks)?
        .checked_add(1)?
        .checked_mul(epochs)?
        .checked_add(1)
}

/// A breached retention relation. Each variant carries the values that broke
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RetentionRelationError {
    /// Relation 1.
    #[error(
        "output_availability_blocks = {output_availability_blocks} is below \
         2 x CHALLENGE_INTERVAL_BLOCKS = {floor}"
    )]
    OutputAvailabilityBelowPorRound {
        output_availability_blocks: u64,
        floor: u64,
    },
    /// Relation 2.
    #[error(
        "output_availability_blocks = {output_availability_blocks} is not greater than \
         finality_depth = {finality_depth}"
    )]
    OutputAvailabilityNotAboveFinality {
        output_availability_blocks: u64,
        finality_depth: u64,
    },
    /// Relation 3 cannot be evaluated: it divides by `t_recompute`.
    #[error("t_recompute_p99_ns = 0; relation 3 requires t_recompute > 0")]
    RecomputeTimeZero,
    /// Relation 3.
    #[error(
        "max_retention_updates_per_block = {max_retention_updates_per_block} exceeds \
         floor(B {per_block_budget_ns} ns / t_recompute {t_recompute_p99_ns} ns) = {bound}"
    )]
    UpdatesPerBlockOverBudget {
        max_retention_updates_per_block: u64,
        per_block_budget_ns: u64,
        t_recompute_p99_ns: u64,
        bound: u64,
    },
    /// Relation 4's right-hand side does not fit in `u64`. It is refused,
    /// because no `u64` cap can satisfy it.
    #[error(
        "max_retention_files_per_job {max_retention_files_per_job} x (1 + E_max \
         {max_indexed_epochs} x (1 + R_max {r_max} x C_ret {retention_chunk_cap})) overflows u64"
    )]
    ReverseIndexRequirementOverflow {
        max_retention_files_per_job: u64,
        r_max: u64,
        retention_chunk_cap: u64,
        max_indexed_epochs: u64,
    },
    /// Relation 4.
    #[error(
        "max_reverse_index_entries = {max_reverse_index_entries} is below \
         max_retention_files_per_job {max_retention_files_per_job} x (1 + E_max \
         {max_indexed_epochs} x (1 + R_max {r_max} x C_ret {retention_chunk_cap})) = {required}"
    )]
    ReverseIndexBelowRequirement {
        max_reverse_index_entries: u64,
        max_retention_files_per_job: u64,
        r_max: u64,
        retention_chunk_cap: u64,
        max_indexed_epochs: u64,
        required: u64,
    },
}

/// Check relations 1 and 2 only: the two relations whose inputs a genesis
/// that declares `ComputePoolParamsV1` always has (`output_availability_blocks`
/// from the parameters, `finality_depth` from `ChainParams`).
/// [`validate_retention_relations`] runs this first, so both report the same
/// error for the same breach.
pub fn validate_output_availability(
    output_availability_blocks: u64,
    finality_depth: u64,
) -> Result<(), RetentionRelationError> {
    use RetentionRelationError as E;

    // 1. The floor is a product of compiled constants. Saturating keeps it
    //    total, and saturation could only make the check stricter.
    let floor = CHALLENGE_INTERVAL_BLOCKS.saturating_mul(2);
    if output_availability_blocks < floor {
        return Err(E::OutputAvailabilityBelowPorRound {
            output_availability_blocks,
            floor,
        });
    }

    // 2.
    if output_availability_blocks <= finality_depth {
        return Err(E::OutputAvailabilityNotAboveFinality {
            output_availability_blocks,
            finality_depth,
        });
    }
    Ok(())
}

/// Check relations 1–4 in table order and return the first breach.
///
/// Relation 5 is per job and is enforced at job creation by
/// `sumchain_state::compute_pool::validate_retention_within_cap`, with
/// `max_retention_files_per_job` as its cap. All arithmetic is checked.
pub fn validate_retention_relations(
    p: &RetentionRelationInputs,
) -> Result<(), RetentionRelationError> {
    use RetentionRelationError as E;

    // 1 and 2.
    validate_output_availability(p.output_availability_blocks, p.finality_depth)?;

    // 3.
    let bound = p
        .per_block_budget_ns
        .checked_div(p.t_recompute_p99_ns)
        .ok_or(E::RecomputeTimeZero)?;
    if p.max_retention_updates_per_block > bound {
        return Err(E::UpdatesPerBlockOverBudget {
            max_retention_updates_per_block: p.max_retention_updates_per_block,
            per_block_budget_ns: p.per_block_budget_ns,
            t_recompute_p99_ns: p.t_recompute_p99_ns,
            bound,
        });
    }

    // 4.
    let required = retention_tracker_entry_bound(p.r_max, p.retention_chunk_cap, p.max_indexed_epochs)
        .and_then(|per_file| p.max_retention_files_per_job.checked_mul(per_file))
        .ok_or(E::ReverseIndexRequirementOverflow {
            max_retention_files_per_job: p.max_retention_files_per_job,
            r_max: p.r_max,
            retention_chunk_cap: p.retention_chunk_cap,
            max_indexed_epochs: p.max_indexed_epochs,
        })?;
    if p.max_reverse_index_entries < required {
        return Err(E::ReverseIndexBelowRequirement {
            max_reverse_index_entries: p.max_reverse_index_entries,
            max_retention_files_per_job: p.max_retention_files_per_job,
            r_max: p.r_max,
            retention_chunk_cap: p.retention_chunk_cap,
            max_indexed_epochs: p.max_indexed_epochs,
            required,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use RetentionRelationError as E;

    /// TEST-ONLY inputs that sit exactly on every relation's boundary. They
    /// are not proposed values.
    fn on_boundary() -> RetentionRelationInputs {
        RetentionRelationInputs {
            output_availability_blocks: 2 * CHALLENGE_INTERVAL_BLOCKS,
            finality_depth: 2 * CHALLENGE_INTERVAL_BLOCKS - 1,
            max_retention_updates_per_block: 300,
            per_block_budget_ns: 300_000_000,
            t_recompute_p99_ns: 1_000_000,
            max_retention_files_per_job: 10,
            max_reverse_index_entries: 50,
            r_max: 3,
            retention_chunk_cap: 1,
            max_indexed_epochs: 1,
        }
    }

    #[test]
    fn all_relations_on_their_boundary_pass() {
        assert_eq!(validate_retention_relations(&on_boundary()), Ok(()));
    }

    #[test]
    fn relation_1_por_round_floor() {
        let p = RetentionRelationInputs {
            output_availability_blocks: 2 * CHALLENGE_INTERVAL_BLOCKS - 1,
            finality_depth: 0,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&p),
            Err(E::OutputAvailabilityBelowPorRound {
                output_availability_blocks: 199,
                floor: 200,
            })
        );
        let p = RetentionRelationInputs {
            output_availability_blocks: 0,
            finality_depth: 0,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&p),
            Err(E::OutputAvailabilityBelowPorRound { .. })
        ));
    }

    #[test]
    fn relation_2_strictly_above_finality_depth() {
        let at = RetentionRelationInputs {
            output_availability_blocks: 500,
            finality_depth: 500,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&at),
            Err(E::OutputAvailabilityNotAboveFinality {
                output_availability_blocks: 500,
                finality_depth: 500,
            })
        );
        let above = RetentionRelationInputs {
            output_availability_blocks: 501,
            ..at
        };
        assert_eq!(validate_retention_relations(&above), Ok(()));
        let max = RetentionRelationInputs {
            output_availability_blocks: u64::MAX,
            finality_depth: u64::MAX,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&max),
            Err(E::OutputAvailabilityNotAboveFinality { .. })
        ));
    }

    #[test]
    fn relation_3_budget_bound() {
        let over = RetentionRelationInputs {
            max_retention_updates_per_block: 301,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&over),
            Err(E::UpdatesPerBlockOverBudget {
                max_retention_updates_per_block: 301,
                per_block_budget_ns: 300_000_000,
                t_recompute_p99_ns: 1_000_000,
                bound: 300,
            })
        );
        // The floor: 300_000_000 / 999_999 = 300 (300.0003…).
        let floored = RetentionRelationInputs {
            t_recompute_p99_ns: 999_999,
            max_retention_updates_per_block: 301,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&floored),
            Err(E::UpdatesPerBlockOverBudget { bound: 300, .. })
        ));
        // A recompute slower than the whole budget leaves a bound of zero.
        // Zero updates satisfies it, and one does not.
        let slow = RetentionRelationInputs {
            t_recompute_p99_ns: 300_000_001,
            max_retention_updates_per_block: 1,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&slow),
            Err(E::UpdatesPerBlockOverBudget { bound: 0, .. })
        ));
        let none = RetentionRelationInputs {
            max_retention_updates_per_block: 0,
            ..slow
        };
        assert_eq!(validate_retention_relations(&none), Ok(()));
    }

    #[test]
    fn relation_3_requires_positive_t_recompute() {
        let zero = RetentionRelationInputs {
            t_recompute_p99_ns: 0,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&zero),
            Err(E::RecomputeTimeZero)
        );
        // Refused even when the cap is also zero, since nothing was measured.
        let zero_cap = RetentionRelationInputs {
            max_retention_updates_per_block: 0,
            ..zero
        };
        assert_eq!(
            validate_retention_relations(&zero_cap),
            Err(E::RecomputeTimeZero)
        );
    }

    #[test]
    fn relation_4_reverse_index_capacity() {
        let short = RetentionRelationInputs {
            max_reverse_index_entries: 49,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&short),
            Err(E::ReverseIndexBelowRequirement {
                max_reverse_index_entries: 49,
                max_retention_files_per_job: 10,
                r_max: 3,
                retention_chunk_cap: 1,
                max_indexed_epochs: 1,
                required: 50,
            })
        );
        // R_max is an explicit input: raising it raises the requirement.
        let r5 = RetentionRelationInputs {
            r_max: 5,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&r5),
            Err(E::ReverseIndexBelowRequirement { required: 70, .. })
        ));
        assert_eq!(
            validate_retention_relations(&RetentionRelationInputs {
                max_reverse_index_entries: 70,
                ..r5
            }),
            Ok(())
        );
    }

    #[test]
    fn relation_4_large_r_max_and_overflow_are_refused() {
        // 1 + R_max x C_ret overflows.
        let r_overflow = RetentionRelationInputs {
            r_max: u64::MAX,
            max_reverse_index_entries: u64::MAX,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&r_overflow),
            Err(E::ReverseIndexRequirementOverflow {
                max_retention_files_per_job: 10,
                r_max: u64::MAX,
                retention_chunk_cap: 1,
                max_indexed_epochs: 1,
            })
        );
        // The product overflows.
        let product = RetentionRelationInputs {
            max_retention_files_per_job: u64::MAX / 2,
            r_max: 1,
            max_reverse_index_entries: u64::MAX,
            ..on_boundary()
        };
        assert!(matches!(
            validate_retention_relations(&product),
            Err(E::ReverseIndexRequirementOverflow { .. })
        ));
        // A large R_max that still fits is checked normally.
        let big = RetentionRelationInputs {
            max_retention_files_per_job: 1,
            r_max: u64::MAX - 2,
            max_reverse_index_entries: u64::MAX,
            ..on_boundary()
        };
        assert_eq!(validate_retention_relations(&big), Ok(()));
        let big_short = RetentionRelationInputs {
            max_reverse_index_entries: u64::MAX - 1,
            ..big
        };
        assert!(matches!(
            validate_retention_relations(&big_short),
            Err(E::ReverseIndexBelowRequirement { required: u64::MAX, .. })
        ));
    }

    /// Relation 4 counts every chunk of a file and every epoch its tracker is
    /// indexed under; the ratified `2 + R_max` per file is its one-chunk,
    /// one-epoch case.
    #[test]
    fn relation_4_counts_every_chunk_and_every_indexed_epoch() {
        // One chunk, one epoch: 2 + R_max.
        assert_eq!(retention_tracker_entry_bound(3, 1, 1), Some(5));
        // 1,024 chunks at R = 3, one epoch (latest-assignment reading).
        assert_eq!(retention_tracker_entry_bound(3, 1_024, 1), Some(3_074));
        // The same file indexed under two epochs (union reading, one
        // reassignment).
        assert_eq!(retention_tracker_entry_bound(3, 1_024, 2), Some(6_147));
        // One file at the chain's default max_chunk_count_per_file.
        assert_eq!(retention_tracker_entry_bound(3, 1_048_576, 1), Some(3_145_730));
        assert_eq!(retention_tracker_entry_bound(u64::MAX, 2, 1), None);

        // The ratified sizing for 10 files at R_max = 3, 50 entries, holds for
        // one-chunk files and is refused once files may have 1,024 chunks.
        assert_eq!(validate_retention_relations(&on_boundary()), Ok(()));
        let multi_chunk = RetentionRelationInputs {
            retention_chunk_cap: 1_024,
            ..on_boundary()
        };
        assert_eq!(
            validate_retention_relations(&multi_chunk),
            Err(E::ReverseIndexBelowRequirement {
                max_reverse_index_entries: 50,
                max_retention_files_per_job: 10,
                r_max: 3,
                retention_chunk_cap: 1_024,
                max_indexed_epochs: 1,
                required: 30_740,
            })
        );
        assert_eq!(
            validate_retention_relations(&RetentionRelationInputs {
                max_reverse_index_entries: 30_740,
                ..multi_chunk
            }),
            Ok(())
        );
    }

    #[test]
    fn zero_files_need_no_reverse_index() {
        // Follows from relation 4 alone. No extra rule refuses zero caps.
        let p = RetentionRelationInputs {
            max_retention_files_per_job: 0,
            max_reverse_index_entries: 0,
            ..on_boundary()
        };
        assert_eq!(validate_retention_relations(&p), Ok(()));
    }

    #[test]
    fn errors_name_their_values() {
        let msg = E::UpdatesPerBlockOverBudget {
            max_retention_updates_per_block: 301,
            per_block_budget_ns: 300_000_000,
            t_recompute_p99_ns: 1_000_000,
            bound: 300,
        }
        .to_string();
        for needle in ["= 301", "300000000 ns", "1000000 ns", "= 300"] {
            assert!(msg.contains(needle), "{needle:?} not in {msg:?}");
        }
    }
}
