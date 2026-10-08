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
//! | 4 | `max_reverse_index_entries >= max_retention_files_per_job × (2 + R_max)` | [`validate_retention_relations`] |
//! | 5 | `max_retention_files_per_job >= job_max_retention_files` per admitted job | `sumchain_state::compute_pool::validate_retention_within_cap` (existing) |
//!
//! Relation 1's floor is at least one complete proof-of-retrievability round
//! after coverage starts, allowing misalignment. In relation 3, `B` is the
//! per-block budget. The B0-FINAL rule gives 300 ms per block on the reference
//! host (10 % of block time), but it is taken here as an argument. `t_recompute`
//! is the measured p99 of one tracker recompute at the per-job file cap.
//! In relation 4, the `2` counts one job entry and one file entry, and
//! `R_max` counts one archive entry per replica.
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
    /// `R_max`. Its definition is an open owner decision (module docs).
    pub r_max: u64,
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
        "max_retention_files_per_job {max_retention_files_per_job} x (2 + R_max {r_max}) \
         overflows u64"
    )]
    ReverseIndexRequirementOverflow {
        max_retention_files_per_job: u64,
        r_max: u64,
    },
    /// Relation 4.
    #[error(
        "max_reverse_index_entries = {max_reverse_index_entries} is below \
         max_retention_files_per_job {max_retention_files_per_job} x (2 + R_max {r_max}) \
         = {required}"
    )]
    ReverseIndexBelowRequirement {
        max_reverse_index_entries: u64,
        max_retention_files_per_job: u64,
        r_max: u64,
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
    let required = p
        .r_max
        .checked_add(2)
        .and_then(|per_file| p.max_retention_files_per_job.checked_mul(per_file))
        .ok_or(E::ReverseIndexRequirementOverflow {
            max_retention_files_per_job: p.max_retention_files_per_job,
            r_max: p.r_max,
        })?;
    if p.max_reverse_index_entries < required {
        return Err(E::ReverseIndexBelowRequirement {
            max_reverse_index_entries: p.max_reverse_index_entries,
            max_retention_files_per_job: p.max_retention_files_per_job,
            r_max: p.r_max,
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
        // 2 + R_max overflows.
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
