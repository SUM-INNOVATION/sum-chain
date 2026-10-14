//! Where the #129 retention-relation inputs come from, and when each
//! relation is checked.
//!
//! [`crate::compute_pool_retention`] checks the relations over ten injected
//! inputs. This module supplies them from the chain's declared parameters and
//! is called by [`crate::ChainParams::validate`], the path every loaded
//! genesis goes through. Nothing here runs during block execution, so state
//! roots and receipts are unchanged.
//!
//! # Sources
//!
//! | input | source | committed by the consensus configuration as |
//! |---|---|---|
//! | `output_availability_blocks` | `ComputePoolParamsV1` | `0x0720` (schema 2) |
//! | `max_retention_updates_per_block` | `ComputePoolParamsV1` | `0x0720` |
//! | `max_retention_files_per_job` | `ComputePoolParamsV1` | `0x0720` |
//! | `max_reverse_index_entries` | `ComputePoolParamsV1` | `0x0720` |
//! | `finality_depth` | `ChainParams::finality_depth` | `0x0103` |
//! | `per_block_budget_ns` (`B`) | **none** | n/a |
//! | `t_recompute_p99_ns` | **none** | n/a |
//! | `r_max` | **none** | n/a |
//! | `retention_chunk_cap` | **none** | n/a |
//! | `max_indexed_epochs` | **none** | n/a |
//!
//! `finality_depth` is the depth the PoA engine finalizes at. The BFT engine
//! reports a depth of 0, so relation 2 checked against `ChainParams` is never
//! weaker than against the engine.
//!
//! The five inputs without a source are [`RetentionInput`]s. Their state
//! today is [`UnsourcedRetentionInputs::undefined`], and that is what
//! `ChainParams::validate` passes. No value is supplied for any of them.
//!
//! * `B`: the ratified text binds it to the B0-FINAL per-block budget rule
//!   (10 % of block time, 300 ms on the reference host). The closest constant
//!   in code, `b0::consts::VALIDATOR_AGGREGATE_VERIFY_BUDGET_NS_PER_BLOCK`, is
//!   the aggregate proof-verification budget, and the constants census
//!   classifies it as not committed with no reader. Reading it here would make
//!   it a genesis-validation input without a commitment, so it is not read.
//! * `t_recompute_p99_ns`: a measured p99; the measurement has not been run.
//! * `r_max`: named by the ratified text but not defined. Relation 4 needs it
//!   to bound the assignment replication factor over a tracked file's indexed
//!   epochs ([`crate::compute_pool_retention`], "Relation 4").
//! * `retention_chunk_cap`: no bound on the chunk count of a file admitted to
//!   retention has been chosen. `max_chunk_count_per_file` is enforced, but at
//!   its default it would size the reverse index at over three million entries
//!   per file.
//! * `max_indexed_epochs`: depends on D-E. It is 1 under the latest-assignment
//!   reading; under the union reading it needs a reassignment limit enforced
//!   for tracked files, which does not exist.
//!
//! # When each relation is checked
//!
//! * Parameters absent: nothing is checked, and a set
//!   `compute_pool_enabled_from_height` is refused as before.
//! * Parameters declared, gate unset (dormant): relations 1 and 2 are checked
//!   at genesis validation ([`validate_declared`]). Relations 3 and 4 cannot be
//!   checked and do not refuse a dormant declaration.
//! * Parameters declared, gate set (activation): relations 1 and 2, then
//!   [`check_activation`], which refuses while any input is undefined and
//!   otherwise checks relations 1–4. `ChainParams::validate` still refuses the
//!   gate after this check passes; opening it is a separate decision.

use std::fmt;

use sumchain_primitives::compute_pool_params::ComputePoolParamsV1;
use thiserror::Error;

use crate::compute_pool_retention::{
    validate_output_availability, validate_retention_relations, RetentionRelationError,
    RetentionRelationInputs,
};

/// A relation input with no source in this repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionInput {
    /// `B`, relation 3.
    PerBlockBudgetNs,
    /// `t_recompute`, relation 3.
    TRecomputeP99Ns,
    /// `R_max`, relation 4.
    RMax,
    /// `C_ret`, relation 4.
    RetentionChunkCap,
    /// `E_max`, relation 4.
    MaxIndexedEpochs,
}

impl RetentionInput {
    /// The [`RetentionRelationInputs`] field name.
    pub fn name(self) -> &'static str {
        match self {
            Self::PerBlockBudgetNs => "per_block_budget_ns",
            Self::TRecomputeP99Ns => "t_recompute_p99_ns",
            Self::RMax => "r_max",
            Self::RetentionChunkCap => "retention_chunk_cap",
            Self::MaxIndexedEpochs => "max_indexed_epochs",
        }
    }

    /// The relation that cannot be checked without it.
    pub fn relation(self) -> u8 {
        match self {
            Self::PerBlockBudgetNs | Self::TRecomputeP99Ns => 3,
            Self::RMax | Self::RetentionChunkCap | Self::MaxIndexedEpochs => 4,
        }
    }

    /// Why it has no source.
    pub fn reason(self) -> &'static str {
        match self {
            Self::PerBlockBudgetNs => "no committed source for the per-block budget B",
            Self::TRecomputeP99Ns => "no measured tracker-recompute p99",
            Self::RMax => "R_max is not defined",
            Self::RetentionChunkCap => "no retention chunk cap is defined",
            Self::MaxIndexedEpochs => "depends on D-E (which assignment epochs a tracker counts)",
        }
    }
}

/// The five inputs that do not come from the declared parameters. `None`
/// means undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsourcedRetentionInputs {
    pub per_block_budget_ns: Option<u64>,
    pub t_recompute_p99_ns: Option<u64>,
    pub r_max: Option<u64>,
    pub retention_chunk_cap: Option<u64>,
    pub max_indexed_epochs: Option<u64>,
}

impl UnsourcedRetentionInputs {
    /// The state of this repository: none of the five has a source.
    pub fn undefined() -> Self {
        Self {
            per_block_budget_ns: None,
            t_recompute_p99_ns: None,
            r_max: None,
            retention_chunk_cap: None,
            max_indexed_epochs: None,
        }
    }

    /// The undefined inputs, in [`RetentionRelationInputs`] field order.
    pub fn missing(&self) -> Vec<RetentionInput> {
        [
            (self.per_block_budget_ns, RetentionInput::PerBlockBudgetNs),
            (self.t_recompute_p99_ns, RetentionInput::TRecomputeP99Ns),
            (self.r_max, RetentionInput::RMax),
            (self.retention_chunk_cap, RetentionInput::RetentionChunkCap),
            (self.max_indexed_epochs, RetentionInput::MaxIndexedEpochs),
        ]
        .into_iter()
        .filter_map(|(v, input)| v.is_none().then_some(input))
        .collect()
    }
}

/// Undefined inputs, listed for an error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingInputs(pub Vec<RetentionInput>);

impl fmt::Display for MissingInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, input) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(
                f,
                "{} (relation {}: {})",
                input.name(),
                input.relation(),
                input.reason()
            )?;
        }
        Ok(())
    }
}

/// Why the retention relations refuse compute-pool activation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RetentionActivationError {
    /// At least one input has no source, so relations 3 and/or 4 cannot be
    /// checked. Activation fails closed.
    #[error("retention relation inputs undefined, relations cannot be checked: {0}")]
    InputsUndefined(MissingInputs),
    /// Every input is defined and a relation does not hold.
    #[error("retention relation does not hold: {0}")]
    Relation(#[from] RetentionRelationError),
}

/// Genesis validation of a declared `ComputePoolParamsV1`, gate set or not:
/// relations 1 and 2, the two whose inputs are always present.
pub fn validate_declared(
    params: &ComputePoolParamsV1,
    finality_depth: u64,
) -> Result<(), RetentionRelationError> {
    validate_output_availability(params.output_availability_blocks, finality_depth)
}

/// The ten relation inputs, or the undefined ones.
pub fn relation_inputs(
    params: &ComputePoolParamsV1,
    finality_depth: u64,
    unsourced: UnsourcedRetentionInputs,
) -> Result<RetentionRelationInputs, MissingInputs> {
    match unsourced {
        UnsourcedRetentionInputs {
            per_block_budget_ns: Some(per_block_budget_ns),
            t_recompute_p99_ns: Some(t_recompute_p99_ns),
            r_max: Some(r_max),
            retention_chunk_cap: Some(retention_chunk_cap),
            max_indexed_epochs: Some(max_indexed_epochs),
        } => Ok(RetentionRelationInputs {
            output_availability_blocks: params.output_availability_blocks,
            finality_depth,
            max_retention_updates_per_block: params.max_retention_updates_per_block,
            per_block_budget_ns,
            t_recompute_p99_ns,
            max_retention_files_per_job: params.max_retention_files_per_job,
            max_reverse_index_entries: params.max_reverse_index_entries,
            r_max,
            retention_chunk_cap,
            max_indexed_epochs,
        }),
        _ => Err(MissingInputs(unsourced.missing())),
    }
}

/// The retention check on the activation path: refuses while any input is
/// undefined, otherwise checks relations 1–4. Passing it does not open the
/// gate.
pub fn check_activation(
    params: &ComputePoolParamsV1,
    finality_depth: u64,
    unsourced: UnsourcedRetentionInputs,
) -> Result<RetentionRelationInputs, RetentionActivationError> {
    let inputs = relation_inputs(params, finality_depth, unsourced)
        .map_err(RetentionActivationError::InputsUndefined)?;
    validate_retention_relations(&inputs)?;
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute_pool_retention::RetentionRelationError as R;
    use RetentionInput as I;

    /// TEST_ONLY parameters, not proposed values: every `max_*` cap 1 except
    /// the retention caps, `output_availability_blocks` on the relation-1
    /// floor, everything else 0.
    fn params() -> ComputePoolParamsV1 {
        serde_json::from_str(
            r#"{
            "b_offer": 0, "b_commit": 0, "b_check": 0,
            "c_layer": 0, "c_tok": 0, "c_sel": 0, "c_emit": 0,
            "accept_reimb": 0, "commit_verify_reimb": 0, "publish_reimb": 0,
            "observe_reimb": 0, "check_reimb": 0, "settle_reimb": 0, "reassign_reimb": 0,
            "max_work_units": 1, "max_generations": 1, "max_reprovisionable_units": 1,
            "max_attempts_per_unit": 1, "max_reassignments_per_file": 1,
            "k_susp": 0, "w_susp": 0, "s_susp": 0, "n_invite_max": 0,
            "max_retention_files_per_job": 10, "max_retention_updates_per_block": 300,
            "max_reverse_index_entries": 50, "output_availability_blocks": 200,
            "d_avail": 0, "d_ack": 0, "d_final": 0
        }"#,
        )
        .unwrap()
    }

    /// TEST_ONLY stand-ins for the five undefined inputs. They exist only to
    /// exercise relations 3 and 4 through this module; they are not values
    /// for B, t_recompute, R_max, C_ret or E_max. `C_ret = E_max = 1` is the
    /// one-chunk, one-epoch case, where relation 4 needs `2 + R_max` per file.
    fn injected() -> UnsourcedRetentionInputs {
        UnsourcedRetentionInputs {
            per_block_budget_ns: Some(300_000_000),
            t_recompute_p99_ns: Some(1_000_000),
            r_max: Some(3),
            retention_chunk_cap: Some(1),
            max_indexed_epochs: Some(1),
        }
    }

    const FINALITY_DEPTH: u64 = 3;

    #[test]
    fn today_every_unsourced_input_is_undefined() {
        let u = UnsourcedRetentionInputs::undefined();
        assert_eq!(
            u.missing(),
            vec![
                I::PerBlockBudgetNs,
                I::TRecomputeP99Ns,
                I::RMax,
                I::RetentionChunkCap,
                I::MaxIndexedEpochs
            ]
        );
        assert_eq!(
            check_activation(&params(), FINALITY_DEPTH, u),
            Err(RetentionActivationError::InputsUndefined(MissingInputs(
                vec![
                I::PerBlockBudgetNs,
                I::TRecomputeP99Ns,
                I::RMax,
                I::RetentionChunkCap,
                I::MaxIndexedEpochs
            ]
            )))
        );
    }

    #[test]
    fn the_refusal_names_each_missing_input_and_its_relation() {
        let msg = check_activation(
            &params(),
            FINALITY_DEPTH,
            UnsourcedRetentionInputs::undefined(),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            msg,
            "retention relation inputs undefined, relations cannot be checked: \
             per_block_budget_ns (relation 3: no committed source for the per-block budget B); \
             t_recompute_p99_ns (relation 3: no measured tracker-recompute p99); \
             r_max (relation 4: R_max is not defined); \
             retention_chunk_cap (relation 4: no retention chunk cap is defined); \
             max_indexed_epochs (relation 4: depends on D-E (which assignment epochs a \
             tracker counts))"
        );
    }

    #[test]
    fn any_single_missing_input_still_refuses() {
        for (u, missing) in [
            (
                UnsourcedRetentionInputs {
                    per_block_budget_ns: None,
                    ..injected()
                },
                I::PerBlockBudgetNs,
            ),
            (
                UnsourcedRetentionInputs {
                    t_recompute_p99_ns: None,
                    ..injected()
                },
                I::TRecomputeP99Ns,
            ),
            (
                UnsourcedRetentionInputs {
                    r_max: None,
                    ..injected()
                },
                I::RMax,
            ),
            (
                UnsourcedRetentionInputs {
                    retention_chunk_cap: None,
                    ..injected()
                },
                I::RetentionChunkCap,
            ),
            (
                UnsourcedRetentionInputs {
                    max_indexed_epochs: None,
                    ..injected()
                },
                I::MaxIndexedEpochs,
            ),
        ] {
            assert_eq!(
                check_activation(&params(), FINALITY_DEPTH, u),
                Err(RetentionActivationError::InputsUndefined(MissingInputs(
                    vec![missing]
                )))
            );
        }
    }

    #[test]
    fn each_input_comes_from_its_source() {
        let p = params();
        let i = relation_inputs(&p, 7, injected()).unwrap();
        assert_eq!(
            i,
            RetentionRelationInputs {
                output_availability_blocks: p.output_availability_blocks,
                finality_depth: 7,
                max_retention_updates_per_block: p.max_retention_updates_per_block,
                per_block_budget_ns: 300_000_000,
                t_recompute_p99_ns: 1_000_000,
                max_retention_files_per_job: p.max_retention_files_per_job,
                max_reverse_index_entries: p.max_reverse_index_entries,
                r_max: 3,
                retention_chunk_cap: 1,
                max_indexed_epochs: 1,
            }
        );
    }

    #[test]
    fn with_every_input_injected_the_test_values_pass() {
        assert_eq!(
            check_activation(&params(), FINALITY_DEPTH, injected()),
            Ok(relation_inputs(&params(), FINALITY_DEPTH, injected()).unwrap())
        );
    }

    #[test]
    fn each_relation_refuses_activation_with_its_exact_error() {
        let refused =
            |p: ComputePoolParamsV1, fd: u64, u: UnsourcedRetentionInputs| match check_activation(
                &p, fd, u,
            ) {
                Err(RetentionActivationError::Relation(e)) => e,
                other => panic!("expected a relation error, got {other:?}"),
            };
        // 1
        let p = ComputePoolParamsV1 {
            output_availability_blocks: 199,
            ..params()
        };
        assert_eq!(
            refused(p, 0, injected()),
            R::OutputAvailabilityBelowPorRound {
                output_availability_blocks: 199,
                floor: 200
            }
        );
        // 2
        assert_eq!(
            refused(params(), 200, injected()),
            R::OutputAvailabilityNotAboveFinality {
                output_availability_blocks: 200,
                finality_depth: 200
            }
        );
        // 3
        let p = ComputePoolParamsV1 {
            max_retention_updates_per_block: 301,
            ..params()
        };
        assert_eq!(
            refused(p, FINALITY_DEPTH, injected()),
            R::UpdatesPerBlockOverBudget {
                max_retention_updates_per_block: 301,
                per_block_budget_ns: 300_000_000,
                t_recompute_p99_ns: 1_000_000,
                bound: 300,
            }
        );
        let zero_t = UnsourcedRetentionInputs {
            t_recompute_p99_ns: Some(0),
            ..injected()
        };
        assert_eq!(
            refused(params(), FINALITY_DEPTH, zero_t),
            R::RecomputeTimeZero
        );
        // 4
        let p = ComputePoolParamsV1 {
            max_reverse_index_entries: 49,
            ..params()
        };
        assert_eq!(
            refused(p, FINALITY_DEPTH, injected()),
            R::ReverseIndexBelowRequirement {
                max_reverse_index_entries: 49,
                max_retention_files_per_job: 10,
                r_max: 3,
                retention_chunk_cap: 1,
                max_indexed_epochs: 1,
                required: 50,
            }
        );
    }

    #[test]
    fn relation_4_overflow_refuses_activation() {
        let r_overflow = UnsourcedRetentionInputs {
            r_max: Some(u64::MAX),
            ..injected()
        };
        assert_eq!(
            check_activation(&params(), FINALITY_DEPTH, r_overflow),
            Err(RetentionActivationError::Relation(
                R::ReverseIndexRequirementOverflow {
                    max_retention_files_per_job: 10,
                    r_max: u64::MAX,
                    retention_chunk_cap: 1,
                    max_indexed_epochs: 1,
                }
            ))
        );
        let p = ComputePoolParamsV1 {
            max_retention_files_per_job: u64::MAX / 2,
            max_reverse_index_entries: u64::MAX,
            ..params()
        };
        let r1 = UnsourcedRetentionInputs {
            r_max: Some(1),
            ..injected()
        };
        assert_eq!(
            check_activation(&p, FINALITY_DEPTH, r1),
            Err(RetentionActivationError::Relation(
                R::ReverseIndexRequirementOverflow {
                    max_retention_files_per_job: u64::MAX / 2,
                    r_max: 1,
                    retention_chunk_cap: 1,
                    max_indexed_epochs: 1,
                }
            ))
        );
    }

    #[test]
    fn a_declaration_is_checked_against_relations_1_and_2_only() {
        assert_eq!(validate_declared(&params(), FINALITY_DEPTH), Ok(()));
        // Relations 3 and 4 would refuse these under the injected inputs;
        // validate_declared does not evaluate them.
        let p = ComputePoolParamsV1 {
            max_retention_updates_per_block: u64::MAX,
            max_retention_files_per_job: u64::MAX,
            max_reverse_index_entries: 1,
            ..params()
        };
        assert_eq!(validate_declared(&p, FINALITY_DEPTH), Ok(()));
        assert!(check_activation(&p, FINALITY_DEPTH, injected()).is_err());
        // Relation 1 and relation 2 are.
        let p = ComputePoolParamsV1 {
            output_availability_blocks: 0,
            ..params()
        };
        assert_eq!(
            validate_declared(&p, 0),
            Err(R::OutputAvailabilityBelowPorRound {
                output_availability_blocks: 0,
                floor: 200
            })
        );
        assert_eq!(
            validate_declared(&params(), u64::MAX),
            Err(R::OutputAvailabilityNotAboveFinality {
                output_availability_blocks: 200,
                finality_depth: u64::MAX
            })
        );
    }
}
