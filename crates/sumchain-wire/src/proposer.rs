//! Protocol v1 proposer selection.
//!
//! One rule, one function: the proposer of `height` is
//! `validators[height mod validators.len()]`, over the canonical ordered
//! validator set. Block production, header validation, import, screening, the
//! reorg branch check and the RPC all call [`round_robin_proposer`], so the
//! rule a producer follows and the rule a validator checks cannot drift apart.
//!
//! The inputs are the height and the ordered set, and nothing else: no stake,
//! no seed, no local configuration, clock, network or environment. The order is
//! the canonical one the caller passes (genesis declaration order while
//! membership is static); this function never sorts, dedups or reorders it.
//!
//! Stake-weighted selection is not part of protocol v1 and has no code path
//! here. A set that is empty or names a validator twice is refused rather than
//! given a proposer: an empty set has no proposer to name, and a duplicate gives
//! one validator extra turns in a way no genesis author intended.

use thiserror::Error;

/// Why the canonical validator set cannot name a proposer.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProposerSelectionError {
    /// The validator set is empty.
    #[error(
        "the validator set is empty; round-robin proposer selection needs at least one validator"
    )]
    EmptyValidatorSet,
    /// The same validator appears at two positions of the set.
    #[error(
        "the validator set lists one validator twice (positions {first} and {second}); \
         round-robin proposer selection needs distinct validators"
    )]
    DuplicateValidator {
        /// Position of the first occurrence.
        first: usize,
        /// Position of the repeat.
        second: usize,
    },
}

/// Check that `validators` can serve as a canonical round-robin set: at least
/// one validator, and no validator listed twice.
///
/// Order is not checked because there is no order to check against: the order
/// the caller passes IS the canonical one.
pub fn check_validator_set(validators: &[[u8; 32]]) -> Result<(), ProposerSelectionError> {
    if validators.is_empty() {
        return Err(ProposerSelectionError::EmptyValidatorSet);
    }
    for (second, v) in validators.iter().enumerate().skip(1) {
        if let Some(first) = validators[..second].iter().position(|w| w == v) {
            return Err(ProposerSelectionError::DuplicateValidator { first, second });
        }
    }
    Ok(())
}

/// The protocol v1 proposer of `height`: `validators[height mod n]`.
///
/// The modulo is taken in `u64`, so the result does not depend on the target's
/// pointer width.
pub fn round_robin_proposer(
    height: u64,
    validators: &[[u8; 32]],
) -> Result<[u8; 32], ProposerSelectionError> {
    check_validator_set(validators)?;
    let index = height % validators.len() as u64;
    Ok(validators[index as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i + 1; 32]).collect()
    }

    #[test]
    fn selects_height_mod_n_in_the_given_order() {
        for n in [1u8, 2, 4, 5, 7] {
            let vs = set(n);
            for h in 0..200u64 {
                assert_eq!(
                    round_robin_proposer(h, &vs).unwrap(),
                    vs[(h % n as u64) as usize]
                );
            }
            // Large heights, including the top of the range.
            for h in [u64::MAX, u64::MAX - 1, 1 << 40, (1 << 32) + 3] {
                assert_eq!(
                    round_robin_proposer(h, &vs).unwrap(),
                    vs[(h % n as u64) as usize]
                );
            }
        }
    }

    /// Pinned indices, worked out by hand from 2^32 and 2^64 residues rather
    /// than by the formula under test, so every CI architecture must produce
    /// exactly these. `2^32 + 3` also catches a pointer-width truncation: a
    /// 32-bit `height as usize` would see 3 instead.
    ///
    /// 2^32 ≡ 4 (mod 7), 1 (mod 5), 0 (mod 4), 0 (mod 2);
    /// 2^64 ≡ 2 (mod 7), 1 (mod 5), 0 (mod 4), 0 (mod 2).
    #[test]
    fn pinned_schedule_is_identical_on_every_target() {
        const H32: u64 = (1 << 32) + 3;
        const MAX: u64 = u64::MAX; // 2^64 - 1
        let table: &[(u64, u8, usize)] = &[
            (0, 7, 0),
            (6, 7, 6),
            (7, 7, 0),
            (H32, 7, 0), // 4 + 3 = 7 ≡ 0
            (MAX, 7, 1), // 2 - 1
            (H32, 5, 4), // 1 + 3
            (MAX, 5, 0), // 1 - 1
            (H32, 4, 3),
            (MAX, 4, 3),
            (H32, 2, 1),
            (MAX, 2, 1),
            (1_000_003, 5, 3),
        ];
        for &(h, n, want) in table {
            let vs = set(n);
            assert_eq!(
                round_robin_proposer(h, &vs).unwrap(),
                vs[want],
                "h={h} n={n}"
            );
        }
        assert_eq!(
            ProposerSelectionError::EmptyValidatorSet.to_string(),
            "the validator set is empty; round-robin proposer selection needs at least one validator"
        );
        assert_eq!(
            ProposerSelectionError::DuplicateValidator {
                first: 0,
                second: 2
            }
            .to_string(),
            "the validator set lists one validator twice (positions 0 and 2); round-robin \
             proposer selection needs distinct validators"
        );
    }

    /// The order passed in is the order used: reversing the set changes the
    /// schedule, so nothing inside sorts it.
    #[test]
    fn order_is_the_callers_not_sorted() {
        let vs = set(4);
        let mut rev = vs.clone();
        rev.reverse();
        assert_eq!(round_robin_proposer(0, &rev).unwrap(), vs[3]);
        assert_eq!(round_robin_proposer(1, &rev).unwrap(), vs[2]);
    }

    #[test]
    fn empty_and_duplicate_sets_are_refused() {
        assert_eq!(
            round_robin_proposer(0, &[]),
            Err(ProposerSelectionError::EmptyValidatorSet)
        );
        let a = [7u8; 32];
        let b = [9u8; 32];
        assert_eq!(
            round_robin_proposer(5, &[a, b, a]),
            Err(ProposerSelectionError::DuplicateValidator {
                first: 0,
                second: 2
            })
        );
        assert_eq!(
            check_validator_set(&[a, a]),
            Err(ProposerSelectionError::DuplicateValidator {
                first: 0,
                second: 1
            })
        );
        assert!(check_validator_set(&[a, b]).is_ok());
    }
}
