//! The validator-topology guard on compute-pool enablement (#126).
//!
//! The pool's per-epoch DKG is bound by its creation phase: with `f` dealers
//! dealing invalidly and `c` submitting nothing, `|QUAL| = n − f − c` must
//! still reach `2f + 1`, so `n ≥ 3f + 1 + c`. The guard reports three bounds:
//!
//! | bound | value | meaning | here |
//! |---|---|---|---|
//! | [`CRYPTOGRAPHIC_MINIMUM`] | 4 | `3f + 1` at `f = 1`, no crash slack | reported |
//! | [`PRODUCT_MINIMUM`] | 5 | `3f + 1 + c` at `f = 1, c = 1` | **enforced** |
//! | [`MAINTENANCE_MINIMUM`] | 7 | one planned maintenance window plus one unplanned failure (#248) | reported, not evaluated |
//!
//! Only the product minimum refuses anything.
//!
//! **Not the maintenance minimum.** The validator maintenance and operational
//! minimum is the owner-ratified #248 profile (2026-09-05, "Minimum validator
//! set 7"): the smallest set whose planned-absence capacity,
//! `validator_count − quorum − 1` with the BFT quorum
//! `validator_count · 2 / 3 + 1`, is at least one. It is a different
//! requirement for a different failure. This guard reports it and does not
//! evaluate it, and passing this guard does not satisfy it.
//!
//! **No margin of 6.** #126's text (2026-07-12) asks for a "recommended
//! margin (6)". That predates the #248 ratification, under which a set of 6
//! has planned-absence capacity 0, the same as 5. The guard does not report 6.
//!
//! # The membership it counts
//!
//! The genesis validator list. Protocol v1 refuses dynamic staking epochs and
//! stake-weighted selection before this guard runs (`StakingParams::
//! check_protocol_v1`, #272), so that list is the whole live validator set at
//! every height and the same on every node. The guard therefore runs once, at
//! genesis load, where pool enablement is decided; it adds no per-block or
//! per-epoch check and no refusal of its own about epochs. Reading any other
//! source (the beacon's per-epoch membership snapshot, which is dormant, or an
//! epoch-derived set, which is not canonical until #266) is left to the change
//! that defines it.
//!
//! The bounds are compiled constants, not genesis parameters: nothing here
//! reads a file, an environment variable, a flag or the network.
//!
//! # A static genesis guard, not the runtime membership check
//!
//! #126 asks for an on-chain guard that reads the beacon membership snapshot.
//! This is not that guard, and it does not satisfy that requirement. It is a
//! static check of the genesis document, run by every node when it loads the
//! genesis; it never reads chain state, the membership snapshot or any
//! runtime membership. It refuses a genesis that enables the pool over too
//! few genesis validators, which under protocol v1 is the whole validator set.
//!
//! The runtime check, over the canonical membership at the pool's activation
//! height, is unresolved: it needs the membership representation #266 has not
//! chosen, and nothing here implements or approximates it. When protocol v1's
//! containment is lifted, this guard alone no longer bounds the live set.

/// `3f + 1 + c`: with `f` invalid dealers and `c` silent ones, the DKG's
/// qualified set still reaches `2f + 1`.
pub const fn dkg_creation_minimum(f: usize, c: usize) -> usize {
    3 * f + 1 + c
}

/// The cryptographic minimum, `3f + 1` at `f = 1`: the DKG completes only if
/// no dealer crashes. Reported, never enforced.
pub const CRYPTOGRAPHIC_MINIMUM: usize = dkg_creation_minimum(1, 0);

/// The product minimum, `3f + 1 + c` at `f = 1, c = 1`: compute-pool
/// enablement is refused over fewer validators.
pub const PRODUCT_MINIMUM: usize = dkg_creation_minimum(1, 1);

/// The validator maintenance and operational minimum ratified on #248.
/// Reported, never evaluated by this guard.
pub const MAINTENANCE_MINIMUM: usize = 7;

/// Pool enablement refused: the validator set is below [`PRODUCT_MINIMUM`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "compute_pool_enabled_from_height cannot be enabled over {validators} validator(s): pool \
     enablement requires at least {product_minimum} (DKG-creation bounds: cryptographic minimum \
     {cryptographic_minimum}, product minimum {product_minimum}). The separate validator \
     maintenance and operational minimum ({maintenance_minimum}, #248) is not evaluated by this \
     check"
)]
pub struct BelowProductMinimum {
    /// Distinct validators in the set.
    pub validators: usize,
    /// [`CRYPTOGRAPHIC_MINIMUM`].
    pub cryptographic_minimum: usize,
    /// [`PRODUCT_MINIMUM`].
    pub product_minimum: usize,
    /// [`MAINTENANCE_MINIMUM`].
    pub maintenance_minimum: usize,
}

/// The number of distinct validators in `validators`. A duplicate never adds
/// to the count (genesis validation refuses one before the guard runs).
pub fn validator_count(validators: &[[u8; 32]]) -> usize {
    validators
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// The guard: compute-pool enablement over `validators` is refused below
/// [`PRODUCT_MINIMUM`]. `Ok` admits nothing by itself; it only means this
/// requirement holds, and every other refusal still applies.
pub fn check_pool_activation(validators: &[[u8; 32]]) -> Result<(), BelowProductMinimum> {
    let n = validator_count(validators);
    if n < PRODUCT_MINIMUM {
        return Err(BelowProductMinimum {
            validators: n,
            cryptographic_minimum: CRYPTOGRAPHIC_MINIMUM,
            product_minimum: PRODUCT_MINIMUM,
            maintenance_minimum: MAINTENANCE_MINIMUM,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumchain_primitives::beacon_schedule::{validate_beacon_params, BeaconParamsViolation};

    fn keys(n: usize) -> Vec<[u8; 32]> {
        (1..=n)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&(i as u64).to_be_bytes());
                k
            })
            .collect()
    }

    #[test]
    fn the_three_bounds_are_4_5_and_7() {
        assert_eq!(CRYPTOGRAPHIC_MINIMUM, 4);
        assert_eq!(PRODUCT_MINIMUM, 5);
        assert_eq!(MAINTENANCE_MINIMUM, 7);
    }

    /// #248's capacity rule, `validator_count − quorum − 1` with the BFT
    /// quorum `validator_count · 2 / 3 + 1` (`consensus::bft::vote`), is
    /// first positive at 7: 5 and 6 both have capacity 0.
    #[test]
    fn seven_is_the_smallest_set_with_planned_absence_capacity() {
        let capacity = |n: usize| n.saturating_sub(n * 2 / 3 + 1 + 1);
        assert_eq!(capacity(5), 0);
        assert_eq!(capacity(6), 0);
        assert_eq!(capacity(MAINTENANCE_MINIMUM), 1);
        assert_eq!(
            (1..=MAINTENANCE_MINIMUM).find(|&n| capacity(n) >= 1),
            Some(MAINTENANCE_MINIMUM)
        );
    }

    #[test]
    fn the_set_size_is_the_number_of_distinct_validators() {
        assert_eq!(validator_count(&[]), 0);
        for n in [1, 2, 5, 7] {
            assert_eq!(validator_count(&keys(n)), n);
        }
        // A repeated key never adds to the count.
        let mut six_entries_five_validators = keys(5);
        six_entries_five_validators.push(six_entries_five_validators[2]);
        assert_eq!(validator_count(&six_entries_five_validators), 5);
        let mut four_distinct = keys(4);
        four_distinct.push(four_distinct[0]);
        assert!(check_pool_activation(&four_distinct).is_err());
    }

    #[test]
    fn fewer_than_five_validators_are_refused_and_five_are_not() {
        for n in 0..PRODUCT_MINIMUM {
            assert_eq!(
                check_pool_activation(&keys(n)),
                Err(BelowProductMinimum {
                    validators: n,
                    cryptographic_minimum: 4,
                    product_minimum: 5,
                    maintenance_minimum: 7,
                }),
                "n = {n}"
            );
        }
        for n in [5, 6, 7, 8, 100] {
            assert_eq!(check_pool_activation(&keys(n)), Ok(()), "n = {n}");
        }
    }

    #[test]
    fn the_refusal_reports_n_and_all_three_bounds_and_does_not_evaluate_seven() {
        for n in [2usize, 3, 4] {
            let text = check_pool_activation(&keys(n)).unwrap_err().to_string();
            assert!(text.contains(&format!("over {n} validator(s)")), "{text}");
            for needle in [
                "requires at least 5",
                "cryptographic minimum 4",
                "product minimum 5",
                "maintenance and operational minimum (7, #248) is not evaluated",
            ] {
                assert!(text.contains(needle), "{needle:?} not in {text}");
            }
        }
    }

    /// The per-phase minimums, read from the single §7.4 predicate the beacon
    /// parameters are validated with (`validate_beacon_params`), at the
    /// ratified `f = 1, T = f + 1 = 2, Q_dkg = 2f + 1 = 3`: DKG creation binds
    /// at `n = 5` with one crash, signing alone would admit `n = 4`, and with no
    /// crash slack the DKG admits `n = 4`.
    #[test]
    fn per_phase_minimums_match_the_shared_beacon_predicate() {
        let (f, t, q) = (1u32, 2u32, 3u32);
        let smallest =
            |c: u32| (1u32..=64).find(|&n| validate_beacon_params(f, c, t, q, n).is_ok());
        assert_eq!(
            smallest(1),
            Some(PRODUCT_MINIMUM as u32),
            "DKG creation, c = 1"
        );
        assert_eq!(
            smallest(0),
            Some(CRYPTOGRAPHIC_MINIMUM as u32),
            "DKG creation, c = 0"
        );
        // At n = 4 with one crash, the signing inequality (n − f − c ≥ T)
        // holds and the DKG-creation one (n − f − c ≥ Q_dkg) does not: the
        // creation phase is the binding one.
        assert_eq!(
            validate_beacon_params(f, 1, t, q, 4),
            Err(BeaconParamsViolation::LivenessQual { avail: 2, q: 3 })
        );
        assert_eq!(
            validate_beacon_params(f, 1, t, q, 3),
            Err(BeaconParamsViolation::LivenessSigning { avail: 1, t: 2 })
        );
        assert_eq!(dkg_creation_minimum(1, 1), 5);
        assert_eq!(dkg_creation_minimum(1, 0), 4);
    }
}
