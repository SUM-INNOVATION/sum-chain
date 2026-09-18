//! The genesis activation digest: one value naming every height at which the
//! chain's behaviour changes.
//!
//! An activation height is a coordination mechanism, and it only coordinates
//! anything if every validator holds the same one. They are distributed as a
//! runtime `genesis.json` per validator and compared by eye; a single mistyped
//! digit gives one node a different rule at a different height, and nothing
//! reports it until blocks start being refused at that height.
//!
//! `Genesis::activation_digest` turns that comparison into an equality. These
//! tests establish the three properties that make it worth reading aloud: it
//! covers every gate (by reading the field declarations out of the source, not
//! by trusting a list), it is a function of configuration and nothing else, and
//! it moves for every difference that matters — including the two that are
//! easiest to miss, `None` against `Some(0)` and a height moved from one gate to
//! another.

use std::collections::HashSet;

use sumchain_genesis::{ChainParams, Genesis};

/// A genesis that parses: two real validator keys and one real allocation.
fn genesis(params: ChainParams) -> Genesis {
    Genesis::new(
        1,
        1_734_624_000_000,
        vec![
            "GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8".to_string(),
            "7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy".to_string(),
        ],
        [("8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4".to_string(), 500u128)]
            .into_iter()
            .collect(),
        params,
    )
}

/// Every `*_from_height` gate declared on `ChainParams` is folded into the
/// digest.
///
/// Read out of the SOURCE rather than out of a list maintained beside it. A
/// gate added to `ChainParams` and forgotten in `activation_heights` would
/// otherwise be a height two validators could silently disagree about while
/// their digests agreed — the exact failure this value exists to expose,
/// reintroduced by the value itself.
#[test]
fn every_activation_height_is_covered_by_the_digest() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("read the ChainParams declaration");

    // The field declarations, taken from the struct definition. `Option<u64>`
    // is part of the pattern on purpose: a gate is an optional height, and a
    // `u64` field whose name ends in `_from_height` would be something else.
    let mut declared: HashSet<String> = HashSet::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(": ") else {
            continue;
        };
        if name.ends_with("_from_height") && ty.starts_with("Option<u64>") {
            declared.insert(name.to_string());
        }
    }
    assert!(
        declared.len() > 10,
        "the source scan found only {} gates, which means the pattern stopped \
         matching rather than that the gates disappeared",
        declared.len()
    );

    let covered: HashSet<String> = ChainParams::default()
        .activation_heights()
        .into_iter()
        .map(|(name, _)| name.to_string())
        .collect();

    let missing: Vec<_> = declared.difference(&covered).collect();
    assert!(
        missing.is_empty(),
        "these gates are declared on ChainParams and not folded into the \
         activation digest, so two validators could disagree about them while \
         their digests agreed: {missing:?}"
    );
    let stale: Vec<_> = covered.difference(&declared).collect();
    assert!(
        stale.is_empty(),
        "these names are folded into the digest and no longer exist on \
         ChainParams: {stale:?}"
    );
}

/// The digest is a function of the configuration, not of the process that
/// computed it.
#[test]
fn the_digest_is_a_function_of_the_configuration() {
    let a = genesis(ChainParams::with_v2_enabled());
    let b = genesis(ChainParams::with_v2_enabled());
    assert_eq!(
        a.activation_digest().unwrap(),
        b.activation_digest().unwrap(),
        "two identically-configured genesis files must digest identically, or \
         operators comparing the value learn nothing"
    );
    assert_eq!(
        a.activation_digest().unwrap(),
        a.activation_digest().unwrap(),
        "recomputation must be stable"
    );
}

/// One changed height changes the digest — and so does the difference between
/// "dormant forever" and "active from genesis".
///
/// `None` against `Some(0)` is the case the presence byte exists for. They are
/// opposite configurations, and a fold that wrote nothing for `None` would let
/// them collide with a neighbouring field's bytes.
#[test]
fn every_difference_that_matters_moves_the_digest() {
    let base = genesis(ChainParams::with_v2_enabled());
    let baseline = base.activation_digest().unwrap();

    let mut one_height = ChainParams::with_v2_enabled();
    one_height.account_root_enabled_from_height = Some(13_800_000);
    assert_ne!(
        baseline,
        genesis(one_height.clone()).activation_digest().unwrap(),
        "opening a gate must move the digest"
    );

    let mut off_by_one = one_height.clone();
    off_by_one.account_root_enabled_from_height = Some(13_800_001);
    assert_ne!(
        genesis(one_height.clone()).activation_digest().unwrap(),
        genesis(off_by_one).activation_digest().unwrap(),
        "a one-block difference is the mistyped digit this value exists to catch"
    );

    let mut from_genesis = ChainParams::with_v2_enabled();
    from_genesis.account_root_enabled_from_height = Some(0);
    assert_ne!(
        baseline,
        genesis(from_genesis).activation_digest().unwrap(),
        "`None` (dormant forever) and `Some(0)` (active from genesis) are \
         opposite configurations and must not share a digest"
    );

    // The same height, moved from one gate to another. The field NAME is folded
    // precisely so this is visible: without it the digest would be a bag of
    // numbers and two chains activating different subsystems at the same height
    // would agree.
    let mut on_account = ChainParams::with_v2_enabled();
    on_account.account_root_enabled_from_height = Some(9_000_000);
    let mut on_governance = ChainParams::with_v2_enabled();
    on_governance.governance_enabled_from_height = Some(9_000_000);
    assert_ne!(
        genesis(on_account).activation_digest().unwrap(),
        genesis(on_governance).activation_digest().unwrap(),
        "one height on two different gates must not digest identically"
    );
}

/// The chain's identity is in the digest too, so two files that agree about
/// every gate and disagree about who validates do not compare equal.
#[test]
fn the_chain_identity_is_part_of_the_digest() {
    let base = genesis(ChainParams::with_v2_enabled());
    let baseline = base.activation_digest().unwrap();

    let mut other_chain = genesis(ChainParams::with_v2_enabled());
    other_chain.chain_id = 2;
    assert_ne!(baseline, other_chain.activation_digest().unwrap());

    // Validator ORDER is the PoA proposer rotation, so a reordered set is a
    // different chain.
    let mut reordered = genesis(ChainParams::with_v2_enabled());
    reordered.validators.reverse();
    assert_ne!(
        baseline,
        reordered.activation_digest().unwrap(),
        "validators are folded in declared order because that order is the \
         proposer rotation"
    );

    let mut richer = genesis(ChainParams::with_v2_enabled());
    *richer
        .alloc
        .get_mut("8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4")
        .unwrap() += 1;
    assert_ne!(baseline, richer.activation_digest().unwrap());
}

/// The allocation fold does not depend on `HashMap` iteration order.
///
/// Two genesis files with the same allocations inserted in different orders are
/// the same chain, and a digest that disagreed about them would fire on every
/// comparison and teach operators to ignore it.
#[test]
fn allocation_order_does_not_reach_the_digest() {
    let entries = [
        ("8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4".to_string(), 500u128),
        ("D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV".to_string(), 700u128),
    ];
    let forward = Genesis::new(
        1,
        1_734_624_000_000,
        vec!["GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8".to_string()],
        entries.iter().cloned().collect(),
        ChainParams::with_v2_enabled(),
    );
    let backward = Genesis::new(
        1,
        1_734_624_000_000,
        vec!["GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8".to_string()],
        entries.iter().rev().cloned().collect(),
        ChainParams::with_v2_enabled(),
    );
    assert_eq!(
        forward.activation_digest().unwrap(),
        backward.activation_digest().unwrap()
    );
}
