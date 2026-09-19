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

// ─────────────────────────────────────────────────────────────────────────────
// Changing an activation height under a running chain
// ─────────────────────────────────────────────────────────────────────────────
//
// The digest above makes disagreement between two nodes visible. This makes
// disagreement between a node and its OWN PAST visible, which is the failure an
// operator produces by hand: editing `genesis.json` on a node that has already
// been running.

/// Rescheduling a gate that is still ahead of the chain is permitted.
///
/// This has to be permitted, and saying why matters: a coordinated activation
/// IS a change to `genesis.json`. A check that refused every change would refuse
/// the mechanism it exists to protect. What it may refuse is a change to a gate
/// the chain has already passed.
#[test]
fn a_gate_still_ahead_of_the_chain_may_be_retuned() {
    let before = ChainParams::with_v2_enabled();
    let mut after = before.clone();
    after.account_root_enabled_from_height = Some(14_700_000);

    let changes = after.activation_changes(&before.recorded_activation_heights(), 12_920_593);
    assert_eq!(changes.len(), 1, "one gate moved: {changes:?}");
    assert!(changes[0].is_permitted());
    assert_eq!(changes[0].gate(), "account_root_enabled_from_height");

    // Moved again, still ahead: still permitted.
    let mut later = after.clone();
    later.account_root_enabled_from_height = Some(15_000_000);
    let changes = later.activation_changes(&after.recorded_activation_heights(), 12_920_593);
    assert!(changes[0].is_permitted(), "{changes:?}");

    // Cancelled while still ahead: also permitted. Standing down a scheduled
    // activation is the same class of act as scheduling it.
    let mut cancelled = after.clone();
    cancelled.account_root_enabled_from_height = None;
    let changes = cancelled.activation_changes(&after.recorded_activation_heights(), 12_920_593);
    assert!(changes[0].is_permitted(), "{changes:?}");
}

/// Changing a gate the chain has ALREADY PASSED is refused.
///
/// Blocks exist that were produced under the old height. Changing it now does
/// not change them; it changes what this binary believes about them, and the
/// node computes a different root for a block it already accepted. Three ways
/// to do it, all refused: move the height, move it backwards, remove it.
#[test]
fn a_gate_the_chain_has_passed_may_not_be_changed() {
    let mut before = ChainParams::with_v2_enabled();
    before.account_root_enabled_from_height = Some(9_000_000);
    let head = 12_920_593;

    for (label, to) in [
        ("moved forward", Some(13_000_000u64)),
        ("moved backward", Some(8_000_000)),
        ("removed", None),
    ] {
        let mut after = before.clone();
        after.account_root_enabled_from_height = to;
        let changes = after.activation_changes(&before.recorded_activation_heights(), head);
        assert_eq!(changes.len(), 1, "{label}: {changes:?}");
        assert!(
            !changes[0].is_permitted(),
            "{label} must be refused: {changes:?}"
        );
        let text = changes[0].to_string();
        assert!(
            text.contains("ALREADY PASSED") && text.contains("9000000"),
            "{label}: the refusal must name the height that already fired: {text}"
        );
    }

    // The boundary: a gate at exactly the head height HAS fired.
    let mut at_head = ChainParams::with_v2_enabled();
    at_head.account_root_enabled_from_height = Some(head);
    let mut moved = at_head.clone();
    moved.account_root_enabled_from_height = Some(head + 1);
    assert!(
        !moved.activation_changes(&at_head.recorded_activation_heights(), head)[0].is_permitted(),
        "a gate whose height equals the head has fired for that block"
    );

    // One block above the head has not fired, and may still move.
    let mut ahead = ChainParams::with_v2_enabled();
    ahead.account_root_enabled_from_height = Some(head + 1);
    let mut moved = ahead.clone();
    moved.account_root_enabled_from_height = Some(head + 2);
    assert!(moved.activation_changes(&ahead.recorded_activation_heights(), head)[0].is_permitted());
}

/// Opening a dormant gate at a height the chain has already passed is refused.
///
/// The one an operator reaches for by accident: copying a peer's genesis, or
/// setting a gate to a height that was in the future when the plan was written
/// and is in the past by the time it is applied. Every block above that height
/// was produced without the rule.
#[test]
fn a_dormant_gate_may_not_be_opened_retroactively() {
    let before = ChainParams::with_v2_enabled();
    assert_eq!(before.account_root_enabled_from_height, None);

    let mut after = before.clone();
    after.account_root_enabled_from_height = Some(9_000_000);
    let changes = after.activation_changes(&before.recorded_activation_heights(), 12_920_593);
    assert_eq!(changes.len(), 1);
    assert!(!changes[0].is_permitted());
    assert!(
        changes[0].to_string().contains("already passed"),
        "{:?}",
        changes[0]
    );

    // And a gate scheduled ahead that is then re-pointed into the past is the
    // same refusal, not a permitted retune.
    let mut scheduled = ChainParams::with_v2_enabled();
    scheduled.account_root_enabled_from_height = Some(14_700_000);
    let mut backdated = scheduled.clone();
    backdated.account_root_enabled_from_height = Some(1_000);
    assert!(
        !backdated.activation_changes(&scheduled.recorded_activation_heights(), 12_920_593)[0]
            .is_permitted()
    );
}

/// An identical configuration produces no changes at all.
///
/// The normal restart. If this were noisy, the warnings that matter would be
/// ignored.
#[test]
fn an_unchanged_configuration_reports_nothing() {
    let params = ChainParams::with_v2_enabled();
    assert!(params
        .activation_changes(&params.recorded_activation_heights(), 12_920_593)
        .is_empty());

    let mut with_gates = params.clone();
    with_gates.account_root_enabled_from_height = Some(14_700_000);
    with_gates.application_journal_enabled_from_height = Some(14_200_000);
    assert!(with_gates
        .activation_changes(&with_gates.recorded_activation_heights(), 12_920_593)
        .is_empty());
}

/// A gate this binary knows and the record does not is treated as having been
/// dormant.
///
/// That is what a binary which did not know the gate believed, so it is the
/// honest reading of a record written by one. The consequence is the right one:
/// a new gate pointed ahead of the chain is a permitted retune, and a new gate
/// pointed behind it is a retroactive opening and refused — which is exactly how
/// an upgrade that ships a new activation should behave.
#[test]
fn a_gate_missing_from_the_record_reads_as_dormant() {
    let old_record: Vec<(String, Option<u64>)> = ChainParams::with_v2_enabled()
        .recorded_activation_heights()
        .into_iter()
        .filter(|(name, _)| name != "account_root_enabled_from_height")
        .collect();

    let mut ahead = ChainParams::with_v2_enabled();
    ahead.account_root_enabled_from_height = Some(14_700_000);
    assert!(ahead.activation_changes(&old_record, 12_920_593)[0].is_permitted());

    let mut behind = ChainParams::with_v2_enabled();
    behind.account_root_enabled_from_height = Some(9_000_000);
    assert!(!behind.activation_changes(&old_record, 12_920_593)[0].is_permitted());

    // And left dormant it is not a change at all.
    let dormant = ChainParams::with_v2_enabled();
    assert!(dormant
        .activation_changes(&old_record, 12_920_593)
        .is_empty());
}

/// On a FIRST start there is no record, and the comparison is not performed —
/// which is load-bearing, not an omission.
///
/// The function itself has no way to distinguish "height 0 because the chain is
/// empty" from "height 0 because the genesis block exists", and a gate at
/// `Some(0)` means opposite things in those two cases. So the caller makes the
/// distinction: `Node::check_activation_parameters` compares only when a record
/// exists, and a database with no record has no blocks for a gate to have fired
/// over.
///
/// This test pins the consequence of getting that wrong, so the caller's
/// structure is not free to drift: fed an empty record at height 0, the
/// comparison reports a gate set to `Some(0)` as a retroactive opening. Correct
/// for a chain that has produced blocks, wrong for one that has not, and the
/// reason the first start is recorded rather than compared.
#[test]
fn a_first_start_is_recorded_rather_than_compared() {
    let mut params = ChainParams::with_v2_enabled();
    params.account_root_enabled_from_height = Some(14_700_000);

    let changes = params.activation_changes(&[], 0);
    assert_eq!(changes.len(), 2, "both set gates are reported: {changes:?}");

    let by_gate = |g: &str| {
        changes
            .iter()
            .find(|c| c.gate() == g)
            .unwrap_or_else(|| panic!("{g} missing from {changes:?}"))
    };
    assert!(
        by_gate("account_root_enabled_from_height").is_permitted(),
        "a future height is a permitted retune even from an empty record"
    );
    assert!(
        !by_gate("v2_enabled_from_height").is_permitted(),
        "`Some(0)` against height 0 reads as retroactive — which is why a first \
         start does not run this comparison at all"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The first start of an upgraded node: no record to compare against
// ─────────────────────────────────────────────────────────────────────────────

/// Every grandfathered name is still a gate.
///
/// The list is closed, so it can never legitimately grow — but a gate can be
/// RENAMED, and a stale name in the list silently grandfathers nothing while
/// looking like it grandfathers something. Worse, the renamed gate then falls
/// through to the strict side and refuses a chain that was fine a commit ago.
#[test]
fn every_grandfathered_gate_still_exists() {
    let gates: HashSet<&str> = ChainParams::default()
        .activation_heights()
        .into_iter()
        .map(|(g, _)| g)
        .collect();
    let stale: Vec<&&str> = sumchain_genesis::GATES_PREDATING_ACTIVATION_RECORDING
        .iter()
        .filter(|g| !gates.contains(**g))
        .collect();
    assert!(
        stale.is_empty(),
        "these grandfathered names are no longer gates, so they grandfather \
         nothing and the gates they used to name are now refused on a first \
         start: {stale:?}"
    );
    assert_eq!(
        sumchain_genesis::GATES_PREDATING_ACTIVATION_RECORDING.len(),
        18,
        "the list is closed: it names the gates that existed before this binary \
         began recording activation heights, which is a historical fact. If this \
         number moved, either a gate was renamed (fix the name) or someone added \
         a new gate to it (do not: a new gate has no blocks behind it)"
    );
}

/// A gate this binary introduced is not grandfathered, whatever else changes.
///
/// The load-bearing default. Thirteen gates arrived after activation recording
/// did, and the point of deriving the strict set by EXCLUSION rather than by
/// listing it is that a fourteenth is strict without anyone remembering to say
/// so.
#[test]
fn a_gate_this_binary_introduced_is_not_grandfathered() {
    for gate in [
        "application_journal_enabled_from_height",
        "account_root_enabled_from_height",
        "nft_receipt_failure_enabled_from_height",
        "subsystem_block_timestamp_enabled_from_height",
        "subsystem_tx_index_enabled_from_height",
        "healthcare_authorization_enabled_from_height",
        "docclass_stake_escrow_enabled_from_height",
    ] {
        assert!(
            !sumchain_genesis::GATES_PREDATING_ACTIVATION_RECORDING.contains(&gate),
            "{gate} did not exist in the binary that wrote any production \
             database, so no block was produced under it and it must not be \
             grandfathered"
        );
    }
}

/// A gate the deployed binary already had may sit below the head.
///
/// `v2_enabled_from_height: Some(0)` on a chain at height 500,000 is the
/// ORDINARY configuration, not a fault: v2 shipped in the binary that produced
/// those blocks. A first-start check that refused this would refuse every real
/// chain, which is the failure mode worth guarding against explicitly.
#[test]
fn a_gate_the_deployed_binary_already_had_may_sit_below_the_head() {
    let p = ChainParams {
        v2_enabled_from_height: Some(0),
        education_enabled_from_height: Some(1),
        contracts_enabled_from_height: Some(400_000),
        ..ChainParams::default()
    };
    assert!(
        p.retroactive_gates_on_a_first_start(496_720).is_empty(),
        "a chain running the gates it was produced under must start"
    );
}

/// A gate this binary introduced may not.
#[test]
fn a_newly_introduced_gate_below_the_head_refuses_a_first_start() {
    let head = 496_720;
    /// One gate's name and the closure that opens it at a given height.
    type GateCase<'a> = (&'a str, &'a dyn Fn(&mut ChainParams, u64));
    let cases: &[GateCase<'_>] = &[
        ("application_journal_enabled_from_height", &|p, h| {
            p.application_journal_enabled_from_height = Some(h)
        }),
        ("account_root_enabled_from_height", &|p, h| {
            p.application_journal_enabled_from_height = Some(h);
            p.account_root_enabled_from_height = Some(h);
        }),
        ("nft_receipt_failure_enabled_from_height", &|p, h| {
            p.nft_receipt_failure_enabled_from_height = Some(h)
        }),
        ("subsystem_block_timestamp_enabled_from_height", &|p, h| {
            p.subsystem_block_timestamp_enabled_from_height = Some(h)
        }),
        ("subsystem_tx_index_enabled_from_height", &|p, h| {
            p.subsystem_tx_index_enabled_from_height = Some(h)
        }),
        ("tax_authorization_enabled_from_height", &|p, h| {
            p.tax_authorization_enabled_from_height = Some(h)
        }),
    ];
    for (name, set) in cases {
        let name = *name;
        let mut p = ChainParams::default();
        set(&mut p, head - 1);
        let refusals = p.retroactive_gates_on_a_first_start(head);
        assert!(
            refusals.iter().any(|c| c.gate() == name),
            "{name} at {} on a chain at {head} must be refused; got {refusals:?}",
            head - 1
        );
        assert!(
            !refusals[0].is_permitted(),
            "a retroactive gate is never a permitted change"
        );

        // The boundary: exactly at the head is still retroactive — the block at
        // that height already exists — and one above it is not.
        let mut at = ChainParams::default();
        set(&mut at, head);
        assert!(
            at.retroactive_gates_on_a_first_start(head)
                .iter()
                .any(|c| c.gate() == name),
            "{name} AT the head is still retroactive: that block already exists"
        );
        let mut ahead = ChainParams::default();
        set(&mut ahead, head + 1);
        assert!(
            ahead
                .retroactive_gates_on_a_first_start(head)
                .iter()
                .all(|c| c.gate() != name),
            "{name} one block ahead of the head is a scheduled activation"
        );
    }
}

/// An empty chain has passed nothing, so nothing is retroactive on it.
///
/// Without this the check would refuse a fresh chain whose genesis opens a gate
/// at 0 — which is how a new chain is configured, and the one case where a
/// height at or below the head is unambiguously fine.
#[test]
fn a_chain_with_no_blocks_may_open_any_gate_at_zero() {
    let p = ChainParams {
        application_journal_enabled_from_height: Some(0),
        account_root_enabled_from_height: Some(0),
        nft_receipt_failure_enabled_from_height: Some(0),
        ..ChainParams::default()
    };
    assert!(
        p.retroactive_gates_on_a_first_start(0).is_empty(),
        "a chain at height 0 has produced nothing to be retroactive about"
    );
}

/// The default configuration starts on any chain.
///
/// The check must not make an upgrade harder than it is. A node upgrading with
/// every new gate dormant — which is what the shipped default is, and what an
/// operator who changes nothing gets — starts at any height.
#[test]
fn the_default_configuration_starts_at_any_height() {
    for head in [1u64, 496_720, 12_920_593] {
        assert!(
            ChainParams::default()
                .retroactive_gates_on_a_first_start(head)
                .is_empty(),
            "the shipped default must start a node at height {head}"
        );
    }
}
