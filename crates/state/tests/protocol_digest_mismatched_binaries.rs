//! Two binaries, one genesis file: the comparison the activation digest cannot
//! make.
//!
//! `Genesis::activation_digest` is a function of the genesis FILE. Two operators
//! reading it to each other learn that their `genesis.json` files agree, which
//! is the question it was built to answer. It is not the question that decides
//! whether their nodes compute the same state root, because the rules a node
//! enforces are only half configuration: `MAX_SUBSYSTEM_PAYLOAD_BYTES`,
//! `MAX_ACCUMULATING_ROW_BYTES`, `MAX_NFT_BATCH_MINT_REQUESTS`,
//! `MAX_BLOCK_WRITE_SET_BYTES` and the rest ship in the BINARY. Two nodes built
//! from different commits enforce different validity and report the same
//! activation digest.
//!
//! These tests construct the comparison two different binaries would make.
//!
//! # How a test links two binaries
//!
//! It does not. [`protocol_digest_with_limits`] takes the limit set as a
//! parameter and [`protocol_digest`] is exactly that function applied to THIS
//! binary's [`consensus_limits`]. So "the digest the other binary would have
//! computed" is [`protocol_digest_with_limits`] applied to the limit set that
//! binary was built with — a value this process can construct by perturbing one
//! entry. That is not a simulation of the mismatch; it is the same function on
//! the same input the other binary would have supplied, so a fold that ignored
//! an entry would fail here for the same reason it would fail in production.

use sumchain_genesis::{ChainParams, Genesis};
use sumchain_state::protocol_digest::{
    consensus_limits, protocol_digest, protocol_digest_with_limits, LimitValue,
};

/// A genesis that parses: two real validator keys and one real allocation.
/// Deliberately the same fixture shape as `genesis/tests/activation_digest.rs`.
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

/// The limit set this binary was built with, with exactly one entry given a
/// different value — "the other binary".
fn limits_with_changed(name: &str) -> Vec<(&'static str, LimitValue)> {
    let mut limits = consensus_limits();
    let mut hit = false;
    for (n, v) in limits.iter_mut() {
        if *n == name {
            *v = match v {
                // A neighbouring value, not a wild one: the failure being
                // modelled is a limit edited by one step between two commits,
                // not a limit replaced by nonsense.
                LimitValue::Num(x) => LimitValue::Num(x.wrapping_add(1)),
                LimitValue::Bytes(_) => LimitValue::Bytes(b"a-different-domain"),
            };
            hit = true;
        }
    }
    assert!(
        hit,
        "{name} is not in this binary's consensus limit registry, so this test \
         is asserting nothing; it was renamed or dropped"
    );
    limits
}

/// The headline claim: same genesis file, different binary, different digest.
///
/// Each of the three constants the brief names, plus the one the census turned
/// up that nobody was looking for, is checked individually — a single "some
/// entry moves the digest" assertion would pass with the other entries dead.
#[test]
fn two_binaries_with_different_consensus_constants_produce_different_digests() {
    let g = genesis(ChainParams::default());

    // The genesis file is IDENTICAL across both binaries; this is the value the
    // operators would have compared, and it cannot see the difference.
    let activation = g.activation_digest().expect("activation digest");
    assert_eq!(
        activation,
        g.activation_digest().expect("activation digest"),
        "the activation digest is a function of the file, which has not changed"
    );

    let ours = protocol_digest(&g).expect("our digest");

    for name in [
        "MAX_SUBSYSTEM_PAYLOAD_BYTES",
        "MAX_ACCUMULATING_ROW_BYTES",
        "MAX_NFT_BATCH_MINT_REQUESTS",
        // Live on the production `execute_block` path today, ungated, and the
        // value the scaffold that used to sit here was replaced by: a limit
        // that can refuse a write helps decide whether a block is applicable.
        "MAX_BLOCK_WRITE_SET_BYTES",
        // The seam that decides whether a divergent root is adopted or refused,
        // which is what absorbs the activation-height defect below the window.
        "LEGACY_ROOT_COMPATIBILITY_HEIGHT",
    ] {
        let theirs =
            protocol_digest_with_limits(&g, &limits_with_changed(name)).expect("their digest");
        assert_ne!(
            ours, theirs,
            "two binaries differing ONLY in {name} must not report the same \
             protocol digest — if they do, the operators' comparison passes \
             while their nodes enforce different validity rules"
        );
    }
}

/// EVERY entry in the registry moves the digest.
///
/// The per-constant test above names the ones that matter most; this one refuses
/// to let any entry be decorative. An entry folded into the preimage but read
/// from the wrong place — a copy-paste that folds `MAX_TITLE_LENGTH` twice and
/// `MAX_NAME_LENGTH` never — passes every test that only checks a few names.
#[test]
fn every_registered_constant_moves_the_protocol_digest() {
    let g = genesis(ChainParams::default());
    let ours = protocol_digest(&g).expect("our digest");

    let names: Vec<&'static str> = consensus_limits().into_iter().map(|(n, _)| n).collect();
    assert!(
        names.len() >= 30,
        "the registry holds only {} entries, which means it shrank rather than \
         that the constants disappeared",
        names.len()
    );

    for name in names {
        let theirs =
            protocol_digest_with_limits(&g, &limits_with_changed(name)).expect("their digest");
        assert_ne!(
            ours, theirs,
            "{name} is in the registry but changing it does not change the \
             digest, so it is folded from the wrong source or not folded at all"
        );
    }
}

/// No two entries share a name.
///
/// A duplicated name is the failure mode that makes the previous test pass while
/// the digest is still blind: `limits_with_changed` would edit both copies, the
/// digest would move, and the constant the second copy was SUPPOSED to name
/// would be uncovered.
#[test]
fn the_registry_has_no_duplicate_names() {
    let limits = consensus_limits();
    let mut names: Vec<&str> = limits.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        before,
        names.len(),
        "the consensus limit registry contains a duplicated name; one of the \
         two constants it was meant to cover is not covered"
    );
}

/// Reordering the registry changes the digest, and the digest is a function of
/// the pair `(genesis, limits)` and nothing else.
#[test]
fn the_digest_is_a_function_of_the_genesis_and_the_limits() {
    let g = genesis(ChainParams::default());

    assert_eq!(
        protocol_digest(&g).expect("digest"),
        protocol_digest(&g).expect("digest"),
        "recomputation must be stable or operators comparing it learn nothing"
    );

    // Two identically-configured genesis files on the same binary agree.
    assert_eq!(
        protocol_digest(&genesis(ChainParams::default())).expect("digest"),
        protocol_digest(&genesis(ChainParams::default())).expect("digest"),
    );

    // A permuted registry is a different digest. This is why the declared order
    // is documented as frozen: a reordering is not a rule change, so it must
    // never be mistaken for one in the other direction either — the test exists
    // so the ordering is deliberate rather than incidental.
    let mut reordered = consensus_limits();
    reordered.swap(0, 1);
    assert_ne!(
        protocol_digest(&g).expect("digest"),
        protocol_digest_with_limits(&g, &reordered).expect("digest"),
        "the fold must be order-sensitive, or a registry whose order drifts \
         between binaries would hide a real difference behind a cancellation"
    );
}

/// The activation heights still move the digest — the coverage is inherited,
/// not replaced.
///
/// The defect this work closes is an activation height mismatch. Folding the
/// activation digest in whole is what keeps that covered here; if a refactor
/// dropped it, this file would still pass every test above while the original
/// defect walked straight back in.
#[test]
fn an_activation_height_difference_still_moves_the_protocol_digest() {
    let a = ChainParams {
        healthcare_authorization_enabled_from_height: Some(6),
        ..Default::default()
    };
    let b = ChainParams {
        healthcare_authorization_enabled_from_height: Some(7),
        ..Default::default()
    };

    let ga = genesis(a);
    let gb = genesis(b);

    assert_ne!(
        ga.activation_digest().expect("digest"),
        gb.activation_digest().expect("digest"),
        "precondition: the activation digest sees this"
    );
    assert_ne!(
        protocol_digest(&ga).expect("digest"),
        protocol_digest(&gb).expect("digest"),
        "a one-digit activation height difference must still move the protocol \
         digest; the limits were ADDED to the comparison, not substituted for it"
    );
}

/// The two digests are different values and must never be compared against each
/// other.
///
/// They answer different questions, they are published side by side, and a
/// monitor that compared one node's activation digest against another's protocol
/// digest would report a permanent false mismatch. The domain separator is what
/// guarantees they cannot collide.
#[test]
fn the_protocol_digest_is_not_the_activation_digest() {
    let g = genesis(ChainParams::default());
    assert_ne!(
        g.activation_digest().expect("digest"),
        protocol_digest(&g).expect("digest"),
        "the protocol digest must be domain-separated from the activation \
         digest it contains"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// `MAX_BLOCK_WRITE_SET_BYTES` — the 256 MiB constant, by NAME and by VALUE
//
// The condition for accepting a 256 MiB compiled-in ceiling this release is that
// its value is covered by MANDATORY compatibility enforcement — that two
// binaries built with different ceilings cannot handshake and conclude they
// agree. "It is in the registry" is not that claim; the registry is a list, and
// a list can hold an entry folded from the wrong source, under a name nothing
// checks, at a value nothing reads.
//
// So the three halves are separated below: the entry is the constant the
// executor enforces, a DIFFERENT VALUE moves the digest, and a DIFFERENT NAME
// moves it too.
// ═════════════════════════════════════════════════════════════════════════════

/// The ceiling this release ships, named here so the assertions below are about
/// a number and not about an expression that changes with it.
const RELEASE_CEILING: u128 = 1 << 28;

/// The registry entry IS the constant the executor enforces, at the value this
/// release ships, exactly once.
///
/// `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES` is what
/// `BlockExecutor::compute_block_state_root` hands `CandidateExecution::new`
/// (`crates/state/src/executor.rs:3122`) on the production `execute_block` path,
/// ungated, today. Two binaries with different ceilings disagree about whether a
/// large block is applicable at the current height — not at some future one —
/// which is why this entry exists at all.
///
/// Asserted as an identity against the constant rather than against a literal
/// alone, so that editing the ceiling cannot leave the digest folding the old
/// number; and against the literal as well, so that editing the ceiling is a
/// decision someone has to come here and make.
#[test]
fn the_block_write_set_ceiling_is_in_the_registry_as_the_constant_the_executor_enforces() {
    let hits: Vec<LimitValue> = consensus_limits()
        .into_iter()
        .filter(|(n, _)| *n == "MAX_BLOCK_WRITE_SET_BYTES")
        .map(|(_, v)| v)
        .collect();

    assert_eq!(
        hits.len(),
        1,
        "the ceiling must appear under exactly that name exactly once; {} \
         occurrences means either it is unnamed in the digest or it is folded \
         twice and one of the copies is free to drift",
        hits.len()
    );
    assert_eq!(
        hits[0],
        LimitValue::Num(sumchain_state::MAX_BLOCK_WRITE_SET_BYTES as u128),
        "the entry does not fold `sumchain_state::MAX_BLOCK_WRITE_SET_BYTES`, so \
         it folds something that can differ from the number the executor \
         enforces — which is the whole hazard, moved one level in"
    );
    assert_eq!(
        hits[0],
        LimitValue::Num(RELEASE_CEILING),
        "the ceiling is no longer the {RELEASE_CEILING}-byte (256 MiB) value this \
         test was written against. That is allowed, and it is a consensus change: \
         update this literal deliberately, and expect every peer on the old value \
         to be refused by the mechanism below"
    );
}

/// Two binaries differing ONLY in the block write-set ceiling report different
/// protocol digests — constructed, not asserted.
///
/// This is the comparison the two binaries would actually make at handshake.
/// `protocol_digest_with_limits` is the same function `protocol_digest` is, so
/// "the digest the other binary computed" is this function applied to the limit
/// set that binary was built with. Four neighbouring ceilings are used rather
/// than one: 128 MiB and 512 MiB are the values a halving or doubling produces,
/// 1 GiB is the value the `CANDIDATE_LIMIT_SCAFFOLD` this entry replaced
/// actually held, and one byte either side is the edit a careless patch makes.
///
/// The genesis file is byte-identical across all of them, and its activation
/// digest is asserted unchanged — so this difference is invisible to the
/// comparison operators were told to perform before this digest existed.
#[test]
fn two_binaries_disagreeing_only_about_the_block_write_set_ceiling_cannot_handshake() {
    let g = genesis(ChainParams::default());
    let ours = protocol_digest(&g).expect("our digest");
    let activation = g.activation_digest().expect("activation digest");

    let mut seen = vec![ours];
    for other in [
        RELEASE_CEILING - 1,
        RELEASE_CEILING + 1,
        RELEASE_CEILING / 2, // 128 MiB
        RELEASE_CEILING * 2, // 512 MiB
        1 << 30,             // the 1 GiB scaffold this entry replaced
    ] {
        assert_ne!(other, RELEASE_CEILING);
        let limits: Vec<(&'static str, LimitValue)> = consensus_limits()
            .into_iter()
            .map(|(n, v)| {
                if n == "MAX_BLOCK_WRITE_SET_BYTES" {
                    (n, LimitValue::Num(other))
                } else {
                    (n, v)
                }
            })
            .collect();

        let theirs = protocol_digest_with_limits(&g, &limits).expect("their digest");
        assert_ne!(
            ours, theirs,
            "a binary built with a {other}-byte block write-set ceiling reports \
             the SAME protocol digest as this one. Its handshake with us would \
             succeed, and the two would then disagree about whether a large block \
             is applicable — a fork with no configuration difference anywhere for \
             an operator to find"
        );
        assert!(
            !seen.contains(&theirs),
            "two different ceilings folded to the same digest, so the fold is \
             lossy in exactly the range it has to be injective over"
        );
        seen.push(theirs);

        // The value operators were told to compare cannot see any of this.
        assert_eq!(
            activation,
            g.activation_digest().expect("activation digest"),
            "the genesis file is identical across these binaries; if the \
             activation digest moved, this test is changing the wrong thing"
        );
    }
}

/// The NAME is folded too: renaming the ceiling moves the digest even though
/// every value stays the same.
///
/// Without this, a binary that moved the 256 MiB number from
/// `MAX_BLOCK_WRITE_SET_BYTES` to some other entry — or that kept the name and
/// silently pointed it at a different constant of equal value — would report a
/// digest identical to ours while enforcing a different rule under it. The name
/// is what ties the folded number to the thing the executor reads, and
/// `protocol_digest_with_limits` folds `name_len ‖ name` before the value
/// precisely so that tie is part of the commitment.
#[test]
fn renaming_the_block_write_set_ceiling_moves_the_digest_with_its_value_unchanged() {
    let g = genesis(ChainParams::default());
    let ours = protocol_digest(&g).expect("our digest");

    for renamed in [
        "MAX_BLOCK_WRITE_SET_BYTES_V2",
        "MAX_BLOCK_WRITE_SET_BYTE", // one character shorter
        "MAX_BLOCK_WRITESET_BYTES",
    ] {
        let limits: Vec<(&'static str, LimitValue)> = consensus_limits()
            .into_iter()
            .map(|(n, v)| {
                if n == "MAX_BLOCK_WRITE_SET_BYTES" {
                    (renamed, v)
                } else {
                    (n, v)
                }
            })
            .collect();

        // Every VALUE is identical to ours — only the label moved.
        assert_eq!(
            limits.iter().find(|(n, _)| *n == renamed).map(|(_, v)| *v),
            Some(LimitValue::Num(
                sumchain_state::MAX_BLOCK_WRITE_SET_BYTES as u128
            )),
            "this test must change the name and nothing else"
        );

        let theirs = protocol_digest_with_limits(&g, &limits).expect("their digest");
        assert_ne!(
            ours, theirs,
            "renaming the ceiling to `{renamed}` left the digest unchanged, so \
             the digest commits to a bag of numbers and not to which rule each \
             number is. A binary that reused this slot for a different constant \
             of the same magnitude would be indistinguishable from us"
        );
    }
}
