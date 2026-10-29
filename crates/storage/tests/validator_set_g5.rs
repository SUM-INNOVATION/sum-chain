//! **G5 validator-set transitions (#266): semantics ratified 2026-10-21;
//! dormant; no values; not activated.**
//!
//! Tests for `validator_set_g5`. They cover:
//! * Q0, Q1, Q2, Q4 (N_min = 5, `max_validators` ≤ 29,127) and Q5;
//! * the named exceptions to the missing-row rule, S1(a) and S2(a);
//! * the derived properties (overflow, who certifies a transition block,
//!   stored rows);
//! * the wiring's API (#351): the configuration, the executor's one call per
//!   block, Q2 before any row is read, the certified height, restart and a
//!   replacement branch's rows;
//! * dormancy: nothing outside this crate names the module yet.
//!
//! Nothing here activates dynamic membership or selects an epoch length,
//! activation height, stake minimum or `max_validators`. Every schedule below
//! is synthetic, as is all data.

use std::path::{Path, PathBuf};

use sumchain_primitives::{
    Block, BlockHeader, DelegationInfo, Hash, ValidatorInfo, ValidatorSet, ValidatorSetEntry,
    ValidatorStatus,
};
use sumchain_storage::branch::BranchState;
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
};
use sumchain_storage::certified::FinalizedPointer;
use sumchain_storage::certified_meta::{certificate_key, encode_pointer, FINALIZED_POINTER_KEY};
use sumchain_storage::db::{cf, Database};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::journal::ApplicationJournal;
use sumchain_storage::schema::{
    encode_delegation, encode_delegator_list, encode_validator, DelegationStore, StakingStore,
    ValidatorSetStore, ACCOUNT_KEY_PREFIX,
};
use sumchain_storage::validator_set_g5::{
    certified_height, check_restart, check_stored_rows, governing_set, read_candidates,
    read_candidates_in, require_transition_certified, resolve_set, select_members,
    stage_boundary_row, stage_transition_row, BranchRows, Candidate, EpochSchedule, G5Error,
    G5Membership, RowlessEpoch, Selection, StagedTransition, VsetLayout, EFFECTIVE_VALIDATOR_CAP,
};
use sumchain_storage::validator_set_record::ValidatorSetRecord;
use sumchain_storage::validator_set_state::StateError;
use tempfile::TempDir;

const LIMIT: u64 = 1 << 22;
/// N_min = 5, ratified 2026-10-21 (the product minimum). The module takes it as
/// a parameter; the wiring passes `pool_topology::PRODUCT_MINIMUM`.
const RATIFIED_N_MIN: usize = 5;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    (Database::open_default(dir.path()).unwrap(), dir)
}

fn key(b: u8) -> [u8; 32] {
    [b; 32]
}

fn genesis() -> Vec<[u8; 32]> {
    (1..=5).map(key).collect()
}

/// A synthetic schedule active from genesis (A = 0).
fn from_genesis(l: u64) -> EpochSchedule {
    EpochSchedule::new(l, 0).unwrap()
}

fn block(parent: Hash, height: u64, tag: u64) -> Block {
    let header = BlockHeader::new(
        parent,
        height,
        1_000 + tag,
        Hash::hash(&tag.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    Block::new(header, Vec::new())
}

fn journals() -> BlockJournals {
    BlockJournals {
        account: JournalRecord::NothingToUndo,
        contract: JournalRecord::NothingToUndo,
        compute_pool: JournalRecord::NothingToUndo,
        beacon: JournalRecord::NothingToUndo,
    }
}

/// Execute `members` as block `height`'s transition row and publish the block.
fn publish_transition(
    d: &Database,
    parent: Hash,
    height: u64,
    s: &EpochSchedule,
    members: Vec<[u8; 32]>,
) -> Result<Block, String> {
    let b = block(parent, height, height);
    let mut cand = CandidateExecution::new(d, LIMIT);
    {
        let mut view = cand.view();
        stage_transition_row(&mut view, height, s, members).map_err(|e| e.to_string())?;
    }
    cand.finish_execution(
        ExecutionSubject::of(&b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(&b)
    .map_err(|e| e.to_string())?
    .publish()
    .map_err(|e| e.to_string())?;
    Ok(b)
}

/// Execute and publish an ordinary block that writes no validator-set row.
fn publish_plain(d: &Database, parent: Hash, height: u64) -> Block {
    let b = block(parent, height, height);
    let mut c = CandidateExecution::new(d, LIMIT);
    let _ = c.view();
    c.finish_execution(
        ExecutionSubject::of(&b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(&b)
    .unwrap()
    .publish()
    .unwrap();
    b
}

/// Publish ordinary blocks `from..to` on top of `parent`; returns the new tip.
fn publish_plain_range(d: &Database, mut parent: Hash, from: u64, to: u64) -> Hash {
    for h in from..to {
        parent = publish_plain(d, parent, h).hash();
    }
    parent
}

fn cand(b: u8, total: u128) -> Candidate {
    Candidate {
        pubkey: key(b),
        active: true,
        jailed: false,
        self_stake: total,
        delegated: 0,
    }
}

// ── Q1: which blocks write, and which epoch ─────────────────────────────────

#[test]
fn q1_only_the_last_block_of_an_epoch_writes_the_next_epochs_row() {
    // L = 1 is S1(a) (below): there block 0 would be a transition block.
    for l in [2u64, 3, 4, 10] {
        let s = from_genesis(l);
        for t in 0..(5 * l) {
            let expected = ((t + 1) % l == 0).then_some((t + 1) / l);
            assert_eq!(s.transition_epoch(t).unwrap(), expected, "L={l} T={t}");
            if let Some(e) = expected {
                assert!(e >= 1, "epoch 0 is never written (it is genesis)");
            }
        }
    }
}

#[test]
fn q1_protocol_v1_epoch_length_zero_has_no_schedule() {
    for a in [0u64, 1, 7, u64::MAX] {
        let err = EpochSchedule::new(0, a).unwrap_err();
        assert!(matches!(err, G5Error::StaticMembership));
        assert!(err.to_string().contains("epoch_length is 0"), "{err}");
    }
}

// ── Q0: the set in T's post-state governs T+1 onward ────────────────────────

#[test]
fn q0_the_row_written_by_block_t_governs_from_t_plus_one() {
    let s = from_genesis(4);
    for t in 0..40u64 {
        if let Some(e) = s.transition_epoch(t).unwrap() {
            // The first height the new epoch governs is exactly T+1, and the
            // last height of the previous epoch is T itself.
            assert_eq!(s.governing_epoch(t + 1), e);
            assert_eq!(s.governing_epoch(t), e - 1);
        }
    }
}

#[test]
fn q0_q1_resolution_reads_genesis_then_required_rows() {
    let (d, _t) = db();
    let l = 4;
    let s = from_genesis(l);
    let g = genesis();
    // Heights below L are governed by the genesis list.
    for h in 0..l {
        assert_eq!(resolve_set(&d, &g, h, &s).unwrap(), g);
    }
    // Height L needs row[1], written by block L-1; it is missing: an error,
    // never a genesis fallback.
    assert!(matches!(resolve_set(&d, &g, l, &s), Err(G5Error::Row(_))));

    // Publish blocks 1..=3; block 3 (= L-1) writes row[1].
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, l - 1);
    let next: Vec<[u8; 32]> = (11..=16).map(key).collect();
    publish_transition(&d, parent, l - 1, &s, next.clone()).unwrap();
    for h in l..2 * l {
        assert_eq!(resolve_set(&d, &g, h, &s).unwrap(), next, "h={h}");
    }
    // Epoch 2 is still missing.
    assert!(resolve_set(&d, &g, 2 * l, &s).is_err());
}

#[test]
fn q1_a_non_transition_block_cannot_write_and_a_row_is_written_once() {
    let (d, _t) = db();
    let s = from_genesis(4);
    let parent = block(Hash::ZERO, 0, 0).hash();
    let err = publish_transition(&d, parent, 2, &s, genesis()).unwrap_err();
    assert!(err.contains("not a transition block"), "{err}");

    let b3 = publish_transition(&d, parent, 3, &s, genesis()).unwrap();
    // A competing block 3 executing over the same committed state would find
    // row[1] occupied: each epoch's row is written once.
    let again = publish_transition(&d, b3.hash(), 3, &s, genesis()).unwrap_err();
    assert!(again.contains("already stored"), "{again}");
}

#[test]
fn q0_a_corrupt_or_foreign_row_is_refused() {
    let (d, _t) = db();
    let l = 4;
    let s = from_genesis(l);
    let g = genesis();
    // A row stored under epoch 1's key that encodes epoch 2.
    let foreign = ValidatorSetRecord::new(2, g.clone()).unwrap();
    d.put(cf::STATE, &VsetLayout::row_key(1), &foreign.encode())
        .unwrap();
    assert!(resolve_set(&d, &g, l, &s).is_err());
    // Garbage bytes.
    d.put(cf::STATE, &VsetLayout::row_key(1), b"not a row")
        .unwrap();
    assert!(resolve_set(&d, &g, l, &s).is_err());
}

// ── Q2: governs only once the transition block is certified ────────────────

#[test]
fn q2_a_set_governs_only_after_its_transition_block_is_certified() {
    let l = 4;
    let s = from_genesis(l);
    // Genesis epoch needs nothing.
    for h in 0..l {
        require_transition_certified(h, &s, None).unwrap();
    }
    // Epoch 1 (heights 4..8) is written by block 3.
    for h in l..2 * l {
        assert!(require_transition_certified(h, &s, None).is_err());
        assert!(require_transition_certified(h, &s, Some(2)).is_err());
        require_transition_certified(h, &s, Some(3)).unwrap();
        require_transition_certified(h, &s, Some(100)).unwrap();
    }
    // Epoch 2 (heights 8..12) needs block 7 certified.
    assert!(require_transition_certified(8, &s, Some(6)).is_err());
    require_transition_certified(8, &s, Some(7)).unwrap();
}

// ── Q4: selection ───────────────────────────────────────────────────────────

#[test]
fn q4_orders_by_total_descending_then_pubkey_ascending() {
    let cands = [
        cand(9, 50),
        cand(3, 100),
        cand(7, 100),
        cand(1, 70),
        cand(5, 100),
        cand(2, 60),
    ];
    let s = select_members(&cands, 0, 10, RATIFIED_N_MIN, &genesis()).unwrap();
    assert_eq!(
        s,
        Selection::Selected(vec![key(3), key(5), key(7), key(1), key(2), key(9)])
    );
}

#[test]
fn q4_filters_inactive_jailed_and_below_minimum_and_counts_delegations() {
    let mut cands: Vec<Candidate> = (1..=7).map(|b| cand(b, 100)).collect();
    cands[0].active = false;
    cands[1].jailed = true;
    cands[2].self_stake = 40; // below 50
    cands[3].self_stake = 20;
    cands[3].delegated = 30; // 20 + 30 = 50: eligible
    let s = select_members(&cands, 50, 10, 4, &genesis()).unwrap();
    assert_eq!(s.members(), &[key(5), key(6), key(7), key(4)]);
}

#[test]
fn q4_truncates_to_max_validators() {
    let cands: Vec<Candidate> = (1..=9).map(|b| cand(b, 100 + u128::from(b))).collect();
    let s = select_members(&cands, 0, 6, RATIFIED_N_MIN, &genesis()).unwrap();
    assert_eq!(
        s.members(),
        &[key(9), key(8), key(7), key(6), key(5), key(4)]
    );
}

#[test]
fn q4_below_n_min_the_previous_set_carries_forward_never_genesis() {
    let previous: Vec<[u8; 32]> = (21..=26).map(key).collect();
    let cands: Vec<Candidate> = (1..=4).map(|b| cand(b, 100)).collect();
    let s = select_members(&cands, 0, 10, RATIFIED_N_MIN, &previous).unwrap();
    assert_eq!(
        s,
        Selection::CarriedForward {
            members: previous.clone(),
            eligible: 4
        }
    );
    assert_ne!(s.members(), genesis().as_slice());
    // Exactly N_min eligible: a new set.
    let cands: Vec<Candidate> = (1..=5).map(|b| cand(b, 100)).collect();
    assert!(matches!(
        select_members(&cands, 0, 10, RATIFIED_N_MIN, &previous).unwrap(),
        Selection::Selected(_)
    ));
    // No previous set to carry: refused.
    assert!(matches!(
        select_members(&[], 0, 10, RATIFIED_N_MIN, &[]),
        Err(G5Error::EmptyPrevious)
    ));
}

#[test]
fn q4_a_duplicated_staking_entry_is_refused_not_counted_twice() {
    let cands = [
        cand(1, 100),
        cand(1, 100),
        cand(2, 90),
        cand(3, 80),
        cand(4, 70),
    ];
    assert!(matches!(
        select_members(&cands, 0, 10, 2, &genesis()),
        Err(G5Error::Record(_))
    ));
}

// ── Q5: layout ──────────────────────────────────────────────────────────────

#[test]
fn q5_rows_live_in_state_under_vset_and_never_in_the_account_range() {
    use sumchain_storage::validator_set_state::ValidatorSetLayout;
    for e in [0u64, 1, 2, 255, 256, u64::MAX] {
        let (family, k) = VsetLayout.row_location(e);
        assert_eq!(family, cf::STATE);
        assert_eq!(&k[..5], b"vset/");
        assert_eq!(&k[5..], &e.to_be_bytes());
        assert!(!k.starts_with(ACCOUNT_KEY_PREFIX));
        assert!(!ACCOUNT_KEY_PREFIX.starts_with(&k[..ACCOUNT_KEY_PREFIX.len().min(k.len())]));
    }
    // Keys sort by epoch.
    assert!(VsetLayout::row_key(1) < VsetLayout::row_key(2));
    assert!(VsetLayout::row_key(255) < VsetLayout::row_key(256));
}

// ── S1(a): L = 1, the boundary at genesis ───────────────────────────────────

#[test]
fn s1_l1_the_genesis_block_never_transitions_and_block_1_writes_row_2() {
    let (d, _t) = db();
    let s = from_genesis(1);
    let g = genesis();
    assert_eq!((s.first_dynamic_block(), s.anchor_epoch()), (1, 1));
    // Read literally, Q1 would make block 0 write row[1]; block 0 is never
    // executed, so it is not a transition block and epochs 0 and 1 are rowless.
    assert_eq!(s.rowless(0), Some(RowlessEpoch::Genesis));
    assert_eq!(
        s.rowless(1),
        Some(RowlessEpoch::GenesisBlockNeverTransitions)
    );
    assert_eq!(s.rowless(2), None);
    assert_eq!(s.transition_epoch(0).unwrap(), None);
    assert_eq!(s.transition_block(1).unwrap(), None);
    assert_eq!(s.transition_epoch(1).unwrap(), Some(2));
    assert_eq!(s.transition_block(2).unwrap(), Some(1));
    let genesis_hash = block(Hash::ZERO, 0, 0).hash();
    let err = publish_transition(&d, genesis_hash, 0, &s, g.clone()).unwrap_err();
    assert!(err.contains("not a transition block"), "{err}");

    // Heights 0 and 1 run on the genesis list with no row and no certificate.
    for h in 0..=1 {
        assert_eq!(resolve_set(&d, &g, h, &s).unwrap(), g);
        require_transition_certified(h, &s, None).unwrap();
    }
    // Block 1 writes row[2]; height 2 needs it and needs block 1 certified.
    let next: Vec<[u8; 32]> = (11..=15).map(key).collect();
    let b1 = publish_transition(&d, genesis_hash, 1, &s, next.clone()).unwrap();
    assert_eq!(resolve_set(&d, &g, 2, &s).unwrap(), next);
    assert!(require_transition_certified(2, &s, None).is_err());
    assert!(require_transition_certified(2, &s, Some(0)).is_err());
    require_transition_certified(2, &s, Some(1)).unwrap();
    // With L = 1 every later block writes the next row: height 3 needs row[3].
    assert!(resolve_set(&d, &g, 3, &s).is_err());
    let after: Vec<[u8; 32]> = (21..=25).map(key).collect();
    publish_transition(&d, b1.hash(), 2, &s, after.clone()).unwrap();
    assert_eq!(resolve_set(&d, &g, 3, &s).unwrap(), after);

    // L = 1 activated later: block A is the first transition and writes row[A+1].
    let s = EpochSchedule::new(1, 9).unwrap();
    assert_eq!(s.anchor_epoch(), 9);
    assert_eq!(s.transition_epoch(8).unwrap(), None);
    assert_eq!(s.transition_epoch(9).unwrap(), Some(10));
}

// ── Derived: checked arithmetic ─────────────────────────────────────────────

#[test]
fn overflow_t_plus_one_is_checked_and_a_block_at_u64_max_is_refused() {
    for l in [1u64, 2, 3, 4, 1 << 32, 1 << 63, u64::MAX] {
        for a in [0u64, 1, u64::MAX] {
            let s = EpochSchedule::new(l, a).unwrap();
            assert!(
                matches!(
                    s.transition_epoch(u64::MAX),
                    Err(G5Error::HeightOverflow { height: u64::MAX })
                ),
                "L={l} A={a}"
            );
        }
    }
    // The largest representable transitions are found without overflow.
    assert_eq!(
        from_genesis(1).transition_epoch(u64::MAX - 1).unwrap(),
        Some(u64::MAX)
    );
    assert_eq!(
        from_genesis(u64::MAX)
            .transition_epoch(u64::MAX - 1)
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        from_genesis(1 << 63)
            .transition_epoch((1 << 63) - 1)
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        from_genesis(2).transition_epoch(u64::MAX - 1).unwrap(),
        None
    );
    // A block at u64::MAX cannot stage a row.
    let (d, _t) = db();
    let mut c = CandidateExecution::new(&d, LIMIT);
    let mut view = c.view();
    let err = stage_transition_row(&mut view, u64::MAX, &from_genesis(2), genesis()).unwrap_err();
    assert!(
        matches!(err, G5Error::HeightOverflow { height: u64::MAX }),
        "{err}"
    );
}

#[test]
fn overflow_e_times_l_minus_one_is_checked() {
    let overflow = |s: EpochSchedule, e: u64| matches!(s.transition_block(e), Err(G5Error::EpochOverflow { epoch, .. }) if epoch == e);
    assert!(overflow(from_genesis(2), u64::MAX));
    assert!(overflow(from_genesis(u64::MAX), 2));
    assert!(overflow(from_genesis(3), u64::MAX / 3 + 1));
    assert_eq!(
        from_genesis(u64::MAX).transition_block(1).unwrap(),
        Some(u64::MAX - 1)
    );
    assert_eq!(
        from_genesis(1).transition_block(u64::MAX).unwrap(),
        Some(u64::MAX - 1)
    );
    assert_eq!(
        from_genesis(3).transition_block(u64::MAX / 3).unwrap(),
        Some(u64::MAX - 1)
    );
    // Every height has a governing epoch whose transition block is
    // representable and round-trips, so Q2 never overflows or panics.
    for l in [1u64, 2, 3, 4, 1 << 32, 1 << 63, u64::MAX] {
        for a in [0u64, 1, 12_345, u64::MAX - 1] {
            let s = EpochSchedule::new(l, a).unwrap();
            for h in [0u64, 1, l - 1, l, u64::MAX - 1, u64::MAX] {
                let e = s.governing_epoch(h);
                if let Some(t) = s.transition_block(e).unwrap() {
                    assert!(t < h, "L={l} A={a} h={h}");
                    assert_eq!(s.transition_epoch(t).unwrap(), Some(e));
                }
                require_transition_certified(h, &s, h.checked_sub(1)).unwrap();
            }
        }
    }
}

// ── S2(a): activation after genesis ─────────────────────────────────────────

/// S1, S2 and the certifying set over every small schedule, against the closed
/// forms.
#[test]
fn s2_every_small_schedule_anchors_the_epoch_containing_activation() {
    for l in 1u64..=6 {
        for a in 0u64..=20 {
            let s = EpochSchedule::new(l, a).unwrap();
            let f = a.max(1);
            let anchor = f / l;
            assert_eq!((s.first_dynamic_block(), s.anchor_epoch()), (f, anchor));
            for t in 0u64..80 {
                // Only executed blocks under the rules transition; block 0
                // and every block before activation never do.
                let want = (t >= f && (t + 1) % l == 0).then_some((t + 1) / l);
                let got = s.transition_epoch(t).unwrap();
                assert_eq!(got, want, "L={l} A={a} T={t}");
                if let Some(e) = got {
                    assert!(e > anchor, "never an anchor epoch's row");
                    assert_eq!(s.transition_block(e).unwrap(), Some(t));
                    // T is governed (so certified) by the preceding epoch.
                    assert_eq!(s.governing_epoch(t), e - 1);
                    assert_eq!(s.governing_epoch(t + 1), e);
                }
            }
            for e in 0..=anchor + 2 {
                // The three named exceptions, and nothing else, are rowless.
                let want = if e == 0 {
                    Some(RowlessEpoch::Genesis)
                } else if e > anchor {
                    None
                } else if l == 1 && e == 1 {
                    Some(RowlessEpoch::GenesisBlockNeverTransitions)
                } else {
                    Some(RowlessEpoch::ActivationAnchor)
                };
                assert_eq!(s.rowless(e), want, "L={l} A={a} e={e}");
                assert_eq!(s.transition_block(e).unwrap().is_none(), want.is_some());
            }
            if a == 0 && l >= 2 {
                assert!((1..=anchor + 2).all(|e| s.rowless(e).is_none()));
            }
            // The first transition block is the first boundary at or after F,
            // and every height up to it is governed by an anchor epoch.
            let first = s.transition_block(anchor + 1).unwrap().unwrap();
            assert!(first >= f && first - f < l, "L={l} A={a} first={first}");
            assert_eq!(s.governing_epoch(first), anchor);
            assert_eq!(s.governing_epoch(first + 1), anchor + 1);
            // A = 0 with L ≥ 2 is exactly the ledger's Q1.
            if a == 0 && l >= 2 {
                assert_eq!(anchor, 0);
                for t in 0u64..80 {
                    let ledger = ((t + 1) % l == 0).then_some((t + 1) / l);
                    assert_eq!(s.transition_epoch(t).unwrap(), ledger);
                }
            }
        }
    }
}

#[test]
fn s2_activation_between_boundaries_writes_nothing_and_the_first_transition_writes_the_first_row() {
    let (d, _t) = db();
    let g = genesis();
    // Synthetic: L = 10, activation at 25, between the boundaries 20 and 30.
    let s = EpochSchedule::new(10, 25).unwrap();
    assert_eq!(s.anchor_epoch(), 2);
    // A static chain up to activation: ordinary blocks, no rows.
    let tip = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 25);
    check_stored_rows(&d, &s).unwrap();
    // Block 19, epoch 2's transition block under Q1, ran before activation and
    // could not have written row[2].
    let err = publish_transition(&d, tip, 19, &s, g.clone()).unwrap_err();
    assert!(err.contains("not a transition block"), "{err}");
    // Activation writes nothing; heights through 29 run on the genesis list
    // with no row and no certificate requirement.
    let tip = publish_plain_range(&d, tip, 25, 29);
    for h in 0..30 {
        assert_eq!(resolve_set(&d, &g, h, &s).unwrap(), g, "h={h}");
        require_transition_certified(h, &s, None).unwrap();
    }
    assert!(
        resolve_set(&d, &g, 30, &s).is_err(),
        "row[3] is not written yet"
    );
    // Block 29 is the first transition: Q4 over its post-state, with the
    // genesis list as `previous`, writes row[3].
    let cands: Vec<Candidate> = (31..=36).map(|b| cand(b, 100)).collect();
    let selected = select_members(&cands, 0, 10, RATIFIED_N_MIN, &g).unwrap();
    publish_transition(&d, tip, 29, &s, selected.members().to_vec()).unwrap();
    for h in 30..40 {
        assert_eq!(
            resolve_set(&d, &g, h, &s).unwrap(),
            selected.members(),
            "h={h}"
        );
    }
    // Block 29 is certified by the anchor membership, not by the row it wrote.
    assert_eq!(resolve_set(&d, &g, 29, &s).unwrap(), g);
    assert!(require_transition_certified(30, &s, Some(28)).is_err());
    require_transition_certified(30, &s, Some(29)).unwrap();
    // Too few eligible at the first transition: the genesis list carries
    // forward (it is the previous set), never an invented set.
    let few: Vec<Candidate> = (31..=34).map(|b| cand(b, 100)).collect();
    assert_eq!(
        select_members(&few, 0, 10, RATIFIED_N_MIN, &g).unwrap(),
        Selection::CarriedForward {
            members: g.clone(),
            eligible: 4
        }
    );
    check_stored_rows(&d, &s).unwrap();

    // Activation exactly on a boundary: the whole epoch is an anchor.
    let s = EpochSchedule::new(10, 30).unwrap();
    assert_eq!(s.anchor_epoch(), 3);
    assert_eq!(s.transition_epoch(29).unwrap(), None);
    assert_eq!(s.transition_block(4).unwrap(), Some(39));
}

/// S1(a) and S2(a) with activation immediately before, exactly on and
/// immediately after a boundary, for L = 1 (around boundary 5) and L = 10
/// (around boundary 30), plus A = 0 for both. Every expectation is written out
/// by hand, not computed by the module.
#[test]
fn s1_s2_activation_immediately_before_exactly_on_and_after_a_boundary() {
    use RowlessEpoch::{ActivationAnchor as S2, Genesis as G0, GenesisBlockNeverTransitions as S1};
    struct Case {
        l: u64,
        a: u64,
        /// The rowless epochs 0, 1, … and which exception makes each rowless.
        rowless: &'static [RowlessEpoch],
        /// The block that writes the first row, and that row's epoch.
        first_block: u64,
        first_row: u64,
    }
    #[rustfmt::skip]
    let cases = [
        Case { l: 1, a: 0, rowless: &[G0, S1], first_block: 1, first_row: 2 },
        Case { l: 1, a: 4, rowless: &[G0, S1, S2, S2, S2], first_block: 4, first_row: 5 },
        Case { l: 1, a: 5, rowless: &[G0, S1, S2, S2, S2, S2], first_block: 5, first_row: 6 },
        Case { l: 1, a: 6, rowless: &[G0, S1, S2, S2, S2, S2, S2], first_block: 6, first_row: 7 },
        Case { l: 10, a: 0, rowless: &[G0], first_block: 9, first_row: 1 },
        Case { l: 10, a: 29, rowless: &[G0, S2, S2], first_block: 29, first_row: 3 },
        Case { l: 10, a: 30, rowless: &[G0, S2, S2, S2], first_block: 39, first_row: 4 },
        Case { l: 10, a: 31, rowless: &[G0, S2, S2, S2], first_block: 39, first_row: 4 },
    ];
    let g = genesis();
    for c in cases {
        let what = format!("L={} A={}", c.l, c.a);
        let s = EpochSchedule::new(c.l, c.a).unwrap();
        for (e, why) in c.rowless.iter().enumerate() {
            assert_eq!(s.rowless(e as u64), Some(*why), "{what} e={e}");
        }
        assert_eq!(s.rowless(c.first_row), None, "{what}");
        assert_eq!(c.rowless.len() as u64, c.first_row, "{what}");

        // No block before the first transition block writes: not block 0, and
        // not the Q1 boundary blocks that ran before activation.
        for t in 0..c.first_block {
            assert_eq!(s.transition_epoch(t).unwrap(), None, "{what} T={t}");
        }
        let (d, _t) = db();
        let tip = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, c.first_block);
        check_stored_rows(&d, &s).unwrap();
        // Through the first transition block the anchor membership governs,
        // with no row and no certificate.
        for h in 0..=c.first_block {
            assert_eq!(resolve_set(&d, &g, h, &s).unwrap(), g, "{what} h={h}");
            require_transition_certified(h, &s, None).unwrap();
        }
        // The first height outside the exceptions needs the first row: the
        // missing-row error fires here and not before.
        let after = c.first_block + 1;
        assert!(
            matches!(
                resolve_set(&d, &g, after, &s),
                Err(G5Error::Row(StateError::Missing { key })) if key == c.first_row
            ),
            "{what}"
        );
        // The first transition block writes it, by Q4 with the anchor
        // membership as `previous`; it governs from the next height once that
        // block is certified.
        let cands: Vec<Candidate> = (41..=46).map(|b| cand(b, 100)).collect();
        let next = select_members(&cands, 0, 10, RATIFIED_N_MIN, &g).unwrap();
        publish_transition(&d, tip, c.first_block, &s, next.members().to_vec()).unwrap();
        for h in after..after + c.l {
            assert_eq!(
                resolve_set(&d, &g, h, &s).unwrap(),
                next.members(),
                "{what} h={h}"
            );
        }
        assert!(require_transition_certified(after, &s, Some(c.first_block - 1)).is_err());
        require_transition_certified(after, &s, Some(c.first_block)).unwrap();
        // The epoch after it is outside the exceptions too.
        assert!(
            matches!(
                resolve_set(&d, &g, after + c.l, &s),
                Err(G5Error::Row(StateError::Missing { key })) if key == c.first_row + 1
            ),
            "{what}"
        );
        check_stored_rows(&d, &s).unwrap();
    }
}

#[test]
fn q4_max_validators_above_the_effective_cap_is_refused() {
    // The ratified bound is field 0x0003's: 4 + 36 · 29,127 = 2^20 exactly, so
    // one more validator does not fit; it is below the 65,535 vote cap.
    assert_eq!(EFFECTIVE_VALIDATOR_CAP, 29_127);
    assert_eq!(4 + 36 * EFFECTIVE_VALIDATOR_CAP, 1 << 20);
    let cands: Vec<Candidate> = (1..=6).map(|b| cand(b, 100)).collect();
    for max in [RATIFIED_N_MIN, 6, EFFECTIVE_VALIDATOR_CAP] {
        select_members(&cands, 0, max, RATIFIED_N_MIN, &genesis()).unwrap();
    }
    // Refused whatever the candidates would give, including a carry-forward.
    for max in [EFFECTIVE_VALIDATOR_CAP + 1, 65_535, usize::MAX] {
        for c in [&cands[..], &cands[..2]] {
            assert!(
                matches!(
                    select_members(c, 0, max, RATIFIED_N_MIN, &genesis()),
                    Err(G5Error::MaxValidatorsAboveCap { configured, cap: 29_127 })
                        if configured == max
                ),
                "max={max}"
            );
        }
    }
    // At the cap, one more eligible validator than fits is truncated away.
    let many: Vec<Candidate> = (0..=EFFECTIVE_VALIDATOR_CAP as u32)
        .map(|i| {
            let mut pubkey = [0u8; 32];
            pubkey[..4].copy_from_slice(&i.to_be_bytes());
            Candidate {
                pubkey,
                active: true,
                jailed: false,
                self_stake: 100,
                delegated: 0,
            }
        })
        .collect();
    let s = select_members(
        &many,
        0,
        EFFECTIVE_VALIDATOR_CAP,
        RATIFIED_N_MIN,
        &genesis(),
    )
    .unwrap();
    assert_eq!(s.members().len(), EFFECTIVE_VALIDATOR_CAP);
    assert_eq!(
        s.members().last(),
        Some(&many[EFFECTIVE_VALIDATOR_CAP - 1].pubkey)
    );
}

// ── Q5: stored rows ─────────────────────────────────────────────────────────

#[test]
fn q5_a_static_membership_database_passes_with_nothing_to_migrate() {
    let (d, _t) = db();
    publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 13);
    assert!(d.iter(cf::VALIDATOR_SETS).unwrap().next().is_none());
    for (l, a) in [(1, 0), (4, 0), (4, 13), (10, 7), (u64::MAX, 0)] {
        check_stored_rows(&d, &EpochSchedule::new(l, a).unwrap()).unwrap();
    }
}

#[test]
fn q5_any_entry_in_the_legacy_family_is_refused_whatever_its_bytes() {
    let s = from_genesis(4);
    // A real pre-#266 row, written through the legacy store.
    let (d, _t) = db();
    let legacy = ValidatorSet::new(1, 4, vec![ValidatorSetEntry::new(key(1), 10, 0)], [0; 32]);
    ValidatorSetStore::new(&d)
        .put_validator_set(&legacy)
        .unwrap();
    let err = check_stored_rows(&d, &s).unwrap_err();
    assert!(
        matches!(&err, G5Error::LegacyEpochSet { key } if key[..] == 1u64.to_be_bytes()),
        "{err}"
    );
    assert!(
        err.to_string().contains("resynchronize from genesis"),
        "{err}"
    );
    // An epoch-0 key, an undecodable value, a key of the wrong length, an
    // empty value: the scan reads keys only, so each one refuses.
    for (k, v) in [
        (0u64.to_be_bytes().to_vec(), b"x".to_vec()),
        (5u64.to_be_bytes().to_vec(), b"not bincode".to_vec()),
        (vec![7u8; 3], b"x".to_vec()),
        (9u64.to_be_bytes().to_vec(), Vec::new()),
    ] {
        let (d, _t) = db();
        d.put(cf::VALIDATOR_SETS, &k, &v).unwrap();
        let err = check_stored_rows(&d, &s).unwrap_err();
        assert!(
            matches!(&err, G5Error::LegacyEpochSet { key } if *key == k),
            "{err}"
        );
    }
}

#[test]
fn q5_rows_for_rowless_epochs_or_under_a_malformed_key_are_refused() {
    let row = |e: u64| ValidatorSetRecord::new(e, genesis()).unwrap().encode();
    for (l, a, e, why) in [
        (10, 25, 0, RowlessEpoch::Genesis),
        (10, 25, 1, RowlessEpoch::ActivationAnchor),
        (10, 25, 2, RowlessEpoch::ActivationAnchor),
        (1, 0, 1, RowlessEpoch::GenesisBlockNeverTransitions),
    ] {
        let s = EpochSchedule::new(l, a).unwrap();
        let (d, _t) = db();
        d.put(cf::STATE, &VsetLayout::row_key(e), &row(e)).unwrap();
        assert!(
            matches!(
                check_stored_rows(&d, &s),
                Err(G5Error::RowForRowlessEpoch { epoch, why: w }) if epoch == e && w == why
            ),
            "L={l} A={a} epoch {e}"
        );
    }
    let s = EpochSchedule::new(10, 25).unwrap();
    for len in [0usize, 7, 9] {
        let (d, _t) = db();
        let mut k = VsetLayout::prefix().to_vec();
        k.extend_from_slice(&vec![0xffu8; len]);
        d.put(cf::STATE, &k, b"x").unwrap();
        assert!(
            matches!(
                check_stored_rows(&d, &s),
                Err(G5Error::MalformedRowKey { .. })
            ),
            "suffix of {len} bytes"
        );
    }
    // Rows after the anchor, and neighbouring keys outside `vset/`, pass.
    let (d, _t) = db();
    for e in [3u64, 4] {
        d.put(cf::STATE, &VsetLayout::row_key(e), &row(e)).unwrap();
    }
    for k in [&b"vset"[..], b"vset0", b"vses/", ACCOUNT_KEY_PREFIX] {
        d.put(cf::STATE, k, b"x").unwrap();
    }
    check_stored_rows(&d, &s).unwrap();
}

// ── Derived: the preceding set certifies the transition block ───────────────

#[test]
fn certifier_a_transition_block_is_certified_by_the_set_before_the_one_it_writes() {
    let (d, _t) = db();
    let l = 4;
    let s = from_genesis(l);
    let g = genesis();
    let s1: Vec<[u8; 32]> = (11..=15).map(key).collect();
    let s2: Vec<[u8; 32]> = (21..=26).map(key).collect();
    let tip = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    let b3 = publish_transition(&d, tip, 3, &s, s1.clone()).unwrap();
    let tip = publish_plain_range(&d, b3.hash(), 4, 7);
    publish_transition(&d, tip, 7, &s, s2.clone()).unwrap();
    // After both rows exist: block 3 (writes row[1]) resolves to genesis,
    // block 7 (writes row[2]) to row[1]; each new set starts one height later.
    assert_eq!(resolve_set(&d, &g, 3, &s).unwrap(), g);
    assert_eq!(resolve_set(&d, &g, 4, &s).unwrap(), s1);
    assert_eq!(resolve_set(&d, &g, 7, &s).unwrap(), s1);
    assert_eq!(resolve_set(&d, &g, 8, &s).unwrap(), s2);
    // And row[e] governs only after the preceding set certified e·L − 1.
    assert!(require_transition_certified(8, &s, Some(6)).is_err());
    require_transition_certified(8, &s, Some(7)).unwrap();
}

// ── #351 wiring: the configuration ──────────────────────────────────────────

/// A synthetic configuration: L, A and `max_validators` as given, minimum
/// stake 1, N_min = 5, the synthetic genesis list as anchor.
fn membership(l: u64, a: u64, max_validators: usize) -> G5Membership {
    G5Membership::new(
        EpochSchedule::new(l, a).unwrap(),
        RATIFIED_N_MIN,
        max_validators,
        1,
        genesis(),
    )
    .unwrap()
}

/// Committed staking validators `keys`, each with self-stake 100.
fn seed_validators(d: &Database, keys: impl IntoIterator<Item = u8>) {
    let store = StakingStore::new(d);
    for b in keys {
        store
            .put_validator(&ValidatorInfo::new(key(b), 100, 0, 0))
            .unwrap();
    }
}

/// Execute block `height` the way the executor does, `before` standing in for
/// its transactions: then the one `stage_boundary_row` call, through the same
/// view. Publishes the block and returns what it staged.
fn publish_executed(
    d: &Database,
    parent: Hash,
    height: u64,
    m: &G5Membership,
    before: impl FnOnce(&mut ExecutionView<'_, '_>),
) -> (Block, Option<StagedTransition>) {
    let b = block(parent, height, height);
    let mut cand = CandidateExecution::new(d, LIMIT);
    let staged = {
        let mut view = cand.view();
        before(&mut view);
        stage_boundary_row(&mut view, height, m).unwrap()
    };
    cand.finish_execution(
        ExecutionSubject::of(&b).unwrap(),
        b.header.state_root,
        Vec::new(),
        journals(),
    )
    .accept_imported(&b)
    .unwrap()
    .publish()
    .unwrap();
    (b, staged)
}

/// The epochs of every stored `vset/` row, in order.
fn stored_epochs(d: &Database) -> Vec<u64> {
    let prefix = VsetLayout::prefix();
    d.iter_checked_from(cf::STATE, Some(prefix))
        .unwrap()
        .map(|e| e.unwrap().0.into_vec())
        .take_while(|k| k.starts_with(prefix))
        .map(|k| u64::from_be_bytes(k[prefix.len()..].try_into().unwrap()))
        .collect()
}

/// The five synthetic validators with the smallest keys among `keys`, in key
/// order: Q4's choice among equal totals.
fn smallest_five(keys: impl IntoIterator<Item = u8>) -> Vec<[u8; 32]> {
    let mut all: Vec<[u8; 32]> = keys.into_iter().map(key).collect();
    all.sort();
    all.truncate(5);
    all
}

#[test]
fn wiring_the_configuration_refuses_a_cap_above_29127_and_an_anchor_v1_cannot_run() {
    let s = from_genesis(4);
    assert!(matches!(
        G5Membership::new(s, RATIFIED_N_MIN, EFFECTIVE_VALIDATOR_CAP + 1, 1, genesis()),
        Err(G5Error::MaxValidatorsAboveCap {
            configured,
            cap: 29_127
        }) if configured == EFFECTIVE_VALIDATOR_CAP + 1
    ));
    for anchor in [Vec::new(), vec![key(1), key(2), key(1)]] {
        assert!(matches!(
            G5Membership::new(s, RATIFIED_N_MIN, 10, 1, anchor),
            Err(G5Error::Anchor(_))
        ));
    }
    let m = G5Membership::new(s, RATIFIED_N_MIN, EFFECTIVE_VALIDATOR_CAP, 7, genesis()).unwrap();
    assert_eq!(*m.schedule(), s);
    assert_eq!(
        (m.n_min(), m.max_validators(), m.min_stake()),
        (RATIFIED_N_MIN, EFFECTIVE_VALIDATOR_CAP, 7)
    );
    assert_eq!(m.anchor(), genesis().as_slice());
}

// ── #351 wiring: the publication batch (Q1, Q4) ─────────────────────────────

#[test]
fn wiring_only_transition_blocks_stage_a_row_and_only_their_publication_commits_it() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 5);
    let mut parent = block(Hash::ZERO, 0, 0).hash();
    for h in 1..=8u64 {
        if h == 3 || h == 7 {
            // Executed and dropped, never published: nothing reaches the
            // database.
            let mut cand = CandidateExecution::new(&d, LIMIT);
            let staged = stage_boundary_row(&mut cand.view(), h, &m).unwrap();
            assert!(staged.is_some(), "h={h}");
            drop(cand);
            assert_eq!(stored_epochs(&d), if h == 3 { vec![] } else { vec![1] });
        }
        let (b, staged) = publish_executed(&d, parent, h, &m, |_| {});
        parent = b.hash();
        match h {
            3 | 7 => {
                let staged = staged.unwrap();
                assert_eq!(staged.epoch, (h + 1) / 4);
                assert!(matches!(staged.selection, Selection::Selected(_)));
            }
            _ => assert!(staged.is_none(), "h={h}"),
        }
        let want: Vec<u64> = match h {
            1..=2 => vec![],
            3..=6 => vec![1],
            _ => vec![1, 2],
        };
        assert_eq!(stored_epochs(&d), want, "after block {h}");
    }
    // Q4 over equal totals: the smallest keys, in key order.
    assert_eq!(
        governing_set(&d, 4, &m, Some(3)).unwrap(),
        smallest_five(31..=36)
    );
    check_stored_rows(&d, m.schedule()).unwrap();
}

#[test]
fn wiring_q4_reads_the_blocks_own_post_state_not_committed_state() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 5);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    // From committed state alone, key(36) would be left out.
    let committed = select_members(
        &read_candidates(&d).unwrap(),
        1,
        5,
        RATIFIED_N_MIN,
        &genesis(),
    )
    .unwrap();
    assert!(!committed.members().contains(&key(36)));
    // The block's own writes: a delegation of 1,000 to key(36), and key(31)
    // jailed.
    let (_b, staged) = publish_executed(&d, parent, 3, &m, |view| {
        let delegator = key(90);
        let delegation = DelegationInfo::new(delegator, key(36), 1_000, 3);
        view.put(
            cf::DELEGATIONS,
            &DelegationStore::delegation_key(&delegator, &key(36)),
            &encode_delegation(&delegation).unwrap(),
        )
        .unwrap();
        view.put(
            cf::DELEGATION_VALIDATOR_INDEX,
            &key(36),
            &encode_delegator_list(&vec![delegator]).unwrap(),
        )
        .unwrap();
        let mut jailed = ValidatorInfo::new(key(31), 100, 0, 0);
        jailed.status = ValidatorStatus::Jailed;
        view.put(
            cf::VALIDATORS,
            &key(31),
            &encode_validator(&jailed).unwrap(),
        )
        .unwrap();
        // The view sees both; committed state sees neither.
        let in_view = read_candidates_in(view).unwrap();
        assert!(in_view
            .iter()
            .any(|c| c.pubkey == key(36) && c.delegated == 1_000));
        assert!(in_view.iter().any(|c| c.pubkey == key(31) && c.jailed));
    });
    let want = vec![key(36), key(32), key(33), key(34), key(35)];
    assert_eq!(staged.unwrap().selection, Selection::Selected(want.clone()));
    assert_eq!(governing_set(&d, 4, &m, Some(3)).unwrap(), want);
}

#[test]
fn wiring_below_n_min_the_previous_set_carries_forward_the_anchor_only_at_the_first() {
    let (d, _t) = db();
    seed_validators(&d, 31..=34);
    let m = membership(4, 0, 10);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    // The first transition: four eligible, so the anchor carries forward.
    let (_, staged) = publish_executed(&d, parent, 3, &m, |_| {});
    assert_eq!(
        staged.unwrap().selection,
        Selection::CarriedForward {
            members: genesis(),
            eligible: 4
        }
    );
    assert_eq!(governing_set(&d, 4, &m, Some(3)).unwrap(), genesis());

    // A selected set, then too few again: that set carries forward, never the
    // anchor.
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    let (b3, _) = publish_executed(&d, parent, 3, &m, |_| {});
    let row1 = governing_set(&d, 4, &m, Some(3)).unwrap();
    assert_ne!(row1, genesis());
    let parent = publish_plain_range(&d, b3.hash(), 4, 7);
    let (_, staged) = publish_executed(&d, parent, 7, &m, |view| {
        for b in [33u8, 34] {
            let mut v = ValidatorInfo::new(key(b), 100, 0, 0);
            v.status = ValidatorStatus::Inactive;
            view.put(cf::VALIDATORS, &key(b), &encode_validator(&v).unwrap())
                .unwrap();
        }
    });
    assert_eq!(
        staged.unwrap().selection,
        Selection::CarriedForward {
            members: row1.clone(),
            eligible: 4
        }
    );
    assert_eq!(governing_set(&d, 8, &m, Some(7)).unwrap(), row1);
}

#[test]
fn wiring_a_missing_required_row_fails_the_transition_never_falls_back() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 10);
    // Blocks 1..=6 published with no row: block 3 wrote nothing.
    publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 7);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    let err = stage_boundary_row(&mut cand.view(), 7, &m).unwrap_err();
    assert!(
        matches!(err, G5Error::Row(StateError::Missing { key: 1 })),
        "{err}"
    );
    assert!(
        cand.view().is_empty(),
        "a refused transition stages nothing"
    );
}

#[test]
fn wiring_a_staking_read_error_fails_a_transition_block_and_no_other() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    d.put(cf::VALIDATORS, &key(40), b"not a validator").unwrap();
    let m = membership(4, 0, 10);
    let mut cand = CandidateExecution::new(&d, LIMIT);
    for h in [1u64, 2, 4] {
        assert!(stage_boundary_row(&mut cand.view(), h, &m)
            .unwrap()
            .is_none());
    }
    assert!(matches!(
        stage_boundary_row(&mut cand.view(), 3, &m),
        Err(G5Error::StakingRead(_))
    ));
    assert!(cand.view().is_empty());
}

#[test]
fn wiring_activation_immediately_before_exactly_on_and_after_a_boundary() {
    // (L, A, the blocks that write a row, and the epoch each writes), by hand,
    // for the first two transitions. L = 1 is S1(a).
    type Case = (u64, u64, [(u64, u64); 2]);
    #[rustfmt::skip]
    let cases: [Case; 8] = [
        (1, 0, [(1, 2), (2, 3)]),
        (1, 4, [(4, 5), (5, 6)]),
        (1, 5, [(5, 6), (6, 7)]),
        (1, 6, [(6, 7), (7, 8)]),
        (10, 0, [(9, 1), (19, 2)]),
        (10, 29, [(29, 3), (39, 4)]),
        (10, 30, [(39, 4), (49, 5)]),
        (10, 31, [(39, 4), (49, 5)]),
    ];
    for (l, a, writes) in cases {
        let what = format!("L={l} A={a}");
        let (d, _t) = db();
        seed_validators(&d, 31..=36);
        let m = membership(l, a, 5);
        let mut parent = block(Hash::ZERO, 0, 0).hash();
        let last = writes[1].0;
        for h in 1..=last {
            let (b, staged) = publish_executed(&d, parent, h, &m, |_| {});
            parent = b.hash();
            let want = writes.iter().find(|(t, _)| *t == h).map(|(_, e)| *e);
            assert_eq!(staged.map(|s| s.epoch), want, "{what} block {h}");
        }
        assert_eq!(stored_epochs(&d), vec![writes[0].1, writes[1].1], "{what}");
        check_stored_rows(&d, m.schedule()).unwrap();
        // Through the first transition block the anchor governs with no
        // certificate; the next height needs its row and that block certified.
        let first = writes[0].0;
        for h in 0..=first {
            assert_eq!(
                governing_set(&d, h, &m, None).unwrap(),
                genesis(),
                "{what} h={h}"
            );
        }
        assert!(matches!(
            governing_set(&d, first + 1, &m, Some(first - 1)),
            Err(G5Error::TransitionNotCertified { .. })
        ));
        assert_eq!(
            governing_set(&d, first + 1, &m, Some(first)).unwrap(),
            smallest_five(31..=36),
            "{what}"
        );
    }
}

// ── #351 wiring: header validation and the proposer (Q0, Q2) ────────────────

#[test]
fn wiring_governing_set_checks_q2_before_it_reads_a_row() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 5);
    for h in 0..4 {
        assert_eq!(governing_set(&d, h, &m, None).unwrap(), genesis());
    }
    // Row[1] missing and block 3 uncertified: Q2 refuses first.
    for certified in [None, Some(2)] {
        assert!(matches!(
            governing_set(&d, 4, &m, certified),
            Err(G5Error::TransitionNotCertified {
                height: 4,
                epoch: 1,
                transition: 3,
                ..
            })
        ));
    }
    // Certified and missing: the missing-row error, never the anchor.
    assert!(matches!(
        governing_set(&d, 4, &m, Some(3)),
        Err(G5Error::Row(StateError::Missing { key: 1 }))
    ));
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    publish_executed(&d, parent, 3, &m, |_| {});
    assert!(governing_set(&d, 4, &m, Some(2)).is_err());
    assert_eq!(
        governing_set(&d, 7, &m, Some(3)).unwrap(),
        smallest_five(31..=36)
    );
}

#[test]
fn wiring_certified_height_reads_the_pointer_and_fails_closed() {
    let (d, _t) = db();
    assert_eq!(certified_height(&d).unwrap(), None);
    // A certificate row without a pointer: the pointer was lost.
    d.put(cf::META, &certificate_key(4, &Hash::hash(b"b4")), b"cert")
        .unwrap();
    assert!(matches!(
        certified_height(&d),
        Err(G5Error::CertifiedPointer(_))
    ));
    let pointer = FinalizedPointer {
        height: 9,
        hash: Hash::hash(b"b9"),
    };
    d.put(cf::META, FINALIZED_POINTER_KEY, &encode_pointer(&pointer))
        .unwrap();
    assert_eq!(certified_height(&d).unwrap(), Some(9));
    d.put(cf::META, FINALIZED_POINTER_KEY, b"short").unwrap();
    assert!(matches!(
        certified_height(&d),
        Err(G5Error::CertifiedPointer(_))
    ));
}

// ── #351 wiring: restart and reorg ──────────────────────────────────────────

#[test]
fn wiring_restart_checks_the_rows_and_resolves_the_set_after_the_head() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 5);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    assert_eq!(check_restart(&d, &m, 2).unwrap(), genesis());
    publish_executed(&d, parent, 3, &m, |_| {});
    assert_eq!(check_restart(&d, &m, 3).unwrap(), smallest_five(31..=36));
    // A missing required row refuses the start, at the head that needs it.
    d.delete(cf::STATE, &VsetLayout::row_key(1)).unwrap();
    assert_eq!(check_restart(&d, &m, 2).unwrap(), genesis());
    assert!(matches!(
        check_restart(&d, &m, 3),
        Err(G5Error::Row(StateError::Missing { key: 1 }))
    ));
    // Q5 runs first: a legacy row, or a row for a rowless epoch, refuses.
    let (d, _t) = db();
    d.put(cf::VALIDATOR_SETS, &1u64.to_be_bytes(), b"x")
        .unwrap();
    assert!(matches!(
        check_restart(&d, &m, 0),
        Err(G5Error::LegacyEpochSet { .. })
    ));
    let (d, _t) = db();
    let row = ValidatorSetRecord::new(0, genesis()).unwrap().encode();
    d.put(cf::STATE, &VsetLayout::row_key(0), &row).unwrap();
    assert!(matches!(
        check_restart(&d, &m, 0),
        Err(G5Error::RowForRowlessEpoch { epoch: 0, .. })
    ));
}

#[test]
fn wiring_branch_rows_read_the_branch_layer_over_committed_state() {
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 5);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    publish_executed(&d, parent, 3, &m, |_| {});
    let canonical = smallest_five(31..=36);
    let other: Vec<[u8; 32]> = (51..=55).map(key).collect();
    let row_key = VsetLayout::row_key(1);
    let other_row = ValidatorSetRecord::new(1, other.clone()).unwrap().encode();

    // No override: committed state.
    let layer = BranchState::new(1 << 20);
    assert_eq!(
        governing_set(&BranchRows::new(&layer, &d), 4, &m, Some(3)).unwrap(),
        canonical
    );
    // A tombstone (the row's block unwound): the row is missing on the branch.
    let mut layer = BranchState::new(1 << 20);
    layer
        .absorb_net_writes([(cf::STATE, row_key.as_slice(), None)])
        .unwrap();
    assert!(matches!(
        governing_set(&BranchRows::new(&layer, &d), 4, &m, Some(3)),
        Err(G5Error::Row(StateError::Missing { key: 1 }))
    ));
    // The branch's own row.
    let mut layer = BranchState::new(1 << 20);
    layer
        .absorb_net_writes([(cf::STATE, row_key.as_slice(), Some(other_row.as_slice()))])
        .unwrap();
    assert_eq!(
        governing_set(&BranchRows::new(&layer, &d), 4, &m, Some(3)).unwrap(),
        other
    );
}

#[test]
fn wiring_unwinding_a_transition_block_removes_its_row_with_the_rest() {
    // A row is journalled application state: the published generic journal
    // records it as absent before the block, so an unwind deletes it.
    let (d, _t) = db();
    seed_validators(&d, 31..=36);
    let m = membership(4, 0, 10);
    let parent = publish_plain_range(&d, block(Hash::ZERO, 0, 0).hash(), 1, 3);
    let (b3, _) = publish_executed(&d, parent, 3, &m, |_| {});
    assert_eq!(stored_epochs(&d), vec![1]);
    let record = d
        .get(
            cf::APPLICATION_JOURNAL,
            &sumchain_storage::schema::journal_key(3, &b3.hash()),
        )
        .unwrap()
        .expect("the block's generic journal is published with it");
    let journal = ApplicationJournal::decode_for(&record, 3, &b3.hash()).unwrap();
    assert!(journal
        .entries()
        .iter()
        .any(|e| e.cf() == cf::STATE && e.key() == VsetLayout::row_key(1).as_slice()));
    journal.check_current_matches_after(&d).unwrap();
    journal.undo_batch(&d).unwrap().commit().unwrap();
    assert_eq!(stored_epochs(&d), Vec::<u64>::new());
}

// ── dormancy ────────────────────────────────────────────────────────────────

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Nothing outside `sumchain-storage`, and nothing else inside it, names the
/// G5 module. Its semantics are ratified, but wiring (activating) it is a
/// separate, authorized change that deletes or rewrites this test.
#[test]
fn the_g5_module_is_dormant() {
    let storage = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for entry in std::fs::read_dir(storage.join("..")).unwrap() {
        let dir = entry.unwrap().path();
        if dir.file_name().is_some_and(|n| n == "storage") {
            continue;
        }
        for sub in ["src", "tests", "benches", "examples"] {
            let d = dir.join(sub);
            if d.is_dir() {
                rust_files(&d, &mut files);
            }
        }
    }
    let mut own = Vec::new();
    rust_files(&storage.join("src"), &mut own);
    files.extend(
        own.into_iter()
            .filter(|f| !f.ends_with("validator_set_g5.rs") && !f.ends_with("lib.rs")),
    );
    assert!(files.len() > 100, "the scan found too few sources");
    let hits: Vec<String> = files
        .iter()
        .filter(|f| {
            std::fs::read_to_string(f)
                .unwrap()
                .contains("validator_set_g5")
        })
        .map(|f| f.display().to_string())
        .collect();
    assert!(
        hits.is_empty(),
        "the dormant G5 module is referenced: {hits:?}"
    );
    let lib = std::fs::read_to_string(storage.join("src/lib.rs")).unwrap();
    let uses: Vec<&str> = lib
        .lines()
        .filter(|l| l.contains("validator_set_g5"))
        .collect();
    assert_eq!(
        uses,
        ["pub mod validator_set_g5;"],
        "lib.rs only declares it"
    );
}
