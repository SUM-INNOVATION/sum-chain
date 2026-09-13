//! Staking and delegation read and write the block's candidate.
//!
//! These two migrated together because they cannot be separated. A delegation
//! row and its validator row move in the same transaction — `Delegate` writes
//! both, `Undelegate` writes both, and slashing rewrites every delegation a
//! validator has plus the validator itself. Migrate one side alone and a single
//! Staking transaction would stage half its effect and commit the other half,
//! which is worse than committing all of it: an abandoned block would then
//! leave the two halves disagreeing about the same stake.
//!
//! Six column families move with them: `VALIDATORS`, `DELEGATIONS`,
//! `DELEGATION_VALIDATOR_INDEX`, `UNBONDING_DELEGATIONS`, `SLASHING_RECORDS`
//! and `VALIDATOR_SIGNING_INFO`. Two of those — validators and delegations —
//! are INCLUDE buckets of the supply census, so a block that bonded or slashed
//! stake and then censused its parent's totals would mint or withhold the
//! difference against a target it had already moved.
//!
//! Byte-for-byte, and NOT because the state root covers it.
//! `compute_block_state_root` folds header fields, receipt outcomes and the
//! gated contract, supply, compute-pool and beacon digests; it commits to
//! staking rows no more than it does to account rows. An abandoned block's
//! validator set has to be checked directly, because nothing downstream would
//! notice it, and these families are what every later block and every RPC read.

mod common;

use std::sync::Arc;

use sumchain_primitives::{
    DelegationInfo, EvidenceType, SlashingRecord, UnbondingDelegation, ValidatorInfo,
    ValidatorSigningInfo, ValidatorStatus,
};
use sumchain_state::staking_executor::StakingExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::{DelegationStore, SlashingStore, StakingStore};
use sumchain_storage::{cf, Database};

const LIMIT: u64 = 1 << 20;

/// Every column family this package moved.
const STAKING_CFS: &[&str] = &[
    cf::VALIDATORS,
    cf::DELEGATIONS,
    cf::DELEGATION_VALIDATOR_INDEX,
    cf::UNBONDING_DELEGATIONS,
    cf::SLASHING_RECORDS,
    cf::VALIDATOR_SIGNING_INFO,
];

fn open() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

fn view_of<'v, 'db>(overlay: &'v mut ApplicationOverlay<'db>) -> ExecutionView<'v, 'db> {
    ExecutionView::new(overlay)
}

/// Every staking row, as raw bytes, across all six families.
///
/// Bytes, not decoded values: a decoded comparison would pass even if a row had
/// been rewritten to an equal value, and a rewrite is a write.
fn staking_rows(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for family in STAKING_CFS {
        for (k, v) in db.prefix_iter(family, &[]).unwrap() {
            out.push((family.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// The families actually represented in a row set. Used to refuse a fixture
/// that silently stops covering one.
fn families_touched(rows: &[(String, Vec<u8>, Vec<u8>)]) -> std::collections::BTreeSet<String> {
    rows.iter().map(|(f, _, _)| f.clone()).collect()
}

/// One family's rows out of a row set.
fn rows_of<'r>(
    rows: &'r [(String, Vec<u8>, Vec<u8>)],
    family: &str,
) -> Vec<&'r (String, Vec<u8>, Vec<u8>)> {
    rows.iter().filter(|(f, _, _)| f == family).collect()
}

/// The families whose rows actually DIFFER between two row sets.
///
/// Presence is not change. A global `staged != before` is satisfied by any one
/// family moving, so a test that stages writes in six families and compares
/// globally still passes when four of those writes are deleted. Comparing per
/// family is what makes each staged write load-bearing.
fn families_changed(
    before: &[(String, Vec<u8>, Vec<u8>)],
    after: &[(String, Vec<u8>, Vec<u8>)],
) -> std::collections::BTreeSet<String> {
    STAKING_CFS
        .iter()
        .filter(|f| rows_of(after, f) != rows_of(before, f))
        .map(|f| f.to_string())
        .collect()
}

/// Every staking row as the CANDIDATE sees it, in the same shape as
/// [`staking_rows`], so the two can be compared directly.
fn staged_rows(view: &ExecutionView<'_, '_>) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for family in STAKING_CFS {
        for item in view.prefix_iter(family, &[]).unwrap() {
            let (k, v) = item.unwrap();
            out.push((family.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

fn slashing_record(pubkey: [u8; 32], at: u64) -> SlashingRecord {
    SlashingRecord::new(
        pubkey,
        EvidenceType::DoubleSign,
        at,
        100,
        50,
        at + 1_000,
        false,
        500,
    )
}

fn validator(pubkey: u8, stake: u128) -> ValidatorInfo {
    let mut v = ValidatorInfo::new([pubkey; 32], stake, 500, 1);
    v.status = ValidatorStatus::Active;
    v
}

/// Seed committed parent state the way genesis and fast-sync do. A view read
/// falls through to it; no test-only write path exists.
fn seed_validator(db: &Database, v: &ValidatorInfo) {
    StakingStore::new(db).put_validator(v).unwrap();
}

fn seed_delegation(db: &Database, d: &DelegationInfo) {
    DelegationStore::new(db).put_delegation(d).unwrap();
}

fn seed_unbonding(db: &Database, u: &UnbondingDelegation) {
    DelegationStore::new(db).put_unbonding(u).unwrap();
}

fn seed_signing_info(db: &Database, i: &ValidatorSigningInfo) {
    SlashingStore::new(db).put_signing_info(i).unwrap();
}

fn seed_slashing_record(db: &Database, r: &SlashingRecord) {
    SlashingStore::new(db).put_slashing_record(r).unwrap();
}

// ── Same-block visibility ────────────────────────────────────────────────────

/// Stake bonded earlier in the block is visible later in it.
#[test]
fn stake_bonded_earlier_in_the_block_is_visible_later_in_it() {
    let (_dir, db) = open();
    seed_validator(&db, &validator(0xA1, 1_000));

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    let mut v = StakingExecutor::v_get_validator(&view, &[0xA1; 32])
        .unwrap()
        .expect("seeded");
    v.stake += 500;
    StakingExecutor::v_put_validator(&mut view, &v).unwrap();

    assert_eq!(
        StakingExecutor::v_get_validator(&view, &[0xA1; 32])
            .unwrap()
            .unwrap()
            .stake,
        1_500,
        "a later transaction in the same block must see the bond"
    );
    assert_eq!(
        StakingStore::new(&db)
            .get_validator(&[0xA1; 32])
            .unwrap()
            .unwrap()
            .stake,
        1_000,
        "and committed storage must still hold the parent's stake"
    );
}

/// A delegation created earlier in the block is visible later in it — through
/// the index, which is how the slash and reward paths find it.
#[test]
fn a_delegation_created_earlier_in_the_block_is_findable_later_in_it() {
    let (_dir, db) = open();
    seed_validator(&db, &validator(0xB1, 1_000));

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    let d = DelegationInfo::new([0xD1; 32], [0xB1; 32], 700, 1);
    StakingExecutor::v_put_delegation(&mut view, &d).unwrap();

    let found = StakingExecutor::v_get_delegations_by_validator(&view, &[0xB1; 32]).unwrap();
    assert_eq!(found.len(), 1, "the index must find the staged delegation");
    assert_eq!(found[0].amount, 700);

    assert!(
        DelegationStore::new(&db)
            .get_delegations_by_validator(&[0xB1; 32])
            .unwrap()
            .is_empty(),
        "and committed storage must not have it yet"
    );
}

/// The index moves with the row it points at, in both directions.
///
/// `cf::DELEGATIONS` is useless without `cf::DELEGATION_VALIDATOR_INDEX`: the
/// slash path scans the index to find what to slash. A staged delegation whose
/// index entry stayed committed would be invisible to the very path that has to
/// find it, and a staged deletion that left the index behind would point at a
/// row that is gone.
#[test]
fn deleting_a_delegation_stages_the_index_removal_with_it() {
    let (_dir, db) = open();
    seed_validator(&db, &validator(0xB2, 1_000));
    seed_delegation(&db, &DelegationInfo::new([0xD2; 32], [0xB2; 32], 400, 1));

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    assert_eq!(
        StakingExecutor::v_get_validator_delegators(&view, &[0xB2; 32])
            .unwrap()
            .len(),
        1,
        "the seeded delegation is indexed"
    );

    StakingExecutor::v_delete_delegation(&mut view, &[0xD2; 32], &[0xB2; 32]).unwrap();

    assert!(
        StakingExecutor::v_get_delegation(&view, &[0xD2; 32], &[0xB2; 32])
            .unwrap()
            .is_none(),
        "the row is gone in the candidate"
    );
    assert!(
        StakingExecutor::v_get_validator_delegators(&view, &[0xB2; 32])
            .unwrap()
            .is_empty(),
        "and so is its index entry — a stale index outlives the row it names"
    );
}

// ── Absence is not emptiness ─────────────────────────────────────────────────

/// A validator that does not exist is ABSENT, not a zero-stake validator.
#[test]
fn an_absent_validator_is_not_a_zero_stake_validator() {
    let (_dir, db) = open();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let view = view_of(&mut overlay);

    assert!(
        StakingExecutor::v_get_validator(&view, &[0xEE; 32])
            .unwrap()
            .is_none(),
        "an unknown validator reads as None, never as a default row"
    );
    assert!(!StakingExecutor::v_validator_exists(&view, &[0xEE; 32]).unwrap());
}

/// Creating a validator records an ABSENT pre-image.
///
/// An undo journal reverting a block that CREATED a validator has to DELETE the
/// row. A pre-image captured as `Some(default)` could only write a zero-stake
/// validator back — a different chain state, and one that still counts in the
/// census and still appears in the validator set.
#[test]
fn creating_a_validator_records_an_absent_preimage() {
    let (_dir, db) = open();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = view_of(&mut overlay);
        StakingExecutor::v_put_validator(&mut view, &validator(0xC1, 900)).unwrap();
    }
    assert_eq!(
        overlay.preimage(cf::VALIDATORS, &[0xC1; 32]),
        Some(&None),
        "the pre-image of a created validator is ABSENT, not a zero row"
    );
}

/// Overwriting one records the parent's bytes.
#[test]
fn overwriting_a_validator_records_the_row_it_replaced() {
    let (_dir, db) = open();
    let parent = validator(0xC2, 100);
    seed_validator(&db, &parent);
    let committed = db.get(cf::VALIDATORS, &[0xC2; 32]).unwrap().unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = view_of(&mut overlay);
        StakingExecutor::v_put_validator(&mut view, &validator(0xC2, 999)).unwrap();
    }
    assert_eq!(
        overlay.preimage(cf::VALIDATORS, &[0xC2; 32]),
        Some(&Some(committed)),
        "the pre-image is the parent's bytes"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A dropped candidate leaves all six families byte-identical — all six.
///
/// The first version of this claimed six families and exercised three. The
/// other three were empty before the block and empty after it, so comparing
/// them compared nothing to nothing: the assertion passed because there was
/// nothing to disagree about, not because rollback worked. A test that names
/// a family it never writes is an assertion about its own fixture.
///
/// So every family is seeded committed, every family is changed in the
/// candidate, and `families_touched` re-derives the set actually written from
/// the rows themselves and requires all six. Deleting any one of the staged
/// writes below now fails the test rather than quietly shrinking its reach.
#[test]
fn a_dropped_candidate_leaves_staking_byte_identical() {
    let (_dir, db) = open();

    // Parent state in all six families.
    seed_validator(&db, &validator(0xF1, 1_000));
    seed_delegation(&db, &DelegationInfo::new([0xD3; 32], [0xF1; 32], 250, 1));
    seed_unbonding(
        &db,
        &UnbondingDelegation::new([0xD3; 32], [0xF1; 32], 60, 99),
    );
    seed_signing_info(&db, &ValidatorSigningInfo::new([0xF1; 32], 1));
    seed_slashing_record(&db, &slashing_record([0xF1; 32], 7));
    let before = staking_rows(&db);
    assert_eq!(
        families_touched(&before).len(),
        STAKING_CFS.len(),
        "the fixture must seed every family this test claims to cover"
    );

    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = view_of(&mut overlay);

        // VALIDATORS: rewrite one, create another.
        StakingExecutor::v_put_validator(&mut view, &validator(0xF1, 5_000)).unwrap();
        StakingExecutor::v_put_validator(&mut view, &validator(0xF2, 42)).unwrap();
        // DELEGATIONS + DELEGATION_VALIDATOR_INDEX: create, delete, slash.
        StakingExecutor::v_put_delegation(
            &mut view,
            &DelegationInfo::new([0xD4; 32], [0xF1; 32], 111, 2),
        )
        .unwrap();
        StakingExecutor::v_delete_delegation(&mut view, &[0xD3; 32], &[0xF1; 32]).unwrap();
        StakingExecutor::v_slash_delegations(&mut view, &[0xF1; 32], 500).unwrap();
        // UNBONDING_DELEGATIONS: add one, withdraw the seeded one.
        StakingExecutor::v_put_unbonding(
            &mut view,
            &UnbondingDelegation::new([0xD4; 32], [0xF1; 32], 30, 120),
        )
        .unwrap();
        StakingExecutor::v_delete_unbonding(&mut view, &[0xD3; 32], 99, &[0xF1; 32]).unwrap();
        // VALIDATOR_SIGNING_INFO: tombstone the validator.
        let mut info = StakingExecutor::v_get_signing_info(&view, &[0xF1; 32])
            .unwrap()
            .expect("seeded");
        info.tombstoned = true;
        info.missed_blocks_counter += 5;
        StakingExecutor::v_put_signing_info(&mut view, &info).unwrap();
        // SLASHING_RECORDS: record a second slash.
        StakingExecutor::v_put_slashing_record(&mut view, &slashing_record([0xF1; 32], 8))
            .unwrap();

        // The candidate differs in EVERY family — each staged write above is
        // load-bearing. A global inequality would not show this: with six
        // families compared as one set, deleting four of the writes still
        // leaves the sets unequal and the test green.
        let staged = staged_rows(&view);
        assert_eq!(
            families_touched(&staged),
            families_touched(&before),
            "every family this test claims must be represented on both sides; \
             a family empty on both proves nothing"
        );
        let changed = families_changed(&before, &staged);
        let expected: std::collections::BTreeSet<String> =
            STAKING_CFS.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            changed, expected,
            "every family must actually CHANGE in the candidate. Missing here \
             means the write for that family was removed or never landed, and \
             what follows would be proving rollback of nothing."
        );
        assert!(
            StakingExecutor::v_is_tombstoned(&view, &[0xF1; 32]).unwrap(),
            "the tombstone is staged"
        );
    }

    assert_eq!(
        staking_rows(&db),
        before,
        "a block that bonded, delegated, undelegated, slashed, unbonded, \
         withdrew, tombstoned and recorded a slash, and was then abandoned, \
         must leave every staking row exactly as it found it"
    );
}

/// ONE `v_put_delegation` stages the row, then fails on its index entry.
///
/// The row and its index entry are one operation, and this is the failure that
/// matters: an overlay whose ceiling is exactly the delegation row's charge
/// accepts the row and refuses the index write, so the candidate holds a
/// delegation that nothing can find — a state no successful execution produces.
/// Dropping it must still leave the families byte-identical.
///
/// The ceiling is measured, not guessed, and measured only through the real
/// operation: a disposable overlay runs the SAME `v_put_delegation` to
/// completion and reports what row-plus-index cost. One byte under that total
/// necessarily admits the row and refuses the index, because the index write
/// costs at least its own key. Nothing here hand-writes into an overlay — a
/// fixture that stages rows itself is a second publisher, and
/// `no_test_publishes_a_candidate_by_hand` is right to refuse it.
///
/// The error is checked to name the limit, so a failure before any write could
/// not pass for this.
#[test]
fn a_delegation_that_fails_after_staging_its_row_leaves_staking_byte_identical() {
    let (_dir, db) = open();
    seed_validator(&db, &validator(0xF3, 1_000));
    let before = staking_rows(&db);
    let d = DelegationInfo::new([0xD5; 32], [0xF3; 32], 600, 1);

    // What row-plus-index costs, measured by running the real operation.
    let both_charge = {
        let mut scratch = ApplicationOverlay::new(&db, LIMIT);
        {
            let mut view = view_of(&mut scratch);
            StakingExecutor::v_put_delegation(&mut view, &d).unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(both_charge > 1, "both writes must cost something");

    {
        // One byte short of both: the row fits, the index cannot.
        let mut overlay = ApplicationOverlay::new(&db, both_charge - 1);
        let mut view = view_of(&mut overlay);

        let err = StakingExecutor::v_put_delegation(&mut view, &d)
            .expect_err("the index write must be refused");
        assert!(
            err.to_string().contains("limit"),
            "it must fail because the INDEX write was refused, not before \
             writing anything: {err}"
        );

        assert!(
            StakingExecutor::v_get_delegation(&view, &[0xD5; 32], &[0xF3; 32])
                .unwrap()
                .is_some(),
            "the delegation row is staged — the operation failed AFTER writing it"
        );
        assert!(
            StakingExecutor::v_get_validator_delegators(&view, &[0xF3; 32])
                .unwrap()
                .is_empty(),
            "and its index entry is not: a delegation nothing can find"
        );
    }

    assert_eq!(
        staking_rows(&db),
        before,
        "a delegation write that failed half-way must leave every staking row \
         exactly as it found it"
    );
}

// ── The census ───────────────────────────────────────────────────────────────

/// The census reads the candidate's stake and delegations.
///
/// Validator self-stake and active delegations are INCLUDE buckets. A census
/// that read the parent's while this block had already bonded would measure a
/// supply the chain no longer has, and the correction mints the difference.
#[test]
fn the_census_sees_this_blocks_stake_and_delegations() {
    let (_dir, db) = open();
    seed_validator(&db, &validator(0xA9, 1_000));
    seed_delegation(&db, &DelegationInfo::new([0xD9; 32], [0xA9; 32], 300, 1));

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    StakingExecutor::v_put_validator(&mut view, &validator(0xA9, 2_500)).unwrap();
    StakingExecutor::v_put_delegation(
        &mut view,
        &DelegationInfo::new([0xDA; 32], [0xA9; 32], 400, 2),
    )
    .unwrap();

    assert_eq!(
        StakingExecutor::v_total_validator_self_stake(&view).unwrap(),
        2_500,
        "the census must see the bond this block staged, not the parent's stake"
    );
    assert_eq!(
        StakingExecutor::v_total_active_delegations(&view).unwrap(),
        700,
        "and both delegations, including the one this block created"
    );

    assert_eq!(
        StakingStore::new(&db).total_validator_self_stake().unwrap(),
        1_000,
        "committed storage is unmoved while the candidate lives"
    );

    // ── The census itself, not just the readers ─────────────────────────────
    //
    // Everything above exercises `v_total_validator_self_stake` and
    // `v_total_active_delegations` directly. That proves the readers — and it
    // kept passing when `v_native_supply_snapshot` was wired back to the
    // COMMITTED stores, which is the mistake that actually matters. A bucket
    // reader that nobody calls from the census proves nothing about the census.
    // So drive the real snapshot.
    let candidate_census = sumchain_state::supply::v_native_supply_snapshot(&view).unwrap();
    assert_eq!(
        candidate_census.validator_self_stake, 2_500,
        "the census must take self-stake from the CANDIDATE"
    );
    assert_eq!(
        candidate_census.active_delegations, 700,
        "and active delegations from the candidate too"
    );

    let committed_census = sumchain_state::supply::native_supply_snapshot(&db).unwrap();
    assert_eq!(
        (
            committed_census.validator_self_stake,
            committed_census.active_delegations
        ),
        (1_000, 300),
        "while the committed census still reports the parent's totals"
    );
    assert_eq!(
        candidate_census.economic_supply().unwrap() - committed_census.economic_supply().unwrap(),
        1_900,
        "and the difference is exactly what this block staged: 1500 of stake \
         plus 400 of delegation"
    );
}
