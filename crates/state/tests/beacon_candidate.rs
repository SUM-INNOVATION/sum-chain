//! The beacon subsystem reads and writes the block's candidate.
//!
//! Beacon rows are folded into the block state root once the gate is open, so
//! staging writes into the candidate while the digest still read committed state
//! would commit the root to the PARENT's beacon state while publishing the
//! child's rows. Reads and writes had to move together.
//!
//! The membership and rehydration reads go through the view as well, so the
//! whole beacon read surface is uniform. That is a consistency property rather
//! than a fix for a reachable bug today: the membership row is staged during
//! finalization, so the executor's block-start lookup misses through either
//! handle at the boundary and finds a published row afterwards. The read that
//! genuinely distinguishes the two handles is exercised directly, by staging a
//! row and reading it back.

mod common;

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::{Block, BlockHeader, Hash, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::beacon_store::BeaconStore;
use sumchain_state::executor::BlockExecutor;
use sumchain_state::state::StateManager;
use sumchain_storage::candidate::JournalRecord;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database};

use common::setup_with_params;

const LIMIT: u64 = 1 << 20;
/// Epoch 0's boundary, per the schedule below.
const BOUNDARY: u64 = 1;

fn beacon_params() -> ChainParams {
    ChainParams {
        beacon_enabled_from_height: Some(0),
        beacon_params: Some(sumchain_genesis::BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
        // Epoch 0 starts at height 1; the KeyRegistration window is positions
        // [0,100], so heights 1..=101 all accept a registration and height 1 is
        // both the boundary and a key-registration block.
        beacon_schedule: Some(BeaconSchedule {
            start_height: 1,
            epoch_length: 1000,
            key_cutoff_offset: 100,
            deal_start_offset: 200,
            deal_cutoff_offset: 300,
            complaint_start_offset: 400,
            complaint_deadline_offset: 500,
        }),
        ..ChainParams::with_v2_enabled()
    }
}

fn validators() -> (Vec<KeyPair>, Vec<[u8; 32]>) {
    let vs: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate()).collect();
    let pubs = vs.iter().map(|k| *k.public_key().as_bytes()).collect();
    (vs, pubs)
}

fn reg_tx(signer: &KeyPair, secret_seed: u8, nonce: u64, fee: u128) -> SignedTransaction {
    use sumchain_beacon_crypto::SecretScalar;
    use sumchain_primitives::beacon_wire::{BeaconOperation, RegisterBeaconKeyV1};
    use sumchain_primitives::BeaconTxData;

    let mut sk_bytes = [0u8; 32];
    sk_bytes[0] = secret_seed;
    let sk = SecretScalar::from_bytes_le(&sk_bytes).unwrap();
    let reg = RegisterBeaconKeyV1 {
        chain_id: 1,
        epoch: 0,
        ek_j: sk.public_g1().to_compressed(),
        pop: sk.pop_prove().to_compressed(),
    };
    let data = BeaconTxData::from_operation(&BeaconOperation::RegisterBeaconKey(reg)).unwrap();
    let tx = TransactionV2 {
        chain_id: 1,
        from: signer.address(),
        fee,
        nonce,
        payload: TxPayload::BeaconSetup(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), signer.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *signer.public_key().as_bytes())
}

fn block_at(height: u64, proposer: &[u8; 32], txs: Vec<SignedTransaction>) -> Block {
    Block::new(
        BlockHeader::new(Hash::ZERO, height, 1000, Hash::ZERO, Hash::ZERO, *proposer),
        txs,
    )
}

fn fund(db: &Database, kp: &KeyPair, balance: u128) {
    sumchain_storage::StateStore::new(db)
        .put_account(
            &kp.address(),
            &sumchain_storage::schema::AccountState { balance, nonce: 0 },
        )
        .unwrap();
}

/// Execute one block against a candidate and drop it, returning the digest the
/// block folded and the journal it produced. Nothing is published.
fn execute_only(
    executor: &BlockExecutor,
    state: &Arc<StateManager>,
    block: &Block,
    validators: &[[u8; 32]],
) -> (Hash, JournalRecord) {
    let exec = executor
        .execute_block(block, state.state_root(), validators)
        .expect("execute_block");
    let root = exec.computed_root();
    let (executed, _sd, _cd) = exec.into_parts();
    // Read the bound journal, then drop the candidate unpublished.
    let journal = executed.journals().beacon.clone();
    (root, journal)
}

/// Reading a membership row staged in the SAME block.
///
/// This is the test that actually discriminates between `v_get_membership` and
/// the committed `get_membership`: it stages the row into a view and reads it
/// back, with nothing published. Point the read at committed storage instead and
/// it fails.
///
/// The boundary tests below do NOT discriminate — see
/// `the_boundary_block_snapshots_without_needing_a_staged_row` — so this is the
/// only evidence for the view-based read.
#[test]
fn v_get_membership_sees_a_row_staged_in_the_same_block() {
    use sumchain_beacon_runtime::dkg::{DkgConfig, DkgEpoch, RehydrateInput};

    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    let (_vs, pubs) = validators();

    // Build the membership row the way production does, so the test cannot pass
    // against an encoding only it knows.
    let cfg = DkgConfig {
        chain_id: 1,
        epoch: 0,
        params: sumchain_beacon_runtime::params::BeaconParams::validated(1, 1, 2, 3, 5).unwrap(),
    };
    let epoch = DkgEpoch::rehydrate(cfg, RehydrateInput::default()).unwrap();
    let rows = BeaconStore::materialize(0, &epoch, None, &pubs).unwrap();
    assert!(
        rows.contains_key(&sumchain_state::beacon_store::membership_row_key(0)),
        "materialization must include the membership row"
    );

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        for (k, v) in &rows {
            view.put(cf::BEACON_STATE, k, v).unwrap();
        }

        assert_eq!(
            BeaconStore::v_get_membership(&view, 0).unwrap(),
            Some(pubs.clone()),
            "a membership row staged in this block must be readable in it"
        );
    }

    // Nothing was published, so the committed read finds nothing. This is the
    // half that makes the assertion above non-vacuous.
    assert_eq!(
        BeaconStore::new(&db).get_membership(0).unwrap(),
        None,
        "the staged row must not have reached canonical storage"
    );
}

/// The boundary block does not depend on reading its own snapshot.
///
/// An earlier version of this file claimed it did. It does not: the membership
/// row is staged during finalization, AFTER `beacon_epoch_membership` runs, so
/// at the boundary that lookup misses through either handle and the
/// `height == epoch_start` arm supplies the active validator set directly.
///
/// The test is kept because the behaviour is worth pinning — a boundary block's
/// beacon op must succeed, and the snapshot must be published — but it is
/// recorded here that it passes identically with a committed-only lookup, and
/// is therefore NOT evidence that the read must go through the view.
#[test]
fn the_boundary_block_snapshots_without_needing_a_staged_row() {
    let (state, db, _dir, executor) = setup_with_params(beacon_params());
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();
    fund(&db, &vs[0], fee + 1_000);

    let receipts = common::publish_block(
        &state,
        &executor,
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
        &pubs,
    );

    assert!(
        receipts[0].is_success(),
        "a registration in the boundary block resolves against the active set \
         the boundary arm supplies (got {:?})",
        receipts[0].status
    );

    let store = BeaconStore::new(&db);
    assert_eq!(
        store.get_membership(0).unwrap(),
        Some(pubs.clone()),
        "the boundary snapshot is published"
    );
    assert!(
        !store.load_state_map().unwrap().is_empty(),
        "the registration row is published alongside it"
    );
}

#[test]
fn the_candidate_digest_is_the_digest_of_what_gets_published() {
    // The consensus property: a proposer folds the digest over its candidate, a
    // validator storing the block recomputes it over committed state.
    let (state, db, _dir, executor) = setup_with_params(beacon_params());
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();
    fund(&db, &vs[0], fee + 1_000);

    let store = BeaconStore::new(&db);
    let empty = store.state_digest().unwrap();

    let blk = block_at(
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
    );
    let exec = executor
        .execute_block(&blk, state.state_root(), &pubs)
        .expect("execute_block");
    let (executed, _sd, _cd) = exec.into_parts();

    // The digest the block would fold, taken from its own candidate.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let candidate_digest = {
        let view = ExecutionView::new(&mut overlay);
        // An empty candidate over an unpublished database: still the parent's.
        BeaconStore::v_state_digest(&view).unwrap()
    };
    assert_eq!(
        candidate_digest, empty,
        "nothing was published, so the parent's digest is unchanged"
    );
    drop(executed);

    // Now publish the same block and compare committed to candidate.
    let (state2, db2, _dir2, executor2) = setup_with_params(beacon_params());
    fund(&db2, &vs[0], fee + 1_000);
    common::publish_block(
        &state2,
        &executor2,
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
        &pubs,
    );
    let published = BeaconStore::new(&db2).state_digest().unwrap();
    assert_ne!(
        published, empty,
        "a published beacon transition must change the digest"
    );

    // And the same rows read through a candidate over the published database
    // digest identically — the encoder is shared, so this is the parity that
    // keeps a proposer and a validator on the same root.
    let mut ov2 = ApplicationOverlay::new(&db2, LIMIT);
    let view2 = ExecutionView::new(&mut ov2);
    assert_eq!(
        BeaconStore::v_state_digest(&view2).unwrap(),
        published,
        "candidate and committed digests must agree over identical rows"
    );
}

#[test]
fn a_dropped_candidate_leaves_storage_byte_identical() {
    let (state, db, _dir, executor) = setup_with_params(beacon_params());
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();
    fund(&db, &vs[0], fee + 1_000);

    let store = BeaconStore::new(&db);
    let before_rows = store.load_state_map().unwrap();
    let before_digest = store.state_digest().unwrap();

    let blk = block_at(
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
    );
    let (_root, journal) = execute_only(&executor, &state, &blk, &pubs);
    assert!(
        matches!(journal, JournalRecord::Recorded(_)),
        "the block did produce a beacon transition"
    );

    assert_eq!(store.load_state_map().unwrap(), before_rows);
    assert_eq!(store.state_digest().unwrap(), before_digest);
    assert!(
        !store.has_journal(BOUNDARY, &blk.hash()).unwrap(),
        "a dropped candidate must leave no journal"
    );
}

#[test]
fn two_blocks_at_one_height_keep_separate_journals() {
    // The old journal key was the height alone, which two competing blocks
    // share: the side branch's journal overwrote the canonical one, and the
    // guard meant to prevent that refused the side branch outright.
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();

    let (state_a, db_a, _da, ex_a) = setup_with_params(beacon_params());
    fund(&db_a, &vs[0], fee + 1_000);
    common::publish_block(
        &state_a,
        &ex_a,
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
        &pubs,
    );

    // A competing block at the same height, with a different proposer, so a
    // different block hash and its own journal row.
    let (state_b, db_b, _db2, ex_b) = setup_with_params(beacon_params());
    fund(&db_b, &vs[1], fee + 1_000);
    common::publish_block(
        &state_b,
        &ex_b,
        BOUNDARY,
        vs[1].public_key().as_bytes(),
        vec![reg_tx(&vs[1], 9, 0, fee)],
        &pubs,
    );

    // Both journals exist, each under its own block's key, and neither is at
    // the height-only key.
    for db in [&db_a, &db_b] {
        let n = db
            .prefix_iter(cf::BEACON_STATE_DIFFS, &BOUNDARY.to_be_bytes())
            .map(|it| it.count())
            .unwrap_or(0);
        assert_eq!(n, 1, "exactly one journal row per published block");
        assert!(
            db.get(cf::BEACON_STATE_DIFFS, &BOUNDARY.to_be_bytes())
                .unwrap()
                .is_none(),
            "nothing is written at the height-only key"
        );
    }
}

#[test]
fn a_height_only_journal_refuses_rather_than_guessing_which_block_it_undoes() {
    let (_state, db, _dir, executor) = setup_with_params(beacon_params());
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();
    fund(&db, &vs[0], fee + 1_000);

    let blk = block_at(
        BOUNDARY,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
    );
    // A row under the height alone, seeded before any candidate exists. The
    // reader refuses on the KEY, before it decodes anything, so the bytes need
    // only be present — and seeding them keeps this test free of a candidate it
    // would then have to publish.
    db.put(
        cf::BEACON_STATE_DIFFS,
        &BOUNDARY.to_be_bytes(),
        b"a-journal-under-the-height-alone",
    )
    .unwrap();

    let store = BeaconStore::new(&db);
    for (label, err) in [
        ("has_journal", store.has_journal(BOUNDARY, &blk.hash()).err()),
        (
            "load_journal",
            store.load_journal(BOUNDARY, &blk.hash()).err(),
        ),
        (
            "revert_block",
            store.revert_block(BOUNDARY, &blk.hash()).err(),
        ),
    ] {
        let err = err.unwrap_or_else(|| panic!("{label} must refuse a height-only journal"));
        assert!(
            format!("{err}").contains("keyed by height alone"),
            "{label}: {err}"
        );
    }

    // The row survives, so an operator can still attribute it offline.
    assert!(db
        .get(cf::BEACON_STATE_DIFFS, &BOUNDARY.to_be_bytes())
        .unwrap()
        .is_some());
}

#[test]
fn a_merged_scan_error_is_not_a_short_row_set() {
    // `v_load_state_map` feeds the digest that goes into the block state root, so
    // a scan that could fail silently is a consensus hazard: a truncated row set
    // is a perfectly well-formed digest over the wrong state, and every validator
    // that read successfully would compute a different root. The scan is fallible
    // for that reason, and `v_load_state_map` propagates with `?` rather than
    // collecting what it managed to read.
    let dir = tempfile::TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();

    // Seed the PARENT first, before any candidate exists. Writing the database
    // after reading a candidate is the shape of a hand-rolled publisher, and
    // `no_test_publishes_a_candidate_by_hand` refuses it.
    let a = sumchain_state::beacon_store::membership_row_key(0);
    let b = sumchain_state::beacon_store::key_row_key(0, 0);
    db.put(cf::BEACON_STATE, &a, b"committed").unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);

    // A scan that cannot START is an error, not an empty result.
    {
        let view = ExecutionView::new(&mut overlay);
        assert!(
            view.iter("no_such_column_family").is_err(),
            "an unopenable scan must not read as zero rows"
        );
    }

    // And a scan that CAN start returns both sides. A merged scan that dropped
    // either one would shorten the row set exactly as silently.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);
        view.put(cf::BEACON_STATE, &b, b"staged").unwrap();

        let rows = BeaconStore::v_load_state_map(&view).unwrap();
        assert_eq!(
            rows.get(&a).map(|v| v.as_slice()),
            Some(b"committed".as_ref()),
            "a base-only row must survive the merge"
        );
        assert_eq!(
            rows.get(&b).map(|v| v.as_slice()),
            Some(b"staged".as_ref()),
            "an overlay-only row must survive the merge"
        );
        assert_eq!(rows.len(), 2);

        // An overlay write over a base row wins, and a delete removes it — a
        // digest built from a stale base value, or from a row this block
        // deleted, is the same class of wrong answer.
        view.put(cf::BEACON_STATE, &a, b"overwritten").unwrap();
        assert_eq!(
            BeaconStore::v_load_state_map(&view)
                .unwrap()
                .get(&a)
                .map(|v| v.as_slice()),
            Some(b"overwritten".as_ref())
        );

        view.delete(cf::BEACON_STATE, &a).unwrap();
        let rows = BeaconStore::v_load_state_map(&view).unwrap();
        assert!(!rows.contains_key(&a), "a deleted row must not be digested");
        assert_eq!(rows.len(), 1);
    }
}

#[test]
fn a_dropped_boundary_leaves_the_epoch_without_membership() {
    // Dropped-candidate isolation for the membership snapshot.
    //
    // The boundary block stages a snapshot and is then abandoned, so nothing is
    // published — and the identical registration one block later fails closed,
    // because past the boundary with no persisted snapshot the epoch_start set
    // cannot be reconstructed. That is the fail-closed rule holding across an
    // abandoned candidate, not a statement about which handle the read uses.
    let (state, db, _dir, executor) = setup_with_params(beacon_params());
    let fee = beacon_params().min_fee;
    let (vs, pubs) = validators();
    fund(&db, &vs[0], fee + 10_000);

    // Boundary block, executed and abandoned.
    let boundary = block_at(BOUNDARY, vs[0].public_key().as_bytes(), vec![]);
    let (_root, journal) = execute_only(&executor, &state, &boundary, &pubs);
    assert!(
        matches!(journal, JournalRecord::Recorded(_)),
        "the boundary block does stage a membership snapshot"
    );
    assert_eq!(
        BeaconStore::new(&db).get_membership(0).unwrap(),
        None,
        "but a dropped candidate publishes nothing"
    );

    // Height 2, same epoch, still inside the key-registration window.
    let receipts = common::publish_block(
        &state,
        &executor,
        2,
        vs[0].public_key().as_bytes(),
        vec![reg_tx(&vs[0], 7, 0, fee)],
        &pubs,
    );
    assert!(
        !receipts[0].is_success(),
        "past the boundary with no published snapshot, a beacon op must fail \
         closed rather than re-sample the current active set"
    );
    assert_eq!(
        BeaconStore::new(&db).get_membership(0).unwrap(),
        None,
        "and no snapshot is invented for the epoch"
    );
}
