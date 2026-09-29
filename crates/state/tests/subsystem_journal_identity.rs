//! Issue #253: the compute-pool and beacon undo journals must name the block
//! they undo, and a revert must refuse any record that does not.
//!
//! Two blocks can exist at one height — that is what a reorg is. These tests
//! publish REAL blocks through the executor and the publisher, with both
//! subsystem gates open, and unwind them through `stage_branch_unwind`, the
//! engine the consensus reorg calls. Every database is RocksDB on disk; the
//! restart test drops every handle and reopens it.
//!
//! With the gates open every published block carries a sealed record for both
//! families: the beacon one describes the registration the block applies, and
//! the compute-pool one is the positive "nothing to undo" (there is no live
//! compute-pool operation source yet). Non-empty compute-pool undo data is
//! covered by the store and executor unit tests.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::beacon_schedule::BeaconSchedule;
use sumchain_primitives::{Block, Hash, SignedTransaction, TransactionV2, TxPayload};
use sumchain_state::beacon_store::BeaconStore;
use sumchain_state::compute_pool_store::ComputePoolStore;
use sumchain_state::reorg_undo::{
    stage_branch_unwind, MissingJournalPolicy, PreActivationBlock, SubsystemJournals, UndoRefusal,
    UnwindReport,
};
use sumchain_state::state::StateManager;
use sumchain_storage::journal::JournalActivation;
use sumchain_storage::subsystem_journal::{self, Family, SubsystemGates};
use sumchain_storage::{cf, Database};

const H: u64 = 1;

/// Both subsystem gates open from genesis. Test-only: genesis validation refuses
/// either gate on a real chain.
fn params() -> ChainParams {
    ChainParams {
        compute_pool_enabled_from_height: Some(0),
        beacon_enabled_from_height: Some(0),
        beacon_params: Some(sumchain_genesis::BeaconParamsConfig {
            f: 1,
            c: 1,
            t: 2,
            q_dkg: 3,
            n: 5,
        }),
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

const GATES: SubsystemGates = SubsystemGates {
    compute_pool: Some(0),
    beacon: Some(0),
};

const FAMILIES: [(Family, &str); 2] = [
    (Family::ComputePool, cf::COMPUTE_POOL_STATE_DIFFS),
    (Family::Beacon, cf::BEACON_STATE_DIFFS),
];

/// The families a block's execution changes and a revert must restore.
const STATE_FAMILIES: [&str; 3] = [cf::STATE, cf::BEACON_STATE, cf::COMPUTE_POOL_STATE];

struct Validators {
    keys: Vec<KeyPair>,
    pubs: Vec<[u8; 32]>,
}

fn validators() -> Validators {
    let keys: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate()).collect();
    let pubs = keys.iter().map(|k| *k.public_key().as_bytes()).collect();
    Validators { keys, pubs }
}

fn reg_tx(signer: &KeyPair, secret_seed: u8, fee: u128) -> SignedTransaction {
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
        nonce: 0,
        payload: TxPayload::BeaconSetup(data),
    };
    let sig = sign(tx.signing_hash().as_bytes(), signer.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *signer.public_key().as_bytes())
}

/// One node: its handles, and the parent state it started from.
struct Node {
    state: Arc<StateManager>,
    db: Arc<Database>,
    executor: sumchain_state::executor::BlockExecutor,
    dir: tempfile::TempDir,
    parent_root: Hash,
}

fn node(v: &Validators) -> Node {
    let (state, db, dir, executor) = common::setup_with_params(params());
    let fee = params().min_fee;
    for k in &v.keys[..2] {
        common::fund(&db, k, fee + 1_000);
    }
    let parent_root = state.state_root();
    Node {
        state,
        db,
        executor,
        dir,
        parent_root,
    }
}

/// Block A: proposed by validator 0, registering validator 0's key.
fn publish_a(n: &Node, v: &Validators) -> Block {
    let fee = params().min_fee;
    let tx = reg_tx(&v.keys[0], 7, fee);
    common::publish_block_returning(
        &n.state,
        &n.executor,
        H,
        v.keys[0].public_key().as_bytes(),
        vec![tx],
        &v.pubs,
    )
    .1
}

/// Block B: a competitor at the same height — another proposer, another
/// registration, so another hash and another transition.
fn publish_b(n: &Node, v: &Validators) -> Block {
    let fee = params().min_fee;
    let tx = reg_tx(&v.keys[1], 9, fee);
    common::publish_block_returning(
        &n.state,
        &n.executor,
        H,
        v.keys[1].public_key().as_bytes(),
        vec![tx],
        &v.pubs,
    )
    .1
}

/// Every row of the state families a revert must restore.
fn snapshot(db: &Database) -> BTreeMap<(String, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for family in STATE_FAMILIES {
        for (k, v) in db.full_iter(family).unwrap() {
            out.insert((family.to_string(), k.to_vec()), v.to_vec());
        }
    }
    out
}

fn record_key(block: &Block) -> Vec<u8> {
    sumchain_storage::schema::journal_key(block.height(), &block.hash())
}

fn raw_record(db: &Database, diffs_cf: &str, block: &Block) -> Option<Vec<u8>> {
    db.get(diffs_cf, &record_key(block)).unwrap()
}

/// Stage the unwind of `block` the way the consensus reorg does, and commit it
/// only if it succeeded.
#[allow(clippy::result_large_err)] // `UndoRefusal` is the engine's own error type
fn unwind(
    db: &Database,
    block: &Block,
    gates: SubsystemGates,
) -> Result<UnwindReport, UndoRefusal> {
    let mut batch = db.batch();
    let journal = SubsystemJournals::new(db, gates);
    let report = stage_branch_unwind(
        db,
        &mut batch,
        std::slice::from_ref(block),
        &journal,
        MissingJournalPolicy::ToleratedEverywhere,
    )?;
    batch.commit().unwrap();
    Ok(report)
}

/// The refusal text, for asserting WHICH check refused.
fn refusal(result: Result<UnwindReport, UndoRefusal>) -> String {
    match result {
        Ok(r) => panic!(
            "the unwind must refuse, but it replayed {} records",
            r.records
        ),
        Err(e) => format!("{e:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Apply A, revert A, apply B at the same height: the node ends up on B.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_reverted_block_leaves_its_parent_and_the_competitor_applies_as_if_it_never_existed() {
    let v = validators();
    let x = node(&v);
    let parent = snapshot(&x.db);

    let a = publish_a(&x, &v);
    assert_ne!(snapshot(&x.db), parent, "block A changed state");
    for (family, diffs_cf) in FAMILIES {
        let row =
            raw_record(&x.db, diffs_cf, &a).expect("a gate-open block publishes both records");
        subsystem_journal::open(&row, family, H, &a.hash()).expect("sealed for block A");
    }

    // Revert A through the reorg's unwind: every state row returns to the parent,
    // and both of A's records are consumed.
    let report = unwind(&x.db, &a, GATES).expect("A reverts");
    assert!(
        report.records > 0,
        "A's registration was replayed backwards"
    );
    assert_eq!(
        snapshot(&x.db),
        parent,
        "state is exactly the parent's again"
    );
    for (_, diffs_cf) in FAMILIES {
        assert!(
            raw_record(&x.db, diffs_cf, &a).is_none(),
            "A's record consumed"
        );
    }

    // Apply the competitor B at the same height, from the same parent.
    x.state.set_state_root(x.parent_root);
    let b = publish_b(&x, &v);
    assert_ne!(a.hash(), b.hash(), "two distinct blocks at one height");

    // A node that only ever saw B must be indistinguishable: same state rows,
    // same state root, therefore the same block hash.
    let y = node(&v);
    let b_only = publish_b(&y, &v);
    assert_eq!(
        b.hash(),
        b_only.hash(),
        "identical header and root as a B-only node"
    );
    assert_eq!(x.state.state_root(), y.state.state_root());
    assert_eq!(snapshot(&x.db), snapshot(&y.db), "state matches B exactly");
    assert_eq!(
        BeaconStore::new(&x.db).state_digest().unwrap(),
        BeaconStore::new(&y.db).state_digest().unwrap()
    );
    assert_eq!(
        ComputePoolStore::new(&x.db).state_digest().unwrap(),
        ComputePoolStore::new(&y.db).state_digest().unwrap()
    );

    // B's records are its own, and A's are gone rather than overwritten.
    for (family, diffs_cf) in FAMILIES {
        let row = raw_record(&x.db, diffs_cf, &b).expect("B published its records");
        subsystem_journal::open(&row, family, H, &b.hash()).expect("sealed for block B");
        assert_eq!(
            Some(row),
            raw_record(&y.db, diffs_cf, &b_only),
            "byte-identical to B-only"
        );
    }
}

#[test]
fn competing_blocks_keep_separate_records_and_each_opens_only_for_itself() {
    let v = validators();
    let x = node(&v);
    let a = publish_a(&x, &v);
    let y = node(&v);
    let b = publish_b(&y, &v);

    // Import B's records beside A's, as a node holding both blocks would.
    for (family, diffs_cf) in FAMILIES {
        let a_row = raw_record(&x.db, diffs_cf, &a).unwrap();
        let b_row = raw_record(&y.db, diffs_cf, &b).unwrap();
        x.db.put(diffs_cf, &record_key(&b), &b_row).unwrap();

        // Two rows at one height, neither overwriting the other.
        let at_height =
            x.db.prefix_iter(diffs_cf, &H.to_be_bytes())
                .unwrap()
                .count();
        assert_eq!(at_height, 2, "{family}: one row per block");

        // Each opens for its own block and for no other.
        subsystem_journal::open(&a_row, family, H, &a.hash()).unwrap();
        subsystem_journal::open(&b_row, family, H, &b.hash()).unwrap();
        assert!(subsystem_journal::open(&a_row, family, H, &b.hash()).is_err());
        assert!(subsystem_journal::open(&b_row, family, H, &a.hash()).is_err());
    }

    // Unwinding A consumes A's records and leaves B's byte-for-byte.
    let b_rows: Vec<_> = FAMILIES
        .iter()
        .map(|(_, c)| raw_record(&x.db, c, &b).unwrap())
        .collect();
    unwind(&x.db, &a, GATES).expect("A reverts with B's records present");
    for ((_, diffs_cf), before) in FAMILIES.iter().zip(b_rows) {
        assert!(raw_record(&x.db, diffs_cf, &a).is_none());
        assert_eq!(raw_record(&x.db, diffs_cf, &b), Some(before));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A record that is not A's is refused, and nothing is committed.
// ─────────────────────────────────────────────────────────────────────────────

/// Publish A, replace its `family` row with what `damage` makes of it (`None`
/// deletes the row), try to revert A, and require a refusal naming `expect`
/// that leaves every row — state and journal — untouched.
fn assert_refused_without_effect(
    family: Family,
    diffs_cf: &str,
    damage: impl FnOnce(&Block, &[u8]) -> Option<Vec<u8>>,
    expect: &str,
) {
    let v = validators();
    let x = node(&v);
    let a = publish_a(&x, &v);
    let row = raw_record(&x.db, diffs_cf, &a).unwrap();
    let bytes = damage(&a, &row);
    match &bytes {
        Some(b) => x.db.put(diffs_cf, &record_key(&a), b).unwrap(),
        None => x.db.delete(diffs_cf, &record_key(&a)).unwrap(),
    }
    let state_before = snapshot(&x.db);
    let journals_before: Vec<_> = FAMILIES
        .iter()
        .map(|(_, c)| raw_record(&x.db, c, &a))
        .collect();

    let why = refusal(unwind(&x.db, &a, GATES));
    assert!(
        why.contains(expect),
        "{family}: expected a refusal naming {expect:?}, got {why}"
    );

    assert_eq!(snapshot(&x.db), state_before, "{family}: nothing reverted");
    let journals_after: Vec<_> = FAMILIES
        .iter()
        .map(|(_, c)| raw_record(&x.db, c, &a))
        .collect();
    assert_eq!(
        journals_after, journals_before,
        "{family}: no record consumed"
    );
}

#[test]
fn a_record_for_the_competing_block_is_refused() {
    // Right height, right family, a real record — for B, not for A.
    for (family, diffs_cf) in FAMILIES {
        let v = validators();
        let y = node(&v);
        let b = publish_b(&y, &v);
        let b_row = raw_record(&y.db, diffs_cf, &b).unwrap();
        assert_refused_without_effect(
            family,
            diffs_cf,
            |_, _| Some(b_row),
            "not the reverted block",
        );
    }
}

#[test]
fn a_record_naming_the_right_block_at_the_wrong_height_is_refused() {
    for (family, diffs_cf) in FAMILIES {
        // The block hash is recovered from a real A, so only the height is wrong.
        let v = validators();
        let x = node(&v);
        let a = publish_a(&x, &v);
        let row = raw_record(&x.db, diffs_cf, &a).unwrap();
        let payload = subsystem_journal::open(&row, family, H, &a.hash())
            .unwrap()
            .to_vec();
        let wrong = subsystem_journal::seal(family, H + 1, &a.hash(), &payload).unwrap();
        x.db.put(diffs_cf, &record_key(&a), &wrong).unwrap();
        let state_before = snapshot(&x.db);

        let why = refusal(unwind(&x.db, &a, GATES));
        assert!(why.contains("records height"), "{family}: {why}");
        assert_eq!(snapshot(&x.db), state_before, "{family}: nothing reverted");
        assert_eq!(
            raw_record(&x.db, diffs_cf, &a),
            Some(wrong),
            "{family}: record kept"
        );
    }
}

#[test]
fn malformed_records_are_refused_and_nothing_is_committed() {
    type Damage = fn(Family, &Block, &[u8]) -> Option<Vec<u8>>;
    fn payload(family: Family, a: &Block, row: &[u8]) -> Vec<u8> {
        subsystem_journal::open(row, family, H, &a.hash())
            .unwrap()
            .to_vec()
    }
    fn other(family: Family) -> Family {
        match family {
            Family::ComputePool => Family::Beacon,
            Family::Beacon => Family::ComputePool,
        }
    }
    let cases: [(&str, Damage, &str); 10] = [
        ("empty row", |_, _, _| Some(vec![]), "shorter than"),
        (
            "header cut short",
            |_, _, row| Some(row[..20].to_vec()),
            "shorter than",
        ),
        (
            "payload cut short",
            |_, _, row| Some(row[..row.len() - 1].to_vec()),
            "payload but carries",
        ),
        (
            "trailing byte",
            |_, _, row| Some([row, &[0u8][..]].concat()),
            "payload but carries",
        ),
        (
            "bad magic",
            |_, _, row| {
                let mut r = row.to_vec();
                r[0] ^= 0xFF;
                Some(r)
            },
            "magic",
        ),
        (
            "unknown version",
            |_, _, row| {
                let mut r = row.to_vec();
                r[4] = 2;
                Some(r)
            },
            "version",
        ),
        (
            "the other family's record",
            |f, a, row| {
                Some(subsystem_journal::seal(other(f), H, &a.hash(), &payload(f, a, row)).unwrap())
            },
            "family tag",
        ),
        // Too short for a header (the empty compute-pool payload) or long enough
        // and without the magic (the beacon one): refused by the envelope either way.
        (
            "an unsealed payload",
            |f, a, row| Some(payload(f, a, row)),
            "envelope",
        ),
        (
            "a corrupt payload, correctly sealed",
            |f, a, _| Some(subsystem_journal::seal(f, H, &a.hash(), &[0xFF; 4]).unwrap()),
            "journal",
        ),
        ("missing", |_, _, _| None, "missing"),
    ];
    for (family, diffs_cf) in FAMILIES {
        for (label, damage, expect) in cases {
            eprintln!("{family}: {label}");
            assert_refused_without_effect(
                family,
                diffs_cf,
                |a, row| damage(family, a, row),
                expect,
            );
        }
    }
}

#[test]
fn a_record_where_the_gate_was_closed_is_refused() {
    // A record no binary following the gate rule writes: the chain says the
    // subsystem was dormant at this height, yet a record is there.
    let v = validators();
    let x = node(&v);
    let a = publish_a(&x, &v);
    let state_before = snapshot(&x.db);
    for gates in [
        SubsystemGates {
            compute_pool: None,
            ..GATES
        },
        SubsystemGates {
            beacon: Some(H + 1),
            ..GATES
        },
    ] {
        let why = refusal(unwind(&x.db, &a, gates));
        assert!(why.contains("gate was closed"), "{why}");
        assert_eq!(snapshot(&x.db), state_before);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Restart, and atomicity of the forward write and of the revert.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_restart_between_publication_and_revert_changes_nothing() {
    let v = validators();
    let x = node(&v);
    let parent = snapshot(&x.db);
    let parent_root = x.parent_root;
    let a = publish_a(&x, &v);
    let after_a = snapshot(&x.db);

    // Restart: every handle dropped, RocksDB closed and reopened from disk.
    let Node {
        state,
        db,
        executor,
        dir,
        ..
    } = x;
    drop((state, executor, db));
    let (state, db, executor) = common::reopen(&dir, params());
    assert_eq!(snapshot(&db), after_a, "reopened on A's published state");

    unwind(&db, &a, GATES).expect("A reverts after a restart");
    assert_eq!(snapshot(&db), parent);

    state.set_state_root(parent_root);
    let reopened = Node {
        state,
        db,
        executor,
        dir,
        parent_root,
    };
    let b = publish_b(&reopened, &v);
    let y = node(&v);
    let b_only = publish_b(&y, &v);
    assert_eq!(b.hash(), b_only.hash());
    assert_eq!(snapshot(&reopened.db), snapshot(&y.db));
}

#[test]
fn a_block_that_is_not_published_leaves_neither_state_nor_record() {
    // The forward write and its record move together: the record is staged into
    // the block's own candidate and reaches storage in the publication batch, or
    // not at all. Executed and dropped, the block leaves no trace of either.
    let v = validators();
    let x = node(&v);
    let parent = snapshot(&x.db);
    let fee = params().min_fee;
    let block = Block::new(
        sumchain_primitives::BlockHeader::new(
            Hash::ZERO,
            H,
            1000,
            Hash::ZERO,
            Hash::ZERO,
            *v.keys[0].public_key().as_bytes(),
        ),
        vec![reg_tx(&v.keys[0], 7, fee)],
    );
    let exec = x
        .executor
        .execute_block(&block, x.state.state_root(), &v.pubs)
        .unwrap();
    drop(exec);
    assert_eq!(snapshot(&x.db), parent, "no state row without publication");
    for (_, diffs_cf) in FAMILIES {
        assert_eq!(
            x.db.prefix_iter(diffs_cf, &H.to_be_bytes())
                .unwrap()
                .count(),
            0,
            "no record without publication"
        );
    }

    // Published, both are there, and the record names the block that was.
    let a = publish_a(&x, &v);
    assert_ne!(snapshot(&x.db), parent);
    for (family, diffs_cf) in FAMILIES {
        let row = raw_record(&x.db, diffs_cf, &a).unwrap();
        subsystem_journal::open(&row, family, H, &a.hash()).unwrap();
    }
}

#[test]
fn a_revert_restores_state_and_consumes_the_record_in_one_batch() {
    let v = validators();
    let x = node(&v);
    let parent = snapshot(&x.db);
    let a = publish_a(&x, &v);
    let after_a = snapshot(&x.db);

    // Staged but not committed: neither the restore nor the deletion is visible.
    {
        let mut batch = x.db.batch();
        let journal = SubsystemJournals::new(&x.db, GATES);
        stage_branch_unwind(
            &x.db,
            &mut batch,
            std::slice::from_ref(&a),
            &journal,
            MissingJournalPolicy::ToleratedEverywhere,
        )
        .unwrap();
        // Dropped uncommitted, as a crash before the write would leave it.
    }
    assert_eq!(snapshot(&x.db), after_a);
    for (_, diffs_cf) in FAMILIES {
        assert!(raw_record(&x.db, diffs_cf, &a).is_some());
    }

    // Committed: both at once.
    unwind(&x.db, &a, GATES).unwrap();
    assert_eq!(snapshot(&x.db), parent);
    for (_, diffs_cf) in FAMILIES {
        assert!(raw_record(&x.db, diffs_cf, &a).is_none());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The legacy per-block revert path applies the same rules.
// ─────────────────────────────────────────────────────────────────────────────

fn pre_activation(block: &Block) -> PreActivationBlock {
    // A boundary above the block, so the block is in the legacy region.
    let activation = JournalActivation::pinned(block.height() + 1);
    PreActivationBlock::classify(&activation, block.height(), block.hash()).unwrap()
}

#[test]
fn the_legacy_revert_path_refuses_a_missing_or_foreign_record_all_or_none() {
    for (family, diffs_cf) in FAMILIES {
        let v = validators();
        let x = node(&v);
        let a = publish_a(&x, &v);
        let y = node(&v);
        let b = publish_b(&y, &v);

        for replacement in [None, raw_record(&y.db, diffs_cf, &b)] {
            match &replacement {
                Some(bytes) => x.db.put(diffs_cf, &record_key(&a), bytes).unwrap(),
                None => x.db.delete(diffs_cf, &record_key(&a)).unwrap(),
            }
            let before = snapshot(&x.db);
            assert!(
                x.state
                    .revert_pre_activation_block_state_diffs(&pre_activation(&a), GATES)
                    .is_err(),
                "{family}: refused"
            );
            assert_eq!(
                snapshot(&x.db),
                before,
                "{family}: account state not reverted alone"
            );
        }
    }

    // And with A's own records it reverts everything, consuming them.
    let v = validators();
    let x = node(&v);
    let parent = snapshot(&x.db);
    let a = publish_a(&x, &v);
    x.state
        .revert_pre_activation_block_state_diffs(&pre_activation(&a), GATES)
        .unwrap();
    assert_eq!(snapshot(&x.db), parent);
    for (_, diffs_cf) in FAMILIES {
        assert!(raw_record(&x.db, diffs_cf, &a).is_none());
    }
}
