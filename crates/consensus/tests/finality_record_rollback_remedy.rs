//! Which damaged local-depth finality records the operator rollback repairs
//! (#350), as `docs/operator-guide.md` (Restarts) states it.
//!
//! The rollback rewrites the record only when it can read `finalized_height`
//! and that height is above its target (`reorg::execute_rollback`). So a
//! rollback below the recorded height repairs a height without its hash,
//! another block's hash, an undecodable hash and a height above the head; it
//! leaves a hash without its height as it is, and stops on an undecodable
//! height. Each case damages a real database, rolls back below the recorded
//! height, and asks the start (`load_chain`) for its verdict.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::branch_switch::failpoints::arm;
use sumchain_consensus::reorg::{execute_rollback, plan_rollback};
use sumchain_consensus::{ConsensusEngine, PoAEngine};
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_state::reorg_undo::ActivatedJournal;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::journal::ActivationSource;
use sumchain_storage::schema::meta_keys;
use sumchain_storage::subsystem_journal::SubsystemGates;
use sumchain_storage::{cf, BlockStore, Database};
use tempfile::TempDir;

const CHAIN_ID: u64 = 1;

fn validator() -> KeyPair {
    KeyPair::from_bytes([7u8; 32])
}

fn genesis() -> Genesis {
    Genesis::new(
        CHAIN_ID,
        0,
        vec![validator().public_key().to_base58()],
        HashMap::from([(validator().address().to_base58(), 1_000_000u128)]),
        ChainParams {
            finality_depth: 2,
            application_journal_enabled_from_height: Some(1),
            ..ChainParams::default()
        },
    )
}

fn engine(db: &Arc<Database>, state: &Arc<StateManager>, key: Option<KeyPair>) -> PoAEngine {
    PoAEngine::new(
        db.clone(),
        state.clone(),
        Arc::new(Mempool::new(MempoolConfig::default())),
        &genesis(),
        key,
    )
    .unwrap()
}

/// Genesis and six produced blocks: the record names height 4.
async fn chain() -> (TempDir, Arc<Database>, Arc<StateManager>) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    let e = engine(&db, &state, Some(validator()));
    e.init_genesis(&genesis()).unwrap();
    for _ in 0..6 {
        e.propose_block(Vec::new()).await.unwrap();
    }
    let at4 = BlockStore::new(&db).get_hash_by_height(4).unwrap().unwrap();
    assert_eq!(
        BlockStore::new(&db).checked_finality_record().unwrap(),
        Some((4, at4))
    );
    (dir, db, state)
}

fn roll_back(db: &Database, state: &StateManager, to: u64) -> sumchain_consensus::Result<()> {
    let journals = ActivatedJournal::resolve(
        db,
        ActivationSource::from_configured_height(Some(1)),
        SubsystemGates::DORMANT,
    )
    .unwrap();
    let plan = plan_rollback(&BlockStore::new(db), to, 10, &journals.activation())?;
    execute_rollback(db, state, &plan, &journals, journals.policy()).map(|_| ())
}

/// The start's verdict on the database as it stands.
fn starts(db: &Arc<Database>) -> Result<(), String> {
    let state = Arc::new(StateManager::new(db.clone(), CHAIN_ID));
    engine(db, &state, None)
        .load_chain()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// What a case does to the record of a stopped node's database.
type Damage = fn(&Database);

#[tokio::test]
async fn a_rollback_below_the_record_repairs_the_records_it_can_read_a_height_from() {
    arm(None);
    let cases: [(&str, Damage); 4] = [
        ("a height without its hash", |db| {
            db.delete(cf::META, meta_keys::FINALIZED_HASH).unwrap()
        }),
        ("another block's hash", |db| {
            let h3 = BlockStore::new(db).get_hash_by_height(3).unwrap().unwrap();
            db.put(cf::META, meta_keys::FINALIZED_HASH, h3.as_bytes())
                .unwrap()
        }),
        ("an undecodable hash", |db| {
            db.put(cf::META, meta_keys::FINALIZED_HASH, &[9u8; 5])
                .unwrap()
        }),
        ("a height above the head", |db| {
            db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &99u64.to_be_bytes())
                .unwrap()
        }),
    ];
    for (what, damage) in cases {
        let (_dir, db, state) = chain().await;
        damage(&db);
        assert!(starts(&db).is_err(), "{what}: the start refuses it");

        roll_back(&db, &state, 2).unwrap_or_else(|e| panic!("{what}: {e}"));
        let at2 = BlockStore::new(&db).get_hash_by_height(2).unwrap().unwrap();
        assert_eq!(
            BlockStore::new(&db).checked_finality_record(),
            Ok(Some((2, at2))),
            "{what}: the rollback rewrites both keys"
        );
        starts(&db).unwrap_or_else(|e| panic!("{what}: the start accepts it now: {e}"));
    }
}

#[tokio::test]
async fn a_rollback_leaves_a_hash_without_its_height_as_it_is() {
    arm(None);
    let (_dir, db, state) = chain().await;
    db.delete(cf::META, meta_keys::FINALIZED_HEIGHT).unwrap();
    let before = BlockStore::new(&db).checked_finality_record();
    assert!(before.is_err());

    roll_back(&db, &state, 2).expect("the rollback itself runs");
    assert!(
        BlockStore::new(&db)
            .get_finalized_height()
            .unwrap()
            .is_none(),
        "the rollback wrote no height"
    );
    assert!(
        BlockStore::new(&db).checked_finality_record().is_err(),
        "the record is still a hash without its height"
    );
    assert!(starts(&db).is_err(), "and the start still refuses it");
}

#[tokio::test]
async fn a_rollback_stops_on_an_undecodable_height() {
    arm(None);
    let (_dir, db, state) = chain().await;
    db.put(cf::META, meta_keys::FINALIZED_HEIGHT, &[3u8; 7])
        .unwrap();
    let head = BlockStore::new(&db).get_latest_height().unwrap();

    let err = roll_back(&db, &state, 2).expect_err("the rollback cannot read the height");
    assert!(
        err.to_string().contains("Invalid finalized height bytes"),
        "{err}"
    );
    assert_eq!(
        BlockStore::new(&db).get_latest_height().unwrap(),
        head,
        "a stopped rollback rolled nothing back"
    );
    assert!(starts(&db).is_err());
}
