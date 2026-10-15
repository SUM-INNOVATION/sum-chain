//! The C1 compute-pool read RPCs (#130) report what committed pool state
//! holds, and nothing else.
//!
//! Pool state is built with the real model operations (`create_job`,
//! `publish_offer`, `reserve_capacity`, `put_assignment`, `accept_leaf`,
//! `transition_unit`) and committed the way a block commits it:
//! `ComputePoolStore::stage_transition` into a candidate's `ExecutionView`,
//! then `accept_imported` -> `publish`. No valid row is written as raw bytes;
//! only the malformed-row tests write bytes directly, because no store API can
//! produce a corrupt row. Genesis validation refuses the pool gate on every
//! network, which is why a production chain answers `null` to every read.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{Address, Block, BlockHeader, Hash};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::{
    PoolAcceptedLeafInfo, PoolAssignmentInfo, PoolOfferInfo, PoolRequiredInputInfo,
    PoolReservationInfo, PoolUnitInfo,
};
use sumchain_state::compute_pool::{
    AcceptedLeaf, AssignmentIndexEntry, BondedOffer, CommitBondId, ComputePoolModel,
    ExposureInputs, JobId, OfferBondId, RequiredInput, SlotId, UnitId, UnitKey, UnitSizing,
    UnitState, WorkItemKey, WorkUnit,
};
use sumchain_state::compute_pool_store::{
    active_offer_index_key_bytes, offer_key_bytes, reservation_key_bytes, unit_key_bytes,
    ComputePoolStore,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;
use tokio::sync::mpsc;

const INVALID_PARAMS: i32 = -32602;
const INTERNAL: i32 = -32603;

fn server() -> (RpcServer, Arc<Database>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::from_bytes([0x51; 32]);
    // The production default: the pool gate is closed.
    let genesis = Genesis::new(
        1,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1u128)]),
        ChainParams::default(),
    );
    let engine = Arc::new(
        PoAEngine::new(
            db.clone(),
            state.clone(),
            mempool.clone(),
            &genesis,
            Some(validator),
        )
        .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let srv = RpcServer::new(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
    );
    (srv, db, dir)
}

fn jid(b: u8) -> JobId {
    JobId::from_bytes([b; 32])
}
fn uid(b: u8) -> UnitId {
    UnitId::from_bytes([b; 32])
}
fn oid(b: u8) -> OfferBondId {
    OfferBondId::from_bytes([b; 32])
}
fn addr(b: u8) -> Address {
    Address::new([b; 20])
}
fn hex32(b: u8) -> String {
    format!("0x{}", hex::encode([b; 32]))
}

fn unit(job: JobId, u: UnitId) -> WorkUnit {
    WorkUnit {
        job_id: job,
        unit_id: u,
        predecessors: vec![],
        required_inputs: vec![],
        generation: 0,
        state: UnitState::Blocked,
    }
}

fn offer(id: OfferBondId, identity: Address, active: bool) -> BondedOffer {
    BondedOffer {
        offer_bond_id: id,
        identity,
        payment_addr: addr(0x50),
        offered_bytes: 1_000,
        offer_seq: 3,
        bond_locked: 500,
        active,
    }
}

/// Job 1 with three units:
/// * unit 2: assigned to offer 3 and accepted (leaf with commit bond 4);
/// * unit 3: assigned to offer 3, not accepted;
/// * unit 4: blocked on unit 2, with one required input.
///
/// Offer 3 is active with a reservation; offer 5 is inactive, with none.
fn model() -> ComputePoolModel {
    let mut m = ComputePoolModel::new();
    let j = jid(1);
    let mut u4 = unit(j, uid(4));
    u4.predecessors = vec![uid(2)];
    u4.required_inputs = vec![RequiredInput {
        predecessor: uid(2),
        required_output_slot_id: SlotId::from_bytes([0x21; 32]),
        pred_output_manifest_root: Hash::new([0x22; 32]),
        required_slot_state_object_root: Hash::new([0x23; 32]),
    }];
    let units = vec![unit(j, uid(2)), unit(j, uid(3)), u4];
    let sizing: Vec<UnitSizing> = units.iter().map(|_| UnitSizing { slots: 0 }).collect();
    m.create_job(
        j,
        addr(9),
        1,
        units,
        &sizing,
        1,
        0,
        1_000,
        ExposureInputs {
            q: 100,
            reprovision_allowance: 10,
            job_max_retention_files: 0,
            max_reassignments_per_file: 2,
            reassign_reimb: 5,
        },
        1_000_000,
    )
    .unwrap();

    m.publish_offer(offer(oid(3), addr(8), true)).unwrap();
    m.publish_offer(offer(oid(5), addr(7), false)).unwrap();
    m.reserve_capacity(oid(3), 1_000, 160).unwrap();

    for u in [uid(2), uid(3)] {
        let key = UnitKey::new(j, u);
        m.transition_unit(&key, UnitState::Eligible).unwrap();
        m.transition_unit(&key, UnitState::Assigned).unwrap();
        m.put_assignment(AssignmentIndexEntry {
            key: WorkItemKey::new(j, u, 0),
            winner_offer_bond_id: oid(3),
            winner_payment_addr: addr(0x50),
        })
        .unwrap();
    }
    m.accept_leaf(AcceptedLeaf {
        key: WorkItemKey::new(j, uid(2), 0),
        offer_bond_id: oid(3),
        commit_bond_id: CommitBondId::from_bytes([4; 32]),
        accepted_bytes: 100,
    })
    .unwrap();
    m.transition_unit(&UnitKey::new(j, uid(2)), UnitState::Accepted)
        .unwrap();
    m
}

/// Commit `after` as block `height` publishes it.
fn publish(
    db: &Database,
    before: Option<&ComputePoolModel>,
    after: &ComputePoolModel,
    height: u64,
) {
    let header = BlockHeader::new(
        Hash::hash(b"parent"),
        height,
        1_000 + height,
        Hash::hash(&height.to_be_bytes()),
        Hash::hash(b"root"),
        [0u8; 32],
    );
    let block = Block::new(header, Vec::new());
    let mut cand = CandidateExecution::new(db, 1 << 24);
    let journal = {
        let mut view = cand.view();
        let (mutated, journal) =
            ComputePoolStore::stage_transition(&mut view, before, after).unwrap();
        assert!(mutated > 0);
        journal
    };
    cand.finish_execution(
        ExecutionSubject::of(&block).unwrap(),
        block.header.state_root,
        Vec::new(),
        BlockJournals {
            account: JournalRecord::NothingToUndo,
            contract: JournalRecord::NothingToUndo,
            compute_pool: journal,
            beacon: JournalRecord::NothingToUndo,
        },
    )
    .accept_imported(&block)
    .unwrap()
    .publish()
    .unwrap();
}

/// Every row in every column family, to prove the reads write nothing.
fn snapshot(db: &Database) -> BTreeMap<(&'static str, Vec<u8>), Vec<u8>> {
    let mut out = BTreeMap::new();
    for cf in sumchain_storage::db::ALL_CFS {
        for (k, v) in db.full_iter(cf).unwrap() {
            out.insert((*cf, k.to_vec()), v.to_vec());
        }
    }
    out
}

async fn unit_of(srv: &RpcServer, job: u8, u: u8) -> Result<Option<PoolUnitInfo>, i32> {
    srv.pool_get_unit(hex32(job), hex32(u))
        .await
        .map_err(|e| e.code())
}

async fn offer_of(srv: &RpcServer, id: u8) -> Result<Option<PoolOfferInfo>, i32> {
    srv.pool_get_offer(hex32(id)).await.map_err(|e| e.code())
}

#[tokio::test]
async fn every_read_is_null_while_the_pool_gate_is_closed() {
    let (srv, db, _dir) = server();
    let before = snapshot(&db);
    assert_eq!(unit_of(&srv, 1, 2).await, Ok(None));
    assert_eq!(offer_of(&srv, 3).await, Ok(None));
    assert_eq!(snapshot(&db), before);
}

#[tokio::test]
async fn a_unit_reports_its_row_and_its_current_generations_work_item() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);

    let accepted = unit_of(&srv, 1, 2).await.unwrap().unwrap();
    assert_eq!(
        accepted,
        PoolUnitInfo {
            job_id: hex32(1),
            unit_id: hex32(2),
            generation: 0,
            state: "accepted".to_string(),
            predecessors: vec![],
            required_inputs: vec![],
            assignment: Some(PoolAssignmentInfo {
                winner_offer_bond_id: hex32(3),
                winner_payment_addr: addr(0x50).to_base58(),
            }),
            accepted_leaf: Some(PoolAcceptedLeafInfo {
                offer_bond_id: hex32(3),
                commit_bond_id: hex32(4),
                accepted_bytes: "100".to_string(),
            }),
        }
    );

    let assigned = unit_of(&srv, 1, 3).await.unwrap().unwrap();
    assert_eq!(assigned.state, "assigned");
    assert!(assigned.assignment.is_some());
    assert_eq!(assigned.accepted_leaf, None, "not accepted: no leaf");

    let blocked = unit_of(&srv, 1, 4).await.unwrap().unwrap();
    assert_eq!(blocked.state, "blocked");
    assert_eq!(blocked.predecessors, vec![hex32(2)]);
    assert_eq!(
        blocked.required_inputs,
        vec![PoolRequiredInputInfo {
            predecessor: hex32(2),
            required_output_slot_id: hex32(0x21),
            pred_output_manifest_root: hex32(0x22),
            required_slot_state_object_root: hex32(0x23),
        }]
    );
    assert_eq!(blocked.assignment, None);
    assert_eq!(blocked.accepted_leaf, None);

    // Absent rows stay absent: another unit, another job.
    assert_eq!(unit_of(&srv, 1, 9).await, Ok(None));
    assert_eq!(unit_of(&srv, 2, 2).await, Ok(None));
}

#[tokio::test]
async fn an_offer_reports_its_reservation_and_whether_it_is_active() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);

    assert_eq!(
        offer_of(&srv, 3).await.unwrap().unwrap(),
        PoolOfferInfo {
            offer_bond_id: hex32(3),
            identity: addr(8).to_base58(),
            payment_addr: addr(0x50).to_base58(),
            offered_bytes: "1000".to_string(),
            offer_seq: 3,
            bond_locked: "500".to_string(),
            active: true,
            reservation: Some(PoolReservationInfo {
                offered: "1000".to_string(),
                reserved: "160".to_string(),
            }),
        }
    );
    let inactive = offer_of(&srv, 5).await.unwrap().unwrap();
    assert!(!inactive.active);
    assert_eq!(inactive.identity, addr(7).to_base58());
    assert_eq!(inactive.reservation, None);
    assert_eq!(offer_of(&srv, 6).await, Ok(None));
}

#[tokio::test]
async fn a_later_block_is_what_the_reads_report() {
    // The answer follows committed state: after a block reserves more and
    // retires the offer, the reads say so.
    let (srv, db, _dir) = server();
    let first = model();
    publish(&db, None, &first, 1);
    let mut second = first.clone();
    second.reserve_capacity(oid(3), 1_000, 40).unwrap();
    publish(&db, Some(&first), &second, 2);
    let o = offer_of(&srv, 3).await.unwrap().unwrap();
    assert_eq!(o.reservation.unwrap().reserved, "200");
}

#[tokio::test]
async fn ids_are_32_byte_hex_with_or_without_0x() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    let bare = srv
        .pool_get_unit(hex::encode([1u8; 32]), hex::encode([2u8; 32]))
        .await
        .unwrap();
    assert_eq!(bare, unit_of(&srv, 1, 2).await.unwrap());
    for bad in ["", "0x", "0x1234", "zz", &"00".repeat(33)] {
        let e = srv
            .pool_get_unit(bad.to_string(), hex32(2))
            .await
            .unwrap_err();
        assert_eq!(e.code(), INVALID_PARAMS, "job id {bad:?}");
        let e = srv.pool_get_offer(bad.to_string()).await.unwrap_err();
        assert_eq!(e.code(), INVALID_PARAMS, "offer id {bad:?}");
    }
}

#[tokio::test]
async fn a_row_that_does_not_decode_is_an_internal_error_never_null() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    db.put(
        cf::COMPUTE_POOL_STATE,
        &unit_key_bytes(&jid(1), &uid(3)),
        b"garbage",
    )
    .unwrap();
    db.put(cf::COMPUTE_POOL_STATE, &offer_key_bytes(&oid(5)), b"")
        .unwrap();
    assert_eq!(unit_of(&srv, 1, 3).await, Err(INTERNAL));
    assert_eq!(offer_of(&srv, 5).await, Err(INTERNAL));
    // The rows beside them still answer.
    assert!(unit_of(&srv, 1, 2).await.unwrap().is_some());
    assert!(offer_of(&srv, 3).await.unwrap().is_some());
}

#[tokio::test]
async fn a_row_stored_under_another_key_is_refused() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    let unit_row = db
        .get(cf::COMPUTE_POOL_STATE, &unit_key_bytes(&jid(1), &uid(2)))
        .unwrap()
        .unwrap();
    db.put(
        cf::COMPUTE_POOL_STATE,
        &unit_key_bytes(&jid(1), &uid(9)),
        &unit_row,
    )
    .unwrap();
    assert_eq!(unit_of(&srv, 1, 9).await, Err(INTERNAL));

    let offer_row = db
        .get(cf::COMPUTE_POOL_STATE, &offer_key_bytes(&oid(5)))
        .unwrap()
        .unwrap();
    db.put(
        cf::COMPUTE_POOL_STATE,
        &offer_key_bytes(&oid(6)),
        &offer_row,
    )
    .unwrap();
    assert_eq!(offer_of(&srv, 6).await, Err(INTERNAL));
}

#[tokio::test]
async fn an_offer_that_disagrees_with_the_active_offer_index_is_refused() {
    let (srv, db, _dir) = server();
    let m = model();
    publish(&db, None, &m, 1);

    // The active offer's index row is gone.
    db.delete(
        cf::COMPUTE_POOL_STATE,
        &active_offer_index_key_bytes(&addr(8)),
    )
    .unwrap();
    assert_eq!(offer_of(&srv, 3).await, Err(INTERNAL));

    // The index names an inactive offer. The row is the real codec's: taken
    // from a model in which offer 5 is active.
    let mut other = ComputePoolModel::new();
    other.publish_offer(offer(oid(5), addr(7), true)).unwrap();
    let rows = ComputePoolStore::materialize(&other).unwrap();
    let index_key = active_offer_index_key_bytes(&addr(7));
    db.put(cf::COMPUTE_POOL_STATE, &index_key, &rows[&index_key])
        .unwrap();
    assert_eq!(offer_of(&srv, 5).await, Err(INTERNAL));
}

#[tokio::test]
async fn a_reservation_above_its_capacity_is_refused() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    let key = reservation_key_bytes(&oid(3));
    let mut row = db.get(cf::COMPUTE_POOL_STATE, &key).unwrap().unwrap();
    // Fixint little-endian: version (1) ‖ id (32) ‖ offered (16) ‖ reserved (16).
    assert_eq!(row.len(), 65);
    row[49..65].copy_from_slice(&1_001u128.to_le_bytes());
    db.put(cf::COMPUTE_POOL_STATE, &key, &row).unwrap();
    assert_eq!(offer_of(&srv, 3).await, Err(INTERNAL));
}

#[tokio::test]
async fn the_reads_write_nothing_even_when_they_refuse() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    db.put(
        cf::COMPUTE_POOL_STATE,
        &unit_key_bytes(&jid(1), &uid(3)),
        b"garbage",
    )
    .unwrap();
    let before = snapshot(&db);
    for u in [2u8, 3, 4, 9] {
        let _ = unit_of(&srv, 1, u).await;
    }
    for o in [3u8, 5, 6] {
        let _ = offer_of(&srv, o).await;
    }
    let _ = srv.pool_get_unit("zz".into(), "zz".into()).await;
    assert_eq!(snapshot(&db), before);
}

#[tokio::test]
async fn the_methods_answer_over_json_rpc_under_their_names() {
    let (srv, db, _dir) = server();
    publish(&db, None, &model(), 1);
    let module = srv.into_rpc();
    let call = |method: &str, params: serde_json::Value| {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
    };

    let (resp, _rx) = module
        .raw_json_request(
            &call("pool_getUnit", serde_json::json!([hex32(1), hex32(2)])),
            1,
        )
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(resp.get()).unwrap();
    let r = &v["result"];
    assert_eq!(r["state"], "accepted");
    assert_eq!(r["accepted_leaf"]["commit_bond_id"], hex32(4));
    assert_eq!(r["assignment"]["winner_offer_bond_id"], hex32(3));

    let (resp, _rx) = module
        .raw_json_request(&call("pool_getOffer", serde_json::json!([hex32(6)])), 1)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(resp.get()).unwrap();
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(v["result"], serde_json::Value::Null);
}
