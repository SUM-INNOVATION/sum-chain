//! The C5 registry record reads (#128), `registry_getRecord` and
//! `registry_getRecords`, report what committed registry state holds under
//! `registry/v1/` in `cf::STATE`, and nothing else, over a real `RpcServer` and
//! RocksDB.
//!
//! The registry is dormant: operations 8 and 9 do not decode, so no block can
//! write a record, and on a real chain every read is `null` or empty. Rows are
//! therefore written the way the state crate's registry tests write them:
//! encoded `RegistryRecordV1`s put directly under `registry_record_key`, and,
//! once, through the dormant `execute_registry_ingress` entry with test-fixture
//! parameters, published as a block publishes it. Every parameter value below
//! is a TEST FIXTURE, not a proposal.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::governance::GovernanceParams;
use sumchain_primitives::validator_authority::ValidatorApproval;
use sumchain_primitives::{Address, Block, BlockHeader, Hash, TxStatus};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::registry_types::{dry_run_response, RegistryRecordView};
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::{RPC_PAGE_DEFAULT, RPC_PAGE_MAX};
use sumchain_state::governance_executor::execute_registry_ingress;
use sumchain_state::registry_ingress::{
    registry_record_key, RegistryIngressContext, RegistryIngressOp, REGISTRY_RECORD_KEY_PREFIX,
};
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::candidate::{
    BlockJournals, CandidateExecution, ExecutionSubject, JournalRecord,
};
use sumchain_storage::schema::AccountState;
use sumchain_storage::{cf, Database, StateStore};
use sumchain_wire::registry_ingress::{
    registry_disable_signing_bytes, registry_register_signing_bytes, RegistryDisableV1,
    RegistryIngressParams, RegistryRegisterV1,
};
use sumchain_wire::registry_wire::{RegistryRecordV1, RegistryStatus};
use tempfile::TempDir;
use tokio::sync::mpsc;

const INVALID_PARAMS: i32 = -32602;
const INTERNAL: i32 = -32603;
const PAGE_OUT_OF_BOUNDS: i32 = -32004;

fn server() -> (RpcServer, Arc<Database>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::from_bytes([0x52; 32]);
    // The production default: no registry operation decodes.
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

/// A record whose every field differs from the others, so a field read from
/// the wrong offset cannot pass.
fn record(id: [u8; 32]) -> RegistryRecordV1 {
    RegistryRecordV1 {
        id,
        proof_system_id: 2,
        audit_commitment: [0xA1; 32],
        source_commitment: [0xB2; 32],
        ceremony_commitment: [0xC3; 32],
        verifier_binary_version: 0x0102_0304,
        activation_height: 0x0A0B_0C0D_0E0F_1011,
        status: RegistryStatus::Enabled,
        approval_threshold_bps: 6_667,
    }
}

fn id(b: u8) -> [u8; 32] {
    [b; 32]
}

fn hex32(b: u8) -> String {
    format!("0x{}", hex::encode(id(b)))
}

/// Store `r` under its own id, as committed state holds it.
fn store(db: &Database, r: &RegistryRecordV1) {
    put_raw(db, &registry_record_key(&r.id), &r.try_encode().unwrap());
}

fn put_raw(db: &Database, key: &[u8], value: &[u8]) {
    db.put(cf::STATE, key, value).unwrap();
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

async fn get(srv: &RpcServer, id: u8) -> Result<Option<RegistryRecordView>, i32> {
    srv.registry_get_record(hex32(id))
        .await
        .map_err(|e| e.code())
}

async fn list(
    srv: &RpcServer,
    start_after: Option<[u8; 32]>,
    limit: Option<u32>,
) -> Result<Vec<RegistryRecordView>, i32> {
    srv.registry_get_records(start_after.map(|s| format!("0x{}", hex::encode(s))), limit)
        .await
        .map_err(|e| e.code())
}

fn ids(page: &[RegistryRecordView]) -> Vec<String> {
    page.iter().map(|r| r.id.clone()).collect()
}

#[tokio::test]
async fn every_read_is_empty_while_the_registry_is_dormant() {
    let (srv, db, _dir) = server();
    let before = snapshot(&db);
    assert_eq!(get(&srv, 0x11).await, Ok(None));
    assert_eq!(list(&srv, None, None).await, Ok(vec![]));
    assert_eq!(
        list(&srv, Some(id(0x11)), Some(RPC_PAGE_MAX)).await,
        Ok(vec![])
    );
    assert_eq!(list(&srv, None, Some(0)).await, Ok(vec![]));
    assert_eq!(snapshot(&db), before);
}

#[tokio::test]
async fn a_stored_record_is_reported_field_for_field() {
    let (srv, db, _dir) = server();
    let enabled = record(id(0x11));
    let disabled = RegistryRecordV1 {
        status: RegistryStatus::Disabled,
        proof_system_id: 1,
        approval_threshold_bps: 10_000,
        ..record(id(0x22))
    };
    store(&db, &enabled);
    store(&db, &disabled);

    assert_eq!(
        get(&srv, 0x11).await.unwrap().unwrap(),
        RegistryRecordView {
            id: hex32(0x11),
            proof_system_id: 2,
            audit_commitment: format!("0x{}", "a1".repeat(32)),
            source_commitment: format!("0x{}", "b2".repeat(32)),
            ceremony_commitment: format!("0x{}", "c3".repeat(32)),
            verifier_binary_version: 0x0102_0304,
            activation_height: 0x0A0B_0C0D_0E0F_1011,
            status: "enabled".to_string(),
            approval_threshold_bps: 6_667,
        }
    );
    // The stored values, as stored: a disabled record, a proof system that is
    // not admitted and an activation height far above the head are all
    // reported, not evaluated.
    let d = get(&srv, 0x22).await.unwrap().unwrap();
    assert_eq!(d.status, "disabled");
    assert_eq!(d.proof_system_id, 1);
    assert_eq!(d.approval_threshold_bps, 10_000);
    assert_eq!(d.activation_height, 0x0A0B_0C0D_0E0F_1011);

    // The same shape as the dry run's candidate for the same bytes.
    let candidate = dry_run_response(&enabled.try_encode().unwrap(), 0)
        .candidate
        .unwrap();
    assert_eq!(get(&srv, 0x11).await.unwrap().unwrap(), candidate);

    // Absent ids stay absent.
    assert_eq!(get(&srv, 0x33).await, Ok(None));
    // The listing reports the same views.
    assert_eq!(
        list(&srv, None, None).await.unwrap(),
        vec![
            get(&srv, 0x11).await.unwrap().unwrap(),
            get(&srv, 0x22).await.unwrap().unwrap()
        ]
    );
}

/// Register and disable through the dormant entry (test-fixture parameters),
/// each published as a block publishes it: the reads report exactly the rows
/// execution wrote.
#[tokio::test]
async fn records_written_by_execution_are_what_the_reads_report() {
    const CHAIN: u64 = 4242;
    const GENESIS: [u8; 32] = [0x47; 32];
    let (srv, db, _dir) = server();
    let payer = Address::new([0x5A; 20]);
    StateStore::new(&db)
        .put_account(
            &payer,
            &AccountState {
                balance: 1_000_000,
                nonce: 0,
            },
        )
        .unwrap();
    let mut params = ChainParams::with_v2_enabled();
    params.governance_enabled_from_height = Some(0);
    params.governance = Some(GovernanceParams {
        validator_authority_threshold_bps: 6_667,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 16,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 0,
    });
    let fixture = RegistryIngressParams {
        registry_min_timelock_blocks: Some(10),
        registry_max_approval_window: Some(100),
    };
    let v = KeyPair::from_bytes([1; 32]);
    let approval = |msg: &[u8]| ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(msg, v.private_key()).to_bytes(),
    };
    let run = |op: RegistryIngressOp, data: Vec<u8>, height: u64| {
        let block = Block::new(
            BlockHeader::new(
                Hash::hash(b"parent"),
                height,
                1_000 + height,
                Hash::hash(&height.to_be_bytes()),
                Hash::hash(b"root"),
                [0u8; 32],
            ),
            Vec::new(),
        );
        let mut c = CandidateExecution::new(&db, sumchain_state::MAX_BLOCK_WRITE_SET_BYTES);
        let status = execute_registry_ingress(
            &mut c.view(),
            CHAIN,
            &params,
            op,
            &data,
            &payer,
            100,
            &Address::new([0x99; 20]),
            height,
            Hash::ZERO,
            &[*v.public_key().as_bytes()],
            RegistryIngressContext {
                params: &fixture,
                genesis_block_hash: Some(&GENESIS),
            },
        )
        .unwrap()
        .status;
        assert_eq!(status, TxStatus::Success);
        c.finish_execution(
            ExecutionSubject::of(&block).unwrap(),
            block.header.state_root,
            Vec::new(),
            BlockJournals {
                account: JournalRecord::NothingToUndo,
                contract: JournalRecord::NothingToUndo,
                compute_pool: JournalRecord::NothingToUndo,
                beacon: JournalRecord::NothingToUndo,
            },
        )
        .accept_imported(&block)
        .unwrap()
        .publish()
        .unwrap();
    };

    let rec = RegistryRecordV1 {
        activation_height: 200,
        ..record(id(0x11))
    };
    let msg = registry_register_signing_bytes(CHAIN, &GENESIS, 50, &rec).unwrap();
    let register = RegistryRegisterV1 {
        valid_until: 50,
        record: rec.clone(),
        approvals: vec![approval(&msg)],
    };
    run(
        RegistryIngressOp::Register,
        register.try_encode().unwrap(),
        1,
    );
    let registered = get(&srv, 0x11).await.unwrap().unwrap();
    assert_eq!(
        registered,
        dry_run_response(&rec.try_encode().unwrap(), 0)
            .candidate
            .unwrap()
    );
    assert_eq!(registered.status, "enabled");
    assert_eq!(registered.activation_height, 200);
    assert_eq!(
        list(&srv, None, None).await.unwrap(),
        vec![registered.clone()]
    );

    let msg = registry_disable_signing_bytes(CHAIN, &GENESIS, 50, &rec.id);
    let disable = RegistryDisableV1 {
        valid_until: 50,
        id: rec.id,
        approvals: vec![approval(&msg)],
    };
    run(RegistryIngressOp::Disable, disable.try_encode().unwrap(), 2);
    let disabled = get(&srv, 0x11).await.unwrap().unwrap();
    assert_eq!(disabled.status, "disabled");
    assert_eq!(
        RegistryRecordView {
            status: "enabled".to_string(),
            ..disabled.clone()
        },
        registered,
        "disable changes the status and nothing else"
    );
    assert_eq!(list(&srv, None, None).await.unwrap(), vec![disabled]);
}

#[tokio::test]
async fn a_row_that_does_not_decode_is_an_internal_error_never_null() {
    let (srv, db, _dir) = server();
    store(&db, &record(id(0x11)));
    put_raw(&db, &registry_record_key(&id(0x22)), b"not a record");
    store(&db, &record(id(0x33)));
    let mut truncated = record(id(0x44)).try_encode().unwrap();
    truncated.pop();
    put_raw(&db, &registry_record_key(&id(0x44)), &truncated);

    assert_eq!(get(&srv, 0x22).await, Err(INTERNAL));
    assert_eq!(get(&srv, 0x44).await, Err(INTERNAL));
    // A listing that reads the row fails as a whole; it never skips it.
    assert_eq!(list(&srv, None, None).await, Err(INTERNAL));
    assert_eq!(list(&srv, Some(id(0x11)), Some(1)).await, Err(INTERNAL));
    // The rows beside them still answer.
    assert!(get(&srv, 0x11).await.unwrap().is_some());
    assert!(get(&srv, 0x33).await.unwrap().is_some());
}

#[tokio::test]
async fn a_record_stored_under_another_id_is_refused() {
    let (srv, db, _dir) = server();
    // A valid record, under the key of another id.
    put_raw(
        &db,
        &registry_record_key(&id(0x22)),
        &record(id(0x11)).try_encode().unwrap(),
    );
    assert_eq!(get(&srv, 0x22).await, Err(INTERNAL));
    assert_eq!(
        get(&srv, 0x11).await,
        Ok(None),
        "it is not under its own id"
    );
    assert_eq!(list(&srv, None, None).await, Err(INTERNAL));
}

#[tokio::test]
async fn a_key_of_the_wrong_length_under_the_prefix_fails_the_listing() {
    for len in [0usize, 31, 33] {
        let (srv, db, _dir) = server();
        store(&db, &record(id(0x11)));
        store(&db, &record(id(0x33)));
        let mut key = REGISTRY_RECORD_KEY_PREFIX.to_vec();
        key.resize(REGISTRY_RECORD_KEY_PREFIX.len() + len, 0x22);
        put_raw(&db, &key, &record(id(0x22)).try_encode().unwrap());

        assert_eq!(list(&srv, None, None).await, Err(INTERNAL), "{len}-byte id");
        // A point read never reads that key: both well-formed rows answer.
        assert!(get(&srv, 0x11).await.unwrap().is_some());
        assert!(get(&srv, 0x33).await.unwrap().is_some());
        assert_eq!(get(&srv, 0x22).await, Ok(None));
    }

    // A page reads only its own rows: one that ends before the bad row, or
    // starts after it, answers; one that reaches it does not.
    let (srv, db, _dir) = server();
    store(&db, &record(id(0x11)));
    store(&db, &record(id(0x33)));
    let mut long = registry_record_key(&id(0x11));
    long.push(0);
    put_raw(&db, &long, &record(id(0x11)).try_encode().unwrap());
    assert_eq!(
        ids(&list(&srv, None, Some(1)).await.unwrap()),
        vec![hex32(0x11)]
    );
    assert_eq!(list(&srv, Some(id(0x11)), Some(1)).await, Err(INTERNAL));
    assert_eq!(list(&srv, None, Some(2)).await, Err(INTERNAL));
    assert_eq!(
        ids(&list(&srv, Some(id(0x22)), None).await.unwrap()),
        vec![hex32(0x33)]
    );
}

#[tokio::test]
async fn the_listing_is_ascending_and_resumes_strictly_after_start_after() {
    let (srv, db, _dir) = server();
    for b in [0x50u8, 0x10, 0xF0, 0x30, 0x00, 0xFF] {
        store(&db, &record(id(b)));
    }
    // Rows outside the prefix, before and after it, are never read: one sorts
    // just after `registry/v1/` (`0` > `/`) and does not decode.
    put_raw(&db, b"registry/v10", b"not a record");
    put_raw(&db, b"acct-not-a-registry-row", b"x");
    put_raw(&db, b"registry/v0/", b"x");

    let all = [0x00u8, 0x10, 0x30, 0x50, 0xF0, 0xFF].map(hex32).to_vec();
    assert_eq!(ids(&list(&srv, None, None).await.unwrap()), all);

    // Strictly after a stored id; after an id that is not stored.
    assert_eq!(
        ids(&list(&srv, Some(id(0x30)), None).await.unwrap()),
        all[3..].to_vec()
    );
    assert_eq!(
        ids(&list(&srv, Some(id(0x31)), None).await.unwrap()),
        all[3..].to_vec()
    );
    let mut just_below = id(0x50);
    just_below[31] = 0x4F;
    assert_eq!(
        ids(&list(&srv, Some(just_below), Some(1)).await.unwrap()),
        vec![hex32(0x50)]
    );
    assert_eq!(list(&srv, Some(id(0xFF)), None).await, Ok(vec![]));

    // Pages of two reconstruct the whole set: nothing skipped, nothing twice.
    let mut paged = Vec::new();
    let mut cursor: Option<[u8; 32]> = None;
    loop {
        let page = list(&srv, cursor, Some(2)).await.unwrap();
        assert!(page.len() <= 2);
        let Some(last) = page.last() else { break };
        let mut next = [0u8; 32];
        next.copy_from_slice(&hex::decode(&last.id[2..]).unwrap());
        cursor = Some(next);
        paged.extend(ids(&page));
    }
    assert_eq!(paged, all);

    // Zero is an empty page, not an error.
    assert_eq!(list(&srv, None, Some(0)).await, Ok(vec![]));
}

#[tokio::test]
async fn the_page_is_bounded_and_a_larger_one_is_refused_not_clamped() {
    let (srv, db, _dir) = server();
    assert_eq!(list(&srv, None, Some(RPC_PAGE_MAX)).await, Ok(vec![]));
    assert_eq!(
        list(&srv, None, Some(RPC_PAGE_MAX + 1)).await,
        Err(PAGE_OUT_OF_BOUNDS)
    );
    assert_eq!(
        list(&srv, None, Some(u32::MAX)).await,
        Err(PAGE_OUT_OF_BOUNDS)
    );

    // One more record than the largest page.
    let n = RPC_PAGE_MAX + 1;
    let mut stored = BTreeSet::new();
    for i in 0..n {
        let mut rid = [0u8; 32];
        rid[..4].copy_from_slice(&i.to_be_bytes());
        store(&db, &record(rid));
        stored.insert(format!("0x{}", hex::encode(rid)));
    }
    let default_page = list(&srv, None, None).await.unwrap();
    assert_eq!(default_page.len(), RPC_PAGE_DEFAULT as usize);
    let full = list(&srv, None, Some(RPC_PAGE_MAX)).await.unwrap();
    assert_eq!(full.len(), RPC_PAGE_MAX as usize);
    assert_eq!(ids(&full)[..default_page.len()], ids(&default_page)[..]);
    let mut last = [0u8; 32];
    last.copy_from_slice(&hex::decode(&full.last().unwrap().id[2..]).unwrap());
    let rest = list(&srv, Some(last), Some(RPC_PAGE_MAX)).await.unwrap();
    assert_eq!(rest.len(), 1, "a short page: nothing follows");
    let seen: BTreeSet<String> = ids(&full).into_iter().chain(ids(&rest)).collect();
    assert_eq!(seen, stored);
    assert_eq!(
        list(&srv, None, Some(RPC_PAGE_MAX + 1)).await,
        Err(PAGE_OUT_OF_BOUNDS),
        "refused even though that many records exist"
    );
}

#[tokio::test]
async fn ids_are_32_byte_hex_with_or_without_0x() {
    let (srv, db, _dir) = server();
    store(&db, &record(id(0x11)));
    store(&db, &record(id(0x22)));
    let bare = srv
        .registry_get_record(hex::encode(id(0x11)))
        .await
        .unwrap();
    assert_eq!(bare, get(&srv, 0x11).await.unwrap());
    let after_bare = srv
        .registry_get_records(Some(hex::encode(id(0x11))), None)
        .await
        .unwrap();
    assert_eq!(ids(&after_bare), vec![hex32(0x22)]);

    let short = "11".repeat(31);
    let long = "11".repeat(33);
    for bad in [
        "",
        "0x",
        "0x1234",
        "zz",
        "0x0",
        short.as_str(),
        long.as_str(),
    ] {
        let e = srv.registry_get_record(bad.to_string()).await.unwrap_err();
        assert_eq!(e.code(), INVALID_PARAMS, "id {bad:?}");
        let e = srv
            .registry_get_records(Some(bad.to_string()), None)
            .await
            .unwrap_err();
        assert_eq!(e.code(), INVALID_PARAMS, "start_after {bad:?}");
    }
}

#[tokio::test]
async fn the_reads_write_nothing_even_when_they_refuse() {
    let (srv, db, _dir) = server();
    store(&db, &record(id(0x11)));
    put_raw(&db, &registry_record_key(&id(0x22)), b"not a record");
    let before = snapshot(&db);
    for b in [0x11u8, 0x22, 0x33] {
        let _ = get(&srv, b).await;
    }
    let _ = list(&srv, None, None).await;
    let _ = list(&srv, None, Some(RPC_PAGE_MAX + 1)).await;
    let _ = srv.registry_get_record("zz".into()).await;
    let _ = srv.registry_get_records(Some("zz".into()), None).await;
    assert_eq!(snapshot(&db), before);
}

#[tokio::test]
async fn the_methods_answer_over_json_rpc_under_their_names() {
    let (srv, db, _dir) = server();
    store(&db, &record(id(0x11)));
    store(&db, &record(id(0x22)));
    put_raw(&db, &registry_record_key(&id(0x44)), b"not a record");
    let module = srv.into_rpc();
    let call = |method: &str, params: serde_json::Value| {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
    };
    let ask = |method: &'static str, params: serde_json::Value| {
        let module = &module;
        let req = call(method, params);
        async move {
            let (resp, _rx) = module.raw_json_request(&req, 1).await.unwrap();
            serde_json::from_str::<serde_json::Value>(resp.get()).unwrap()
        }
    };

    let v = ask("registry_getRecord", serde_json::json!([hex32(0x11)])).await;
    let r = v["result"].as_object().unwrap();
    let keys: Vec<&str> = r.keys().map(|k| k.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "activation_height",
            "approval_threshold_bps",
            "audit_commitment",
            "ceremony_commitment",
            "id",
            "proof_system_id",
            "source_commitment",
            "status",
            "verifier_binary_version"
        ]
    );
    assert_eq!(r["id"], hex32(0x11));
    assert_eq!(r["status"], "enabled");
    assert_eq!(r["activation_height"], 0x0A0B_0C0D_0E0F_1011u64);
    assert_eq!(r["verifier_binary_version"], 0x0102_0304u32);

    let v = ask("registry_getRecord", serde_json::json!([hex32(0x33)])).await;
    assert!(v.get("error").is_none(), "{v}");
    assert_eq!(v["result"], serde_json::Value::Null);

    // Both arguments are trailing and optional.
    let v = ask("registry_getRecords", serde_json::json!([null, 1])).await;
    assert_eq!(v["result"].as_array().unwrap().len(), 1);
    assert_eq!(v["result"][0]["id"], hex32(0x11));
    let v = ask("registry_getRecords", serde_json::json!([hex32(0x11), 1])).await;
    assert_eq!(v["result"][0]["id"], hex32(0x22));
    let v = ask("registry_getRecords", serde_json::json!([hex32(0x11)])).await;
    assert_eq!(
        v["error"]["code"], INTERNAL,
        "this page reaches the bad row: {v}"
    );
    let v = ask("registry_getRecords", serde_json::json!([hex32(0x44)])).await;
    assert_eq!(v["result"], serde_json::json!([]));
    let v = ask("registry_getRecords", serde_json::json!([])).await;
    assert_eq!(v["error"]["code"], INTERNAL, "{v}");

    for (method, params, code) in [
        (
            "registry_getRecord",
            serde_json::json!(["zz"]),
            INVALID_PARAMS,
        ),
        (
            "registry_getRecord",
            serde_json::json!([hex32(0x44)]),
            INTERNAL,
        ),
        (
            "registry_getRecords",
            serde_json::json!(["0x1234"]),
            INVALID_PARAMS,
        ),
        (
            "registry_getRecords",
            serde_json::json!([null, RPC_PAGE_MAX + 1]),
            PAGE_OUT_OF_BOUNDS,
        ),
    ] {
        let v = ask(method, params.clone()).await;
        assert_eq!(v["error"]["code"], code, "{method} {params}: {v}");
    }
}

fn read_repo_file(rel: &str) -> String {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The `registry_*` surface is exactly the dry run and the two record reads,
/// all read-only, and each is in the RPC reference.
#[test]
fn the_registry_surface_is_exactly_three_read_only_methods() {
    let api = read_repo_file("src/api.rs");
    let needle = "name = \"registry_";
    let registered: BTreeSet<String> = api
        .match_indices(needle)
        .map(|(i, _)| {
            let rest = &api[i + "name = \"".len()..];
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .collect();
    let expected: BTreeSet<String> = [
        "registry_dryRunAdmit",
        "registry_getRecord",
        "registry_getRecords",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(registered, expected);

    let docs = read_repo_file("../../docs/rpc/api-reference.md");
    for m in &expected {
        assert!(
            docs.contains(&format!("`{m}(")),
            "{m} is not in the RPC reference"
        );
    }
}
