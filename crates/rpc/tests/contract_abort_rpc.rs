//! #279: a contract call that reaches the `abort` host import, served by the
//! read-only contract RPCs, comes back as an error result and leaves no
//! storage write behind.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::Address;
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_rpc::types::ViewCallRequest;
use sumchain_state::{ContractExecutorState, Mempool, MempoolConfig, StateManager};
use sumchain_storage::{cf, Database};
use tempfile::TempDir;
use tokio::sync::mpsc;

const WAT: &str = r#"
(module
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (import "env" "abort"         (func $abort  (param i32 i32)))
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (data (i32.const 0) "k")
  (data (i32.const 8) "VAL")
  (func (export "alloc") (param $size i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $size)))
    (local.get $p))
  (func (export "write_then_abort") (param i32 i32) (result i32)
    (call $swrite (i32.const 0) (i32.const 1) (i32.const 8) (i32.const 3))
    (call $abort (i32.const 0) (i32.const 1))
    (i32.const 0))
)
"#;

fn server_with_contract() -> (RpcServer, Arc<Database>, Address, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::generate();
    let params = ChainParams::with_contracts_enabled();
    let genesis = Genesis::new(
        1,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1u128)]),
        params.clone(),
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
    let contract = Address::new([0xC0; 20]);
    db.put(
        cf::CONTRACT_CODE,
        contract.as_bytes(),
        &wat::parse_str(WAT).unwrap(),
    )
    .unwrap();
    let srv = RpcServer::new(
        db.clone(),
        state,
        mempool,
        engine,
        tx_sender,
        Arc::new(|| 0usize),
    )
    .with_contract_executor(Arc::new(ContractExecutorState::new(db.clone(), params)));
    (srv, db, contract, dir)
}

fn request(contract: Address) -> ViewCallRequest {
    ViewCallRequest {
        contract: contract.to_base58(),
        method: "write_then_abort".into(),
        args: String::new(),
        from: None,
    }
}

#[tokio::test]
async fn contract_call_reports_an_abort_as_a_failed_result() {
    let (srv, db, contract, _d) = server_with_contract();
    let res = srv
        .contract_call(request(contract))
        .await
        .expect("an error RESULT, not a transport failure");
    assert!(!res.success);
    assert!(
        res.error
            .as_deref()
            .unwrap_or("")
            .contains("contract aborted"),
        "{:?}",
        res.error
    );
    assert_eq!(
        db.full_iter(cf::CONTRACT_STORAGE).unwrap().count(),
        0,
        "a view writes nothing"
    );
}

#[tokio::test]
async fn contract_estimate_gas_reports_an_abort_as_an_error() {
    let (srv, db, contract, _d) = server_with_contract();
    let err = srv
        .contract_estimate_gas(request(contract))
        .await
        .expect_err("no estimate for an aborting call");
    assert!(
        err.message().contains("contract aborted"),
        "{}",
        err.message()
    );
    assert_eq!(
        db.full_iter(cf::CONTRACT_STORAGE).unwrap().count(),
        0,
        "a dry run writes nothing"
    );
}
