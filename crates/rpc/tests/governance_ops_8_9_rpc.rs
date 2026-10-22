//! C5 registry ingress (#242, PROPOSED) keeps operations 8 and 9 off the wire.
//! `send_raw_transaction` decodes before anything else, so a governance
//! transaction naming operation 8 or 9 is refused there with the
//! unknown-variant decode error, and the mempool stays empty.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_consensus::PoAEngine;
use sumchain_crypto::KeyPair;
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::governance::{GovernanceOperation, GovernanceTxData};
use sumchain_primitives::{SignedTransaction, TransactionV2, TxPayload};
use sumchain_rpc::api::SumChainApiServer;
use sumchain_rpc::server::RpcServer;
use sumchain_state::{Mempool, MempoolConfig, StateManager};
use sumchain_storage::Database;
use tempfile::TempDir;
use tokio::sync::mpsc;

const DATA: [u8; 5] = [0xC5; 5];

fn server() -> (RpcServer, Arc<Mempool>, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    let mempool = Arc::new(Mempool::new(MempoolConfig::default()));
    let validator = KeyPair::generate();
    let genesis = Genesis::new(
        1,
        0,
        vec![validator.public_key().to_base58()],
        HashMap::from([(validator.address().to_base58(), 1u128)]),
        ChainParams::with_v2_enabled(),
    );
    let engine = Arc::new(
        PoAEngine::new(db.clone(), state.clone(), mempool.clone(), &genesis, Some(validator))
            .unwrap(),
    );
    let (tx_sender, _rx) = mpsc::channel(8);
    let srv = RpcServer::new(db, state, mempool.clone(), engine, tx_sender, Arc::new(|| 0usize));
    (srv, mempool, dir)
}

/// A signed governance transaction naming operation 7, re-encoded with the
/// operation index set to `op`, as hex.
fn raw_with_op(op: u32) -> String {
    let kp = KeyPair::from_bytes([0x5A; 32]);
    let tx = TransactionV2 {
        chain_id: 1,
        from: kp.address(),
        fee: 1,
        nonce: 0,
        payload: TxPayload::Governance(GovernanceTxData {
            operation: GovernanceOperation::CastEquityVote,
            data: DATA.to_vec(),
        }),
    };
    let sig = sumchain_crypto::sign(tx.signing_hash().as_bytes(), kp.private_key());
    let bytes = SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes()).to_bytes();
    let marker: Vec<u8> = [
        &23u32.to_le_bytes()[..],
        &7u32.to_le_bytes(),
        &(DATA.len() as u64).to_le_bytes(),
        &DATA,
    ]
    .concat();
    let at: Vec<usize> = bytes
        .windows(marker.len())
        .enumerate()
        .filter(|(_, w)| *w == marker.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1);
    let mut out = bytes;
    out[at[0] + 4..at[0] + 8].copy_from_slice(&op.to_le_bytes());
    hex::encode(out)
}

#[tokio::test]
async fn send_raw_transaction_refuses_operations_8_and_9_at_decode() {
    let (srv, mempool, _dir) = server();
    // Control: the unpatched transaction decodes.
    assert!(SignedTransaction::from_hex(&raw_with_op(7)).is_ok());

    for op in [8u32, 9] {
        let err = srv.send_raw_transaction(raw_with_op(op)).await.unwrap_err();
        let expected = format!("invalid value: integer `{op}`, expected variant index 0 <= i < 8");
        assert_eq!(err.code(), -32602, "op {op}: invalid params");
        assert!(
            err.message().contains("Invalid transaction") && err.message().contains(&expected),
            "op {op}: {}",
            err.message()
        );
        assert!(mempool.is_empty(), "op {op} reached the mempool");
    }
}
