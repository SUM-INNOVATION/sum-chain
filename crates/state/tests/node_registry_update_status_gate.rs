//! `node_registry_update_status_unsupported_enabled_from_height`: a
//! transaction-borne node-registry `UpdateStatus` is refused from the gate on.
//!
//! Below the gate, or while it is unset, the operation executes exactly as it
//! always has. At and above it, the transaction fails as any other failed
//! node-registry operation does (fee charged, nonce advanced, `Failed(18)`), and
//! no node record or active-archive snapshot changes. Other registry
//! operations are unaffected.

mod common;
use common::{fund, publish_block, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    NodeRegistryOperation, NodeRegistryTxData, NodeRole, NodeStatus, SignedTransaction,
    TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::NodeRegistryExecutor;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;
const FUNDS: u128 = 10 * STAKE as u128;

fn params(gate: Option<u64>) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.node_registry_update_status_unsupported_enabled_from_height = gate;
    p
}

fn nr(kp: &KeyPair, nonce: u64, op: NodeRegistryOperation) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: FEE,
        nonce,
        payload: TxPayload::NodeRegistry(NodeRegistryTxData { operation: op }),
    };
    let sig = sign(tx.signing_hash().as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn register(kp: &KeyPair, nonce: u64) -> SignedTransaction {
    nr(
        kp,
        nonce,
        NodeRegistryOperation::Register {
            role: NodeRole::ArchiveNode,
            stake: STAKE,
        },
    )
}

fn update_status(kp: &KeyPair, nonce: u64, target: &KeyPair, s: NodeStatus) -> SignedTransaction {
    nr(
        kp,
        nonce,
        NodeRegistryOperation::UpdateStatus {
            target: target.address(),
            new_status: s,
        },
    )
}

fn archive() -> KeyPair {
    KeyPair::from_bytes([0x61; 32])
}

fn other() -> KeyPair {
    KeyPair::from_bytes([0x62; 32])
}

fn proposer() -> KeyPair {
    KeyPair::from_bytes([0x63; 32])
}

/// One chain: the archive registers at height 1, then `txs` run at `height`.
/// Returns the receipts of that block, the archive's status after it, whether
/// the archive is in the active set at that height, the state root, and the
/// sender of the last transaction's balance and nonce.
struct Outcome {
    receipts: Vec<sumchain_primitives::Receipt>,
    status: NodeStatus,
    active: bool,
    root: sumchain_primitives::Hash,
    other_balance: u128,
    other_nonce: u64,
}

fn run(gate: Option<u64>, height: u64, txs: impl FnOnce() -> Vec<SignedTransaction>) -> Outcome {
    let (state, db, _dir, ex) = setup_with_params(params(gate));
    fund(&db, &archive(), FUNDS);
    fund(&db, &other(), FUNDS);
    let pk = *proposer().public_key().as_bytes();
    let r = publish_block(&state, &ex, 1, &pk, vec![register(&archive(), 0)], &[]);
    assert_eq!(r[0].status, TxStatus::Success, "{r:?}");
    let receipts = publish_block(&state, &ex, height, &pk, txs(), &[]);
    let registry = NodeRegistryExecutor::new(db.clone());
    Outcome {
        receipts,
        status: registry
            .get_node(&archive().address())
            .unwrap()
            .unwrap()
            .status,
        active: registry
            .get_active_archive_nodes_at_height(height)
            .unwrap()
            .iter()
            .any(|r| r.address == archive().address()),
        root: state.state_root(),
        other_balance: state.get_balance(&other().address()).unwrap(),
        other_nonce: state.get_nonce(&other().address()).unwrap(),
    }
}

#[test]
fn the_gate_is_dormant_by_default() {
    assert_eq!(
        ChainParams::default().node_registry_update_status_unsupported_enabled_from_height,
        None
    );
}

#[test]
fn below_the_gate_update_status_executes_as_before() {
    // The same block on a chain without the gate and on one whose gate is far
    // above: identical outcome and identical state root.
    let txs = || vec![update_status(&other(), 0, &archive(), NodeStatus::Slashed)];
    let unset = run(None, 2, txs);
    let above = run(Some(1_000_000), 2, txs);
    assert_eq!(unset.receipts, above.receipts);
    assert_eq!(unset.root, above.root);
    assert_eq!(unset.receipts[0].status, TxStatus::Success);
    assert_eq!((unset.status, unset.active), (NodeStatus::Slashed, false));
    assert_eq!((above.status, above.active), (NodeStatus::Slashed, false));
}

#[test]
fn from_the_gate_a_transaction_borne_update_status_is_refused() {
    let gated = run(Some(2), 2, || {
        vec![update_status(&other(), 0, &archive(), NodeStatus::Slashed)]
    });
    assert_eq!(gated.receipts[0].status, TxStatus::Failed(18));
    // Charged as every failed registry operation is; nothing else moves.
    assert_eq!(gated.other_balance, FUNDS - FEE);
    assert_eq!(gated.other_nonce, 1);
    assert_eq!((gated.status, gated.active), (NodeStatus::Active, true));
}

#[test]
fn the_gate_refuses_the_node_itself_too() {
    // The operation is unsupported from transactions, whoever signs it.
    let gated = run(Some(2), 2, || {
        vec![update_status(
            &archive(),
            1,
            &archive(),
            NodeStatus::Unbonding,
        )]
    });
    assert_eq!(gated.receipts[0].status, TxStatus::Failed(18));
    assert_eq!((gated.status, gated.active), (NodeStatus::Active, true));
}

#[test]
fn the_gate_boundary_is_exact() {
    let txs = || vec![update_status(&other(), 0, &archive(), NodeStatus::Slashed)];
    let below = run(Some(3), 2, txs);
    let at = run(Some(3), 3, txs);
    assert_eq!(below.receipts[0].status, TxStatus::Success);
    assert_eq!(below.status, NodeStatus::Slashed);
    assert_eq!(at.receipts[0].status, TxStatus::Failed(18));
    assert_eq!(at.status, NodeStatus::Active);
}

#[test]
fn every_status_change_is_refused_from_the_gate() {
    for s in [
        NodeStatus::Active,
        NodeStatus::Slashed,
        NodeStatus::Unbonding,
        NodeStatus::Withdrawn,
    ] {
        let gated = run(Some(2), 2, || {
            vec![update_status(&other(), 0, &archive(), s)]
        });
        assert_eq!(gated.receipts[0].status, TxStatus::Failed(18), "{s:?}");
        assert_eq!(
            (gated.status, gated.active),
            (NodeStatus::Active, true),
            "{s:?}"
        );
    }
}

#[test]
fn other_registry_operations_are_unchanged_from_the_gate() {
    // Registering after the gate is open works as before, and lands the node
    // in the active archive set.
    let gated = run(Some(1), 2, || vec![register(&other(), 0)]);
    assert_eq!(gated.receipts[0].status, TxStatus::Success);
    let (state, db, _dir, ex) = setup_with_params(params(Some(1)));
    fund(&db, &other(), FUNDS);
    let pk = *proposer().public_key().as_bytes();
    let r = publish_block(&state, &ex, 1, &pk, vec![register(&other(), 0)], &[]);
    assert_eq!(r[0].status, TxStatus::Success);
    let registry = NodeRegistryExecutor::new(db.clone());
    assert!(registry
        .get_active_archive_nodes_at_height(1)
        .unwrap()
        .iter()
        .any(|r| r.address == other().address()));
}
