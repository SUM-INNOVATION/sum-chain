//! Issue #20 × SNIP V2 — an `Unbonding` archive must not accept new chunk
//! assignments. Ruling #5: reject `AcceptAssignmentV2` while the archive's
//! status is `Unbonding`.
//!
//! The test proves the rejection is caused by the unbonding transition (and not
//! by some other `AcceptAssignmentV2` validity failure, which shares receipt
//! code 33) by contrasting the SAME accept: it succeeds while the archive is
//! `Active`, then fails once the archive begins unbonding.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    Hash, NodeRegistryOperation, NodeRegistryTxData, NodeRole, SignedTransaction,
    StorageMetadataOperationV2, StorageMetadataV2TxData, TransactionV2, TxPayload, TxStatus,
};

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;

fn params_enabled() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.archive_unbonding_enabled_from_height = Some(0);
    p.archive_unbonding_period_blocks = 100;
    p
}

fn signed(kp: &KeyPair, fee: u128, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn nr(op: NodeRegistryOperation) -> TxPayload {
    TxPayload::NodeRegistry(NodeRegistryTxData { operation: op })
}

fn sm(op: StorageMetadataOperationV2) -> TxPayload {
    TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation: op })
}

#[test]
fn accept_assignment_v2_rejected_once_archive_unbonding() {
    let (state, _db, _dir, executor) = setup_with_params(params_enabled());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);

    let merkle_root = Hash::hash(b"accept-unbonding-file");

    // Height 1: register the archive → Active, and a snapshot at height 1
    // captures it in the active-archive set.
    let r = executor
        .execute_tx(
            &signed(&archive, FEE, 0, nr(NodeRegistryOperation::Register {
                role: NodeRole::ArchiveNode,
                stake: STAKE,
            })),
            &proposer.address(),
            1,
            1000,
        )
        .unwrap();
    assert!(r.status.is_success());

    // Height 2: owner registers a 1-chunk Public file. assignment_height = 2,
    // whose snapshot (≤2) includes the Active archive.
    let r = executor
        .execute_tx(
            &signed(&owner, FEE, 0, sm(StorageMetadataOperationV2::RegisterFilePendingV2 {
                merkle_root,
                plaintext_size_bytes: 500,
                stored_size_bytes: 1000, // ceil(1000 / 1 MiB) == 1 chunk
                chunk_count: 1,
                fee_deposit: 0,
                visibility: 0, // Public
                initial_access: vec![],
            })),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(r.status.is_success(), "register file got {:?}", r.status);

    // Height 3: while Active, the archive can accept the assignment.
    let ok = executor
        .execute_tx(
            &signed(&archive, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root,
                chunk_indices: vec![0],
            })),
            &proposer.address(),
            3,
            1000,
        )
        .unwrap();
    assert!(ok.status.is_success(), "active accept got {:?}", ok.status);

    // Height 4: the archive begins unbonding (full exit) → Unbonding.
    let b = executor
        .execute_tx(
            &signed(&archive, FEE, 2, nr(NodeRegistryOperation::BeginUnstake { amount: STAKE })),
            &proposer.address(),
            4,
            1000,
        )
        .unwrap();
    assert!(b.status.is_success(), "begin unstake got {:?}", b.status);

    // Height 5: the SAME accept now fails — an unbonding archive cannot take on
    // new assignments (ruling #5). Code 33 is the AcceptAssignmentV2 validity
    // code; the contrast with the height-3 success pins it to the unbonding
    // transition.
    let rejected = executor
        .execute_tx(
            &signed(&archive, FEE, 3, sm(StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root,
                chunk_indices: vec![0],
            })),
            &proposer.address(),
            5,
            1000,
        )
        .unwrap();
    assert!(
        matches!(rejected.status, TxStatus::Failed(33)),
        "unbonding archive accept should fail 33, got {:?}",
        rejected.status
    );
}
