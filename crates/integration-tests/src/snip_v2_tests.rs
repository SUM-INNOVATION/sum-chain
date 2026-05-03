//! SNIP V2 end-to-end integration tests.
//!
//! These tests go through `TestNode::produce_block` — the same path the live
//! chain uses — so they exercise full executor dispatch, state writes, and
//! receipt persistence end-to-end. Compared with the state-crate unit tests
//! (which call `BlockExecutor::execute_tx` directly), these tests catch any
//! regression in the consensus → executor → storage handoff for SNIP V2 ops.
//!
//! Phase 2 checkpoint 2a (plan v3.2 §7) — covers the canonical SNIP V2 flow:
//!   1. Public file full lifecycle: register → attest → activate → access ops.
//!   2. Private file with X25519 registration on both sides.
//!   3. Abandon-after-grace flow with refund.
//!   4. Multi-block AcceptAssignmentV2 OR-merge + coverage RPC backend.

use std::collections::HashMap;
use std::sync::Arc;

use sumchain_crypto::KeyPair;
use sumchain_primitives::{
    AccessEntryV2, Address, EncryptedKeyBundleV2, FileLifecycleV2, FileVisibilityV2, Hash,
    NodeRegistryOperation, NodeRegistryOperationV2, NodeRegistryTxData, NodeRegistryV2TxData,
    NodeRole, SignedTransaction, StorageMetadataOperationV2, StorageMetadataV2TxData,
    TransactionV2, TxPayload, TxStatus, CHUNK_SIZE,
};
use sumchain_state::{NodeRegistryExecutor, StorageMetadataExecutor};
use sumchain_storage::ReceiptStore;

use crate::TestNode;

/// Stake required to register an ArchiveNode (1 Koppa). Matches the constant
/// in `crates/state/src/node_registry.rs::MIN_ARCHIVE_STAKE`.
const ARCHIVE_STAKE: u64 = 1_000_000_000;

/// Sign and submit one V2 tx, then produce a block. Returns the receipt's
/// `TxStatus`. Panics on mempool rejection — tests use this only for txs
/// that should at least reach a block; success/failure is asserted by the
/// caller via the returned status.
async fn submit_v2(
    node: &TestNode,
    signer_bytes: [u8; 32],
    payload: TxPayload,
    fee: u128,
) -> TxStatus {
    let signer = KeyPair::from_bytes(signer_bytes);
    let nonce = node.nonce(&signer.address());
    let tx = TransactionV2 {
        chain_id: node.chain_id(),
        from: signer.address(),
        fee,
        nonce,
        payload,
    };
    let signing_hash = tx.signing_hash();
    let s = sumchain_crypto::sign(signing_hash.as_bytes(), signer.private_key());
    let signed = SignedTransaction::new_v2(tx, *s.as_bytes(), *signer.public_key().as_bytes());
    // Receipts are keyed by `SignedTransaction::hash()` (the bincode of the
    // full signed envelope), not `signing_hash()`. The PoA proposer's
    // `create_block` uses `tx.hash()` for both the tx-root and the receipt
    // store ([crates/consensus/src/poa.rs:419,460-468](...)).
    let tx_hash = signed.hash();
    node.submit_tx(signed).expect("mempool accepts tx");
    node.produce_block().await.expect("block produced");
    ReceiptStore::new(node.db())
        .get(&tx_hash)
        .expect("receipt query")
        .expect("receipt exists for submitted tx")
        .status
}

/// Register an `ArchiveNode` for `archive_bytes` (V1 NodeRegistry path).
/// Returns the receipt status.
async fn register_archive(node: &TestNode, archive_bytes: [u8; 32]) -> TxStatus {
    submit_v2(
        node,
        archive_bytes,
        TxPayload::NodeRegistry(NodeRegistryTxData {
            operation: NodeRegistryOperation::Register {
                role: NodeRole::ArchiveNode,
                stake: ARCHIVE_STAKE,
            },
        }),
        10,
    )
    .await
}

/// Register an X25519 encryption pubkey for `account_bytes` (V2 ask 3).
async fn register_encryption_key(
    node: &TestNode,
    account_bytes: [u8; 32],
    pubkey: [u8; 32],
) -> TxStatus {
    submit_v2(
        node,
        account_bytes,
        TxPayload::NodeRegistryV2(NodeRegistryV2TxData {
            operation: NodeRegistryOperationV2::RegisterEncryptionKey {
                encryption_pubkey: pubkey,
            },
        }),
        10,
    )
    .await
}

/// `RegisterFilePendingV2` — registers a Pending V2 file. `chunk_count` and
/// `stored_size_bytes` are forced into canonical-derivation form.
#[allow(clippy::too_many_arguments)]
async fn register_pending_file(
    node: &TestNode,
    owner_bytes: [u8; 32],
    merkle_root: Hash,
    chunk_count: u32,
    fee_deposit: u64,
    visibility: FileVisibilityV2,
    initial_access: Vec<AccessEntryV2>,
) -> TxStatus {
    let stored_size_bytes = (chunk_count as u64).saturating_mul(CHUNK_SIZE);
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::RegisterFilePendingV2 {
                merkle_root,
                plaintext_size_bytes: stored_size_bytes,
                stored_size_bytes,
                chunk_count,
                fee_deposit,
                visibility: visibility as u8,
                initial_access,
            },
        }),
        10,
    )
    .await
}

async fn accept_assignment(
    node: &TestNode,
    archive_bytes: [u8; 32],
    merkle_root: Hash,
    chunk_indices: Vec<u32>,
) -> TxStatus {
    submit_v2(
        node,
        archive_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::AcceptAssignmentV2 {
                merkle_root,
                chunk_indices,
            },
        }),
        1,
    )
    .await
}

async fn activate_file(node: &TestNode, owner_bytes: [u8; 32], merkle_root: Hash) -> TxStatus {
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::ActivateFileV2 { merkle_root },
        }),
        1,
    )
    .await
}

async fn abandon_file(node: &TestNode, owner_bytes: [u8; 32], merkle_root: Hash) -> TxStatus {
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::AbandonFileV2 { merkle_root },
        }),
        1,
    )
    .await
}

async fn add_access(
    node: &TestNode,
    owner_bytes: [u8; 32],
    merkle_root: Hash,
    entry: AccessEntryV2,
) -> TxStatus {
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::AddAccessV2 { merkle_root, entry },
        }),
        1,
    )
    .await
}

async fn remove_access(
    node: &TestNode,
    owner_bytes: [u8; 32],
    merkle_root: Hash,
    address: Address,
) -> TxStatus {
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::RemoveAccessV2 { merkle_root, address },
        }),
        1,
    )
    .await
}

async fn update_access(
    node: &TestNode,
    owner_bytes: [u8; 32],
    merkle_root: Hash,
    address: Address,
    new_entry: AccessEntryV2,
) -> TxStatus {
    submit_v2(
        node,
        owner_bytes,
        TxPayload::StorageMetadataV2(StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::UpdateAccessV2 {
                merkle_root,
                address,
                new_entry,
            },
        }),
        1,
    )
    .await
}

/// Build a TestNode with three pre-funded accounts (validator, owner, archive)
/// plus an extra recipient. Returns the keypair-bytes for each so callers can
/// mint signed txs without re-extracting addresses.
fn setup_node_with_funded_accounts() -> (
    TestNode,
    [u8; 32], // validator
    [u8; 32], // owner
    [u8; 32], // archive
    [u8; 32], // recipient
) {
    let validator = *KeyPair::generate().private_key().as_bytes();
    let owner = *KeyPair::generate().private_key().as_bytes();
    let archive = *KeyPair::generate().private_key().as_bytes();
    let recipient = *KeyPair::generate().private_key().as_bytes();

    let alloc = HashMap::from([
        (
            KeyPair::from_bytes(validator).address().to_base58(),
            10_000_000_000_u128,
        ),
        (
            KeyPair::from_bytes(owner).address().to_base58(),
            10_000_000_000_u128,
        ),
        (
            KeyPair::from_bytes(archive).address().to_base58(),
            5_000_000_000_u128, // enough for 1 Koppa stake + many fees
        ),
        (
            KeyPair::from_bytes(recipient).address().to_base58(),
            1_000_000_000_u128,
        ),
    ]);

    let node = TestNode::with_allocations(validator, 1, alloc);
    (node, validator, owner, archive, recipient)
}

// ============================================================================
// Phase 2 checkpoint 2a tests
// ============================================================================

/// Public file full lifecycle: register Pending → archive attests all chunks
/// → owner activates → owner adds/updates/removes access entries. Each step
/// goes through real block production.
#[tokio::test]
async fn snip_v2_public_file_full_lifecycle_through_block_production() {
    let (node, _validator, owner, archive, recipient) = setup_node_with_funded_accounts();

    // 1. Register archive (V1 op — needed for the V2 file's snapshot).
    assert!(register_archive(&node, archive).await.is_success());

    // 2. Owner registers a Pending Public file (4 chunks, ~5 Koppa deposit).
    let merkle_root = Hash::hash(b"e2e-public-lifecycle");
    let chunks: u32 = 4;
    let deposit: u64 = 5_000_000;
    assert_eq!(
        register_pending_file(
            &node,
            owner,
            merkle_root,
            chunks,
            deposit,
            FileVisibilityV2::Public,
            Vec::new(),
        )
        .await,
        TxStatus::Success
    );

    let store = StorageMetadataExecutor::new(node.db().clone());
    let row = store.get_metadata_v2(&merkle_root).unwrap().expect("file row");
    assert_eq!(row.lifecycle, FileLifecycleV2::Pending);
    assert_eq!(row.chunk_count, chunks);
    assert_eq!(row.fee_pool, deposit);
    assert!(row.activated_at_height.is_none());

    // 3. Archive attests all 4 chunks (single tx).
    assert_eq!(
        accept_assignment(&node, archive, merkle_root, vec![0, 1, 2, 3]).await,
        TxStatus::Success
    );

    // 4. Owner activates.
    assert_eq!(activate_file(&node, owner, merkle_root).await, TxStatus::Success);
    let row = store.get_metadata_v2(&merkle_root).unwrap().unwrap();
    assert_eq!(row.lifecycle, FileLifecycleV2::Active);
    assert!(row.activated_at_height.is_some());

    // 5. Add → Update → Remove on the access list.
    let r_addr = KeyPair::from_bytes(recipient).address();
    assert_eq!(
        add_access(
            &node,
            owner,
            merkle_root,
            AccessEntryV2 {
                address: r_addr,
                encrypted_key_bundle: None,
                expires_at: None,
            },
        )
        .await,
        TxStatus::Success
    );

    assert_eq!(
        update_access(
            &node,
            owner,
            merkle_root,
            r_addr,
            AccessEntryV2 {
                address: r_addr,
                encrypted_key_bundle: None,
                expires_at: Some(99_999),
            },
        )
        .await,
        TxStatus::Success
    );
    let row = store.get_metadata_v2(&merkle_root).unwrap().unwrap();
    assert_eq!(row.access_list.len(), 1);
    assert_eq!(row.access_list[0].expires_at, Some(99_999));

    assert_eq!(
        remove_access(&node, owner, merkle_root, r_addr).await,
        TxStatus::Success
    );
    let row = store.get_metadata_v2(&merkle_root).unwrap().unwrap();
    assert!(row.access_list.is_empty());
}

/// Private file flow: both owner and recipient register X25519 keys; owner
/// registers a Private file with the recipient included; archive attests +
/// owner activates. Verifies that the recipient's bundle is persisted and
/// `account_getEncryptionPublicKey`-equivalent queries return the registered
/// keys.
#[tokio::test]
async fn snip_v2_private_file_with_x25519_registration() {
    let (node, _validator, owner, archive, recipient) = setup_node_with_funded_accounts();

    // 1. Both parties register X25519 keys (distinct, non-low-order).
    let owner_pk = [11u8; 32];
    let recipient_pk = [22u8; 32];
    assert_eq!(register_encryption_key(&node, owner, owner_pk).await, TxStatus::Success);
    assert_eq!(register_encryption_key(&node, recipient, recipient_pk).await, TxStatus::Success);

    let registry = NodeRegistryExecutor::new(node.db().clone());
    let owner_addr = KeyPair::from_bytes(owner).address();
    let recipient_addr = KeyPair::from_bytes(recipient).address();
    assert_eq!(registry.get_encryption_pubkey(&owner_addr).unwrap(), Some(owner_pk));
    assert_eq!(
        registry.get_encryption_pubkey(&recipient_addr).unwrap(),
        Some(recipient_pk)
    );

    // 2. Archive registers (snapshot capture target).
    assert!(register_archive(&node, archive).await.is_success());

    // 3. Owner registers a Private file with both parties in initial_access.
    let merkle_root = Hash::hash(b"e2e-private-lifecycle");
    let owner_entry = AccessEntryV2 {
        address: owner_addr,
        encrypted_key_bundle: Some(EncryptedKeyBundleV2([1u8; 80])),
        expires_at: None,
    };
    let recipient_entry = AccessEntryV2 {
        address: recipient_addr,
        encrypted_key_bundle: Some(EncryptedKeyBundleV2([2u8; 80])),
        expires_at: None,
    };
    assert_eq!(
        register_pending_file(
            &node,
            owner,
            merkle_root,
            1,
            5_000_000,
            FileVisibilityV2::Private,
            vec![owner_entry, recipient_entry],
        )
        .await,
        TxStatus::Success
    );

    // 4. Archive attests the single chunk; owner activates.
    assert_eq!(
        accept_assignment(&node, archive, merkle_root, vec![0]).await,
        TxStatus::Success
    );
    assert_eq!(activate_file(&node, owner, merkle_root).await, TxStatus::Success);

    // 5. Verify both bundles persisted under their addresses.
    let store = StorageMetadataExecutor::new(node.db().clone());
    let row = store.get_metadata_v2(&merkle_root).unwrap().unwrap();
    assert_eq!(row.lifecycle, FileLifecycleV2::Active);
    assert_eq!(row.visibility, FileVisibilityV2::Private);
    assert_eq!(row.access_list.len(), 2);
    let owner_in_list = row
        .access_list
        .iter()
        .find(|e| e.address == owner_addr)
        .expect("owner entry");
    assert!(owner_in_list.encrypted_key_bundle.is_some());
    let r_in_list = row
        .access_list
        .iter()
        .find(|e| e.address == recipient_addr)
        .expect("recipient entry");
    assert_eq!(
        r_in_list.encrypted_key_bundle.as_ref().unwrap().0,
        [2u8; 80]
    );
}

/// Abandonment flow: owner registers a Pending file but never gets it
/// activated; after the activation grace window passes, owner abandons and
/// receives 90% of the deposit back. Verifies fee_pool zeroing and the
/// lifecycle transition.
#[tokio::test]
async fn snip_v2_abandon_after_grace_refunds_owner() {
    let (node, _validator, owner, _archive, _recipient) = setup_node_with_funded_accounts();

    let owner_addr = KeyPair::from_bytes(owner).address();

    // Register at h=1 (block produced by submit_v2).
    let merkle_root = Hash::hash(b"e2e-abandon");
    let deposit: u64 = 1_000_000;
    let bal_before_register = node.balance(&owner_addr);
    assert_eq!(
        register_pending_file(
            &node,
            owner,
            merkle_root,
            1,
            deposit,
            FileVisibilityV2::Public,
            Vec::new(),
        )
        .await,
        TxStatus::Success
    );
    let bal_after_register = node.balance(&owner_addr);
    // Owner balance dropped by deposit + the 10-Koppa fee.
    assert_eq!(bal_before_register - bal_after_register, (deposit as u128) + 10);

    // Default activation_grace_blocks = 50 from §3.4. Submit no-op transfers
    // until we're past created_at + 50. Registration happened at block 1, so
    // we need block >= 52 to abandon.
    let h_after_register = node.height();
    while node.height() <= h_after_register + 50 {
        // Empty block — propose with no txs.
        node.produce_block().await.expect("empty block produced");
    }

    // Now abandon: refund = 90% × deposit.
    assert_eq!(abandon_file(&node, owner, merkle_root).await, TxStatus::Success);
    let bal_after_abandon = node.balance(&owner_addr);

    // Net delta from before-register: -deposit (paid in) - 10 (register fee)
    //                                   + 0.9 * deposit (refund) - 1 (abandon fee)
    // = -0.1 * deposit - 11
    let expected_refund = (deposit as u128 * 90) / 100;
    let expected_delta = -((deposit as i128) + 10) + (expected_refund as i128) - 1;
    let actual_delta = bal_after_abandon as i128 - bal_before_register as i128;
    assert_eq!(actual_delta, expected_delta);

    let store = StorageMetadataExecutor::new(node.db().clone());
    let row = store.get_metadata_v2(&merkle_root).unwrap().unwrap();
    assert_eq!(row.lifecycle, FileLifecycleV2::Abandoned);
    assert_eq!(row.fee_pool, 0);
    // SNIP indexer dependency: the chain must surface the abandon block via
    // `abandoned_at_height`. End-to-end check: row write happened, value lies
    // strictly past the activation grace window (otherwise the abandon would
    // have been rejected with code 31).
    let abandoned_at = row.abandoned_at_height.expect("abandoned_at_height populated");
    assert!(
        abandoned_at > row.created_at + 50, // default activation_grace_blocks
        "abandoned_at_height ({}) must be past created_at + grace ({} + 50)",
        abandoned_at,
        row.created_at
    );
}

/// Multi-block AcceptAssignmentV2 OR-merge: two attestation txs from the
/// same archive in separate blocks must accumulate bits, not overwrite.
/// Then verify the coverage backend (the same logic the RPC reads) sees full
/// coverage and `can_activate_now == true`.
#[tokio::test]
async fn snip_v2_accept_assignment_or_merge_across_blocks() {
    let (node, _validator, owner, archive, _recipient) = setup_node_with_funded_accounts();

    assert!(register_archive(&node, archive).await.is_success());

    let merkle_root = Hash::hash(b"e2e-or-merge");
    let chunks: u32 = 8;
    assert_eq!(
        register_pending_file(
            &node,
            owner,
            merkle_root,
            chunks,
            1_000_000,
            FileVisibilityV2::Public,
            Vec::new(),
        )
        .await,
        TxStatus::Success
    );

    // Block N: attest {0, 1, 2}.
    assert_eq!(
        accept_assignment(&node, archive, merkle_root, vec![0, 1, 2]).await,
        TxStatus::Success
    );
    // Block N+1: attest {2, 3, 4} — overlaps at 2, OR-merges to {0,1,2,3,4}.
    assert_eq!(
        accept_assignment(&node, archive, merkle_root, vec![2, 3, 4]).await,
        TxStatus::Success
    );

    // Verify bitmap state directly.
    let store = StorageMetadataExecutor::new(node.db().clone());
    let archive_addr = KeyPair::from_bytes(archive).address();
    let bm = store
        .get_attestation_bitmap_v2(&merkle_root, &archive_addr)
        .unwrap()
        .expect("bitmap allocated");
    assert_eq!(bm.len(), 1); // ceil(8/8) = 1
    // Bits 0..=4 set, bits 5..=7 unset.
    assert_eq!(bm[0], 0b0001_1111);

    // Activation must still fail — chunks 5, 6, 7 uncovered.
    assert_eq!(activate_file(&node, owner, merkle_root).await, TxStatus::Failed(34));

    // Block N+2: attest {5, 6, 7} — fills coverage.
    assert_eq!(
        accept_assignment(&node, archive, merkle_root, vec![5, 6, 7]).await,
        TxStatus::Success
    );

    // Verify coverage RPC backend now reports `can_activate_now`.
    let registry = NodeRegistryExecutor::new(node.db().clone());
    let cov = store
        .compute_coverage_v2(&merkle_root, &registry, 3)
        .unwrap()
        .expect("file exists");
    assert_eq!(cov.chunk_count, chunks);
    assert_eq!(cov.covered_count, chunks);
    assert_eq!(cov.lifecycle, FileLifecycleV2::Pending);

    // Now activation succeeds.
    assert_eq!(activate_file(&node, owner, merkle_root).await, TxStatus::Success);
}
