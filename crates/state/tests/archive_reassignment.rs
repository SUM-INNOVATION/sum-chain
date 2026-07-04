//! Issue #62 — deterministic archive-node chunk reassignment.
//!
//! Exercises the epoch-aware design end-to-end through the `BlockExecutor`:
//! the activation gate (330, no fee), owner/lifecycle/no-gap validity
//! (331–334), Active-file re-attestation gating (335), epoch-aware bitmap CF
//! separation, Pending and Active reassignment flows, aggregate coverage
//! recovery, the coverage RPC summary (`per_epoch` / `reassignment_needed`),
//! pre-#62 compatibility, and restart persistence of the new CFs.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    assigned_archives, Address, Hash, NodeRegistryOperation, NodeRegistryTxData, NodeRole,
    NodeStatus, SignedTransaction, StorageMetadataOperationV2, StorageMetadataV2TxData,
    TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::storage_metadata::{
    CoverageSummaryV2, StorageMetadataExecutor, CF_ASSIGNMENT_ATTESTATIONS_V2,
    CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH,
};
use sumchain_state::NodeRegistryExecutor;
use sumchain_storage::Database;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// v2 on, reassignment gate open from genesis, replication factor 1 (one archive
/// per chunk → clean departure/replacement).
fn params_reassign_enabled() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.archive_reassignment_enabled_from_height = Some(0);
    p.assignment_replication_factor = 1;
    p
}

/// v2 on, reassignment gate DORMANT (default None), replication factor 1.
fn params_reassign_dormant() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.assignment_replication_factor = 1;
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

fn register_archive_op() -> NodeRegistryOperation {
    NodeRegistryOperation::Register { role: NodeRole::ArchiveNode, stake: STAKE }
}

fn register_file_op(merkle_root: Hash) -> StorageMetadataOperationV2 {
    StorageMetadataOperationV2::RegisterFilePendingV2 {
        merkle_root,
        plaintext_size_bytes: 500,
        stored_size_bytes: 1000, // ceil(1000 / 1 MiB) == 1 chunk
        chunk_count: 1,
        fee_deposit: 0,
        visibility: 0, // Public
        initial_access: vec![],
    }
}

// ── Test helpers ─────────────────────────────────────────────────────────────

/// Manually-built epoch-0 attestation bitmap key: `[b'A', root, archive]`.
fn epoch0_key(root: &Hash, archive: &Address) -> Vec<u8> {
    let mut k = vec![b'A'];
    k.extend_from_slice(root.as_bytes());
    k.extend_from_slice(archive.as_bytes());
    k
}

/// Manually-built reassignment bitmap key: `[b'R', root, epoch_be, archive]`.
fn epoch_key(root: &Hash, epoch: u64, archive: &Address) -> Vec<u8> {
    let mut k = vec![b'R'];
    k.extend_from_slice(root.as_bytes());
    k.extend_from_slice(&epoch.to_be_bytes());
    k.extend_from_slice(archive.as_bytes());
    k
}

/// Which archive is assigned chunk 0 for `root` given the (unsorted) address set,
/// under replication factor 1.
fn assigned_to_chunk0(root: &Hash, addrs: &[Address]) -> Address {
    let a = assigned_archives(root, addrs, 0, 1);
    a[0]
}

fn coverage(db: &Arc<Database>, root: &Hash) -> CoverageSummaryV2 {
    let storage = StorageMetadataExecutor::new(db.clone());
    let registry = NodeRegistryExecutor::new(db.clone());
    storage
        .compute_coverage_v2(root, &registry, 1)
        .unwrap()
        .expect("file exists")
}

// ── Activation gate ──────────────────────────────────────────────────────────

#[test]
fn defaults_leave_reassignment_dormant() {
    let p = ChainParams::default();
    assert_eq!(p.archive_reassignment_enabled_from_height, None);
}

#[test]
fn gate_closed_reassign_rejects_330_no_mutation() {
    let (state, db, _dir, executor) = setup_with_params(params_reassign_dormant());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"gate-closed-reassign");

    executor
        .execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    let owner_bal = state.get_balance(&owner.address()).unwrap();

    let res = executor
        .execute_tx(
            &signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            3,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(330)), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0);
    // No fee, no nonce bump, no epoch appended.
    assert_eq!(state.get_balance(&owner.address()).unwrap(), owner_bal);
    assert!(StorageMetadataExecutor::new(db.clone())
        .get_file_reassignments(&root)
        .unwrap()
        .is_empty());
}

// ── ReassignChunksV2 validity (gate open) ────────────────────────────────────

#[test]
fn reassign_file_missing_331() {
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &owner, 1_000_000);
    let res = executor
        .execute_tx(
            &signed(&owner, FEE, 0, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: Hash::hash(b"nope") })),
            &proposer.address(),
            1,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(331)), "got {:?}", res.status);
}

#[test]
fn reassign_non_owner_332() {
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let owner = KeyPair::generate();
    let stranger = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &owner, 1_000_000);
    fund(&state, &stranger, 1_000_000);
    let root = Hash::hash(b"non-owner");
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 1, 1000)
        .unwrap();
    let res = executor
        .execute_tx(
            &signed(&stranger, FEE, 0, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            2,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(332)), "got {:?}", res.status);
}

#[test]
fn reassign_no_gap_334() {
    // Archive is active and never leaves → no gap → 334.
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"no-gap");
    executor
        .execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    let res = executor
        .execute_tx(
            &signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            3,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(334)), "got {:?}", res.status);
}

#[test]
fn reassign_abandoned_333() {
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"abandoned");
    // Register at height 2, abandon after the 50-block grace window.
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    let ab = executor
        .execute_tx(
            &signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::AbandonFileV2 { merkle_root: root })),
            &proposer.address(),
            200,
            1000,
        )
        .unwrap();
    assert!(ab.status.is_success(), "abandon got {:?}", ab.status);
    let res = executor
        .execute_tx(
            &signed(&owner, FEE, 2, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            201,
            1000,
        )
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(333)), "got {:?}", res.status);
}

// ── Active-file reassignment: full recovery flow ─────────────────────────────

#[test]
fn active_file_reassignment_recovers_coverage_with_epoch_cf_separation() {
    let (state, db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &a, (STAKE as u128) + 1_000_000);
    fund(&state, &b, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"active-reassign");

    // Register both archives at height 1 → epoch-0 snapshot {A,B}.
    executor
        .execute_tx(&signed(&a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&b, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();

    // Register file at height 2 (assignment_height = 2).
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();

    // Discover the epoch-0 assignee for chunk 0 and accept from it.
    let assignee0 = assigned_to_chunk0(&root, &[a.address(), b.address()]);
    let (assignee_kp, other_kp) = if assignee0 == a.address() { (&a, &b) } else { (&b, &a) };
    let acc = executor
        .execute_tx(
            &signed(assignee_kp, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })),
            &proposer.address(),
            3,
            1000,
        )
        .unwrap();
    assert!(acc.status.is_success(), "epoch-0 accept got {:?}", acc.status);

    // Activate (coverage complete via the assignee).
    let act = executor
        .execute_tx(
            &signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })),
            &proposer.address(),
            4,
            1000,
        )
        .unwrap();
    assert!(act.status.is_success(), "activate got {:?}", act.status);

    // The epoch-0 assignee leaves the active set (Slashed) at height 5.
    let slash = executor
        .execute_tx(
            &signed(&owner, FEE, 2, nr(NodeRegistryOperation::UpdateStatus { target: assignee_kp.address(), new_status: NodeStatus::Slashed })),
            &proposer.address(),
            5,
            1000,
        )
        .unwrap();
    assert!(slash.status.is_success(), "slash got {:?}", slash.status);

    // Coverage now shows a gap: the assignee's bitmap no longer counts.
    let cov = coverage(&db, &root);
    assert_eq!(cov.covered_count, 0, "departed archive should not contribute");
    assert!(cov.reassignment_needed, "a latest-epoch archive left → reassignment needed");
    assert_eq!(cov.assignment_epochs, vec![2]);

    // Owner reassigns at height 6 → epoch 1 (snapshot excludes the departed one).
    let re = executor
        .execute_tx(
            &signed(&owner, FEE, 3, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            6,
            1000,
        )
        .unwrap();
    assert!(re.status.is_success(), "reassign got {:?}", re.status);
    assert_eq!(
        StorageMetadataExecutor::new(db.clone()).get_file_reassignments(&root).unwrap(),
        vec![6]
    );

    // The surviving archive is assigned chunk 0 in epoch 1; it re-attests
    // (Active file, gate open, reassignment epoch exists).
    let acc2 = executor
        .execute_tx(
            &signed(other_kp, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })),
            &proposer.address(),
            7,
            1000,
        )
        .unwrap();
    assert!(acc2.status.is_success(), "epoch-1 re-accept got {:?}", acc2.status);

    // Epoch-CF separation: the replacement bit lives in the epoch CF; the
    // epoch-0 CF for the replacement is untouched; the original assignee's
    // epoch-0 bitmap is untouched.
    assert!(
        db.get(CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH, &epoch_key(&root, 6, &other_kp.address())).unwrap().is_some(),
        "replacement attestation must be in the epoch CF"
    );
    assert!(
        db.get(CF_ASSIGNMENT_ATTESTATIONS_V2, &epoch0_key(&root, &other_kp.address())).unwrap().is_none(),
        "replacement must NOT write the epoch-0 CF"
    );
    assert!(
        db.get(CF_ASSIGNMENT_ATTESTATIONS_V2, &epoch0_key(&root, &assignee_kp.address())).unwrap().is_some(),
        "original epoch-0 bitmap must remain stored"
    );

    // Aggregate coverage recovered; no further reassignment needed.
    let cov2 = coverage(&db, &root);
    assert_eq!(cov2.covered_count, 1, "replacement epoch restores coverage");
    assert!(!cov2.reassignment_needed, "latest epoch is all-active → no churn");
    assert_eq!(cov2.assignment_epochs, vec![2, 6]);
    assert_eq!(cov2.latest_assignment_epoch, 6);
    // Top-level per_archive is epoch-0-only; per_epoch has both epochs.
    assert_eq!(cov2.per_epoch.len(), 2);
    assert!(cov2.per_epoch[0].is_epoch_zero);
    assert!(!cov2.per_epoch[1].is_epoch_zero);
    assert_eq!(cov2.per_epoch[1].epoch_height, 6);

    // A second reassignment now is a no-op (anti-churn).
    let re2 = executor
        .execute_tx(
            &signed(&owner, FEE, 4, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })),
            &proposer.address(),
            8,
            1000,
        )
        .unwrap();
    assert!(matches!(re2.status, TxStatus::Failed(334)), "no-op churn should 334, got {:?}", re2.status);
}

// ── Active-file re-attestation gating (335) ──────────────────────────────────

#[test]
fn active_reattest_without_reassignment_epoch_335() {
    // Gate OPEN, Active file, no reassignment epoch → 335 (not 33).
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"reattest-335");
    executor
        .execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&archive, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 3, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 4, 1000)
        .unwrap();

    let res = executor
        .execute_tx(&signed(&archive, FEE, 2, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 5, 1000)
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(335)), "got {:?}", res.status);
}

#[test]
fn active_reattest_gate_dormant_stays_33() {
    // Gate DORMANT → pre-#62 behavior preserved: Active re-attest → 33.
    let (state, _db, _dir, executor) = setup_with_params(params_reassign_dormant());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"reattest-33");
    executor
        .execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&archive, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 3, 1000)
        .unwrap();
    executor
        .execute_tx(&signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 4, 1000)
        .unwrap();

    let res = executor
        .execute_tx(&signed(&archive, FEE, 2, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 5, 1000)
        .unwrap();
    assert!(matches!(res.status, TxStatus::Failed(33)), "pre-#62 behavior expected, got {:?}", res.status);
}

// ── Pending-file reassignment ────────────────────────────────────────────────

#[test]
fn pending_file_reassignment_flow() {
    let (state, db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &a, (STAKE as u128) + 1_000_000);
    fund(&state, &b, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"pending-reassign");

    executor.execute_tx(&signed(&a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    executor.execute_tx(&signed(&b, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    executor.execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000).unwrap();

    // The epoch-0 assignee leaves BEFORE the file activates.
    let assignee0 = assigned_to_chunk0(&root, &[a.address(), b.address()]);
    let (assignee_kp, other_kp) = if assignee0 == a.address() { (&a, &b) } else { (&b, &a) };
    executor
        .execute_tx(&signed(&owner, FEE, 1, nr(NodeRegistryOperation::UpdateStatus { target: assignee_kp.address(), new_status: NodeStatus::Slashed })), &proposer.address(), 3, 1000)
        .unwrap();

    // Reassign the still-Pending file, then the survivor accepts + activates.
    let re = executor
        .execute_tx(&signed(&owner, FEE, 2, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })), &proposer.address(), 4, 1000)
        .unwrap();
    assert!(re.status.is_success(), "pending reassign got {:?}", re.status);

    let acc = executor
        .execute_tx(&signed(other_kp, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 5, 1000)
        .unwrap();
    assert!(acc.status.is_success(), "survivor accept got {:?}", acc.status);
    // Replacement bit is in the epoch CF, not epoch-0 CF.
    assert!(db.get(CF_ASSIGNMENT_ATTESTATIONS_V2_EPOCH, &epoch_key(&root, 4, &other_kp.address())).unwrap().is_some());

    let cov = coverage(&db, &root);
    assert_eq!(cov.covered_count, cov.chunk_count, "aggregate coverage complete");
    assert_eq!(cov.lifecycle, sumchain_primitives::FileLifecycleV2::Pending);

    let act = executor
        .execute_tx(&signed(&owner, FEE, 3, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 6, 1000)
        .unwrap();
    assert!(act.status.is_success(), "activate got {:?}", act.status);
}

// ── Insufficient active archives → coverage stays incomplete ─────────────────

#[test]
fn insufficient_active_archives_incomplete() {
    // A single archive covers, then leaves; no replacement exists → after
    // reassignment there is no active archive to attest, so coverage stays 0.
    let (state, db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let a = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &a, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"insufficient");

    executor.execute_tx(&signed(&a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    executor.execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000).unwrap();
    executor.execute_tx(&signed(&a, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 3, 1000).unwrap();
    executor.execute_tx(&signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 4, 1000).unwrap();
    // The only archive leaves.
    executor.execute_tx(&signed(&owner, FEE, 2, nr(NodeRegistryOperation::UpdateStatus { target: a.address(), new_status: NodeStatus::Slashed })), &proposer.address(), 5, 1000).unwrap();

    let cov = coverage(&db, &root);
    assert_eq!(cov.covered_count, 0);
    assert!(cov.reassignment_needed);

    // Reassign — but there is no active archive, so coverage cannot recover.
    let re = executor.execute_tx(&signed(&owner, FEE, 3, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })), &proposer.address(), 6, 1000).unwrap();
    assert!(re.status.is_success(), "reassign got {:?}", re.status);
    let cov2 = coverage(&db, &root);
    assert_eq!(cov2.covered_count, 0, "no active archive → still incomplete");
}

// ── Pre-#62 compatibility ────────────────────────────────────────────────────

#[test]
fn file_without_reassignment_is_epoch_zero_only() {
    let (state, db, _dir, executor) = setup_with_params(params_reassign_enabled());
    let archive = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    fund(&state, &owner, 1_000_000);
    let root = Hash::hash(b"epoch0-only");
    executor.execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    executor.execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000).unwrap();
    executor.execute_tx(&signed(&archive, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 3, 1000).unwrap();

    let cov = coverage(&db, &root);
    assert_eq!(cov.assignment_epochs, vec![2], "single epoch = assignment_height");
    assert_eq!(cov.latest_assignment_epoch, 2);
    assert_eq!(cov.per_epoch.len(), 1);
    assert!(cov.per_epoch[0].is_epoch_zero);
    assert!(!cov.reassignment_needed);
    assert_eq!(cov.covered_count, 1);
    // No epoch CF rows exist for this file.
    assert!(StorageMetadataExecutor::new(db.clone()).get_file_reassignments(&root).unwrap().is_empty());
}

// ── Restart persistence of the new CFs ───────────────────────────────────────

#[test]
fn reassignment_state_survives_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = KeyPair::generate();
    let b = KeyPair::generate();
    let owner = KeyPair::generate();
    let proposer = KeyPair::generate();
    let root = Hash::hash(b"restart");

    {
        let db = Arc::new(Database::open_default(dir.path()).unwrap());
        let state = Arc::new(sumchain_state::StateManager::new(db.clone(), CHAIN_ID));
        let executor = sumchain_state::executor::BlockExecutor::new(state.clone(), db.clone(), params_reassign_enabled());
        fund(&state, &a, (STAKE as u128) + 1_000_000);
        fund(&state, &b, (STAKE as u128) + 1_000_000);
        fund(&state, &owner, 1_000_000);

        executor.execute_tx(&signed(&a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
        executor.execute_tx(&signed(&b, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
        executor.execute_tx(&signed(&owner, FEE, 0, sm(register_file_op(root))), &proposer.address(), 2, 1000).unwrap();
        let assignee0 = assigned_to_chunk0(&root, &[a.address(), b.address()]);
        let assignee_kp = if assignee0 == a.address() { &a } else { &b };
        executor.execute_tx(&signed(assignee_kp, FEE, 1, sm(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })), &proposer.address(), 3, 1000).unwrap();
        executor.execute_tx(&signed(&owner, FEE, 1, sm(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 4, 1000).unwrap();
        executor.execute_tx(&signed(&owner, FEE, 2, nr(NodeRegistryOperation::UpdateStatus { target: assignee_kp.address(), new_status: NodeStatus::Slashed })), &proposer.address(), 5, 1000).unwrap();
        executor.execute_tx(&signed(&owner, FEE, 3, sm(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })), &proposer.address(), 6, 1000).unwrap();
    }

    // Reopen the same RocksDB path.
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let epochs = StorageMetadataExecutor::new(db.clone()).get_file_reassignments(&root).unwrap();
    assert_eq!(epochs, vec![6], "reassignment epoch persisted across restart");
}
