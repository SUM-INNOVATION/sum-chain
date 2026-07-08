//! Issue #100 (Phase 2) — bounded assignment-aware PoR scheduler + the V2
//! `SubmitStorageProof` settlement prerequisite + the challengeable-file index.
//!
//! Gate closed ⇒ post-#101 single-challenge behavior. Gate open ⇒ a bounded,
//! deterministic set of assignment-aware challenges sampled from the compact
//! challengeable-file index (never a files×chunks sweep). The settlement fix
//! lets a V2-challenged archive actually prove (paid from V2 `fee_pool`) instead
//! of being slashed.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    assigned_archives_presorted, Address, Hash, NodeRecord, NodeRegistryOperation,
    NodeRegistryTxData, NodeRole, NodeStatus, SignedTransaction, StorageMetadataOperation,
    StorageMetadataOperationV2, StorageMetadataTxData, StorageMetadataV2TxData, TransactionV2,
    TxPayload, CHALLENGE_REWARD,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::storage_metadata::{StorageMetadataExecutor, CF_CHALLENGEABLE_FILES_V2};
use sumchain_state::{NodeRegistryExecutor, StateManager};
use sumchain_storage::Database;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;
const SMALL_DEPOSIT: u64 = 1_000_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn params_scheduler(r: u32, max_files: u32, max_chunks: u32, max_emit: u32) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.assignment_aware_por_scheduler_enabled_from_height = Some(0);
    p.assignment_replication_factor = r;
    p.max_files_sampled_per_interval = max_files;
    p.max_chunks_sampled_per_file = max_chunks;
    p.max_assignment_aware_challenges_per_block = max_emit;
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
fn sm_v2(op: StorageMetadataOperationV2) -> TxPayload {
    TxPayload::StorageMetadataV2(StorageMetadataV2TxData { operation: op })
}
fn sm_v1(op: StorageMetadataOperation) -> TxPayload {
    TxPayload::StorageMetadata(StorageMetadataTxData { operation: op })
}
fn register_archive_op() -> NodeRegistryOperation {
    NodeRegistryOperation::Register { role: NodeRole::ArchiveNode, stake: STAKE }
}
fn v2_register_op(root: Hash, chunk_count: u32, fee_deposit: u64) -> StorageMetadataOperationV2 {
    StorageMetadataOperationV2::RegisterFilePendingV2 {
        merkle_root: root,
        plaintext_size_bytes: 500,
        stored_size_bytes: (chunk_count as u64) * 1_048_576, // C chunks of 1 MiB
        chunk_count,
        fee_deposit,
        visibility: 0,
        initial_access: vec![],
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn sorted_addrs(nodes: &[NodeRecord]) -> Vec<Address> {
    let mut v: Vec<Address> = nodes.iter().map(|n| n.address).collect();
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    v
}
fn assigned(root: &Hash, snapshot: &[NodeRecord], chunk: u32, r: u32) -> Vec<Address> {
    assigned_archives_presorted(root, &sorted_addrs(snapshot), chunk, r)
}
fn executors(db: &Arc<Database>) -> (StorageMetadataExecutor, NodeRegistryExecutor) {
    (StorageMetadataExecutor::new(db.clone()), NodeRegistryExecutor::new(db.clone()))
}

/// Register `k` archives at height 1. Returns keypairs + a per-archive nonce
/// vector (each starts at 1, after the register at nonce 0).
fn register_archives(state: &StateManager, executor: &BlockExecutor, k: usize) -> (Vec<KeyPair>, Vec<u64>) {
    let proposer = KeyPair::generate();
    let archives: Vec<KeyPair> = (0..k).map(|_| KeyPair::generate()).collect();
    for a in &archives {
        fund(state, a, (STAKE as u128) + 1_000_000);
        executor.execute_tx(&signed(a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    }
    (archives, vec![1u64; k])
}

/// Fund a fresh sender and set `target`'s node status to `Slashed` at `height`.
fn slash_node(state: &StateManager, executor: &BlockExecutor, target: Address, height: u64) {
    let admin = KeyPair::generate();
    fund(state, &admin, 1_000_000);
    let r = executor
        .execute_tx(&signed(&admin, FEE, 0, nr(NodeRegistryOperation::UpdateStatus { target, new_status: NodeStatus::Slashed })), &KeyPair::generate().address(), height, 1000)
        .unwrap();
    assert!(r.status.is_success(), "slash: {:?}", r.status);
}

/// Register a funded V2 file (assignment_height = 2), have every assigned archive
/// accept its chunks (height 3), then activate (height 4) → funded + Active.
/// Returns the file owner keypair (owner nonce is at 2 afterwards).
#[allow(clippy::too_many_arguments)]
fn make_active_funded_file(
    state: &StateManager,
    executor: &BlockExecutor,
    db: &Arc<Database>,
    archives: &[KeyPair],
    arch_nonces: &mut [u64],
    r: u32,
    root: Hash,
    chunk_count: u32,
    fee_deposit: u64,
) -> KeyPair {
    let proposer = KeyPair::generate();
    let owner = KeyPair::generate();
    fund(state, &owner, (fee_deposit as u128) + 5_000_000);
    let rv = executor.execute_tx(&signed(&owner, FEE, 0, sm_v2(v2_register_op(root, chunk_count, fee_deposit))), &proposer.address(), 2, 1000).unwrap();
    assert!(rv.status.is_success(), "v2 register: {:?}", rv.status);

    let registry = NodeRegistryExecutor::new(db.clone());
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    for (idx, kp) in archives.iter().enumerate() {
        let my_chunks: Vec<u32> = (0..chunk_count)
            .filter(|c| assigned(&root, &snapshot, *c, r).iter().any(|a| a.as_bytes() == kp.address().as_bytes()))
            .collect();
        if !my_chunks.is_empty() {
            let acc = executor.execute_tx(&signed(kp, FEE, arch_nonces[idx], sm_v2(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: my_chunks })), &proposer.address(), 3, 1000).unwrap();
            assert!(acc.status.is_success(), "accept: {:?}", acc.status);
            arch_nonces[idx] += 1;
        }
    }
    let act = executor.execute_tx(&signed(&owner, FEE, 1, sm_v2(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })), &proposer.address(), 4, 1000).unwrap();
    assert!(act.status.is_success(), "activate: {:?}", act.status);
    owner
}

// ── Gate default ─────────────────────────────────────────────────────────────

#[test]
fn defaults_leave_scheduler_dormant() {
    let p = ChainParams::default();
    assert_eq!(p.assignment_aware_por_scheduler_enabled_from_height, None);
    assert_eq!(p.max_assignment_aware_challenges_per_block, 16);
    assert_eq!(p.max_files_sampled_per_interval, 8);
    assert_eq!(p.max_chunks_sampled_per_file, 4);
}

// ── V2 SubmitStorageProof settlement (prerequisite) ──────────────────────────

#[test]
fn v2_proof_settlement_pays_from_v2_fee_pool_no_slash() {
    // A funded, single-chunk V2 file: challenge it, and the assigned archive
    // proves against the V2 root (chunk_hash == root for a 1-chunk file) and is
    // PAID from V2 fee_pool — not slashed.
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 8, 4, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"settle-file");
    let deposit = CHALLENGE_REWARD * 3;
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, deposit);

    let (storage, registry) = executors(&db);
    let emitted = storage
        .generate_challenge_schedule(&Hash::hash(b"p"), 100, &registry, r, 8, 4, 16)
        .unwrap();
    assert_eq!(emitted.len(), 1, "one funded+Active file, one chunk");
    let ch = &emitted[0];
    assert_eq!(ch.merkle_root, root);

    let target_kp = archives.iter().find(|k| k.address().as_bytes() == ch.target_node.as_bytes()).unwrap();
    let bal_before = state.get_balance(&ch.target_node).unwrap();
    let fee_pool_before = storage.get_metadata_v2(&root).unwrap().unwrap().fee_pool;
    let tgt_nonce = nonces[archives.iter().position(|k| k.address().as_bytes() == ch.target_node.as_bytes()).unwrap()];

    // Single-chunk proof: chunk_hash == merkle_root, empty path. Submit at the
    // challenge height (within TTL).
    let proof = StorageMetadataOperation::SubmitStorageProof {
        challenge_id: ch.challenge_id, merkle_root: root, chunk_index: 0, chunk_hash: root, merkle_path: vec![],
    };
    let res = executor.execute_tx(&signed(target_kp, FEE, tgt_nonce, sm_v1(proof)), &KeyPair::generate().address(), 100, 1000).unwrap();
    assert!(res.status.is_success(), "V2 proof must succeed: {:?}", res.status);

    // Paid CHALLENGE_REWARD from V2 fee_pool (archive also pays the proof-tx FEE);
    // challenge cleared; archive Active. The V2 fee_pool debit is the exact,
    // fee-independent economics check.
    assert_eq!(state.get_balance(&ch.target_node).unwrap(), bal_before + CHALLENGE_REWARD as u128 - FEE, "paid CHALLENGE_REWARD net of the proof-tx fee");
    assert_eq!(storage.get_metadata_v2(&root).unwrap().unwrap().fee_pool, fee_pool_before - CHALLENGE_REWARD, "debited exactly CHALLENGE_REWARD from V2 fee_pool");
    assert!(storage.get_challenge(&ch.challenge_id).unwrap().is_none(), "challenge deleted after proof");
    assert_eq!(registry.get_node(&ch.target_node).unwrap().unwrap().status, NodeStatus::Active, "honest archive not slashed");
}

#[test]
fn v2_payout_to_zero_removes_index_entry() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 8, 4, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"drain-file");
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, CHALLENGE_REWARD); // exactly one payout drains it

    let (storage, registry) = executors(&db);
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, root.as_bytes()).unwrap().is_some(), "activated funded file indexed");

    let ch = storage.generate_challenge_schedule(&Hash::hash(b"p"), 100, &registry, r, 8, 4, 16).unwrap().remove(0);
    let target_kp = archives.iter().find(|k| k.address().as_bytes() == ch.target_node.as_bytes()).unwrap();
    let tgt_nonce = nonces[archives.iter().position(|k| k.address().as_bytes() == ch.target_node.as_bytes()).unwrap()];
    let proof = StorageMetadataOperation::SubmitStorageProof {
        challenge_id: ch.challenge_id, merkle_root: root, chunk_index: 0, chunk_hash: root, merkle_path: vec![],
    };
    executor.execute_tx(&signed(target_kp, FEE, tgt_nonce, sm_v1(proof)), &KeyPair::generate().address(), 100, 1000).unwrap();

    assert_eq!(storage.get_metadata_v2(&root).unwrap().unwrap().fee_pool, 0, "fee_pool drained");
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, root.as_bytes()).unwrap().is_none(), "drained file removed from challengeable index");
}

// ── Backfill ─────────────────────────────────────────────────────────────────

#[test]
fn backfill_populates_preupgrade_files_and_marker_prevents_repeat() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 8, 4, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"preupgrade-file");
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, SMALL_DEPOSIT);

    let (storage, _registry) = executors(&db);
    // Simulate a pre-upgrade file: index entry absent though the file is Active+funded.
    storage.challengeable_index_remove(&root).unwrap();
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, root.as_bytes()).unwrap().is_none());

    // First backfill scans once, populates, and sets the marker.
    assert!(storage.backfill_challengeable_index().unwrap(), "first backfill runs");
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, root.as_bytes()).unwrap().is_some(), "backfill indexed the file");
    assert!(storage.por_scheduler_backfill_done().unwrap(), "marker set");

    // Remove again; a second backfill must be a no-op (marker present → no scan).
    storage.challengeable_index_remove(&root).unwrap();
    assert!(!storage.backfill_challengeable_index().unwrap(), "second backfill is a no-op");
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, root.as_bytes()).unwrap().is_none(), "no repeat full scan → entry stays absent");
}

// ── Scheduler: caps, determinism, targeting ──────────────────────────────────

#[test]
fn scheduler_emits_within_caps() {
    // 6 single-chunk files, cap emit=3 ⇒ at most 3 challenges, ≤ max_files distinct.
    let r = 2u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 4, 4, 3));
    let (archives, mut nonces) = register_archives(&state, &executor, 4);
    for i in 0..6u32 {
        let root = Hash::hash(format!("capfile-{i}").as_bytes());
        make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, SMALL_DEPOSIT);
    }
    let (storage, registry) = executors(&db);
    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 4, 4, 3).unwrap();
    assert!(emitted.len() <= 3, "emit cap enforced: {}", emitted.len());
    let distinct_files: std::collections::HashSet<_> = emitted.iter().map(|c| c.merkle_root).collect();
    assert!(distinct_files.len() <= 4, "file-sample cap enforced");
}

#[test]
fn scheduler_respects_chunk_cap_per_file() {
    // One 8-chunk file, max_chunks=3 ⇒ ≤3 challenges for it.
    let r = 2u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 4, 3, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 3);
    let root = Hash::hash(b"multichunk");
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 8, SMALL_DEPOSIT);
    let (storage, registry) = executors(&db);
    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 4, 3, 16).unwrap();
    let for_file = emitted.iter().filter(|c| c.merkle_root == root).count();
    assert!(for_file <= 3, "chunk-sample cap per file enforced: {for_file}");
    let distinct_chunks: std::collections::HashSet<_> = emitted.iter().filter(|c| c.merkle_root == root).map(|c| c.chunk_index).collect();
    assert_eq!(distinct_chunks.len(), for_file, "no duplicate (file,chunk) pairs");
}

#[test]
fn scheduler_deterministic_replay_conformance() {
    let r = 2u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 4, 4, 8));
    let (archives, mut nonces) = register_archives(&state, &executor, 4);
    for i in 0..4u32 {
        make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, Hash::hash(format!("detfile-{i}").as_bytes()), 2, SMALL_DEPOSIT);
    }
    let (storage, registry) = executors(&db);
    let parent = Hash::hash(b"det-parent");
    let a = storage.generate_challenge_schedule(&parent, 100, &registry, r, 4, 4, 8).unwrap();
    // Clear written challenges, replay on a fresh executor over the same DB.
    for c in &a { storage.delete_challenge(c).unwrap(); }
    let (storage2, registry2) = executors(&db);
    let b = storage2.generate_challenge_schedule(&parent, 100, &registry2, r, 4, 4, 8).unwrap();
    let key = |c: &sumchain_primitives::StorageChallenge| (c.merkle_root, c.chunk_index, c.target_node);
    assert_eq!(a.iter().map(key).collect::<Vec<_>>(), b.iter().map(key).collect::<Vec<_>>(), "schedule must be deterministic/replayable");
}

#[test]
fn scheduler_target_is_always_assigned_active() {
    let r = 2u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 6, 4, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 5); // >R ⇒ some active unassigned
    for i in 0..4u32 {
        make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, Hash::hash(format!("tgtfile-{i}").as_bytes()), 3, SMALL_DEPOSIT);
    }
    let (storage, registry) = executors(&db);
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let active: Vec<Address> = registry.get_active_archive_nodes().unwrap().iter().map(|n| n.address).collect();
    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 6, 4, 16).unwrap();
    assert!(!emitted.is_empty());
    for c in &emitted {
        let assigned_set = assigned(&c.merkle_root, &snapshot, c.chunk_index, r);
        assert!(assigned_set.iter().any(|a| a.as_bytes() == c.target_node.as_bytes()), "target assigned to chunk");
        assert!(active.iter().any(|a| a.as_bytes() == c.target_node.as_bytes()), "target currently active");
    }
}

#[test]
fn scheduler_skips_stale_index_entry() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 8, 4, 16));
    register_archives(&state, &executor, 2);
    let (storage, registry) = executors(&db);
    // Insert a stale entry: a root with no V2 row at all.
    let bogus = Hash::hash(b"bogus-root");
    storage.challengeable_index_insert(&bogus, 1).unwrap();
    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 8, 4, 16).unwrap();
    assert!(emitted.is_empty(), "stale entry produces no challenge");
    assert!(db.get(CF_CHALLENGEABLE_FILES_V2, bogus.as_bytes()).unwrap().is_none(), "stale entry healed (removed)");
}

#[test]
fn scheduler_skips_pair_with_no_assigned_active() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_scheduler(r, 8, 4, 16));
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"noactive-file");
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, SMALL_DEPOSIT);

    let (storage, registry) = executors(&db);
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assignee = assigned(&root, &snapshot, 0, r)[0];
    // Slash the sole assignee ⇒ no assigned-active target for chunk 0.
    slash_node(&state, &executor, assignee, 5);
    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 8, 4, 16).unwrap();
    assert!(emitted.is_empty(), "no assigned-active archive ⇒ skip, no bystander");
}

#[test]
fn scheduler_uses_latest_epoch() {
    let r = 1u32;
    let mut params = params_scheduler(r, 8, 4, 16);
    params.archive_reassignment_enabled_from_height = Some(0);
    let (state, db, _dir, executor) = setup_with_params(params);
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"reassign-sched");
    let owner = make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, r, root, 1, SMALL_DEPOSIT);

    let (storage, registry) = executors(&db);
    let snap0 = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assignee0 = assigned(&root, &snap0, 0, r)[0];
    let survivor = archives.iter().find(|k| k.address().as_bytes() != assignee0.as_bytes()).unwrap();

    // Slash epoch-0 assignee (height 5), owner reassigns (height 6) → epoch 1
    // snapshot excludes the slashed archive; survivor becomes the assignee.
    slash_node(&state, &executor, assignee0, 5);
    let re = executor.execute_tx(&signed(&owner, FEE, 2, sm_v2(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })), &KeyPair::generate().address(), 6, 1000).unwrap();
    assert!(re.status.is_success(), "reassign: {:?}", re.status);
    assert_eq!(storage.get_file_reassignments(&root).unwrap(), vec![6], "epoch 1 recorded");

    let emitted = storage.generate_challenge_schedule(&Hash::hash(b"parent"), 100, &registry, r, 8, 4, 16).unwrap();
    assert_eq!(emitted.len(), 1, "the surviving archive is assigned-active in the latest epoch");
    assert_eq!(emitted[0].target_node.as_bytes(), survivor.address().as_bytes(), "target comes from the latest (reassignment) epoch");
    assert_ne!(emitted[0].target_node.as_bytes(), assignee0.as_bytes(), "slashed epoch-0 assignee never targeted");
}

// ── Gate closed preserves post-#101 behavior ─────────────────────────────────

#[test]
fn gate_closed_uses_single_challenge_path() {
    // Scheduler dormant, Phase-1 targeting on: the block path must produce the
    // single #97 challenge, and the scheduler helper is simply never invoked.
    let mut p = ChainParams::with_v2_enabled();
    p.por_assignment_targeting_enabled_from_height = Some(0);
    p.assignment_replication_factor = 1;
    let (state, db, _dir, executor) = setup_with_params(p);
    let (archives, mut nonces) = register_archives(&state, &executor, 2);
    let root = Hash::hash(b"single-file");
    make_active_funded_file(&state, &executor, &db, &archives, &mut nonces, 1, root, 1, SMALL_DEPOSIT);

    let (storage, registry) = executors(&db);
    // Single-challenge path still selects the funded+Active V2 file via #101.
    let active = registry.get_active_archive_nodes().unwrap();
    let ch = storage.generate_challenge(&Hash::hash(b"p"), 100, &active, &registry, true, 1).unwrap();
    assert!(ch.is_some(), "post-#101 single challenge still works with scheduler dormant");
    assert_eq!(ch.unwrap().merkle_root, root);
}
