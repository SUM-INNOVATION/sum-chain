//! Issue #97 (Phase 1) — assignment-aware PoR challenge targeting.
//!
//! Below `por_assignment_targeting_enabled_from_height` the challenge picks a
//! file from the legacy V1 funded set and a target from all active archives
//! (byte-identical legacy behavior). At/above the gate the file is sampled from
//! the V2 funded+Active candidates and the target is drawn only from the
//! archives assigned to the challenged chunk (under the file's latest assignment
//! epoch snapshot) that are currently Active; an empty assigned-active set skips
//! the challenge, so a bystander is never challenged or slashed.
//!
//! Tests drive real state through the `BlockExecutor`, then call the public
//! `StorageMetadataExecutor::generate_challenge` against the shared DB for
//! precise, deterministic assertions.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    assigned_archives_presorted, Address, Hash, NodeRecord, NodeRegistryOperation,
    NodeRegistryTxData, NodeRole, NodeStatus, SignedTransaction, StorageMetadataOperation,
    StorageMetadataOperationV2, StorageMetadataTxData, StorageMetadataV2TxData, TransactionV2,
    TxPayload,
};
use sumchain_state::executor::BlockExecutor;
use sumchain_state::storage_metadata::StorageMetadataExecutor;
use sumchain_state::{NodeRegistryExecutor, StateManager};
use sumchain_storage::Database;

const STAKE: u64 = 1_000_000_000;
const FEE: u128 = 1_000;
const FEE_DEPOSIT: u64 = 1_000_000;

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// v2 on, assignment-aware targeting gate open from genesis, replication `r`.
fn params_targeting(r: u32) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.por_assignment_targeting_enabled_from_height = Some(0);
    p.assignment_replication_factor = r;
    p
}

/// As `params_targeting`, plus the #62 reassignment gate open.
fn params_targeting_reassign(r: u32) -> ChainParams {
    let mut p = params_targeting(r);
    p.archive_reassignment_enabled_from_height = Some(0);
    p
}

/// v2 on, targeting gate DORMANT (default None), replication `r`.
fn params_legacy(r: u32) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.assignment_replication_factor = r;
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

/// Funded V2 registration: one 1000-byte file ⇒ 1 chunk, `fee_deposit > 0`.
fn v2_register_op(root: Hash) -> StorageMetadataOperationV2 {
    StorageMetadataOperationV2::RegisterFilePendingV2 {
        merkle_root: root,
        plaintext_size_bytes: 500,
        stored_size_bytes: 1000,
        chunk_count: 1,
        fee_deposit: FEE_DEPOSIT,
        visibility: 0,
        initial_access: vec![],
    }
}

/// Legacy V1 funded registration (challenge-eligible under the dormant gate).
fn v1_register_op(root: Hash) -> StorageMetadataOperation {
    StorageMetadataOperation::RegisterFile {
        merkle_root: root,
        total_size_bytes: 1000,
        access_list: vec![],
        fee_deposit: FEE_DEPOSIT,
    }
}

// ── Test helpers ─────────────────────────────────────────────────────────────

fn sorted_addrs(nodes: &[NodeRecord]) -> Vec<Address> {
    let mut v: Vec<Address> = nodes.iter().map(|n| n.address).collect();
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    v.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    v
}

fn challenge_seed(parent: &Hash, height: u64) -> [u8; 32] {
    let seed = Hash::hash_many(&[parent.as_bytes(), b"storage_challenge", &height.to_be_bytes()]);
    *seed.as_bytes()
}

fn seed_u64(seed: &[u8], from: usize) -> u64 {
    u64::from_be_bytes(seed[from..from + 8].try_into().unwrap())
}

fn executors(db: &Arc<Database>) -> (StorageMetadataExecutor, NodeRegistryExecutor) {
    (StorageMetadataExecutor::new(db.clone()), NodeRegistryExecutor::new(db.clone()))
}

/// Assigned set for chunk 0 of `root` under `snapshot`, replication `r`.
fn assigned_chunk0(root: &Hash, snapshot: &[NodeRecord], r: u32) -> Vec<Address> {
    assigned_archives_presorted(root, &sorted_addrs(snapshot), 0, r)
}

/// Independently compute the assignment-aware target for a single-chunk file:
/// the deterministic pick from the chunk's assigned set (under `epoch_snapshot`)
/// filtered to `currently_active`. `None` ⇒ skip.
fn expected_target(
    root: &Hash,
    epoch_snapshot: &[NodeRecord],
    currently_active: &[Address],
    parent: &Hash,
    height: u64,
    r: u32,
) -> Option<Address> {
    let seed = challenge_seed(parent, height);
    let assigned_active: Vec<Address> = assigned_chunk0(root, epoch_snapshot, r)
        .into_iter()
        .filter(|a| currently_active.iter().any(|c| c.as_bytes() == a.as_bytes()))
        .collect();
    if assigned_active.is_empty() {
        return None;
    }
    let idx = seed_u64(&seed, 12) % assigned_active.len() as u64;
    Some(assigned_active[idx as usize])
}

/// Register `k` archives (height 1), register a funded V2 file for `root`
/// (height 2, assignment_height = 2), accept chunk 0 from one assigned archive
/// (height 3), and activate (height 4) → funded + Active. Returns the archive
/// keypairs and the owner keypair (owner nonce is at 2 afterwards).
fn setup_v2_active_funded(
    state: &StateManager,
    executor: &BlockExecutor,
    db: &Arc<Database>,
    root: Hash,
    k: usize,
    r: u32,
) -> (Vec<KeyPair>, KeyPair) {
    let proposer = KeyPair::generate();
    let owner = KeyPair::generate();
    fund(state, &owner, (FEE_DEPOSIT as u128) + 2_000_000);

    let archives: Vec<KeyPair> = (0..k).map(|_| KeyPair::generate()).collect();
    for a in &archives {
        fund(state, a, (STAKE as u128) + 1_000_000);
        executor
            .execute_tx(&signed(a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000)
            .unwrap();
    }
    let rv = executor
        .execute_tx(&signed(&owner, FEE, 0, sm_v2(v2_register_op(root))), &proposer.address(), 2, 1000)
        .unwrap();
    assert!(rv.status.is_success(), "v2 register: {:?}", rv.status);

    // Accept chunk 0 from one assigned archive, then activate.
    let registry = NodeRegistryExecutor::new(db.clone());
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assignee = assigned_chunk0(&root, &snapshot, r)[0];
    let assignee_kp = archives.iter().find(|kp| kp.address().as_bytes() == assignee.as_bytes()).unwrap();
    let acc = executor
        .execute_tx(
            &signed(assignee_kp, FEE, 1, sm_v2(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: root, chunk_indices: vec![0] })),
            &proposer.address(), 3, 1000,
        )
        .unwrap();
    assert!(acc.status.is_success(), "accept: {:?}", acc.status);
    let act = executor
        .execute_tx(
            &signed(&owner, FEE, 1, sm_v2(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: root })),
            &proposer.address(), 4, 1000,
        )
        .unwrap();
    assert!(act.status.is_success(), "activate: {:?}", act.status);

    (archives, owner)
}

// ── Gate default ─────────────────────────────────────────────────────────────

#[test]
fn defaults_leave_targeting_dormant() {
    assert_eq!(ChainParams::default().por_assignment_targeting_enabled_from_height, None);
}

// ── V1 legacy path: get_funded_file_roots guard + gate-closed target ──────────

#[test]
fn v1_get_funded_file_roots_ignores_non_f_keys() {
    // Registering a V1 file writes both the `F`-row and an `O`-owner-index key
    // into the same CF. The funded scan must return only the file root and must
    // not choke decoding the owner-index marker value (issue #97 guard).
    let (state, db, _dir, executor) = setup_with_params(params_legacy(1));
    let proposer = KeyPair::generate();
    let owner = KeyPair::generate();
    fund(&state, &owner, (FEE_DEPOSIT as u128) + 1_000_000);
    let root = Hash::hash(b"v1-guard-file");
    executor
        .execute_tx(&signed(&owner, FEE, 0, sm_v1(v1_register_op(root))), &proposer.address(), 2, 1000)
        .unwrap();

    let (storage, _registry) = executors(&db);
    let roots = storage.get_funded_file_roots().unwrap();
    assert_eq!(roots, vec![root], "only the funded V1 root, owner-index keys ignored");
}

#[test]
fn gate_closed_targets_legacy_global_set() {
    // Gate dormant ⇒ V1 file source + target drawn from ALL active archives.
    let (state, db, _dir, executor) = setup_with_params(params_legacy(2));
    let proposer = KeyPair::generate();
    let owner = KeyPair::generate();
    fund(&state, &owner, (FEE_DEPOSIT as u128) + 1_000_000);
    let archives: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate()).collect();
    for a in &archives {
        fund(&state, a, (STAKE as u128) + 1_000_000);
        executor.execute_tx(&signed(a, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();
    }
    let root = Hash::hash(b"legacy-file");
    executor.execute_tx(&signed(&owner, FEE, 0, sm_v1(v1_register_op(root))), &proposer.address(), 2, 1000).unwrap();

    let (storage, registry) = executors(&db);
    let active = registry.get_active_archive_nodes().unwrap();
    let parent = Hash::hash(b"parent-legacy");
    let height = 10;
    let seed = challenge_seed(&parent, height);
    let legacy_target = active[(seed_u64(&seed, 12) % active.len() as u64) as usize].address;

    let ch = storage
        .generate_challenge(&parent, height, &active, &registry, /* assignment_targeting */ false, 2)
        .unwrap()
        .expect("legacy challenge generated");
    assert_eq!(ch.merkle_root, root, "gate closed must select the V1 funded file");
    assert_eq!(ch.target_node, legacy_target, "gate closed must match legacy global target");
}

// ── Gate open uses V2 funded+Active files, not V1 ────────────────────────────

#[test]
fn gate_open_uses_v2_not_v1_files() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting(r));
    let root_v2 = Hash::hash(b"v2-active-file");
    let (_archives, owner) = setup_v2_active_funded(&state, &executor, &db, root_v2, 2, r);

    // Also register a separate V1 funded file — it must never be selected.
    let root_v1 = Hash::hash(b"v1-decoy-file");
    executor
        .execute_tx(&signed(&owner, FEE, 2, sm_v1(v1_register_op(root_v1))), &KeyPair::generate().address(), 5, 1000)
        .unwrap();

    let (storage, registry) = executors(&db);
    let active = registry.get_active_archive_nodes().unwrap();
    for i in 0..15u64 {
        let parent = Hash::hash(format!("p{i}").as_bytes());
        let ch = storage.generate_challenge(&parent, 20 + i, &active, &registry, true, r).unwrap().expect("challenge");
        assert_eq!(ch.merkle_root, root_v2, "gate open must select the V2 file, never the V1 decoy (seed {i})");
        storage.delete_challenge(&ch).unwrap();
    }
}

#[test]
fn gate_open_excludes_pending_and_unfunded_v2() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting(r));
    let proposer = KeyPair::generate();
    let owner = KeyPair::generate();
    let archive = KeyPair::generate();
    fund(&state, &owner, (FEE_DEPOSIT as u128) + 2_000_000);
    fund(&state, &archive, (STAKE as u128) + 1_000_000);
    executor.execute_tx(&signed(&archive, FEE, 0, nr(register_archive_op())), &proposer.address(), 1, 1000).unwrap();

    // (a) Funded but PENDING (never activated) ⇒ excluded.
    let pending = Hash::hash(b"pending-file");
    executor.execute_tx(&signed(&owner, FEE, 0, sm_v2(v2_register_op(pending))), &proposer.address(), 2, 1000).unwrap();

    // (b) Active but UNFUNDED (fee_deposit 0) ⇒ excluded. Register, accept, activate.
    let unfunded = Hash::hash(b"unfunded-file");
    let op = StorageMetadataOperationV2::RegisterFilePendingV2 {
        merkle_root: unfunded, plaintext_size_bytes: 500, stored_size_bytes: 1000,
        chunk_count: 1, fee_deposit: 0, visibility: 0, initial_access: vec![],
    };
    executor.execute_tx(&signed(&owner, FEE, 1, sm_v2(op)), &proposer.address(), 2, 1000).unwrap();
    executor.execute_tx(&signed(&archive, FEE, 1, sm_v2(StorageMetadataOperationV2::AcceptAssignmentV2 { merkle_root: unfunded, chunk_indices: vec![0] })), &proposer.address(), 3, 1000).unwrap();
    executor.execute_tx(&signed(&owner, FEE, 2, sm_v2(StorageMetadataOperationV2::ActivateFileV2 { merkle_root: unfunded })), &proposer.address(), 4, 1000).unwrap();

    let (storage, registry) = executors(&db);
    assert!(storage.funded_active_v2_candidates().unwrap().is_empty(), "pending + unfunded files must be excluded");
    let active = registry.get_active_archive_nodes().unwrap();
    let out = storage.generate_challenge(&Hash::hash(b"p"), 30, &active, &registry, true, r).unwrap();
    assert!(out.is_none(), "no funded+Active V2 candidate ⇒ skip");
}

// ── Gate open: target assigned + deterministic + conformance vector ──────────

#[test]
fn gate_open_target_is_assigned_and_deterministic() {
    let r = 2u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting(r));
    let root = Hash::hash(b"assigned-file");
    setup_v2_active_funded(&state, &executor, &db, root, 4, r);

    let (storage, registry) = executors(&db);
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let active_now: Vec<Address> = registry.get_active_archive_nodes().unwrap().iter().map(|n| n.address).collect();
    let assigned = assigned_chunk0(&root, &snapshot, r);
    let parent = Hash::hash(b"parent-assigned");
    let height = 40;
    let expected = expected_target(&root, &snapshot, &active_now, &parent, height, r).expect("assigned-active");

    let active = registry.get_active_archive_nodes().unwrap();
    let ch = storage.generate_challenge(&parent, height, &active, &registry, true, r).unwrap().expect("challenge");
    assert_eq!(ch.merkle_root, root);
    assert_eq!(ch.target_node, expected, "conformance vector: exact deterministic assigned pick");
    assert!(assigned.iter().any(|a| a.as_bytes() == ch.target_node.as_bytes()), "target must be assigned to the chunk");

    // Replay on a fresh executor over the same DB ⇒ identical target.
    let (storage2, registry2) = executors(&db);
    storage2.delete_challenge(&ch).unwrap();
    let ch2 = storage2.generate_challenge(&parent, height, &active, &registry2, true, r).unwrap().expect("replay");
    assert_eq!(ch2.target_node, ch.target_node, "target selection must be replayable");
}

#[test]
fn gate_open_unassigned_active_never_targeted() {
    // R=1 with 4 archives ⇒ one assignee; the other three are active but
    // unassigned and must never be selected, for any seed.
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting(r));
    let root = Hash::hash(b"unassigned-file");
    setup_v2_active_funded(&state, &executor, &db, root, 4, r);

    let (storage, registry) = executors(&db);
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assigned = assigned_chunk0(&root, &snapshot, r);
    assert_eq!(assigned.len(), 1, "R=1 ⇒ single assignee");
    let assignee = assigned[0];
    let active = registry.get_active_archive_nodes().unwrap();

    for i in 0..25u64 {
        let parent = Hash::hash(format!("seed-{i}").as_bytes());
        let ch = storage.generate_challenge(&parent, 50 + i, &active, &registry, true, r).unwrap().expect("challenge");
        assert_eq!(ch.target_node.as_bytes(), assignee.as_bytes(), "only the assignee may be targeted (seed {i})");
        storage.delete_challenge(&ch).unwrap();
    }
}

#[test]
fn gate_open_no_assigned_active_skips_without_slash() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting(r));
    let root = Hash::hash(b"skip-file");
    let (archives, owner) = setup_v2_active_funded(&state, &executor, &db, root, 2, r);

    let (storage, registry) = executors(&db);
    let snapshot = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assignee = assigned_chunk0(&root, &snapshot, r)[0];
    let assignee_kp = archives.iter().find(|k| k.address().as_bytes() == assignee.as_bytes()).unwrap();
    let bal_before = state.get_balance(&assignee).unwrap();

    // Slash the sole assignee ⇒ assigned-active set becomes empty.
    let _ = assignee_kp;
    let sl = executor
        .execute_tx(&signed(&owner, FEE, 2, nr(NodeRegistryOperation::UpdateStatus { target: assignee, new_status: NodeStatus::Slashed })), &KeyPair::generate().address(), 5, 1000)
        .unwrap();
    assert!(sl.status.is_success(), "slash: {:?}", sl.status);

    let active = registry.get_active_archive_nodes().unwrap();
    let out = storage.generate_challenge(&Hash::hash(b"parent-skip"), 60, &active, &registry, true, r).unwrap();
    assert!(out.is_none(), "no assigned-active archive ⇒ skip");
    assert!(storage.get_challenges_by_node(&assignee).unwrap().is_empty(), "no challenge written");
    assert_eq!(registry.get_node(&assignee).unwrap().unwrap().status, NodeStatus::Slashed);
    assert_eq!(state.get_balance(&assignee).unwrap(), bal_before, "skipped challenge must not move funds");
}

// ── Gate open: reassignment epoch changes the target set (latest epoch used) ──

#[test]
fn gate_open_reassignment_uses_latest_epoch_target_set() {
    let r = 1u32;
    let (state, db, _dir, executor) = setup_with_params(params_targeting_reassign(r));
    let root = Hash::hash(b"reassign-file");
    let (archives, owner) = setup_v2_active_funded(&state, &executor, &db, root, 2, r);

    let (storage, registry) = executors(&db);
    let snap0 = registry.get_active_archive_nodes_at_height(2).unwrap();
    let assignee0 = assigned_chunk0(&root, &snap0, r)[0];
    let assignee_kp = archives.iter().find(|k| k.address().as_bytes() == assignee0.as_bytes()).unwrap();
    let survivor_kp = archives.iter().find(|k| k.address().as_bytes() != assignee0.as_bytes()).unwrap();

    // Epoch-0 assignee leaves at height 5; owner reassigns at height 6 (epoch 1).
    executor.execute_tx(&signed(&owner, FEE, 2, nr(NodeRegistryOperation::UpdateStatus { target: assignee0, new_status: NodeStatus::Slashed })), &KeyPair::generate().address(), 5, 1000).unwrap();
    let re = executor.execute_tx(&signed(&owner, FEE, 3, sm_v2(StorageMetadataOperationV2::ReassignChunksV2 { merkle_root: root })), &KeyPair::generate().address(), 6, 1000).unwrap();
    assert!(re.status.is_success(), "reassign: {:?}", re.status);
    assert_eq!(storage.get_file_reassignments(&root).unwrap(), vec![6], "epoch 1 recorded");

    let active = registry.get_active_archive_nodes().unwrap();
    let ch = storage.generate_challenge(&Hash::hash(b"parent-reassign"), 70, &active, &registry, true, r).unwrap().expect("challenge");
    assert_eq!(ch.target_node.as_bytes(), survivor_kp.address().as_bytes(), "target must come from the latest (reassignment) epoch's assigned-active set");
    assert_ne!(ch.target_node.as_bytes(), assignee_kp.address().as_bytes(), "the slashed epoch-0 assignee must never be targeted");
}
