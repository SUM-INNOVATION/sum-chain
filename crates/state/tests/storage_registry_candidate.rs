//! The storage-metadata and node-registry subsystems read and write the block's
//! candidate.
//!
//! These two migrated together, and could not have migrated separately. The
//! dependency runs one way statically — storage-metadata reads the node registry
//! at eight sites; the registry never reads storage — but the *write* ordering
//! inside a single block runs both ways:
//!
//! * `process_expired_challenges` slashes archives and rewrites the
//!   active-archive snapshot BEFORE the transaction loop, and the storage
//!   transactions in that loop resolve their assignment set from that snapshot.
//! * `RegisterArchiveNode` and `BeginUnstake` rewrite the snapshot INSIDE the
//!   loop, and later storage transactions in the same block read it.
//!
//! Migrate one side alone and the other reads committed state: one node computes
//! an assignment set from the parent's archives while every other node computes
//! it from this block's. That is a consensus split, not a latent bug, which is
//! why there was no "strict order" option here.
//!
//! What this file pins: the cross-subsystem ordering in both directions, the
//! index and mirror writes that must move with their primary row, the
//! read-modify-write on the attestation bitmap, candidate isolation, and the
//! census totals the supply correction depends on.

mod common;

use std::sync::Arc;

use sumchain_genesis::ChainParams;
use sumchain_primitives::supply::GENESIS_ACCOUNTED_SUPPLY;
use sumchain_primitives::{
    Address, ArchiveUnbondingRecord, Hash, NodeRecord, NodeRegistryOperation, NodeRegistryTxData,
    NodeRole, NodeStatus, StorageChallenge, StorageMetadataOperationV2, StorageMetadataV2TxData,
};
use sumchain_state::node_registry::NodeRegistryExecutor;
use sumchain_state::state::StateManager;
use sumchain_state::storage_metadata::StorageMetadataExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::Database;

const LIMIT: u64 = 1 << 20;
const STAKE: u64 = 1_000_000_000;
const CHUNKS: u32 = 1;
const STORED: u64 = 1_048_576; // exactly CHUNKS × 1 MiB

fn open_db() -> (tempfile::TempDir, Arc<Database>, Arc<StateManager>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    let state = Arc::new(StateManager::new(db.clone(), 1));
    (dir, db, state)
}

fn params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.assignment_replication_factor = 1;
    p
}

fn fund(state: &StateManager, addr: &Address, balance: u128) {
    state
        .put_account(
            addr,
            &sumchain_storage::schema::AccountState { balance, nonce: 0 },
        )
        .unwrap();
}

fn archive(tag: u8, status: NodeStatus) -> NodeRecord {
    NodeRecord {
        address: Address::new([tag; 20]),
        role: NodeRole::ArchiveNode,
        staked_balance: STAKE,
        status,
        registered_at: 1,
    }
}

fn register_op() -> NodeRegistryTxData {
    NodeRegistryTxData {
        operation: NodeRegistryOperation::Register {
            role: NodeRole::ArchiveNode,
            stake: STAKE,
        },
    }
}

fn update_status_op(target: Address, new_status: NodeStatus) -> NodeRegistryTxData {
    NodeRegistryTxData {
        operation: NodeRegistryOperation::UpdateStatus { target, new_status },
    }
}

fn register_file_op(root: Hash) -> StorageMetadataV2TxData {
    StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::RegisterFilePendingV2 {
            merkle_root: root,
            plaintext_size_bytes: 500,
            stored_size_bytes: STORED,
            chunk_count: CHUNKS,
            fee_deposit: 0,
            visibility: 0,
            initial_access: vec![],
        },
    }
}

fn accept_op(root: Hash) -> StorageMetadataV2TxData {
    StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::AcceptAssignmentV2 {
            merkle_root: root,
            chunk_indices: vec![0],
        },
    }
}

fn challenge(tag: u8, target: Address, expires: u64) -> StorageChallenge {
    StorageChallenge {
        challenge_id: Hash::hash(&[tag]),
        merkle_root: Hash::hash(b"challenged-file"),
        chunk_index: 0,
        target_node: target,
        created_at_height: 1,
        expires_at_height: expires,
    }
}

// ── Cross-subsystem ordering, both directions ────────────────────────────────

/// An archive that registers earlier in the block can attest later in it.
///
/// This is the `RegisterArchiveNode` → `AcceptAssignmentV2` direction. The
/// attestation resolves its assignment snapshot through
/// `v_get_active_archive_nodes_at_height`, which walks back to the snapshot the
/// registration wrote moments earlier — in this same candidate. Read committed
/// and that snapshot does not exist, the assignment set is empty, and the
/// attestation is rejected as "signer not in the target epoch's assignment
/// snapshot".
#[test]
fn an_archive_registered_earlier_in_the_block_can_attest_later_in_it() {
    let (_dir, db, state) = open_db();
    let p = params();
    let a = Address::new([0xA1; 20]);
    let owner = Address::new([0x0E; 20]);
    fund(&state, &a, (STAKE as u128) + 1_000);
    fund(&state, &owner, 1_000);
    let root = Hash::hash(b"same-block-register-then-attest");

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert!(
        NodeRegistryExecutor::execute(
            &mut view,
            &a,
            &register_op(),
            &state,
            &Address::ZERO,
            0,
            1,
            1000,
        )
        .unwrap()
        .success,
        "registration must succeed"
    );
    assert!(
        StorageMetadataExecutor::execute_v2(
            &mut view,
            &owner,
            &register_file_op(root),
            &state,
            &Address::ZERO,
            0,
            1,
            1000,
            &p,
        )
        .unwrap()
        .success,
        "file registration must succeed"
    );

    let accepted = StorageMetadataExecutor::execute_v2(
        &mut view,
        &a,
        &accept_op(root),
        &state,
        &Address::ZERO,
        0,
        1,
        1000,
        &p,
    )
    .unwrap();
    assert!(
        accepted.success,
        "an archive registered in this block must be in this block's assignment \
         snapshot: {:?}",
        accepted.error
    );
}

/// An archive slashed earlier in the block cannot attest later in it.
///
/// This is the `process_expired_challenges` → storage-transaction direction,
/// reduced to its decisive step. The slash rewrites the node row and the
/// active-archive snapshot; the attestation's `signer is not currently Active`
/// check reads that row. Committed, the archive is still Active and the
/// attestation is accepted — the block would credit coverage to an archive it
/// just slashed, and disagree with every node that applied the slash first.
#[test]
fn an_archive_slashed_earlier_in_the_block_cannot_attest_later_in_it() {
    let (_dir, db, state) = open_db();
    let p = params();
    let a = Address::new([0xA1; 20]);
    let owner = Address::new([0x0E; 20]);
    fund(&state, &a, (STAKE as u128) + 1_000);
    fund(&state, &owner, 1_000);
    let root = Hash::hash(b"same-block-slash-then-attest");

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    NodeRegistryExecutor::execute(
        &mut view, &a, &register_op(), &state, &Address::ZERO, 0, 1, 1000,
    )
    .unwrap();
    StorageMetadataExecutor::execute_v2(
        &mut view,
        &owner,
        &register_file_op(root),
        &state,
        &Address::ZERO,
        0,
        1,
        1000,
        &p,
    )
    .unwrap();

    // The slash — what an expired challenge does, before the transaction loop.
    assert!(
        NodeRegistryExecutor::execute(
            &mut view,
            &Address::ZERO,
            &update_status_op(a, NodeStatus::Slashed),
            &state,
            &Address::ZERO,
            0,
            1,
            1000,
        )
        .unwrap()
        .success
    );

    let accepted = StorageMetadataExecutor::execute_v2(
        &mut view,
        &a,
        &accept_op(root),
        &state,
        &Address::ZERO,
        0,
        1,
        1000,
        &p,
    )
    .unwrap();
    assert!(
        !accepted.success,
        "a slashed archive must not be able to attest in the block that slashed it"
    );
    assert_eq!(accepted.failure_code, Some(33));
}

/// The snapshot a block writes reflects the slashes that block applied.
///
/// `v_write_active_archive_snapshot` captures `v_get_active_archive_nodes`,
/// which walks the role index and reads each row. Both halves have to see the
/// candidate: a committed scan would snapshot the archive set as the PARENT left
/// it and hand that set to every assignment computed for the rest of the block.
#[test]
fn the_snapshot_a_block_writes_excludes_an_archive_it_slashed() {
    let (_dir, db, _state) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let a = archive(0xA1, NodeStatus::Active);
    let b = archive(0xB2, NodeStatus::Active);
    NodeRegistryExecutor::v_put_node(&mut view, &a).unwrap();
    NodeRegistryExecutor::v_put_node(&mut view, &b).unwrap();
    NodeRegistryExecutor::v_write_active_archive_snapshot(&mut view, 7).unwrap();

    let before = NodeRegistryExecutor::v_get_active_archive_nodes_at_height(&view, 7).unwrap();
    assert_eq!(before.len(), 2, "both archives are active at the snapshot");

    // Slash A later in the SAME block and re-snapshot, as the slash pass does.
    NodeRegistryExecutor::v_put_node(&mut view, &archive(0xA1, NodeStatus::Slashed)).unwrap();
    NodeRegistryExecutor::v_write_active_archive_snapshot(&mut view, 7).unwrap();

    let after = NodeRegistryExecutor::v_get_active_archive_nodes_at_height(&view, 7).unwrap();
    assert_eq!(after.len(), 1, "the slashed archive must leave the snapshot");
    assert_eq!(after[0].address, b.address);

    // Nothing published.
    drop(overlay);
    let committed = NodeRegistryExecutor::new(db.clone());
    assert!(committed.get_active_archive_nodes_at_height(7).unwrap().is_empty());
}

// ── Index and mirror writes move with their primary row ──────────────────────

/// A node row and its role-index mirror are staged together.
///
/// `v_get_nodes_by_role` — and therefore the whole active-archive set, and
/// therefore every assignment — walks the role index. A candidate holding the
/// row without the index computes a smaller archive set than the one it
/// publishes.
#[test]
fn staging_a_node_carries_its_role_index_with_it() {
    let (_dir, db, _state) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let a = archive(0xA1, NodeStatus::Active);
    NodeRegistryExecutor::v_put_node(&mut view, &a).unwrap();

    assert!(NodeRegistryExecutor::v_get_node(&view, &a.address).unwrap().is_some());
    let by_role = NodeRegistryExecutor::v_get_nodes_by_role(&view, NodeRole::ArchiveNode).unwrap();
    assert_eq!(
        by_role.len(),
        1,
        "the role index must see a node staged in this block"
    );
    assert_eq!(by_role[0].address, a.address);
}

/// A challenge and BOTH of its indexes are staged together, and deleted together.
///
/// The node index is the `BeginUnstake` gate — an archive must not be able to
/// unbond out of a challenge issued moments earlier in the same block — and the
/// expiry index is what the next block's slash pass walks. A primary row without
/// them is a challenge nothing can find.
#[test]
fn staging_a_challenge_carries_both_indexes_with_it() {
    let (_dir, db, _state) = open_db();
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let target = Address::new([0xA1; 20]);
    let ch = challenge(1, target, 50);
    StorageMetadataExecutor::v_put_challenge(&mut view, &ch).unwrap();

    assert!(StorageMetadataExecutor::v_get_challenge(&view, &ch.challenge_id)
        .unwrap()
        .is_some());
    assert_eq!(
        StorageMetadataExecutor::v_get_challenges_by_node(&view, &target)
            .unwrap()
            .len(),
        1,
        "the node index must see a challenge staged in this block"
    );
    assert_eq!(
        StorageMetadataExecutor::v_get_expired_challenges(&view, 50)
            .unwrap()
            .len(),
        1,
        "the expiry index must see it too"
    );

    StorageMetadataExecutor::v_delete_challenge(&mut view, &ch).unwrap();
    assert!(StorageMetadataExecutor::v_get_challenge(&view, &ch.challenge_id)
        .unwrap()
        .is_none());
    assert!(StorageMetadataExecutor::v_get_challenges_by_node(&view, &target)
        .unwrap()
        .is_empty());
    assert!(StorageMetadataExecutor::v_get_expired_challenges(&view, 50)
        .unwrap()
        .is_empty());
}

/// A file row and its owner index are staged together, so the funded-file scan
/// a challenge is drawn from sees a file this block registered.
#[test]
fn a_file_funded_in_this_block_is_challengeable_in_it() {
    let (_dir, db, state) = open_db();
    let p = params();
    let owner = Address::new([0x0E; 20]);
    fund(&state, &owner, 10_000);
    let root = Hash::hash(b"funded-in-this-block");

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    assert!(StorageMetadataExecutor::execute_v2(
        &mut view,
        &owner,
        &StorageMetadataV2TxData {
            operation: StorageMetadataOperationV2::RegisterFilePendingV2 {
                merkle_root: root,
                plaintext_size_bytes: 500,
                stored_size_bytes: STORED,
                chunk_count: CHUNKS,
                fee_deposit: 5_000,
                visibility: 0,
                initial_access: vec![],
            },
        },
        &state,
        &Address::ZERO,
        0,
        2,
        1000,
        &p,
    )
    .unwrap()
    .success);

    let row = StorageMetadataExecutor::v_get_metadata_v2(&view, &root)
        .unwrap()
        .expect("row staged in this block");
    assert_eq!(row.fee_pool, 5_000);
    assert_eq!(row.assignment_height, 2);

    // Committed storage has neither the row nor the fee pool it holds.
    drop(overlay);
    assert!(StorageMetadataExecutor::new(db.clone())
        .get_metadata_v2(&root)
        .unwrap()
        .is_none());
}

// ── The attestation bitmap is a read-modify-write ────────────────────────────

/// Two accepts in one block OR into one bitmap.
///
/// `execute_accept_assignment_v2` reads the existing bitmap, sets bits, and
/// writes it back — through a column-family binding chosen at runtime between
/// the epoch-0 and reassignment-epoch CFs, which is why no name-based check can
/// see this write. If the read went to committed storage the second accept would
/// start from the parent's bitmap and silently erase the first accept's bits.
#[test]
fn two_accepts_in_one_block_or_into_the_same_bitmap() {
    let (_dir, db, state) = open_db();
    let mut p = params();
    p.assignment_replication_factor = 1;
    let owner = Address::new([0x0E; 20]);
    let root = Hash::hash(b"two-accepts");
    fund(&state, &owner, 10_000);

    // Four chunks so one archive can attest two disjoint index sets.
    const N: u32 = 4;
    let register = StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::RegisterFilePendingV2 {
            merkle_root: root,
            plaintext_size_bytes: 500,
            stored_size_bytes: (N as u64) * 1_048_576,
            chunk_count: N,
            fee_deposit: 0,
            visibility: 0,
            initial_access: vec![],
        },
    };

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    // One archive, so replication factor 1 assigns every chunk to it.
    let a = Address::new([0xA1; 20]);
    fund(&state, &a, (STAKE as u128) + 1_000);
    NodeRegistryExecutor::execute(
        &mut view, &a, &register_op(), &state, &Address::ZERO, 0, 1, 1000,
    )
    .unwrap();
    assert!(StorageMetadataExecutor::execute_v2(
        &mut view, &owner, &register, &state, &Address::ZERO, 0, 1, 1000, &p,
    )
    .unwrap()
    .success);

    let accept = |indices: Vec<u32>| StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::AcceptAssignmentV2 {
            merkle_root: root,
            chunk_indices: indices,
        },
    };
    for set in [vec![0, 1], vec![2, 3]] {
        let r = StorageMetadataExecutor::execute_v2(
            &mut view,
            &a,
            &accept(set.clone()),
            &state,
            &Address::ZERO,
            0,
            1,
            1000,
            &p,
        )
        .unwrap();
        assert!(r.success, "accept {:?} failed: {:?}", set, r.error);
    }

    let bitmap = StorageMetadataExecutor::v_get_attestation_bitmap_v2(&view, &root, &a)
        .unwrap()
        .expect("bitmap staged");
    let popcount: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
    assert_eq!(
        popcount, N,
        "the second accept must OR into the bitmap the first one staged, not \
         start from the parent's"
    );
}

// ── Candidate isolation ──────────────────────────────────────────────────────

/// A dropped candidate leaves both subsystems byte-identical.
///
/// Twenty-two writes moved in this cluster, across twelve column families. A
/// block that is abandoned must leave every one of them untouched — the file
/// rows and their owner indexes, the challenges and both of their indexes, the
/// node rows and their role index, the unbonding records, the encryption keys,
/// the archive snapshots and the challengeable index.
#[test]
fn a_dropped_candidate_leaves_storage_and_registry_untouched() {
    let (_dir, db, state) = open_db();
    let p = params();
    let a = Address::new([0xA1; 20]);
    let owner = Address::new([0x0E; 20]);
    fund(&state, &a, (STAKE as u128) + 1_000);
    fund(&state, &owner, 10_000);
    let root = Hash::hash(b"dropped");

    {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let mut view = ExecutionView::new(&mut overlay);
        NodeRegistryExecutor::execute(
            &mut view, &a, &register_op(), &state, &Address::ZERO, 0, 1, 1000,
        )
        .unwrap();
        StorageMetadataExecutor::execute_v2(
            &mut view,
            &owner,
            &register_file_op(root),
            &state,
            &Address::ZERO,
            0,
            1,
            1000,
            &p,
        )
        .unwrap();
        StorageMetadataExecutor::v_put_challenge(&mut view, &challenge(9, a, 50)).unwrap();
        NodeRegistryExecutor::v_put_archive_unbonding(
            &mut view,
            &ArchiveUnbondingRecord {
                operator: a,
                amount: STAKE,
                started_height: 1,
                unlock_height: 100,
                remaining_amount: STAKE,
            },
        )
        .unwrap();
        // The candidate is dropped here without being accepted or published.
    }

    let registry = NodeRegistryExecutor::new(db.clone());
    let storage = StorageMetadataExecutor::new(db.clone());
    assert!(registry.get_node(&a).unwrap().is_none());
    assert!(registry.get_archive_unbonding(&a).unwrap().is_none());
    assert!(registry.get_active_archive_nodes().unwrap().is_empty());
    assert!(registry
        .get_active_archive_nodes_at_height(1)
        .unwrap()
        .is_empty());
    assert!(storage.get_metadata_v2(&root).unwrap().is_none());
    assert!(storage.get_challenges_by_node(&a).unwrap().is_empty());
    assert_eq!(registry.total_archive_staked_balance().unwrap(), 0);
    assert_eq!(storage.total_fee_pools().unwrap(), (0, 0));
}

// ── The census the supply correction runs on ─────────────────────────────────

/// A same-block archive-stake or fee-pool change moves the correction's reserve
/// delta by exactly that amount.
///
/// Archive stake and the storage V1+V2 fee pools are INCLUDE buckets of the
/// native-supply census, and the delta minted is `TARGET - economic_supply`.
/// Both subsystems now stage their rows, so a block that registers an archive or
/// funds a file changes what the census must measure. Reading committed totals
/// would mint a delta that does not reconcile with the state the same block
/// publishes — the reserve would be wrong by exactly what the block created.
///
/// The assertion is on the EXACT delta. An off-by-anything here is a supply
/// error, and the test drives `apply_supply_correction_if_needed` — the function
/// a block actually runs — so rewiring it back to the committed assessment
/// fails, not just rewiring the readers.
#[test]
fn a_same_block_archive_stake_or_fee_pool_change_moves_the_reserve_delta_exactly() {
    use sumchain_state::supply::{v_assess_supply_correction, SupplyStore};

    const FEE_POOL: u64 = 4_242;

    let (_dir, db, state) = open_db();
    let p = params();
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    state.credit(&Address::new([0xE1; 20]), half).unwrap();
    state.credit(&Address::new([0xE2; 20]), half).unwrap();

    let mid = sumchain_primitives::supply::supply_correction_migration_id();

    // Baseline: an empty candidate over this parent.
    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let baseline = {
        let view = ExecutionView::new(&mut overlay);
        v_assess_supply_correction(&view, &db, 1, false, mid)
    };
    assert_eq!(
        baseline.reason,
        sumchain_primitives::supply::MigrationWithheldReason::NotWithheld,
        "the correction must apply on this parent, or the delta below is not \
         the thing under test"
    );
    drop(overlay);

    // The same parent, with an archive registered and a file funded EARLIER IN
    // THE BLOCK. Both buckets have their own reader; covering only one would
    // leave the other free to read committed state unnoticed.
    let a = Address::new([0xA1; 20]);
    let owner = Address::new([0x0E; 20]);
    let root = Hash::hash(b"census-file");
    let fund_file = StorageMetadataV2TxData {
        operation: StorageMetadataOperationV2::RegisterFilePendingV2 {
            merkle_root: root,
            plaintext_size_bytes: 500,
            stored_size_bytes: STORED,
            chunk_count: CHUNKS,
            fee_deposit: FEE_POOL,
            visibility: 0,
            initial_access: vec![],
        },
    };

    // Registering the archive and funding the file MOVE balance out of accounts
    // and into the stake and fee-pool buckets, so economic supply is unchanged
    // by the transfer itself. Crediting the two senders first keeps the parent's
    // accounted supply at the genesis figure the correction requires, and the
    // buckets then hold value the census must find in the CANDIDATE.
    state.credit(&a, (STAKE as u128) + 1_000).unwrap();
    state.credit(&owner, (FEE_POOL as u128) + 1_000).unwrap();
    let funded_baseline = {
        let mut overlay = ApplicationOverlay::new(&db, LIMIT);
        let view = ExecutionView::new(&mut overlay);
        v_assess_supply_correction(&view, &db, 1, false, mid)
    };

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = ExecutionView::new(&mut overlay);
    NodeRegistryExecutor::execute(
        &mut view, &a, &register_op(), &state, &Address::ZERO, 0, 1, 1000,
    )
    .unwrap();
    assert!(StorageMetadataExecutor::execute_v2(
        &mut view, &owner, &fund_file, &state, &Address::ZERO, 0, 1, 1000, &p,
    )
    .unwrap()
    .success);

    let with_rows = v_assess_supply_correction(&view, &db, 1, false, mid);
    assert_eq!(
        with_rows.snapshot.archive_staked_balance, STAKE as u128,
        "the stake staged in this block must be censused"
    );
    assert_eq!(
        with_rows.snapshot.storage_v2_fee_pool, FEE_POOL as u128,
        "the fee pool staged in this block must be censused"
    );

    // Conservation is the sharp assertion. Registering the archive and funding
    // the file MOVED value: accounts fell by `STAKE + FEE_POOL` (through
    // `StateManager`, which still writes committed), and the archive-stake and
    // fee-pool buckets rose by the same, in the candidate. Economic supply is
    // therefore unchanged.
    //
    // Read either bucket from committed storage and the debit is counted while
    // the credit is not: economic supply falls by that bucket's amount and the
    // correction mints that much extra reserve. The equality below is what
    // fails in that case, by exactly the bucket that regressed.
    assert_eq!(
        with_rows.economic_supply, funded_baseline.economic_supply,
        "value moved out of accounts and into stake and fee pools is conserved; \
         a committed read of either bucket loses the credit and keeps the debit"
    );
    assert_eq!(
        with_rows.reserve_delta, funded_baseline.reserve_delta,
        "a conserved move must not change what the correction mints"
    );

    // Drive the production entry point and assert on what it STAGES. Reading
    // this through the committed assessment instead would measure an archive
    // stake and fee pool of zero.
    let expected_delta = with_rows.reserve_delta;
    let applied =
        sumchain_state::supply::apply_supply_correction_if_needed(&mut view, &db, 1, 8_900_000)
            .unwrap();
    assert!(applied, "the correction must apply on this parent");

    let ledger = SupplyStore::v_get_ledger(&view).unwrap();
    assert_eq!(
        ledger.total_minted_by_migration, expected_delta,
        "the staged ledger must record the delta measured against THIS block's \
         archive stake and fee pools, not the parent's"
    );
    let reserve = SupplyStore::v_get_reserve(&view).unwrap().unwrap();
    assert_eq!(reserve.total_remaining(), expected_delta);

    // Nothing published.
    drop(overlay);
    assert!(!SupplyStore::new(db.clone()).is_migration_applied().unwrap());
}
