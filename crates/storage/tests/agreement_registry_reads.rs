//! Issue #26 (sub-issue 3): Agreement executor-link storage read helpers
//! round-trip. Executor links ONLY — no commitments, parties, signatures,
//! attestations, IP actions, proofs, or events.

use sumchain_primitives::agreement::{ExecutorLink, ExecutorState};
use sumchain_primitives::Address;
use sumchain_storage::{Database, ExecutorLinkStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn link(
    link_id: [u8; 32],
    agreement_id: [u8; 32],
    executor: Address,
    state: ExecutorState,
) -> ExecutorLink {
    ExecutorLink {
        link_id,
        agreement_id,
        executor_contract: executor,
        executor_interface_id: [1u8; 32],
        terms_commitment: [2u8; 32],
        activation_policy_id: [3u8; 32],
        state,
        created_at: 100,
        updated_at: 100,
        created_at_height: 5,
        activation_proof_id: None,
    }
}

#[test]
fn executor_link_get_by_agreement_by_executor_active() {
    let (db, _dir) = temp_db();
    let store = ExecutorLinkStore::new(&db);
    let agr = [0xA1; 32];
    let exec_a = Address::new([0xE1; 20]);
    let exec_b = Address::new([0xE2; 20]);

    store.put(&link([0x01; 32], agr, exec_a, ExecutorState::Active)).unwrap();
    store.put(&link([0x02; 32], agr, exec_b, ExecutorState::Terminated)).unwrap();
    store.put(&link([0x03; 32], [0xA2; 32], exec_a, ExecutorState::Active)).unwrap();

    // get by id
    assert_eq!(store.get(&[0x01; 32]).unwrap().unwrap().agreement_id, agr);
    assert!(store.get(&[0u8; 32]).unwrap().is_none());

    // by agreement
    assert_eq!(store.get_by_agreement(&agr).unwrap().len(), 2);
    // by executor
    assert_eq!(store.get_by_executor(&exec_a).unwrap().len(), 2);
    assert_eq!(store.get_by_executor(&exec_b).unwrap().len(), 1);
    // active only
    assert_eq!(store.list_active().unwrap().len(), 2);
}
