//! Governance v2 storage tests (#91 qualifying registry, #92 equity roots +
//! chain-derived Merkle root determinism / verification).

use sumchain_primitives::Address;
use sumchain_storage::{
    equity_balances_root, equity_balances_root_and_proof, equity_merkle_leaf, equity_merkle_verify,
    Database, EquityClassRoot, EquityStore, GovStore, QualifyingAsset,
};
use tempfile::TempDir;

fn db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    (Database::open_default(dir.path()).unwrap(), dir)
}

const CLASS: [u8; 32] = [0xEC; 32];

#[test]
fn qualifying_asset_registry_round_trip_and_effective_filter() {
    let (db, _d) = db();
    let s = GovStore::new(&db);
    s.put_qualifying_asset(&QualifyingAsset { token_id: [1; 32], min_balance: 10, effective_height: 0 }).unwrap();
    s.put_qualifying_asset(&QualifyingAsset { token_id: [2; 32], min_balance: 20, effective_height: 100 }).unwrap();
    assert_eq!(s.list_qualifying_assets().unwrap().len(), 2);
    assert_eq!(s.get_qualifying_asset(&[1; 32]).unwrap().unwrap().min_balance, 10);
    // Effective at height 50: only the height-0 asset.
    let eff = s.list_effective_qualifying_assets(50).unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].token_id, [1; 32]);
}

#[test]
fn equity_class_root_and_commitment_dedup() {
    let (db, _d) = db();
    let s = GovStore::new(&db);
    let pid = [9u8; 32];
    let root = EquityClassRoot { class_id: CLASS, balances_root: [7; 32], votes_per_share: 3, frozen_height: 5 };
    s.put_equity_class_root(&pid, &root).unwrap();
    assert_eq!(s.get_equity_class_root(&pid).unwrap().unwrap(), root);

    let hc = [0x22; 32];
    assert!(!s.is_equity_commitment_used(&pid, &hc).unwrap());
    s.mark_equity_commitment_used(&pid, &hc).unwrap();
    assert!(s.is_equity_commitment_used(&pid, &hc).unwrap());
    // Different proposal → independent namespace.
    assert!(!s.is_equity_commitment_used(&[8u8; 32], &hc).unwrap());
}

#[test]
fn equity_merkle_root_is_deterministic_and_order_independent() {
    let (db, _d) = db();
    let equity = EquityStore::new(&db);
    // Insert holders in a non-sorted order.
    equity.balances().set_balance(&CLASS, &[0x33; 32], 30).unwrap();
    equity.balances().set_balance(&CLASS, &[0x11; 32], 10).unwrap();
    equity.balances().set_balance(&CLASS, &[0x22; 32], 20).unwrap();

    let r1 = equity_balances_root(&db, &CLASS).unwrap();
    // Recompute is stable.
    assert_eq!(r1, equity_balances_root(&db, &CLASS).unwrap());

    // Every holder's proof verifies against the root.
    for hc in [[0x11u8; 32], [0x22; 32], [0x33; 32]] {
        let (root, proof) = equity_balances_root_and_proof(&db, &CLASS, &hc).unwrap();
        assert_eq!(root, r1);
        let (idx, path) = proof.unwrap();
        let shares = equity.balances().get_balance(&CLASS, &hc).unwrap();
        assert!(equity_merkle_verify(&root, &hc, shares, idx, &path), "proof for {:?}", hc);
        // A wrong shares value must NOT verify.
        assert!(!equity_merkle_verify(&root, &hc, shares + 1, idx, &path));
    }
}

#[test]
fn equity_merkle_empty_tree_has_fixed_nonzero_root() {
    let (db, _d) = db();
    let root = equity_balances_root(&db, &CLASS).unwrap();
    assert_ne!(root, [0u8; 32], "empty root is a fixed non-zero constant");
    // A non-member has no proof.
    let (_r, proof) = equity_balances_root_and_proof(&db, &CLASS, &[0x99; 32]).unwrap();
    assert!(proof.is_none());
}

#[test]
fn equity_merkle_odd_leaf_count_verifies() {
    // 3 leaves exercise the odd-tail-promotion rule at the first level.
    let (db, _d) = db();
    let equity = EquityStore::new(&db);
    for (hc, s) in [([0x01u8; 32], 1u64), ([0x02; 32], 2), ([0x03; 32], 3)] {
        equity.balances().set_balance(&CLASS, &hc, s).unwrap();
    }
    let (root, proof) = equity_balances_root_and_proof(&db, &CLASS, &[0x03; 32]).unwrap();
    let (idx, path) = proof.unwrap();
    assert!(equity_merkle_verify(&root, &[0x03; 32], 3, idx, &path), "odd-tail leaf proof verifies");
}

#[test]
fn equity_merkle_leaf_binds_commitment_and_shares() {
    let a = equity_merkle_leaf(&[1; 32], 10);
    assert_ne!(a, equity_merkle_leaf(&[1; 32], 11));
    assert_ne!(a, equity_merkle_leaf(&[2; 32], 10));
    let _ = Address::ZERO; // keep the import meaningful
}
