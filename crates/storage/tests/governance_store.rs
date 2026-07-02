//! Issue #50 Phase 2: governance store round-trips + deterministic key layouts.
//! Data model / persistence only — no lifecycle, snapshots-building, or voting
//! behavior (those are later phases; governance stays dormant behind the gate).

use sumchain_primitives::governance::{
    ExecutionKind, ExternalRef, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
    GovProposalClass, GovProposalStatus, GovVote, VoteChoice, WeightRule,
};
use sumchain_primitives::Address;
use sumchain_storage::{Database, GovStore};
use tempfile::TempDir;

fn temp_db() -> (Database, TempDir) {
    let dir = TempDir::new().unwrap();
    let db = Database::open_default(dir.path()).unwrap();
    (db, dir)
}

fn asset(token: u8, status: GovAssetStatus, effective: u64) -> GovAsset {
    GovAsset {
        asset: GovAssetKind::Src20Token([token; 32]),
        create_threshold: 1_000,
        vote_weight_rule: WeightRule::Linear,
        status,
        effective_height: effective,
    }
}

fn proposal(id: u8, proposer: Address, status: GovProposalStatus) -> GovProposal {
    GovProposal {
        id: [id; 32],
        proposer,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/pr/1".into(), content_hash: [0xEE; 32] },
        asset: GovAssetKind::Src20Token([7u8; 32]),
        voting_start_height: 100,
        status,
        created_at: 1000,
        created_at_height: 100,
        expires_at: 2000,
        bond: 0,
        bond_state: sumchain_primitives::governance::BondState::Escrowed,
        treasury_beneficiary: None,
        treasury_amount: None,
    }
}

#[test]
fn cfs_open_and_registry_round_trip() {
    let (db, _dir) = temp_db();
    let store = GovStore::new(&db);

    store.put_asset(&asset(7, GovAssetStatus::Enabled, 10)).unwrap();
    store.put_asset(&asset(8, GovAssetStatus::Disabled, 10)).unwrap();
    store.put_asset(&asset(9, GovAssetStatus::Enabled, 50)).unwrap();

    let got = store.get_asset(&GovAssetKind::Src20Token([7u8; 32])).unwrap().unwrap();
    assert_eq!(got.create_threshold, 1_000);
    assert!(store.get_asset(&GovAssetKind::Src20Token([0u8; 32])).unwrap().is_none());

    assert_eq!(store.list_assets().unwrap().len(), 3);
    assert_eq!(store.list_enabled_assets().unwrap().len(), 2); // 7 and 9
    // Effective at height 20: enabled AND effective_height <= 20 → only token 7.
    let eff = store.list_effective_assets(20).unwrap();
    assert_eq!(eff.len(), 1);
    assert_eq!(eff[0].asset, GovAssetKind::Src20Token([7u8; 32]));
}

#[test]
fn proposal_round_trip_status_and_proposer_index() {
    let (db, _dir) = temp_db();
    let store = GovStore::new(&db);
    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xB2; 20]);

    store.put_proposal(&proposal(1, a, GovProposalStatus::Created)).unwrap();
    store.put_proposal(&proposal(2, a, GovProposalStatus::Voting)).unwrap();
    store.put_proposal(&proposal(3, b, GovProposalStatus::Created)).unwrap();

    assert_eq!(store.get_proposal(&[1; 32]).unwrap().unwrap().proposer, a);
    assert!(store.get_proposal(&[9; 32]).unwrap().is_none());

    assert_eq!(store.list_proposals().unwrap().len(), 3);
    assert_eq!(store.list_proposals_by_status(GovProposalStatus::Created).unwrap().len(), 2);
    assert_eq!(store.list_proposals_by_status(GovProposalStatus::Voting).unwrap().len(), 1);

    // by-proposer index
    assert_eq!(store.list_proposals_by_proposer(&a).unwrap().len(), 2);
    assert_eq!(store.list_proposals_by_proposer(&b).unwrap().len(), 1);
    assert_eq!(store.list_proposals_by_proposer(&Address::new([0xCC; 20])).unwrap().len(), 0);
}

#[test]
fn vote_one_per_voter_and_list_by_proposal() {
    let (db, _dir) = temp_db();
    let store = GovStore::new(&db);
    let pid = [1u8; 32];
    let voter = Address::new([0x11; 20]);

    let v1 = GovVote { proposal_id: pid, voter, weight: 100, choice: VoteChoice::Yes, cast_at_height: 101 };
    store.put_vote(&v1).unwrap();
    // Same (proposal, voter) overwrites — one vote per voter (key-enforced).
    let v2 = GovVote { proposal_id: pid, voter, weight: 100, choice: VoteChoice::No, cast_at_height: 102 };
    store.put_vote(&v2).unwrap();
    assert_eq!(store.get_vote(&pid, &voter).unwrap().unwrap().choice, VoteChoice::No);

    // A different voter, and a vote on a different proposal.
    store
        .put_vote(&GovVote { proposal_id: pid, voter: Address::new([0x22; 20]), weight: 5, choice: VoteChoice::Abstain, cast_at_height: 103 })
        .unwrap();
    store
        .put_vote(&GovVote { proposal_id: [2u8; 32], voter, weight: 7, choice: VoteChoice::Yes, cast_at_height: 104 })
        .unwrap();

    // list by proposal is prefix-scoped: pid has 2 voters, not 3.
    assert_eq!(store.list_votes(&pid).unwrap().len(), 2);
    assert_eq!(store.list_votes(&[2u8; 32]).unwrap().len(), 1);
}

#[test]
fn snapshot_round_trip_and_list_by_proposal() {
    let (db, _dir) = temp_db();
    let store = GovStore::new(&db);
    let pid = [1u8; 32];
    let h1 = Address::new([0x11; 20]);
    let h2 = Address::new([0x22; 20]);

    store.put_snapshot(&pid, &h1, 1_000).unwrap();
    store.put_snapshot(&pid, &h2, 2_500).unwrap();
    store.put_snapshot(&[2u8; 32], &h1, 9).unwrap();

    assert_eq!(store.get_snapshot(&pid, &h1).unwrap(), Some(1_000));
    assert_eq!(store.get_snapshot(&pid, &Address::new([0x33; 20])).unwrap(), None);

    let mut snap = store.list_snapshot(&pid).unwrap();
    snap.sort_by_key(|(_, w)| *w);
    assert_eq!(snap.len(), 2);
    assert_eq!(snap[0], (h1, 1_000));
    assert_eq!(snap[1], (h2, 2_500));
    assert_eq!(store.list_snapshot(&[2u8; 32]).unwrap().len(), 1);
}
