//! The governance, token and equity candidate surfaces stage, and agree with
//! their committed twins.
//!
//! Nothing in production calls these yet — that is the next commit. What this
//! file establishes is that when it does, the behaviour will not change: each
//! `v_` function writes the same bytes to the same key as the committed store,
//! reads what the same block staged, and leaves committed storage untouched
//! until the candidate is published.
//!
//! Testing a surface before routing to it is the point of splitting the
//! preparation out. A routing commit that also introduced these functions would
//! have to be read as two changes at once, and a disagreement between candidate
//! and committed would surface as a behaviour change in an executor rather than
//! as what it is.
//!
//! What is deliberately NOT here: the three CFs an executor writes through more
//! than one path, abandonment across the full family set, and the census. Those
//! belong with the routing, where there is a block to abandon.

use std::sync::Arc;

use sumchain_primitives::equity::{
    ControllerModel, EntityProfile, EntityStatus, EquityToken, GovernanceAction,
    GovernanceActionStatus, GovernanceActionType, OrgType, OwnershipProofEnvelope,
    OwnershipProofType, ShareClassType, TokenStatus,
};
use sumchain_primitives::governance::{
    BondState, ExecutionKind, ExternalRef, GovAsset, GovAssetKind, GovAssetStatus, GovProposal,
    GovProposalClass, GovProposalStatus, GovVote, VoteChoice, WeightRule,
};
use sumchain_primitives::Address;
use sumchain_state::equity_executor::EquityExecutor;
use sumchain_state::governance_view as gv;
use sumchain_state::token_executor::TokenExecutor;
use sumchain_storage::equity_store::{
    EntityProfileStore, EquityBalanceStore, EquityTokenStore, GovernanceActionStore,
    OwnershipProofStore,
};
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::governance_store::{EquityClassRoot, GovStore, QualifyingAsset};
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::{Src20TokenData, TokenStore};
use sumchain_storage::{cf, Database};

const LIMIT: u64 = 1 << 20;

fn open() -> (tempfile::TempDir, Arc<Database>) {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Arc::new(Database::open_default(dir.path()).unwrap());
    (dir, db)
}

fn view_of<'v, 'db>(o: &'v mut ApplicationOverlay<'db>) -> ExecutionView<'v, 'db> {
    ExecutionView::new(o)
}

fn addr(b: u8) -> Address {
    Address::new([b; 20])
}

/// The families actually represented in a row set — used to refuse a
/// comparison that names a family nothing writes.
fn families_in(rows: &[(String, Vec<u8>, Vec<u8>)]) -> std::collections::BTreeSet<String> {
    rows.iter().map(|(f, _, _)| f.clone()).collect()
}

fn gov_action(action_id: [u8; 32], org_subject: [u8; 32]) -> GovernanceAction {
    GovernanceAction {
        action_id,
        org_subject,
        action_type: GovernanceActionType::BoardResolutionApproved,
        policy_id: [0xB1; 32],
        action_commitment: [0xB2; 32],
        effective_at: 1,
        expires_at: 100,
        attachments: None,
        approvers: vec![addr(0xB3)],
        required_threshold: 1,
        status: GovernanceActionStatus::Pending,
        created_at: 1,
        recorded_at_height: 1,
    }
}

fn ownership_proof(proof_id: [u8; 32]) -> OwnershipProofEnvelope {
    OwnershipProofEnvelope {
        proof_id,
        profile_id: "p".into(),
        policy_ids: vec![[0xC1; 32]],
        public_inputs: vec![1, 2, 3],
        proof_data: vec![4, 5, 6],
        proof_type: OwnershipProofType::Mock,
        subject_nullifier: [0xC2; 32],
        generated_at: 1,
        expires_at: 100,
    }
}

fn gov_asset(kind: GovAssetKind) -> GovAsset {
    GovAsset {
        asset: kind,
        create_threshold: 10,
        vote_weight_rule: WeightRule::Linear,
        status: GovAssetStatus::Enabled,
        effective_height: 1,
    }
}

fn gov_proposal(id: [u8; 32], proposer: Address) -> GovProposal {
    GovProposal {
        id,
        proposer,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: String::new(), content_hash: [0; 32] },
        asset: GovAssetKind::NativeEligibility,
        voting_start_height: 1,
        status: GovProposalStatus::Created,
        created_at: 1,
        created_at_height: 1,
        expires_at: 100,
        bond: 0,
        bond_state: BondState::Escrowed,
        treasury_beneficiary: None,
        treasury_amount: None,
    }
}

fn gov_vote(proposal_id: [u8; 32], voter: Address) -> GovVote {
    GovVote { proposal_id, voter, weight: 1, choice: VoteChoice::Yes, cast_at_height: 2 }
}

fn token(owner: Address, supply: u128) -> Src20TokenData {
    Src20TokenData {
        name: "Surface".into(),
        symbol: "SUR".into(),
        decimals: 6,
        owner,
        total_supply: supply,
        max_supply: 0,
        mintable: true,
        burnable: true,
        pausable: false,
        paused: false,
        minters: vec![owner],
        created_at: 1,
        created_at_block: 1,
    }
}

/// Every row in a set of column families, as raw bytes, from COMMITTED storage.
fn rows(db: &Database, families: &[&str]) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in families {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// The same, from the CANDIDATE.
///
/// The comparison below is staged-against-committed rather than
/// published-against-committed on purpose. Publishing an overlay from a test
/// would mean reaching past `AcceptedCandidate::publish` — a second publisher,
/// which `no_test_publishes_a_candidate_by_hand` refuses and should. Reading
/// the candidate proves the same thing: these are the bytes that would be
/// published, at the keys they would be published to.
fn staged(view: &ExecutionView<'_, '_>, families: &[&str]) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in families {
        for item in view.prefix_iter(f, &[]).unwrap() {
            let (k, v) = item.unwrap();
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

// ── Token ────────────────────────────────────────────────────────────────────

/// The token surface writes what the committed store writes, and stages it.
#[test]
fn the_token_surface_matches_its_committed_twin_byte_for_byte() {
    let (_d1, a) = open();
    let (_d2, b) = open();
    let t = [0x11u8; 32];
    let owner = addr(0x12);
    let spender = addr(0x13);
    let data = token(owner, 500);

    // Committed side.
    let store = TokenStore::new(&a);
    store.put_token(&t, &data).unwrap();
    store.set_balance(&t, &owner, 500).unwrap();
    store.set_allowance(&t, &owner, &spender, 77).unwrap();

    // Candidate side, over an empty database.
    let families = [cf::TOKENS, cf::TOKEN_BALANCES, cf::TOKEN_ALLOWANCES, cf::TOKEN_HOLDER_INDEX];
    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    TokenExecutor::v_put_token(&mut view, &t, &data).unwrap();
    TokenExecutor::v_set_balance(&mut view, &t, &owner, 500).unwrap();
    TokenExecutor::v_set_allowance(&mut view, &t, &owner, &spender, 77).unwrap();

    assert_eq!(
        rows(&a, &families),
        staged(&view, &families),
        "the candidate surface and the committed store must produce identical \
         rows, in identical families, at identical keys"
    );
}

/// A balance set earlier in the block is visible later in it, and committed
/// storage does not move while the candidate lives.
#[test]
fn a_token_balance_set_earlier_in_the_block_is_visible_later_in_it() {
    let (_dir, db) = open();
    let t = [0x21u8; 32];
    let owner = addr(0x22);
    TokenStore::new(&db).set_balance(&t, &owner, 100).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    TokenExecutor::v_set_balance(&mut view, &t, &owner, 350).unwrap();
    assert_eq!(TokenExecutor::v_get_balance(&view, &t, &owner).unwrap(), 350);
    assert_eq!(
        TokenStore::new(&db).get_balance(&t, &owner).unwrap(),
        100,
        "committed storage still holds the parent's balance"
    );
}

/// Zero deletes the row and drops the holder-index entry, in the candidate too.
#[test]
fn a_zero_token_balance_stages_an_absence_not_a_zero() {
    let (_dir, db) = open();
    let t = [0x31u8; 32];
    let owner = addr(0x32);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);
    TokenExecutor::v_set_balance(&mut view, &t, &owner, 10).unwrap();
    assert_eq!(
        TokenExecutor::v_get_holder_tokens(&view, &owner).unwrap(),
        vec![t.to_vec()]
    );
    TokenExecutor::v_set_balance(&mut view, &t, &owner, 0).unwrap();

    assert_eq!(TokenExecutor::v_get_balance(&view, &t, &owner).unwrap(), 0);
    assert!(
        TokenExecutor::v_get_holder_tokens(&view, &owner)
            .unwrap()
            .is_empty(),
        "the holder index drops the token with the balance"
    );
    // Neither family has a row staged at all: an absence, not a zero.
    let families = [cf::TOKEN_BALANCES, cf::TOKEN_HOLDER_INDEX];
    assert!(
        staged(&view, &families).is_empty(),
        "a zero balance stages an ABSENT row, not a row of zeroes"
    );
}

// ── Equity ───────────────────────────────────────────────────────────────────

/// The equity surface writes what the committed stores write.
#[test]
fn the_equity_surface_matches_its_committed_twin_byte_for_byte() {
    let (_d1, a) = open();
    let (_d2, b) = open();
    let class = [0x41u8; 32];
    let holder = [0x42u8; 32];

    let profile = EntityProfile {
        subject_id: [0x43; 32],
        org_type: OrgType::Corporation,
        name_commitment: [0x44; 32],
        jurisdiction: Some("XX".into()),
        registration_commitment: None,
        controller_model: ControllerModel::SingleSigner,
        controllers: vec![addr(0x45)],
        multisig_threshold: None,
        services: Vec::new(),
        metadata_hash: [0x46; 32],
        created_at: 1,
        updated_at: 2,
        status: EntityStatus::Active,
    };
    let eq_token = EquityToken {
        issuer_subject: profile.subject_id,
        class_id: class,
        share_class_type: ShareClassType::Common,
        name: "Common".into(),
        symbol: "CMN".into(),
        authorized_shares: 1_000,
        issued_shares: 250,
        votes_per_share: 1,
        economic_rights_hash: [0x47; 32],
        liquidation_preference_hash: None,
        dividend_policy_hash: None,
        conversion_rules_hash: None,
        controller: addr(0x48),
        par_value: None,
        created_at: 1,
        updated_at: 1,
        status: TokenStatus::Active,
    };

    let action = gov_action([0x49; 32], profile.subject_id);
    let proof = ownership_proof([0x4A; 32]);

    EntityProfileStore::new(&a).put(&profile).unwrap();
    EquityTokenStore::new(&a).put(&eq_token).unwrap();
    EquityBalanceStore::new(&a).set_balance(&class, &holder, 250).unwrap();
    GovernanceActionStore::new(&a).put(&action).unwrap();
    OwnershipProofStore::new(&a).put(&proof).unwrap();

    // All SEVEN families this package writes, not the four that are easiest to
    // reach. Governance actions, the entity index they are found through, and
    // ownership proofs were omitted at first, which made the comparison a claim
    // about three families it never touched.
    let families = [
        cf::EQUITY_ENTITIES,
        cf::EQUITY_TOKENS,
        cf::EQUITY_BALANCES,
        cf::EQUITY_HOLDER_INDEX,
        cf::EQUITY_GOVERNANCE,
        cf::EQUITY_ENTITY_INDEX,
        cf::EQUITY_PROOFS,
    ];
    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    EquityExecutor::v_put_entity(&mut view, &profile).unwrap();
    EquityExecutor::v_put_equity_token(&mut view, &eq_token).unwrap();
    EquityExecutor::v_set_equity_balance(&mut view, &class, &holder, 250).unwrap();
    EquityExecutor::v_put_governance_action(&mut view, &action).unwrap();
    EquityExecutor::v_put_ownership_proof(&mut view, &proof).unwrap();

    let committed = rows(&a, &families);
    assert_eq!(
        families_in(&committed).len(),
        families.len(),
        "every family this test names must actually receive a row; one that is \
         empty on both sides is not covered by the comparison that follows"
    );
    assert_eq!(committed, staged(&view, &families));
}

/// A self-transfer INFLATES, identically on both sides.
///
/// `EquityBalanceStore::transfer` reads both balances before either write. For
/// a self-transfer those are the same row, so 90 shares transferring 30 to
/// themselves are written 60 and then 90 + 30 = 120: the class gains 30 out of
/// nothing. That is a live defect in committed code, not an artefact of this
/// preparation.
///
/// The candidate reproduces it exactly, and this test asserts the two agree
/// rather than asserting either is right. An earlier version of `v_transfer_equity`
/// copied `StateManager::v_transfer`'s ordering — recipient read AFTER the
/// debit, which is the correct shape and is why accounts do not have this bug —
/// and produced 90 where committed produces 120. Correct, and wrong to do here:
/// a parity preparation that quietly fixed a consensus-visible bug would hide
/// the fix inside a refactor, and leave the routing commit with no baseline to
/// be reviewed against.
///
/// The fix is tracked separately, for an activation-gated change. Until it
/// lands, this test is what stops the two sides drifting apart — in either
/// direction.
#[test]
fn an_equity_self_transfer_inflates_identically_on_both_sides() {
    let (_d1, a) = open();
    let (_d2, b) = open();
    let class = [0x51u8; 32];
    let holder = [0x52u8; 32];

    EquityBalanceStore::new(&a).set_balance(&class, &holder, 90).unwrap();
    EquityBalanceStore::new(&b).set_balance(&class, &holder, 90).unwrap();

    EquityBalanceStore::new(&a)
        .transfer(&class, &holder, &holder, 30)
        .unwrap();

    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    EquityExecutor::v_transfer_equity(&mut view, &class, &holder, &holder, 30).unwrap();

    assert_eq!(
        EquityBalanceStore::new(&a).get_balance(&class, &holder).unwrap(),
        120,
        "committed inflates a self-transfer: both reads precede both writes"
    );
    assert_eq!(
        EquityExecutor::v_get_equity_balance(&view, &class, &holder).unwrap(),
        120,
        "and the candidate must inflate identically, or routing changes what \
         the chain computes"
    );

    let families = [cf::EQUITY_BALANCES, cf::EQUITY_HOLDER_INDEX];
    assert_eq!(
        rows(&a, &families),
        staged(&view, &families),
        "byte-identical, defect included"
    );
}

/// A transfer between two DIFFERENT holders moves shares without inflating,
/// identically on both sides.
///
/// The ordering defect is specific to the aliasing case. This pins the ordinary
/// path so a future fix for the self-transfer cannot quietly change it.
#[test]
fn an_equity_transfer_between_holders_matches_committed() {
    let (_d1, a) = open();
    let (_d2, b) = open();
    let class = [0x53u8; 32];
    let from = [0x54u8; 32];
    let to = [0x55u8; 32];

    for db in [&a, &b] {
        EquityBalanceStore::new(db).set_balance(&class, &from, 90).unwrap();
        EquityBalanceStore::new(db).set_balance(&class, &to, 5).unwrap();
    }

    EquityBalanceStore::new(&a).transfer(&class, &from, &to, 30).unwrap();

    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    EquityExecutor::v_transfer_equity(&mut view, &class, &from, &to, 30).unwrap();

    assert_eq!(
        EquityExecutor::v_get_equity_balance(&view, &class, &from).unwrap(),
        60
    );
    assert_eq!(
        EquityExecutor::v_get_equity_balance(&view, &class, &to).unwrap(),
        35
    );
    let families = [cf::EQUITY_BALANCES, cf::EQUITY_HOLDER_INDEX];
    assert_eq!(rows(&a, &families), staged(&view, &families));
}

/// Holders scanned from the candidate include the shares this block moved.
#[test]
fn equity_holders_are_scanned_from_the_candidate() {
    let (_dir, db) = open();
    let class = [0x61u8; 32];
    let a = [0x62u8; 32];
    let b = [0x63u8; 32];
    EquityBalanceStore::new(&db).set_balance(&class, &a, 100).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);
    EquityExecutor::v_transfer_equity(&mut view, &class, &a, &b, 40).unwrap();

    let mut holders = EquityExecutor::v_get_equity_holders(&view, &class).unwrap();
    holders.sort();
    assert_eq!(holders, vec![(a, 60), (b, 40)]);

    let committed = EquityBalanceStore::new(&db).get_holders(&class).unwrap();
    assert_eq!(committed, vec![(a, 100)], "committed storage is unmoved");
}

// ── Governance, and the reads that cross into token ─────────────────────────

/// A vote snapshot frozen from the candidate sees this block's balances.
///
/// This is the read that forces the three to migrate together: a snapshot taken
/// from committed balances in a block that already staged a mint binds the
/// proposal to voting power the chain no longer has, for the proposal's whole
/// life.
#[test]
fn a_vote_snapshot_scans_this_blocks_token_balances() {
    let (_dir, db) = open();
    let t = [0x71u8; 32];
    let early = addr(0x72);
    let minted = addr(0x73);
    TokenStore::new(&db).set_balance(&t, &early, 100).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    // This block mints to a new holder and moves the existing one.
    TokenExecutor::v_set_balance(&mut view, &t, &minted, 400).unwrap();
    TokenExecutor::v_set_balance(&mut view, &t, &early, 150).unwrap();

    let mut scanned = gv::v_scan_token_holders(&view, &t, 10).unwrap();
    scanned.sort();
    let mut expected = vec![(early, 150u128), (minted, 400u128)];
    expected.sort();
    assert_eq!(
        scanned, expected,
        "the snapshot must see the mint and the move this block staged"
    );
    assert_eq!(gv::v_token_balance(&view, &t, &early).unwrap(), 150);

    assert_eq!(
        GovStore::new(&db).scan_token_holders(&t, 10).unwrap(),
        vec![(early, 100)],
        "while the committed scan still reports the parent's holders"
    );
}

/// A zero balance is skipped by the candidate scan, as by the committed one.
#[test]
fn a_holder_zeroed_by_this_block_leaves_the_snapshot() {
    let (_dir, db) = open();
    let t = [0x81u8; 32];
    let leaving = addr(0x82);
    TokenStore::new(&db).set_balance(&t, &leaving, 100).unwrap();

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);
    TokenExecutor::v_set_balance(&mut view, &t, &leaving, 0).unwrap();

    assert!(
        gv::v_scan_token_holders(&view, &t, 10).unwrap().is_empty(),
        "a holder this block zeroed is not in the snapshot"
    );
}

/// Proposal creation stages the proposal, its index entry and every snapshot
/// row — what the committed `create_proposal_atomic` batches.
#[test]
fn creating_a_proposal_stages_its_index_and_snapshot_rows() {
    let (_d1, a) = open();
    let (_d2, b) = open();
    let proposal = gov_proposal([0x91; 32], addr(0x92));
    let snapshot = vec![(addr(0x93), 10u128), (addr(0x94), 20u128)];

    GovStore::new(&a)
        .create_proposal_atomic(&proposal, &snapshot)
        .unwrap();

    let families = [cf::GOV_PROPOSALS, cf::GOV_PROPOSAL_INDEX, cf::GOV_SNAPSHOTS];
    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    gv::v_create_proposal(&mut view, &proposal, &snapshot).unwrap();

    assert_eq!(
        rows(&a, &families),
        staged(&view, &families),
        "staging must reproduce the batch's rows exactly — the proposal, its \
         proposer index entry, and one snapshot row per holder"
    );
}

/// The registry, qualifying-asset and equity-class-root families match
/// committed, byte for byte.
///
/// These are the governance families `create_proposal_atomic` does not touch,
/// and they were not compared at all at first — the proposal set was, and the
/// rest were assumed to follow from sharing a codec. Sharing a codec is not the
/// same as being written to the same key.
#[test]
fn the_governance_registry_families_match_their_committed_twin() {
    let (_d1, a) = open();
    let (_d2, b) = open();

    let native = gov_asset(GovAssetKind::NativeEligibility);
    let src20 = gov_asset(GovAssetKind::Src20Token([0xD1; 32]));
    let qualifying = QualifyingAsset {
        token_id: [0xD2; 32],
        min_balance: 25,
        effective_height: 3,
    };
    let pid = [0xD3u8; 32];
    let root = EquityClassRoot {
        class_id: [0xD4; 32],
        balances_root: [0xD5; 32],
        votes_per_share: 2,
        frozen_height: 9,
    };

    let store = GovStore::new(&a);
    store.put_asset(&native).unwrap();
    store.put_asset(&src20).unwrap();
    store.put_qualifying_asset(&qualifying).unwrap();
    store.put_equity_class_root(&pid, &root).unwrap();

    let families = [
        cf::GOV_REGISTRY,
        cf::GOV_QUALIFYING_ASSETS,
        cf::GOV_EQUITY_CLASS_ROOTS,
    ];
    let mut overlay = ApplicationOverlay::new(&b, LIMIT);
    let mut view = view_of(&mut overlay);
    gv::v_put_asset(&mut view, &native).unwrap();
    gv::v_put_asset(&mut view, &src20).unwrap();
    gv::v_put_qualifying_asset(&mut view, &qualifying).unwrap();
    gv::v_put_equity_class_root(&mut view, &pid, &root).unwrap();

    let committed = rows(&a, &families);
    assert_eq!(
        families_in(&committed).len(),
        families.len(),
        "every family named here must receive a row"
    );
    assert_eq!(committed, staged(&view, &families));

    // And the readers agree with the writers, including the asset-kind keying
    // that puts two assets in one family without colliding.
    assert_eq!(
        gv::v_get_asset(&view, &GovAssetKind::NativeEligibility).unwrap(),
        Some(native)
    );
    assert_eq!(
        gv::v_get_asset(&view, &GovAssetKind::Src20Token([0xD1; 32])).unwrap(),
        Some(src20)
    );
    assert_eq!(gv::v_get_equity_class_root(&view, &pid).unwrap(), Some(root));
    assert_eq!(
        gv::v_list_effective_qualifying_assets(&view, 3).unwrap(),
        vec![qualifying]
    );
    assert!(
        gv::v_list_effective_qualifying_assets(&view, 2)
            .unwrap()
            .is_empty(),
        "an asset that is not yet effective is not listed"
    );
}

/// A vote staged in this block is visible to the tally in the same block, and
/// its dedup row stops a second one.
#[test]
fn a_vote_staged_in_this_block_is_visible_and_deduped_in_it() {
    let (_dir, db) = open();
    let pid = [0xA1u8; 32];
    let voter = addr(0xA2);
    let commitment = [0xA3u8; 32];
    let vote = gov_vote(pid, voter);

    let mut overlay = ApplicationOverlay::new(&db, LIMIT);
    let mut view = view_of(&mut overlay);

    assert!(!gv::v_is_equity_commitment_used(&view, &pid, &commitment).unwrap());
    gv::v_record_equity_vote(&mut view, &vote, &commitment).unwrap();

    assert_eq!(gv::v_list_votes(&view, &pid).unwrap().len(), 1);
    assert!(gv::v_get_vote(&view, &pid, &voter).unwrap().is_some());
    assert!(
        gv::v_is_equity_commitment_used(&view, &pid, &commitment).unwrap(),
        "the dedup row is staged with the vote, so the same commitment cannot \
         vote twice inside one block"
    );
    assert!(
        GovStore::new(&db).get_vote(&pid, &voter).unwrap().is_none(),
        "and committed storage has neither"
    );
}
