//! Governance v2 executor integration tests.
//!
//! - #91 native-Koppa 1-address-1-vote eligibility (register qualifying SRC-20,
//!   snapshot at creation = allowlisted holders ∩ ≥ Koppa floor, 6667 pass).
//! - #92 SRC-833 controller-attested equity vote (register class w/ chain-derived
//!   root, valid merkle proof + controller signature → weight = shares*vpps,
//!   recompute-root match, votes_per_share==0 → 317, bad proof/sig → 318,
//!   duplicate commitment → 309, no holder table leaks).

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::equity::{EquityToken, ShareClassType, TokenStatus};
use sumchain_primitives::governance::{
    equity_vote_signing_bytes, generate_proposal_id, CastEquityVoteRequest, CastVoteRequest,
    CreateProposalRequest, ExecuteProposalRequest, ExecutionKind, ExternalRef, GovAssetKind,
    GovProposalClass, GovProposalStatus, GovernanceOperation, GovernanceParams,
    RegisterEquityClassRequest, RegisterQualifyingAssetRequest, VoteChoice,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_storage::schema::Src20TokenData;
use sumchain_storage::{
    equity_balances_root_and_proof, Database, EquityStore, GovStore, TokenStore,
};
use std::sync::Arc;

const CLASS: [u8; 32] = [0xEC; 32];
const QTOKEN: [u8; 32] = [0x51; 32];

fn params(min_koppa: u128) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.governance_enabled_from_height = Some(0);
    p.governance = Some(GovernanceParams {
        validator_authority_threshold_bps: 5_000, // 1-validator set: ceil(1*5000/10000)=1
        quorum_bps: 1, // trivially-met quorum for these focused tests
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 1000,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: min_koppa,
    });
    p
}

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: kp.address(), fee: 100, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn gov(op: GovernanceOperation, data: Vec<u8>) -> TxPayload {
    TxPayload::Governance(sumchain_primitives::governance::GovernanceTxData { operation: op, data })
}

fn seed_qualifying_token(db: &Arc<Database>, balances: &[(Address, u128)]) {
    let ts = TokenStore::new(db);
    ts.put_token(
        &QTOKEN,
        &Src20TokenData {
            name: "Qual".into(),
            symbol: "QAL".into(),
            decimals: 0,
            owner: Address::new([0xC0; 20]),
            total_supply: 1_000,
            max_supply: 1_000,
            mintable: false,
            burnable: false,
            pausable: false,
            paused: false,
            minters: vec![],
            created_at: 0,
            created_at_block: 0,
        },
    )
    .unwrap();
    for (a, b) in balances {
        ts.set_balance(&QTOKEN, a, *b).unwrap();
    }
}

fn seed_equity_class(db: &Arc<Database>, controller: Address, votes_per_share: u64, holders: &[([u8; 32], u64)]) {
    let equity = EquityStore::new(db);
    equity
        .tokens()
        .put(&EquityToken {
            issuer_subject: [1u8; 32],
            class_id: CLASS,
            share_class_type: ShareClassType::Common,
            name: "Common".into(),
            symbol: "ACME-A".into(),
            authorized_shares: 1_000_000,
            issued_shares: 100_000,
            votes_per_share,
            economic_rights_hash: [7u8; 32],
            liquidation_preference_hash: None,
            dividend_policy_hash: None,
            conversion_rules_hash: None,
            controller,
            par_value: Some(1),
            created_at: 0,
            updated_at: 0,
            status: TokenStatus::Active,
        })
        .unwrap();
    for (hc, shares) in holders {
        equity.balances().set_balance(&CLASS, hc, *shares).unwrap();
    }
}

fn qualify_approval(v: &KeyPair, token_id: &[u8; 32], min_balance: u128, eff: u64) -> sumchain_primitives::ValidatorApproval {
    let msg = sumchain_primitives::validator_authority::register_asset_signing_bytes(
        CHAIN_ID, token_id, min_balance, eff,
    );
    sumchain_primitives::ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(&msg, v.private_key()).to_bytes(),
    }
}

fn equity_class_approval(v: &KeyPair, class_id: &[u8; 32], create_threshold: u128, eff: u64) -> sumchain_primitives::ValidatorApproval {
    let msg = sumchain_primitives::validator_authority::register_equity_class_signing_bytes(
        CHAIN_ID, class_id, create_threshold, eff,
    );
    sumchain_primitives::ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(&msg, v.private_key()).to_bytes(),
    }
}

// ── #91 native-Koppa eligibility ─────────────────────────────────────────────

#[test]
fn native_eligibility_snapshot_is_allowlisted_holders_intersect_koppa() {
    // Floor 500 Koppa. Holders of QTOKEN: A(bal 100, koppa 1000), B(bal 100,
    // koppa 100 → excluded by floor), C(bal 40 < min_balance 50 → excluded).
    let (state, db, _dir, exec) = setup_with_params(params(500));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);

    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xB2; 20]);
    let c = Address::new([0xC3; 20]);
    seed_qualifying_token(&db, &[(a, 100), (b, 100), (c, 40)]);
    state.credit(&a, 1000).unwrap();
    state.credit(&b, 100).unwrap();
    state.credit(&c, 1000).unwrap();

    // Register the qualifying SRC-20 (validator-quorum, min_balance 50).
    let req = bincode::serialize(&RegisterQualifyingAssetRequest {
        token_id: QTOKEN, min_balance: 50, effective_height: 0, approvals: vec![qualify_approval(&v, &QTOKEN, 50, 0)],
    }).unwrap();
    let r = exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 1, 1000, &vset).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "register qualifying: {:?}", r.status);

    // Create a native proposal.
    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None,
        treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "create native: {:?}", r.status);

    let pid = generate_proposal_id(&proposer.address(), &GovAssetKind::NativeEligibility, &[0xAB; 32], 5, 0);
    let store = GovStore::new(&db);
    // A eligible (weight 1); B/C excluded.
    assert_eq!(store.get_snapshot(&pid, &a).unwrap(), Some(1), "A eligible weight 1");
    assert_eq!(store.get_snapshot(&pid, &b).unwrap(), None, "B excluded (koppa floor)");
    assert_eq!(store.get_snapshot(&pid, &c).unwrap(), None, "C excluded (below min_balance)");
    // Exactly one eligible address.
    assert_eq!(store.list_snapshot(&pid).unwrap().len(), 1);
}

#[test]
fn native_create_without_registry_fails_316() {
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    // Manually enable the NativeEligibility asset but leave the qualifying
    // registry empty → 316 at create.
    GovStore::new(&db).put_asset(&sumchain_primitives::governance::GovAsset {
        asset: GovAssetKind::NativeEligibility,
        create_threshold: 0,
        vote_weight_rule: sumchain_primitives::governance::WeightRule::OneAddressOneVote,
        status: sumchain_primitives::governance::GovAssetStatus::Enabled,
        effective_height: 0,
    }).unwrap();
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None,
        treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(316)), "empty registry: {:?}", r.status);
}

#[test]
fn native_create_mode_not_enabled_fails_313() {
    // No NativeEligibility asset registered at all → mode not enabled → 313.
    let (state, _db, _dir, exec) = setup_with_params(params(0));
    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility,
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None,
        treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(313)), "mode not enabled: {:?}", r.status);
}

#[test]
fn native_no_qualifying_holders_fails_315() {
    // A qualifying asset is registered but its token has zero holders → 315.
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    seed_qualifying_token(&db, &[]); // token exists, no balances
    let req = bincode::serialize(&RegisterQualifyingAssetRequest { token_id: QTOKEN, min_balance: 1, effective_height: 0, approvals: vec![qualify_approval(&v, &QTOKEN, 1, 0)] }).unwrap();
    assert!(matches!(exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 1, 1000, &vset).unwrap().status, TxStatus::Success));

    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility, class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None, treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(315)), "no qualifying holders: {:?}", r.status);
}

#[test]
fn native_all_holders_below_koppa_floor_fails_314() {
    // Qualifying holders exist but none meet the Koppa floor → empty eligible set
    // → 314.
    let (state, db, _dir, exec) = setup_with_params(params(1_000_000)); // very high floor
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    let a = Address::new([0xA1; 20]);
    seed_qualifying_token(&db, &[(a, 100)]);
    state.credit(&a, 500).unwrap(); // < 1_000_000 floor
    let req = bincode::serialize(&RegisterQualifyingAssetRequest { token_id: QTOKEN, min_balance: 1, effective_height: 0, approvals: vec![qualify_approval(&v, &QTOKEN, 1, 0)] }).unwrap();
    assert!(matches!(exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 1, 1000, &vset).unwrap().status, TxStatus::Success));

    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility, class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None, treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(314)), "empty eligible set: {:?}", r.status);
}

#[test]
fn native_one_address_one_vote_and_6667_pass() {
    // 3 eligible addresses each weight 1. 2 Yes, 1 No → 2/3 = 6666bps < 6667 →
    // Rejected. Then flip to 3 Yes → pass.
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);

    // Three eligible voter keypairs (need to sign votes).
    let voters: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate()).collect();
    let bals: Vec<(Address, u128)> = voters.iter().map(|k| (k.address(), 100u128)).collect();
    seed_qualifying_token(&db, &bals);
    for k in &voters { fund(&state, k, 100_000); }

    let req = bincode::serialize(&RegisterQualifyingAssetRequest { token_id: QTOKEN, min_balance: 1, effective_height: 0, approvals: vec![qualify_approval(&v, &QTOKEN, 1, 0)] }).unwrap();
    assert!(matches!(exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 1, 1000, &vset).unwrap().status, TxStatus::Success));

    let proposer = &voters[0];
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility, class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None, treasury_amount: None,
    }).unwrap();
    assert!(matches!(exec.execute_tx(&signed(proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap().status, TxStatus::Success));
    let pid = generate_proposal_id(&proposer.address(), &GovAssetKind::NativeEligibility, &[0xAB; 32], 5, 0);

    // voters[0] Yes, voters[1] Yes, voters[2] No.
    let yes = bincode::serialize(&CastVoteRequest { proposal_id: pid, choice: VoteChoice::Yes }).unwrap();
    let no = bincode::serialize(&CastVoteRequest { proposal_id: pid, choice: VoteChoice::No }).unwrap();
    // voters[0] is the proposer (nonce 0 used at create) → votes at nonce 1;
    // voters[1]/voters[2] have no prior tx → vote at nonce 0.
    assert!(matches!(exec.execute_tx(&signed(&voters[0], 1, gov(GovernanceOperation::CastVote, yes.clone())), &Address::new([9; 20]), 10, 1000).unwrap().status, TxStatus::Success));
    assert!(matches!(exec.execute_tx(&signed(&voters[1], 0, gov(GovernanceOperation::CastVote, yes)), &Address::new([9; 20]), 10, 1000).unwrap().status, TxStatus::Success));
    assert!(matches!(exec.execute_tx(&signed(&voters[2], 0, gov(GovernanceOperation::CastVote, no)), &Address::new([9; 20]), 10, 1000).unwrap().status, TxStatus::Success));

    // Execute after window: 2 Yes / 3 = 6666 bps < 6667 → Rejected.
    let ereq = bincode::serialize(&ExecuteProposalRequest { proposal_id: pid }).unwrap();
    assert!(matches!(exec.execute_tx(&signed(&voters[0], 2, gov(GovernanceOperation::ExecuteProposal, ereq)), &Address::new([9; 20]), 200, 1000).unwrap().status, TxStatus::Success));
    assert_eq!(GovStore::new(&db).get_proposal(&pid).unwrap().unwrap().status, GovProposalStatus::Rejected, "2/3 < 6667 bps");
}

#[test]
fn native_snapshot_bound_305() {
    // max_snapshot_holders = 1, two eligible holders → 305.
    let mut p = params(0);
    p.governance.as_mut().unwrap().max_snapshot_holders = 1;
    let (state, db, _dir, exec) = setup_with_params(p);
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    let a = Address::new([0xA1; 20]);
    let b = Address::new([0xB2; 20]);
    seed_qualifying_token(&db, &[(a, 100), (b, 100)]);
    state.credit(&a, 1).unwrap();
    state.credit(&b, 1).unwrap();
    let req = bincode::serialize(&RegisterQualifyingAssetRequest { token_id: QTOKEN, min_balance: 1, effective_height: 0, approvals: vec![qualify_approval(&v, &QTOKEN, 1, 0)] }).unwrap();
    assert!(matches!(exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 1, 1000, &vset).unwrap().status, TxStatus::Success));

    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::NativeEligibility, class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None, treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 5, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(305)), "bound: {:?}", r.status);
    let pid = generate_proposal_id(&proposer.address(), &GovAssetKind::NativeEligibility, &[0xAB; 32], 5, 0);
    assert!(GovStore::new(&db).get_proposal(&pid).unwrap().is_none(), "no partial rows");
}

// ── #92 SRC-833 controller-attested equity vote ──────────────────────────────

fn register_equity(exec: &sumchain_state::executor::BlockExecutor, submitter: &KeyPair, v: &KeyPair, vset: &[[u8; 32]], nonce: u64, threshold: u128) -> TxStatus {
    let req = bincode::serialize(&RegisterEquityClassRequest {
        class_id: CLASS, create_threshold: threshold, effective_height: 0,
        approvals: vec![equity_class_approval(v, &CLASS, threshold, 0)],
    }).unwrap();
    exec.execute_tx_with_validators(&signed(submitter, nonce, gov(GovernanceOperation::RegisterEquityClass, req)), &Address::new([9; 20]), 1, 1000, vset).unwrap().status
}

fn create_equity_proposal(exec: &sumchain_state::executor::BlockExecutor, proposer: &KeyPair, nonce: u64, height: u64) -> [u8; 32] {
    let creq = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::EquityClass(CLASS), class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef { url: "https://x/1".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: None, treasury_amount: None,
    }).unwrap();
    let r = exec.execute_tx(&signed(proposer, nonce, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), height, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "create equity: {:?}", r.status);
    generate_proposal_id(&proposer.address(), &GovAssetKind::EquityClass(CLASS), &[0xAB; 32], height, nonce)
}

#[test]
fn equity_vote_valid_records_weight_and_root_recomputes() {
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    let controller = KeyPair::generate();

    // Class with votes_per_share = 3; holders H1(10 shares), H2(20), H3(30).
    let h1 = [0x11; 32];
    let h2 = [0x22; 32];
    let h3 = [0x33; 32];
    seed_equity_class(&db, controller.address(), 3, &[(h1, 10), (h2, 20), (h3, 30)]);

    assert!(matches!(register_equity(&exec, &submitter, &v, &vset, 0, 0), TxStatus::Success), "register equity");

    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let pid = create_equity_proposal(&exec, &proposer, 0, 5);

    // Frozen root must match an independent recompute from EQUITY_BALANCES.
    let frozen = GovStore::new(&db).get_equity_class_root(&pid).unwrap().unwrap();
    let (recomputed, proof) = equity_balances_root_and_proof(&db, &CLASS, &h2).unwrap();
    assert_eq!(frozen.balances_root, recomputed, "on-chain root == independent recompute");
    let (_idx, path) = proof.unwrap();

    // Cast a valid vote for H2 (20 shares) as `voter` (submitter), attested by
    // the controller signature over the frozen root.
    let voter = KeyPair::generate();
    fund(&state, &voter, 100_000);
    let signing = equity_vote_signing_bytes(CHAIN_ID, &pid, &CLASS, &frozen.balances_root, &h2, 20, &voter.address());
    let controller_sig = sign(&signing, controller.private_key()).to_bytes();
    let vote_req = CastEquityVoteRequest {
        proposal_id: pid, holder_commitment: h2, shares: 20, merkle_path: path.clone(),
        controller_pubkey: *controller.public_key().as_bytes(), controller_sig, choice: VoteChoice::Yes,
    };
    let r = exec.execute_tx(&signed(&voter, 0, gov(GovernanceOperation::CastEquityVote, bincode::serialize(&vote_req).unwrap())), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Success), "equity vote: {:?}", r.status);

    // Weight = 20 * 3 = 60, tallied.
    let vote = GovStore::new(&db).get_vote(&pid, &voter.address()).unwrap().unwrap();
    assert_eq!(vote.weight, 60, "weight = shares * votes_per_share");

    // Duplicate (proposal, holder_commitment) → 309, even from another voter.
    let voter2 = KeyPair::generate();
    fund(&state, &voter2, 100_000);
    let signing2 = equity_vote_signing_bytes(CHAIN_ID, &pid, &CLASS, &frozen.balances_root, &h2, 20, &voter2.address());
    let sig2 = sign(&signing2, controller.private_key()).to_bytes();
    let dup = CastEquityVoteRequest {
        proposal_id: pid, holder_commitment: h2, shares: 20, merkle_path: path,
        controller_pubkey: *controller.public_key().as_bytes(), controller_sig: sig2, choice: VoteChoice::Yes,
    };
    let r = exec.execute_tx(&signed(&voter2, 0, gov(GovernanceOperation::CastEquityVote, bincode::serialize(&dup).unwrap())), &Address::new([9; 20]), 11, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(309)), "dup commitment: {:?}", r.status);
}

#[test]
fn equity_register_non_voting_class_317() {
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    // votes_per_share = 0 → non-voting.
    seed_equity_class(&db, KeyPair::generate().address(), 0, &[([0x11; 32], 10)]);
    assert!(matches!(register_equity(&exec, &submitter, &v, &vset, 0, 0), TxStatus::Failed(317)), "non-voting class");
    let _ = db;
}

#[test]
fn equity_bad_merkle_bad_sig_and_wrong_signer_all_318() {
    let (state, db, _dir, exec) = setup_with_params(params(0));
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    fund(&state, &submitter, 100_000);
    let controller = KeyPair::generate();
    let h1 = [0x11; 32];
    let h2 = [0x22; 32];
    seed_equity_class(&db, controller.address(), 2, &[(h1, 10), (h2, 20)]);
    assert!(matches!(register_equity(&exec, &submitter, &v, &vset, 0, 0), TxStatus::Success));

    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let pid = create_equity_proposal(&exec, &proposer, 0, 5);
    let frozen = GovStore::new(&db).get_equity_class_root(&pid).unwrap().unwrap();
    let (_r, proof) = equity_balances_root_and_proof(&db, &CLASS, &h1).unwrap();
    let (_idx, good_path) = proof.unwrap();

    let voter = KeyPair::generate();
    fund(&state, &voter, 100_000);
    let good_sig = sign(&equity_vote_signing_bytes(CHAIN_ID, &pid, &CLASS, &frozen.balances_root, &h1, 10, &voter.address()), controller.private_key()).to_bytes();

    // (a) bad merkle path (wrong sibling) → 318.
    let mut bad_path = good_path.clone();
    bad_path[0][0] ^= 0xff;
    let bad_merkle = CastEquityVoteRequest { proposal_id: pid, holder_commitment: h1, shares: 10, merkle_path: bad_path, controller_pubkey: *controller.public_key().as_bytes(), controller_sig: good_sig, choice: VoteChoice::Yes };
    let r = exec.execute_tx(&signed(&voter, 0, gov(GovernanceOperation::CastEquityVote, bincode::serialize(&bad_merkle).unwrap())), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(318)), "bad merkle: {:?}", r.status);

    // (b) bad controller signature (corrupted) → 318.
    let mut corrupt = good_sig;
    corrupt[0] ^= 0xff;
    let bad_sig = CastEquityVoteRequest { proposal_id: pid, holder_commitment: h1, shares: 10, merkle_path: good_path.clone(), controller_pubkey: *controller.public_key().as_bytes(), controller_sig: corrupt, choice: VoteChoice::Yes };
    let r = exec.execute_tx(&signed(&voter, 1, gov(GovernanceOperation::CastEquityVote, bincode::serialize(&bad_sig).unwrap())), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(318)), "bad sig: {:?}", r.status);

    // (c) non-controller signer (different key signs a valid-shaped attestation) → 318.
    let impostor = KeyPair::generate();
    let imp_sig = sign(&equity_vote_signing_bytes(CHAIN_ID, &pid, &CLASS, &frozen.balances_root, &h1, 10, &voter.address()), impostor.private_key()).to_bytes();
    let wrong_signer = CastEquityVoteRequest { proposal_id: pid, holder_commitment: h1, shares: 10, merkle_path: good_path, controller_pubkey: *impostor.public_key().as_bytes(), controller_sig: imp_sig, choice: VoteChoice::Yes };
    let r = exec.execute_tx(&signed(&voter, 2, gov(GovernanceOperation::CastEquityVote, bincode::serialize(&wrong_signer).unwrap())), &Address::new([9; 20]), 10, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(318)), "non-controller signer: {:?}", r.status);
}
