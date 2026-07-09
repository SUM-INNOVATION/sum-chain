//! Monetary-policy governance (800B correction): `ReserveRelease*` and
//! `MonetaryPolicyMint` are NativeEligibility-only (native Koppa consensus,
//! fixed 6667 bps), gated dormant by default, rejected for SRC-20/equity
//! governance at creation, and validator-quorum has no proposal-passage path.
//! A passed release moves pool→account with canonical supply unchanged; a
//! passed mint is the ONLY way canonical supply grows.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;

use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{
    generate_proposal_id, CastVoteRequest, CreateProposalRequest, ExecuteProposalRequest,
    ExecutionKind, ExternalRef, GovAssetKind, GovProposalClass, GovernanceOperation,
    GovernanceParams, RegisterQualifyingAssetRequest, VoteChoice,
};
use sumchain_primitives::supply::{
    GENESIS_ACCOUNTED_SUPPLY, POOL_ECOSYSTEM, TARGET_CANONICAL_SUPPLY,
};
use sumchain_primitives::{Address, SignedTransaction, TransactionV2, TxPayload, TxStatus};
use sumchain_state::supply::{apply_supply_correction_if_needed, SupplyStore};
use sumchain_state::StateManager;
use sumchain_storage::schema::Src20TokenData;
use sumchain_storage::{Database, TokenStore};

const QTOKEN: [u8; 32] = [0x51; 32];

fn params(monetary_open: bool) -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.governance_enabled_from_height = Some(0);
    p.monetary_policy_enabled_from_height = if monetary_open { Some(0) } else { None };
    p.governance = Some(GovernanceParams {
        validator_authority_threshold_bps: 5_000,
        quorum_bps: 1,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 1000,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 1,
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

fn migrate(state: &StateManager, db: &Arc<Database>) {
    let half = GENESIS_ACCOUNTED_SUPPLY / 2;
    state.credit(&Address::new([0xE1; 20]), half).unwrap();
    state.credit(&Address::new([0xE2; 20]), half).unwrap();
    assert!(apply_supply_correction_if_needed(db, 1, 100).unwrap());
}

fn seed_qualifying_token(db: &Arc<Database>, holders: &[(Address, u128)]) {
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
    for (a, b) in holders {
        ts.set_balance(&QTOKEN, a, *b).unwrap();
    }
}

fn qualify_approval(v: &KeyPair, min_balance: u128, eff: u64) -> sumchain_primitives::ValidatorApproval {
    let msg = sumchain_primitives::validator_authority::register_asset_signing_bytes(
        CHAIN_ID, &QTOKEN, min_balance, eff,
    );
    sumchain_primitives::ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(&msg, v.private_key()).to_bytes(),
    }
}

fn create_req(class: GovProposalClass, asset: GovAssetKind, to: Address, amount: u128) -> Vec<u8> {
    bincode::serialize(&CreateProposalRequest {
        asset,
        class,
        execution_kind: ExecutionKind::OnChain,
        external_ref: ExternalRef { url: "https://x/mp".into(), content_hash: [0xAB; 32] },
        treasury_beneficiary: Some(to),
        treasury_amount: Some(amount),
    })
    .unwrap()
}

// ── Dormant gate + asset enforcement at CREATION ─────────────────────────────

#[test]
fn monetary_classes_dormant_by_default_387_at_creation() {
    let (state, db, _dir, exec) = setup_with_params(params(false));
    migrate(&state, &db);
    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    for (i, class) in [
        GovProposalClass::ReserveReleaseEcosystem,
        GovProposalClass::ReserveReleaseGovernance,
        GovProposalClass::MonetaryPolicyMint,
    ]
    .into_iter()
    .enumerate()
    {
        // 387 is a fee-paid semantic failure (Policy-B) → the nonce advances.
        let req = create_req(class, GovAssetKind::NativeEligibility, Address::new([7; 20]), 1_000);
        let r = exec
            .execute_tx(&signed(&proposer, i as u64, gov(GovernanceOperation::CreateProposal, req)), &Address::new([9; 20]), 5, 1000)
            .unwrap();
        assert!(matches!(r.status, TxStatus::Failed(387)), "dormant monetary gate: {:?}", r.status);
    }
}

#[test]
fn monetary_classes_reject_non_native_assets_388() {
    // SRC-20 (and by the same check equity) governance can NEVER carry a
    // monetary-policy class — rejected 388 at creation before any registry work.
    let (state, db, _dir, exec) = setup_with_params(params(true));
    migrate(&state, &db);
    let proposer = KeyPair::generate();
    fund(&state, &proposer, 100_000);
    let req = create_req(
        GovProposalClass::MonetaryPolicyMint,
        GovAssetKind::Src20Token(QTOKEN),
        Address::new([7; 20]),
        1_000,
    );
    let r = exec
        .execute_tx(&signed(&proposer, 0, gov(GovernanceOperation::CreateProposal, req)), &Address::new([9; 20]), 5, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Failed(388)), "SRC-20 cannot mint: {:?}", r.status);
}

// ── End-to-end NativeEligibility release + mint ──────────────────────────────

/// Full native flow: register qualifying asset (validator quorum), create the
/// monetary proposal (NativeEligibility), vote yes (1 addr = 1 vote, 6667 bps
/// trivially passed at 1/1), execute after the voting window.
fn run_native_proposal(
    class: GovProposalClass,
    recipient: Address,
    amount: u128,
) -> (Arc<StateManager>, Arc<Database>) {
    let (state, db, _dir, exec) = setup_with_params(params(true));
    migrate(&state, &db);
    let validator = KeyPair::generate();
    let vset = [*validator.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    let voter = KeyPair::generate();
    fund(&state, &submitter, 1_000_000);
    fund(&state, &voter, 1_000_000); // ≥ min_koppa_for_eligibility (1)
    seed_qualifying_token(&db, &[(voter.address(), 100)]);

    // Register the qualifying SRC-20 via validator quorum (min_balance 50).
    let req = bincode::serialize(&RegisterQualifyingAssetRequest {
        token_id: QTOKEN,
        min_balance: 50,
        effective_height: 0,
        approvals: vec![qualify_approval(&validator, 50, 0)],
    })
    .unwrap();
    let r = exec
        .execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 101, 1000, &vset)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "register qualifying: {:?}", r.status);

    // Create the monetary proposal under NativeEligibility (voter is eligible).
    let creq = create_req(class, GovAssetKind::NativeEligibility, recipient, amount);
    let r = exec
        .execute_tx(&signed(&voter, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 105, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "create: {:?}", r.status);
    let pid = generate_proposal_id(&voter.address(), &GovAssetKind::NativeEligibility, &[0xAB; 32], 105, 0);

    // Vote yes (weight 1 of snapshot 1 ⇒ 100% ≥ 6667 bps).
    let vreq = bincode::serialize(&CastVoteRequest { proposal_id: pid, choice: VoteChoice::Yes }).unwrap();
    let r = exec
        .execute_tx(&signed(&voter, 1, gov(GovernanceOperation::CastVote, vreq)), &Address::new([9; 20]), 110, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "vote: {:?}", r.status);

    // Execute after the voting window closes (105 + 100 < 300).
    let ereq = bincode::serialize(&ExecuteProposalRequest { proposal_id: pid }).unwrap();
    let r = exec
        .execute_tx(&signed(&submitter, 1, gov(GovernanceOperation::ExecuteProposal, ereq)), &Address::new([9; 20]), 300, 1000)
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "execute: {:?}", r.status);
    (state, db)
}

#[test]
fn native_governance_reserve_release_moves_pool_to_account_canonical_unchanged() {
    let recipient = Address::new([0x77; 20]);
    let amount = 12_345_000u128;
    let (state, db) = run_native_proposal(GovProposalClass::ReserveReleaseEcosystem, recipient, amount);

    let store = SupplyStore::new(db.clone());
    // Pool decremented exactly; recipient credited exactly.
    assert_eq!(
        store.get_reserve().unwrap().unwrap().ecosystem_pool_remaining,
        POOL_ECOSYSTEM - amount
    );
    assert_eq!(state.get_balance(&recipient).unwrap(), amount);
    // Canonical supply UNCHANGED by a release (ledger→account move).
    let ledger = store.get_ledger().unwrap();
    assert_eq!(ledger.current_canonical_supply(), TARGET_CANONICAL_SUPPLY);
    assert_eq!(ledger.total_minted_by_governance, 0);
}

#[test]
fn native_governance_mint_grows_canonical_supply() {
    let recipient = Address::new([0x78; 20]);
    let amount = 999_000u128;
    let (state, db) = run_native_proposal(GovProposalClass::MonetaryPolicyMint, recipient, amount);

    let store = SupplyStore::new(db.clone());
    let ledger = store.get_ledger().unwrap();
    assert_eq!(ledger.total_minted_by_governance, amount, "mint recorded");
    assert_eq!(
        ledger.current_canonical_supply(),
        TARGET_CANONICAL_SUPPLY + amount,
        "mint is the ONLY supply-expansion path"
    );
    assert_eq!(state.get_balance(&recipient).unwrap(), amount);
    // Reserve pools untouched by a mint.
    assert_eq!(
        store.get_reserve().unwrap().unwrap().total_remaining(),
        sumchain_primitives::supply::SUPPLY_CORRECTION_DELTA
    );
}

#[test]
fn release_exceeding_pool_fails_385_and_moves_nothing() {
    let recipient = Address::new([0x79; 20]);
    // Amount larger than the whole ecosystem pool → the execute tx fails 385.
    let (state, db, _dir, exec) = setup_with_params(params(true));
    migrate(&state, &db);
    let validator = KeyPair::generate();
    let vset = [*validator.public_key().as_bytes()];
    let submitter = KeyPair::generate();
    let voter = KeyPair::generate();
    fund(&state, &submitter, 1_000_000);
    fund(&state, &voter, 1_000_000);
    seed_qualifying_token(&db, &[(voter.address(), 100)]);
    let req = bincode::serialize(&RegisterQualifyingAssetRequest {
        token_id: QTOKEN, min_balance: 50, effective_height: 0,
        approvals: vec![qualify_approval(&validator, 50, 0)],
    }).unwrap();
    exec.execute_tx_with_validators(&signed(&submitter, 0, gov(GovernanceOperation::RegisterQualifyingAsset, req)), &Address::new([9; 20]), 101, 1000, &vset).unwrap();
    let creq = create_req(GovProposalClass::ReserveReleaseEcosystem, GovAssetKind::NativeEligibility, recipient, POOL_ECOSYSTEM + 1);
    exec.execute_tx(&signed(&voter, 0, gov(GovernanceOperation::CreateProposal, creq)), &Address::new([9; 20]), 105, 1000).unwrap();
    let pid = generate_proposal_id(&voter.address(), &GovAssetKind::NativeEligibility, &[0xAB; 32], 105, 0);
    let vreq = bincode::serialize(&CastVoteRequest { proposal_id: pid, choice: VoteChoice::Yes }).unwrap();
    exec.execute_tx(&signed(&voter, 1, gov(GovernanceOperation::CastVote, vreq)), &Address::new([9; 20]), 110, 1000).unwrap();
    let ereq = bincode::serialize(&ExecuteProposalRequest { proposal_id: pid }).unwrap();
    let r = exec.execute_tx(&signed(&submitter, 1, gov(GovernanceOperation::ExecuteProposal, ereq)), &Address::new([9; 20]), 300, 1000).unwrap();
    assert!(matches!(r.status, TxStatus::Failed(385)), "over-pool release: {:?}", r.status);
    // Nothing moved.
    assert_eq!(state.get_balance(&recipient).unwrap(), 0);
    assert_eq!(SupplyStore::new(db).get_reserve().unwrap().unwrap().ecosystem_pool_remaining, POOL_ECOSYSTEM);
}
