//! Governance, token and equity execute against the block's candidate.
//!
//! The surfaces existed before this; what changed is who calls them. So these
//! drive `BlockExecutor::execute_tx` — real signed transactions, in sequence,
//! in one block — rather than calling the view accessors directly. An accessor
//! test proves the accessor; only a transaction sequence proves that the LATER
//! executor observes what the earlier one staged, which is the property the
//! package exists for.
//!
//! None of these PUBLISHES. Every candidate is dropped, so what they prove is
//! that transactions leave canonical rows untouched while they execute, and
//! that an abandoned block leaves them exactly as it found them — not that a
//! published block writes the right thing. Publication is covered by the
//! candidate/acceptance suites in `sumchain-storage`; reaching past
//! `AcceptedCandidate::publish` from here would make these fixtures a second
//! publisher, which `no_test_publishes_a_candidate_by_hand` refuses.
//!
//! ## Why the three could not migrate separately
//!
//! Governance takes a create-threshold from a live token balance and freezes a
//! vote snapshot by scanning `cf::TOKEN_BALANCES`; it reads equity state to
//! register a class and weigh a vote. Route token alone and governance answers
//! from the parent. Route governance alone and it reads balances the block has
//! already staged. A snapshot is frozen for the proposal's whole life, so that
//! divergence never washes out.

mod common;

use std::sync::Arc;

use common::{setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::governance::{
    CreateProposalRequest, ExecutionKind, ExternalRef, GovAssetKind, GovProposalClass,
    GovernanceOperation, GovernanceTxData,
};
use sumchain_primitives::{
    Address, SignedTransaction, TokenOperation, TokenTxData, TransactionV2, TxPayload, TxStatus,
};
use sumchain_primitives::token_ops::{TokenApproveData, TokenMintData};
use sumchain_state::governance_view as gv;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::schema::{Src20TokenData, TokenStore};
use sumchain_storage::{cf, Database, GovStore};

/// Every family this package moved.
const GTE_CFS: &[&str] = &[
    cf::TOKENS,
    cf::TOKEN_BALANCES,
    cf::TOKEN_ALLOWANCES,
    cf::TOKEN_HOLDER_INDEX,
    cf::EQUITY_ENTITIES,
    cf::EQUITY_ENTITY_INDEX,
    cf::EQUITY_GOVERNANCE,
    cf::EQUITY_TOKENS,
    cf::EQUITY_BALANCES,
    cf::EQUITY_HOLDER_INDEX,
    cf::EQUITY_PROOFS,
    cf::GOV_REGISTRY,
    cf::GOV_PROPOSALS,
    cf::GOV_PROPOSAL_INDEX,
    cf::GOV_SNAPSHOTS,
    cf::GOV_VOTES,
    cf::GOV_QUALIFYING_ASSETS,
    cf::GOV_EQUITY_CLASS_ROOTS,
    cf::GOV_EQUITY_USED_COMMITMENTS,
];

const TOKEN: [u8; 32] = [0x7A; 32];

/// Governance gated open and configured, as the governance suites do it.
fn gov_params() -> ChainParams {
    let mut p = ChainParams::with_v2_enabled();
    p.governance_enabled_from_height = Some(0);
    p.governance = Some(sumchain_primitives::governance::GovernanceParams {
        validator_authority_threshold_bps: 5_000,
        quorum_bps: 2_000,
        pass_threshold_bps: 5_000,
        voting_period_blocks: 100,
        max_snapshot_holders: 100,
        proposal_bond: 0,
        treasury: None,
        min_koppa_for_eligibility: 0,
    });
    p
}

fn signed(kp: &KeyPair, nonce: u64, payload: TxPayload) -> SignedTransaction {
    let tx = TransactionV2 {
        chain_id: CHAIN_ID,
        from: kp.address(),
        fee: 100,
        nonce,
        payload,
    };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), kp.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *kp.public_key().as_bytes())
}

fn gov(op: GovernanceOperation, data: Vec<u8>) -> TxPayload {
    TxPayload::Governance(GovernanceTxData { operation: op, data })
}

fn token(op: TokenOperation, token_id: [u8; 32], data: Vec<u8>) -> TxPayload {
    TxPayload::Token(TokenTxData {
        operation: op,
        token_id,
        data,
    })
}

fn mint_data(to: Address, amount: u128) -> Vec<u8> {
    bincode::serialize(&TokenMintData { to, amount }).unwrap()
}

fn create_proposal_req() -> Vec<u8> {
    bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::Src20Token(TOKEN),
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef {
            url: "https://x/pr/1".into(),
            content_hash: [0xAB; 32],
        },
        treasury_beneficiary: None,
        treasury_amount: None,
    })
    .unwrap()
}

/// Seed a mintable token committed, the way genesis would.
fn seed_token(db: &Arc<Database>, owner: Address, holders: &[(Address, u128)]) {
    let ts = TokenStore::new(db);
    ts.put_token(
        &TOKEN,
        &Src20TokenData {
            name: "Routed".into(),
            symbol: "RTD".into(),
            decimals: 0,
            owner,
            total_supply: holders.iter().map(|(_, b)| *b).sum(),
            max_supply: 0,
            mintable: true,
            burnable: true,
            pausable: false,
            paused: false,
            minters: vec![owner],
            created_at: 0,
            created_at_block: 0,
        },
    )
    .unwrap();
    for (a, b) in holders {
        ts.set_balance(&TOKEN, a, *b).unwrap();
    }
}

/// Register the governance asset committed, so proposals can be created.
fn seed_gov_asset(db: &Arc<Database>, create_threshold: u128) {
    GovStore::new(db)
        .put_asset(&sumchain_primitives::governance::GovAsset {
            asset: GovAssetKind::Src20Token(TOKEN),
            create_threshold,
            vote_weight_rule: sumchain_primitives::governance::WeightRule::Linear,
            status: sumchain_primitives::governance::GovAssetStatus::Enabled,
            effective_height: 0,
        })
        .unwrap();
}

/// Canonical rows across every family this package moved.
fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in GTE_CFS {
        for (k, v) in db.prefix_iter(f, &[]).unwrap() {
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// The same, from the candidate.
fn staged(view: &ExecutionView<'_, '_>) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in GTE_CFS {
        for item in view.prefix_iter(f, &[]).unwrap() {
            let (k, v) = item.unwrap();
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

/// The families whose rows actually DIFFER between committed and candidate.
///
/// Not "which families the candidate can see" — `staged` reads the view, and a
/// view merges committed rows with staged ones, so a family the block never
/// touched still appears there. That made an earlier version of these
/// assertions pass while the write they were checking for was deleted. What is
/// wanted is the difference, per family.
fn families_staged(
    committed: &[(String, Vec<u8>, Vec<u8>)],
    candidate: &[(String, Vec<u8>, Vec<u8>)],
) -> std::collections::BTreeSet<String> {
    let of = |rows: &[(String, Vec<u8>, Vec<u8>)], f: &str| -> Vec<(Vec<u8>, Vec<u8>)> {
        rows.iter()
            .filter(|(g, _, _)| g == f)
            .map(|(_, k, v)| (k.clone(), v.clone()))
            .collect()
    };
    GTE_CFS
        .iter()
        .filter(|f| of(candidate, f) != of(committed, f))
        .map(|f| f.to_string())
        .collect()
}

// ── A later transaction observes what an earlier one staged ─────────────────

/// Token mint, then a Governance proposal, in ONE block, through the executor.
///
/// This is the cross-subsystem read that forced a single package, driven the
/// way a block drives it. The proposal's create-threshold check and its frozen
/// vote snapshot both read `cf::TOKEN_BALANCES`; the mint that put the balance
/// there is an earlier transaction of the same block and has committed nothing.
///
/// Set the threshold above the seeded balance and below the post-mint balance,
/// and the proposal can only succeed if governance sees the mint. It is the
/// sequence that proves it, not an accessor: nothing here calls `v_*` to make
/// the state, only to read the result.
#[test]
fn a_proposal_sees_a_mint_from_earlier_in_the_same_block() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let owner = KeyPair::generate();
    let proposer_addr = Address::new([9; 20]);
    common::fund(&db, &owner, 1_000_000);
    seed_token(&db, owner.address(), &[(owner.address(), 40)]);
    // Threshold sits between the seeded 40 and the post-mint 140.
    seed_gov_asset(&db, 100);

    let mut candidate = common::candidate(&db);

    // 1. Mint 100 to the owner. Nothing canonical moves.
    let r = exec
        .execute_tx(
            &mut candidate.view(),
            &signed(
                &owner,
                0,
                token(TokenOperation::Mint, TOKEN, mint_data(owner.address(), 100)),
            ),
            &proposer_addr,
            5,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "mint: {:?}", r.status);
    assert_eq!(
        TokenStore::new(&db).get_balance(&TOKEN, &owner.address()).unwrap(),
        40,
        "the mint staged: canonical balance is still the seeded one"
    );

    // 2. Create a proposal whose threshold only the minted balance meets.
    let r = exec
        .execute_tx(
            &mut candidate.view(),
            &signed(
                &owner,
                1,
                gov(GovernanceOperation::CreateProposal, create_proposal_req()),
            ),
            &proposer_addr,
            5,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "the proposal must see the mint from earlier in this block: {:?}",
        r.status
    );

    // 3. And the frozen snapshot carries the POST-mint weight.
    let pid = sumchain_primitives::governance::generate_proposal_id(
        &owner.address(),
        &GovAssetKind::Src20Token(TOKEN),
        &[0xAB; 32],
        5,
        1,
    );
    assert_eq!(
        gv::v_get_snapshot(&candidate.view(), &pid, &owner.address()).unwrap(),
        Some(140),
        "the snapshot freezes the balance this block produced, not its parent's"
    );
    assert!(
        GovStore::new(&db).get_proposal(&pid).unwrap().is_none(),
        "and none of it is canonical yet"
    );
}

/// The same sequence with the mint removed fails, which is what makes the test
/// above meaningful rather than coincidental.
#[test]
fn without_the_mint_the_same_proposal_is_refused() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let owner = KeyPair::generate();
    common::fund(&db, &owner, 1_000_000);
    seed_token(&db, owner.address(), &[(owner.address(), 40)]);
    seed_gov_asset(&db, 100);

    let mut candidate = common::candidate(&db);
    let r = exec
        .execute_tx(
            &mut candidate.view(),
            &signed(
                &owner,
                0,
                gov(GovernanceOperation::CreateProposal, create_proposal_req()),
            ),
            &Address::new([9; 20]),
            5,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Failed(304)),
        "40 is under the 100 threshold, so without the mint this must fail: {:?}",
        r.status
    );
}

// ── Abandonment, per family, non-vacuously ───────────────────────────────────

/// A Token sequence stages its own families and leaves canonical rows untouched.
///
/// The families are DERIVED from what the block actually staged and asserted to
/// be exactly the token set. An earlier version of this named all nineteen and
/// exercised four; naming a family a test never writes makes the comparison a
/// statement about the fixture rather than about rollback.
#[test]
fn an_abandoned_token_sequence_leaves_canonical_rows_untouched() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let owner = KeyPair::generate();
    let spender = Address::new([0x5B; 20]);
    // A recipient who holds nothing yet: minting to an EXISTING holder leaves
    // the holder index unchanged (the re-add is idempotent), and the family
    // would then not be staged at all — which the assertion below would catch.
    let newcomer = Address::new([0x5C; 20]);
    common::fund(&db, &owner, 1_000_000);
    seed_token(&db, owner.address(), &[(owner.address(), 40)]);
    let before = canonical(&db);

    {
        let mut candidate = common::candidate(&db);
        for (nonce, payload) in [
            (0u64, token(TokenOperation::Mint, TOKEN, mint_data(newcomer, 100))),
            (
                1,
                token(
                    TokenOperation::Approve,
                    TOKEN,
                    bincode::serialize(&TokenApproveData {
                        spender,
                        amount: 25,
                    })
                    .unwrap(),
                ),
            ),
        ] {
            let r = exec
                .execute_tx(
                    &mut candidate.view(),
                    &signed(&owner, nonce, payload),
                    &Address::new([9; 20]),
                    5,
                    1000,
                )
                .unwrap();
            assert!(matches!(r.status, TxStatus::Success), "tx {nonce}: {:?}", r.status);
        }

        let touched = families_staged(&before, &staged(&candidate.view()));
        let expected: std::collections::BTreeSet<String> = [
            cf::TOKENS,
            cf::TOKEN_BALANCES,
            cf::TOKEN_ALLOWANCES,
            cf::TOKEN_HOLDER_INDEX,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            touched, expected,
            "this sequence stages exactly the token families — no more, and no \
             fewer, than the rollback below can prove anything about"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned token sequence must leave every canonical row as it found it"
    );
}

/// A Governance sequence stages its own families and leaves canonical rows
/// untouched.
#[test]
fn an_abandoned_governance_sequence_leaves_canonical_rows_untouched() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let owner = KeyPair::generate();
    common::fund(&db, &owner, 1_000_000);
    seed_token(&db, owner.address(), &[(owner.address(), 500)]);
    seed_gov_asset(&db, 100);
    let before = canonical(&db);

    {
        let mut candidate = common::candidate(&db);
        let r = exec
            .execute_tx(
                &mut candidate.view(),
                &signed(
                    &owner,
                    0,
                    gov(GovernanceOperation::CreateProposal, create_proposal_req()),
                ),
                &Address::new([9; 20]),
                5,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "create: {:?}", r.status);

        let touched = families_staged(&before, &staged(&candidate.view()));
        for required in [cf::GOV_PROPOSALS, cf::GOV_PROPOSAL_INDEX, cf::GOV_SNAPSHOTS] {
            assert!(
                touched.contains(required),
                "creating a proposal must stage {required}; without it the \
                 rollback assertion covers nothing"
            );
        }
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned governance sequence must leave every canonical row as it \
         found it — proposal, proposer index and every frozen snapshot row"
    );
}

// ── A refusal part-way through a routed executor ─────────────────────────────

/// A Token transaction refused mid-write leaves canonical rows untouched.
///
/// The ceiling is measured, not guessed: a disposable candidate runs the SAME
/// transaction to completion and reports what it cost. One byte under that
/// necessarily admits some of its writes and refuses a later one, so the
/// transaction fails with rows already staged — a half-applied mint, which no
/// successful execution produces.
///
/// The error is checked to name the limit, so a validation failure before any
/// write could not pass for this.
#[test]
fn a_token_transaction_refused_mid_write_leaves_canonical_rows_untouched() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let owner = KeyPair::generate();
    common::fund(&db, &owner, 1_000_000);
    seed_token(&db, owner.address(), &[(owner.address(), 40)]);
    let before = canonical(&db);
    let tx = signed(
        &owner,
        0,
        token(TokenOperation::Mint, TOKEN, mint_data(owner.address(), 100)),
    );

    // What the whole transaction costs.
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            exec.execute_tx(&mut view, &tx, &Address::new([9; 20]), 5, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "the transaction must cost something");

    {
        // One byte short: some writes land, a later one cannot.
        let mut overlay = ApplicationOverlay::new(&db, full - 1);
        let mut view = ExecutionView::new(&mut overlay);
        let err = exec
            .execute_tx(&mut view, &tx, &Address::new([9; 20]), 5, 1000)
            .expect_err("the transaction must be refused");
        assert!(
            err.to_string().contains("limit"),
            "it must fail because a WRITE was refused, not before writing \
             anything: {err}"
        );
        assert!(
            !families_staged(&before, &staged(&view)).is_empty(),
            "and it must fail AFTER staging something, or this proves nothing \
             about a half-applied transaction. Compared against committed, not \
             merely non-empty: the view merges committed rows, so `!is_empty()` \
             would hold even if the transaction had staged nothing at all"
        );
    }

    assert_eq!(
        canonical(&db),
        before,
        "a transaction refused part-way must leave every canonical row as it \
         found it"
    );
}

// ── Equity, and the governance read that crosses into it ────────────────────

const CLASS: [u8; 32] = [0x2C; 32];

fn seed_equity_class(db: &Arc<Database>, controller: Address, holders: &[([u8; 32], u64)]) {
    use sumchain_primitives::equity::{EquityToken, ShareClassType, TokenStatus};
    let equity = sumchain_storage::EquityStore::new(db);
    equity
        .tokens()
        .put(&EquityToken {
            issuer_subject: [1u8; 32],
            class_id: CLASS,
            share_class_type: ShareClassType::Common,
            name: "Common".into(),
            symbol: "ACME-A".into(),
            authorized_shares: 1_000_000,
            issued_shares: 0,
            votes_per_share: 1,
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

fn equity_class_approval(v: &KeyPair) -> sumchain_primitives::ValidatorApproval {
    let msg = sumchain_primitives::validator_authority::register_equity_class_signing_bytes(
        CHAIN_ID, &CLASS, 0, 0,
    );
    sumchain_primitives::ValidatorApproval {
        pubkey: *v.public_key().as_bytes(),
        signature: sign(&msg, v.private_key()).to_bytes(),
    }
}

fn register_equity_class(
    view: &mut ExecutionView<'_, '_>,
    exec: &sumchain_state::executor::BlockExecutor,
    submitter: &KeyPair,
    v: &KeyPair,
    vset: &[[u8; 32]],
    nonce: u64,
) -> TxStatus {
    let req = bincode::serialize(&sumchain_primitives::governance::RegisterEquityClassRequest {
        class_id: CLASS,
        create_threshold: 0,
        effective_height: 0,
        approvals: vec![equity_class_approval(v)],
    })
    .unwrap();
    exec.execute_tx_with_validators(
        view,
        &signed(submitter, nonce, gov(GovernanceOperation::RegisterEquityClass, req)),
        &Address::new([9; 20]),
        1,
        1000,
        vset,
    )
    .unwrap()
    .status
}

fn create_equity_proposal(
    view: &mut ExecutionView<'_, '_>,
    exec: &sumchain_state::executor::BlockExecutor,
    proposer: &KeyPair,
    nonce: u64,
    height: u64,
) -> [u8; 32] {
    let req = bincode::serialize(&CreateProposalRequest {
        asset: GovAssetKind::EquityClass(CLASS),
        class: GovProposalClass::RoutineProcess,
        execution_kind: ExecutionKind::RecordOnly,
        external_ref: ExternalRef {
            url: "https://x/pr/1".into(),
            content_hash: [0xAB; 32],
        },
        treasury_beneficiary: None,
        treasury_amount: None,
    })
    .unwrap();
    let r = exec
        .execute_tx(
            view,
            &signed(proposer, nonce, gov(GovernanceOperation::CreateProposal, req)),
            &Address::new([9; 20]),
            height,
            1000,
        )
        .unwrap();
    assert!(
        matches!(r.status, TxStatus::Success),
        "create equity proposal: {:?}",
        r.status
    );
    sumchain_primitives::governance::generate_proposal_id(
        &proposer.address(),
        &GovAssetKind::EquityClass(CLASS),
        &[0xAB; 32],
        height,
        nonce,
    )
}

fn equity_mint(class_id: [u8; 32], to_commitment: [u8; 32], amount: u64) -> TxPayload {
    #[derive(serde::Serialize)]
    struct MintData {
        class_id: [u8; 32],
        to_commitment: [u8; 32],
        amount: u64,
    }
    TxPayload::Equity(sumchain_primitives::equity::EquityTxData {
        operation: sumchain_primitives::equity::EquityOperation::Mint,
        data: bincode::serialize(&MintData {
            class_id,
            to_commitment,
            amount,
        })
        .unwrap(),
        recipient: Address::ZERO,
    })
}

/// An equity mint is frozen into a GOVERNANCE proposal's root, same block.
///
/// The earlier version of this stopped at `v_equity_balances_root`: it proved
/// the accessor saw staged shares, not that a later Governance transaction used
/// them. That is the whole claim of the package, so the sequence now runs all
/// the way through — Equity mint, RegisterEquityClass, CreateProposal — as real
/// transactions in one block.
///
/// A proposal freezes this root and keeps it for life. Computed from committed
/// storage in a block that had already minted, it would bind every later equity
/// vote to a holder set the chain no longer has, and unlike a balance a frozen
/// root is never recomputed, so the divergence is permanent.
///
/// The expected value is what the COMMITTED path produces for the post-mint
/// holder set in a second database. Asserting only that the root moved would be
/// satisfied by any wrong root, the empty one included.
#[test]
fn a_proposal_freezes_the_equity_root_including_a_mint_from_this_block() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let controller = KeyPair::generate();
    let submitter = KeyPair::generate();
    let proposer = KeyPair::generate();
    let holder = [0x3D; 32];
    let newcomer = [0x3E; 32];
    for kp in [&controller, &submitter, &proposer] {
        common::fund(&db, kp, 1_000_000);
    }
    seed_equity_class(&db, controller.address(), &[(holder, 10)]);
    let parent_root = sumchain_storage::equity_balances_root(&db, &CLASS).unwrap();

    let mut candidate = common::candidate(&db);

    let r = exec
        .execute_tx(
            &mut candidate.view(),
            &signed(&controller, 0, equity_mint(CLASS, newcomer, 90)),
            &Address::new([9; 20]),
            5,
            1000,
        )
        .unwrap();
    assert!(matches!(r.status, TxStatus::Success), "mint: {:?}", r.status);

    assert!(
        matches!(
            register_equity_class(&mut candidate.view(), &exec, &submitter, &v, &vset, 0),
            TxStatus::Success
        ),
        "register equity class"
    );

    let pid = create_equity_proposal(&mut candidate.view(), &exec, &proposer, 0, 5);
    let frozen = gv::v_get_equity_class_root(&candidate.view(), &pid)
        .unwrap()
        .expect("the proposal must freeze a root");

    let expected = {
        let dir = tempfile::TempDir::new().unwrap();
        let db2 = Arc::new(Database::open_default(dir.path()).unwrap());
        seed_equity_class(&db2, controller.address(), &[(holder, 10), (newcomer, 90)]);
        sumchain_storage::equity_balances_root(&db2, &CLASS).unwrap()
    };

    assert_eq!(
        frozen.balances_root, expected,
        "the proposal must freeze the root over the shares THIS BLOCK minted"
    );
    assert_ne!(frozen.balances_root, parent_root, "and not the parent's root");
    assert_eq!(
        sumchain_storage::equity_balances_root(&db, &CLASS).unwrap(),
        parent_root,
        "while committed storage is unmoved: nothing was published"
    );
}

/// The same sequence WITHOUT the mint freezes the parent's root instead.
///
/// The discriminator. Without it the test above would pass even if governance
/// read committed storage, because the frozen root would then be the parent's
/// and nothing would say which of the two it was supposed to be.
#[test]
fn without_the_mint_the_proposal_freezes_the_parent_root() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let v = KeyPair::generate();
    let vset = [*v.public_key().as_bytes()];
    let controller = KeyPair::generate();
    let submitter = KeyPair::generate();
    let proposer = KeyPair::generate();
    let holder = [0x3D; 32];
    let newcomer = [0x3E; 32];
    for kp in [&controller, &submitter, &proposer] {
        common::fund(&db, kp, 1_000_000);
    }
    seed_equity_class(&db, controller.address(), &[(holder, 10)]);
    let parent_root = sumchain_storage::equity_balances_root(&db, &CLASS).unwrap();

    let mut candidate = common::candidate(&db);
    assert!(
        matches!(
            register_equity_class(&mut candidate.view(), &exec, &submitter, &v, &vset, 0),
            TxStatus::Success
        ),
        "register equity class"
    );
    let pid = create_equity_proposal(&mut candidate.view(), &exec, &proposer, 0, 5);
    let frozen = gv::v_get_equity_class_root(&candidate.view(), &pid)
        .unwrap()
        .unwrap();

    assert_eq!(
        frozen.balances_root, parent_root,
        "with no mint in the block, the frozen root is the parent's"
    );

    let post_mint = {
        let dir = tempfile::TempDir::new().unwrap();
        let db2 = Arc::new(Database::open_default(dir.path()).unwrap());
        seed_equity_class(&db2, controller.address(), &[(holder, 10), (newcomer, 90)]);
        sumchain_storage::equity_balances_root(&db2, &CLASS).unwrap()
    };
    assert_ne!(
        parent_root, post_mint,
        "the two roots must differ, or neither test discriminates anything"
    );
}

/// An abandoned Equity sequence stages its own families and leaves canonical
/// rows untouched.
#[test]
fn an_abandoned_equity_sequence_leaves_canonical_rows_untouched() {
    let (_state, db, _dir, exec) = setup_with_params(gov_params());
    let controller = KeyPair::generate();
    let holder = [0x4E; 32];
    // A commitment with no prior shares, for the same reason as the token case.
    let newcomer = [0x4F; 32];
    common::fund(&db, &controller, 1_000_000);
    seed_equity_class(&db, controller.address(), &[(holder, 10)]);
    let before = canonical(&db);

    {
        let mut candidate = common::candidate(&db);
        let r = exec
            .execute_tx(
                &mut candidate.view(),
                &signed(&controller, 0, equity_mint(CLASS, newcomer, 90)),
                &Address::new([9; 20]),
                5,
                1000,
            )
            .unwrap();
        assert!(matches!(r.status, TxStatus::Success), "mint: {:?}", r.status);

        let touched = families_staged(&before, &staged(&candidate.view()));
        for required in [cf::EQUITY_BALANCES, cf::EQUITY_TOKENS, cf::EQUITY_HOLDER_INDEX] {
            assert!(
                touched.contains(required),
                "an equity mint must stage {required}; without it the rollback \
                 assertion below covers nothing"
            );
        }
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned equity sequence must leave every canonical row as it \
         found it — the balance, the class row and the holder index together"
    );
}
