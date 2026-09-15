//! Policy accounts execute against the block's candidate.
//!
//! These drive `BlockExecutor::execute_tx` — real signed transactions, in
//! sequence, in one block — rather than calling the view accessors directly.
//! An accessor test proves the accessor; only a transaction sequence proves
//! that a later transaction sees what an earlier one staged, which is what the
//! package is for.
//!
//! ## What was wrong before this
//!
//! `execute_proposal` had TWO commit points inside one transaction. The wrapped
//! action — a native transfer, or one of the five allowlisted token admin ops —
//! staged into the block's candidate, while the policy account's nonce
//! increment and the proposal's `Executed` status were written straight to
//! RocksDB. An abandoned block kept the second and lost the first: a proposal
//! marked executed, a policy nonce advanced past it, and no transfer.
//! `a_wrapped_token_op_and_its_policy_rows_vanish_together` is that case.

mod common;

use common::{fund, setup_with_params, CHAIN_ID};
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::policy_account::{
    MemberApproval, PolicyAccount, PolicyAccountOperation, PolicyAccountTxData, PolicyConfig,
    PolicyMember, PolicyProfile, Proposal, ProposalStatus,
};
use sumchain_primitives::{
    Address, Hash, SignedTransaction, TokenOperation, TokenTxData, TransactionV2, TxPayload,
};
use sumchain_state::policy_account_executor::{
    CreatePolicyAccountRequest, ExecuteProposalRequest, SubmitProposalRequest,
};
use sumchain_state::PolicyAccountExecutor;
use sumchain_storage::exec_view::ExecutionView;
use sumchain_storage::overlay::ApplicationOverlay;
use sumchain_storage::{cf, Database, PolicyAccountStorage};

/// Both families this unit moved.
const POLICY_CFS: &[&str] = &[cf::POLICY_ACCOUNTS, cf::POLICY_PROPOSALS];

const TOKEN: [u8; 32] = [0x5C; 32];

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

fn policy(op: PolicyAccountOperation, payload: &impl serde::Serialize) -> TxPayload {
    TxPayload::PolicyAccount(PolicyAccountTxData {
        operation: op,
        data: bincode::serialize(payload).unwrap(),
        recipient: Address::ZERO,
    })
}

fn create_req(member: &KeyPair, salt: u8) -> CreatePolicyAccountRequest {
    CreatePolicyAccountRequest {
        members: vec![PolicyMember::new(member.address())],
        policy: PolicyConfig {
            profile: PolicyProfile::Personal,
            overrides: vec![],
        },
        salt: vec![salt; 32],
    }
}

fn account_id(member: &KeyPair, salt: u8) -> [u8; 32] {
    PolicyAccount::compute_id(&[PolicyMember::new(member.address())], &[salt; 32])
}

/// An approval by `member` over `action`, signed the way the executor verifies
/// it — the shared `approval_signing_bytes`, not a message shape restated here.
fn approval(
    member: &KeyPair,
    id: &[u8; 32],
    action: &TxPayload,
    policy_nonce: u64,
) -> MemberApproval {
    let action_hash = Hash::hash(&bincode::serialize(action).unwrap());
    let msg = Proposal::approval_signing_bytes(id, &action_hash, policy_nonce);
    MemberApproval {
        approver: member.address(),
        approver_pubkey: *member.public_key().as_bytes(),
        signature: *sign(&msg, member.private_key()).as_bytes(),
        timestamp: 0,
    }
}

/// Canonical rows across both families.
fn canonical(db: &Database) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for f in POLICY_CFS {
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
    for f in POLICY_CFS {
        for item in view.prefix_iter(f, &[]).unwrap() {
            let (k, v) = item.unwrap();
            out.push((f.to_string(), k.to_vec(), v.to_vec()));
        }
    }
    out.sort();
    out
}

// ── Same-block visibility ────────────────────────────────────────────────────

/// A proposal submitted against a policy account created earlier in the SAME
/// block finds it.
///
/// The create stages the account row now. If the submit still read committed
/// state it would answer "Policy account not found" for an account this block
/// had already created.
#[test]
fn a_proposal_finds_a_policy_account_created_earlier_in_the_same_block() {
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    {
        let mut view = ExecutionView::new(&mut overlay);

        let create = signed(
            &m,
            0,
            policy(PolicyAccountOperation::Create, &create_req(&m, 1)),
        );
        let r0 = executor
            .execute_tx(&mut view, &create, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r0.status, sumchain_primitives::TxStatus::Success),
            "create must succeed: {:?}",
            r0.status
        );

        let action = TxPayload::Transfer {
            to: Address::new([7; 20]),
            amount: 1,
        };
        let id_for_approval = account_id(&m, 1);
        let req = SubmitProposalRequest {
            policy_account_id: id_for_approval,
            action_payload: bincode::serialize(&action).unwrap(),
            approvals: vec![approval(&m, &id_for_approval, &action, 0)],
            expires_at: 4_000_000_000_000,
        };
        let submit = signed(&m, 1, policy(PolicyAccountOperation::SubmitProposal, &req));
        let r1 = executor
            .execute_tx(&mut view, &submit, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(r1.status, sumchain_primitives::TxStatus::Success),
            "the proposal must find the account this block created: {:?}",
            r1.status
        );
    }
    // Nothing committed: the candidate went out of scope unpublished.
    let _ = state;
    assert!(
        canonical(&db).is_empty(),
        "executing must not commit policy rows"
    );
}

/// Without the create, the same submit is refused.
///
/// The discriminator for the test above: it would pass on any block in which
/// submits happen to succeed.
#[test]
fn without_the_create_the_same_proposal_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    let action = TxPayload::Transfer {
        to: Address::new([7; 20]),
        amount: 1,
    };
    let id_for_approval = account_id(&m, 1);
    let req = SubmitProposalRequest {
        policy_account_id: id_for_approval,
        action_payload: bincode::serialize(&action).unwrap(),
        approvals: vec![approval(&m, &id_for_approval, &action, 0)],
        expires_at: 4_000_000_000_000,
    };
    let submit = signed(&m, 0, policy(PolicyAccountOperation::SubmitProposal, &req));
    let r = executor
        .execute_tx(&mut view, &submit, &proposer, 1, 1000)
        .unwrap();
    assert!(
        !matches!(r.status, sumchain_primitives::TxStatus::Success),
        "a proposal against an account that does not exist must be refused"
    );
    assert!(staged(&view).is_empty(), "and it must stage nothing at all");
}

/// Two creations of the same policy account in one block: the second is
/// refused.
///
/// The duplicate guard is a READ, and it used to be a committed read that was
/// only correct because the first create had already committed. It reads the
/// candidate now.
#[test]
fn a_duplicate_create_in_the_same_block_is_refused() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);

    let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
    let mut view = ExecutionView::new(&mut overlay);

    for (nonce, expect_success) in [(0u64, true), (1u64, false)] {
        let tx = signed(
            &m,
            nonce,
            policy(PolicyAccountOperation::Create, &create_req(&m, 1)),
        );
        let r = executor
            .execute_tx(&mut view, &tx, &proposer, 1, 1000)
            .unwrap();
        assert_eq!(
            matches!(r.status, sumchain_primitives::TxStatus::Success),
            expect_success,
            "create at nonce {nonce} should {}have succeeded",
            if expect_success { "" } else { "not " }
        );
    }

    let rows = staged(&view);
    assert_eq!(
        rows.iter()
            .filter(|(f, _, _)| f == cf::POLICY_ACCOUNTS)
            .count(),
        1,
        "the duplicate must not leave a second row"
    );
}

// ── Abandonment ──────────────────────────────────────────────────────────────

/// A dropped block leaves no policy rows, having staged several.
#[test]
fn an_abandoned_block_leaves_no_policy_rows() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let create = signed(
            &m,
            0,
            policy(PolicyAccountOperation::Create, &create_req(&m, 2)),
        );
        executor
            .execute_tx(&mut view, &create, &proposer, 1, 1000)
            .unwrap();

        let action = TxPayload::Transfer {
            to: Address::new([7; 20]),
            amount: 1,
        };
        let id_for_approval = account_id(&m, 2);
        let req = SubmitProposalRequest {
            policy_account_id: id_for_approval,
            action_payload: bincode::serialize(&action).unwrap(),
            approvals: vec![approval(&m, &id_for_approval, &action, 0)],
            expires_at: 4_000_000_000_000,
        };
        let submit = signed(&m, 1, policy(PolicyAccountOperation::SubmitProposal, &req));
        executor
            .execute_tx(&mut view, &submit, &proposer, 1, 1000)
            .unwrap();

        // Both families are staged: the assertion below is about losing
        // something, so there has to be something to lose.
        let rows = staged(&view);
        assert!(
            rows.iter().any(|(f, _, _)| f == cf::POLICY_ACCOUNTS)
                && rows.iter().any(|(f, _, _)| f == cf::POLICY_PROPOSALS),
            "the block must have staged both families: {rows:?}"
        );
        // dropped
    }

    assert_eq!(
        canonical(&db),
        before,
        "an abandoned block must leave every policy row as it found it"
    );
}

// ── The defect this unit removes ─────────────────────────────────────────────

/// A wrapped token op and the policy rows that authorise it vanish together.
///
/// This is the split commit point. The token op has staged into the candidate
/// since the governance/token/equity package; the policy nonce and the
/// proposal's `Executed` status were still committed directly. Abandoning the
/// block used to keep the second and lose the first.
#[test]
fn a_wrapped_token_op_and_its_policy_rows_vanish_together() {
    use sumchain_storage::schema::{Src20TokenData, TokenStore};

    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);
    let id = account_id(&m, 3);
    let pa_address = PolicyAccount::id_to_address(&id);

    // A token the policy account owns, committed the way genesis would.
    TokenStore::new(&db)
        .put_token(
            &TOKEN,
            &Src20TokenData {
                name: "Policy".into(),
                symbol: "POL".into(),
                decimals: 0,
                owner: pa_address,
                total_supply: 0,
                max_supply: 0,
                mintable: true,
                burnable: true,
                pausable: true,
                paused: false,
                minters: vec![pa_address],
                created_at: 0,
                created_at_block: 0,
            },
        )
        .unwrap();
    let token_before = db.get(cf::TOKENS, &TOKEN).unwrap();
    let policy_before = canonical(&db);

    {
        let mut overlay = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        let mut view = ExecutionView::new(&mut overlay);

        let create = signed(
            &m,
            0,
            policy(PolicyAccountOperation::Create, &create_req(&m, 3)),
        );
        executor
            .execute_tx(&mut view, &create, &proposer, 1, 1000)
            .unwrap();

        // Pause: one of the five allowlisted admin ops.
        let action = TxPayload::Token(TokenTxData {
            operation: TokenOperation::Pause,
            token_id: TOKEN,
            data: vec![],
        });
        let id_for_approval = id;
        let req = SubmitProposalRequest {
            policy_account_id: id,
            action_payload: bincode::serialize(&action).unwrap(),
            approvals: vec![approval(&m, &id_for_approval, &action, 0)],
            expires_at: 4_000_000_000_000,
        };
        let submit = signed(&m, 1, policy(PolicyAccountOperation::SubmitProposal, &req));
        let rs = executor
            .execute_tx(&mut view, &submit, &proposer, 1, 1000)
            .unwrap();
        assert!(matches!(rs.status, sumchain_primitives::TxStatus::Success));

        let pid = {
            let p = PolicyAccountExecutor::v_get_proposal(&view, &{
                // The proposal id the submit produced, recomputed from the
                // candidate rather than parsed out of a receipt.
                let mut found = [0u8; 32];
                for item in view.prefix_iter(cf::POLICY_PROPOSALS, &[]).unwrap() {
                    let (k, _) = item.unwrap();
                    found.copy_from_slice(&k);
                }
                found
            })
            .unwrap();
            p.expect("the submit staged a proposal").id
        };

        let exec_tx = signed(
            &m,
            2,
            policy(
                PolicyAccountOperation::ExecuteProposal,
                &ExecuteProposalRequest { proposal_id: pid },
            ),
        );
        let re = executor
            .execute_tx(&mut view, &exec_tx, &proposer, 1, 1000)
            .unwrap();
        assert!(
            matches!(re.status, sumchain_primitives::TxStatus::Success),
            "the wrapped pause must execute: {:?}",
            re.status
        );

        // Inside the block: the token is paused, the proposal is Executed and
        // the policy nonce has advanced. All three in the candidate.
        let account = PolicyAccountExecutor::v_get_policy_account(&view, &id)
            .unwrap()
            .expect("account staged");
        assert_eq!(account.nonce, 1, "the policy nonce advanced");
        let proposal = PolicyAccountExecutor::v_get_proposal(&view, &pid)
            .unwrap()
            .expect("proposal staged");
        assert_eq!(proposal.status, ProposalStatus::Executed);
        let staged_token = view.get(cf::TOKENS, &TOKEN).unwrap().unwrap();
        assert_ne!(
            Some(staged_token),
            token_before,
            "and the token row changed in the candidate"
        );
        // dropped
    }

    // Outside it: none of the three.
    assert_eq!(
        db.get(cf::TOKENS, &TOKEN).unwrap(),
        token_before,
        "the token must be untouched by an abandoned block"
    );
    assert_eq!(
        canonical(&db),
        policy_before,
        "and so must the policy rows that authorised it — the nonce and the \
         Executed status used to survive here while the token op did not"
    );
}

// ── Limit refusal ────────────────────────────────────────────────────────────

/// A create refused by the candidate's ceiling leaves no policy row.
#[test]
fn a_create_refused_by_the_ceiling_leaves_no_policy_row() {
    let (_state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let proposer = Address::new([9; 20]);
    let before = canonical(&db);
    let tx = signed(
        &m,
        0,
        policy(PolicyAccountOperation::Create, &create_req(&m, 4)),
    );

    // What the whole transaction costs.
    let full = {
        let mut scratch = ApplicationOverlay::new(&db, common::TEST_CANDIDATE_LIMIT);
        {
            let mut view = ExecutionView::new(&mut scratch);
            executor
                .execute_tx(&mut view, &tx, &proposer, 1, 1000)
                .unwrap();
        }
        scratch.logical_bytes()
    };
    assert!(full > 1, "a create must cost something");

    for ceiling in [1u64, full / 2, full - 1] {
        let mut overlay = ApplicationOverlay::new(&db, ceiling);
        let mut view = ExecutionView::new(&mut overlay);
        let outcome = executor.execute_tx(&mut view, &tx, &proposer, 1, 1000);
        assert!(outcome.is_err(), "ceiling {ceiling} must refuse");
        let err = outcome.unwrap_err().to_string();
        assert!(
            err.contains("limit"),
            "it must fail because a WRITE was refused: {err}"
        );
        assert_eq!(
            canonical(&db),
            before,
            "a refusal at ceiling {ceiling} must leave every policy row as it \
             found it"
        );
    }
}

// ── Index parity ─────────────────────────────────────────────────────────────

/// What the candidate writes is what the committed scans expect.
///
/// The RPC's policy-account lookups are scans over these two families —
/// `get_by_address`, `list_by_policy_account`, `list_pending` — not secondary
/// index rows. So index parity here means: a row staged through the candidate
/// and then published is found by every one of those scans, at the same id and
/// with the same contents. A key or codec that drifted on the candidate side
/// would round-trip through itself and fail exactly here.
#[test]
fn published_rows_satisfy_the_committed_scans() {
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let m = KeyPair::generate();
    fund(&db, &m, 10_000_000);
    let id = account_id(&m, 5);

    let action = TxPayload::Transfer {
        to: Address::new([7; 20]),
        amount: 1,
    };
    let id_for_approval = id;
    let req = SubmitProposalRequest {
        policy_account_id: id,
        action_payload: bincode::serialize(&action).unwrap(),
        approvals: vec![approval(&m, &id_for_approval, &action, 0)],
        expires_at: 4_000_000_000_000,
    };
    let receipts = common::publish_block(
        &state,
        &executor,
        1,
        &[3u8; 32],
        vec![
            signed(
                &m,
                0,
                policy(PolicyAccountOperation::Create, &create_req(&m, 5)),
            ),
            signed(&m, 1, policy(PolicyAccountOperation::SubmitProposal, &req)),
        ],
        &[],
    );
    assert!(
        receipts
            .iter()
            .all(|r| matches!(r.status, sumchain_primitives::TxStatus::Success)),
        "both transactions must succeed: {:?}",
        receipts.iter().map(|r| r.status).collect::<Vec<_>>()
    );

    let storage = PolicyAccountStorage::new(&db);
    let accounts = storage.policy_accounts();

    // The point lookup, by id.
    let account = accounts
        .get(&id)
        .unwrap()
        .expect("the published account must be readable at its id");
    assert_eq!(account.id, id);
    assert_eq!(account.address, PolicyAccount::id_to_address(&id));

    // The address scan — the RPC's `policy_account_by_address`.
    assert_eq!(
        accounts
            .get_by_address(&PolicyAccount::id_to_address(&id))
            .unwrap()
            .map(|a| a.id),
        Some(id),
        "the address scan must find it"
    );
    // The membership scan.
    assert_eq!(
        accounts
            .list_by_member(&m.address())
            .unwrap()
            .iter()
            .map(|a| a.id)
            .collect::<Vec<_>>(),
        vec![id],
        "the member scan must find it"
    );

    // And the proposal scans.
    let proposals = storage.proposals();
    let listed = proposals.list_by_policy_account(&id).unwrap();
    assert_eq!(listed.len(), 1, "the proposal scan must find it");
    assert_eq!(listed[0].policy_account_id, id);
    assert_eq!(
        proposals.list_pending(&id).unwrap().len(),
        1,
        "and it must still be pending"
    );
    assert_eq!(
        proposals
            .list_by_proposer(&m.address())
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
        listed.iter().map(|p| p.id).collect::<Vec<_>>(),
        "the proposer scan must agree with the account scan"
    );
}
