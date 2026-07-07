//! Focused tests for policy-account governance (issue #23).
//!
//! Rewritten against the current API. Covers the surface made usable in the
//! "policy accounts public surface" work: approval signature verification,
//! fail-closed wrapped-action execution, fee/submitter-nonce accounting, and
//! the policy-native + native-transfer execution paths, plus cancel and
//! pending-proposal listing.
//!
//! Not rebuilt from the old (stale) harness — older scenarios (weighted DAO
//! voting, expiration, non-member rejection, duplicate-approval) are noted in
//! the PR body as deferred future coverage.

mod common;
use common::{fund, setup_with_params, CHAIN_ID};

use std::sync::Arc;
use sumchain_crypto::{sign, KeyPair};
use sumchain_genesis::ChainParams;
use sumchain_primitives::{
    policy_account::{
        MemberApproval, PolicyAccount, PolicyAccountOperation, PolicyAccountStatus,
        PolicyAccountTxData, PolicyConfig, PolicyMember, PolicyProfile, Proposal, ProposalStatus,
    },
    Address, Hash, SignedTransaction, TransactionV2, TxPayload, TxStatus,
};
use sumchain_state::{
    policy_account_executor::{
        CreatePolicyAccountRequest, ExecuteProposalRequest, ModifyMembershipRequest,
        ModifyPolicyRequest, SubmitProposalRequest,
    },
    PolicyAccountExecutionResult, PolicyAccountExecutor, StateManager,
};
use sumchain_storage::{schema::AccountState, Database, PolicyAccountStorage};

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn kp() -> KeyPair {
    KeyPair::generate()
}

fn zero_addr() -> Address {
    Address::new([0u8; 20])
}

/// A single-member Personal policy account, put directly into storage and its
/// controlled address funded with `balance`. A single member keeps approval
/// thresholds trivially satisfiable for execution-path tests.
fn put_account(db: &Arc<Database>, state: &StateManager, member: &KeyPair, balance: u128) -> PolicyAccount {
    let members = vec![PolicyMember::new(member.address())];
    let salt = vec![7u8; 32];
    let id = PolicyAccount::compute_id(&members, &salt);
    let address = PolicyAccount::id_to_address(&id);
    let account = PolicyAccount {
        id,
        address,
        members,
        policy: PolicyConfig { profile: PolicyProfile::Personal, overrides: vec![] },
        nonce: 0,
        status: PolicyAccountStatus::Active,
        created_at: 0,
        created_timestamp: 0,
    };
    PolicyAccountStorage::new(db).policy_accounts().put(&account).unwrap();
    if balance > 0 {
        state.put_account(&address, &AccountState { balance, nonce: 0 }).unwrap();
    }
    account
}

/// Sign an approval over the canonical signing bytes.
fn approve(
    account: &PolicyAccount,
    action_hash: &Hash,
    policy_nonce: u64,
    signer: &KeyPair,
    pubkey_override: Option<[u8; 32]>,
    corrupt: bool,
) -> MemberApproval {
    let msg = Proposal::approval_signing_bytes(&account.id, action_hash, policy_nonce);
    let mut sig = *sign(&msg, signer.private_key()).as_bytes();
    if corrupt {
        sig[0] ^= 0xff;
    }
    MemberApproval {
        approver: signer.address(),
        approver_pubkey: pubkey_override.unwrap_or(*signer.public_key().as_bytes()),
        signature: sig,
        timestamp: 0,
    }
}

fn tx_data(op: PolicyAccountOperation, payload: &impl serde::Serialize) -> PolicyAccountTxData {
    PolicyAccountTxData {
        operation: op,
        data: bincode::serialize(payload).unwrap(),
        recipient: zero_addr(),
    }
}

/// Submit `action` as a proposal with the given approvals.
fn submit(
    pe: &PolicyAccountExecutor,
    state: &StateManager,
    account: &PolicyAccount,
    sender: &KeyPair,
    action: &TxPayload,
    approvals: Vec<MemberApproval>,
) -> PolicyAccountExecutionResult {
    let action_payload = bincode::serialize(action).unwrap();
    let req = SubmitProposalRequest {
        policy_account_id: account.id,
        action_payload,
        approvals,
        expires_at: 4_000_000_000_000,
    };
    let data = tx_data(PolicyAccountOperation::SubmitProposal, &req);
    pe.execute(&sender.address(), &data, state, &zero_addr(), 0, 1, 1000).unwrap()
}

fn exec(
    pe: &PolicyAccountExecutor,
    state: &StateManager,
    sender: &KeyPair,
    proposal_id: [u8; 32],
) -> PolicyAccountExecutionResult {
    let req = ExecuteProposalRequest { proposal_id };
    let data = tx_data(PolicyAccountOperation::ExecuteProposal, &req);
    pe.execute(&sender.address(), &data, state, &zero_addr(), 0, 2, 2000).unwrap()
}

fn action_hash(action: &TxPayload) -> Hash {
    Hash::hash(&bincode::serialize(action).unwrap())
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[test]
fn create_policy_account() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let req = CreatePolicyAccountRequest {
        members: vec![PolicyMember::new(m.address())],
        policy: PolicyConfig { profile: PolicyProfile::Personal, overrides: vec![] },
        salt: vec![1u8; 32],
    };
    let data = tx_data(PolicyAccountOperation::Create, &req);
    let res = pe.execute(&m.address(), &data, &state, &zero_addr(), 0, 1, 1000).unwrap();
    assert!(res.success, "create failed: {}", res.message);
    let id = PolicyAccount::compute_id(&[PolicyMember::new(m.address())], &[1u8; 32]);
    assert!(PolicyAccountStorage::new(&db).policy_accounts().get(&id).unwrap().is_some());
}

#[test]
fn submit_with_valid_approval_succeeds() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let action = TxPayload::Transfer { to: zero_addr(), amount: 1 };
    let approval = approve(&account, &action_hash(&action), 0, &m, None, false);
    let res = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(res.success, "submit failed: {}", res.message);
}

#[test]
fn forged_approval_rejected() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let action = TxPayload::Transfer { to: zero_addr(), amount: 1 };
    // Corrupt the signature.
    let approval = approve(&account, &action_hash(&action), 0, &m, None, true);
    let res = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(!res.success, "forged approval must be rejected");
}

#[test]
fn approval_pubkey_address_mismatch_rejected() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let action = TxPayload::Transfer { to: zero_addr(), amount: 1 };
    // Valid signature by `m`, but advertise a different (attacker) pubkey that
    // does not hash to the approver address.
    let attacker = kp();
    let approval = approve(&account, &action_hash(&action), 0, &m, Some(*attacker.public_key().as_bytes()), false);
    let res = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(!res.success, "pubkey/address mismatch must be rejected");
}

#[test]
fn transfer_native_executes_from_policy_account() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 1_000);
    let to = kp().address();
    let action = TxPayload::Transfer { to, amount: 100 };
    let ah = action_hash(&action);
    let approval = approve(&account, &ah, 0, &m, None, false);
    let sres = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(sres.success, "submit failed: {}", sres.message);
    let pid = Proposal::compute_id(&account.id, 0, &ah);
    let eres = exec(&pe, &state, &m, pid);
    assert!(eres.success, "execute failed: {}", eres.message);
    assert_eq!(state.get_balance(&to).unwrap(), 100, "funds did not move");
    let updated = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert_eq!(updated.nonce, 1, "policy nonce should advance on success");
}

// --------------------------------------------------------------------------
// Governance v2 (#90): Policy-Account token-admin op dispatch
// --------------------------------------------------------------------------

use sumchain_primitives::{TokenOperation, TokenTxData};
use sumchain_primitives::token_ops::{TokenMinterData, TokenTransferOwnershipData};
use sumchain_storage::schema::Src20TokenData;
use sumchain_storage::TokenStore;

const PA_TOKEN: [u8; 32] = [0x7A; 32];

/// Seed a pausable/mintable SRC-20 owned by `owner`.
fn seed_pa_token(db: &Arc<Database>, owner: Address, paused: bool, minters: Vec<Address>) {
    TokenStore::new(db)
        .put_token(
            &PA_TOKEN,
            &Src20TokenData {
                name: "PA".into(),
                symbol: "PA".into(),
                decimals: 0,
                owner,
                total_supply: 0,
                max_supply: 0,
                mintable: true,
                burnable: false,
                pausable: true,
                paused,
                minters,
                created_at: 0,
                created_at_block: 0,
            },
        )
        .unwrap();
}

/// Submit + execute a wrapped Token op through the policy account. Returns the
/// execute result.
fn run_token_op(
    pe: &PolicyAccountExecutor,
    state: &StateManager,
    account: &PolicyAccount,
    m: &KeyPair,
    op: TokenOperation,
    data: Vec<u8>,
) -> PolicyAccountExecutionResult {
    let action = TxPayload::Token(TokenTxData { token_id: PA_TOKEN, operation: op, data });
    let ah = action_hash(&action);
    let approval = approve(account, &ah, account.nonce, m, None, false);
    let sres = submit(pe, state, account, m, &action, vec![approval]);
    assert!(sres.success, "submit failed: {}", sres.message);
    let pid = Proposal::compute_id(&account.id, account.nonce, &ah);
    exec(pe, state, m, pid)
}

#[test]
fn policy_account_executes_five_token_admin_ops() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let mut account = put_account(&db, &state, &m, 0);
    let ts = TokenStore::new(&db);

    // 1) Pause (token owned by the policy account, not paused).
    seed_pa_token(&db, account.address, false, vec![]);
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::Pause, vec![]);
    assert!(r.success, "pause: {}", r.message);
    assert!(ts.get_token(&PA_TOKEN).unwrap().unwrap().paused, "token paused");
    account.nonce += 1;

    // 2) Unpause.
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::Unpause, vec![]);
    assert!(r.success, "unpause: {}", r.message);
    assert!(!ts.get_token(&PA_TOKEN).unwrap().unwrap().paused, "token unpaused");
    account.nonce += 1;

    // 3) AddMinter.
    let minter = kp().address();
    let add = bincode::serialize(&TokenMinterData { minter }).unwrap();
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::AddMinter, add);
    assert!(r.success, "add_minter: {}", r.message);
    assert!(ts.get_token(&PA_TOKEN).unwrap().unwrap().minters.contains(&minter), "minter added");
    account.nonce += 1;

    // 4) RemoveMinter.
    let rem = bincode::serialize(&TokenMinterData { minter }).unwrap();
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::RemoveMinter, rem);
    assert!(r.success, "remove_minter: {}", r.message);
    assert!(!ts.get_token(&PA_TOKEN).unwrap().unwrap().minters.contains(&minter), "minter removed");
    account.nonce += 1;

    // 5) TransferOwnership.
    let new_owner = kp().address();
    let to = bincode::serialize(&TokenTransferOwnershipData { new_owner }).unwrap();
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::TransferOwnership, to);
    assert!(r.success, "transfer_ownership: {}", r.message);
    assert_eq!(ts.get_token(&PA_TOKEN).unwrap().unwrap().owner, new_owner, "ownership transferred");
}

#[test]
fn policy_account_failing_token_op_no_partial_state_no_nonce_advance() {
    // The policy account does NOT own the token → execute_pause fails ("Only
    // owner can pause"). No token state changes; policy nonce stays put.
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let ts = TokenStore::new(&db);
    // Owner is someone else.
    seed_pa_token(&db, kp().address(), false, vec![]);

    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::Pause, vec![]);
    assert!(!r.success, "unauthorized pause must fail");
    // No partial state: token not paused.
    assert!(!ts.get_token(&PA_TOKEN).unwrap().unwrap().paused, "token must not be paused");
    // Policy nonce NOT advanced.
    let stored = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert_eq!(stored.nonce, 0, "policy nonce must not advance on failure");
}

#[test]
fn policy_account_non_allowlisted_token_op_fail_closed() {
    // Mint is NOT one of the five allowlisted admin ops → classifies as `Other`
    // → fail-closed (never dispatched), no nonce advance.
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    seed_pa_token(&db, account.address, false, vec![]);

    // Mint payload: TokenMintData { to, amount }. Even well-formed, Mint stays
    // fail-closed.
    let mint = bincode::serialize(&sumchain_primitives::token_ops::TokenMintData { to: kp().address(), amount: 5 }).unwrap();
    let r = run_token_op(&pe, &state, &account, &m, TokenOperation::Mint, mint);
    assert!(!r.success, "Mint must be fail-closed via a policy account");
    // No supply minted.
    assert_eq!(TokenStore::new(&db).get_token(&PA_TOKEN).unwrap().unwrap().total_supply, 0, "no mint");
    let stored = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert_eq!(stored.nonce, 0, "policy nonce must not advance");
}

#[test]
fn modify_membership_executes() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let new_member = kp();
    let modify = ModifyMembershipRequest {
        new_members: vec![PolicyMember::new(m.address()), PolicyMember::new(new_member.address())],
    };
    let action = TxPayload::PolicyAccount(tx_data(PolicyAccountOperation::ModifyMembership, &modify));
    let ah = action_hash(&action);
    let approval = approve(&account, &ah, 0, &m, None, false);
    let sres = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(sres.success, "submit failed: {}", sres.message);
    let pid = Proposal::compute_id(&account.id, 0, &ah);
    let eres = exec(&pe, &state, &m, pid);
    assert!(eres.success, "execute failed: {}", eres.message);
    let updated = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert_eq!(updated.members.len(), 2, "membership should be updated");
}

#[test]
fn modify_policy_executes_with_fee_charged_once() {
    // Exercises the full block path: submit a ModifyPolicy proposal, then
    // execute it via `execute_tx` so submitter fee/nonce accounting runs
    // alongside the policy update + policy-nonce advance.
    let (state, db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let modify = ModifyPolicyRequest {
        new_policy: PolicyConfig { profile: PolicyProfile::Company, overrides: vec![] },
    };
    let action = TxPayload::PolicyAccount(tx_data(PolicyAccountOperation::ModifyPolicy, &modify));
    let ah = action_hash(&action);
    let approval = approve(&account, &ah, 0, &m, None, false);
    let sres = submit(&pe, &state, &account, &m, &action, vec![approval]);
    assert!(sres.success, "submit failed: {}", sres.message);
    let pid = Proposal::compute_id(&account.id, 0, &ah);

    // Execute through the block executor so fee/nonce are charged.
    let fee = 1_000u128;
    fund(&state, &m, 10_000);
    let exec = ExecuteProposalRequest { proposal_id: pid };
    let payload = TxPayload::PolicyAccount(tx_data(PolicyAccountOperation::ExecuteProposal, &exec));
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: m.address(), fee, nonce: 0, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), m.private_key());
    let signed = SignedTransaction::new_v2(tx, *sig.as_bytes(), *m.public_key().as_bytes());
    let proposer = kp();
    let res = executor.execute_tx(&signed, &proposer.address(), 2, 2000).unwrap();
    assert!(matches!(res.status, TxStatus::Success), "got {:?}", res.status);

    // Policy updated + policy nonce advanced.
    let updated = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert!(matches!(updated.policy.profile, PolicyProfile::Company), "policy not updated");
    assert_eq!(updated.nonce, 1, "policy nonce should advance");
    // Submitter fee charged exactly once + one nonce step.
    assert_eq!(state.get_balance(&m.address()).unwrap(), 10_000 - fee, "fee charged exactly once");
    assert_eq!(state.get_nonce(&m.address()).unwrap(), 1, "submitter nonce +1");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), fee, "proposer credited fee");
}

#[test]
fn unsupported_wrapped_action_fails_closed() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    // A wrapped PolicyAccount(Freeze) classifies as `Other` -> unsupported.
    let wrapped = TxPayload::PolicyAccount(PolicyAccountTxData {
        operation: PolicyAccountOperation::Freeze,
        data: vec![],
        recipient: zero_addr(),
    });
    let ah = action_hash(&wrapped);
    let approval = approve(&account, &ah, 0, &m, None, false);
    let sres = submit(&pe, &state, &account, &m, &wrapped, vec![approval]);
    assert!(sres.success, "submit validates approvals, not executability: {}", sres.message);
    let pid = Proposal::compute_id(&account.id, 0, &ah);
    let eres = exec(&pe, &state, &m, pid);
    assert!(!eres.success, "unsupported wrapped action must fail closed");
    // Proposal stays Pending; policy nonce unchanged.
    let prop = PolicyAccountStorage::new(&db).proposals().get(&pid).unwrap().unwrap();
    assert_eq!(prop.status, ProposalStatus::Pending, "proposal must remain Pending on fail-closed");
    let acct = PolicyAccountStorage::new(&db).policy_accounts().get(&account.id).unwrap().unwrap();
    assert_eq!(acct.nonce, 0, "policy nonce must NOT advance on fail-closed");
}

#[test]
fn cancel_proposal() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    let action = TxPayload::Transfer { to: zero_addr(), amount: 1 };
    let ah = action_hash(&action);
    let approval = approve(&account, &ah, 0, &m, None, false);
    submit(&pe, &state, &account, &m, &action, vec![approval]);
    let pid = Proposal::compute_id(&account.id, 0, &ah);
    // CancelProposal's payload is a raw ProposalId (matches the RPC builder).
    let cancel = PolicyAccountTxData {
        operation: PolicyAccountOperation::CancelProposal,
        data: bincode::serialize(&pid).unwrap(),
        recipient: zero_addr(),
    };
    let res = pe.execute(&m.address(), &cancel, &state, &zero_addr(), 0, 2, 2000).unwrap();
    assert!(res.success, "cancel failed: {}", res.message);
    let prop = PolicyAccountStorage::new(&db).proposals().get(&pid).unwrap().unwrap();
    assert_eq!(prop.status, ProposalStatus::Cancelled);
}

#[test]
fn pending_proposal_listing() {
    let (state, db, _dir, _ex) = setup_with_params(ChainParams::with_v2_enabled());
    let pe = PolicyAccountExecutor::new(db.clone());
    let m = kp();
    let account = put_account(&db, &state, &m, 0);
    for amount in [1u128, 2u128] {
        let action = TxPayload::Transfer { to: zero_addr(), amount };
        let approval = approve(&account, &action_hash(&action), 0, &m, None, false);
        submit(&pe, &state, &account, &m, &action, vec![approval]);
    }
    let pending = PolicyAccountStorage::new(&db).proposals().list_pending(&account.id).unwrap();
    assert_eq!(pending.len(), 2, "two pending proposals expected");
}

// ---- block-level fee / submitter-nonce accounting (executor arm) ----

fn create_tx(sender: &KeyPair, nonce: u64, fee: u128) -> SignedTransaction {
    let req = CreatePolicyAccountRequest {
        members: vec![PolicyMember::new(sender.address())],
        policy: PolicyConfig { profile: PolicyProfile::Personal, overrides: vec![] },
        salt: vec![9u8; 32],
    };
    let payload = TxPayload::PolicyAccount(tx_data(PolicyAccountOperation::Create, &req));
    let tx = TransactionV2 { chain_id: CHAIN_ID, from: sender.address(), fee, nonce, payload };
    let h = tx.signing_hash();
    let sig = sign(h.as_bytes(), sender.private_key());
    SignedTransaction::new_v2(tx, *sig.as_bytes(), *sender.public_key().as_bytes())
}

#[test]
fn fee_and_submitter_nonce_charged_once_on_success() {
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = kp();
    let proposer = kp();
    let fee = 1_000u128;
    fund(&state, &sender, 10_000);
    let tx = create_tx(&sender, 0, fee);
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();
    assert!(matches!(res.status, TxStatus::Success), "expected success, got {:?}", res.status);
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10_000 - fee, "fee charged exactly once");
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 1, "submitter nonce +1");
    assert_eq!(state.get_balance(&proposer.address()).unwrap(), fee, "proposer credited fee");
}

#[test]
fn insufficient_balance_is_free_no_nonce() {
    let (state, _db, _dir, executor) = setup_with_params(ChainParams::with_v2_enabled());
    let sender = kp();
    let proposer = kp();
    let fee = 1_000u128;
    fund(&state, &sender, 10); // less than fee
    let tx = create_tx(&sender, 0, fee);
    let res = executor.execute_tx(&tx, &proposer.address(), 1, 1000).unwrap();
    assert!(matches!(res.status, TxStatus::InsufficientBalance), "got {:?}", res.status);
    assert_eq!(res.fee_paid, 0, "no fee on insufficient balance");
    assert_eq!(state.get_balance(&sender.address()).unwrap(), 10, "balance unchanged");
    assert_eq!(state.get_nonce(&sender.address()).unwrap(), 0, "nonce unchanged");
}
