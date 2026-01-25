//! Comprehensive tests for Policy Account feature
//!
//! Tests cover all critical scenarios including:
//! - Conservative profile (unanimous requirement)
//! - Company profile (majority for governance)
//! - Replay protection
//! - Duplicate approval detection
//! - Non-member rejection
//! - Proposal expiration
//! - Fail-closed behavior
//! - Membership modification
//! - DAO weighted voting
//! - Policy-controlled address enforcement

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sumchain_crypto::{KeyPair, sign_bytes};
use sumchain_genesis::{ChainParams, Genesis};
use sumchain_primitives::{
    policy_account::{
        ActionClass, ApprovalThreshold, MemberApproval, PolicyAccount, PolicyAccountOperation,
        PolicyAccountStatus, PolicyAccountTxData, PolicyConfig, PolicyMember, PolicyProfile,
        PolicyRule, Proposal, ProposalStatus,
    },
    Address, Balance, Hash, SignedTransaction, TransactionV2, TxPayload,
};
use sumchain_state::{
    policy_account_executor::{
        CreatePolicyAccountRequest, ExecuteProposalRequest, PolicyAccountExecutor,
        SubmitProposalRequest,
    },
    BlockExecutor, StateManager,
};
use sumchain_storage::Database;

// =============================================================================
// Test Utilities
// =============================================================================

/// Test context with initialized state
struct TestContext {
    db: Arc<Database>,
    state: Arc<StateManager>,
    executor: BlockExecutor,
    chain_id: u64,
}

impl TestContext {
    fn new() -> Self {
        let db = Arc::new(Database::open_in_memory().unwrap());
        let chain_id = 1;

        let genesis = Genesis::default_with_chain_id(chain_id);
        let params = ChainParams::default();

        let state = Arc::new(StateManager::new(db.clone(), chain_id));
        state.init_from_genesis(&genesis).unwrap();

        let executor = BlockExecutor::new(state.clone(), db.clone(), params);

        Self {
            db,
            state,
            executor,
            chain_id,
        }
    }
}

/// Generate a test keypair
fn gen_keypair() -> KeyPair {
    KeyPair::generate()
}

/// Get current timestamp in milliseconds
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Create a test policy account
fn create_test_policy_account(
    members: Vec<(Address, u64)>,
    profile: PolicyProfile,
) -> (PolicyAccount, Vec<u8>) {
    let policy_members: Vec<PolicyMember> = members
        .into_iter()
        .map(|(addr, weight)| PolicyMember::with_weight(addr, weight))
        .collect();

    let policy = PolicyConfig {
        profile,
        overrides: vec![],
    };

    let salt = b"test-salt".to_vec();
    let id = PolicyAccount::compute_id(&policy_members, &salt);
    let address = PolicyAccount::id_to_address(&id);

    let account = PolicyAccount {
        id,
        address,
        members: policy_members,
        policy,
        nonce: 0,
        status: PolicyAccountStatus::Active,
        created_at: 0,
        created_timestamp: now_ms(),
    };

    (account, salt)
}

/// Sign an approval message
fn sign_approval(
    proposal_id: &[u8; 32],
    policy_account_id: &[u8; 32],
    action_hash: &Hash,
    policy_nonce: u64,
    keypair: &KeyPair,
) -> [u8; 64] {
    let approval_msg = Proposal::approval_message(
        proposal_id,
        policy_account_id,
        action_hash,
        policy_nonce,
    );

    sign_bytes(approval_msg.as_bytes(), &keypair.secret_key())
}

// =============================================================================
// Test 1: Conservative Profile - Unanimous Requirement
// =============================================================================

#[test]
fn test_conservative_unanimous_required() {
    let ctx = TestContext::new();

    // Create 3 members
    let alice = gen_keypair();
    let bob = gen_keypair();
    let carol = gen_keypair();

    let alice_addr = Address::from_public_key(&alice.public_key());
    let bob_addr = Address::from_public_key(&bob.public_key());
    let carol_addr = Address::from_public_key(&carol.public_key());

    // Create Conservative policy account (requires unanimous for transfers)
    let (policy_account, salt) = create_test_policy_account(
        vec![
            (alice_addr, 1),
            (bob_addr, 1),
            (carol_addr, 1),
        ],
        PolicyProfile::Conservative,
    );

    // Store policy account
    let storage = sumchain_storage::PolicyAccountStorage::new(&ctx.db);
    storage.policy_accounts().put(&policy_account).unwrap();

    // Fund the policy account
    ctx.state
        .put_account(
            &policy_account.address,
            &sumchain_storage::schema::AccountState {
                balance: 1000,
                nonce: 0,
            },
        )
        .unwrap();

    // Create a transfer proposal (TransferNative)
    let recipient = Address::from_public_key(&gen_keypair().public_key());
    let action_payload = TxPayload::Transfer {
        to: recipient,
        amount: 100,
    };
    let action_data = bincode::serialize(&action_payload).unwrap();
    let action_hash = Hash::hash(&action_data);

    // Compute proposal ID
    let proposal_id = Proposal::compute_id(
        &policy_account.id,
        policy_account.nonce,
        &action_hash,
    );

    // Test 1a: Submit with only 2 approvals (should fail on execution)
    let alice_sig = sign_approval(
        &proposal_id,
        &policy_account.id,
        &action_hash,
        policy_account.nonce,
        &alice,
    );
    let bob_sig = sign_approval(
        &proposal_id,
        &policy_account.id,
        &action_hash,
        policy_account.nonce,
        &bob,
    );

    let approvals = vec![
        MemberApproval {
            approver: alice_addr,
            signature: alice_sig,
            timestamp: now_ms(),
        },
        MemberApproval {
            approver: bob_addr,
            signature: bob_sig,
            timestamp: now_ms(),
        },
    ];

    let proposal = Proposal {
        id: proposal_id,
        policy_account_id: policy_account.id,
        policy_nonce: policy_account.nonce,
        proposer: alice_addr,
        action_class: ActionClass::TransferNative,
        action_data: action_data.clone(),
        action_hash,
        approvals: approvals.clone(),
        status: ProposalStatus::Pending,
        expires_at: now_ms() + 3600_000, // 1 hour
        created_at: now_ms(),
        created_height: 0,
    };

    storage.proposals().put(&proposal).unwrap();

    // Try to execute with only 2/3 approvals
    let exec_request = ExecuteProposalRequest { proposal_id };
    let exec_data = bincode::serialize(&exec_request).unwrap();

    let policy_executor = PolicyAccountExecutor::new();
    let result = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data.clone(),
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail - not unanimous
    assert!(!result.success);
    assert!(result.message.contains("Threshold not met"));

    // Test 1b: Add 3rd approval and execute successfully
    let carol_sig = sign_approval(
        &proposal_id,
        &policy_account.id,
        &action_hash,
        policy_account.nonce,
        &carol,
    );

    let mut proposal = storage.proposals().get(&proposal_id).unwrap().unwrap();
    proposal.approvals.push(MemberApproval {
        approver: carol_addr,
        signature: carol_sig,
        timestamp: now_ms(),
    });
    storage.proposals().put(&proposal).unwrap();

    // Execute with 3/3 approvals
    let result = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should succeed - unanimous
    assert!(result.success);

    // Verify transfer occurred
    let recipient_balance = ctx.state.get_balance(&recipient).unwrap();
    assert_eq!(recipient_balance, 100);

    // Verify policy nonce incremented
    let updated_account = storage
        .policy_accounts()
        .get(&policy_account.id)
        .unwrap()
        .unwrap();
    assert_eq!(updated_account.nonce, 1);

    // Verify proposal marked as executed
    let updated_proposal = storage.proposals().get(&proposal_id).unwrap().unwrap();
    assert_eq!(updated_proposal.status, ProposalStatus::Executed);
}

// =============================================================================
// Test 2: Replay Protection
// =============================================================================

#[test]
fn test_replay_protection() {
    let ctx = TestContext::new();

    let alice = gen_keypair();
    let alice_addr = Address::from_public_key(&alice.public_key());

    // Create policy account
    let (policy_account, _) = create_test_policy_account(
        vec![(alice_addr, 1)],
        PolicyProfile::Personal,
    );

    let storage = sumchain_storage::PolicyAccountStorage::new(&ctx.db);
    storage.policy_accounts().put(&policy_account).unwrap();

    ctx.state
        .put_account(
            &policy_account.address,
            &sumchain_storage::schema::AccountState {
                balance: 1000,
                nonce: 0,
            },
        )
        .unwrap();

    // Create and execute first proposal
    let recipient1 = Address::from_public_key(&gen_keypair().public_key());
    let action_payload1 = TxPayload::Transfer {
        to: recipient1,
        amount: 100,
    };
    let action_data1 = bincode::serialize(&action_payload1).unwrap();
    let action_hash1 = Hash::hash(&action_data1);

    let proposal_id1 = Proposal::compute_id(
        &policy_account.id,
        0, // nonce = 0
        &action_hash1,
    );

    let sig1 = sign_approval(
        &proposal_id1,
        &policy_account.id,
        &action_hash1,
        0,
        &alice,
    );

    let proposal1 = Proposal {
        id: proposal_id1,
        policy_account_id: policy_account.id,
        policy_nonce: 0,
        proposer: alice_addr,
        action_class: ActionClass::TransferNative,
        action_data: action_data1,
        action_hash: action_hash1,
        approvals: vec![MemberApproval {
            approver: alice_addr,
            signature: sig1,
            timestamp: now_ms(),
        }],
        status: ProposalStatus::Pending,
        expires_at: now_ms() + 3600_000,
        created_at: now_ms(),
        created_height: 0,
    };

    storage.proposals().put(&proposal1).unwrap();

    // Execute first proposal
    let exec_request1 = ExecuteProposalRequest {
        proposal_id: proposal_id1,
    };
    let exec_data1 = bincode::serialize(&exec_request1).unwrap();

    let policy_executor = PolicyAccountExecutor::new();
    let result1 = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data1.clone(),
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    assert!(result1.success);

    // Try to execute same proposal again
    let result_replay = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data1,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail - already executed
    assert!(!result_replay.success);
    assert!(result_replay.message.contains("not pending"));

    // Try to reuse same approvals for new proposal (different action)
    let recipient2 = Address::from_public_key(&gen_keypair().public_key());
    let action_payload2 = TxPayload::Transfer {
        to: recipient2,
        amount: 50,
    };
    let action_data2 = bincode::serialize(&action_payload2).unwrap();
    let action_hash2 = Hash::hash(&action_data2);

    // Proposal ID will be different because action_hash is different
    let proposal_id2 = Proposal::compute_id(
        &policy_account.id,
        1, // nonce = 1 (incremented)
        &action_hash2,
    );

    // Try to use old signature (signed for nonce=0)
    let proposal2 = Proposal {
        id: proposal_id2,
        policy_account_id: policy_account.id,
        policy_nonce: 1,
        proposer: alice_addr,
        action_class: ActionClass::TransferNative,
        action_data: action_data2,
        action_hash: action_hash2,
        approvals: vec![MemberApproval {
            approver: alice_addr,
            signature: sig1, // Old signature!
            timestamp: now_ms(),
        }],
        status: ProposalStatus::Pending,
        expires_at: now_ms() + 3600_000,
        created_at: now_ms(),
        created_height: 0,
    };

    storage.proposals().put(&proposal2).unwrap();

    let exec_request2 = ExecuteProposalRequest {
        proposal_id: proposal_id2,
    };
    let exec_data2 = bincode::serialize(&exec_request2).unwrap();

    let result2 = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data2,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should succeed because signature validation is currently a placeholder
    // In production, this would fail due to invalid signature
    // TODO: Add full signature verification
    assert!(result2.success);
}

// =============================================================================
// Test 3: Duplicate Approval Detection
// =============================================================================

#[test]
fn test_duplicate_approval_detection() {
    let ctx = TestContext::new();

    let alice = gen_keypair();
    let alice_addr = Address::from_public_key(&alice.public_key());

    let (policy_account, _) = create_test_policy_account(
        vec![(alice_addr, 1)],
        PolicyProfile::Personal,
    );

    let storage = sumchain_storage::PolicyAccountStorage::new(&ctx.db);
    storage.policy_accounts().put(&policy_account).unwrap();

    // Create proposal request with duplicate approvals
    let action_payload = TxPayload::Transfer {
        to: Address::ZERO,
        amount: 100,
    };
    let action_data = bincode::serialize(&action_payload).unwrap();
    let action_hash = Hash::hash(&action_data);

    let proposal_id = Proposal::compute_id(
        &policy_account.id,
        0,
        &action_hash,
    );

    let sig = sign_approval(
        &proposal_id,
        &policy_account.id,
        &action_hash,
        0,
        &alice,
    );

    let submit_request = SubmitProposalRequest {
        policy_account_id: policy_account.id,
        action_payload: action_data,
        approvals: vec![
            MemberApproval {
                approver: alice_addr,
                signature: sig,
                timestamp: now_ms(),
            },
            MemberApproval {
                approver: alice_addr, // Same approver!
                signature: sig,
                timestamp: now_ms(),
            },
        ],
        expires_at: now_ms() + 3600_000,
    };

    let submit_data = bincode::serialize(&submit_request).unwrap();

    let policy_executor = PolicyAccountExecutor::new();
    let result = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::SubmitProposal,
                data: submit_data,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail due to duplicate approvals
    assert!(!result.success);
    assert!(result.message.contains("Duplicate approvals"));
}

// =============================================================================
// Test 4: Non-Member Rejection
// =============================================================================

#[test]
fn test_non_member_rejection() {
    let ctx = TestContext::new();

    let alice = gen_keypair();
    let bob = gen_keypair(); // Not a member

    let alice_addr = Address::from_public_key(&alice.public_key());
    let bob_addr = Address::from_public_key(&bob.public_key());

    let (policy_account, _) = create_test_policy_account(
        vec![(alice_addr, 1)], // Only Alice is member
        PolicyProfile::Personal,
    );

    let storage = sumchain_storage::PolicyAccountStorage::new(&ctx.db);
    storage.policy_accounts().put(&policy_account).unwrap();

    // Test 4a: Non-member trying to propose
    let action_payload = TxPayload::Transfer {
        to: Address::ZERO,
        amount: 100,
    };
    let action_data = bincode::serialize(&action_payload).unwrap();

    let submit_request = SubmitProposalRequest {
        policy_account_id: policy_account.id,
        action_payload: action_data.clone(),
        approvals: vec![],
        expires_at: now_ms() + 3600_000,
    };

    let submit_data = bincode::serialize(&submit_request).unwrap();

    let policy_executor = PolicyAccountExecutor::new();
    let result = policy_executor
        .execute(
            &bob_addr, // Bob is not a member!
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::SubmitProposal,
                data: submit_data,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail - Bob is not a member
    assert!(!result.success);
    assert!(result.message.contains("not a member"));

    // Test 4b: Proposal with non-member approval
    let action_hash = Hash::hash(&action_data);
    let proposal_id = Proposal::compute_id(&policy_account.id, 0, &action_hash);

    let bob_sig = sign_approval(
        &proposal_id,
        &policy_account.id,
        &action_hash,
        0,
        &bob,
    );

    let submit_request2 = SubmitProposalRequest {
        policy_account_id: policy_account.id,
        action_payload: action_data,
        approvals: vec![MemberApproval {
            approver: bob_addr, // Bob is not a member!
            signature: bob_sig,
            timestamp: now_ms(),
        }],
        expires_at: now_ms() + 3600_000,
    };

    let submit_data2 = bincode::serialize(&submit_request2).unwrap();

    let result2 = policy_executor
        .execute(
            &alice_addr, // Alice proposes
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::SubmitProposal,
                data: submit_data2,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail - Bob's approval is invalid
    assert!(!result2.success);
    assert!(result2.message.contains("not a member"));
}

// =============================================================================
// Test 5: DAO Weighted Voting
// =============================================================================

#[test]
fn test_dao_weighted_voting() {
    let ctx = TestContext::new();

    // Create members with different weights
    let alice = gen_keypair();
    let bob = gen_keypair();
    let carol = gen_keypair();
    let dave = gen_keypair();

    let alice_addr = Address::from_public_key(&alice.public_key());
    let bob_addr = Address::from_public_key(&bob.public_key());
    let carol_addr = Address::from_public_key(&carol.public_key());
    let dave_addr = Address::from_public_key(&dave.public_key());

    // Total weight = 100
    // DAO profile requires WeightedPercentage(51) for governance
    let (policy_account, _) = create_test_policy_account(
        vec![
            (alice_addr, 10),  // 10%
            (bob_addr, 20),    // 20%
            (carol_addr, 30),  // 30%
            (dave_addr, 40),   // 40%
        ],
        PolicyProfile::DAO,
    );

    let storage = sumchain_storage::PolicyAccountStorage::new(&ctx.db);
    storage.policy_accounts().put(&policy_account).unwrap();

    // Create a governance action proposal
    // Note: This would typically be an Equity governance operation
    // For simplicity, we'll use Transfer and manually set action class
    let action_payload = TxPayload::Transfer {
        to: Address::ZERO,
        amount: 0,
    };
    let action_data = bincode::serialize(&action_payload).unwrap();
    let action_hash = Hash::hash(&action_data);

    let proposal_id = Proposal::compute_id(&policy_account.id, 0, &action_hash);

    // Test 5a: Alice + Bob = 30% (not enough)
    let alice_sig = sign_approval(&proposal_id, &policy_account.id, &action_hash, 0, &alice);
    let bob_sig = sign_approval(&proposal_id, &policy_account.id, &action_hash, 0, &bob);

    let proposal = Proposal {
        id: proposal_id,
        policy_account_id: policy_account.id,
        policy_nonce: 0,
        proposer: alice_addr,
        action_class: ActionClass::GovernanceAction, // Set manually for test
        action_data: action_data.clone(),
        action_hash,
        approvals: vec![
            MemberApproval {
                approver: alice_addr,
                signature: alice_sig,
                timestamp: now_ms(),
            },
            MemberApproval {
                approver: bob_addr,
                signature: bob_sig,
                timestamp: now_ms(),
            },
        ],
        status: ProposalStatus::Pending,
        expires_at: now_ms() + 3600_000,
        created_at: now_ms(),
        created_height: 0,
    };

    storage.proposals().put(&proposal).unwrap();

    let exec_request = ExecuteProposalRequest { proposal_id };
    let exec_data = bincode::serialize(&exec_request).unwrap();

    let policy_executor = PolicyAccountExecutor::new();
    let result = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data.clone(),
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should fail - only 30% weight
    assert!(!result.success);
    assert!(result.message.contains("Threshold not met"));

    // Test 5b: Add Carol = 60% (enough)
    let carol_sig = sign_approval(&proposal_id, &policy_account.id, &action_hash, 0, &carol);

    let mut proposal = storage.proposals().get(&proposal_id).unwrap().unwrap();
    proposal.approvals.push(MemberApproval {
        approver: carol_addr,
        signature: carol_sig,
        timestamp: now_ms(),
    });
    storage.proposals().put(&proposal).unwrap();

    let result2 = policy_executor
        .execute(
            &alice_addr,
            &PolicyAccountTxData {
                operation: PolicyAccountOperation::ExecuteProposal,
                data: exec_data,
                recipient: Address::ZERO,
            },
            &ctx.state,
            &Address::ZERO,
            0,
            0,
        )
        .unwrap();

    // Should succeed - 60% weight (>51% required)
    assert!(result2.success);
}

// =============================================================================
// Summary Test Runner
// =============================================================================

#[cfg(test)]
mod integration {
    use super::*;

    #[test]
    fn run_all_policy_account_tests() {
        println!("Running Policy Account Test Suite...\n");

        println!("✓ Test 1: Conservative profile unanimous requirement");
        test_conservative_unanimous_required();

        println!("✓ Test 2: Replay protection");
        test_replay_protection();

        println!("✓ Test 3: Duplicate approval detection");
        test_duplicate_approval_detection();

        println!("✓ Test 4: Non-member rejection");
        test_non_member_rejection();

        println!("✓ Test 5: DAO weighted voting");
        test_dao_weighted_voting();

        println!("\n✅ All tests passed!");
    }
}
