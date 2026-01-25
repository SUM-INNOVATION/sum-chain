# Policy Accounts - Group Governance on SUM Chain

## Table of Contents

1. [Introduction](#introduction)
2. [What Are Policy Accounts?](#what-are-policy-accounts)
3. [Use Cases](#use-cases)
4. [Creating a Policy Account](#creating-a-policy-account)
5. [Policy Profiles](#policy-profiles)
6. [Action Classification](#action-classification)
7. [Submitting and Executing Proposals](#submitting-and-executing-proposals)
8. [Security Considerations](#security-considerations)
9. [End-to-End Examples](#end-to-end-examples)
10. [RPC API Reference](#rpc-api-reference)

---

## Introduction

Policy Accounts enable **group governance** on SUM Chain at the consensus level. Multiple parties can jointly control an address with configurable multi-signature approval policies. Unlike smart contract-based multisig, Policy Accounts are enforced directly in the chain's state executor, providing maximum security and compatibility.

### Key Features

- **Consensus-Level Enforcement**: All logic runs in the state executor, not in smart contracts
- **Flexible Thresholds**: Unanimous, majority, percentage, weighted, or custom rules
- **Action-Based Policies**: Different approval requirements for different types of actions
- **Safe Defaults**: Pre-configured profiles for common use cases
- **Replay Protection**: Built-in nonce mechanism prevents approval reuse
- **Fail-Closed**: Unknown actions require explicit configuration

---

## What Are Policy Accounts?

A **Policy Account** is a group-governed address where:

1. **Multiple members** jointly control the address
2. **Each member** has an optional voting weight
3. **A policy** defines approval thresholds for different action classes
4. **Proposals** contain actions to be executed on behalf of the group
5. **Approvals** from members are collected and verified
6. **Execution** happens once the threshold is met

### How It Works

```
┌─────────────────────────────────────────────────────────┐
│  Policy Account (owns NFT, tokens, native balance)      │
│                                                          │
│  Members: Alice (weight=1), Bob (1), Carol (1)          │
│  Profile: Conservative                                   │
│  → TransferOwnership: Unanimous                          │
│  → AdministerToken: Majority                             │
│                                                          │
│  Nonce: 5 (for replay protection)                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  Proposal: Transfer house NFT to buyer                   │
│                                                          │
│  Action: TransferTokenOwnership                          │
│  Required: Unanimous (3/3)                               │
│  Approvals: [Alice ✓, Bob ✓, Carol ✓]                   │
│  Status: Ready to execute                                │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                    Execution
           (NFT transferred to buyer)
         (Policy nonce increments to 6)
```

---

## Use Cases

### 1. Joint Asset Ownership (House, Car, Art)
- **Scenario**: Alice, Bob, and Carol jointly own a tokenized house
- **Profile**: Conservative (unanimous for transfers)
- **Benefit**: All owners must approve before selling

### 2. Corporate Governance
- **Scenario**: 5-member board controlling company equity tokens
- **Profile**: Company (majority for governance, unanimous for asset transfers)
- **Benefit**: Flexible voting for decisions, protected assets

### 3. Decentralized Organizations (DAOs)
- **Scenario**: Token-weighted governance for protocol decisions
- **Profile**: DAO (weighted voting)
- **Benefit**: Democratic decision-making

### 4. Family Trusts
- **Scenario**: Multiple trustees managing family assets
- **Profile**: Trust (conservative with fiduciary requirements)
- **Benefit**: Legal compliance and safety

### 5. Shared Personal Accounts
- **Scenario**: Couples or roommates sharing expenses
- **Profile**: Personal (simple majority)
- **Benefit**: Easy joint financial management

---

## Creating a Policy Account

### Step 1: Choose Members

Each member needs:
- **Address**: Their SUM Chain address
- **Weight** (optional): Voting power (default: 1)

```rust
let members = vec![
    PolicyMember { address: alice_addr, weight: 1 },
    PolicyMember { address: bob_addr, weight: 1 },
    PolicyMember { address: carol_addr, weight: 1 },
];
```

### Step 2: Select a Policy Profile

Choose a profile that matches your use case:

| Profile | Best For | Transfer Ownership | Governance | Membership |
|---------|----------|-------------------|------------|------------|
| **Conservative** | High-value assets | Unanimous | Majority | Unanimous |
| **Company** | Corporate boards | Unanimous | Majority | 67% |
| **DAO** | Decentralized orgs | Majority | Weighted 51% | Weighted 67% |
| **Personal** | Shared accounts | Majority | Majority | Majority |
| **Trust** | Fiduciary duties | Unanimous | 67% | Unanimous |
| **Custom** | Advanced users | Must configure | Must configure | Must configure |

### Step 3: Create via RPC

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_createAccount",
    "params": {
      "private_key": "<CREATOR_PRIVATE_KEY_HEX>",
      "members": [
        {"address": "<ALICE_ADDRESS>", "weight": 1},
        {"address": "<BOB_ADDRESS>", "weight": 1},
        {"address": "<CAROL_ADDRESS>", "weight": 1}
      ],
      "policy": {
        "profile": "Conservative",
        "overrides": []
      },
      "salt": "<RANDOM_HEX_32_BYTES>"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "policy_account_id": "0x1234...",
    "address": "2ABcD...",
    "tx_hash": "0xabcd..."
  },
  "id": 1
}
```

### Step 4: Transfer Assets to Policy Account

Transfer NFTs, tokens, or native balance to the policy account address. The group now jointly controls these assets.

---

## Policy Profiles

### Conservative Profile

**Use Case**: High-value assets like houses, expensive art, or family heirlooms

**Thresholds:**
- Transfer Native/Token Ownership: **Unanimous**
- Modify Membership: **Unanimous**
- Modify Policy: **Unanimous**
- Administer Token: **Majority**
- All Others: **Majority**

**Philosophy**: Maximum safety for ownership changes, flexibility for administration.

---

### Company Profile

**Use Case**: Traditional corporate governance

**Thresholds:**
- Transfer Native/Token Ownership: **Unanimous**
- Governance Actions: **Majority**
- Modify Membership/Policy: **67% (Supermajority)**
- All Others: **Majority**

**Philosophy**: Protect assets, enable efficient governance, require supermajority for structural changes.

---

### DAO Profile

**Use Case**: Decentralized autonomous organizations

**Thresholds:**
- Governance Actions: **Weighted 51%**
- Modify Membership/Policy: **Weighted 67%**
- Transfer Native/Token: **Majority**
- All Others: **Majority**

**Philosophy**: Democratic governance weighted by token holdings or contribution.

---

### Personal Profile

**Use Case**: Joint personal accounts, couples, roommates

**Thresholds:**
- All Actions: **Majority**

**Philosophy**: Simple and efficient for everyday shared decisions.

---

### Trust Profile

**Use Case**: Legal trusts, estate planning

**Thresholds:**
- Transfer Native/Token Ownership: **Unanimous**
- Modify Membership/Policy: **Unanimous**
- All Others: **67%**

**Philosophy**: Conservative and legally compliant for fiduciary responsibilities.

---

### Custom Profile

**Use Case**: Advanced users with specific requirements

**Default Thresholds:**
- All Actions: **Deny** (fail-closed)

**Must Configure**: Explicit override for each action class you want to allow.

**Philosophy**: Security-first, explicit configuration required.

---

## Action Classification

Every transaction is classified into an **Action Class** to determine the required approval threshold:

| Action Class | Examples | Typical Threshold |
|--------------|----------|-------------------|
| **TransferNative** | Send Koppa from policy account | Unanimous (Conservative) |
| **TransferTokenOwnership** | Transfer NFT, change token owner | Unanimous (Conservative) |
| **AdministerToken** | Pause token, update metadata | Majority |
| **StakingOperation** | Stake, unstake, delegate | Majority |
| **GovernanceAction** | Vote on proposal, change parameters | Majority or Weighted |
| **ModifyMembership** | Add/remove members | Unanimous or 67% |
| **ModifyPolicy** | Change approval rules | Unanimous or 67% |
| **DeployContract** | Deploy smart contract | Varies by profile |
| **CallContract** | Call smart contract | Varies by profile |
| **Other** | Unknown/unconfigured | **Deny** (fail-closed) |

### Custom Overrides

You can override the threshold for any action class:

```json
{
  "profile": "Conservative",
  "overrides": [
    {
      "action_class": "StakingOperation",
      "threshold": {"type": "Percentage", "value": 67}
    }
  ]
}
```

---

## Submitting and Executing Proposals

### Workflow

```
1. Propose Action
   ↓
2. Collect Approvals (off-chain signing)
   ↓
3. Submit Proposal (with approvals)
   ↓
4. Execute (once threshold met)
```

### Step 1: Propose an Action

The proposer decides what action to perform (e.g., transfer NFT, vote on governance).

### Step 2: Collect Approvals Off-Chain

Each member signs an approval message:

```
ApprovalMessage = Hash(
  proposalId +
  policyAccountId +
  actionHash +
  policyNonce
)
```

Members sign this message with their private keys.

### Step 3: Submit Proposal with Approvals

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_submitProposal",
    "params": {
      "proposer_private_key": "<PROPOSER_KEY>",
      "policy_account_id": "0x1234...",
      "action_data": "<HEX_ENCODED_TX_PAYLOAD>",
      "approvals": [
        {
          "approver_address": "<ALICE_ADDRESS>",
          "signature": "<ALICE_SIGNATURE_HEX>"
        },
        {
          "approver_address": "<BOB_ADDRESS>",
          "signature": "<BOB_SIGNATURE_HEX>"
        }
      ],
      "expires_in_seconds": 3600
    },
    "id": 1
  }'
```

### Step 4: Execute Proposal

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_executeProposal",
    "params": {
      "executor_private_key": "<ANY_MEMBER_KEY>",
      "proposal_id": "0x5678..."
    },
    "id": 1
  }'
```

**Success Criteria:**
- ✅ All approvers are current members
- ✅ No duplicate approvals
- ✅ Threshold met for action class
- ✅ Policy nonce matches
- ✅ Not expired
- ✅ Status is Pending

**On Success:**
- Action executes as if from policy account address
- Policy nonce increments
- Proposal marked as Executed

---

## Security Considerations

### 1. Replay Protection

**How it works:**
- Each policy account has a **nonce** (starts at 0)
- Each proposal is bound to the current nonce
- After execution, nonce increments
- Old approvals can't be reused

**Guarantee:** A proposal can only be executed once.

---

### 2. Approval Binding

Approvals are cryptographically bound to:
- **Proposal ID** (unique per proposal)
- **Policy Account ID** (specific group)
- **Action Hash** (exact action)
- **Policy Nonce** (current state)

**Guarantee:** Approvals can't be reused for different actions or different groups.

---

### 3. Membership Changes

**Challenge:** What if members change while a proposal is pending?

**Solution:**
- Threshold checks use membership at **execution time**
- If Alice is removed before execution, her approval no longer counts
- If Bob is added after proposal creation, he can't approve (nonce mismatch)

**Best Practice:** Execute proposals promptly after collecting approvals.

---

### 4. Fail-Closed Design

**Unknown actions are denied by default.**

If you use Custom profile and don't configure a rule for an action class, that action will always fail (threshold = Deny).

**Benefit:** Security-first approach prevents accidental dangerous operations.

---

### 5. DoS Protection

**Limits:**
- MAX_MEMBERS: 100
- MAX_APPROVALS: 100
- MAX_CUSTOM_RULES: 50
- MAX_PROPOSAL_PAYLOAD_SIZE: 100 KB

**Benefit:** Prevents denial-of-service attacks via resource exhaustion.

---

## End-to-End Examples

### Example 1: House-Like Asset (Conservative Profile)

**Scenario:** Alice, Bob, and Carol jointly own a tokenized house (NFT).

#### Setup

```bash
# 1. Create policy account
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_createAccount",
    "params": {
      "private_key": "<ALICE_KEY>",
      "members": [
        {"address": "2Alice...", "weight": 1},
        {"address": "2Bob...", "weight": 1},
        {"address": "2Carol...", "weight": 1}
      ],
      "policy": {"profile": "Conservative", "overrides": []},
      "salt": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    "id": 1
  }'

# Response: policy_account_id = 0xAABBCC..., address = 2PolicyHouse...

# 2. Transfer house NFT to policy account
# (Use standard NFT transfer to address 2PolicyHouse...)
```

#### Selling the House

```bash
# 1. Alice proposes transfer to buyer
# Prepare action data (NFT transfer)
ACTION_DATA = {
  "Nft": {
    "collection_id": "0xHOUSE_COLLECTION...",
    "token_id": 42,
    "operation": "Transfer",
    "data": "<BUYER_ADDRESS_SERIALIZED>"
  }
}

# 2. Collect signatures OFF-CHAIN
# Alice signs approval message
# Bob signs approval message
# Carol signs approval message

# 3. Submit proposal with all 3 approvals
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_submitProposal",
    "params": {
      "proposer_private_key": "<ALICE_KEY>",
      "policy_account_id": "0xAABBCC...",
      "action_data": "<ACTION_DATA_HEX>",
      "approvals": [
        {"approver_address": "2Alice...", "signature": "<ALICE_SIG>"},
        {"approver_address": "2Bob...", "signature": "<BOB_SIG>"},
        {"approver_address": "2Carol...", "signature": "<CAROL_SIG>"}
      ],
      "expires_in_seconds": 86400
    },
    "id": 1
  }'

# Response: proposal_id = 0xDDEEFF...

# 4. Execute proposal
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_executeProposal",
    "params": {
      "executor_private_key": "<ALICE_KEY>",
      "proposal_id": "0xDDEEFF..."
    },
    "id": 1
  }'

# Response: success=true, house NFT transferred to buyer
```

**Thresholds Applied:**
- NFT Transfer → TransferTokenOwnership → **Unanimous (3/3 required)**

---

### Example 2: Company Governance (Company Profile)

**Scenario:** 5-member board controlling company equity tokens and governance.

#### Setup

```bash
# Create policy account with 5 board members
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_createAccount",
    "params": {
      "private_key": "<MEMBER1_KEY>",
      "members": [
        {"address": "2Member1...", "weight": 1},
        {"address": "2Member2...", "weight": 1},
        {"address": "2Member3...", "weight": 1},
        {"address": "2Member4...", "weight": 1},
        {"address": "2Member5...", "weight": 1}
      ],
      "policy": {"profile": "Company", "overrides": []},
      "salt": "0x..."
    },
    "id": 1
  }'

# Response: policy_account_id = 0x112233..., address = 2CompanyBoard...
```

#### Board Resolution (Governance Action)

```bash
# 1. Member1 proposes governance action
# Collect 3 signatures (majority = 3/5)

# 2. Submit proposal
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "policy_submitProposal",
    "params": {
      "proposer_private_key": "<MEMBER1_KEY>",
      "policy_account_id": "0x112233...",
      "action_data": "<GOVERNANCE_ACTION_HEX>",
      "approvals": [
        {"approver_address": "2Member1...", "signature": "<SIG1>"},
        {"approver_address": "2Member2...", "signature": "<SIG2>"},
        {"approver_address": "2Member3...", "signature": "<SIG3>"}
      ],
      "expires_in_seconds": 604800
    },
    "id": 1
  }'

# 3. Execute
# Success! Majority (3/5) achieved
```

**Thresholds Applied:**
- Governance Action → **Majority (3/5 required)**

#### Selling Company Assets (Token Transfer)

```bash
# 1. Member1 proposes token transfer
# Collect 5 signatures (UNANIMOUS required for ownership transfer)

# 2. Submit proposal with all 5 approvals
# 3. Execute
# Success! Unanimous (5/5) achieved
```

**Thresholds Applied:**
- Token Transfer → TransferTokenOwnership → **Unanimous (5/5 required)**

---

## RPC API Reference

### policy_createAccount

Create a new policy account.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_createAccount",
  "params": {
    "private_key": "<HEX>",
    "members": [{"address": "<ADDR>", "weight": 1}],
    "policy": {"profile": "Conservative", "overrides": []},
    "salt": "<HEX_32_BYTES>"
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "policy_account_id": "<HEX>",
    "address": "<BASE58>",
    "tx_hash": "<HEX>"
  },
  "id": 1
}
```

---

### policy_getAccount

Get policy account information.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_getAccount",
  "params": "<POLICY_ACCOUNT_ID_HEX>",
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "<HEX>",
    "address": "<BASE58>",
    "members": [{"address": "<BASE58>", "weight": 1}],
    "policy": {"profile": "Conservative", "overrides": []},
    "nonce": 0,
    "status": "Active",
    "created_at": 12345,
    "created_timestamp": 1234567890000
  },
  "id": 1
}
```

---

### policy_submitProposal

Submit a proposal with approvals.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_submitProposal",
  "params": {
    "proposer_private_key": "<HEX>",
    "policy_account_id": "<HEX>",
    "action_data": "<HEX>",
    "approvals": [
      {"approver_address": "<BASE58>", "signature": "<HEX>"}
    ],
    "expires_in_seconds": 3600
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "proposal_id": "<HEX>",
    "status": "Pending",
    "tx_hash": "<HEX>"
  },
  "id": 1
}
```

---

### policy_executeProposal

Execute a proposal once threshold is met.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_executeProposal",
  "params": {
    "executor_private_key": "<HEX>",
    "proposal_id": "<HEX>"
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "new_policy_nonce": 1,
    "message": "Proposal executed successfully",
    "tx_hash": "<HEX>"
  },
  "id": 1
}
```

---

### policy_getProposal

Get proposal details.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_getProposal",
  "params": "<PROPOSAL_ID_HEX>",
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "id": "<HEX>",
    "policy_account_id": "<HEX>",
    "policy_nonce": 0,
    "proposer": "<BASE58>",
    "action_class": "TransferNative",
    "action_hash": "<HEX>",
    "approval_count": 2,
    "approvals": [
      {"approver": "<BASE58>", "signature": "<HEX>", "timestamp": 123}
    ],
    "status": "Pending",
    "expires_at": 1234567890000,
    "created_at": 1234567890000,
    "created_height": 100
  },
  "id": 1
}
```

---

### policy_listProposals

List all proposals for a policy account.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "policy_listProposals",
  "params": "<POLICY_ACCOUNT_ID_HEX>",
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [<ProposalInfo>, ...],
  "id": 1
}
```

---

## Common Questions

### Q: Can I change members after creating a policy account?

**A:** Yes! Submit a `ModifyMembership` proposal with approvals meeting the `ModifyMembership` threshold (varies by profile).

### Q: What happens if a proposal expires?

**A:** Expired proposals cannot be executed. Status changes to `Expired`. You must create a new proposal.

### Q: Can I cancel a proposal?

**A:** Yes, the proposer can cancel their own pending proposals using `policy_cancelProposal`.

### Q: How do I know what threshold is required?

**A:** Call `policy_getAccount` to see the policy configuration, then check the threshold for your action class.

### Q: Can one person have multiple votes?

**A:** No. Each member gets one approval, but members can have different **weights** for weighted voting (DAO profile).

### Q: What if I lose my private key?

**A:** Policy accounts support membership changes. Other members can propose removing the lost key and adding a new one (if threshold permits).

---

## Conclusion

Policy Accounts bring **consensus-level group governance** to SUM Chain, enabling secure joint ownership and flexible decision-making for everything from family assets to decentralized organizations.

**Key Takeaways:**
- ✅ **Safe by default** (Conservative profile)
- ✅ **Flexible** (6 profiles + custom overrides)
- ✅ **Secure** (replay protection, fail-closed)
- ✅ **Compatible** (works with all SUM Chain features)

For technical implementation details, see:
- [Policy Account Implementation Status](policy-accounts-implementation-status.md)
- [Source Code](../crates/primitives/src/policy_account.rs)
- [Tests](../crates/state/tests/policy_account_tests.rs)
