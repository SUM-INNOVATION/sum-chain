# Policy Accounts & Contracts

Current public usage for policy accounts and smart contracts on SUM Chain.
Examples use the public endpoint `https://rpc.sumchain.io`.

---

## Policy accounts

> Status:             code-backed
> Last verified:      2026-06-28
> Code references:    crates/primitives/src/policy_account.rs, crates/state/src/policy_account_executor.rs, crates/rpc/src/server.rs
> Public RPC support: reads (policy_getAccount, policy_getAccountByAddress, policy_listMemberAccounts, policy_getProposal, policy_listProposals, policy_listPendingProposals); builders (policy_buildCreateAccount, policy_buildSubmitProposal, policy_buildExecuteProposal, policy_buildCancelProposal)

Policy accounts provide consensus-level group governance: multiple members
jointly control an address under configurable multi-signature approval policies,
enforced in the state executor. A member proposes an action, members approve it
with their signatures, and any submitter executes it once the policy threshold
is met.

In v1 a proposal wraps and executes these action classes:

- **Native transfer** of Ϙ from the policy-controlled address.
- **Membership change** (`ModifyMembership`).
- **Policy change** (`ModifyPolicy`).

### Read examples

```bash
# Policy account by ID (hex)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_getAccount","params":["<policy_account_id_hex>"]}'

# Policy account by controlled address (base58)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_getAccountByAddress","params":["<address>"]}'

# Policy accounts a member belongs to
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_listMemberAccounts","params":["<member_address>"]}'

# A proposal by ID, and a policy account's proposals
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_getProposal","params":["<proposal_id_hex>"]}'
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_listPendingProposals","params":["<policy_account_id_hex>"]}'
```

### Writes: build, sign locally, submit

Policy writes use no-key **builder** methods. The server assembles an unsigned
transaction and returns its bincode encoding plus the hash to sign; you sign
locally and submit the signed transaction through
[`sum_sendRawTransaction`](./tokens.md#submitting-writes). Private keys are never
sent to the node.

The four builders — `policy_buildCreateAccount`, `policy_buildSubmitProposal`,
`policy_buildExecuteProposal`, `policy_buildCancelProposal` — each take a
request object containing `from` (the submitter address) and an optional `fee`;
the server fills in the chain id and the submitter's current nonce.

```bash
# 1. Build an unsigned create-account transaction.
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"policy_buildCreateAccount","params":[{
        "from":"<submitter_address>",
        "members":[{"address":"<member_address>","weight":1}],
        "policy":{"profile":"Personal","overrides":[]},
        "salt":"0x<32_byte_hex>"
      }]}'
```

The response contains `unsigned_tx` (hex), `signing_hash` (hex), the filled
`from` / `nonce` / `fee` / `chain_id`, and derived ids (`policy_account_id` and
`address` for create; `proposal_id` and `action_hash` for submit).

```text
2. Sign `signing_hash` with the `from` key (Ed25519).
3. Assemble the signed transaction from `unsigned_tx` + signature + public key
   and submit it via sum_sendRawTransaction.
```

Submitting a proposal: build the wrapped action's `TxPayload` (a native
transfer, `ModifyMembership`, or `ModifyPolicy`), each approving member signs
the canonical approval bytes
(`SUM-POLICY-APPROVAL:v1: || policy_account_id || action_hash || policy_nonce`),
and pass those approvals (each with the approver's address, public key, and
signature) to `policy_buildSubmitProposal`.

---

## Smart contracts

> Status:             code-backed
> Last verified:      2026-06-27
> Code references:    crates/state/src/contract_executor.rs, crates/sumc-runtime/, crates/rpc/src/server.rs
> Public RPC support: yes (contract_getContract, contract_isContract, contract_call, contract_getCodeHash, contract_getBalance)

WASM smart contracts. Deploy and call are signed transactions
(`TxPayload::ContractDeploy` / `TxPayload::ContractCall`) submitted through
[`sum_sendRawTransaction`](./tokens.md#submitting-writes). Contract examples
below are intended for current public read/view usage.

### Read examples

```bash
# Contract metadata (code hash, owner, balance)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_getContract","params":["<contract_addr>"]}'

# Is an address a contract?
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_isContract","params":["<contract_addr>"]}'

# Contract code hash
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_getCodeHash","params":["<contract_addr>"]}'

# Contract balance
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_getBalance","params":["<contract_addr>"]}'

# Read-only (view) call: request object is { contract, method, args (hex), from? }
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_call","params":[{"contract":"<contract_addr>","method":"<method_name>","args":"<hex_args>","from":null}]}'
```

---

## Source-of-truth pointers

- Policy types/executor: `crates/primitives/src/policy_account.rs`,
  `crates/state/src/policy_account_executor.rs`.
- Contract runtime/executor: `crates/sumc-runtime/`,
  `crates/state/src/contract_executor.rs`.
- RPC: `crates/rpc/src/api.rs` + `crates/rpc/src/server.rs`.
