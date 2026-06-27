# Policy Accounts & Contracts

Canonical reference for two features that existing docs overstate: **policy
accounts** (multi-party governed accounts) and **smart contracts**. This doc
states plainly what works via public RPC today and what does not, with code
references. Examples use the public endpoint `https://rpc.sumchain.io`.

---

## Policy accounts

> Status:             unavailable via public RPC (core logic exists; all RPC handlers are stubs)
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/policy_account.rs, crates/state/src/policy_account_executor.rs, crates/rpc/src/server.rs (policy_* handlers)
> Public RPC support: no — the 10 `policy_*` methods are declared but return "Not yet implemented"

### What exists

- Types and the proposal/approval model: `crates/primitives/src/policy_account.rs`.
- On-chain transaction support: `TxPayload::PolicyAccount` (`TxType::PolicyAccount`).
- A wired executor (`PolicyAccountExecutor`) handling Create, SubmitProposal,
  ExecuteProposal, CancelProposal, Freeze, Unfreeze, ModifyMembership,
  ModifyPolicy.

### What does NOT work today

- **All 10 `policy_*` RPC methods are stubs.** Each handler in
  `crates/rpc/src/server.rs` returns `Err("Not yet implemented")`. There is no
  public way to create a policy account, submit/inspect proposals, or query
  policy state over RPC. The methods (`policy_createAccount`, `policy_getAccount`,
  `policy_getAccountByAddress`, `policy_listMemberAccounts`, `policy_submitProposal`,
  `policy_executeProposal`, `policy_cancelProposal`, `policy_getProposal`,
  `policy_listProposals`, `policy_listPendingProposals`) exist only as
  declarations.
- **Approved non-policy actions are not re-dispatched.** When a proposal wraps a
  non-policy action (a transfer, token op, or contract call), the executor marks
  the proposal successful but does **not** execute the wrapped action
  (`crates/state/src/policy_account_executor.rs`). Do not assume an approved
  proposal performs its payload.

### Usage today

There are **no working `curl` examples** for policy accounts — every `policy_*`
call returns a "Not yet implemented" error. A client could in principle build
and submit a raw `PolicyAccount` transaction via
[`sum_sendRawTransaction`](./tokens.md#submitting-writes), but with the
re-dispatch gap above and no read RPC, policy accounts are **not usable as a
product feature through the public endpoint today**.

---

## Smart contracts

> Status:             partial (deploy/call wired; storage ephemeral; some reads stubbed)
> Last verified:      2026-06-27
> Code references:    crates/state/src/contract_executor.rs, crates/sumc-runtime/src/, crates/rpc/src/server.rs (contract_* handlers)
> Public RPC support: partial — contract_getContract, contract_isContract, contract_call, contract_getCodeHash, contract_getBalance work; contract_getStorageAt is unimplemented; contract_estimateGas is a fixed estimate

### What exists

- A WASM runtime (`crates/sumc-runtime`) and a Rust contract SDK
  (`crates/sumc-sdk`, `crates/sumc-sdk-macros`).
- On-chain transaction support: `TxPayload::ContractDeploy` and
  `TxPayload::ContractCall`, both wired into the block executor
  (`crates/state/src/contract_executor.rs`) — deploy and call execute, deduct
  fees, and increment the sender nonce.

### Important caveat: contract storage is in-memory only

Contract storage uses an in-memory backend (`crates/state/src/contract_executor.rs`),
**not** the persistent database. Contract state is ephemeral and is lost on node
restart. Contracts are usable for development and view calls, but are **not
production-ready for persistent state**.

### Read RPC — what works

```bash
# Contract metadata (code hash, owner, balance)
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_getContract","params":["<contract_addr>"]}'

# Is an address a contract?
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_isContract","params":["<contract_addr>"]}'

# Contract balance
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_getBalance","params":["<contract_addr>"]}'

# Read-only (view) call: request object is { contract, method, args (hex), from? }
curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"contract_call","params":[{"contract":"<contract_addr>","method":"<method_name>","args":"<hex_args>","from":null}]}'
```

### Read RPC — what does NOT work

- **`contract_getStorageAt`** returns "Storage querying not yet implemented"
  (`crates/rpc/src/server.rs`). You cannot read arbitrary contract storage slots.
- **`contract_estimateGas`** returns a fixed formula (base + per-byte), not a
  simulated execution — treat it as a rough floor, not an accurate estimate.

### Writes

Contract deploy/call writes are submitted as signed transactions via
[`sum_sendRawTransaction`](./tokens.md#submitting-writes) carrying
`TxPayload::ContractDeploy` / `TxPayload::ContractCall`.

---

## Source-of-truth pointers

- Policy types/executor: `crates/primitives/src/policy_account.rs`,
  `crates/state/src/policy_account_executor.rs`.
- Contract runtime/executor: `crates/sumc-runtime/`,
  `crates/state/src/contract_executor.rs`.
- RPC: `crates/rpc/src/api.rs` (declarations) + `crates/rpc/src/server.rs`
  (handlers — note the policy stubs and contract storage stub).
- Detailed policy implementation tracking:
  [policy-accounts-implementation-status](./policy-accounts-implementation-status.md).
