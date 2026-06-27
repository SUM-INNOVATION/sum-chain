# Policy Accounts & Contracts

Current public usage for policy accounts and smart contracts on SUM Chain.
Examples use the public endpoint `https://rpc.sumchain.io`.

---

## Policy accounts

> Status:             code-backed (executor); no public RPC published
> Last verified:      2026-06-27
> Code references:    crates/primitives/src/policy_account.rs, crates/state/src/policy_account_executor.rs
> Public RPC support: none published

Policy accounts provide consensus-level group governance: multiple members
jointly control an address under configurable multi-signature approval policies,
enforced in the state executor.

**No public policy-account commands are published in this guide.**

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
