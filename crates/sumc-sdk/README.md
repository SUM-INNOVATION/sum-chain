# sumc-sdk

SDK for writing SUM Chain smart contracts in Rust (compiled to WASM).

## Purpose

Provides the host-environment bindings, storage helpers, and types a contract
needs, plus a `prelude` for ergonomic imports.

## Main modules

- `prelude` — common imports for contract code.
- `env` — host environment access (caller, block context, etc.).
- `storage` — contract storage helpers.
- `types` — shared contract types.
- `error` — SDK error type.

## Public interfaces

Use `sumc_sdk::prelude::*` in contract code; `env`, `storage`, and `types`
provide the host interface. See the contract examples under
[`examples/contracts/`](../../examples/contracts/).

## Not for

- Node/chain logic — the contract runtime is `sumc-runtime`; node assembly is
  `sumchain-node`.
- Procedural macros — those live in `sumc-sdk-macros`.
