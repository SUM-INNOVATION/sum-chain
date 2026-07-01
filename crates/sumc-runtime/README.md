# sumc-runtime

WebAssembly runtime for SUM Chain smart contracts.

## Purpose

Executes contract WASM in a sandbox with gas metering, host functions, memory
management, and contract storage backends.

## Main modules

- `executor` — `ContractExecutor`, `ExecutionContext`, `ExecutionResult`.
- `gas` — `Gas`, `GasCosts`, `GasMeter` (metering and cost model).
- `host` — host functions exposed to contracts.
- `memory` — WASM memory management.
- `storage` — `ContractStorage` with `MemoryStorage` and `RocksDbStorage` backends.
- `types` — shared runtime types.
- `error` — `RuntimeError` and `Result`.

## Public interfaces

- `ContractExecutor`, `ExecutionContext`, `ExecutionResult`.
- `Gas`, `GasCosts`, `GasMeter`.
- `ContractStorage`, `MemoryStorage`, `RocksDbStorage`.
- `RuntimeError`.

## Not for

- Writing contracts — use `sumc-sdk` (and `sumc-sdk-macros`).
- Node/state wiring — contract dispatch lives in `sumchain-state`
  (`contract_executor`) and node assembly in `sumchain-node`.
