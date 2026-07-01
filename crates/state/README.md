# sumchain-state

State management and transaction execution for SUM Chain.

## Purpose

Applies blocks and transactions to chain state — account balances and nonces,
the mempool, state caching/snapshots, and the per-payload executors that carry
out each `TxPayload` variant.

## Main modules

- `state` — `StateManager`, the account/state store.
- `executor` — `BlockExecutor` and `TxExecutionResult`; applies blocks and
  dispatches transactions to the payload executors.
- `mempool` — `Mempool`, `MempoolConfig`, `MempoolStats`.
- `cache` — `StateCache` (account caching).
- `snapshot` — `SnapshotManager` and snapshot/restore types for state sync.
- Payload executors — `token_executor`, `nft_executor`, `contract_executor`,
  `staking_executor`, `messaging_executor`, `docclass_executor`,
  `policy_account_executor`, `inference_attestation_executor`, and the SRC-8X
  family executors (`tax`, `equity`, `agreement`, `legal`, `property`,
  `healthcare`, `employment`, `finance`).
- `node_registry`, `schema_validator`, `storage_metadata` — supporting state.

## Public interfaces

- `StateManager` — the state entry point.
- `BlockExecutor`, `TxExecutionResult` — block/transaction application.
- `Mempool`, `MempoolConfig`, `MempoolStats`.
- `StateCache`, `SnapshotManager`.
- The `*Executor` / `*ExecutionResult` types re-exported per payload family.

## Not for

- Persistence — durable storage lives in `sumchain-storage`.
- Block production / finality — see `sumchain-consensus`.
- Payload type definitions — see `sumchain-primitives` and the per-standard
  crates (`sumchain-token`, `sumchain-nft`).
