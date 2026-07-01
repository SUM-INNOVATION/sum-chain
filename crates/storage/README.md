# sumchain-storage

Persistent key-value storage for SUM Chain, backed by RocksDB.

## Purpose

Provides the RocksDB database wrapper, column-family schemas for blocks, state,
transactions and receipts, per-family record stores, and database maintenance
(pruning, backups).

## Main modules

- `db` — `Database`, `DatabaseConfig`, the `cf` column-family names, `BackupInfo`.
- `schema` — key/value schema helpers for core chain data.
- `pruner` — `Pruner`, `PrunerConfig`, `PruneStats`, `DbStats`.
- Per-family record stores — `tax_store`, `equity_store`, `agreement_store`,
  `legal_store`, `property_store`, `healthcare_store`, `employment_store`,
  `finance_store`, `docclass_store`, `messaging_store`, `policy_account_store`.

## Public interfaces

- `Database`, `DatabaseConfig`, `cf`, `BackupInfo`.
- `Pruner`, `PrunerConfig`, `PruneStats`, `DbStats`.
- The `*Store` types re-exported per record family.

## Not for

- Execution logic — reads/writes are driven by `sumchain-state`.
- Record/type definitions — see `sumchain-primitives`.
