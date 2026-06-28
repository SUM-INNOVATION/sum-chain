# sumchain-genesis

Genesis configuration for initializing a SUM Chain network — chain parameters,
initial validators, and prefunded accounts.

## Purpose

Defines and (de)serializes the genesis document and chain parameters used to
bootstrap a network, plus helpers to compute the genesis state root and block.

## Public interfaces

- `Genesis` — the genesis document. `new`, `from_file`/`to_file`,
  `from_json`/`to_json`, `validate`, `validator_pubkeys`, `genesis_proposer`,
  `parsed_alloc`, `compute_state_root`, `create_genesis_block`, `local_dev`.
- `ChainParams` — chain parameters incl. subprotocol activation gates
  (`*_enabled_from_height`); `with_v2_enabled` for dev. Sub-configs:
  `MessagingParams`, `DocClassParams`.
- `NodeConfig` — node config loader (`from_file`/`to_file`).
- `GenesisError` — error type.

Activation-gate semantics are documented under
[`docs/subprotocols/`](../../docs/subprotocols/).

## Not for

- Runtime chain state — this crate only describes the initial configuration;
  execution lives in `sumchain-state`.
