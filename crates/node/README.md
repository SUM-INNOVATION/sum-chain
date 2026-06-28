# sumchain-node

The SUM Chain full node — the `sumchain` binary that ties all components
together (consensus, state, storage, p2p, RPC).

## Purpose

Boots and runs a node: loads genesis/config, wires the consensus engine, state
executor, storage, P2P networking, mempool, and the RPC server, then produces
and/or follows blocks.

## Entry points

- `sumchain` binary — `cargo run --bin sumchain -- run --genesis <file> --data-dir <dir> [--validator-key <file>] [--rpc-addr <addr>] …`
- `main.rs` — CLI / startup.
- `node.rs` — the assembled node; `config.rs` — node configuration;
  `consensus_wrapper.rs` — consensus integration; `tx_broadcaster.rs` — outbound tx gossip.

## Public interfaces

- `TxBroadcaster` (+ `TxBroadcasterConfig`, `TxBroadcasterStats`).
- Primarily a binary; treat it as the run target, not a stable library API.

See [`docs/operations/production-checklist.md`](../../docs/operations/production-checklist.md)
for operational guidance.

## Not for

- Embedding as a library — depend on the individual crates (`state`, `consensus`,
  `rpc`, …) instead.
