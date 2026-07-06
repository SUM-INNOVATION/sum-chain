# SUM Chain Operator Guide

A concise entry point for running a SUM Chain node (validator or full node).
For the full operational checklist see
[operations/production-checklist.md](./operations/production-checklist.md).

## Build & Run

```bash
cargo build --release
./target/release/sumchain run --config config.toml --genesis genesis.json
```

- **Config:** TOML at the default path `config.toml`
  (`--config config.toml`). The committed sample is a starting point, not a
  production config.
- **Genesis:** the root runtime `genesis.json` is the file production nodes boot
  from. All nodes on a network must run a **byte-identical** `genesis.json`.
  `genesis/mainnet_genesis.json` is a **template only** (placeholder
  validators/allocations) — nodes do not boot from it.

## Joining an Existing Network (Bootnodes)

The sample `config.toml` ships `bootnodes = []` on purpose — no infrastructure
addresses are committed. `mdns = true` only discovers peers on the local
network, so joining a network across hosts requires an explicit bootnode.

Obtain a current bootnode multiaddr from the operator team / a secure channel
(it is not stored in the repo, and real addresses must not be committed). Format:

```
/ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>
```

Supply it via the CLI/systemd override (recommended — it takes precedence over
`config.toml`, so it survives sample-config changes):

```bash
sumchain run --config config.toml --genesis genesis.json \
  --bootnodes /ip4/<PUBLIC_IP>/tcp/9933/p2p/<PEER_ID>
```

See the README's
[Run a node (join the live network)](../README.md#run-a-node-join-the-live-network)
section for details.

## Full Node vs. Block-Producing Validator

- Supplying a bootnode lets a node **sync** as a full node.
- **Producing blocks** additionally requires the validator's public key to be in
  the **active validator set**. Consensus is PoA round-robin (proposer for
  height `H` is `validators[H % N]`), and the set is defined in the runtime
  genesis and coordinated by the operator team — a node does not join the set by
  simply connecting.
- Generate your own validator key; never reuse another node's key.

## Monitoring

- The node exposes Prometheus metrics; see
  [deploy/monitoring/prometheus.yml](../deploy/monitoring/prometheus.yml) and the
  Kubernetes [ServiceMonitor](../deploy/kubernetes/servicemonitor.yaml).
- Check node health via `node_info` (`current_height`, `peer_count`,
  `mempool_size`, `uptime_seconds`, `is_validator`).
- Inspect live chain parameters (including `finality_depth` and the RPC-exposed
  activation gates) with `chain_getChainParams`. SNIP V2 storage and OmniNode
  inference attestation are **active** on mainnet; the 8,900,000-cohort gates
  (governance, education, WASM contracts, archive unbonding/reassignment,
  inference settlement) are **set to height 8,900,000 — active once the chain
  reaches it (≈2026-07-12)**. Full gate table:
  [operations/production-checklist.md](./operations/production-checklist.md#mainnet-parameters).

## Restarts

Under PoA round-robin there is no proposer-skip, so restarting a validator
stalls that validator's block slots until it rejoins. Restart in a known window,
one validator at a time, and confirm it reconnects and produces before touching
the next.

## Further Reading

- [operations/production-checklist.md](./operations/production-checklist.md) — full operations checklist.
- [../README.md](../README.md) — build/run and joining a network.
- [rpc/api-reference.md](./rpc/api-reference.md) — JSON-RPC reference.
