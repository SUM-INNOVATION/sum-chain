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
- **Unknown genesis fields are refused.** The document, `params` and every
  structure inside `params` accept only the fields the binary defines. Anything
  else (a misspelled gate, a parameter at the wrong level) stops the command
  when it loads the genesis, before the data directory or database is created
  or touched, with an error naming the field. That holds for `run`, `init`,
  `acknowledge-consensus-config` and `rollback --genesis`. The one exception is
  a top-level `_comment`, which must be a string and is ignored (any other
  value, `null` included, is refused). Older binaries ignored such a field. This changes only which
  files are accepted: a file that was accepted before is read to the same
  values, so its genesis hash, activation and protocol digests and
  consensus-configuration commitment do not change.

  **Before upgrading a node to a binary with this check**, run the new binary
  against a copy of that node's runtime `genesis.json`, with a throwaway data
  directory (never the node's own). It uses the same loader as `sumchain run`:

  ```bash
  probe=$(mktemp -d)
  sumchain init --genesis ./genesis.json --data-dir "$probe/data"; echo "exit $?"
  rm -rf "$probe"
  ```

  Exit 0 means the node will load its genesis after the upgrade. An
  `unknown field` error means it would refuse to start. Deleting that key keeps
  the rules the node runs today, because the old binary never read it; it is
  still a change to a file that must stay byte-identical across nodes, so make
  it on every node together. Correcting a misspelled gate instead *changes*
  the rules (it sets a gate that is unset today) and is an activation decision,
  not an upgrade step. A `_comment` error (a top-level `_comment` that is not a
  string) is fixed the same way, by deleting it or making it a string, on every
  node together; the node never read it.

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

- Supplying a bootnode lets a node **sync** as a full node. It compares heights
  with each peer when they connect, and when a gossiped block arrives whose
  parent it does not have (a block it missed while not connected to its
  producer), it requests the missing blocks from the peer that sent it and logs
  `Missing blocks <from>..=<to> below gossiped block …; requesting them from …`.
- **Producing blocks** additionally requires the validator's public key to be in
  the **active validator set**. Consensus is PoA round-robin (proposer for
  height `H` is `validators[H % N]`), and the set is defined in the runtime
  genesis and coordinated by the operator team — a node does not join the set by
  simply connecting.
- Generate your own validator key; never reuse another node's key.
- Use the validator key only with the node and its own commands: never with an
  arbitrary-message signer, a general-purpose wallet or an RPC service. See
  [the production checklist's Security section](operations/production-checklist.md#security).

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
