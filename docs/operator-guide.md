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

A start reads the node's local finality record (`finalized_height` and
`finalized_hash`: the height at or below which the node refuses to
reorganize, and the block there). The start is refused if the record cannot
be read, holds one key without the other, is above the head, or does not name
the canonical block at its height. The record is never reset to zero, and a
refused start changes nothing. A database with no record starts with nothing
finalized, as before. The record is written as one batch after each block that
finalizes another.

If that write fails, the consensus engine halts rather than run on with
finality it has not recorded. **The process does not exit.**
- It logs `consensus engine fail-stopped; restart to reload the committed
  chain` once, at error level, with the reason (`could not persist local
  finality at height …`).
- From then on it refuses every production and import with `node
  fail-stopped: …`, logged as `Failed to create block`, `Failed to import
  block` and `Failed to import synced block` warnings.
- It keeps serving RPC, and the liveness probe `/health` stays 200 (`"status":
  "ok"`): the process is alive.
- The readiness probe `/ready` answers 503 (`"ready": false`, `"status":
  "not_ready"`) with the reason in `checks.consensus_halted`, until the node is
  restarted. While the engine runs, `/ready` answers exactly as before.
- Nothing restarts the node automatically: a supervisor that restarts it only
  when it exits does not, and a liveness probe on `/health` does not fail.
  Alert on either signal: `/ready` returning 503 with `consensus_halted`, or the
  log line `consensus engine fail-stopped`.
- Restart the node to recover. The start reads the last record that was
  written, and the next block derives finality again.
- A block this validator produced in the slot whose finality write failed is
  kept but was never announced. After the restart, its peers fetch it by sync.
  Under round robin, the chain makes no progress from the halt until that
  restart.

Before installing a binary with this start check, run that binary's check on
each validator's data directory while the node is stopped:

```bash
sumchain check-finality-record --data-dir <validator data directory>
```

It opens the database read-only and writes nothing, applies exactly the check a
start applies, and prints the record with `Result: START_ACCEPTS`, or the reason
the start would refuse with the remedies that apply and `Result:
START_REFUSES`. It exits 0 when the start accepts the record, 2 when the start
would refuse it, and 1 when there is no database to check. Install the binary
only once every validator's directory passes. Do not use RPC `get_finality` for
this: it reports the running node's memory, not the stored record. `sumchain
info` prints the two stored keys but does not check them: it prints a missing
hash as zeros, omits a height it cannot decode, and opens the database
read-write.

If the check or a start refuses the record, rewrite the record before starting
this binary. Which tool rewrites it depends on what the record holds (the
check prints the remedies that apply):

| The record holds | `sumchain rollback --to-height <h>`, h below the recorded height | The previous binary, until one block finalizes |
|---|---|---|
| a height without its hash; another block's hash; an undecodable hash | rewrites both keys, in its own batch | rewrites both keys |
| a height above the head | rewrites both keys | no: it rewrites nothing until its head passes the recorded height |
| a hash without its height | no: it decides from `finalized_height`, finds none, and leaves the record as it is | rewrites both keys |
| an undecodable height | no: it stops with `Invalid finalized height bytes` | rewrites both keys |

Restoring the pre-upgrade backup of the directory, or resynchronizing from an
empty one, works in every case. Before an upgrade nothing has changed yet, so
the simplest remedy is usually the previous binary: start it again, let a block
finalize, stop it gracefully, and run the check again.

## Further Reading

- [operations/production-checklist.md](./operations/production-checklist.md) — full operations checklist.
- [../README.md](../README.md) — build/run and joining a network.
- [rpc/api-reference.md](./rpc/api-reference.md) — JSON-RPC reference.
