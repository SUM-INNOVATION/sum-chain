# SUM Chain Production Operations & Launch Readiness Checklist

Operational checklist for running SUM Chain validators and full nodes in
production (mainnet).

> **Status:** current
> **Last verified:** height 8,716,604 · 2026-07-06 (live `chain_getChainParams` on `https://rpc.sumchain.io` + deployed genesis; deployed commit `21de231d` on both validators)
> **Consensus:** Proof of Authority (PoA) with depth-based finality.
> BFT is experimental/roadmap and not part of the supported production path.

## Consensus & Finality

- Production consensus is **PoA** — round-robin (or stake-weighted) proposer
  selection: the proposer for height `H` is `validators[H % N]`.
- **Depth-based finality:** a block at height `H` is finalized once the chain
  reaches `H + finality_depth`. The live `finality_depth` is **6** (≈18s at the
  3s block time). Finalized blocks cannot be reverted by reorg.
- A Tendermint-style BFT engine exists as **experimental/roadmap** work only.

**Code references:**
- [crates/consensus/src/poa.rs](../../crates/consensus/src/poa.rs) — production PoA engine.
- [crates/consensus/src/bft/](../../crates/consensus/src/bft) — experimental BFT (roadmap).
- [docs/architecture/bft-consensus.md](../architecture/bft-consensus.md) (experimental).

## Genesis

- The **root runtime `genesis.json`** is the genesis file production validators
  boot from (`sumchain run --config config.toml --genesis genesis.json`). Its
  validator set and allocations are the live chain's.
- [genesis/mainnet_genesis.json](../../genesis/mainnet_genesis.json) is a
  **template only** — its validators/allocations are placeholders. Production
  validators do **not** boot from it.
- All validators must run a **byte-identical** runtime `genesis.json`; any
  subprotocol activation heights are edited into each validator's runtime
  genesis identically, never into the template.
- [genesis/testnet_genesis.json](../../genesis/testnet_genesis.json) is the
  testnet template.

**Consistency check:** confirm the `genesis.json` on every validator hashes
identically before starting or restarting the network.

## Node Configuration

- Node config is TOML at the default path `config.toml`
  (`sumchain run --config config.toml`).
- The committed sample `config.toml` ships `bootnodes = []` and no
  infrastructure addresses. `mdns = true` only discovers peers on the local
  network.
- Production validators supply real bootnodes out-of-band, preferably via the
  systemd/CLI `--bootnodes` override (it takes precedence over `config.toml`, so
  it survives sample-config changes). See the joining-network guidance in the
  [README](../../README.md#run-a-node-join-the-live-network).

## Validator Setup

- Install/build the node (`cargo build --release`) and run under a process
  manager (e.g. systemd), `Restart=on-failure`.
- Generate a **fresh validator key per node**; never reuse another node's key.
- Being reachable as a block producer requires the validator's public key to be
  in the active validator set (defined in the runtime genesis and coordinated by
  the operator team) — running a node alone does not add it to the set.
- Supply bootnodes via `--bootnodes` (see Node Configuration).
- **Provision at least 4 GiB of memory per validator.** 4 GiB is the supported
  validator memory floor for this release — an OPERATIONAL minimum, not a
  consensus rule and not an eligibility gate. The shipped StatefulSets reserve
  it as an equal `requests.memory` / `limits.memory`. See
  [validator-memory-floor.md](validator-memory-floor.md), which also explains
  why the 256 MiB block write-set ceiling is derived from it.
- **A node accepts at most 50 inbound peers** (100 total) and now actually
  enforces that: a node at 50 refuses the 51st where it previously accepted it.
  `[network] max_peers` in `config.toml` does **not** change these numbers — it
  is read by nothing. See
  [p2p-admission-and-compatibility.md](p2p-admission-and-compatibility.md).

## Deployment Assets

- [docker-compose.yaml](../../docker-compose.yaml) — local/multi-node compose (root of repo).
- [deploy/kubernetes/](../../deploy/kubernetes) — StatefulSet manifests + ConfigMap
  (the ConfigMap ships `bootnodes = []`; per-pod bootnodes are set via `--bootnodes`).
- [deploy/monitoring/prometheus.yml](../../deploy/monitoring/prometheus.yml) — Prometheus scrape config.

## Monitoring

- Prometheus metrics are exposed by the node; scrape config in
  [deploy/monitoring/prometheus.yml](../../deploy/monitoring/prometheus.yml) and a
  Kubernetes `ServiceMonitor` in
  [deploy/kubernetes/servicemonitor.yaml](../../deploy/kubernetes/servicemonitor.yaml).
- Track per validator: current height, peer count, mempool size, and finalized
  height. `node_info` (health) exposes `current_height`, `peer_count`,
  `mempool_size`, `uptime_seconds`, `is_validator`.
- Watch for a validator falling behind its round-robin slots (see Restart
  coordination).

## State & Storage

- State is persisted in RocksDB via [sumchain-storage](../../crates/storage);
  accounts/storage are served through an LRU cache
  ([crates/state/src/cache.rs](../../crates/state/src/cache.rs)).
- The block state root is a content hash over state; see
  [crates/state/src/state.rs](../../crates/state/src/state.rs).

## Mainnet Parameters

Live values (verified at height 8,716,604 · 2026-07-06). `chain_getChainParams`
exposes only the `v2` / `omninode` / `education` gates; the other five
8,900,000 gates and the `governance` params object are verified from the
deployed genesis:

```json
{
  "chain_id": 1,
  "block_time_ms": 3000,
  "max_block_bytes": 2000000,
  "max_txs_per_block": 1000,
  "min_fee": 1000,
  "finality_depth": 6,
  "storage_fee_per_byte": 100,
  "max_metadata_bytes": 16384,
  "max_access_list_bytes": 16384,
  "activation_grace_blocks": 50,
  "abandonment_fee_percent": 10,
  "assignment_replication_factor": 3,
  "v2_enabled_from_height": 5200000,
  "omninode_enabled_from_height": 6000000,
  "education_enabled_from_height": 8900000,
  "contracts_enabled_from_height": 8900000,
  "governance_enabled_from_height": 8900000,
  "archive_unbonding_enabled_from_height": 8900000,
  "archive_reassignment_enabled_from_height": 8900000,
  "inference_settlement_enabled_from_height": 8900000,
  "inference_settlement_dispute_threshold_bps": 6667,
  "governance": {
    "validator_authority_threshold_bps": 6667,
    "quorum_bps": 2000,
    "pass_threshold_bps": 5000,
    "voting_period_blocks": 201600,
    "max_snapshot_holders": 10000,
    "proposal_bond": 0,
    "treasury": null
  }
}
```

- `v2_enabled_from_height` and `omninode_enabled_from_height` are past the
  current chain height — those subprotocols are **active** on mainnet.
- The six `*_from_height` gates set to `8900000` (education, WASM contracts,
  governance, archive unbonding #20, archive reassignment #62, inference
  settlement #61) are **deployed and code-backed; each activation gate is set to
  height 8,900,000 — active once the chain reaches it (≈2026-07-12)**. They
  auto-activate when the chain crosses 8,900,000; no further operator action is
  required beyond the coordinated genesis that set the gate.
- Governance admin/council authority is **validator-quorum** controlled
  (`validator_authority_threshold_bps 6667` → both validators of the current
  2-validator net must sign); there is no single council address. Inference-
  settlement dispute resolution is likewise validator-quorum controlled
  (`inference_settlement_dispute_threshold_bps 6667`).
- Query the RPC-exposed gates with:
  ```bash
  curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getChainParams","params":[]}'
  ```

## Restart & Rollback Coordination

Under PoA round-robin there is no proposer-skip: restarting a validator stalls
that validator's block slots until it rejoins, so coordinate restarts.

1. **Pause / investigate** — coordinate a validator halt if a critical issue is
   found; the chain stops advancing while proposers are down.
2. **Fix & test** — reproduce on a testnet/local network before rolling out.
3. **Coordinated restart** — bring validators back on a byte-identical
   `genesis.json` and the same binary; verify peers reconnect and finalized
   height advances.
4. **One at a time** — for rolling restarts, restart a single validator and wait
   for it to rejoin and produce before touching the next.
5. **Expect a short peer-compatibility window after each restart.** Peer
   protocol-digest declarations are held in memory and are forgotten on
   restart. Below the enforcement height this is an accepted property and needs
   no action; at or above it, peers the node had verified cannot supply blocks
   until each re-answers the handshake, which resolves on its own. Details and
   the test that pins both halves:
   [p2p-admission-and-compatibility.md](p2p-admission-and-compatibility.md).
5. **Never start an older binary on a data directory a newer binary has OPENED
   — not "executed a block": opened.** Snapshot restoration is the only
   supported rollback once a newer binary has touched the volume, and the
   snapshot must be taken BEFORE the newer binary first opens it.

   This supersedes the image-only rollback PR #254 describes. The 0.2.0-era
   binaries deployed today classify RocksDB's "Invalid argument" as corruption
   and auto-repair by default; the repair recovers only the `default` column
   family and moves every other family to `lost/`. Stage 1 adds one family
   (`application_journal`) at its FIRST OPEN, before any activation check and
   before any block. So reverting the image after that open -- even if the new
   binary then refused to start -- makes the old binary empty the database and
   re-initialise from genesis. Reproduced: 189 families before, 1 after;
   `blocks`, `state` and `meta` from 2000 rows to 0. With the real 0.2.0
   binary on a small Stage-1 volume the loss was partial instead: it loaded a
   height below its own finalized height and produced a different block at
   the next height (stage1-local-evidence.md §1.2). Either outcome is silent.

   The rollback target is therefore the pre-upgrade snapshot, restored into a
   NEW volume, running the EXACT old image digest. The Stage 1 rollout does not
   start until `tools/lane-b/rollout-preflight.py` prints `PREFLIGHT COMPLETE`
   (stage1-rollout-runbook.md §2.8): a ready snapshot of each validator's own
   volume, `Retain` volumes, the old digest, and a rehearsed, timed restore.

   From this release on the node fails closed instead: a data directory
   containing a family it does not know refuses to open, `auto_repair` is off
   by default, and "Invalid argument" is no longer treated as corruption. That
   protects the NEXT transition (rolling back to this binary), not this one --
   the binary that runs on a revert from Stage 1 is the deployed 0.2.0, which
   still has the defect. There is no in-place repair or migration command:
   `Database::repair` has no caller outside `crates/storage/src/db.rs`, and as
   implemented it would destroy every non-default family anyway. When a node
   refuses to open, the operator's options are to run the binary that wrote
   the data, or to restore the pre-upgrade snapshot.

   The same holds for the undo journal on its own. Its
   key shape changed, from height alone to `height ‖ block_hash`
   (`crates/storage/src/schema.rs`). The UPGRADE direction is handled in code: a
   journal written by an older binary is still read, because the reader falls
   back to the legacy key, and still deleted, because the delete removes both
   forms. The DOWNGRADE direction is not and cannot be: a journal written under
   the new key is invisible to a binary that only knows the old one, so rolling
   a validator back after it has executed even one block loses that block's undo
   record and the reorg that would have used it. If a rollback is unavoidable,
   restore the validator's data directory from a snapshot taken BEFORE the new
   binary first produced or imported a block, rather than pointing the old
   binary at the new data directory. The journals are node-local — neither
   `STATE_DIFFS` nor `CONTRACT_STATE_DIFFS` reaches the state root — so this is
   a per-validator recovery hazard and not a consensus one, which is why it
   belongs here and not in an activation height. (ACTIVATION-AUDIT row JR-1.)

## Security

- Keep validator keys off shared storage; restrict `config.toml`/key file perms.
- Do not commit real bootnode IPs, peer IDs, or validator keys to the repo.
- See [docs/architecture/security-overview.md](../architecture/security-overview.md)
  for the security architecture, threat model, and mitigations.

## Support Resources

- [README.md](../../README.md) — project overview, build/run, joining a network.
- [docs/operator-guide.md](../operator-guide.md) — operator entry point.
- [docs/rpc/api-reference.md](../rpc/api-reference.md) — JSON-RPC reference.
- [sdk/typescript/README.md](../../sdk/typescript/README.md) — TypeScript SDK guide.
- [docs/architecture/performance-guide.md](../architecture/performance-guide.md) — performance/tuning notes.
