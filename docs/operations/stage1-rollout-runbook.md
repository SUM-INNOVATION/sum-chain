# Stage 1 rollout runbook — binary rollout with every activation gate UNSET

> **Not the production procedure.** A read-only inspection on 2026-09-26
> found production is a native binary under systemd: no Kubernetes, no
> containers. Use [stage1-native-runbook.md](stage1-native-runbook.md). The
> analysis below still applies (the database-open hazard, SIGTERM, halts,
> genesis), but its `kubectl` commands and its fixed dialer/listener
> assignment do not. The inspection found 7jUZ… is the **dialer**, not the
> listener. Roles are now derived from each host's configuration.

> **Status:** preparation. Nothing in this document has been executed against
> production. It was written from the repository at `8954b0d0`, the node source,
> and the public read-only endpoint `https://rpc.sumchain.io`. The author had
> **no cluster access**: no `kubectl`, no kubeconfig, no SSH.
>
> **Scope:** Stage 1 as defined in
> [activation-rollout-evidence.md](activation-rollout-evidence.md): every
> validator runs the exact release binary, with **no** activation height set
> anywhere. Stage 2 (heights) is out of scope.
>
> Each statement below is labelled **[V]** verified (with the evidence), **[I]**
> inferred (with the reasoning), or **[U]** unresolved (with the command that
> closes it). Being unable to reach production is never evidence. Where this
> document says "the repo says", it means the repo, not the cluster.

---

## 0. The five findings that shape the plan

### 0.1 One validator down halts the whole chain. A "rolling" upgrade is two planned halts.

**[V] from code.** The proposer for height `H` is fixed. No timeout, no
skip-proposer, no fallback exists anywhere in the PoA engine:

* `crates/consensus/src/poa.rs:284-309` `compute_proposer`: with no active
  epoch validator set it falls back to `genesis_validators[H % N]`.
* `crates/consensus/src/poa.rs:1721-1766` `run_block_producer`: on each
  `block_time_ms` tick a validator proposes `current_height + 1` **only if**
  `is_proposer(height)`. Otherwise it does nothing and waits for the next
  tick. There is no path that proposes someone else's height.
* `crates/consensus/src/poa.rs:1153-1156` `draft_block` refuses with
  `NotProposer` for any height not assigned to this key.
* `crates/state/src/executor.rs:4529-4538` `validate_header`: an importing
  node **rejects** any block whose `proposer_pubkey != validators[H % N]`. So
  even a patched proposer could not fill a missing validator's slot.
* `crates/consensus/src/poa.rs:405-453` `check_finality`: finality is purely
  depth-based (`current_height - finality_depth`), so it stops when the head
  stops.

With `N = 2`, if validator X is down, the first height `H` with
`H % 2 == index(X)` can never be produced. The chain stops at `H - 1`, at most
one block after X goes down, and resumes only when X is back, has the tip, and
proposes `H`.

**[V] from live chain history.** Block timestamps (from
`sum_getBlockByHeight`) show chain-wide halts in the last ~2.5 months. Each
line is the largest single inter-block gap inside a 20,000-block window whose
total time was over 60 s more than expected:

| last block before the gap | gap | UTC at the last block |
|---|---|---|
| 9,432,295 | 7,651 s (2 h 08 m) | 2026-07-18T20:25:28Z |
| 10,026,099 | 1,782 s (30 m) | 2026-07-29T06:03:18Z |
| 10,140,205 | 3,168 s (53 m) | 2026-07-31T06:06:21Z |
| 11,635,620 | 52,495 s (14 h 35 m) | 2026-08-26T06:11:42Z |
| 12,521,733 | 5,585 s (1 h 33 m) | 2026-09-11T06:03:37Z |

The 2026-09-11 gap matches the model exactly. The public RPC node's process
started at about 07:36:40Z. From its `get_metrics` counters since that start
(`blocks_produced 359,663`, `blocks_imported 359,662`, `blocks_processed
719,325` up to height 13,241,058), it produces the **even** heights, so it is
validator index 0. The chain stopped at 12,521,733, an odd block from
validator 1. The next slot, 12,521,734, belonged to the node that was down. That
block was produced about 3 s after the node came back. **[I]** Nothing public
explains the other gaps. They are consistent with validator restarts, but that
is not established.

**Consequence for the plan.** A validator restart is a **planned chain halt**,
the expected behaviour and not an incident. Upgrading two validators one at a
time means **two halts**, with a mixed-version run between them. That run is the
reason to do it this way. A single coordinated halt of both would give one halt,
but no validator running the old rules would ever check a block from the new
binary. The mixed-version window is Stage 1's consensus-equivalence test (§4.3).

### 0.2 A downgrade after the new binary has opened the database destroys that database

**[V] by a local probe, using this tree's storage crate and the same `rocksdb`
0.22.0 / `librocksdb-sys` 0.16.0+8.10.0 that every 0.2.0-era lockfile pins.**

* The new binary opens RocksDB with `create_missing_column_families(true)`
  (`crates/storage/src/db.rs:844`). It carries one column family that no
  0.2.0-era binary has: `application_journal` (`db.rs:582`, added 2026-09-17
  in `a72c9b86`). The HEAD set has 188 CFs. The set at `c51eead1` (first 0.2.0
  commit, 2026-07-09) differs by `application_journal`, `beacon_state`,
  `beacon_state_diffs`, `compute_pool_state` and `compute_pool_state_diffs`. The
  set at `8abbd304` (last 0.2.0 commit, 2026-09-01) differs by
  `application_journal` only.
* The CF is created when the database is opened, at `crates/node/src/node.rs:187`.
  That is **before** any activation check, journal check or refusal. **A new
  binary that refuses to start has still added the CF.**
* An older binary opening that directory gets
  `Invalid argument: Column families not opened: application_journal`
  (reproduced). Its `is_corruption_error` treats any `"invalid argument"` as
  corruption (`db.rs:966-973`, identical at `c51eead1` and `8abbd304`).
  `auto_repair` defaults to `true` (`db.rs:821`, same in both). So it runs
  `DB::repair` with default options.
* **Reproduced result of that repair:** every one of the 188 named column
  families is dropped from the manifest and every SST moves to `lost/`. The
  reopen then **succeeds** on an empty database. After repair, rows in `blocks`,
  `state` and `meta` numbered **0**, down from 2,000 each. An older node would
  come up with no chain and **re-initialise from genesis**.

**[V] with the real binaries (docs/operations/stage1-local-evidence.md §1.2).**
The deployed 0.2.0 binary (`8abbd304`), started on a copy of a volume that the
Stage 1 binary had advanced from height 27 to 38, logged `Invalid argument:
Column families not opened: application_journal`, then `Database appears
corrupted, attempting repair...` and `Database opened successfully after
repair`. It loaded height **27** while its restored finality state read
**35 finalized**, then produced a **different** block 28 (`0xc28f…`; Stage 1's
was `0xdbc281…`). On this small database the loss was partial rather than a
wipe, and that is worse: the node looks healthy, and it re-produces heights
its peer holds as final. `auto_repair` is hard-coded `true` in 0.2.0 (the node
never builds a `DatabaseConfig`), so no setting prevents it.

**Rule:** once the Stage 1 binary has started on a volume, even for a moment and
even if it failed, **the 0.2.0 binary must never open that volume.** Not to
"check", not read-only, not once.
From then on, rollback means restoring the volume from a snapshot taken before
that first start **into a new volume**, and starting the **exact old image
digest** on that new volume. This goes further than the
existing warning at `production-checklist.md:183` ("never downgrade a binary
that has executed a block"). The hazard is triggered by the **open**, not by the
first executed block.

**[I]** This holds only if the deployed binary was built from this repository's
0.2.0-era source (see §0.5). If it was built from something else, re-run the
probe against that source before relying on either answer.

### 0.3 The node ignores SIGTERM

**[V] from code.** The node's only shutdown trigger is
`tokio::signal::ctrl_c()`, which is SIGINT (`crates/node/src/node.rs:1193-1196`).
The image runs the binary as PID 1 with an exec-form `ENTRYPOINT ["sumchain"]`
and no init process (`Dockerfile:119`).

**[I]** Linux does not deliver SIGTERM to a PID 1 that has no handler for it.
A pod delete therefore waits the whole `terminationGracePeriodSeconds`
(default 30 s, none is set in any manifest) and then sends SIGKILL. That adds
about 30 s to each halt, and every shutdown is unclean, so RocksDB replays its
WAL on the next start. §4.2 sends SIGINT explicitly.

### 0.4 Which validator restarts first matters

**[V] live.** The public RPC node reports `outbound_connections 1,
inbound_connections 0, connected_peers 1` (`get_p2p_stats`). It is the dialer.
The other validator is the listener. The dialer is validator index 0
(`GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8`, header proposer
`e64e11c6…a4cd`), from the counter arithmetic in §0.1.

**[I] from source at `8abbd304`** (`crates/p2p/src/network.rs:481`). A 0.2.0-era
binary dials its bootnodes **once, at startup**, with no retry. The
retry-while-isolated loop (`BOOTNODE_RETRY`, 30 s) only arrived in `e2d0ab79`
(2026-09-04). So if the **listener** restarts first, the old dialer loses its
only connection and, **[I]**, never redials. The chain would stay halted until
someone also restarts the old dialer. If the **dialer** restarts first, it
arrives on the new binary, dials the listener at startup and retries every 30 s
until it connects.

**Order: dialer (validator index 0, the one serving `rpc.sumchain.io`) first,
listener second.**

**[I] The second restart has its own risk.** The Stage 1 binary's `/ready` is
true only once p2p sync reports synced **or** the node has passed the height it
started at (`crates/node/src/node.rs:1306-1320`, `:1400-1406`). A headless
Service publishes DNS only for Ready pods unless `publishNotReadyAddresses:
true` is set, and none of the repo's Services set it. Suppose the listener stops
right after proposing its own block, so its tip is its own block and the next
slot is the dialer's. It cannot produce, so it never becomes Ready, so its DNS
name never resolves, so the dialer cannot reach it. That is a deadlock. It
applies **only** if the dialer's bootnode is a DNS name of a headless Service.
§2.5 checks for it.

### 0.5 The repo's Kubernetes manifests do not describe production

| fact | label | evidence |
|---|---|---|
| Production has **two** validators | **[V]** live | `sum_getValidators` returns exactly `GW1pJKzq…EbEv8` and `7jUZxm5r…Liydy`. In 120 consecutive headers (13,240,944–13,241,063) proposers alternate strictly, 60/60, one per key, even heights to `e64e11c6…` and odd to `6407afe6…`. Samples at heights 1, 2, 3, 1,000, 100,000, 1,000,000, 5,199,999, 5,200,000, 6,000,000, 8,900,000, 10,000,000, 12,000,000, 13,000,000 and 13,200,000 show only these two keys, all on the parity rule. |
| These are the two keys in the **committed root `genesis.json`** | **[V]** | Its `validators` array is exactly these two, in this order. Base58 decoding gives the header proposer hex values. |
| The committed root `genesis.json` produces the **live genesis block** | **[V]** | Computed locally with this tree's `Genesis::create_genesis_block`: state root `0x5fa18c9e…11ff2`, block hash `0x1156d350…d68e6`. Both equal live `sum_getBlockByHeight [0]`. This covers `validators`, `alloc` and `genesis_time`. It does **not** cover `params`, and the live params contain activation heights the committed file lacks (§3). |
| The repo contains **four** validator StatefulSets | **[V]** | `statefulset.yaml` is a DEPRECATED 3-replica set with one shared key Secret, which is one identity on three pods. `statefulset-validator-{1,2,3}.yaml` are three single-replica sets with per-validator Secrets. That is up to six pods and up to four identities, for a network that has two. |
| The committed ConfigMap genesis cannot boot **any** node | **[V]** | `Genesis::from_file` on it: `JSON parse error: missing field block_time_ms`. It is `chain_id 1337`, `validators: []`, `alloc: {}`, `params: {}`. Its header claims it is "identical to genesis/local_genesis.json". **That claim is false** (§3). |
| A 0.2.0-era binary could not have used the manifests' `/dns4/…` bootnode | **[V]** from `e2d0ab79`'s message | "Kubernetes peer discovery is broken on main today … `/dns4/sumchain-validator-1-0…` … which the transport rejects as MultiaddrNotSupported". Production's dialer is connected, so it does not dial that way. |
| The ops checklist describes **systemd** hosts, not Kubernetes | **[V]** repo text | `production-checklist.md` has "run under a process manager (e.g. systemd)" and `sumchain run --config config.toml --genesis genesis.json`, and records the deployed commit as `21de231d` on 2026-07-06. That commit is workspace version 0.1.0. Live now reports `0.2.0`, so the deployment has changed since. |
| Production runs a 0.2.0-era binary | **[V]** live, **[I]** source window | `node_info.version = "0.2.0"` (`CARGO_PKG_VERSION`, `crates/rpc/src/server.rs:32`). The workspace was `0.2.0` from `c51eead1` (2026-07-09) until `2e30fcab` (2026-09-01). `chain_getActivationStatus` and `chain_getSyncCapability` return `-32601`. |

**Conclusion [I]:** the repo's manifests are templates for a 3-validator
Kubernetes/SNIP-testnet layout. Production is a 2-validator network whose
deployment is **not** represented in this tree. It may not be on Kubernetes at
all. **§2.1 is a hard gate:** do not start until an operator has established
what production actually runs on and mapped each validator key to a workload.

---

## 1. Measured live state (public RPC, read-only)

All requests were `POST https://rpc.sumchain.io` with
`content-type: application/json`, body
`{"jsonrpc":"2.0","id":1,"method":M,"params":P}`. The endpoint is behind
Cloudflare. All 38 `node_info` calls (8 plus 30 with `Connection: close`)
returned the same libp2p peer id
`12D3KooWKDR6B3KRApHb7Ee81pE9AyW7tGks2ctZsMvSXsmfc9iL`, so one node answers.

| UTC | method | result |
|---|---|---|
| 2026-09-23T19:20:32Z | `eth_blockNumber` | `0xca0ad6` = 13,241,046 |
| 2026-09-23T19:20:32Z | `chain_getChainParams` | `chain_id 1`, `block_time_ms 3000`, `finality_depth 6`, `max_txs_per_block 1000`, `min_fee 1000`, `v2 5,200,000`, `omninode 6,000,000`, `education 8,900,000`, `governance 8,900,000`, `monetary_policy null`, `service_grants null`, `governance.validator_authority_threshold_bps 6667` |
| 2026-09-23T19:20:32Z | `chain_getActivationStatus`, `eth_chainId`, `net_version`, `web3_clientVersion` | `-32601 Method not found` |
| 2026-09-23T19:20:48Z | `health` | `{"status":"ok","chain_id":1,"height":13241057,"peer_count":1,"is_validator":true,"is_synced":false}` |
| 2026-09-23T19:20:48Z | `node_info` | `version "0.2.0"`, `network "sumchain-1"`, `uptime_seconds 1079049`, `peer_count 1` |
| 2026-09-23T19:20:48Z | `get_finality` | `finalized 13,241,051`, `current 13,241,057`, `depth 6` |
| 2026-09-23T19:20:48Z | `get_p2p_stats` | `connected_peers 1`, `outbound 1`, `inbound 0`, `banned 0` |
| 2026-09-23T19:20:48Z | `get_metrics` | `blocks_produced 359663`, `blocks_imported 359662`, `block_errors 0`, `current_height 13241058` |
| 2026-09-23T19:20:48Z | `validatorSet_getCurrent` | `null`, so no epoch validator set is stored and proposer selection uses the genesis round-robin fallback |
| 2026-09-23T19:20:48Z | `staking_getActiveValidators` | `[]` |
| 2026-09-23T19:20:48Z | `epoch_getInfo` | `epoch_length 14400, stake_weighted_selection true`. **Hardcoded constants** (`crates/rpc/src/server.rs:3302-3304`). This is not evidence of anything. |
| 2026-09-23T19:20:48Z | `chain_getSyncCapability` | `-32601` |
| 2026-09-23T19:20:48Z | `get_peers` | `[]`, which does not match `get_p2p_stats` (1 connected). The old binary's `get_peers` does not list the peer. |

**Block interval, wall clock.** `eth_blockNumber` every 30 s, 13 samples:
`2026-09-23T19:20:39Z` = 13,241,051 → `2026-09-23T19:26:40Z` = 13,241,292. That
is 241 blocks in 361 s, **1.498 s/block** (±0.4 % for ±1 block). **From
headers:** 119 intervals over 13,240,944–13,241,063 total 178.275 s, 1.498
s/block. Individual gaps alternate between about 1.275 s and 1.725 s, which is
two independent 3,000 ms proposer tickers out of phase. This matches the
decision packet §0.3 (1.502 s/block, about 57,500 blocks/day).

**Genesis block (live):** hash
`0x1156d350e7d0ac45cb96bfca25d57c71675ceea5949ea44d81432d08baed68e6`,
state root `0x5fa18c9e8b229ac4cec3aca0b28eba87e2bb1b54c249510f16f084c421511ff2`,
proposer `e64e11c6…a4cd`.

---

## 2. Pre-flight: read-only, all must pass

Set these once:

```bash
export NS=sumchain                 # confirm in 2.1; the repo's namespace
export CTX=<production-context>    # never rely on the current-context default
alias k="kubectl --context $CTX -n $NS"
```

### 2.1 Gate: what is production actually running on?

```bash
kubectl config get-contexts
k get statefulsets,deployments,daemonsets,pods -o wide --show-labels
k get pods -o custom-columns='POD:.metadata.name,NODE:.spec.nodeName,IMAGE:.spec.containers[*].image,IMAGEID:.status.containerStatuses[*].imageID,READY:.status.containerStatuses[*].ready,RESTARTS:.status.containerStatuses[*].restartCount'
for s in $(k get sts -o name); do echo "== $s"; k get $s -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}{.spec.template.spec.volumes}{"\n"}{.spec.updateStrategy}{"\n"}'; done
```

For each validator pod, map pod to validator key. Use a local port-forward
tunnel, which changes nothing in the pod:

```bash
k port-forward pod/<POD> 18545:8545 &   # one at a time
curl -s localhost:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_info","params":[]}' | jq '{peer_id,version,current_height,is_validator}'
curl -s localhost:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_metrics","params":[]}' | jq '.result.blocks'
curl -s localhost:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_p2p_stats","params":[]}' | jq .result
```

A node whose `blocks_produced` matches the count of even heights since its start
is validator 0 (`GW1p…`). Odd heights means validator 1 (`7jUZ…`).

**Pass:** exactly two validator pods (or hosts) with `is_validator: true`. One
maps to `GW1p…` and one to `7jUZ…`. Record which one has
`outbound_connections ≥ 1` (the **dialer**, `$POD_D`/`$STS_D`) and which has
only inbound (the **listener**, `$POD_L`/`$STS_L`). Also record every other pod
selected by `app.kubernetes.io/component=validator`. **Stop if** any key has
two pods (the deprecated shared-Secret layout), if more than two
validator-key pods exist, or if production is not on this cluster. For a
systemd deployment, see §6.

### 2.2 Gate: genesis bytes

Expected values from this tree:

| file | sha256 (bytes) | sha256 of `jq -S -c 'del(.params)'` | loads? |
|---|---|---|---|
| root `genesis.json` | `d90fa1e7a6435f53155b25f1662042217602442620c63923700b6b783555815d` | `23d767306e5960ddb9d365747e707e63fba6390f986d5ba78d0c193b0bc423d0` | yes, `chain_id 1`, genesis hash = live |
| `genesis/local_genesis.json` | `009983f9ab76cc37a2658b20eee70d7ffe3e503b65b591697d1c17b3974f0ba5` | `8480b76bbe00d084f3f3d058c56867b4ad2842868f28ae76beb42a4947ab0836` | yes, `chain_id 1337`, different chain |
| ConfigMap `data["genesis.json"]` as committed | `47cf132ddbe3cc3a83c71afe5a782595f9d8e6e81c60c7810eac148cfe0b362f` | n/a | **no**, missing `block_time_ms` |

All three differ from one another. **The deployed genesis cannot byte-equal the
committed root `genesis.json`.** Live `chain_getChainParams` carries
`v2_enabled_from_height: 5200000` and three other heights that the committed
file does not set (the decision packet §0.9 calls it "that base plus edits").
Byte equality with `d90fa1e7…` is therefore **not** the test.

```bash
# What each validator actually mounts. Resolve the path from the pod spec first:
k get pod <POD> -o jsonpath='{.spec.containers[0].args}{"\n"}{.spec.containers[0].volumeMounts}{"\n"}{.spec.volumes}{"\n"}'
# Copy it OUT. A read-only cat; compute the hash locally, since the image has no jq.
k exec <POD> -c sumchain -- cat /config/genesis.json > genesis.<POD>.json
sha256sum genesis.<POD>.json
jq -S -c 'del(.params)' genesis.<POD>.json | sha256sum   # must be 23d76730…23d0
jq -S '.params' genesis.<POD>.json                         # record, and diff the two validators
# And the ConfigMap as stored in the API server, if that is the source:
k get configmap sumchain-config -o jsonpath='{.data.genesis\.json}' | sha256sum
```

**Pass:** (a) both validators' mounted files have **identical** sha256. (b) The
params-stripped hash is `23d76730…23d0`, the committed validators, alloc and
genesis time. (c) `jq '.params | to_entries | map(select(.key|endswith("_from_height")) | select(.value != null)) | from_entries'`
lists only gates on `GATES_PREDATING_ACTIVATION_RECORDING`
(`crates/genesis/src/lib.rs:2783`). Any other non-null height at or below the
head will make the Stage 1 binary **refuse to start**
(`crates/node/src/node.rs:514-608` `check_activation_parameters`, first-start refusal at `:563`). That refusal comes *after* the database
open, so it trips §0.2.

**(d) — and this is the one the three conditions above do NOT catch: the four
live heights must be PRESENT, with these exact values.**

```bash
jq -c '.params | {v2_enabled_from_height, omninode_enabled_from_height,
                  education_enabled_from_height, governance_enabled_from_height}' genesis.<POD>.json
# must print exactly:
# {"v2_enabled_from_height":5200000,"omninode_enabled_from_height":6000000,"education_enabled_from_height":8900000,"governance_enabled_from_height":8900000}
```

Those are the values live `chain_getChainParams` reports (read 2026-09-23), and
all four passed millions of blocks ago. A genesis MISSING them fails loudly
nowhere. All four are on `GATES_PREDATING_ACTIVATION_RECORDING`, and
`retroactive_gates_on_a_first_start` exempts that list
(`crates/genesis/src/lib.rs`), so the Stage 1 binary **starts normally** with
`v2`, `omninode`, `education` and `governance` read as `None` — disabled — on a
network that has run them since those heights. The 0.2.0 validator exchanges no
protocol digest, so nothing compares the two. Any block that uses one of those
features is then judged differently by the two validators: a consensus split,
with no refusal and no log line to announce it. Conditions (a)–(c) all pass for
the committed root `genesis.json`, which is exactly the file an operator is
most likely to reach for.

**Therefore: never swap the genesis file as part of this upgrade.** Stage 1
starts on the SAME genesis bytes the 0.2.0 node is running now — copied out in
the block above, byte-identical, not regenerated and not replaced with any
committed file. This rollout changes the image and nothing else.

### 2.3 Gate: resources, QoS, schedulability

What the repo declares **[V]**. There are no init or sidecar containers in any
manifest. Each pod has one container, `sumchain`.

| manifest | replicas | cpu req / lim | mem req / lim | QoS | PVC | anti-affinity |
|---|---|---|---|---|---|---|
| `statefulset.yaml` (deprecated) | 3 | 500m / 2000m | 4Gi / 4Gi | **Burstable** | `data` 100Gi `fast-ssd` RWO | preferred, hostname |
| `statefulset-validator-1.yaml` | 1 | 500m / 2000m | 4Gi / 4Gi | **Burstable** | `data` 100Gi `fast-ssd` RWO | none |
| `statefulset-validator-2.yaml` | 1 | 500m / 2000m | 4Gi / 4Gi | **Burstable** | same | none |
| `statefulset-validator-3.yaml` | 1 | 500m / 2000m | 4Gi / 4Gi | **Burstable** | same | none |

None set `updateStrategy` (default `RollingUpdate`, so changing the image
immediately deletes the pod), `terminationGracePeriodSeconds` (default 30 s),
`priorityClassName`, or a `PodDisruptionBudget`. **[I]** A node drain can
therefore take a validator down, and with two validators that halts the chain.

What production runs, and whether 4Gi fits:

```bash
k get pods -l app.kubernetes.io/component=validator -o custom-columns='POD:.metadata.name,NODE:.spec.nodeName,QOS:.status.qosClass,REQ:.spec.containers[*].resources.requests,LIM:.spec.containers[*].resources.limits'
# Allocatable on every candidate node
kubectl --context $CTX get nodes -o custom-columns='NODE:.metadata.name,CPU:.status.allocatable.cpu,MEM:.status.allocatable.memory,ZONE:.metadata.labels.topology\.kubernetes\.io/zone'
# What is already reserved on it
kubectl --context $CTX describe node <NODE> | sed -n '/Allocated resources/,/Events/p'
# Where the validator's volume can attach. A zonal RWO PV pins the pod to that zone or node.
PV=$(k get pvc data-<STS>-0 -o jsonpath='{.spec.volumeName}'); kubectl --context $CTX get pv $PV -o jsonpath='{.spec.nodeAffinity}{"\n"}{.spec.persistentVolumeReclaimPolicy}{"\n"}'
```

**Pass rule, per validator.** Take the nodes the PV can attach to. On at least
one of them, `allocatable.memory − (sum of memory requests of all other
non-terminated pods on that node, excluding the validator pod being replaced) ≥
4Gi`, and likewise `≥ 500m` CPU. If the rollout also raises the memory request
(the comment in `statefulset.yaml` says it was 1Gi), compute against 4Gi.
**Fail:** the replacement pod would sit `Pending` and the chain would stay
halted for as long. Do not start. Resolve capacity first, or leave resources
unchanged in this rollout.

### 2.4 Gate: a restorable snapshot path exists

Layout from the manifests **[V]**: the PVC `data` is mounted at `/data`, and
`node.toml` sets `data_dir = "/data"`. The RocksDB directory **is** `/data`,
because `Database::open_default(&data_dir)` is at `crates/node/src/node.rs:187`.
It is a single RocksDB instance with 188 column families at HEAD.

The built-in `sumchain backup` (`crates/node/src/main.rs:560`) cannot be used
here, for two reasons. It needs the RocksDB lock, which the running node holds.
And run from the **new** image, it opens the directory with `open_default` and
so creates `application_journal`, which is §0.2. Use volume snapshots.

```bash
kubectl --context $CTX get volumesnapshotclass
kubectl --context $CTX get storageclass fast-ssd -o yaml | grep -E 'provisioner|reclaimPolicy|volumeBindingMode'
k exec <POD> -c sumchain -- du -sh /data     # size, to estimate snapshot and restore time
```

**Pass:** a `VolumeSnapshotClass` exists for the PV's CSI driver, or a
cloud-provider disk snapshot procedure exists and has been rehearsed.
**Fail:** there is no way to take the pre-upgrade copy that §0.2 makes the
only rollback. Do not start.

### 2.5 Gate: peer addressing, for the §0.4 deadlock

```bash
k get pod $POD_D -o jsonpath='{.spec.containers[0].args}{"\n"}'   # --bootnodes value
k exec $POD_D -c sumchain -- cat /config/node.toml | grep -A3 '^\[network\]'
k get svc -o custom-columns='SVC:.metadata.name,CLUSTERIP:.spec.clusterIP,PUBLISH_NOT_READY:.spec.publishNotReadyAddresses,SELECTOR:.spec.selector'
```

**Pass:** the dialer's bootnode is a literal `/ip4/…` address that is stable
across a listener pod restart, or a DNS name whose Service has
`publishNotReadyAddresses: true`. **If it is a headless-Service DNS name
without that flag,** get an owner decision before step 4.4. Either add the flag
(a manifest change, not part of this runbook) or accept that the listener
restart may need the break-glass in §5.3.

### 2.6 Gate: the image, by digest

```bash
export IMAGE_NEW='<REGISTRY>/<REPO>@sha256:<DIGEST>'   # from Track 1. Never a tag.
# The OLD image, by digest, as each pod actually pulled it. This is the rollback target.
k get pod $POD_D -o jsonpath='{.status.containerStatuses[0].imageID}{"\n"}' | tee old-image-D.txt
k get pod $POD_L -o jsonpath='{.status.containerStatuses[0].imageID}{"\n"}' | tee old-image-L.txt
k get sts $STS_D -o yaml > sts-D.before.yaml ; k get sts $STS_L -o yaml > sts-L.before.yaml
```

**Pass:** `IMAGE_NEW` is a digest reference that matches the release record.
Both old `imageID`s are digests, not tags. The manifests ship
`sumchain/node:latest` with `IfNotPresent`, so reverting to "the old tag" could
pull something else. Also confirm the binary path. The Dockerfile installs
`/usr/local/bin/sumchain` (`Dockerfile:92`), **not** `/usr/local/bin/sumchain-node`
as `activation-rollout-evidence.md` §1 says. Use the correct path in the
evidence commands.

### 2.7 Baseline, immediately before step 4.1

```bash
RPC=https://rpc.sumchain.io
j() { curl -s $RPC -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"; }
date -u +%FT%TZ; j sum_blockNumber; j get_finality; j get_p2p_stats; j get_metrics | jq '.result.blocks'
```

Re-measure the interval (120 s apart, two samples). **Pass:** about 1.5 s/block
and `block_errors 0` on both validators.

**Capture each validator's consensus params, from the OLD binary, before
anything changes.** §4.3 check 7 compares the upgraded node against this file,
and it is the only check in this runbook that catches a node started on the
wrong genesis (§2.2 d). Take it per validator, through that validator's own
tunnel, not only through the public endpoint -- the public endpoint is one node.

```bash
curl -s -X POST localhost:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getChainParams","params":[]}' \
  | jq -S '.result' > params.before.<POD>.json
jq -c '{v2_enabled_from_height, omninode_enabled_from_height,
        education_enabled_from_height, governance_enabled_from_height}' params.before.<POD>.json
# must print the four live heights of §2.2 (d). The two files must be identical.
```

Tested against the live 21-field params on 2026-09-23: an identical copy prints
`[]`; a copy with `v2_enabled_from_height` nulled prints
`["v2_enabled_from_height"]`; a copy with an extra field only the new binary
exposes prints `[]`, so the new binary's larger RPC surface cannot false-stop it.


### 2.8 Gate: the rollback preflight (after 4.1's snapshots, before 4.2)

Numbered after 2.7 because it needs 4.1's snapshots, but it gates 4.2: **no pod
gets the Stage 1 image until this prints `PREFLIGHT COMPLETE`.**

```bash
export OLD_DIGEST='sha256:<the digest both pods run now>'   # from §2.6; production-only evidence
export NEW_DIGEST='sha256:<the release image registry digest>'
tools/lane-b/rollout-preflight-record.sh $POD_D stage1-pre-$STS_D preflight/
tools/lane-b/rollout-preflight-record.sh $POD_L stage1-pre-$STS_L preflight/
python3 tools/lane-b/rollout-preflight.py --validators 2 \
  --expected-old-image-digest "$OLD_DIGEST" --new-image-digest "$NEW_DIGEST" \
  --restore-rehearsal restore-rehearsal.txt preflight/
```

The recorder refuses, and writes nothing, when a pod's image is not pinned
by digest, when its volume is not `Retain`, when the snapshot is not
`readyToUse` or is of another claim, when the snapshot content has no
handle, or when either the current or the previous container log shows the
Stage 1 binary has already opened the volume.

The checker stops without the exact old digest, the new digest, or a restore
rehearsal record. That record comes from restoring one of these snapshots
into a **scratch** claim and starting the old image on it. It gives the
snapshot handle, the scratch claim, the old digest, `repair_lines: 0`, the
`cf::STATE` row count of the snapshot and of the restored copy (they must be
equal), and the measured `snapshot_seconds` and `restore_seconds`. Nothing in
this repository can produce that record; it is production-only evidence.

---

## 3. Halt budget

Each restart halts the chain for roughly the sum of these:

| component | size | basis |
|---|---|---|
| stop | ≈1 s with SIGINT (§4.2), else **30 s** grace then SIGKILL | §0.3 |
| image pull | unknown; zero if pre-pulled on the node | measure: `k describe pod` events `Pulled … in Xs` |
| RocksDB open (188 CFs) + WAL replay + messaging-index backfill check | unknown at 13 M blocks | `crates/node/src/node.rs:187-283` |
| producer start delay | 5 s | `poa.rs:1729` `sleep(5s)` |
| reconnect | dialer restart: immediate dial, then every 30 s. Listener restart: depends on the dialer's 30 s retry and on §2.5 | `crates/p2p/src/network.rs:317,717-727` |
| sync the missed tip block(s), then own slot | ≤ a few seconds | |

Kubernetes kills a container that is not healthy within `startupProbe`
`5 s + 30 × 5 s ≈ 155 s`. A start slower than that crash-loops. Measure the
real open time on a copy of the data before the window if possible.

**Budget per restart: target ≤ 5 min, hard stop at 15 min (§5).** For
calibration, the unplanned halts in §0.1 lasted 30 min to 14.6 h. Announce two
halt windows and a mixed-version period between them.

---

## 4. Procedure

### 4.1 Snapshot both validators' volumes, while running the old binary

RocksDB is crash-consistent, so a point-in-time volume snapshot of a running
node restores as a clean crash recovery. Take both snapshots now, **before
either pod ever runs the new image**:

```bash
for S in $STS_D $STS_L; do
cat <<EOF | kubectl --context $CTX apply -f -
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata: { name: stage1-pre-$S, namespace: $NS }
spec:
  volumeSnapshotClassName: <CLASS>
  source: { persistentVolumeClaimName: data-$S-0 }
EOF
done
k get volumesnapshot -w     # wait for READYTOUSE=true on both
```

Also set the current PVs to `Retain`, so a later restore cannot delete the
evidence:

```bash
for S in $STS_D $STS_L; do PV=$(k get pvc data-$S-0 -o jsonpath='{.spec.volumeName}'); kubectl --context $CTX patch pv $PV -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}'; done
```

**Do not proceed** until both snapshots report `readyToUse: true`, and §2.8
prints `PREFLIGHT COMPLETE`. Record the chain height at snapshot time.

### 4.2 Upgrade the DIALER (validator 0, `GW1p…`) — halt #1

```bash
date -u +%FT%TZ; j sum_blockNumber                       # T0 and height
OLD_UID=$(k get pod $POD_D -o jsonpath='{.metadata.uid}')
k set image statefulset/$STS_D sumchain="$IMAGE_NEW"      # the controller deletes the pod now
k exec $POD_D -c sumchain -- sh -c 'kill -INT 1' || true  # SIGINT while it is Terminating (§0.3)
# The OLD process must have exited, and released /data/LOCK, before a new one
# opens the volume. The StatefulSet controller creates the replacement only
# after the old pod object is gone, which the kubelet allows only once its
# containers have stopped. That guarantee is void if anything force-deletes
# the pod: NEVER `k delete pod --force --grace-period=0` a validator.
until [[ $(k get pod $POD_D -o jsonpath='{.metadata.uid}' 2>/dev/null) != "$OLD_UID" ]]; do sleep 2; done
k get pod $POD_D -w                                       # Pending → Running (new uid)
```

If the new container logs `LOCK`, `lock hold by current process` or
`Resource temporarily unavailable` on opening `/data`, two processes reached
the volume: **STOP** (§5.1).

Once the container is `Running`:

```bash
k logs $POD_D -c sumchain --since=10m | grep -E 'Opening database|Application journal format|Usable reorg depth|Genesis activation digest|Activation parameter|refus|REFUSING|bootnode|Our turn|Produced block|Imported|ERROR|WARN' | head -100
```

**From the first `Opening database at /data` line on, the image cannot be
reverted on this volume (§0.2).** Note the time.

Expected, in order:

1. The activation lines show no gate set beyond the four predecessor gates of
   §2.2 (d), at their live heights.
2. `dialing bootnode` then a connection.
3. Blocks imported from the listener.
4. `Produced block` at an even height.
5. `j sum_blockNumber` advances again.

Record `T1`, the first new block. Halt #1 = `T1 − T0`.

### 4.3 Observation boundary: mixed versions

The dialer now runs the new binary and the listener the old. Every block the
dialer proposes is validated and executed by the old binary, and the other way
round. With no gates set, a single differing state root would show as a
rejected import and a halt. This is the Stage 1 equivalence test. **Hold for at
least 1,200 blocks (≈30 min).** Make it longer if the mempool is quiet, because
empty blocks test less. Every check below must hold for the whole window.

```bash
# Tunnels to both pods (read-only)
k port-forward pod/$POD_D 18545:8545 & k port-forward pod/$POD_L 28545:8545 &
d() { curl -s localhost:18545 -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"; }
l() { curl -s localhost:28545 -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"; }

# 1. health / sync: both advance, within 2 blocks of each other
d sum_blockNumber; l sum_blockNumber
d health | jq .result; l health | jq .result

# 2. state-root agreement at a finalized height both hold
F=$(l get_finality | jq .result.finalized_height)
diff <(d sum_getBlockByHeight "[$F]" | jq -c '.result|{hash,state_root,proposer}') \
     <(l sum_getBlockByHeight "[$F]" | jq -c '.result|{hash,state_root,proposer}') && echo "AGREE at $F"

# 3. peers
d get_p2p_stats | jq .result; l get_p2p_stats | jq .result      # connected_peers == 1 on both

# 4. no import errors, on either side
d get_metrics | jq .result.blocks.block_errors; l get_metrics | jq .result.blocks.block_errors
k logs $POD_L -c sumchain --since=30m | grep -Ei 'invalid|reject|mismatch|failed to import' | head
k logs $POD_D -c sumchain --since=30m | grep -Ei 'invalid|reject|mismatch|failed to import|REFUSING' | head

# 5. strict alternation over the window (proposer parity never breaks)
for h in $(seq $((F-40)) $F); do l sum_getBlockByHeight "[$h]" | jq -r '.result|"\(.height) \(.proposer[0:8])"'; done | awk '{print $1%2, $2}' | sort | uniq -c   # exactly two lines

# 7. the upgraded node runs the SAME consensus params the old one did.
#    Capture BEFORE the upgrade (old binary), compare AFTER (new binary). Any
#    difference in a field both expose is an immediate STOP: the node is running
#    different rules -- see §2.2 (d) for why no startup check catches this.
curl -s -X POST localhost:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getChainParams","params":[]}' \
  | jq -S '.result' > params.after.<POD>.json
jq -S --slurpfile a params.after.<POD>.json '. as $b | [keys[] | select($a[0][.] != $b[.])]' params.before.<POD>.json
# must print []

# 6. the new RPC surface, on the new node only
d chain_getActivationStatus | jq '{chain_id,current_height,digest,protocol_digest,gates_set:([.gates[]|select(.height!=null)|"\(.gate)=\(.height)"])}'
```

**Pass:** all six hold throughout. Run 2 at least every 5 minutes.
`block_errors` stays at its pre-upgrade value on the listener. Check 6 gives
`chain_id 1` and **`gates_set` = 0**, the Stage 1 condition in
`activation-rollout-evidence.md` §1.

### 4.4 Upgrade the LISTENER (validator 1, `7jUZ…`) — halt #2

Only after 4.3 passes, and after §2.5 is resolved:

```bash
date -u +%FT%TZ; j sum_blockNumber
OLD_UID=$(k get pod $POD_L -o jsonpath='{.metadata.uid}')
k set image statefulset/$STS_L sumchain="$IMAGE_NEW"
k exec $POD_L -c sumchain -- sh -c 'kill -INT 1' || true
until [[ $(k get pod $POD_L -o jsonpath='{.metadata.uid}' 2>/dev/null) != "$OLD_UID" ]]; do sleep 2; done   # §4.2: old process gone
k get pod $POD_L -w
k logs $POD_D -c sumchain --since=5m | grep -E 'no peers connected|dialing bootnode|bootnode .* unusable'   # the dialer's 30 s retry
k logs $POD_L -c sumchain --since=10m | grep -E 'Opening database|Usable reorg depth|Our turn|Produced block|Imported|REFUSING|ERROR' | head -60
```

Then repeat checks 1–5 of §4.3 until the chain has advanced ≥ 100 blocks with
both validators proposing.

### 4.5 Stage 1 evidence, both validators

Run `activation-rollout-evidence.md` §1.1 and §1.2 for **each** pod, with the
binary path `/usr/local/bin/sumchain` (§2.6). Record both `imageID` values,
which must equal `IMAGE_NEW`'s digest. Record the two
`compatibility handshake accepted` lines, one per direction (N·(N−1) = 2), and
zero `REFUSING`. Stage 1 is complete only when all five records exist for both
validators.

---

## 5. Stop conditions and rollback

### 5.1 Stop immediately (do not start the next step) if

1. §2.1–§2.6 is not fully passed, or §2.8 has not printed `PREFLIGHT COMPLETE`.
2. The replacement pod is `Pending` more than 2 min (unschedulable or volume
   attach), or `ImagePullBackOff` or `CreateContainerConfigError`.
3. The new binary logs a refusal to start: `RetroactivelyOpened`,
   `AlreadyActive`, `chain activation parameters are unsound`, or
   `application journal format check failed`. It crash-loops, or it restarts
   more than once.
4. No new block within **15 min** of the pod delete (`T0`).
5. **Any** state-root or hash disagreement in §4.3 check 2. **Any** rejected or
   failed import, or a rise in `block_errors`, on either validator. **Any**
   `REFUSING peer` line.
6. Proposer parity breaks, or a third proposer key appears.
7. `chain_getActivationStatus` on the new node shows `chain_id ≠ 1`, or any
   gate with a height other than the four predecessor gates of §2.2 (d) at
   their live heights.
8. A listener restart with no reconnection after 3 dialer retry cycles (≈90 s):
   go to §5.3.
9. A replacement container logs a RocksDB lock error on `/data` (§4.2), or a
   validator pod was force-deleted.

### 5.2 Rollback, decided by one question: did the new binary ever open this volume?

```bash
k logs $POD --previous -c sumchain 2>/dev/null | grep -m1 'Opening database'; k logs $POD -c sumchain | grep -m1 'Opening database'
k get pod $POD -o jsonpath='{.status.containerStatuses[0].state}{"\n"}{.status.containerStatuses[0].lastState}{"\n"}{.status.containerStatuses[0].restartCount}{"\n"}'
```

**A. Never opened.** The container never started (Pending, pull error, config
error), no `Opening database` line exists in either current or previous logs,
and `restartCount` is 0 with no `lastState.terminated`. Image revert is safe:

```bash
k set image statefulset/$STS sumchain="<REGISTRY>/<REPO>@$OLD_DIGEST"   # the EXACT digest §2.8 recorded; never a tag
```

**B. Opened, even once, even if it then refused.** **0.2.0 must never open
this volume.** It would "repair" it, fall back below its finalized height and
produce different blocks (§0.2). Either fix forward on the new binary, or restore from the §4.1
snapshot first. The restore replaces a volume and needs owner sign-off at the
time:

```bash
k scale statefulset/$STS --replicas=0
k delete pvc data-$STS-0                    # the PV is Retain (4.1), so the data stays for forensics
cat <<EOF | kubectl --context $CTX apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: data-$STS-0, namespace: $NS }
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: fast-ssd
  resources: { requests: { storage: 100Gi } }
  dataSource: { name: stage1-pre-$STS, kind: VolumeSnapshot, apiGroup: snapshot.storage.k8s.io }
EOF
# The restored claim must be a NEW volume, never the one Stage 1 opened:
NEWPV=$(k get pvc data-$STS-0 -o jsonpath='{.spec.volumeName}')
[[ -n $NEWPV && $NEWPV != "$(grep '^pv:' preflight/$POD.preflight | awk '{print $2}')" ]] || { echo STOP; exit 1; }
k set image statefulset/$STS sumchain="<REGISTRY>/<REPO>@$OLD_DIGEST"   # the EXACT old digest
k scale statefulset/$STS --replicas=1
k logs $POD -c sumchain -f | grep -m1 -E 'attempting repair|Loaded existing chain'   # a repair line: STOP
```

A `Database appears corrupted, attempting repair` line means the restored
volume is not the pre-upgrade snapshot. Scale to 0 at once; do not let it
produce.

The restored validator comes back at the snapshot height and syncs forward
from its peer. Blocks produced in between are canonical, because both
validators accepted them. If this is the dialer, the old binary dials only at
startup, so the listener must already be up.

**Rollback after the listener is also upgraded** means both volumes are
post-open. Rolling back one validator runs mixed versions in the other
direction, which 4.3 already passed. Rolling back both needs both snapshots and
a coordinated halt -- **and it rewinds the chain.** With both volumes restored,
no node holds any block produced after the snapshots, so every block since the
upgrade is abandoned, FINALIZED ones included, and any transaction in them is
undone. That is the decision packet's rollback option E ("a chain-wide rollback
below h ... abandons finalised blocks; a social decision, not an operational
one"), not a step an operator takes on their own. The later the both-validator
rollback, the more it abandons, so the practical window for it is the
observation period after 4.4, and after that the answer is fix-forward.

### 5.3 Listener-restart deadlock (§0.4), break-glass

The symptoms: the listener is `Running` but not Ready, and its tip is one block
behind the dialer's. The dialer logs `no peers connected; re-resolving` and
`bootnode … unusable … NoAddresses`. The remedy needs an owner decision,
because each option changes something:

* (a) Set `publishNotReadyAddresses: true` on the listener's headless Service.
  The DNS record then appears within one retry cycle.
* (b) Restart the dialer. It reconnects at startup, but only once the name
  resolves, so this alone does not help unless (a) is also done.

Both nodes are on the new binary at this point, so neither needs a volume
restore.

---

## 6. If production is not on Kubernetes

The repo's own operations checklist describes systemd hosts (§0.5). If §2.1
finds that, every finding above still applies: §0.1 halt, §0.2 downgrade
wipe, §0.3 SIGTERM, §0.4 order. Only the commands change:

| step | systemd equivalent |
|---|---|
| inventory | `systemctl cat sumchain`, `ps -o args= -C sumchain`, `sha256sum $(command -v sumchain)` |
| genesis | `sha256sum <genesis path from the unit's --genesis / config>` and the same `jq` checks |
| snapshot | stop the unit (starts halt), copy or snapshot the data dir or disk, start the **old** binary again. Or snapshot the running disk if the platform supports crash-consistent snapshots. |
| stop cleanly | `systemctl stop` sends SIGTERM by default, which the node does **not** handle (§0.3, [I] for a non-PID-1 process: the default action terminates it immediately and uncleanly). Use `KillSignal=SIGINT` in the unit or `kill -INT <pid>` |
| process exit and lock | before starting any binary on the data dir: the old PID is gone (`while kill -0 $PID 2>/dev/null; do sleep 0.2; done`) **and** nothing holds the lock (`lsof $DATA/LOCK` prints nothing). The RPC port closes before RocksDB releases `LOCK`; a start in that gap fails to open the database (measured locally, stage1-local-evidence.md §1.1). |
| upgrade | swap the binary by verified sha256 and start |
| rollback | copy the pre-upgrade snapshot into a **new, empty** data dir and point the **old** binary at that; never at a dir the Stage 1 binary opened (§0.2). The same §2.8 preflight fields apply: snapshot id, old binary sha256, rehearsed restore with timings. |

---

## 7. Open items: each closes with one command or one permission

| # | item | closes with |
|---|---|---|
| U1 | Where production runs (which cluster/namespace, or systemd), and which workload holds which key | §2.1 commands, with a production kubeconfig or host access |
| U2 | Mounted genesis bytes on each validator, and whether both are identical | §2.2 `kubectl exec … cat /config/genesis.json` on each pod |
| U3 | Live requests/limits/QoS and node allocatable, i.e. whether 4Gi schedules | §2.3 commands |
| U4 | Snapshot capability and data-dir size | §2.4 commands |
| U5 | Dialer's bootnode form and `publishNotReadyAddresses` | §2.5 commands |
| U6 | Old image digest (rollback target) and the Stage 1 digest | §2.6. `<DIGEST>` from Track 1 |
| U7 | Exact source commit of the deployed 0.2.0 binary. §0.2 and §0.4 assume it is from this repo's 0.2.0 window. | `kubectl exec <POD> -- sumchain --version` if it reports a commit, or the build record for the old image digest |
| U8 | Real RocksDB open and WAL-replay time at 13 M blocks | Time a start of the **old** image against a clone of a §4.1 snapshot on a scratch node |
| U9 | That PID 1 really ignores SIGTERM in this image | `k describe pod` after any past deletion: termination about 30 s after delete, with `Reason: Error`/exit 137. Or look for the absence of `Shutdown signal received` in `k logs --previous` |
| U10 | Causes of the five historical halts in §0.1 | Operator change log for 2026-07-18, 07-29, 07-31, 08-26, 09-11 |

### Side observations, not blocking Stage 1

* The manifests annotate and scrape metrics on port 9090. No code in
  `crates/node` or `crates/rpc` binds 9090. `/metrics` is served by the health
  server on 8546 (`crates/rpc/src/health.rs:244`). **[I]** The `ServiceMonitor`
  scrapes nothing.
* The per-validator StatefulSets have no pod anti-affinity. **[I]** Two
  validators can land on the same node, and one node failure then halts the
  chain.
* The deprecated `statefulset.yaml` selects on `name` + `component=validator`,
  which also matches the per-validator pods' labels. Applying it next to them
  gives overlapping selectors.
