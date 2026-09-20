# Activation rollout: the evidence procedures

**Deployment is two stages, and they are separate commits.**

| stage | what ships | gates | this commit? |
|---|---|---|---|
| **1** | the exact release binary, with the failed-receipt telemetry already in it | **all UNSET** | yes |
| **2** | the release genesis configuration, with recalculated heights | set | **no** — only after stage 1 completion is PROVEN |

Stage 1 is not "we deployed it". Stage 1 is **complete when the five records
in §1 exist for EVERY validator.** Until then no height is recalculated, no
genesis is committed, and `docs/lane-a/ACTIVATION-PROPOSAL.json` stays exactly
as it is, with every height at `UNSET-PENDING-OWNER-AUTHORIZATION`.

These are procedures, not narrative. Each one is a command, an output to
record, and a condition that either holds or stops the rollout.

---

## 1. Binary-rollout proof

**For EVERY validator, record all five.** Four out of five for one validator
is not four fifths of a rollout; it is a rollout that has not happened.

Let `$V` be the validator's RPC base URL and `$POD` its pod name.

| # | record | how |
|---|---|---|
| 1 | **binary sha256** | `kubectl exec $POD -- sha256sum /usr/local/bin/sumchain-node` — **and** the image digest, `kubectl get pod $POD -o jsonpath='{.status.containerStatuses[0].imageID}'`. The image digest is what Kubernetes actually pulled; the file hash is what is running. Record both, because a mutable tag makes them able to disagree. |
| 2 | **activation digest** | `chain_getActivationStatus` → `digest` **and** `protocol_digest`. `digest` answers "do our genesis files agree"; `protocol_digest` answers "do our binaries enforce the same rules", and it is the one peers compare at the handshake. Two binaries from different commits can share a `digest` and differ in `protocol_digest`. |
| 3 | **chain id** | `chain_getActivationStatus` → `chain_id`. |
| 4 | **current height** | `chain_getActivationStatus` → `current_height`. Carried in the same response as 2 and 3 deliberately: a digest recorded without the height it was read at cannot be placed in time. |
| 5 | **peer compatibility handshake** | See §1.2. Not "the peer is connected" — a peer that declares nothing is admitted at every height below the enforcement gate, so connectivity is not evidence of compatibility. |

### 1.1 One validator, one command

```bash
#!/usr/bin/env bash
# rollout-record.sh <pod> <rpc-url> <metrics-url>
set -euo pipefail
POD=$1 RPC=$2 METRICS=$3

rpc() { curl -fsS -X POST "$RPC" -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" | jq -c '.result'; }

echo "pod:            $POD"
echo "binary_sha256:  $(kubectl exec "$POD" -- sha256sum /usr/local/bin/sumchain-node | awk '{print $1}')"
echo "image_id:       $(kubectl get pod "$POD" -o jsonpath='{.status.containerStatuses[0].imageID}')"
rpc chain_getActivationStatus | jq -r '
  "activation_digest: \(.digest)",
  "protocol_digest:   \(.protocol_digest)",
  "chain_id:          \(.chain_id)",
  "current_height:    \(.current_height)",
  "gates_set:         \([.gates[] | select(.height != null)] | length)"'
echo "peers:          $(rpc get_peers | jq -r '[.[] | select(.state=="Connected")] | length')"

# Stage 1 requires the telemetry to already be present.
tools/lane-b/wave1-monitor.sh verify "$METRICS"
```

**Record the output for every validator into one file.** Then:

```bash
# Every validator must agree on chain_id, activation_digest and protocol_digest.
grep -E 'chain_id|activation_digest|protocol_digest' rollout-records.txt \
  | sort | uniq -c | sort -rn
```

Any line with a count below the validator count is a disagreement. **A
`protocol_digest` disagreement means the binaries are not the same release and
stage 1 is not complete**, regardless of what the image tags say.

**`gates_set` must be `0` for every validator at stage 1.** A validator
reporting a non-zero count is running a genesis with heights in it and has
skipped straight to stage 2.

### 1.2 The handshake record

The digest exchange is a p2p event, and the node logs both outcomes. Collect
the log line per peer, per validator:

```bash
kubectl logs "$POD" --since=1h \
  | grep -E 'enforces our protocol digest|REFUSING peer|declared protocol digest'
```

* **Success** (`crates/node/src/node.rs:898`): `Peer <id> enforces our protocol
  digest` — emitted at `debug`, so the validator must be started with
  `RUST_LOG` at `debug` for `sumchain_node` during the rollout window, or this
  evidence does not exist.
* **Failure** (`crates/node/src/node.rs:899`, `crates/p2p/src/peer_compat.rs:196`):
  `REFUSING peer <id>: it enforces protocol digest X but this node enforces Y`.
  **Any occurrence stops the rollout.** The peer is banned for 24h and is
  permanently `Incompatible` from that point whatever it declares later, so
  this is not self-healing.

**The record is complete when every validator has logged a success line for
every OTHER validator.** N validators means N·(N−1) success lines and zero
refusals. Silence is not success: a peer that declares nothing is admitted
below the enforcement height, so an absent line means the exchange did not
happen, not that it passed.

---

## 2. `ChainParams::validate` against the EXACT committed genesis, and a
restart from an EXISTING database

Two halves, and the second is the one that gets skipped.

### 2.1 The committed bytes, not a copy

Validation must run against the genesis file **that was committed**, byte for
byte. A regenerated file that "should be the same" is the thing this check
exists to catch.

```bash
# The bytes under review.
sha256sum genesis.json
git show HEAD:genesis.json | sha256sum   # must be identical
```

### 2.2 The restart path, against a POPULATED database

`ChainParams::validate` runs on **both** the chain-creation path and the
restart path, through one entry point:

```
Node::with_rpc_config                       crates/node/src/node.rs:172
  └─ sumchain_state::account_root::validate_runtime_activation   :225
       ├─ params.validate()                 crates/state/src/account_root.rs
       └─ validate_account_root_activation(params)
```

It runs **before anything that processes a block exists** — no `StateManager`,
no executor, no mempool, no consensus engine — which is asserted by
`nothing_that_processes_a_block_is_built_before_activation_is_validated`.

**A fresh database does not exercise this.** The restart path is where a
running chain meets a new configuration, and a fresh-database start proves
nothing about it. The procedure:

```bash
# 1. Take a backup of a POPULATED validator database. Node stopped.
sumchain-node backup --data-dir /data --output /backups/pre-activation

# 2. Restore it somewhere isolated, off the network.
sumchain-node restore --backup /backups/pre-activation --data-dir /tmp/restart-check

# 3. Confirm it is actually populated. A height of 0 means you are about to
#    run the fresh-database test again by accident.
sumchain-node info --data-dir /tmp/restart-check    # height MUST be > 0

# 4. Start against the EXACT committed genesis, with p2p and RPC bound to
#    loopback and no bootnodes, so this node joins nothing.
sumchain-node run \
  --data-dir /tmp/restart-check \
  --genesis ./genesis.json \
  --p2p-addr 127.0.0.1:0 \
  --rpc-addr 127.0.0.1:18545 \
  --bootnodes '' \
  --log-level debug
```

**Pass:** the node starts, and the log carries
`Genesis activation digest … N gates set: …` and, if any height moved,
`Activation parameter changed (permitted): …` (`crates/node/src/node.rs:514,545`).
Record both lines.

**Fail:** startup exits with `chain activation parameters are unsound: …`.
That is the whole point of running it here rather than on a validator. The
five things it refuses are the §0.7 load rules, including
`peer_protocol_declaration_required_from_height` above the earliest open
remediation gate, and R5 above R30.

**Then confirm the restart did not silently change what the node can do:**

```bash
curl -fsS -X POST http://127.0.0.1:18545 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getSyncCapability","params":[]}' | jq
```

A node restored from a backup holds canonical state and **no undo history**,
so its advertisable reorg depth is the number of blocks published since the
restore. That is expected here and is not a failure — it is recorded so nobody
reads it as one later.

---

## 3. Byte-identical genesis on every validator

Not "equivalent content". **Byte identity.** A genesis differing only in key
order or trailing whitespace can still produce the same activation digest
while being a different file, and the next person to diff them will not know
which one is canonical.

```bash
# In-cluster, from the file each node actually loaded.
for POD in validator-1-0 validator-2-0 validator-3-0; do
  printf '%s %s\n' "$POD" "$(kubectl exec "$POD" -- sha256sum /config/genesis.json | awk '{print $1}')"
done | tee genesis-hashes.txt

# Exactly one distinct hash, and it is the committed one.
test "$(awk '{print $2}' genesis-hashes.txt | sort -u | wc -l)" -eq 1 \
  || { echo 'GENESIS BYTES DIFFER ACROSS VALIDATORS — STOP'; exit 1; }
test "$(awk 'NR==1{print $2}' genesis-hashes.txt)" = "$(git show HEAD:genesis.json | sha256sum | awk '{print $1}')" \
  || { echo 'DEPLOYED GENESIS IS NOT THE COMMITTED GENESIS — STOP'; exit 1; }
```

Do the ConfigMap too, because that is what a restarted pod will remount:

```bash
kubectl get configmap sumchain-genesis -o jsonpath='{.data.genesis\.json}' | sha256sum
```

All three hashes — committed, in every pod, in the ConfigMap — must be the
same string. **The activation-configuration rollout is not complete until they
are.** The digest comparison in §1 is a weaker check that runs earlier; this
is the one that closes it.

---

## 4. The abort rule

> **If ANY validator misses the configuration rollout, STOP BEFORE the
> `peer_protocol_declaration_required_from_height` enforcement height. Do not
> continue toward Wave 1.**

### 4.1 The stop condition, stated so it can be acted on

At any point between the stage-2 deploy and the peer-protocol enforcement
height, **halt** if any of these is true:

1. Any validator's `sha256sum` of `genesis.json` differs from the committed
   one (§3).
2. Any validator's `chain_getActivationStatus.digest` differs from any other's.
3. Any validator's `protocol_digest` differs from any other's.
4. Any validator is not running, is CrashLoopBackOff, or exited with
   `chain activation parameters are unsound`.
5. Any log line matching `REFUSING peer .*: it enforces protocol digest`
   appears on any validator.
6. `tools/lane-b/wave1-monitor.sh agree <every validator metrics url>` reports
   `DISAGREE` on counts taken over a common window.

```bash
# The whole stop condition, as one check. Non-zero exit means HALT.
tools/lane-b/wave1-monitor.sh agree \
  http://validator-1:9090 http://validator-2:9090 http://validator-3:9090
```

### 4.2 Why the peer-protocol height specifically, and not Wave 1

`peer_protocol_declaration_required_from_height` is the point of no return, not
Wave 1. Below it, a validator running the wrong configuration is a validator
producing blocks the others will reject — bad, visible, and recoverable by
fixing that validator. **At and above it, a validator that declares a
different protocol digest is refused from consensus and banned for 24 hours,
permanently `Incompatible` whatever it declares later.** Passing that height
with a lagging validator does not degrade the rollout; it removes that
validator from the set for a day, which on a small validator set is a
liveness event.

So the enforcement height is the last moment at which a missed rollout is
still cheap. That is where the stop goes.

### 4.3 The two ways out, and the one that is not available

* **Fix the validator, before the enforcement height.** Redeploy it with the
  identical genesis bytes and the identical binary, re-run §1 for it, and
  confirm §3 across all validators. Then continue on the original schedule.
* **Postpone the whole schedule.** Write a new genesis with later heights,
  from a NEW recalculation head, and redeploy it to every validator. The lead
  times are preserved — see below.

* **NOT available: compress the lead time to recover the slip.** The Wave 1
  lead exists so that every operator is on the new binary before behaviour
  changes under it. A slipped rollout is evidence that more time is needed,
  not less. Shortening the lead to hold the original activation date is
  precisely the move that produces a mixed-binary fork, and
  `docs/lane-a/ACTIVATION-PROPOSAL.json` carries it as a rule
  (`derivation_rule.lead_time_rule`) rather than as advice.

---

## 5. What recalculates the heights, when the owner authorizes it

Nothing in this commit sets a height and nothing here should be read as
authorizing one. The procedure, for when that changes:

1. **Measure the head and the rate.** `chain_getActivationStatus.current_height`
   on a healthy validator, with a UTC timestamp. Then measure blocks/day over
   at least 24 hours against the CURRENT validator set — the last measured
   57,524 blocks/day was taken against a two-validator set (packet §0.3) and
   is not a protocol constant.
2. **Apply the offsets** in `docs/lane-a/ACTIVATION-PROPOSAL.json`:
   `H + days * BLOCKS_PER_DAY`, with the per-wave `days` exactly as committed
   (14 / 28 / 42 / 56 / 70). Not shortened.
3. **Place the peer gate**, strictly below the Wave 1 height by at least
   48 hours of blocks.
4. **Write the heights into `genesis.json`** — in the stage-2 commit, not this
   one — and re-run §2 and §3 in full.
5. **`python3 tools/lane-b/activation-proposal.py`** will then FAIL, because it
   refuses any height in the proposal artifact. That is intended: the artifact
   is the stage-1 proposal and stays symbolic. The stage-2 commit records the
   absolute heights in `genesis.json`, where `ChainParams::validate` checks
   them, and not in a second place where they can drift.

---

## 6. Related

* [wave1-activation-monitoring.md](wave1-activation-monitoring.md)
* [production-checklist.md](production-checklist.md)
* [validator-memory-floor.md](validator-memory-floor.md)
* `docs/lane-a/ACTIVATION-PROPOSAL.json`
* `docs/lane-a/ACTIVATION-DECISION-PACKET.md` §0.7 (the load rules) and §0.9
  (how an activation is actually deployed)
