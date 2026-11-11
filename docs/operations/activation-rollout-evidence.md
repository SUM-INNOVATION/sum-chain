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
| 1 | **binary sha256** | `kubectl -n sumchain exec $POD -- sha256sum /usr/local/bin/sumchain` — the path the `Dockerfile` installs the node at (`COPY --from=builder /build/target/release/sumchain /usr/local/bin/`, `ENTRYPOINT ["sumchain"]`); `tools/lane-b/rollout-check-test.py` derives it from the Dockerfile and fails if this document hashes anything else — **and** the image digest, `kubectl -n sumchain get pod $POD -o jsonpath='{.status.containerStatuses[0].imageID}'`. The image digest is what Kubernetes actually pulled; the file hash is what is running. Record both, because a mutable tag makes them able to disagree. **Three identities, all compared:** the file hash against the sha256 of the release binary; the image digest against the release image's registry digest; and `sumchain --version` against `sumchain <release commit>`. Since PR #259 the release Dockerfile refuses to build without a full 40-hex `GIT_HASH` and the binary reports it; 0.2.0 has no `--version` and cannot be recorded. The self-report is never the only identity: the file hash and the digest do not depend on anything the node says. |
| 2 | **activation digest** | `chain_getActivationStatus` → `digest` **and** `protocol_digest`. `digest` answers "do our genesis files agree"; `protocol_digest` answers "do our binaries enforce the same rules", and it is the one peers compare at the handshake. Two binaries from different commits can share a `digest` and differ in `protocol_digest`. |
| 3 | **chain id** | `chain_getActivationStatus` → `chain_id`. |
| 4 | **current height** | `chain_getActivationStatus` → `current_height`. Carried in the same response as 2 and 3 deliberately: a digest recorded without the height it was read at cannot be placed in time. |
| 5 | **peer compatibility handshake** | See §1.2. Not "the peer is connected" — a peer that declares nothing is admitted at every height below the enforcement gate, so connectivity is not evidence of compatibility. |

### 1.1 One validator, one command

```bash
#!/usr/bin/env bash
# rollout-record.sh <pod> <rpc-url> <metrics-url> <out-dir>
# Writes <out-dir>/<pod>.record and <out-dir>/<pod>.log. Namespace: $NS (default sumchain).
#
# Every field is read and validated BEFORE anything is written, and the record
# is written atomically. A missing command, a failing command, a blank or
# malformed field, or failed telemetry exits non-zero and leaves NO record: a
# record that exists is one whose every field was read. (An earlier version put
# each command inside `echo "$(...)"`, where a failure does not trip `set -e`,
# and wrote a blank field with exit 0.)
set -euo pipefail
[[ $# -eq 4 ]] || { echo "usage: rollout-record.sh <pod> <rpc-url> <metrics-url> <out-dir>" >&2; exit 2; }
POD=$1 RPC=$2 METRICS=$3 OUT=$4 NS=${NS:-sumchain}
GENESIS_PATH=${GENESIS_PATH:-/config/genesis.json}   # the genesis file the pod mounts
fail() { echo "FAIL [$POD]: $*; no record written" >&2; exit 1; }
for c in kubectl curl jq awk grep; do
  command -v "$c" >/dev/null || fail "required command '$c' not found"
done
mkdir -p "$OUT"

rpc() { curl -fsS -X POST "$RPC" -H 'content-type: application/json' \
          -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"; }

# The WHOLE current-container log, not a --since window: the handshake lines
# are written when each peer connects, which can be long before the window, and
# the peer-ID line is written once at startup.
kubectl -n "$NS" logs "$POD" > "$OUT/$POD.log" || fail "kubectl logs failed"

sha=$(kubectl -n "$NS" exec "$POD" -- sha256sum /usr/local/bin/sumchain) \
  || fail "hashing /usr/local/bin/sumchain in the pod failed"
sha=${sha%% *}
[[ $sha =~ ^[0-9a-f]{64}$ ]] || fail "binary_sha256 '$sha' is not a sha256"

# The commit the running binary was built from. Release builds embed it
# (Dockerfile GIT_HASH guard); a binary that cannot say, like 0.2.0, fails.
ver=$(kubectl -n "$NS" exec "$POD" -- /usr/local/bin/sumchain --version) \
  || fail "/usr/local/bin/sumchain --version failed; this binary cannot report its commit"
[[ $ver =~ ^sumchain\ [0-9a-f]{40}$ ]] || fail "binary_version '$ver' is not 'sumchain <40-hex commit>'"

img=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].imageID}') \
  || fail "reading the pod's imageID failed"
[[ $img == *sha256:* ]] || fail "image_id '$img' carries no digest"

status=$(rpc chain_getActivationStatus) || fail "chain_getActivationStatus failed"
field() { jq -er ".result.$1 // empty" <<<"$status" 2>/dev/null \
            || fail "chain_getActivationStatus returned no $1"; }
act=$(field digest)
proto=$(field protocol_digest)
chain=$(field chain_id)
height=$(field current_height)
# Every gate with a height, as name=height, not a count: a count of 0 is wrong
# for production, whose genesis legitimately carries four passed predecessor
# gates (v2, omninode, education, governance). The checker compares the names
# AND heights against those four, so a genesis missing one fails here too.
gates=$(jq -er '[.result.gates[] | select(.height != null) | "\(.gate)=\(.height)"] | join(",")' <<<"$status" 2>/dev/null) \
  || fail "chain_getActivationStatus returned no gates list"
[[ -n $gates ]] || gates=none

# How this validator's handshake lines are attributed by the others.
peer=$(grep -m1 -o 'Local peer ID: [0-9A-Za-z]*' "$OUT/$POD.log" | awk '{print $4}') || true
[[ -n $peer ]] || fail "no 'Local peer ID' line in the container log; its handshakes cannot be attributed"

# The public validator identity, PROVEN BY POSSESSION rather than self-reported:
# the node reports no validator key of its own (node_info has none, and no log
# line states it), and its key file is private. So take a height this
# workload's log says it produced, and read that block's proposer from public
# RPC. A block signed by the key is the proof the workload holds it. A
# validator that has produced no block yet cannot be identified, and fails.
H=$(grep -oE 'Produced block [0-9a-fx]+ at height [0-9]+' "$OUT/$POD.log" | tail -1 | awk '{print $NF}') || true
[[ -n $H ]] || fail "no 'Produced block' line in the log; this workload's validator identity cannot be proven"
vpk=$(rpc get_block_by_height "[$H]" | jq -er '.result.proposer // empty' 2>/dev/null) \
  || fail "get_block_by_height $H returned no proposer"
[[ $vpk =~ ^[0-9a-f]{64}$ ]] || fail "validator_pubkey '$vpk' is not 64-hex"

gen=$(kubectl -n "$NS" exec "$POD" -- sha256sum "$GENESIS_PATH") \
  || fail "hashing the mounted genesis $GENESIS_PATH failed"
gen=${gen%% *}
[[ $gen =~ ^[0-9a-f]{64}$ ]] || fail "genesis_sha256 '$gen' is not a sha256"

# Stage 1 requires the telemetry to already be present.
tools/lane-b/wave1-monitor.sh verify "$METRICS" >&2 || fail "telemetry verify failed"

tmp=$(mktemp "$OUT/.$POD.record.XXXXXX")
{
echo "pod:            $POD"
echo "binary_sha256:  $sha"
echo "binary_version: $ver"
echo "image_id:       $img"
echo "activation_digest: $act"
echo "protocol_digest:   $proto"
echo "chain_id:          $chain"
echo "current_height:    $height"
echo "gates_set:         $gates"
echo "local_peer_id:  $peer"
echo "validator_pubkey: $vpk"
echo "genesis_sha256: $gen"
echo "telemetry:      OK"
} > "$tmp"
mv "$tmp" "$OUT/$POD.record"
```

**Run it for every validator into one directory, then let the checker decide.**
Nothing in this section is read by eye:

```bash
python3 tools/lane-b/rollout-check.py \
  --validators <N> \
  --expected-binary-sha256 <binary_sha256 from the release record> \
  --expected-commit <40-hex release commit> \
  --expected-image-digest <sha256:... registry digest from the release record> \
  --expected-chain-id <chain id> \
  --expected-validator <64-hex public key of validator 1> \
  --expected-validator <64-hex public key of validator 2> \
  --expected-genesis-sha256 <sha256 of the PRODUCTION genesis bytes> \
  <out-dir>
```

It exits 0 only when:
- every validator has a complete record;
- `binary_sha256` equals the release record's;
- `binary_version` is `sumchain <release commit>`;
- `image_id` is pinned at the release digest;
- `activation_digest` and `protocol_digest` are the same on every validator;
- `chain_id` is the expected one, and `current_height` is above 0;
- `gates_set` is exactly the four production predecessor gates at their live
  heights;
- the `validator_pubkey` values are distinct and equal the expected set;
- `genesis_sha256` is identical on every validator and equal to the
  production hash;
- `telemetry` is `OK`;
- the N·(N−1) handshakes of §1.2 are present, with zero refusals.

Without the production genesis hash, the release commit or the image digest,
it prints `STOP` and exits 1. **A missing record, field, log
or handshake line is a failure, not a pass.** `rollout-check-test.py` proves
each of those rules fails the check when it is broken.

A **`protocol_digest` disagreement means the binaries are not the same release
and stage 1 is not complete**, regardless of what the image tags say. A
**`gates_set` with any gate beyond the four predecessor gates** means the
validator is running a genesis with a remediation height in it: it has skipped
straight to stage 2. A `gates_set` **missing** one of the four means a genesis
that silently disables a live feature (runbook §2.2 (d)).

If `local_peer_id` comes back empty, the startup line has rotated out of the
container log. The record is then incomplete and the check fails; it is not
filled in by hand from anything other than that node's own log.

### 1.2 The handshake record

The digest exchange is a p2p event, and the node logs both outcomes, one line
per peer, per validator. `rollout-record.sh` above captures each validator's whole current-container
log into `<pod>.log`; `rollout-check.py` reads the two lines below out of it.
To look at them by hand:

```bash
kubectl -n sumchain logs "$POD" \
  | grep -E 'compatibility handshake accepted|REFUSING peer|declared protocol digest'
```

* **Success** (`crates/node/src/node.rs:916`): `compatibility handshake
  accepted: peer enforces our protocol digest`, carrying `peer` and `digest` as
  fields — emitted at **`info`**, so this evidence exists under the default log
  level and does not depend on anyone having raised it for the rollout window.
  It was `debug!` until this procedure was written: at that level a correct
  rollout and an unobserved one leave identical logs afterwards, which is
  exactly the distinction this section exists to make.
* **Failure** (`crates/node/src/node.rs:920`, `crates/p2p/src/peer_compat.rs:196`):
  `REFUSING peer <id>: it enforces protocol digest X but this node enforces Y`.
  **Any occurrence stops the rollout.** The peer is banned for 24h and is
  permanently `Incompatible` from that point whatever it declares later, so
  this is not self-healing.

**The record is complete when every validator has logged a success line for
every OTHER validator.** N validators means N·(N−1) success lines and zero
refusals. Silence is not success: a peer that declares nothing is admitted
below the enforcement height, so an absent line means the exchange did not
happen, not that it passed. `rollout-check.py` enforces exactly this: for every
ordered pair of validators it requires a success line in the first one's log
naming the second one's `local_peer_id` and the common `protocol_digest`, and it
fails on any refusal line in any log.

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
sumchain backup --data-dir /data --output /backups/pre-activation

# 2. Restore it somewhere isolated, off the network.
sumchain restore --backup /backups/pre-activation --data-dir /tmp/restart-check

# 3. Confirm it is actually populated. A height of 0 means you are about to
#    run the fresh-database test again by accident.
sumchain info --data-dir /tmp/restart-check    # height MUST be > 0

# 4. Start against the EXACT committed genesis, with p2p and RPC bound to
#    loopback and no bootnodes, so this node joins nothing.
sumchain run \
  --data-dir /tmp/restart-check \
  --genesis ./genesis.json \
  --p2p-addr 127.0.0.1:0 \
  --rpc-addr 127.0.0.1:18545 \
  --bootnodes '' \
  --log-level debug
```

**Pass:** the node starts, and the log carries
`Genesis activation digest … N gates set: …` and, if any height moved,
`Activation parameter changed (permitted): …` (`crates/node/src/node.rs:584,615`).
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
6. `tools/lane-b/wave1-monitor.sh agree <every validator's baseline>` reports
   `DISAGREE` (exit 1): the same blocks, no restart on any node, different
   refusals.

```bash
# Baselines are taken on the health port, 8546 -- NOT 9090, which nothing binds.
tools/lane-b/wave1-monitor.sh baseline http://validator-1:8546 > baseline-v1.txt
tools/lane-b/wave1-monitor.sh baseline http://validator-2:8546 > baseline-v2.txt
# ... observe ...
tools/lane-b/wave1-monitor.sh agree baseline-v1.txt baseline-v2.txt
```

**Exit 1 means HALT. Exits 3 and 4 do NOT.** Exit 4 is MISSING DATA: an
endpoint could not be scraped, or a series the check needs is absent -- fix the
scrape and run it again; an unreachable metrics port is not a fork. (Before
this was fixed, an unreachable validator made `agree` exit 1.) Exit 3 is
INCONCLUSIVE: a node
restarted inside the window, or the nodes' windows cover different blocks. It
is never a fork signal -- the counter is per-process and resets on restart, so a
restart makes a window unmeasurable rather than disagreeing. Take new baselines
and observe again. The pre-repair script compared raw totals, which differ
between any two validators that started at different times, and so reported
"fork in progress" -- and sent the operator here -- after every restart.

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
