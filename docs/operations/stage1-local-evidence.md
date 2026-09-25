# Stage 1 rollout: local evidence battery

Run 2026-09-24 against merged `main` `e93d38dfa1681ae96947f04302952d94ddd7e893`
(PR #259), with fixture keys only. **Nothing here is production evidence.** Every
number below comes from a local devnet or a CI runner. It narrows the risk, but
it cannot close any item in §4.

Binaries used:

| Label | Commit | `--version` |
|---|---|---|
| Stage 1 (merged main) | `e93d38dfa1681ae96947f04302952d94ddd7e893` | `sumchain e93d38dfa1681ae96947f04302952d94ddd7e893` |
| Stage 1 + `/metrics` fix | `62b8d7e201c8854a5058114f6bbfcf6fa7c12c45` (branch `rollout/local-battery`; the same change is `d14bc7e6` on `rollout/deployable-stage1`) | `sumchain 62b8d7e201c8854a5058114f6bbfcf6fa7c12c45` |
| Deployed 0.2.0 | `8abbd3044a3cddca06d4df2d2ef7064339dc5492` | no `--version` flag |

## 1. Verified locally

### 1.1 Two-validator liveness
Two validators on the same round-robin rule (`validators[height % 2]`) and a
fixture genesis (sha256 `ae235264406ea3dea7bf94725639d70c48abb0898a0e7f10af09a6e572f8ccde`).

| Step | Observed |
|---|---|
| v0 stopped | the chain froze at 47, and height 48 is v0's slot. v0 was down 22.1 s. |
| v0 restarted (listener) | first new block after **19.30 s**, because recovery waits for v1's 30 s redial. The whole halt, block 47 → 48, was **40.8 s** (02:43:39.47 → 02:44:20.23 UTC). |
| v1 stopped | the chain froze at 66, and height 67 is v1's slot. v1 was down 22.7 s. |
| v1 restarted (dialer) | first new block after **5.52 s**. The whole halt, block 66 → 67, was **27.7 s** (02:44:38.23 → 02:45:05.94 UTC). |
| SIGINT to exit | about 0.55 s |

The per-block timeline from both node logs is in `halt-recovery.log` (§6).

With two validators, either one down halts the chain. Nothing skips or times
out a missing proposer.

**Runbook finding.** Before restarting, wait for the old process to *exit*,
not for its RPC port to close. The port closes before RocksDB releases
`LOCK`. A restart in that gap fails to open the database.

### 1.2 Database upgrade and rollback (nonproduction timings)
The inventory is read-only: every column family, its row count, and a sha256
over keys and values (`cfcount-main.rs` in the evidence set).

| Step | Families | Rows | Result |
|---|---|---|---|
| 0.2.0 seeds a single-validator chain to height 27 | 188 | 121 | blocks 28, block_height 28, state 5, meta 4, state_diffs 27, contract_state_diffs 27, 2 others |
| Snapshot (`cp -Rp`, 1.1 MB) | — | — | 0.004 s. The snapshot inventory is identical to the seed inventory. |
| Stage 1 opens the database and advances it to 38 | 189 | 156 | adds `application_journal` (11 rows). Every pre-existing family's digest is unchanged except the growing `blocks`, `block_height` and `meta`. |
| **0.2.0 on a copy of the post-Stage-1 database** | 188 | 154 | **See the defect below.** |
| Restore from the snapshot | 188 | 121 | 0.006 s. Before any open, the restored inventory is identical to the seed: every row and every digest. |
| 0.2.0 on the restored database | 188 | 137 | Opens with no repair and no "Invalid argument", loads height 27, produces from 28. State and the static families keep their seed digests. |

**Defect (deployed 0.2.0, not fixable in place).** The old binary does not
refuse a database that Stage 1 has opened:

```
ERROR Failed to open database: Invalid argument: Column families not opened: application_journal
WARN  Database appears corrupted, attempting repair...
INFO  Database opened successfully after repair
INFO  Loaded chain at height 27
INFO  Restored finality state: height 35 finalized
INFO  Produced block 0xc28f0d37…e134 at height 28
```

Stage 1 had produced `0xdbc281be…830a` at height 28. After the repair, 0.2.0
drops `application_journal`, falls back to height 27 even though its restored
finality state says height 35 is final, and produces a *different* block 28.
On a two-validator network that means re-producing finalized heights, and the
two validators diverge. The downgrade probe's README describes a total wipe.
On this small database the loss was partial. Either way the repair is silent,
and `auto_repair` is hard-coded to `true` in 0.2.0: the node never builds a
`DatabaseConfig`, so no operator setting disables it. The volume snapshot
remains the only safe rollback, and a 0.2.0 binary must never be started on a
volume that Stage 1 has opened.

### 1.3 Genesis safety
Genesis A sets `v2`, `omninode`, `education` and `governance` to height 0.
Genesis B is A without `governance_enabled_from_height`.

- The byte difference is detected: A is `6b7299485d96…adaca` and B is
  `b978f2c60140…fe05`. The rollout checker fails a genesis that differs from
  the supplied production hash (`GENESIS MISMATCH`) and fails validators
  that disagree with each other (`GENESIS DISAGREEMENT`). This was run live
  on the devnet and in the fixture battery.
- The semantic difference is detected: Stage 1 **starts on B with no
  refusal**, and reports `governance_enabled_from_height: null` where A
  reports 0. The runbook's §4.3 comparison prints
  `["governance_enabled_from_height"]` for A against B and `[]` for A
  against itself.
- A missing production genesis stops the procedure. Without
  `--expected-genesis-sha256` the checker prints `STOP: the production
  genesis sha256 was not supplied` and exits 1 (live and fixture). No local
  hash was used in place of the production one.

### 1.4 Evidence collector (`tools/lane-b/rollout-check.py` and the recorder)
Both public identities are proven by possession. The recorder takes the
height of the workload's last "Produced block" log line and reads that
block's `proposer`. The recorder also hashes the genesis file that the
workload mounts.

- Live on the two-validator devnet:
  - Complete evidence passes: `STAGE 1 ROLLOUT EVIDENCE COMPLETE: 2
    validators …, 2/2 directed handshakes, 0 refusals`.
  - No production genesis supplied → STOP.
  - Wrong expected genesis → `GENESIS MISMATCH`.
  - Wrong expected identity → `VALIDATOR SET MISMATCH`.
- Fixture battery at the time of the live run (22 checker cases + 7
  recorder refusals): passes. PR `rollout/deployable-stage1` extends it to
  37 checker cases and 9 recorder refusals. The additions pin the release
  commit (`binary_version`), the image digest, and exactly the four
  production predecessor gates at their live heights. It
  covers blank or missing hashes, a missing handshake in either direction,
  duplicate identities, unequal genesis hashes, a missing record, a wrong
  binary sha, a wrong chain id, a missing production genesis, a
  non-predating gate, the production shape with four predating gates set
  (which must pass), and a recorder refusal when no "Produced block" line
  proves identity.
- Mutations: I removed, one at a time, the duplicate-identity check, the
  genesis-disagreement check, the non-predating-gate check and the
  missing-genesis STOP. Each named case failed. The file was restored to
  sha256 `f824cc81…a8e6`.

### 1.5 Monitoring
Run against the running devnet on the `/metrics`-fixed binary:
- `verify`: 124 series, two bounded labels, all nine Wave 1 subsystems. Exit 0 on both validators.
- `agree` over a common block window: exit 0 (`same blocks, no restart, identical refusal deltas`).
- v1 restarted inside a window, then `delta`: exit 3, `INCONCLUSIVE: the process restarted`.
- An unreachable endpoint: exit 4, `MISSING DATA`, which is not zero and not a disagreement.

**No live refusal was produced.** Every Wave 1 refusal needs a gate open, and
the node's `transfer` CLI panics (see §3). The refusal-to-label path is
proven in-process with the real executor. Locally,
`wave1_execution_error_signal` passes (15 tests, one per subsystem gate),
and the exposition tests pass (7 tests: closed series table, exactly two
labels, no label value can come from a transaction).

### 1.6 Scheduling model (manifests only)
Every validator manifest (`statefulset.yaml`, `statefulset-validator-{1,2,3}.yaml`)
has a single container `sumchain` with no init containers:
requests `cpu 500m, memory 4Gi` and limits `cpu 2000m, memory 4Gi`. CPU
request ≠ CPU limit, so the pod is **Burstable** (not Guaranteed). It is
OOM-killed above 4 GiB. `statefulset.yaml` has only a *preferred*
anti-affinity on hostname, so the two validators may be scheduled on the
same node.

The minimum unreserved allocatable per node, after every other pod's requests:
- Two validators on separate nodes: ≥ 4 GiB memory and ≥ 500m CPU on each node.
- Both validators on one node: ≥ 8 GiB memory and ≥ 1000m CPU.

The repository carries three validator manifests and a three-replica
StatefulSet. Production runs two validators, so the manifests actually
applied in production are unknown here.

## 2. Verified by CI
- PR #259's head `e93d38d`, and the same commit on the `main` push (run
  35948150237, `docker-image`):
  - Built on the pinned `rust:1.88.0-slim-bookworm@sha256:38bc5a86…d89` with
    `--locked`.
  - `docker run … --version` reported `sumchain e93d38dfa1681ae96947f04302952d94ddd7e893`.
  - A build with no `GIT_HASH` was refused (`GIT_HASH must be the full 40-hex commit`).
  - Local image ID `sha256:3c76216151c1c819d5b11eae7b960e3c8aa80457895fe11f8696cc202bdcaa1f`
    (amd64). **Nothing was pushed, so no registry digest exists.**
- `Rust CI` and `health-e2e` passed on the `main` push of `e93d38d`.

## 3. Defects found locally
1. **The shipped Stage 1 binary serves no `/metrics`** (404), so none of the
   Wave 1 monitoring can run against `e93d38d`. It is fixed in `62b8d7e2`
   (the health server is built with the metrics provider, plus two tests
   and two killed mutations). That fix is not on `main`, so the release
   artifact must be rebuilt after it merges. Cherry-picked as `d14bc7e6`.
2. **The rollout checker would have refused the correct production
   genesis.** It required `gates_set == 0`, but production carries four
   predating heights. Fixed in `3f03468d` (cherry-picked as `5475bb8c`).
   `rollout/deployable-stage1` tightens the rule to exactly the four
   predecessor gates at their live heights.
3. **The evidence recorder captured neither validator identity nor the
   genesis hash.** Fixed in `3f03468d` (`5475bb8c`).
4. **Deployed 0.2.0 silently repairs a Stage-1 database**, then rewinds
   below its finalized height and re-produces different blocks (§1.2). This
   cannot be fixed in the deployed binary. The mitigation is procedural:
   snapshot before the first Stage 1 open, and never start 0.2.0 on that
   volume.
5. **The `transfer` CLI panics in both 0.2.0 and Stage 1**:
   `reqwest::blocking::Client::new()` runs inside the tokio runtime
   (`crates/node/src/main.rs:712`), giving "Cannot drop a runtime in a
   context where blocking is not allowed". This does not block the rollout.
6. Runbook: wait for process exit, not port closure, before a restart (§1.1).
   Fixed in the runbook (§4.2, §4.4, §6) on `rollout/deployable-stage1`.
7. **Every scrape configuration pointed at port 9090, which nothing binds.**
   That covered the StatefulSets, the Services, `prometheus.yml` and
   `docker-compose.yaml`. `/metrics` is on the health port, 8546. Fixed on
   `rollout/deployable-stage1` and pinned by
   `tools/lane-b/metrics-endpoint-test.py`.
8. **`wave1-monitor.sh verify` exited silently** on a family with no samples,
   because grep's no-match status under `pipefail` ended the script. It
   failed closed, but said nothing. Fixed on `rollout/deployable-stage1`.

### Known, not blocking, and not in this PR
- The `transfer` CLI panic (item 5), at `crates/node/src/main.rs:712`.
- The 30-second redial asymmetry: a restarted listener waits for the
  dialer's redial (§1.1: 19.3 s against 5.5 s).
- Validator anti-affinity is *preferred*, not *required*, so both validators
  may share a node (§1.6).
- No production access from this environment.
- Future activation work (Stage 2 heights), which needs production evidence.

## 4. Owner-attested (not verified here)
- Production has exactly two validators.
- The private keys sit at operator paths (`~/sum-chain/keys/validator{n}.json`),
  which this battery neither needed nor read.
- The production genesis bytes exist and will be supplied later.

## 5. Production-only evidence still required
Deployment stays blocked until every item has production evidence.
1. The sha256 of the production genesis bytes, and proof that **both**
   validators mount byte-identical copies of them (§4.3 check 7 plus the
   checker's `--expected-genesis-sha256`).
2. The mapping of the two public validator identities to the live
   workloads, proven by possession (recorder output for both pods, and both
   `--expected-validator` values).
3. Actual node schedulability: allocatable memory and CPU on the target
   nodes against §1.6, and which manifests production actually applies.
4. A production volume snapshot of each validator, created **and
   restored**, with the time each took.
5. The digest of the currently deployed production image, and the
   registry digest of the release image. That image must include the
   `/metrics` fix (§3.1).
6. The production `cf::STATE` row count, before and after.
7. OC-3 and SC-8 evidence where production or historical access is required.

Local substitutes do not close any of these, and do not close any issue.

## 6. Evidence set
Tracked, sanitized:
[`evidence/stage1-local-2026-09-24/`](evidence/stage1-local-2026-09-24/INDEX.txt),
with a `SHA256SUMS` manifest. It holds:
- the per-step database inventories and the nonproduction timings;
- the halt/recovery timeline and the 0.2.0 downgrade reproduction;
- the genesis files and chain params;
- the live evidence records and monitor outputs;
- the CI identity lines for `e93d38d`;
- `mutations.txt`: every mutation run against the metrics exposition,
  checker, recorder, preflight, monitor, manifest check and genesis check,
  with the named test that failed and the restored hash.

Before tracking, the source bundle (34 files) was scanned for secrets,
tokens, private keys, local credentials, local paths and production
identifiers. It contained no secrets or private keys; the fixture keys were
never in it. Local paths are replaced, ANSI codes are stripped, and the full
node and CI logs are reduced to the excerpts the report cites.
