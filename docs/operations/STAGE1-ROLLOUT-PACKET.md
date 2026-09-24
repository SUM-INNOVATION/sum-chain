# Stage 1 rollout packet

Prepared 2026-09-23 against merged `origin/main` =
`8954b0d0ace726ab9491cac8a7757f11158c3d1a`. Read-only throughout: nothing was
deployed, pushed, built into a registry, or changed on any external system.

**Status: NOT READY TO AUTHORIZE A DEPLOYMENT.** There is no artifact to
authorize (§1), the only safe rollback depends on a snapshot capability nobody
has verified (§5), and this machine has no access to production (§12). The
preparation is complete; the packet says exactly what closes each gap.

Every row below is marked **VERIFIED** (checked against source, CI, the live
chain or a reproduction), **INFERRED**, or **UNVERIFIED — needs access**.
Inability to reach production is never recorded as a pass.

Detail lives in: `stage1-release-artifact.md` (artifact),
`stage1-rollout-runbook.md` (procedure), `stage1-external-evidence.md`
(measurements), `activation-rollout-evidence.md` (evidence collector),
`wave1-activation-monitoring.md` (telemetry), `stage2-procedure.md`.

---

## 0. What this round found that changes the plan

Five findings, each reproduced or verified independently, not taken on report.

1. **No deployable artifact exists.** CI builds only the `dev` profile and
   uploads nothing; the one release build (inside `health-e2e`'s Docker build)
   is discarded when the job ends. No image, digest, SBOM or signature exists
   anywhere. **VERIFIED.**
2. **The only image build uses a different compiler from the one every test ran
   on.** The Dockerfile builds with `rust:1.85`, unpinned, without `--locked`;
   `rust-toolchain.toml` and all CI pin 1.88.0. The binary also cannot report
   its commit (`GIT_HASH` is never set). **VERIFIED.** Repaired in this PR (§14).
3. **Rolling back by reverting the image destroys the validator's database.**
   Stage 1 adds one column family (`application_journal`) to the 187 the
   deployed 0.2.0 binary knows, and creates it at first open. On revert, 0.2.0's
   open fails with "Invalid argument"; it classifies that as corruption, and its
   default-on auto-repair runs `DB::repair` without family descriptors, which
   keeps only `default`. **Reproduced**: 189 families → 1; `blocks`, `state`,
   `meta` 2000 rows → 0. Stage 1 also writes every journal under a new key on
   every block, so this is not one fixable column: **snapshot restore is the only
   safe rollback.** The release candidate carries the same landmine forward to
   Stage 2; repaired in this PR (§14).
4. **One validator down halts the chain.** Proposer is `validators[height % N]`
   (`poa.rs`), importers reject any other proposer, and nothing skips a slot.
   With two validators, a "rolling" upgrade is **two planned halts**.
   **VERIFIED** from code; seen live (93 min halt, 2026-09-11).
5. **Starting Stage 1 on the wrong genesis splits the chain silently.**
   Production's genesis carries four passed heights no committed file has. A
   genesis missing them passes every startup check (they are on the
   predating-gate list, which the retroactive check exempts), and the old
   validator compares no digest. **VERIFIED** from code and live params.
   **The upgrade must never replace the genesis file.** Runbook §2.2 (d), §2.7
   and §4.3 check 7 now catch it.

**This PR supersedes PR #254's rollback statement.** #254's historical
description is left unedited. It presents
image revert as a safe pre-activation rollback. Stage 1 is dormant in consensus
but not on disk. From this PR on, the supported rollback after Stage 1 has
opened a volume is **restoring a volume snapshot taken before that first open**,
and nothing else (`production-checklist.md` item 5, §9 below).

---

## 1. Artifact and provenance

| field | value | status |
|---|---|---|
| commit | `8954b0d0ace726ab9491cac8a7757f11158c3d1a` (= `main` = `lane-a/final`) | VERIFIED |
| `Cargo.lock` sha256 | `c78c4039b75af095506afa759e215e0e6355cbbe94cfef8f5fe2070c31fcaab4` | VERIFIED |
| toolchain tested | rustc 1.88.0 (`6b00bc388 2025-06-23`), x86_64 + aarch64 | VERIFIED |
| toolchain the image uses | rustc **1.85**, unpinned tag | VERIFIED — defect |
| image tag / digest | **none exists** | VERIFIED — blocker |
| binary sha256 | **none exists** (CI discards its release build) | VERIFIED — blocker |
| binary reports its commit | **no** on `main` — logs `Commit: unknown`; **yes** with this PR (`sumchain --version`) | VERIFIED |
| SBOM / provenance / signature | none; no workflow signs or attests | VERIFIED |
| `sumchain-wire` 0.5.0 | workspace path dependency; crates.io publish **not** needed for the node; `publish-wire.yml` fires only on a `wire-v*` tag, and none exists | VERIFIED |
| manifests' image | `sumchain/node:latest` — mutable, and absent from Docker Hub | VERIFIED |
| private registry (GHCR) | could not check: `gh` lacks `read:packages` | UNVERIFIED — needs access |

**Repair, in this PR:** `FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86…d89`
(resolved read-only from the registry) and `--locked`. The image now
**refuses to build without the full 40-hex `GIT_HASH`** instead of falling back
to `unknown`, and every caller of the Dockerfile supplies it (four compose
services, the snip mirror, the health-e2e harness). `sumchain --version` prints
the exact commit. The new workflow `docker-image.yml` builds the real image,
runs it, and fails unless `--version` prints exactly the commit it built. It
also proves the build refuses without one. **No image is pushed**: no registry
login, no push step, `contents: read`. Locally: the guard over 7 inputs, the
built binary's `--version`, and 30 node tests. The Docker image itself is tested
only in CI, because this machine has no Docker.

The exact build, push and digest-inspect commands are in
`stage1-release-artifact.md`, with the registry left as `<REGISTRY>`.

## 2. Validator inventory

| index | public key | address | slot | network role | status |
|---|---|---|---|---|---|
| 0 | `GW1pJKzqDmmHczMGz5g7CV51RgDuR6kKw76yZ1cVbEv8` | `8zZ1pfbpUcAmoByWKYgJgiFZWpmhWQKJ4` | even heights | dialer; answers `rpc.sumchain.io` | VERIFIED |
| 1 | `7jUZxm5rJ5PazGYkrtJ4sUJj7ztib2VHEoM2Yc4Liydy` | `D7Ls8H7Y2jCqYEEUUxWUcgQkF9cKhHxjV` | odd heights | listener | VERIFIED |

Two validators, from `sum_getValidators` and 120 consecutive headers
alternating 60/60; the keys are byte-identical to the two in the committed
root `genesis.json` (checked directly). Track 2 also rebuilt genesis block 0 from
that file and matched the live hash `0x1156d350…d68e6`; that one reproduction
was not repeated for this packet. Deployed binary: `node_info` version
**0.2.0** (170 commits of source history carry that version; the exact commit
is unrecoverable, since it reports `Commit: unknown`).

**The repo's four StatefulSets do not describe this network** (a deprecated
three-replica set sharing one key, plus three single-validator sets — up to four
identities for a network of two). Production may not run on Kubernetes at all.
**Where each key actually runs: UNVERIFIED — needs access** (runbook §2.1).

## 3. Genesis byte hashes

| file | sha256 | chain | validators | loads |
|---|---|---|---|---|
| root `genesis.json` | `d90fa1e7a6435f53155b25f1662042217602442620c63923700b6b783555815d` | 1 | 2 | yes |
| `genesis/local_genesis.json` | `009983f9ab76cc37a2658b20eee70d7ffe3e503b65b591697d1c17b3974f0ba5` | 1337 | 3 | yes |
| ConfigMap-embedded genesis | `47cf132ddbe3cc3a83c71afe5a782595f9d8e6e81c60c7810eac148cfe0b362f` | 1337 | 0 | **no** — missing `block_time_ms` |

All three differ. The ConfigMap's comment calling its genesis identical to
`local_genesis.json` is false, and the ConfigMap cannot boot a node.

**The deployed genesis is none of these.** Live params carry `v2` 5,200,000,
`omninode` 6,000,000, `education` and `governance` 8,900,000; no committed file
sets them. Validators, allocation and genesis time match root `genesis.json`
(params-stripped hash `23d76730…23d0`). **Mounted bytes on each validator:
UNVERIFIED — needs access** (runbook §2.2).

## 4. Capacity and schedulability

| | value | status |
|---|---|---|
| per validator container | cpu 500m request / 2000m limit; memory 4Gi / 4Gi | VERIFIED (manifests) |
| QoS class | **Burstable** — CPU request ≠ limit | VERIFIED |
| memory on the eviction path | protected: usage cannot exceed an equal request without first hitting the limit, which is a cgroup OOM-kill, not an eviction | VERIFIED (documented kubelet ranking) |
| init / sidecar containers | none | VERIFIED |
| 4Gi schedulable on the real nodes | **UNVERIFIED — needs access** (runbook §2.3 gives the commands and pass rule) | |
| metrics port | `/metrics` on **8546**; nothing binds the 9090 the manifests declare and annotate | VERIFIED |

## 5. Database backup plan

**A pre-upgrade volume snapshot of BOTH validators is mandatory, not optional**
— after §0.3 it is the only rollback that preserves the chain. Runbook §4.1:
CSI `VolumeSnapshot` of each validator's `data` volume while it still runs the
old binary, PV reclaim `Retain`, snapshot confirmed `readyToUse` before either
validator changes. `sumchain backup` is not a usable substitute (runbook §2.4).

**Snapshot capability: UNVERIFIED — needs access.** If production cannot take
and restore a volume snapshot, **there is no safe rollback, and the rollout
should not be authorized.** Measure restore time on a clone before the window.

## 6. Rollout commands

Runbook §4. Order and reason:

1. **Pre-flight gates §2.1–2.7**, all read-only, all must pass — including
   §2.2 (d), the four live heights present, and §2.7, each validator's params
   captured from the old binary.
2. **Snapshot both volumes** (§4.1).
3. **Upgrade the dialer first** (validator 0, `GW1p…`) — halt #1. The 0.2.0
   dialer dials only at startup, so restarting the listener first would leave
   the old dialer never reconnecting (INFERRED from 0.2.0-era `network.rs`).
   Image changes by **immutable digest**; the genesis file does not change.
   Stop with SIGINT: the node ignores SIGTERM and runs as PID 1 (INFERRED).
4. **Observe mixed versions** (§4.3) — the old binary validating the new one's
   blocks is itself the Stage 1 agreement test.
5. **Upgrade the listener** (validator 1, `7jUZ…`) — halt #2. Watch for the
   listener-restart deadlock (§5.3).
6. **Collect Stage 1 evidence** on both (§4.5, `rollout-check.py`).

## 7. Observation window

At least **1,200 blocks ≈ 30 min** at the measured 1.498 s/block, between the
two upgrades. Checks (§4.3): both advance within 2 blocks; state root agrees at
a finalized height both hold; peers connected; no import errors; proposer parity
never breaks; the new RPC surface answers on the new node; **params identical to
the pre-upgrade capture** (check 7, tested against live params — see §0.5).

Compatibility handshake lines appear only once **both** validators run Stage 1:
0.2.0 predates the handshake, so during the mixed period silence from it is
expected, not a failure. After §6 step 5, N·(N−1) = **2** success lines and
zero refusals are required; there, silence is failure.

## 8. Telemetry

`tools/lane-b/wave1-monitor.sh` against `http://<validator>:8546`:
`verify` (the metric is present and correctly shaped — for Stage 1 this is the
check that matters, since no gate opens and the counter should stay flat),
`baseline`, `delta`, `agree`. Handshake: `info!` "compatibility handshake
accepted"; refusal: `warn!` "REFUSING peer". Full queries and alert rules:
`wave1-activation-monitoring.md`.

**The monitor as merged was wrong in both directions, and is repaired in
this PR.** The counter is per-process
and resets on restart. `delta` computed `now − baseline`, so a restart made
every delta negative and it printed "Nothing moved" — **reproduced on the merged
script: baseline 100, restart, three real refusals, delta −97, "Nothing moved",
exit 0.** `agree` diffed raw totals, so two *healthy* validators that started at
different times reported "DISAGREE … fork in progress" — **reproduced.** The
repair detects a restart by process start time (wall clock minus uptime) and by
any series falling, and exits **3, INCONCLUSIVE** instead of either wrong
answer; `agree` compares deltas over the same block range and calls a fork only
when that range is identical, with no restart, and the refusals still differ.
10-case battery passes. The docs also scraped port 9090 (nothing binds it) and
listed three validators; both corrected.

This blocks **Wave 1**, not the Stage 1 binary: Stage 1 opens no gate, so there
is nothing to refuse yet.

## 9. Rollback commands

Runbook §5.2, decided by one question — **did the new binary ever open this
volume?** Check for an `Opening database` log line in the current and previous
container and `restartCount`.

* **Never opened** (pull error, config error, never started): image revert by
  the recorded old digest is safe.
* **Opened, even once, even if it then refused to start:** **never start the old
  image on that volume** — it would auto-repair and wipe it. Restore from the
  §4.1 snapshot (needs owner sign-off at the time), or fix forward. A single
  restored validator comes back at the snapshot height and syncs forward from
  its peer; nothing is lost chain-wide.
* **Both validators upgraded:** restoring both **rewinds the chain** — every
  block since the upgrade, finalized ones included, is abandoned. That is the
  decision packet's option E, a social decision. Its practical window is the
  observation period after the listener upgrade; after that, fix forward.

The old image digest (the revert target) must be recorded before anything
changes (§2.6). **UNVERIFIED — needs access.**

## 10. Stop conditions

Runbook §5.1. Stop before the next step if: any pre-flight gate fails; a halt
exceeds its 15-minute hard limit; the new node crash-loops or reports
`chain activation parameters are unsound`; any `REFUSING peer` line; state
roots disagree at a finalized height; proposer parity breaks; **params differ
from the pre-upgrade capture**; or either node reports import errors.

## 11. External measurements collected

From the public endpoint `https://rpc.sumchain.io`, read-only:

| measurement | result | when (UTC) | status |
|---|---|---|---|
| chain id | 1 | 2026-09-23 | VERIFIED |
| height | 13,242,067 | 19:46:02 | VERIFIED |
| block interval | 1.498 s/block (241 blocks / 361 s; header gaps 1.275/1.725 s) | 19:20–19:26 | VERIFIED |
| validators | 2, strict alternation | 19:46 | VERIFIED |
| activation heights live | v2 5.2M, omninode 6M, education 8.9M, governance 8.9M | 19:46 | VERIFIED |
| deployed version | 0.2.0; uptime ≈12.5 d; 1 peer | 2026-09-23 | VERIFIED |
| `chain_getActivationStatus` | "Method not found" — the deployed binary predates it | 2026-09-23 | VERIFIED |
| backend behind the endpoint | a single node (validator 0) | 2026-09-23 | VERIFIED |

**Not measured, and no proxy recorded:**

* **Production `cf::STATE` row count** — needs a node built from this tree
  opened against the production data directory, or `chain_getSyncCapability`,
  which the deployed binary does not serve. Missing: production access with
  `pods/exec` (form A) or `pods/portforward` (form B), or a production snapshot
  plus its height. Acceptance bands in `stage1-external-evidence.md`.
* **OC-3** — the tree the designated "thirteen" was counted against is recorded
  nowhere: it came from an uncommitted session summary. Its reproducer also has a
  defect: on trees older than `fdc077e1` it panics before printing anything.
  Reported, not fixed.
* **SC-8** — needs the deployed service/ingress, the deployed `[rpc] addr`, and
  the Cloudflare origin configuration.

None of the three gates Stage 1: all three apply to future activation.

## 12. Unresolved access blockers

This machine has **no** `kubectl`, kubeconfig, cloud CLI, SSH configuration or
Docker, and `gh` lacks `read:packages`. Each item names what closes it.

| blocker | closes it |
|---|---|
| where production runs; which workload holds which key | runbook §2.1 with a production kubeconfig or host access |
| genesis bytes each validator mounts | §2.2: `cat /config/genesis.json` from both, hashed locally |
| 4Gi schedulability, live QoS | §2.3: node allocatable, placed requests, volume `nodeAffinity` |
| **snapshot capability and restore time** | §2.4: `volumesnapshotclass`, a test snapshot, a timed restore on a clone |
| dialer's bootnode addressing; `publishNotReadyAddresses` | §2.5 |
| old image digest (rollback target) | §2.6: `.status.containerStatuses[0].imageID` |
| real open and WAL-replay time at ~13M blocks | time a start on a snapshot clone |
| whether SIGTERM is ignored | `kubectl describe pod` after a past deletion |
| images in GHCR | a token with `read:packages` |
| the artifact itself | §1: repair merged, image built from the exact commit, pushed, digest recorded |

## 13. Duration and operator responsibilities

**Active window ≈ 1–1.5 h**, plus pre-flight: two halts (target ≤ 5 min each,
hard stop 15 min — the database open time at ~13M blocks is unmeasured and
dominates), and ≥ 30 min of mixed-version observation between them. Past
unplanned halts ran 30 min to 14.6 h, so announce both windows in advance.

Two operators recommended: one executing, one reading the stop conditions.
The operator owns: every pre-flight gate; both snapshots confirmed
`readyToUse`; the old digests and pre-upgrade params recorded; the genesis
file left untouched; SIGINT rather than SIGTERM; the observation window held
to its full length; the rollback decision per §9; and the evidence bundle
`rollout-check.py` must accept.

---

## 14. Defects found and repaired this round

Everything is in **this one PR, as separate commits**, on top of `8954b0d`.
Nothing is merged, no image or package is published, and no activation height
is set. The final tree is byte-identical to the integrated tree every battery
below ran on.

| # | defect | commits | tested |
|---|---|---|---|
| 1 | image built with rustc 1.85, unpinned, no `--locked`, and the binary cannot report its commit | `docker:` ×2 | guard over 7 inputs; built `--version` = the commit; 30 node tests; clippy and rustfmt identical to base; **the image is tested by `docker-image.yml` in CI** |
| 2 | auto-repair wipes the database on a downgrade, and the release candidate carries this forward to Stage 2; the checklist put the danger at the first block instead of the first open | `storage:` ×2 | 3 tests; 3 mutations killed; workspace 212 suites / 2837 passed / 0 failed; `downgrade-probe` reproduction preserved (rocksdb 0.22.0 pinned) |
| 3 | monitor hid refusals after a restart, reported a fork on healthy nodes, read missing data as zero, and scraped a port nothing binds | `monitor:` ×2 | 15-case battery (the original 10 plus 5 missing-data cases); the defects reproduced on the earlier scripts |
| 4 | evidence recorder hashed a path that does not exist and **silently wrote a blank hash, exit 0**; its rules were prose | `rollout evidence:` ×2 | 14 checker cases + 6 recorder refusals; path derived from the Dockerfile; the 6 refusals fail against the old recorder |
| 5 | runbook could not catch a wrong-genesis start, and understated a both-validator rollback | `runbook:` ×2 | params check tested against the live 21-field params |

Plus the release-artifact manifest (`docs(ops):`), the runbook itself
(`ops:`), and this packet (`packet:`).

Repair 2 does **not** make the Stage 1 rollback safe. On a revert, the binary
that runs is the deployed 0.2.0. What repair 2 does is stop the next transition
from inheriting the defect.
