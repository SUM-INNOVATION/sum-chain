# SNIP: Assignment-Aware, Bounded PoR Challenge Scheduling (design)

> **Status:** implemented and code-backed (issue #81). **Deployed in runtime
> genesis and activation-gated at height 9,200,000** on mainnet, as two of the
> seven post-supply gates: `por_assignment_targeting_enabled_from_height`
> (Phase 1) and `assignment_aware_por_scheduler_enabled_from_height` (Phase 2).
> Both are a strict extension of base PoR / SNIP V2, which is already active:
> below the gate, behavior is identical to today. They are **not usable before
> height 9,200,000** and auto-activate when the chain reaches it. Neither gate is
> exposed by `chain_getChainParams`, so **runtime genesis is the source of
> truth** (the website hard-codes the operator-verified constant `9,200,000` and
> derives active/pending from the live block height). The design rationale below
> is retained as written.

**Refs:** #62 (epoch-aware assignment/coverage), #20 (archive unbonding), #80
(operator tooling). See also [SNIP-V2-CHAIN-PLAN.md](./SNIP-V2-CHAIN-PLAN.md) §5.

---

## 1. Current baseline (code-grounded)

- **PoR challenges are probabilistic and already bounded.** Every
  `CHALLENGE_INTERVAL_BLOCKS = 100` blocks, `generate_storage_challenge_if_due`
  ([executor.rs](../../crates/state/src/executor.rs)) uses the **parent block hash**
  as a deterministic seed and issues **one** deterministic-random `(file, chunk,
  node)` challenge into the `ACTIVE_CHALLENGES` CF. On expiry the target node is
  slashed 5% and the challenge is deleted; `fee_pool` is paid only on a successful
  proof (SNIP-V2-CHAIN-PLAN §5.1–§5.2).
- **Assignment and coverage are epoch-aware (#62).** A file's chunk→archive
  assignment is derived by rendezvous hashing over the active-archive snapshot at
  each **assignment epoch** height; `storage_getAssignmentCoverageV2` reports
  `assignment_epochs`, `latest_assignment_epoch`, `reassignment_needed`, and
  per-epoch coverage. Epoch 0 is the original assignment.
- **Reassignment is owner-triggered (#62).** `ReassignChunksV2` appends a new
  assignment epoch when a latest-epoch archive has left the active set; it never
  mutates prior epochs. Operators drive it via the #80 wallet tooling.

## 2. Problem

- The current selection is **not assignment-aware**: it picks a `(file, chunk,
  node)` at random and does not guarantee that, over time, *every assigned
  (chunk, archive) pair* is challenged. A lazy archive holding a rarely-selected
  chunk can go unchallenged far longer than a chunk that happens to be picked.
- The obvious fix — sweep **files × chunks × archives** each interval and
  challenge every assigned pair — is **too expensive**: it scales with total
  stored data and would blow the per-block consensus budget. That is a non-starter.
- We want **deterministic, assignment-aware coverage** whose **per-block cost is
  bounded and independent of `files × chunks`**, and that plays correctly with the
  epoch model.

## 3. Design goals

1. **Deterministic** — derived purely from on-chain state + a block-derived seed,
   so every node computes the identical challenge set (replayable, consensus-safe).
2. **Bounded per block/interval** — a hard cap on challenges issued per interval,
   set by chain params; no unbounded work.
3. **Assignment-aware** — challenges target the archive actually *assigned* to a
   chunk under the applicable epoch, not a random node.
4. **Replayable by every node** — no local randomness, no wall-clock, no per-node
   state; same inputs → same output on all validators.
5. **Independent of `files × chunks` for per-block cost** — sampling, not
   sweeping. Total data may grow arbitrarily; per-block work stays flat.
6. **Compatible with the epoch model** — reads epochs, never mutates them;
   epoch 0 stays the original assignment; reassignment epochs remain append-only.

## 4. Proposed bounded scheduler (design)

At each challenge interval `H` (where `H % challenge_interval_blocks == 0`):

1. **Seed.** `seed = BLAKE3("snip.por.schedule.v1" || parent_block_hash || H)`.
   Deterministic and unpredictable-until-parent-known, matching the existing
   parent-hash convention. (Domain-separated from the v1 selector.)
2. **Sample files.** Deterministically select up to `max_files_sampled_per_interval`
   from the set of **funded, Active** files. This requires an **enumerable, bounded
   index of challengeable files** (see §6) so selection is O(sample size), not
   O(total files). Selection is a seeded stride/rejection walk over that index.
3. **Sample chunks.** For each sampled file, deterministically pick a bounded number
   of chunk indices in `[0, chunk_count)` from `seed`.
4. **Resolve assigned archive (assignment-aware).** For each `(file, chunk)`, pick
   the applicable epoch (default: the **latest** epoch; see §5 preference) and
   compute the assigned archive(s) via the existing rendezvous function over that
   epoch's snapshot — the same `assigned_archives`/`assigned_archives_presorted`
   used by the executor and `storage_getAssignmentCoverageV2`, so results agree
   byte-for-byte. Choose one assigned archive deterministically from `seed`.
5. **Emit, capped.** Issue challenges until `max_assignment_aware_challenges_per_block`
   is reached, then stop. Skip pairs already covered by an open challenge or within
   an optional per-file cooldown. Excess candidates are **dropped this interval**
   (they resurface in later intervals) — never queued unboundedly.

The output is a bounded, deterministic list of `(file, chunk, assigned_archive)`
challenges written exactly like today's single challenge. Everything downstream
(proof submission, expiry/slash, fee-pool payout) is **unchanged**.

## 5. Parameters (all new; fresh-chain default `None`, mainnet gate 9,200,000)

| Param | Meaning |
|---|---|
| `challenge_interval_blocks` | Interval cadence (generalizes the current `CHALLENGE_INTERVAL_BLOCKS = 100`). |
| `max_assignment_aware_challenges_per_block` | Hard cap on challenges emitted per interval — the primary cost bound. |
| `max_files_sampled_per_interval` | Cap on files inspected per interval. |
| `por_file_cooldown_blocks` (optional) | Minimum spacing before the same file is re-sampled, to spread coverage. |
| `por_epoch_preference` (optional) | Which epoch to challenge — default **latest** epoch; optionally round-robin older epochs at reduced rate for defense-in-depth. |

Defaults keep the feature **off** (a `None`/`0` gate height, mirroring the other
SNIP/OmniNode gates), so enabling it is a coordinated, reviewed rollout (§9).

## 6. Cost bound

Let `S = max_files_sampled_per_interval`, `C = max chunks sampled per file`,
`R = replication_factor`. Per interval:

```
work = O( S · C · R )        # bounded by params — NOT O(files × chunks × archives)
```

This is **independent of total files and total chunks**. To keep file **sampling**
itself sub-linear, the design needs a bounded, enumerable index of *challengeable*
(funded, Active) files — either reuse/extend the pushable/funded-file index that
already backs `storage_getPushableFilesV2`, or add an append-only challengeable-file
index. Chunk sampling is arithmetic on `chunk_count`; assignment resolution reuses
the existing rendezvous function (already bounded by `MAX_ASSIGNED_COUNT_CHUNK_COUNT`
semantics in coverage). **No full scan is ever performed.** If a required index does
not exist, adding it is part of the implementation scope (separate review), not this
document.

## 7. Coverage analysis

- **Current path (baseline).** One random `(file, chunk, node)` per interval.
  Expected intervals to first challenge a specific assigned `(chunk, archive)` pair
  scales with the *total* number of candidate pairs — i.e. coverage of any given
  pair degrades as the network grows. Not assignment-aware.
- **Proposed path.** Up to `max_assignment_aware_challenges_per_block` assignment-
  aware challenges per interval, spread deterministically across sampled files and
  chunks with an optional per-file cooldown. Over `k` intervals the probability that
  a given assigned pair remains unchallenged falls geometrically in the per-interval
  sampling probability; tuning `S`, `C`, and cooldown trades per-block cost against
  expected time-to-cover.
- **Representative example.** With `S = 8`, `C = 4`, `R = 3`, per interval the
  scheduler resolves ≤ `8·4 = 32` `(file, chunk)` pairs and emits ≤
  `max_assignment_aware_challenges_per_block` challenges — a flat per-block budget
  regardless of whether the network stores 1 GB or 1 PB. A file with 1,024 chunks
  sampled at `C = 4`/visit and revisited each cooldown window is expected to have
  every chunk challenged within `O(chunk_count / C)` visits — bounded and
  predictable, versus the baseline's growth-dependent expectation.

These are illustrative, not commitments; concrete probabilities and parameter
values are set during implementation review.

## 8. Epoch interaction

- **Epoch 0 stays the original assignment**; the scheduler only *reads* it.
- **Reassignment epochs are append-only** (#62); the scheduler reads whichever
  epoch `por_epoch_preference` selects (default latest) and never mutates epoch
  state or writes new epochs.
- Because assignment resolution reuses the same rendezvous function as the
  executor and `storage_getAssignmentCoverageV2`, a scheduled challenge always
  targets an archive that coverage would also consider assigned for that epoch —
  no divergence between "who is challenged" and "who is counted as covering."
- After an owner `ReassignChunksV2`, new challenges naturally target the new
  epoch's assigned archives on subsequent intervals; prior-epoch attestations keep
  their meaning per #62.

## 9. Rollout plan

1. **Design review** of this document before any code.
2. Implement behind a **new activation gate** (fresh-chain default `None`) so it
   ships gate-closed; the v1 probabilistic selector remains the only active path
   until the gate is reached. **On mainnet the Phase 1 and Phase 2 gates are now
   set to height 9,200,000** (see §9a/§9b).
3. Below the gate, **behavior is identical to today** — this is a strict superset,
   activated at the gate height.
4. Add operator visibility (extend the #80 coverage tooling) and conformance
   vectors so all nodes agree on the deterministic schedule before activation.

**The original design PR made no behavior change; Phases 1 and 2 have since
shipped (issues #97 and #100) and are activation-gated at height 9,200,000 on
mainnet — see §9a/§9b.**

## 9a. Phase 1 shipped behavior (issue #97)

Phase 1 (assignment-aware *targeting* of the existing single challenge, distinct
from the bounded multi-challenge scheduler above) is implemented behind its own
gate `por_assignment_targeting_enabled_from_height: Option<u64>` (fresh-chain
default `None`; **on mainnet deployed and set to height 9,200,000**, one of the
seven post-supply gates; **not** shared with the scheduler gate, per §5/#97).
This gate is not exposed by `chain_getChainParams`, so runtime genesis is the
source of truth.

- **Below the gate** — byte-identical legacy: `generate_challenge` samples one
  file from the V1 funded set (`get_funded_file_roots`) and one target from
  **all** currently-active archives.
- **At/above the gate** — same single-challenge cadence, but:
  1. the file is sampled from the **V2 funded + Active** candidates
     (`funded_active_v2_candidates`: `lifecycle == Active`, `fee_pool > 0`,
     `chunk_count > 0`; deterministic order), which are the only files that
     carry an assignment;
  2. after `(file, chunk)` is chosen, the target is drawn only from the archives
     **assigned to that chunk** under the file's **latest** applicable assignment
     epoch snapshot, filtered to those **currently Active**, chosen
     deterministically from the existing challenge seed;
  3. if no assigned archive is currently Active for that chunk, the challenge is
     **skipped** for the interval — a bystander is never challenged or slashed.

Cost is `O(V2 funded+Active candidates + epoch snapshot size)` for the single
challenge — no files×chunks sweep, no new CF, no schema change, no economics
change. A pre-existing V1 bug was fixed alongside: `get_funded_file_roots` now
guards `key[0] == b'F'` so owner-index marker keys are never decoded as funded
rows.

## 9b. Phase 2 shipped behavior (issue #100)

The bounded scheduler is implemented behind its own gate
`assignment_aware_por_scheduler_enabled_from_height: Option<u64>` (fresh-chain
default `None`; **on mainnet deployed and set to height 9,200,000**, never shared
with the Phase-1 gate). This gate is not exposed by `chain_getChainParams`, so
runtime genesis is the source of truth. Below the gate, challenge generation is
exactly the post-#101 single-challenge path.

- **Params** (consulted only when the gate is open): `max_assignment_aware_challenges_per_block`
  (default 16, the hard emit cap), `max_files_sampled_per_interval` (8),
  `max_chunks_sampled_per_file` (4). Cadence reuses `CHALLENGE_INTERVAL_BLOCKS`;
  epoch preference is fixed to **latest**; no cooldown in v1 (`TTL 50 < interval
  100`, so no open challenge survives across intervals).
- **Challengeable index** — CF `challengeable_files_v2`, key `merkle_root` (32
  raw bytes) → value `chunk_count` (4-byte big-endian `u32`). Present iff a V2
  file is `Active && fee_pool > 0 && chunk_count > 0`. Maintained on
  `ActivateFileV2` and on a V2 challenge payout that drains `fee_pool` to 0. A
  **one-time** backfill (guarded by a persisted marker in `meta`) is the only
  full V2 scan and runs once when the gate first opens; if it fails the scheduler
  fails closed for that block.
- **Sampling** — seed `blake3("snip.por.schedule.v1" || parent_hash || H)`; a
  seeded stride-walk (`iter_from`, wrap-around) samples ≤ `max_files` files from
  the index, ≤ `max_chunks` chunks each; each `(file, chunk)` resolves to an
  assigned-active target under the file's latest epoch (reusing #97's
  `select_assigned_active_target`); emits ≤ `max_emit` challenges, identical in
  shape to the single-challenge path. Pairs with no assigned-active archive are
  skipped; stale index entries are removed and skipped. Cost is
  `O(max_files·(log n + max_chunks·R))` — never files×chunks.
- **V2 proof settlement (prerequisite)** — `SubmitStorageProof` now settles V2
  files: V1 rows keep exact prior behavior; a V2-only file requires `Active`,
  bounds `chunk_index < chunk_count`, verifies the same Merkle proof against the
  root, and pays `CHALLENGE_REWARD` (partial if low) from V2 `fee_pool`, removing
  the file from the index when drained. Without this, an honest archive holding a
  challenged V2 chunk could not prove and would be slashed. Payout amount, slash
  percentage, and TTL are unchanged.

## 10. Out of scope

- **Reward / slash economics** — payout stays fee-pool based; slash stays the
  existing 5%-on-expiry. No emissions, no new economics (see
  [economic-model.md](../architecture/economic-model.md)).
- **Automatic / chain-driven reassignment** — reassignment remains owner-triggered
  (#62); this scheduler only *challenges*, it does not reassign.
- **Filecoin-style PoRep / Arweave-style randomized recall / per-chunk continuous
  proof** — explicitly out of scope, consistent with SNIP-V2-CHAIN-PLAN §1/§5.1.
- **Unbounded scans** of any kind — the design exists specifically to avoid them.
