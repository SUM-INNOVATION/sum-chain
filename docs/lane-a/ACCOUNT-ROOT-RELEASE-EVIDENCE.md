# Account-root release evidence

What the account-state-root commitment does, what it costs, and what about it is
still unproven. Every number below is either a command's real output or is
marked UNPROVEN with the command that would settle it. Nothing here is an
estimate presented as a measurement.

**Measurement machine, stated once because it bounds every timing:** Apple M5,
10 cores, 16 GiB RAM, macOS 26.6, internal NVMe/APFS, rustc 1.88.0, `--release`.
**This is a dev Mac, not validator hardware.** A validator on slower storage or
fewer cores pays more.

**Live chain, measured 2026-09-18** against the endpoint
`docs/operations/production-checklist.md:145` documents:

```
$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHeight","params":[]}'
{"jsonrpc":"2.0","result":{"height":12970099,"finality":"latest"},"id":1}
```

and the block interval, sampled directly rather than taken from `block_time_ms`:

```
sample A: height=12970111
sample B: height=12970191   (+80 blocks in 120.2 s)
observed block interval = 1.502 s/block
observed rate = 57,524 blocks/day
```

This independently confirms the **1,506 ms** figure `crates/state/src/account_root.rs:93`
and `docs/operations/ACCOUNT-ROOT-ACTIVATION.md:30` already use. `block_time_ms`
is 3,000 — a proposer's own slot, halved by two validators in round-robin
(`sum_getValidators` → 2). **1,506 ms is the per-block budget the commitment
must fit inside.**

---

## 1. The stored `cf::STATE` row count — UNPROVEN, and precisely so

### 1.1 What the instrument counts

`crates/state/src/account_root.rs:499`:

```rust
pub fn account_row_count(db: &Database) -> Result<u64>
```

- iterates `db.prefix_iter_checked(cf::STATE, ACCOUNT_KEY_PREFIX)`;
- breaks on the first key not carrying `ACCOUNT_KEY_PREFIX` (prefix iterators
  overrun the family; prefixed keys are contiguous);
- **skips without counting** a prefixed key `StateStore::address_in_account_key`
  cannot parse — matching `AccountDigest::fold` at `account_root.rs:410`, so the
  count and the digest see exactly the same record set;
- counts every other row.

**It counts raw stored rows. It applies no balance or nonce filter.** That is
the whole point, and it is pinned by two tests rather than asserted:

- `crates/state/tests/account_state_root.rs:1236
  the_row_count_is_not_the_count_of_accounts_holding_value` — seeds four rows
  `(1000,0)`, `(0,7)`, `(0,0)`, `(0,0)`, asserts `account_row_count == 4` while
  the balance-based count is `1`, then deletes one and asserts the count drops to
  3 **and** the digest moves;
- `:1270 the_row_count_agrees_with_the_fold_it_predicts` — 37 rows, count 37;
  adding one moves both count and digest.

Both pass (§2).

### 1.2 The "18 value-holding accounts" figure

It exists in the repository, in three places, and **all three already label it as
not a stored-row count**:

- `crates/state/src/account_root.rs:106` — "18 accounts hold value on mainnet …
  That is a **lower bound** on stored rows and nothing more."
- `docs/operations/ACCOUNT-ROOT-ACTIVATION.md:34` — table row "accounts holding
  value | **18**", immediately above "| **stored account rows** | **NOT
  MEASURED** |".
- `crates/state/tests/account_state_root.rs:689` —
  `const MAINNET_ACCOUNTS_HOLDING_VALUE: usize = 18;` with the same caveat.

The two reasons 18 is not an upper bound are code-grounded, not rhetorical:
zero-balance/zero-nonce rows are invisible to RPC because `get_account` flattens
absence to `{0,0}`; and `contract_executor.rs` credits the **contract** address
on a value-carrying deployment, an address no transaction index reaches
(contracts have been gate-open on mainnet since height 8,900,000).

The supply arithmetic that 18 was derived from does check out independently —
live `chain_getSupplyInfo.accounted_account_supply` is `"999998997000000000"`,
the exact figure the closure argument is cross-checked against. **That confirms
the supply, not the row count.**

### 1.3 Is a representative database reachable from this machine? No.

| probe | command | result |
|---|---|---|
| home data dirs | `ls -d ~/.sumchain ~/.sum ~/sumchain-data` | none exist |
| any RocksDB anywhere | `find ~/ -maxdepth 4 \( -name IDENTITY -o -name CURRENT \) -not -path '*/Library/*' -not -path '*/.Trash/*'` | **zero hits** |
| repo `./data` | `ls -la data` | does not exist (`config.toml` sets `data_dir = "data"`; `configs/local/validator1.json` sets `data/validator1`; neither exists) |
| docker | `docker ps` | `command not found` — the four `docker-compose.yaml` volumes are declarations, never materialised |
| `deploy/` | `ls -R deploy` | k8s manifests and Prometheus/Grafana config only; no database |

### 1.4 And the live RPC cannot serve it either

```
$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"chain_getSyncCapability","params":[]}'
{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"},"id":2}
```

`chain_getSyncCapability` is where this tree exposes `account_rows`
(`crates/rpc/src/server.rs:1608`). Mainnet answers **Method not found**, so the
deployed node runs a binary that predates this work. `chain_getActivationStatus`
answers the same way. No other method on the surface exposes a state-size or
account-count statistic.

### 1.5 Verdict, and the external dependency stated as a contract

> **UNPROVEN. The stored `cf::STATE` row count is `≥ 18`. The upper bound is
> unknown, and no path from this machine can establish it.**

**`≥ 18` is a LOWER BOUND carried over from the value-holding count, and it is
not a row count.** §1.2 gives the two code-grounded reasons it cannot be an upper
bound. Nothing in this document, and nothing in the record this table asks for,
may substitute one for the other. The node's own source says it in the same
words (`crates/node/src/node.rs:606-611`): "this number is the stored-row count,
not the count of accounts holding value. The two are different: a row whose
balance and nonce are both zero is invisible to every balance query and costs
exactly as much to fold as any other."

This is an **external dependency**: it can only be discharged by someone with
access to a production data directory. Stated as a contract so that whoever
discharges it does not have to reconstruct what was wanted.

| | requirement |
|---|---|
| **What is being measured** | the number of rows in `cf::STATE` carrying `ACCOUNT_KEY_PREFIX` — the record set `AccountDigest::fold` walks once per block. **Not** the number of accounts holding value, **not** the number of addresses any RPC or index can enumerate, **not** the number of transaction senders. Zero-balance and nonce-only rows are in `cf::STATE` and are folded by the digest (§1.1), so any figure derived from balances is a lower bound and is not an answer |
| **The instrument** | `account_row_count` (`crates/state/src/account_root.rs:499`). It applies no balance or nonce filter, and it skips exactly the keys `AccountDigest::fold` skips, so the count and the digest see the same record set. Pinned by `crates/state/tests/account_state_root.rs:1235 the_row_count_is_not_the_count_of_accounts_holding_value` and `:1270 the_row_count_agrees_with_the_fold_it_predicts` |
| **Endpoint requirement** | **The public mainnet RPC cannot serve this and will not be able to until the rollout.** `https://rpc.sumchain.io` answers `chain_getSyncCapability` with `{"code":-32601,"message":"Method not found"}` (§1.4, re-verified). The reading must come from **a node running a binary built from this tree, opened against the production data directory** — either a production validator after the upgrade, or a node restored from a production snapshot. A reading from a dev, test or synthetic database answers a different question and must not be recorded here |
| **Exact command — form A (preferred, no RPC needed)** | start the node and read the startup line it emits at `crates/node/src/node.rs:619-643`: <br>`Account rows: N (warn at 250000, act at 500000)` <br>or, at or above a threshold, `Account rows: N — at or above the warning threshold 250000 …` / `… the action threshold 500000 …` |
| **Exact command — form B (a running node)** | `curl -s http://<that node>:<rpc port>/ -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"chain_getSyncCapability","params":[]}'` and take `.result.account_rows` |
| **Expected output** | a single non-negative integer `N`. Form A prints it in the log line above; form B returns it as `result.account_rows` (`crates/rpc/src/server.rs:1608`, `SyncCapabilityInfo.account_rows`, `crates/rpc/src/types.rs:809`). **`N` must be `≥ 18`**; a smaller value means the instrument was pointed at the wrong database |
| **Recorded alongside — all four, or the number means nothing** | **(1) chain height** at which the count was taken (`chain_getBlockHeight`, or the node's own head) — a row count without a height is not a measurement of anything, because the count moves; **(2) wall-clock UTC timestamp**; **(3) node identity** — hostname or validator key, and the binary's commit SHA; **(4) data-directory identity** — the absolute `data_dir` path and whether the database was executed from genesis or restored from a snapshot, and if restored, the snapshot's height |
| **Measurement validity** | the reading is valid only if the node's head is within `finality_depth` (6) of the public head at the recorded timestamp — otherwise it describes a lagging database. **Two independent nodes should be read**, and their counts must agree once adjusted for any height difference; a disagreement is a finding in its own right and blocks the activation rather than being averaged away |

**Acceptance threshold — what the number has to be for the activation to be
schedulable.** The thresholds are the repository's own constants
(`ACCOUNT_ROW_WARN_THRESHOLD = 250_000` at `account_root.rs:471`,
`ACCOUNT_ROW_ACT_THRESHOLD = 500_000` at `:484`) read against the measured
1,502 ms inter-block interval and the measured ~0.16 µs/row scan cost (§2):

| measured `N` | scan cost | share of 1,502 ms | verdict |
|---:|---:|---:|---|
| `N < 250,000` | < 40 ms | < 2.7 % | **ACCEPT.** The activation may be scheduled on cost grounds |
| `250,000 ≤ N < 500,000` | 40–80 ms | 2.7–5.3 % | **ACCEPT WITH A TRACKING OBLIGATION.** Schedulable, and the count must be re-read on a stated cadence and the trie replacement designed in parallel |
| `500,000 ≤ N < 2,000,000` | 80–320 ms | 5.3–21 % | **DO NOT SCHEDULE on this evidence alone.** The repository's own escalation table puts the replacement's design at this count; committing more to the O(n) fold here is a decision, not a default |
| `N ≥ 2,000,000` | ≥ 320 ms | ≥ 21 % | **REFUSE.** The replacement must be SCHEDULED at 2M and ACTIVE at 4M. Opening the v1 fold above 2M schedules work that must be undone |
| `N ≥ 9,400,000` | ≥ 1,502 ms | ≥ 100 % | **REFUSE.** The scan no longer fits inside a block interval; measured at 10M it is 117 % (§2.1) |

Two riders on the acceptance thresholds, because they are inferences and should
not be read as measurements:

1. **Every timing behind them is a dev Mac** (§2, and gap 2 in *What remains
   UNPROVEN*). A validator on slower storage pays more, so the row counts at
   which each band begins are optimistic. The verdict bands are stated in rows,
   not milliseconds, precisely so the owner can re-derive them from a
   validator-host measurement without re-reading this document.
2. **The thresholds themselves are pinned by nothing.** §8.4 records that
   `ACCOUNT_ROW_WARN_THRESHOLD` and `ACCOUNT_ROW_ACT_THRESHOLD` have zero test
   references, and that `SyncCapabilityInfo.account_rows` — the field form B
   reads — is untested at the RPC surface. **The one number this activation is
   blocked on is served by an untested field**, which is an argument for
   preferring form A, or for taking both and comparing them.

`docs/operations/ACCOUNT-ROOT-ACTIVATION.md` already makes this Sequence step 0
and says the activation "should not be scheduled until it has been" measured.
This document does not weaken that.

---

## 2. Cold and warm benchmarks — run, with real numbers

Two tests measure it, both in `crates/state/tests/account_state_root.rs`:
`the_cost_of_the_account_commitment_at_a_realistic_account_count` (`:716`) and
`the_cost_of_the_account_commitment_with_a_cold_cache` (`:1055`).

**Run 1 — whole suite, default 100k rows:**

```
$ CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<isolated> \
    cargo test --release -p sumchain-state --test account_state_root -- --nocapture --test-threads=1

ACCOUNT-ROOT COST: 18 accounts (the mainnet value-holding count, a LOWER BOUND on stored rows)
  | committed scan 2.583µs (0.144 us/account) | 0.000172 % of a 1,506 ms block interval
  | digest 0xfdf921355b39274e71ae3a250e6db4f6a334047865b9687c980cffa1a62dda71
ACCOUNT-ROOT COST: 100000 accounts | first scan 11.824833ms | committed scan 11.788916ms (0.118 us/account)
  | execution-path merged scan 11.167208ms (0.112 us/account)
  | digest 0x6d04d27a2a1ec337329d9ac4b7a4d8f0bef27e2d4b810d6af536244962e08ca8
ACCOUNT-ROOT COLD COST: 100000 accounts | on disk 3341830 B (33.4 B/account)
  | warm 13.384458ms (0.134 us/account) | cold block cache 28.60825ms (0.286 us/account)
  | cold page cache not measured

test result: ok. 19 passed; 0 failed
```

**Run 2 — 1M rows, page cache evicted with 24 GiB of ballast:**

```
$ ACCOUNT_ROOT_COST_ACCOUNTS=1000000 ACCOUNT_ROOT_EVICT_PAGE_CACHE=25769803776 \
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<isolated> cargo test --release -p sumchain-state \
    --test account_state_root the_cost_of_the_account_commitment_with_a_cold_cache -- --nocapture --test-threads=1

page-cache eviction: wrote and read back 25769803776 B of ballast
ACCOUNT-ROOT COLD COST: 1000000 accounts | on disk 23605766 B (23.6 B/account)
  | warm 159.498458ms (0.159 us/account) | cold block cache 165.826125ms (0.166 us/account)
  | cold page cache 162.228333ms (0.162 us/account)

test result: ok. 1 passed; 0 failed; finished in 16.47s
```

**Run 3 — 10M rows, page cache evicted:**

```
$ ACCOUNT_ROOT_COST_ACCOUNTS=10000000 ACCOUNT_ROOT_EVICT_PAGE_CACHE=25769803776 … (same command)

page-cache eviction: wrote and read back 25769803776 B of ballast
ACCOUNT-ROOT COLD COST: 10000000 accounts | on disk 223425152 B (22.3 B/account)
  | warm 1.585767625s (0.159 us/account) | cold block cache 1.57591825s (0.158 us/account)
  | cold page cache 1.764532708s (0.176 us/account)

test result: ok. 1 passed; 0 failed; finished in 18.65s
```

### 2.1 Measured today, against the table the code carries

| rows | on disk | warm | cold block cache | cold page cache | µs/row | doc's warm / cold-page | share of 1,506 ms |
|---:|---:|---:|---:|---:|---:|---|---:|
| 18 † | <1 KiB | 2.58 µs | — | — | 0.144 | 4.6 µs / — | 0.00017 % |
| 100k | 3.34 MB | 13.4 ms | 28.6 ms | not run | 0.134 / 0.286 | 12.0 ms / 15.3 ms | 1.9 % |
| 1M | 23.6 MB | 159 ms | 166 ms | 162 ms | ~0.16 | 147 ms / 152 ms | 10.8 % |
| 10M | 223 MB | 1.586 s | 1.576 s | **1.765 s** | ~0.17 | 1.45 s / 1.62 s | **117 %** |

† **The `18` row is a BENCHMARK SIZE, not the production row count.** It is
the mainnet *value-holding account* count, which §1.2 shows is a lower bound on
stored rows and nothing more. The production `cf::STATE` row count is UNPROVEN
(§1.5). Read this row as "what the fold costs at eighteen rows", never as "what
the fold costs on mainnet".

On-disk sizes reproduce the code's table to three figures. Timings run 8–10%
above it at 1M and 10M — same order, same shape, same verdict.

**One discrepancy, flagged rather than smoothed:** the 100k **cold block cache**
figure is 28.6 ms here against 14.7 ms in the code's table — a ~2x gap at that
one point only. At 1M and 10M cold ≈ warm exactly as documented. These are
single runs with no variance collected, and 100k is the point where fixed cost
still dominates, so this may be noise. It is not explained, and it is recorded
rather than dropped.

**The 10M verdict is re-measured and unchanged: the coldest scan (1.765 s)
exceeds the 1,506 ms inter-block interval. At ten million rows it does not fit.**

### 2.2 What bounds these numbers

Stated in the test source at `account_state_root.rs:1180-1200` and true of every
run above: page-cache eviction is *approximate* — 24 GiB of ballast pressure on
a 16 GiB machine, not a proven page drop, so the cold-page figures are **lower
bounds** on a truly cold device; single runs, no variance; synthetic generated
addresses rather than production key distribution, so SST layout and compression
under real keys is unmeasured. The tests' own assertions are deliberately loose
tripwires on the *shape* of the cost (`cold_per_account < 200.0` µs,
`per_account_us < 50.0` µs), **not** benchmark gates.

---

## 3. Snapshot / fast-sync disposition

**A snapshot carries the account DIGEST, not the block state root's authority.**
`SnapshotHeader` (`crates/state/src/snapshot.rs:223`) holds three relevant
fields:

- `state_root` — kept as **provenance only**; the doc comment at `:232` says in
  so many words that it is "NOT what the account rows are checked against";
- `account_digest` (`:248`) — computed by `account_root::account_state_digest`,
  the same function over the same record layout a validator recomputes and
  `compute_block_state_root` folds once the gate is open;
- `account_root_activation` (`:256`) — the producer's gate height, so a consumer
  can say whether that digest is consensus-bound at all.

**Fast sync is DISABLED, structurally rather than by a flag.**
`SNAPSHOT_CARRIES = ["state:accounts"]` (`snapshot.rs:148`) against
`REQUIRED_FAST_SYNC_FAMILIES` (`:173`) — ten families including `supply`,
`contracts`, `contract_storage`, `tokens`, `nft`, `compute_pool`, `beacon`,
`storage_metadata`, `validators`. `missing_for_fast_sync` is the comparison, so
the refusal lifts itself when the format grows; it is not a hardcoded `false`,
and `the_disable_is_derived_from_the_two_family_lists` (`:987`) proves that by
handing it the full required set and watching the refusal disappear.

**Can a fast-synced node verify it?** Verification is not a property of the
file — the digest in it is a claim by whoever wrote it. It is the **chain**
checking at the restored node's first imported block:

- `snapshot_commitment.rs:741 above_the_gate_the_chain_verifies_a_fast_synced_node_at_its_first_block`
  — honest restore: the importer's own execution reaches the header root.
  Restore tampered by **one unit on an account the block never touches**:
  refused with "state root mismatch".
- `:797 below_the_gate_a_fast_sync_cannot_be_verified_at_all` — same fixture,
  production default with the gate dormant: **the tampered node imports
  cleanly.** `RestoreResult.consensus_verified_from == None` says so explicitly,
  rather than letting "no error" read as "verified".
- `:672 a_snapshot_carries_only_the_account_family_so_a_restore_cannot_reproduce_a_root`
  — the account family restores perfectly (the digest reproduces) and the very
  next block is **still refused**, because the supply digest is folded with no
  gate at all.
- `:942 fast_sync_is_disabled_and_the_refusal_names_what_is_missing` — the error
  contains the words "fast sync is DISABLED" and names the missing families;
  nothing is written.
- `:1177 the_snapshot_policy_admits_only_what_the_commitment_can_check` — the
  conjunction of all five clauses on one source/file/target.
- `:203 the_old_verification_could_never_have_succeeded` — the prior
  `verify_snapshot` compared `blake3(address‖balance)` against
  `header.state_root`, two unrelated values, and returned "not verified" for a
  perfect snapshot.

```
$ cargo test --release -p sumchain-state --test snapshot_commitment -- --test-threads=4
test result: ok. 24 passed; 0 failed
```

---

## 4. Historical-root refusal behaviour

**Code:** `crates/rpc/src/server.rs:871 refuse_below_history_floor(&self, height)`.
It reads one number — `history_floor()` → `sumchain_state::snapshot::imported_at`
→ `sumchain_storage::journal::undo_history_floor` — the same row the startup log
and `chain_getSyncCapability.state_history_floor` read, so the **advertised and
enforced floors cannot drift**. The rule itself is factored into
`crates/state/src/snapshot.rs:844 can_serve_history_at`.

**Behaviour:** a height below the floor is refused with error code **-32003**
(`crates/rpc/src/lib.rs:69-71`), deliberately distinct from -32001 (Not found).
The message names the floor and says:

> "This is not an assertion that nothing exists at {height} — this node cannot
> know. Query a node that replayed this range."

The distinction is the entire point: `-32001`, `null`, an empty list and `false`
all mean "absent", and **"I cannot know" is indistinguishable from them
otherwise.**

Two caller shapes (`server.rs:857-870`): **unconditional** where the path would
otherwise produce a *wrong* answer — `storage_getActiveNodesAtHeight` walks
backwards to the nearest snapshot and would return the oldest record the machine
holds, shaped exactly like a correct answer — and **on absence** where the path
has a real answer when it has the data. A node that executed its own chain has
`imported_at == None` and is wholly unrestricted.

```
$ cargo test --release -p sumchain-rpc --test operator_visible_activation_and_history
test result: ok. 12 passed; 0 failed
```

| test (`crates/rpc/tests/operator_visible_activation_and_history.rs`) | asserts |
|---|---|
| `:318 the_active_node_set_is_refused_below_the_floor_before_the_walk_runs` | -32003 at `0`, `1`, `FLOOR-1`; message carries the floor and "cannot know"; answers at `FLOOR` and above; an unrestricted node still answers at 0 |
| `:372 a_block_lookup_says_absent_or_says_it_cannot_know_but_never_confuses_them` | below floor → -32003; **above** floor an absent block is a real `null`; the `sum_*` alias is not a way around it |
| `:419 a_block_range_crossing_the_floor_fails_whole_rather_than_truncating` | whole-range -32003, never a short list |
| `:438 a_finality_check_below_the_floor_refuses_rather_than_answering_not_final` | -32003, because `false` is what a caller polls on |
| `:457 an_empty_message_list_below_the_floor_is_a_refusal` | -32003 |
| `:481 the_advertised_floor_and_the_enforced_floor_are_the_same_number` | `state_history_floor == FLOOR`, `journal_history_begins_at == FLOOR+1`; refuses at `advertised-1`, answers at `advertised` |
| `snapshot_commitment.rs:1128 a_corrupt_import_record_is_an_error_not_an_absence` | an unreadable record refuses everything rather than defaulting to "never imported" |

---

## 5. Restored-node depth clamp

**The clamp is `0` at the restore height, `+1` per block the node publishes
itself, capped at `UNDO_RETENTION_FLOOR = 4_096`** (`crates/storage/src/pruner.rs:60`),
which is a deliberate duplicate of `sumchain_consensus::poa::MAX_REORG_WALK =
4_096` (`crates/consensus/src/poa.rs:67`).

Why it starts at zero: the application journal is **node-local** — never hashed
into a block, never folded into a root, never transmitted. A snapshot delivers
canonical state and zero undo records. Replaying to build them is the sync that
was just avoided, and receiving journals from a peer is forbidden because
nothing authenticates non-consensus data. So the node accumulates its own, one
published block at a time.

**Two independently-derived numbers, required to agree:**

- **advertised** — `crates/state/src/snapshot.rs:875 usable_reorg_depth(restored_at, current)`
  `= current.saturating_sub(restored_at).min(UNDO_RETENTION_FLOOR)`, derived from
  the recorded import height;
- **enforced on the walk** — `crates/consensus/src/reorg.rs:114 plan_reorg_within_undo_history`
  → `:129 refuse_beyond_undo_history`, reading
  `JournalActivation::advertisable_reorg_depth(head, engine_max)` =
  `restorable_depth(head).min(engine_max)` (`crates/storage/src/journal.rs:670-712`),
  derived from **the journals the database actually holds**.

`plan.depth() > usable` → `ConsensusError::InvalidBlock`, refused **at plan
time** rather than mid-unwind.

Pinned by:

- `crates/state/tests/snapshot_commitment.rs:881 a_restored_node_has_no_reorg_depth_until_it_has_earned_it`
  — `usable_reorg_depth(R,R)==0`; `R+1→1`; `R+500→500`; `R+4095→4095`;
  `R+4096→4096`; `R+40960→4096` (never exceeds); a head **below** R → 0, not
  negative;
- `:1330 a_restored_node_cannot_accept_a_branch_it_cannot_unwind` — the one that
  pins the **agreement**: at the restore height both sides say 0, then for four
  published blocks it asserts `advertised == i+1` **and**
  `planner_depth(height) == advertised` at every height. Two numbers here would
  be a node that either refuses reorgs it could perform or attempts ones it
  cannot finish, leaving a branch half-applied;
- `crates/consensus/tests/reorg_execution.rs:4577 a_node_with_no_journal_history_advertises_zero_until_it_publishes`
  and `:5345 a_switch_deeper_than_this_nodes_undo_history_is_refused_at_plan_time`.

All passed.

---

## 6. Account and supply convergence

**The load-bearing test is `crates/consensus/tests/reorg_execution.rs:6178
a_reorg_converges_account_rows_supply_rows_journals_and_the_activated_root`.**
It passed.

Fixture: the fork is placed **above** `LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1`, so
`force_adopted` cannot absorb a disagreement and hide it. Abandoned branch 3
blocks (alice→carol); adopted branch 2 blocks (bob→carol) — different sender,
different amounts, different length.

Outcome shape asserted first: `unwound.blocks == 3`, `tolerated_absences == 0`,
`applied == 2`, `force_adopted == 0`, `verified == 2`.

Then four claims:

1. **Accounts.** `account_rows(&a) == account_rows(&b)` (raw `cf::STATE` rows
   under `ACCOUNT_KEY_PREFIX`) **and** `account_state_digest(&a.db) ==
   account_state_digest(&b.db)` — the same claim expressed as the value
   consensus folds. Plus named balances: carol `== 8_000` (the adopted branch's
   two payments, not the abandoned branch's three), alice `== 10_000_000`
   untouched, and **a bystander account no transaction touched `== 4_242`** —
   which reaches the root through the commitment and through nothing else.
2. **Supply.** `family(&a, cf::SUPPLY) == family(&b, cf::SUPPLY)` — the family
   covered by no per-subsystem legacy journal and folded into the root today via
   `SupplyStore::v_state_digest` with no gate at all.
3. **Journals.** Exactly 2 records remain in `cf::APPLICATION_JOURNAL` (3
   consumed by the unwind, 2 written by the apply) and they are
   **byte-identical** to what the branch-builder wrote.
4. **The activated root.** `activated_root == b.state.state_root()`, and the
   head blocks they name are the same block.

**And a control, which is what makes (4) mean anything:** the same fixture
rebuilt with `ChainParams::with_v2_enabled()` (account gate dormant) must
produce `applied == 2` and `assert_ne!(activated_root, dormant_root)`. Without
it, "the root converged" would be a statement about the supply digest and
receipts alone.

Strong form last: whole-database snapshot equality, `left == right`.

Supporting, both passed:

- `crates/state/tests/account_state_root.rs:1349 the_commitment_survives_publishing_a_chain_of_blocks`
  — five heights across the boundary, proposer versus importer, and the digest
  must **move** at every height so the equalities cannot be satisfied by a fold
  that ignores its input;
- `:1422 the_commitment_survives_a_restart` — digest, row count **including a
  zero row**, and state root all survive a restart, and the restarted node and a
  never-stopped twin publish the same next root.

A live cross-check of the supply side, from mainnet today:

```
chain_getSupplyInfo:
  accounted_account_supply     999,998,997,000,000,000
  economic_supply_before_reserve 999,999,000,000,000,000
  staked_or_locked                       3,000,000,000
```

`999,999,000,000,000,000 − 999,998,997,000,000,000 = 3,000,000,000`, exactly the
`staked_or_locked` figure. The account and supply views of mainnet agree to the
base unit.

---

## 7. The activation heights, and the invariant between them

**The two heights** are `application_journal_enabled_from_height` and
`account_root_enabled_from_height`, both `ChainParams` fields in the runtime
`genesis.json`.

**Every committed genesis in this tree leaves both absent (`None`)** — verified
across `genesis.json`, `genesis/local_genesis.json`,
`genesis/mainnet_genesis.json`, `genesis/testnet_genesis.json`. `None` on the
account gate is closed at every height, and the root formula is byte-for-byte an
un-upgraded node's.

The runbook's **proposed, NOT APPROVED** pair
(`docs/operations/ACCOUNT-ROOT-ACTIVATION.md:170`) is journal `14,200,000`,
account `14,700,000`, a gap of 500,000 blocks, stated against a chain height of
12,920,593 measured 2026-09-17. The live height is 12,970,099 today, so **every
day-count in that document must be recomputed at the moment of decision** — at
the measured 57,400 blocks/day, not at `block_time_ms`.

### 7.1 There are two invariants, at two layers

**(a) The loader's, weak form** — `ChainParams::validate`
(`crates/genesis/src/lib.rs:1515`, the `match` at `:1551`):

```
application_journal_enabled_from_height <= account_root_enabled_from_height
```

| pair | outcome |
|---|---|
| `(_, None)` | ok — the dormant default asks nothing |
| `(None, Some(a))` | `GenesisError::AccountRootWithoutJournalGate` |
| `(Some(j), Some(a))`, `j > a` | `GenesisError::JournalGateAfterAccountRoot` |
| otherwise | ok |

The rejection of `(None, Some(a))` is the subtle one, and the source says why
(`:1538-1545`): `None` is **not** "always on" — it means OBSERVED FROM CHAIN,
each node's boundary being its own first journalled height. That is fine for
node-local undo metadata and **not fine once consensus output depends on it**:
two validators would hold different boundaries and find out at a reorg. Opening
the account commitment therefore forces the journal boundary to be
CHAIN-DEFINED, written in the same genesis document, covered by the same genesis
identity, and read the same way by every validator.

It is a **load-time** check, so an inconsistent pair is refused before a block
executes rather than at the boundary 100,000 blocks later.

**(b) The account-commitment side, strict form** —
`crates/state/src/account_root.rs:320 validate_account_root_activation`, which
owns the two invariants the genesis crate cannot express because its constants
live in `sumchain-storage`:

- `account > LEGACY_ROOT_COMPATIBILITY_HEIGHT` (**496,720**,
  `crates/storage/src/candidate.rs:437`), else
  `AccountRootActivationInsideLegacyWindow`. At or below that height
  `accept_imported` *adopts* a mismatching header root, so an activation inside
  the window produces exactly the silent split the commitment exists to prevent.
- the journal gate must be `Some(j)`, else
  `AccountRootActivationWithoutPinnedJournal`.
- **`account − j >= UNDO_RETENTION_FLOOR` (4,096)**, saturating so that a journal
  above the account height reports the same failure rather than underflowing
  into success, else `AccountRootActivationOutrunsJournal`. A reorg at the
  activation height can walk `MAX_REORG_WALK` back, so records must already
  exist that far below.

**One entry point for both a new and a restarted chain:**
`account_root.rs:308 validate_runtime_activation` = `params.validate()` then
`validate_account_root_activation`, called from `StateManager::init_from_genesis`
**and** `Node::new` (`crates/node/src/node.rs:180`). Previously the two paths
enforced different rules: a new chain checked the window and horizon, a restarted
one did not.

### 7.2 Tests

```
$ cargo test --release -p sumchain-state --test runtime_activation
test result: ok. 7 passed; 0 failed

$ cargo test --release -p sumchain-genesis
activation_digest: 17 passed; lib: 15 passed; gate tests: 2 passed; 0 failed
```

- `account_state_root.rs:884 the_account_gate_requires_a_pinned_journal_gate_far_enough_below_it`
  — the boundary arithmetic exactly: with `account = 13_800_000`, journals at
  `{account, account−1, account−4095}` are **refused**; `{account−4096,
  account−4097, 0}` are **accepted**. Exactly one horizon below is the first
  sound pair.
- `runtime_activation.rs:47 each_invalid_pair_is_refused_with_its_own_error_identity`
  — pins **which layer** names each fault, by error identity rather than by
  "it failed".
- `runtime_activation.rs:93 the_shared_validator_reports_the_ordering_fault_before_the_window_fault`
  — a pair wrong in two ways names the actionable one first.
- `runtime_activation.rs:136 nothing_that_processes_a_block_is_built_before_activation_is_validated`
  — a **source-level** test reading `node.rs` and requiring
  `validate_runtime_activation` to precede `StateManager::new`,
  `BlockExecutor::new`, `Mempool::new` and the rest.
- `account_state_root.rs:957 an_unsound_activation_pair_fails_before_the_chain_exists`
  — a chain cannot be *created* on a bad pair, the refusal names the gate to
  pin, and the account family is left empty.
- `account_state_root.rs:645`/`:837` — the legacy-window hazard is *demonstrated*
  and then proven *unreachable*.
- `Genesis::activation_digest()` covers every gate (the coverage test reads the
  field declarations out of the source), distinguishes `None` from `Some(0)`,
  and distinguishes one height on two different gates. Served over JSON-RPC and
  compared between two servers by
  `two_nodes_with_identical_heights_serve_one_digest_and_a_one_block_difference_serves_another`.

---

## 8. Trie migration threshold, and what would monitor it

### 8.1 Where the repository states it

Two constants and one table. The constants exist so the code and the runbook
cannot drift apart:

- `crates/state/src/account_root.rs:466`
  `pub const ACCOUNT_ROW_WARN_THRESHOLD: u64 = 250_000;` — ~40 ms/block, 2.7% of
  the interval. Its comment: "Nothing is wrong at this count; what is wrong is
  nobody knowing the count is moving."
- `crates/state/src/account_root.rs:481`
  `pub const ACCOUNT_ROW_ACT_THRESHOLD: u64 = 500_000;` — ~80 ms, 5.3%. "the
  last count at which 'comfortable' and 'we have time to build the replacement'
  are both true."

The escalation table (`account_root.rs:203-210`, mirrored at
`docs/operations/ACCOUNT-ROOT-ACTIVATION.md:145-151`):

| rows | scan | share of 1,506 ms | action |
|---:|---:|---:|---|
| 250,000 | 40 ms | 2.7% | warn; track the trend weekly |
| 500,000 | 80 ms | 5.3% | design the trie replacement and its activation |
| 2,000,000 | 320 ms | 21% | the replacement must be SCHEDULED, with a height |
| 4,000,000 | 640 ms | 43% | the replacement must be ACTIVE |
| 10,000,000 | 1.62 s | 108% | the scan no longer fits inside a block interval |

### 8.2 The threshold, stated two ways

**The hard ceiling** is where the scan equals the interval: ~9.4M rows at
0.16 µs/row. The measurement in §2 puts 10M at **117%** of the interval, so it is
already past.

**The practical ceiling the repository commits to** is "a few million", with the
replacement required ACTIVE at **4,000,000 rows**.

Interpolating the measured cold-page 0.176 µs/row: 10% of the interval at ~856k
rows, 50% at ~4.28M — slightly tighter than the doc's 940k / 4.7M, which used
0.16. **That interpolation is an inference from a dev-Mac measurement, not a
production figure.**

**The replacement** is the persistent authenticated trie explicitly considered
and rejected for v1 at `account_root.rs:36-46`: O(touched · log n) per block
instead of O(n), at the cost of a storage-layout change with its own
reorg-revert, snapshot/fast-sync and activation stories. Nothing forecloses it —
the domain separator is versioned (`b"sumchain/account-state/v1"`,
`account_root.rs:275`) and a `v2` domain can replace the fold at a second, later
height.

### 8.3 What would monitor it in production

| mechanism | location | status |
|---|---|---|
| startup log + threshold evaluation | `crates/node/src/node.rs:619-643` — `warn!` at ≥ ACT, `warn!` at ≥ WARN, else `info!("Account rows: N (warn at 250000, act at 500000)")` | **exists**, fires **once per start** |
| on-demand RPC | `chain_getSyncCapability.account_rows`, `crates/rpc/src/server.rs:1608` | **exists in this tree**; **absent from the deployed binary** (§1.4) |
| Prometheus metric | `crates/rpc/src/metrics.rs` | **NONE.** No `sumchain_account_rows` or equivalent gauge exists |
| alert rule | `deploy/monitoring/prometheus.yml` | **NONE.** `rule_files: []`, `alertmanagers: []` |
| Grafana panel | `deploy/monitoring/grafana/dashboards/sumchain-overview.json` | **NONE** |

**The absence of a metric is deliberate and documented, not an oversight.**
`account_rows` *is* the O(n) scan the commitment pays for: at 10M rows producing
the number costs ~1.6 s of CPU (measured 1.765 s cold). Polling it at a 15 s
scrape interval would add a full account scan to every node every 15 seconds.
The runbook (`ACCOUNT-ROOT-ACTIVATION.md:153-163`) prescribes instead: once at
startup in the log; for a running node, read at most every 15 minutes, from one
node rather than all of them, and alert on the thresholds.

**That alerting is described and not implemented.** There is no rule file, no
exporter, no scrape job for it anywhere in this repository. It is operator
action, not shipped configuration, and the release should say so rather than
point at the runbook table as though it were wired.

### 8.4 Two coverage gaps found while establishing this

Both verified by grep, both recorded as risk rather than as failures:

1. **No test exercises the node-startup threshold branch.**
   `ACCOUNT_ROW_WARN_THRESHOLD` and `ACCOUNT_ROW_ACT_THRESHOLD` appear only in
   `account_root.rs` (definition) and `node.rs` (use) — **zero test
   references.** The constants' values are pinned by nothing; changing 250,000
   to 250,000,000 would turn no test red.
2. **No test exercises `SyncCapabilityInfo.account_rows` at the RPC surface.**
   `account_rows` appears in `server.rs` and `types.rs` and in no test. By
   contrast `state_history_floor` **is** surface-tested
   (`the_advertised_floor_and_the_enforced_floor_are_the_same_number`). Since the
   runbook makes reading `chain_getSyncCapability.account_rows` Sequence step 0 —
   a prerequisite for scheduling the activation at all — **the one number the
   whole activation is blocked on is served by an untested field.**

---

## Consolidated test runs

| suite | result |
|---|---|
| `sumchain-state --test account_state_root` (`--nocapture --test-threads=1`) | **19 passed, 0 failed** |
| same, `ACCOUNT_ROOT_COST_ACCOUNTS=1000000` + eviction | **1 passed** |
| same, `ACCOUNT_ROOT_COST_ACCOUNTS=10000000` + eviction | **1 passed** |
| `sumchain-state --test snapshot_commitment` | **24 passed, 0 failed** |
| `sumchain-state --test runtime_activation` | **7 passed, 0 failed** |
| `sumchain-consensus --test reorg_execution` (3 filtered) | **3 passed, 0 failed** |
| `sumchain-rpc --test operator_visible_activation_and_history` | **12 passed, 0 failed** |
| `sumchain-genesis` (activation_digest + lib gate tests) | **17 + 15 + 2 passed, 0 failed** |

**101 tests, 0 failures.** All under `CARGO_INCREMENTAL=0` and the single
isolated `CARGO_TARGET_DIR`.

---

## What remains UNPROVEN

| # | gap | what would settle it |
|---|---|---|
| 1 | **The production stored-row count.** `≥ 18` — and that `18` is the *value-holding account* count, a LOWER BOUND, **not a row count** (§1.2). Upper bound unknown. No database on this machine; no docker; the public mainnet RPC answers -32601 for `chain_getSyncCapability`, reproduced live today | **§1.5 states this as a contract**: the instrument, the endpoint requirement, both command forms, the expected output, the four things recorded alongside it (height, UTC timestamp, node identity + commit SHA, data-directory identity), the measurement-validity rule, and the acceptance threshold that decides whether the activation is schedulable at all |
| 2 | **Production hardware cost.** Every timing is a dev Mac, not a validator | Re-run `the_cost_of_the_account_commitment_with_a_cold_cache` at the measured production row count on a validator host |
| 3 | **Truly-cold device reads.** Eviction is 24 GiB of ballast pressure, not a proven page drop; the cold-page figures are lower bounds | No portable fix on macOS; measure on the Linux validator host, where the page cache can be dropped |
| 4 | **Key distribution.** All benchmark rows are synthetic addresses; SST layout and compression under production keys is unmeasured | Re-run against a copy of the production account family |
| 5 | **The 100k cold-block-cache 2x discrepancy** (§2.1) | Repeat runs with variance collected at that one point |
| 6 | **Whether the threshold constants are the right ones** — nothing tests them (§8.4) | A test asserting the node's startup branch selects on those constants, plus a surface test for `account_rows` |
