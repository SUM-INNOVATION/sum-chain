# Journal operational evidence

The operational half of `docs/lane-a/JOURNAL-CONTRACT.md`: what an operator can
actually do with the application journal today, what is wired and what is only
written down, and where the documentation and the shipped binary disagree.

Every claim below is either a command's real output or is marked UNPROVEN with
what would settle it.

---

## 0. One naming fact first, because it affects every command here

**The shipped binary is `sumchain`, not `sum-node`.**
`crates/node/Cargo.toml:9-11` declares `[[bin]] name = "sumchain"`.

`docs/lane-a/JOURNAL-CONTRACT.md` writes `sum-node rollback` and
`sum-node set-disk-budget` in three places, and the same spelling appears in
code comments at `crates/consensus/src/poa.rs:467,498`.
**Those commands as written do not exist.** `grep -rn 'sum-node' --include='*.rs'
--include='*.sh' --include='*.toml'` returns only comments and doc strings,
never a binary target.

An operator following the contract verbatim during an incident gets
`command not found`. Recorded here rather than silently corrected, because the
fix belongs in the contract and in the two comments, not in this evidence file.

---

## 1. Production pruning: DISABLED, and nothing constructs a Pruner

### 1.1 The claim, verified independently

```
$ grep -rn 'Pruner' crates/node/src
(exit 1, no output)
```

Widened to the whole tree, every `Pruner::new` site:

```
crates/consensus/tests/reorg_execution.rs:3875            (test)
crates/consensus/tests/reorg_execution.rs:4954            (test)
crates/storage/tests/application_journal.rs:1442          (test)
crates/node/tests/unit/node_activation_boot_tests.rs:785  (test)
crates/storage/src/pruner.rs:591,601,611,630,678,700,713,728
```

The `pruner.rs` sites are all inside its own `#[cfg(test)]` module —
`grep -n '#\[cfg(test)\]' crates/storage/src/pruner.rs` → `535`, and every site
listed is above 535.

Every `.prune()` call: `reorg_execution.rs:3885,4968`, `pruner.rs:640,688`,
`node_activation_boot_tests.rs:808`. All tests.

**VERDICT: zero non-test construction sites** across `crates/`, `scripts/`,
`tools/`, `deploy/`, `configs/`, `sdk/`, `examples/`, `explorer/`, `website/`,
`genesis/`, `Dockerfile`, `docker-compose.yaml`. No loop calls `prune`.
`PrunerConfig::enabled` defaults to `false` (`crates/storage/src/pruner.rs:196`).
**The prior work's claim holds.**

### 1.2 One correction to how that claim is usually phrased

"Nothing in `crates/node` constructs a Pruner" is true of the **struct**. But
`crates/node` **does** use the `pruner` module in production code:

- `crates/node/src/main.rs:1003` — `pruner::record_disk_budget(&db, bytes)`
- `crates/node/src/main.rs:1005,1014-1015` — `pruner::CapacityGuard::new`,
  `CAPACITY_WARN_PERCENT`, `CAPACITY_STOP_PERCENT`
- `crates/node/src/node.rs:519` — `pruner::UNDO_RETENTION_FLOOR`

So the module is live; the pruning is not.

### 1.3 The real production caller: there isn't one for pruning

The only production consumer of `pruner.rs` is the **capacity brake**, in block
production at `crates/consensus/src/poa.rs:477`:

```rust
match self.capacity.assess_db(&self.db) {
    Healthy => {}
    Warn { used, budget } => warn!(… "at {}% of its recorded disk budget" …),
    StopProducing { used, budget } => return Err(ConsensusError::InvalidBlock(
        "refusing to produce a block at height {height}: … at or above the 95%
         stop threshold. Pruning is disabled in this build … Producing is braked
         and importing is not, so this delays exhaustion rather than preventing
         it")),
}
```

80% warn, 95% stop-producing (`pruner.rs:81,85`). The budget is **opt-in**;
absent, it is unbounded and the brake never fires.

The error message's own last clause is the honest summary: **producing is braked
and importing is not, so this delays exhaustion rather than preventing it.**

### 1.4 The config keys are dead

```
configs/bft-config.toml:63  # Enable state pruning (keep only recent states)
configs/bft-config.toml:64  enable_pruning = false
configs/bft-config.toml:66  # How many historical states to keep if pruning is enabled
configs/bft-config.toml:67  pruning_history = 256
```

`grep -rn 'enable_pruning\|pruning_history' --include='*.rs' --include='*.toml'
--include='*.sh' .` returns **only those two lines**. No Rust reader exists.
`crates/node/src/config.rs`'s `NodeConfig` (lines 13-300) has
`node`/`consensus`/`network`/`rpc`/`health`/`logging` sections and **no pruning
field at all**, so the keys would be ignored even if that file were loaded. The
root `config.toml` has no pruning key; `deploy/` has none.

**Inference, not verified by execution:** an operator reading
`configs/bft-config.toml` would reasonably believe pruning is a supported
toggle. Setting `enable_pruning = true` there changes nothing, silently. That is
a documentation-shaped hazard in a configuration file, and it should either be
removed or given a reader.

---

## 2. Disk growth with pruning disabled

### 2.1 Measurement: it exists, and it is real rather than extrapolated from layout

```
$ CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<isolated> cargo test -p sumchain-consensus \
    --test reorg_execution journal_bytes_per_block_are_measured_against_real_published_blocks \
    -- --exact --nocapture

journal sizing:   0 tx ->     55 bytes, 0 entries (0 families)
journal sizing:   1 tx ->    347 bytes, 5 entries (2 families)
journal sizing:   8 tx ->    956 bytes, 12 entries (2 families)
journal sizing:  32 tx ->   3044 bytes, 36 entries (2 families)
journal sizing: fixed cost (0 tx) = 55 bytes
journal sizing: marginal cost ~87 bytes per transaction
journal sizing: a full 1000-tx block journals ~87260 bytes

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 0.58s
```

And the retained set at full production depth:

```
$ … cargo test -p sumchain-consensus --test reorg_execution \
    a_real_reorg_at_the_full_production_depth_survives_the_real_retention_floor -- --exact --nocapture

depth evidence: 4095 retained journal records total 1294020 bytes (1.2 MiB)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out; finished in 9.63s
```

### 2.2 The per-day and per-year projection exists

`docs/lane-a/JOURNAL-CONTRACT.md:1115-1137` (§12.3), computed at 43,200
blocks/day:

| load | per day | per year |
|---|---|---|
| idle | 2.3 MiB | 0.81 GiB |
| 1 tx/block | 14.3 MiB | 5.1 GiB |
| 8 tx/block | 39.4 MiB | 14.0 GiB |
| 32 tx/block | 125.4 MiB | 44.7 GiB |
| saturated (1000 tx) | 3.51 GiB | 1.25 TiB |

A provisioning table follows at `:1138-1159`. This is the **journal family
alone**, additive to blocks, transactions, receipts, indexes and legacy diffs.

**One correction the operator needs.** That table assumes 43,200 blocks/day (a
2 s interval). The measured mainnet rate is **57,524 blocks/day** (1.502 s/block
— see `docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md`), so **every figure above
is roughly 33% low for mainnet.** At 1 tx/block that is ~19 MiB/day rather than
14.3; saturated it is ~4.7 GiB/day rather than 3.51.

### 2.3 Alerting: it does not exist

Full enumeration of every Prometheus series this tree exports
(`crates/rpc/src/metrics.rs:322-378`, `to_prometheus`):

```
sumchain_uptime_seconds, sumchain_block_height, sumchain_blocks_processed_total,
sumchain_blocks_produced_total, sumchain_blocks_imported_total, sumchain_block_errors_total,
sumchain_last_block_timestamp, sumchain_txs_processed_total, sumchain_txs_received_total,
sumchain_txs_submitted_total, sumchain_tx_validation_errors_total, sumchain_tx_execution_errors_total,
sumchain_peer_count, sumchain_peers_connected_total, sumchain_peers_disconnected_total,
sumchain_p2p_messages_received_total, sumchain_p2p_messages_sent_total,
sumchain_rpc_requests_total, sumchain_rpc_requests_success_total, sumchain_rpc_requests_failed_total,
sumchain_rpc_rate_limited_total, sumchain_rpc_unauthorized_total,
sumchain_mempool_size, sumchain_mempool_txs_added_total, sumchain_mempool_txs_removed_total,
sumchain_mempool_txs_rejected_total
```

```
$ grep -rni 'disk\|journal\|db_size\|storage_bytes' crates/rpc/src/metrics.rs crates/rpc/src/health.rs
(no output)

$ grep -rni 'alert\|disk\|journal' deploy/monitoring/prometheus.yml \
    deploy/monitoring/grafana/dashboards/sumchain-overview.json
deploy/monitoring/prometheus.yml:6:alerting:
deploy/monitoring/prometheus.yml:7:  alertmanagers: []
```

**No alert rule files exist anywhere. No Grafana panel shows disk.**

`Database::approximate_size` (`crates/storage/src/db.rs:1062`) has no RPC and no
metric exposure — its callers are `pruner.rs:156,259,274,317,464` and
`crates/node/src/main.rs:630,636,1004`. The only way an operator reads it is by
**stopping the node** and running `sumchain set-disk-budget`.

### 2.4 So, precisely, about §12.6 of the contract

`JOURNAL-CONTRACT.md:1197-1225` presents a table of "alert thresholds" naming
three signals: journal bytes on disk, usable reorg depth, and record count
against head height.

**None of the three is a metric.**

| signal | how it is actually reachable |
|---|---|
| journal bytes on disk | a stop-the-node CLI invocation, and nothing else |
| usable reorg depth | a one-shot `info!`/`warn!` log line at boot (`crates/node/src/node.rs:513-521`) plus the `chain_getSyncCapability` RPC (`crates/rpc/src/api.rs:605`, `crates/rpc/src/server.rs:1601`) |
| record count vs head height | **no reader at all** |

The only automated action anywhere in this area is the in-process 80%/95%
capacity brake (§1.3), which logs through `tracing` and never reaches
Prometheus.

A release document that points at §12.6 as though those thresholds were wired
would be wrong. They are a specification for monitoring, not monitoring.

**UNPROVEN:** whether any out-of-repo monitoring (node_exporter filesystem
metrics, Kubernetes PVC alerts) covers disk growth. *What would settle it:* an
alert rule or a scrape config in `deploy/` referencing filesystem usage. Neither
exists — `find deploy/monitoring -type f` returns 4 files, all enumerated above,
and `alertmanagers: []`.

---

## 3. The `rollback` CLI, end to end

**Invoked as `sumchain rollback`** (the contract says `sum-node rollback`; §0).

### 3.1 Surface

`crates/node/src/main.rs:220-250`:

| flag | default | meaning |
|---|---|---|
| `-d, --data-dir` | `data` | the database to rewrite |
| `--to-height` | *required* | the target tip |
| `--max-blocks` | `10` | per-invocation depth limit |
| `--genesis` | none | resolve the activation boundary from a genesis file rather than from the database |
| `--yes` | false | skip the confirmation prompt |

### 3.2 Sequence

`crates/node/src/main.rs:843-999`:

1. `:876` — opens the DB, then runs **the same downgrade gate the node runs at
   boot**, `journal::validate_startup(&db)`. The comment at `:871-874`: *"An
   operator tool that REWRITES state must not run against journal history this
   binary cannot read."*
2. `:882-905` — resolves the activation boundary. With `--genesis`, from
   `params.application_journal_enabled_from_height`; without it, **OBSERVED from
   the database**, and it prints a `NOTE:` telling the operator to pass
   `--genesis` on a chain that pins the height.
3. `:913-921` — if a restore floor row exists, prints: *"this database was
   populated by a snapshot restore or fast sync at height {floor}. It holds NO
   undo records at or below that height … nothing below {floor+1} can be rolled
   back here, and this tool will refuse to try."*
4. `:936` — `plan_rollback(&block_store, to_height, max_blocks, &journals.activation())`.
   **Planning writes nothing.**
5. `:941-963` — prints depth, data dir, current tip, target tip and hash, the
   undo boundary and usable depth, then the three things the batch will do, then
   *"An interruption leaves either the old tip or the target, never a
   half-rolled-back chain"*, then *"The node must be stopped before running this
   command"*, then prompts for a literal `yes` unless `--yes`.
6. `:976` — `execute_rollback(&db, &state, &plan, &journals, journals.policy())`.
7. `:979-997` — prints `Rollback complete.`, the new tip and hash,
   `Unwound N block(s), replaying M record(s) with K current-value check(s)`,
   and — if `report.tolerated_absences > 0` — a WARNING that those blocks'
   effects were **NOT reverted and remain applied**, which is only possible
   below the activation boundary. Ends with `Start the node to resume block
   production.`

### 3.3 What it refuses

`crates/consensus/src/reorg.rs:580-632`, `plan_rollback`:

| condition | message |
|---|---|
| `:591` no recorded height | "cannot roll back a database with no recorded height" |
| `:596` `to_height >= current` | "target height {t} must be strictly below the current tip {c}" |
| `:602` `depth > max_depth` | "refusing to roll back {depth} block(s): the limit for this invocation is {max_depth}" |
| `:608` no block at target | "no block at target height {t}" |
| `:613` gap in range | "no block at height {h}; the rollback range has a gap, and unwinding across one would leave the missing block's rows applied" |
| `:624-631` | `refuse_beyond_undo_history(…)` — the same predicate the reorg path uses, reconstructing the rollback as a `ReorgPlan` with an empty adopted branch |

### 3.4 What it writes — one batch

`crates/consensus/src/reorg.rs:649-687`, `execute_rollback`:

- `:658` `stage_branch_unwind(…)` — the reorg path's own unwind: per-block
  journal classification, missing-record halt, activation checkpoint,
  current-value validation, journal deletion;
- `:661-663` `stage_deindex` plus `batch.delete(cf::BLOCKS, hash)` per abandoned
  block — **block rows are deleted here**, which differs from a reorg, where they
  are kept;
- `:664` `stage_head_reset(&plan.target)`;
- `:669-683` **finality pull-back**: if `finalized > target.height()`, rewrites
  `meta_keys::FINALIZED_HEIGHT` and `FINALIZED_HASH` to the target **in the same
  batch**;
- `:685` `batch.commit()`, then `:687` `state.set_state_root(…)` **only after**
  the commit.

### 3.5 A finding worth stating plainly

**`plan_rollback` does not refuse to cross the finalized height. It silently
pulls finality back to the target.** `plan_reorg` *does* refuse (§4).

So the operator CLI is the one path in the system that can rewrite finalized
history. That is deliberate — the doc comment at `reorg.rs:663-668` argues
"Finality cannot outlive the tip" — but it means **finality is an absolute floor
for the reorg path and not for the rollback tool**, and an operator reading
"finalized" as "cannot be undone" would be wrong about this one command.

### 3.6 Tests

```
$ cargo test -p sumchain-consensus --test reorg_execution rollback
test a_rollback_restores_every_family_the_legacy_diffs_never_covered ... ok
test an_interrupted_rollback_leaves_the_old_tip_untouched ... ok
test a_rollback_across_the_activation_checkpoint_is_refused ... ok
test a_rollback_refuses_a_bad_target_a_deep_range_and_a_gap ... ok
test a_rollback_restores_accounts_contracts_supply_and_an_indexed_subsystem ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 54 filtered out; finished in 0.27s

$ cargo test -p sumchain-state --test application_journal \
    the_legacy_revert_path_has_no_production_caller_and_the_rollback_cli_has_its_own
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.04s
```

The second (`crates/state/tests/application_journal.rs:387`) is a
source-scanning guard. Its own doc at `:374-386` records that the CLI *used to*
walk the tip down over `cf::STATE_DIFFS`, reverting account rows only — a real
under-revert above the activation height.

**UNPROVEN: no test drives the `sumchain` binary itself.** Argument parsing, the
`NOTE:` lines, the confirmation prompt and the printed report are all uncovered.
The comment at `main.rs:865-867` concedes exactly this — *"a correctness-critical
unwind only a binary can reach is one no test can reach either"* — which is why
the logic was moved into `crates/consensus`. *What would settle it:* an
integration test invoking the built binary (`assert_cmd` or equivalent) against
a temporary data directory.

---

## 4. Checkpoint and finality

Two distinct floors, both enforced at **plan** time.

### 4.1 Finality

- `finality_depth` blocks behind the head. **Code default 3**
  (`crates/genesis/src/lib.rs:1135-1137`); **deployed mainnet value 6**,
  confirmed live (`chain_getChainParams` → `"finality_depth": 6`) and matching
  the committed `genesis.json`. Probabilistic, per `crates/consensus/src/lib.rs:10,24`.
- Enforced at `crates/consensus/src/reorg.rs:238-241` (abandoned walk),
  `:264-267` (adopted walk), `:283-286` (fork point):

```rust
if height.saturating_sub(1) < finalized_height {
    "reorg would unwind block {height} at or below the finalized height
     {finalized_height}; refusing to abandon finalized history"
}
…
if ancestor.height() < finalized_height {
    "reorg forks at block {} below the finalized height {finalized_height}"
}
```

- Persisted in `cf::META` under `meta_keys::FINALIZED_HEIGHT` / `FINALIZED_HASH`;
  restored at boot at `crates/consensus/src/poa.rs:349-356`.
- Test: `crates/consensus/src/reorg.rs:815-831 a_reorg_below_finality_is_refused`.

**Caveat, repeated because it is the one thing here that surprises:**
`execute_rollback` pulls finality *back* rather than refusing (§3.5).

### 4.2 The activation checkpoint

The harder floor. See §7.

---

## 5. Snapshot history-floor behaviour

### 5.1 What the row is

One `cf::META` row under
`UNDO_HISTORY_FLOOR_META_KEY = b"application_journal/undo_history_floor"`
(`crates/storage/src/journal.rs:861`), holding the height a snapshot left the
database at.

Accessors: `undo_history_floor(db)` `:864`, `record_undo_history_floor(db, h)`
`:892`, `stage_undo_history_floor(db, batch, h)` `:927`. **Monotone** — a later
restore may raise it, never lower it (`:921`).

### 5.2 It used to be two rows. It is one now.

`snapshot/imported_at` was a second key with its own encoding and its own
last-write-wins rule. It is gone: `crates/storage/src/snapshot_meta.rs` **no
longer exists**, and `crates/state/src/snapshot.rs:196` re-exports the surviving
key under the old name:

```rust
pub use sumchain_storage::journal::UNDO_HISTORY_FLOOR_META_KEY as SNAPSHOT_IMPORT_META_KEY;
```

So the collapse `JOURNAL-CONTRACT.md` §13.2 (`:1304-1355`) describes as pending
is **done**.

### 5.3 How a restore sets it — staged, not written afterwards

`crates/storage/src/schema.rs:359-399`,
`StateStore::import_accounts(rows, undo_history_floor)`:

```rust
if !staged_floor {
    crate::journal::stage_undo_history_floor(self.db, &mut batch, undo_history_floor)?;
    staged_floor = true;
}
```

The floor goes into the **first** chunked batch (10,000 accounts per chunk,
`:363`), with the first rows. The reason is in the doc comment at `:322-357`: a
crash between "rows written" and "floor recorded" leaves restored state at height
`h` with the boundary reading as unestablished and the planner offering its full
horizon — *"the import 'succeeded' and nothing is left to notice."*

The only caller is `crates/state/src/snapshot.rs:477`, and the comment at `:475`
records that the caller deliberately does not get to choose the order.

### 5.4 What a caller sees below the floor

1. `JournalActivation::resolve` raises the boundary to `floor + 1`, taking the
   higher of that and any configured height.
2. A reorg deeper than the usable depth is refused **at plan time** —
   `crates/consensus/src/reorg.rs:129-167 refuse_beyond_undo_history`, message at
   `:150-164`: *"refusing a {n}-block switch: this node holds undo history for
   only {u} block(s) below its head at {h}. The application journal is
   node-local … a node restored from a snapshot or fast sync arrives with
   canonical state and no undo records at all, and rebuilds them only by
   publishing blocks itself … the retention floor is a promise not to discard
   undo history, never a claim to hold it."*
3. At boot the node warns — `crates/node/src/node.rs:513-521`: *"This node was
   seeded from a snapshot at height {h}. It holds NO undo records at or below
   that height: usable reorg depth is {d} of 4096, and historical state below
   {h} is unavailable and must not be served."*
4. `chain_getSyncCapability` serves the same on demand (`crates/rpc/src/api.rs:605`,
   `crates/rpc/src/server.rs:1601-1606`) — **on a node running this tree's
   binary; mainnet answers -32601 for that method today.**
5. The rollback CLI prints the `NOTE:` at `crates/node/src/main.rs:913-921` and
   then refuses via (2).

### 5.5 Tests

```
$ cargo test -p sumchain-storage --test application_journal
test the_restore_floor_and_the_restored_state_commit_or_fail_together ... ok
test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 16.36s
```

Relevant names in that 32: `a_restore_floor_raises_the_activation_boundary`,
`a_node_that_was_never_restored_is_unaffected_by_the_floor`,
`a_restored_node_rebuilds_its_usable_depth_one_published_block_at_a_time`,
`one_row_records_the_history_floor_and_the_retired_key_is_gone`,
`the_restore_floor_and_the_restored_state_commit_or_fail_together`.

**Doc drift found:** `JOURNAL-CONTRACT.md:1308` names the fourth of those
`producer/one_row_records_the_history_floor_under_every_name_that_reaches_it`.
The shipped name is `one_row_records_the_history_floor_and_the_retired_key_is_gone`.
The contract is stale on that one test name.

Consumer side:

```
$ cargo test -p sumchain-consensus --test reorg_execution -- restore snapshot undo_history
test a_restored_nodes_usable_depth_rebuilds_one_block_at_a_time ... ok
test a_snapshot_restored_node_refuses_a_switch_below_its_restore_point ... ok
test a_switch_deeper_than_this_nodes_undo_history_is_refused_at_plan_time ... ok
test unwinding_a_branch_restores_the_fork_point_byte_for_byte ... ok
test a_rollback_restores_accounts_contracts_supply_and_an_indexed_subsystem ... ok
test a_rollback_restores_every_family_the_legacy_diffs_never_covered ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 53 filtered out; finished in 0.37s
```

---

## 6. Downgrade refusal

### 6.1 The gate

`journal::validate_startup(db)` — `crates/storage/src/journal.rs:1050-1072`.
`refuse_downgrade` is the same function under its former name (`:809-810`).

```rust
pub fn validate_startup(db: &Database) -> Result<JournalFormatState> {
    let state = JournalFormatState {
        binary_version:     FORMAT_VERSION_V1,
        persisted:          persisted_format_high_water(db)?,   // the 2-byte META stamp
        scanned:            highest_stored_format_version(db)?, // exact scan over records
        observed_boundary:  lowest_journal_height(db)?,
        undo_history_floor: undo_history_floor(db)?,
    };
    if let Some(v) = state.effective_high_water() {   // the HIGHER of stamp and scan
        if v > FORMAT_VERSION_V1 { return Err(invalid(…)) }
    }
    Ok(state)
}
```

### 6.2 What the operator sees

`journal.rs:1060-1070`, verbatim:

> "this database holds application journals in record format version {v}
> (stamped: {..}, present in records: {..}), and this binary implements version
> {FORMAT_VERSION_V1}. It cannot revert a block written by the newer binary, so
> it refuses to start rather than discovering that during a reorg. Downgrading a
> node that has published under a newer record format is prohibited; recover by
> running the newer binary, or by resyncing this node from an empty database."

### 6.3 Where it is called in production

`crates/node/src/node.rs:183-193`, immediately after `Database::open_default`,
**before** the `StateManager`, consensus, RPC or messaging backfill exist. The
failure fails startup. Also `crates/node/src/main.rs:876` for the rollback CLI
(§3.2 step 1).

### 6.4 Why two watermarks

The stamp survives pruning (`journal.rs:837,861`); the scan does not. With
pruning off today the scan alone would suffice — the stamp is what keeps the
gate honest **if pruning is ever enabled**, which is the relevant interaction
between §1 and this section.

### 6.5 The scope limit, stated rather than implied

`JOURNAL-CONTRACT.md:800-811` records it and it is true: the stamp is an opaque
2-byte `META` row with no magic and nothing self-describing. **A binary
predating the journal entirely will not look for `FORMAT_HIGH_WATER_META_KEY` or
`cf::APPLICATION_JOURNAL` and is NOT caught.** The refusal only fires on a
binary new enough to contain the gate and old enough not to implement the format
it finds.

### 6.6 Tests

All inside the 32-pass run in §5.5:

```
a_binary_refuses_to_start_against_a_newer_record_format
the_format_watermark_survives_pruning_away_every_record
the_format_watermark_is_opaque_to_a_binary_that_does_not_look_for_it
a_database_with_no_journal_history_starts_and_requires_nothing
the_supported_upgrade_and_rollback_procedure_walked_in_order
```

The last (`crates/storage/tests/application_journal.rs:1113`) walks all four
steps of the upgrade/rollback procedure in order on real databases: upgrading
onto pre-journal history is fine; rolling back **before** the first publish is
supported; the first publish closes that window permanently; pruning does not
reopen it.

---

## 7. Cross-activation reorg policy

### 7.1 The rule

A branch that reaches **below** the activation boundary while also holding
blocks **at or above** it is refused **whole**, before a single row is read or
staged — `sumchain_state::reorg_undo::UndoRefusal::CrossesActivationCheckpoint`.
Enforced by `crosses_activation_checkpoint`, called **first** in
`stage_branch_unwind` so no unwind can reach around it.
Contract §7.3, `JOURNAL-CONTRACT.md:617-694`.

### 7.2 Why a checkpoint and not a backfill

`:645-660`: a generic journal is the set of pre-images captured by the overlay
while a block executed. For a pre-upgrade block they were never captured.
Reconstructing one requires re-executing that block **from the state you would
need the backfill to reach** — circular. The only non-circular route is a
resync, and a resynced node's journal starts at the bottom of its chain, so it
has no boundary to cross.

### 7.3 Why the earlier behaviour was wrong

`:629-641`: per-block classification answers *which record governs this block*;
it cannot answer *what restores the families no record covers*. Below the
boundary the only records are the four legacy per-subsystem journals, and
`cf::SUPPLY` is restorable from **none** of them. The old code unwound upper
blocks completely and lower blocks partially, committed both in one batch, moved
the head, and returned success — leaving rows applied under a chain that no
longer contained the blocks that wrote them. Silently.

### 7.4 It is self-extinguishing

`:662-668`: `plan_reorg` bounds the abandoned branch at `MAX_REORG_WALK = 4_096`.
Once the head is 4,096 past the boundary the checkpoint cannot refuse anything.
Finality shortens the window further.

### 7.5 The cost inside the window, stated plainly

`:670-676`: a deep reorg across the upgrade height is refused, the node stops
following the canonical chain, and **the operator's recovery is a resync.** A
bounded availability cost, deliberately traded against an unbounded correctness
cost. A reorg wholly below the boundary is not a crossing and is untouched.

### 7.6 Tests

```
$ cargo test -p sumchain-consensus --test reorg_execution -- crossing checkpoint
test the_checkpoint_stops_binding_once_the_head_outruns_the_engine_walk_limit ... ok
test a_reorg_crossing_the_journal_activation_boundary_is_refused_whole ... ok
test the_advertised_reorg_depth_is_the_depth_the_checkpoint_actually_allows ... ok
test a_reorg_wholly_below_the_boundary_is_not_a_crossing ... ok
test a_rollback_across_the_activation_checkpoint_is_refused ... ok
test a_reorg_crossing_the_checkpoint_is_refused_by_the_real_reorg_driver ... ok
test a_reorg_crossing_an_activation_boundary_reproduces_both_sides ... ok
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 52 filtered out; finished in 1.62s

$ cargo test -p sumchain-consensus --test journal_activation_e2e
test a_coordinated_activation_pair_is_accepted_by_the_authoritative_loader ... ok
test a_crossing_reorg_is_refused_through_import_block ... ok
test a_pinned_activation_height_is_accepted_and_journals_are_written_from_it ... ok
test a_node_at_its_disk_budget_refuses_to_produce_and_says_why ... ok
test the_pinned_height_decides_whether_a_reorg_halts_or_falls_back ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.41s
```

`a_crossing_reorg_is_refused_through_import_block` is the strongest: the branch
arrives over `PoAEngine::import_block`, fork choice picks it, and the switch is
refused with the node still on its original branch and the canonical height
index still naming its own block.

---

## 8. Issue #253: real-journal evidence

### 8.1 The probe

`crates/consensus/tests/fork_reachability.rs:747-782`,
`reorged_node_must_converge_with_the_chain_it_adopted_issue_253`. Its sibling is
`depth1_sibling_import_reaches_the_reorg_path` at `:598`; both share one helper,
`run_probe()` at `:367`. Neither is `#[ignore]`d any more — `:50-51`: *"the
second was, for as long as it described a defect rather than a property."*

### 8.2 The run

```
$ CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<isolated> cargo test -p sumchain-consensus \
    --test fork_reachability reorged_node_must_converge_with_the_chain_it_adopted_issue_253 \
    -- --exact --nocapture

─── issue #253 fork-reachability probe ───
genesis (common ancestor):   0x41189f7e3cdce90fb250662173808c55c04ddd653b843904e06306f3d55add34
A head @1:                   0x42b61bd1c387ae71ecc48e74ccc9772eabeeb2ea5baf5effbcbc1797403bc9cb   state_root=0x8b387f54...
B sibling @1:                0x0a2af0e77b239e864d09d0bfa0528129bf2026f501320829a018d756ca929837   state_root=0x84a1a912...   (fee_b=21, attempts=2)
state root at genesis:       0x488952b491143422b1a1eaf72a73ca2a0894efb40d07d68f5b76dab98cc2ae49
fork choice wants to switch: true (hash(B) < hash(A))
import B into A returned:    Ok(())
CLASSIFIED OUTCOME:          ReorgRan
Reorg event observed:        true (depth=Some(1))
BlockImported observed:      true
A head after import:         0x0a2af0e77b239e864d09d0bfa0528129bf2026f501320829a018d756ca929837
STATE_DIFFS[1] before:       191 bytes, addrs=Some({"9coyt...", "LLnnf...", "LMwhZ..."})
STATE_DIFFS[1] after:        0 bytes, addrs=None
STATE_DIFFS[1] changed:      true
B's block touches:           {"2dSmE...", "5r1bV...", "9coyt..."}
A's block alone touches:     {"LLnnf...", "LMwhZ..."}
A pre-import vs A post-import (5):
      2dSmEkXmooZjc7J7vA4guDipoxCgnKjrb: None vs Some((2000, 0))
      5r1bV4g4xdCC2djnJ9Wyt3eqahqRLu2Y8: Some((10000000, 0)) vs Some((9997979, 1))
      9coytFCY6Btd2ZVgxCL199Bcqkxkwn5KU: Some((100000010, 0)) vs Some((100000021, 0))
      LLnnfeZXXikuXZTBCPss3py1mpjYXKGVS: Some((9998990, 1)) vs Some((10000000, 0))
      LMwhZm2tiHReA9G37XwreM4j7vLysmaEo: Some((1000, 0)) vs None
A post-import vs B (0) -- same head, different state:
      (none)
──────────────────────────────────────────

test reorged_node_must_converge_with_the_chain_it_adopted_issue_253 ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.78s
```

### 8.3 Is the journal real or synthetic? REAL.

`run_probe` builds the chain with `ChainParams::default()`
(`fork_reachability.rs:393`), whose `application_journal_enabled_from_height` is
`None` (`crates/genesis/src/lib.rs:1420`). With `None` the boundary is
**observed**, and node A published its genesis and its height-1 block through
`publish`, which writes a record for each — so the observed boundary is 0 and
**height 1 is in the REQUIRED region.**

The accessor at `fork_reachability.rs:171-178` reads `cf::APPLICATION_JOURNAL`
(not the legacy family) via `schema::journal_key(height, block_hash)`.

**The label `STATE_DIFFS[1]` in the printed report is a misleading leftover
name.** The value it prints is `app_journal_row_before/after` (`:475`, `:525`) —
the real `cf::APPLICATION_JOURNAL` row. The `191 bytes → 0 bytes` transition
above is a real encoded application-journal record being consumed and deleted.
Worth renaming; recorded here so nobody reading the output concludes the probe
is about the legacy diffs.

The assertions that **pin** that are in the *sibling* test, not in the 253 test
— `fork_reachability.rs:645-671`:

```rust
assert!(ev.app_journal_row_before.is_some(),
    "A must have had a generic application journal …");
assert!(ev.app_journal_row_after.is_none(),
    "the generic application-journal row for the ABANDONED block must have been
     consumed and deleted by the unwind; if it survived, the live reorg path did
     not run on the real encoded record");
```

with the comment at `:646-655`: the unwind read A's height-1 record off
`cf::APPLICATION_JOURNAL`, decoded it through `ApplicationJournal::decode_for`
(magic, format version, identity against the key, canonical order, framing),
checked every row against its 8-byte after-tag, and deleted the record in the
same batch that applied the restores. *"No oracle, no snapshot diff."*

### 8.4 What the 253 test PROVES

Two assertions, `:753-781`:

1. `ev.head_after == ev.b_hash` — A actually adopted B's block. Without this the
   test would be vacuous, and it says so.
2. `ev.divergence().is_empty()` — every row in `cf::STATE` under the `acct`
   prefix agrees between A and B. Output: **`A post-import vs B (0)`**.

Against real machinery: a real `PoAEngine::import_block`, a real `plan_reorg`, a
real encoded application-journal unwind, a real
`ConsensusEvent::Reorg { depth: 1 }`.

The two historical defects its docs record (`:706-728`) — `cf::STATE_DIFFS`
keyed by height alone so siblings collided, and the reorg arm executing the
arriving block and then *dropping* the candidate so B's state was never
committed — are both fixed, and this is the regression pin.

### 8.5 What the 253 test DOES NOT prove

Its own docs say so at `:732-746`; each was verified:

1. **It compares ACCOUNT state only** — `cf::STATE` under the `acct` prefix. Not
   every column family.
2. **`cf::SUPPLY` still diverges.** It is written by every block and journalled
   by nothing, so the unwind cannot restore it. Because
   `SupplyStore::v_state_digest` is folded into the block state root, **the
   replayed root for B's block does not equal its header's.**
3. **That mismatch is force-adopted, not refused.** Height 1 is inside the
   `height <= 496720` legacy compatibility window —
   `LEGACY_ROOT_COMPATIBILITY_HEIGHT: BlockHeight = 496_720` at
   `crates/storage/src/candidate.rs:437`, pinned as source text by
   `crates/state/tests/orchestration_shape.rs:95`. The reorg reports it as
   `ReorgOutcome::force_adopted` and the engine logs it; **nothing in this test
   fails on it.** The `import B into A returned: Ok(())` line above can only have
   come from that branch (`fork_reachability.rs:462`).
4. **Depth 1 only.** One block on each side, one fork. It says nothing about deep
   reorgs, multi-block branches, or the retention floor.
5. **It does not exercise the activation checkpoint** — the boundary is observed
   at 0, so nothing crosses it. §7 covers that separately.
6. **No pruning, no restore floor, no downgrade** are in scope.

The `cf::SUPPLY` gap is not hidden: it is a producer-side obligation measured and
pinned elsewhere, in
`crates/consensus/tests/reorg_execution.rs::the_subsystem_journals_do_not_cover_every_family_a_block_writes`.
And it is closed **above** the legacy window by
`reorg_execution.rs:6178 a_reorg_converges_account_rows_supply_rows_journals_and_the_activated_root`,
which forks above `LEGACY_ROOT_COMPATIBILITY_HEIGHT + 1` precisely so
`force_adopted` cannot absorb the disagreement, and asserts
`family(&a, cf::SUPPLY) == family(&b, cf::SUPPLY)` — see
`docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md` §6.

**So the precise statement about #253 is:** at depth 1 inside the legacy
compatibility window, account state converges and supply does not, and the
resulting root mismatch is force-adopted. Above the window, a separate test
proves both converge. The 253 probe alone does not prove the second thing, and
should not be cited as though it did.

---

## What remains UNPROVEN

| § | gap | what would settle it |
|---|---|---|
| 1 | Whether `configs/bft-config.toml`'s `enable_pruning` / `pruning_history` were ever intended to be wired | A commit or issue. The keys have no reader today and `NodeConfig` has no field for them |
| 2 | Whether disk growth is monitored out-of-repo (node_exporter, PVC alerts) | An alert rule or scrape target in `deploy/`; none exists — `deploy/monitoring` is 4 files with `alertmanagers: []` |
| 2 | Whether the §12.6 signals are *actionable* in practice | They are documented, not instrumented: signal 1 needs a stopped node, signal 2 is a boot log plus one RPC, signal 3 has no reader at all |
| 3 | The `sumchain rollback` binary path itself — argument parsing, prompts, `NOTE:` lines, printed report | An integration test invoking the built binary against a temporary data directory |
| 3 | That `execute_rollback` pulling finality back (rather than refusing) is intended release behaviour | It is coded and commented deliberately at `reorg.rs:663-683`, but no test asserts the operator is *told* finality moved |
| 8 | Convergence of `cf::SUPPLY` after a reorg **inside** the legacy window | It provably does not converge there, and the root mismatch is force-adopted. Above the window it is proven to converge |
| 0 | The binary-name discrepancy (`sum-node` in the contract and two source comments vs `sumchain` shipped) | `crates/node/Cargo.toml:10` is authoritative; every `sum-node` reference is wrong as typed |
