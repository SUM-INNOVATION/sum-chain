# Account-state commitment: activation

The block state root does not cover account balances or nonces. Two nodes can
disagree about every balance on the chain and publish identical block hashes,
and nothing built on the root — light client, fast-sync check, fraud proof — can
tell. `crates/state/tests/account_state_root.rs` reproduces that rather than
asserting it, and `account_root_enabled_from_height` is what closes it.

This document proposes the height, the paired journal height it depends on, and
how both are distributed and verified identical across validators.

**The heights below are NOT APPROVED.** They are arithmetic against a chain
height measured on 2026-09-17 and a rollout shape assumed rather than scheduled,
and they are blocked on a measurement that has not been taken — see
"Prerequisite: the stored account-row count". Nothing here is set in any
`genesis.json` in this tree, and the production default remains `None`, which is
byte-for-byte the root formula an un-upgraded node computes. Every day-count
must be recomputed from a fresh `chain_getBlockHeight` at the moment the
decision is actually made; a height that was 31 days out when this was written
is 31 days minus the delay by the time anyone acts on it.

## Measured starting point

All figures taken 2026-09-17 against live mainnet (`https://rpc.sumchain.io`,
`chain_id: 1`).

| quantity | value | how |
|---|---|---|
| chain height | 12,920,593 | `chain_getBlockHeight` |
| interval between blocks | 1,506 ms | 920,593 blocks of real history, heights 12,000,000 → 12,920,593 |
| blocks per day | 57,361 | derived from the above |
| `block_time_ms` in params | 3,000 | `chain_getChainParams` — a **proposer slot**, halved by two validators in round-robin |
| validators | 2 | `sum_getValidators` |
| accounts holding value | **18** | transaction-graph closure, cross-checked against `accounted_account_supply` to the base unit |
| **stored account rows** | **NOT MEASURED** | requires a production database; see below |
| `LEGACY_ROOT_COMPATIBILITY_HEIGHT` | 496,720 | `crates/storage/src/candidate.rs` — 12.4M blocks in the past |
| `MAX_REORG_WALK` / `UNDO_RETENTION_FLOOR` | 4,096 | `crates/consensus/src/poa.rs`, `crates/storage/src/pruner.rs` |

The 1,506 ms figure matters and is easy to get wrong. `block_time_ms` is what a
proposer waits for its own slot; with two validators alternating, blocks arrive
at half that. Every node executes every block, so the interval is the budget.

## Prerequisite: the stored account-row count

**This has not been measured, and the activation should not be scheduled until
it has been.**

The commitment folds one record per STORED ROW and its per-block cost is linear
in that count. Every count reached so far is a count of something else.

### What 18 is, and what it is not

18 accounts hold value on mainnet, enumerated by transaction-graph closure and
cross-checked against `accounted_account_supply` to the base unit. Each of the
18 holds a nonzero balance, so each is certainly a stored row: **18 ≤ rows**.
That is the entire strength of the claim.

It is not an upper bound, for two reasons that are not hypothetical:

* **Zero rows are invisible over RPC.** `get_account` flattens absence into
  `{balance: 0, nonce: 0}`, so `sum_getBalance` cannot distinguish a stored zero
  row from no row. The two cost identically to fold.
* **Rows exist at addresses no transaction index reaches.**
  `ContractExecutorState` credits the CONTRACT address on a deployment carrying
  value (`crates/state/src/contract_executor.rs`, `v_credit(view,
  &result.contract_address, …)`). A contract address is not a transaction's
  `to` field, so a recipient-index walk never sees it. The contracts gate has
  been open on mainnet since height 8,900,000.

No production database was available in the environment this work was done in,
so the count could not be taken. The instrument ships instead of the
measurement.

### The attempt, and why it failed

Recorded so this reads as a measurement that was attempted and could not be
taken, rather than one nobody tried.

Two routes exist and both were tried on 2026-09-18.

**A production database on this machine.** There is none. The filesystem holds
no SUM Chain data directory; every database this work touched was created by a
test in a temporary directory and destroyed with it. `account_row_count` was run
against synthetic databases from 18 to 10,000,000 rows, which measures the
FUNCTION, not the chain.

**The public mainnet RPC.** `https://rpc.sumchain.io` answers
`chain_getBlockHeight` (12,929,466 at 2026-09-18T09:30:53Z) and every other
method this chain has shipped, but returns `-32601 Method not found` for
`chain_getSyncCapability`. That node runs a binary predating this work, so the
row count is not reachable from it. No other endpoint exposes a state-size,
account-count or column-family statistic — that was checked across the whole RPC
surface, not assumed.

So the count stands at: **≥ 18, upper bound unknown.** It must be taken on a
node running this binary against the production database before the activation
is scheduled, and recorded as described below.

### How to take the measurement

On a node holding the production database, either read it from a running node:

```bash
curl -s https://<node>/ -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getSyncCapability","params":[]}'
```

`account_rows` in the response is the number, produced by
`sumchain_state::account_root::account_row_count` — the same scan as the
commitment, through the same prefix bound and the same stop condition, so it is
exactly what the fold will pay for and not an approximation of it. The same
value is logged at node startup.

**Record with it**: the chain height it was taken at, the wall-clock timestamp,
and which database — node identity and data directory — so the reading can be
reproduced and so two readings from two nodes can be compared. A row count
without a height is not a measurement of anything.

### What to do with it

Compare against the thresholds below and re-derive the activation timing. If the
count is within an order of magnitude of 18, the cost argument in this document
holds unchanged. If it is not, the interpolation table is what decides, and at a
few hundred thousand rows the activation becomes more urgent rather than less —
the commitment gets more expensive to adopt as the family grows, never cheaper.

## Operational threshold and alert

A threshold on the MEASURED count. There is deliberately no projection here: an
earlier draft of this document extrapolated a growth rate from 18 accounts over
the chain's whole lifetime and concluded a million accounts was tens of
thousands of years away. That figure is withdrawn. Historical usage of a chain
with 88 transactions bounds nothing about its adoption, and one integration can
add more rows in a day than this chain has produced in its life.

What can be said is narrower and more useful: the cost is linear and the input
is observable, so the ceiling is approached visibly rather than suddenly —
provided somebody is looking. This is the looking.

These two thresholds are CONSTANTS in the code —
`account_root::ACCOUNT_ROW_WARN_THRESHOLD` and `ACCOUNT_ROW_ACT_THRESHOLD` — and
a node warns on them at startup, so the number a node alerts at and the number
this table names cannot drift apart.

| rows | scan (cold) | share of 1,506 ms | action |
|-----:|------------:|------------------:|--------|
| 250,000 | 40 ms | 2.7 % | **warn** (`ACCOUNT_ROW_WARN_THRESHOLD`). Track the trend weekly. |
| 500,000 | 80 ms | 5.3 % | **act** (`ACCOUNT_ROW_ACT_THRESHOLD`). Design the trie replacement and its activation. |
| 2,000,000 | 320 ms | 21 % | The replacement must be SCHEDULED, with a height. |
| 4,000,000 | 640 ms | 43 % | The replacement must be ACTIVE. |
| 10,000,000 | 1.62 s | 108 % | The scan no longer fits inside a block interval. |

### Cadence, and why it is not a scrape

`account_rows` is an **O(n) scan** — the same scan the commitment performs once
per block. At ten million rows, producing the number costs 1.6 s of CPU. Polling
it at Prometheus scrape frequency would add a second full account scan every 15
seconds to every node, which is a meaningful fraction of the budget this alert
exists to protect.

So: a node reports the count and evaluates both thresholds **once at startup**,
in its log. For a running node, **read it at most every 15 minutes**, from one
node rather than all of them, and alert on the thresholds above. A count that moves fast enough for a
15-minute sample to miss a threshold is a count that has already crossed several,
and the response to that is not a faster poll.

## The proposal

```jsonc
// in each validator's runtime genesis.json, under "params"
"application_journal_enabled_from_height": 14200000,
"account_root_enabled_from_height":        14700000
```

| gate | height | blocks from 12,920,593 | days at 57,361/day | approximate date |
|---|---:|---:|---:|---|
| `application_journal_enabled_from_height` | 14,200,000 | 1,279,407 | 22.3 | 2026-10-09 |
| `account_root_enabled_from_height` | 14,700,000 | 1,779,407 | 31.0 | 2026-10-18 |
| gap between them | 500,000 | | 8.7 | |

### Why 14,700,000 for the account gate

**Above the legacy window, by 12.4 million blocks.** At or below
`LEGACY_ROOT_COMPATIBILITY_HEIGHT` (496,720) `accept_imported` ADOPTS a
mismatching header root instead of refusing the block. An activation inside that
window produces exactly the outcome the commitment exists to prevent: an
upgraded and an un-upgraded node computing different roots, both publishing the
proposer's, and neither able to tell. Any future height clears this trivially —
it is recorded because it is a hard constraint, now enforced by
`validate_account_root_activation` and pinned by
`an_activation_inside_the_legacy_window_is_refused`.

**31 days of lead time.** This is a two-validator PoA network with no
proposer-skip: restarting a validator stalls its slots until it rejoins
(`docs/operations/production-checklist.md`, "Restart & Rollback Coordination").
The window has to hold a binary cut, a testnet soak, the coordinated genesis
edit, two coordinated restarts, and a verification pass — with room to abort.
Thirty days is the shortest span that fits all of it without any step being
rushed, and the chain is not waiting on this: at 18 accounts the commitment
costs 4.6 µs per block, so there is no operational pressure to activate sooner.

**A round number.** 14,700,000 is read aloud between operators and typed into
two files by hand. A digit transposed in 14,683,211 is invisible; one in
14,700,000 is not.

### Why 14,200,000 for the journal gate, and why it comes first

The invariant is
`application_journal_enabled_from_height <= account_root_enabled_from_height`,
owned and checked by the journal workstream in `ChainParams::validate`. The
account-commitment side enforces the stricter form the reorg horizon actually
requires:

```
application_journal_enabled_from_height + UNDO_RETENTION_FLOOR
    <= account_root_enabled_from_height
```

Once the root folds account rows, a reorg has to be able to put those rows back.
A reorg at the activation height can walk `MAX_REORG_WALK` = 4,096 blocks
backwards, so records must already exist at least that far below it. If they do
not, the walk reaches a block whose root committed to account state that no
journal can restore, and the chain can neither revert nor agree. That is the
terminal failure; the check is at startup, not at the boundary, because by the
boundary the node has already been publishing.

The gate must also be `Some(_)`, not `None`. `None` is not "off" — it means
"observed from this node's own chain", the lowest height for which this database
holds a record. That is the right rule for a node-local record, and it is a
node-local answer: two nodes may legitimately hold different boundaries. A
commitment folded into the state root cannot rest on that.

500,000 blocks (8.7 days) of separation against a 4,096-block (1.7-hour)
minimum. The margin is not for the reorg horizon, which 4,096 covers; it is
operational. A pinned journal height is a claim that every node holds records
from there. If a validator is late to upgrade, its records begin above
14,200,000 and it will refuse reorgs into the gap — loudly, and while there are
still eight days to correct the genesis before the account gate arrives. A
1-day gap would give the same guarantee to the reorg planner and none at all to
the operators.

The journal height must be far enough in the future that both validators are
running a journal-writing binary before the chain reaches it. 22 days is that,
with the same reasoning as above.

### The benchmark environment, for the record

The cost figures this document and `crates/state/src/account_root.rs` rely on
were produced on one machine. Recording it is not ceremony: a per-row cost is a
property of a CPU, a storage device and a build profile, and a figure quoted
without them cannot be reproduced or challenged.

| | |
|---|---|
| machine | Apple M5, 10 cores, 16 GiB RAM |
| storage | internal NVMe, APFS, 265 GiB free of 926 GiB |
| OS | macOS (Darwin 25.6.0) |
| toolchain | rustc 1.88.0 (pinned by `rust-toolchain.toml`) |
| profile | `--release` |
| store | RocksDB via this repo's `Database::open_default`, flushed and compacted before measuring |
| test | `the_cost_of_the_account_commitment_with_a_cold_cache`, `crates/state/tests/account_state_root.rs` |
| command | `ACCOUNT_ROOT_COST_ACCOUNTS=<n> ACCOUNT_ROOT_EVICT_PAGE_CACHE=25769803776 CARGO_INCREMENTAL=0 cargo test --release -p sumchain-state --test account_state_root the_cost_of_the_account_commitment_with_a_cold_cache -- --nocapture --test-threads=1` |
| runs | one per row count; no repetition, no variance reported |

Three properties of the measurement that bound what it proves:

* **Page-cache eviction is approximate.** There is no portable way to drop the
  OS page cache — `posix_fadvise(DONTNEED)` does not exist on this platform,
  `purge` needs privileges, and `F_NOCACHE` applies to a descriptor RocksDB
  opens itself. The harness applies 24 GiB of read pressure on a 16 GiB machine
  to a 223 MB database. That is far more pressure than the database occupies; it
  is not a proof that every page was dropped, so the cold-page figure is a lower
  bound on a truly cold device.
* **Single runs.** No variance is reported because none was collected. The
  numbers are consistent across three orders of magnitude of row count, which is
  evidence about the shape of the cost and not about its stability on one input.
* **Synthetic rows.** Addresses are generated, not drawn from production. That
  affects key distribution and therefore SST layout and compression; the flat
  per-row cost from 100k to 10M suggests it does not affect the shape, and the
  measurement on a production database has not been taken.

Production hardware is not this machine. A validator on slower storage or fewer
cores pays more, and the thresholds above should be re-derived against a
measurement on the hardware that will actually run them.

### What would change these numbers

Four things, and the first of them is not optional.

**The stored row count, once measured.** If it is far above 18, the cost
argument has to be re-derived from the interpolation table, and the activation
should be brought FORWARD rather than delayed — the commitment gets more
expensive to adopt as the family grows, never cheaper.

**The chain height at the moment of decision.** Every day-count in this document
is arithmetic against a reading taken on 2026-09-17. Recompute from a fresh
`chain_getBlockHeight`.

**The release date and rollout duration.** 31 days is a shape assumed for a
two-validator PoA net, not a schedule anyone has agreed. If the binary cut, the
testnet soak or the restart window are longer, the heights move out; if the
release is already cut and soaked, they move in.

**The validator set.** It is 2 today, and the 1,506 ms interval is 3,000 ms
halved by round-robin. A third validator changes the interval, and with it both
the day-counts and every "share of a block" figure above.

## Distribution and verification

### Where the heights live

Both are fields of `ChainParams`, inside the runtime `genesis.json` each
validator boots from. That file is loaded by `Genesis::from_file` on every
start, and `Genesis::validate` — and through it `ChainParams::validate` — runs
on every load. They are chain-defined in the sense that matters: the same two
numbers for every node, requiring no operator interpretation. Neither is an
"upgrade height", neither is derived from local history, and neither has a
default that differs per node.

Note the asymmetry with the journal gate's usual semantics. Left at `None` it is
deliberately node-local. Pinning it is what this activation requires, and
pinning it is what makes it distributable.

### How they are verified identical

`Genesis::activation_digest()` is one 32-byte value over the chain's identity
and every activation height it declares:

```
blake3( "sumchain/genesis-activation/v1"
        ‖ chain_id ‖ genesis_time
        ‖ validator count ‖ each validator pubkey, in declared order
        ‖ alloc count ‖ each (address, balance), in ascending address order
        ‖ for each gate, in a fixed declared order:
              name length ‖ name ‖ present ‖ height if present )
```

The procedure is an equality, not an inspection. Each operator prints the digest
from their own runtime genesis and the values are compared. Identical digests
across all validators means identical configuration; any difference — a
transposed digit, a gate set on one node and not another, a validator set in a
different order — changes it.

Four properties make it usable, each pinned by a test in
`crates/genesis/tests/activation_digest.rs`:

* **It covers every gate.** The coverage test reads the field declarations out
  of `crates/genesis/src/lib.rs` and fails if one is missing from the digest. A
  gate added and forgotten would otherwise be a height two validators could
  disagree about while their digests agreed.
* **It distinguishes `None` from `Some(0)`.** "Dormant forever" and "active from
  genesis" are opposite configurations.
* **It distinguishes one height on two different gates.** The field name is
  folded, so the digest is not a bag of numbers.
* **It does not depend on anything that is not configuration.** `HashMap`
  iteration order over the allocations is sorted away; a digest that disagreed
  on identical files would fire on every comparison and teach operators to
  ignore it.

It is deliberately **not** a consensus value. Nothing rejects a peer for
disagreeing about it. The chain already rejects the blocks that a disagreement
produces — that refusal is the detection the commitment provides, and it is what
makes activation a coordinated upgrade rather than a silent split. The digest is
the earlier, cheaper signal, available before the height arrives instead of
after.

### Surfaced, and enforced

The digest is logged at node startup and returned by
`chain_getActivationStatus`, alongside every gate and whether the chain has
reached it. The RPC server is handed the whole genesis rather than a digest, so
it cannot report one that does not correspond to the parameters it serves; a
server built without one reports the digest unavailable rather than a digest
over defaults, which would compare EQUAL between two nodes that share nothing.

Startup also REFUSES, rather than warns. The heights a database was last started
under are recorded in `cf::META`, and on every subsequent start they are
compared:

* a gate still ahead of the chain that moves, is rescheduled or is cancelled is
  **permitted** and logged as a warning — that is a coordinated activation being
  scheduled, and a check that refused it would refuse the mechanism it protects;
* a gate the chain has **already passed** that changes at all — moved forward,
  moved back, or removed — **refuses startup**. Blocks exist that were produced
  under the old height; changing it does not change them, it changes what this
  binary believes about them, and the node computes a different root for a block
  it already accepted;
* a dormant gate set to a height the chain has already passed **refuses
  startup**, for the same reason from the other side: every block above that
  height was produced without the rule.

The refusal happens before consensus, RPC or the network exist, so a node that
fails it never joins rather than joins and diverges. An unreadable record is an
error rather than a first start: treating it as absent would skip the only check
that catches a rule changed underneath existing blocks.

What is still manual is the comparison BETWEEN nodes. Each node reports its own
digest; nothing compares two of them automatically, and step 4 below is
therefore an operator action. That is a smaller gap than it was — the value to
compare exists, is stable, and is scrapeable — and it is the remaining one.

## History a seeded node must not serve

A node seeded from a snapshot holds canonical state at the import height and
nothing below it. The blocks are not there, and if they were, replaying them is
the sync the import avoided. So there are questions it cannot answer, and the
requirement is that it refuses them rather than answering badly.

`snapshot::can_serve_history_at` is the predicate. `imported_at` is the floor it
reads, persisted in `cf::META` so a restart does not forget it.

Every RPC that takes a height was audited against it:

| RPC | reads historical state? | today |
|---|---|---|
| `storage_getActiveNodesAtHeight` | **yes — walks BACKWARDS to the nearest snapshot** | **refuses below the floor** |
| `get_block_by_height`, `sum_getBlockByHeight` | no — returns a stored block | returns `null` when absent |
| `messaging_getMessagesInBlock` | no — returns stored rows | returns empty when absent |
| `is_block_finalized` | no — compares against the finalized height | unaffected |
| `validatorSet_getProposer` | no — derived from the validator set | unaffected |

Only the first could return a WRONG answer: its backward walk runs off the
bottom of a seeded node's history and returns whatever it finds there, which a
caller cannot distinguish from a correct result. That one refuses now, naming
the floor.

The rest return "absent", which is a defined answer and not a wrong one. The
remaining wart is that "absent" does not say WHY — a caller cannot tell "this
block never existed" from "this node was seeded above it". That is a reporting
gap rather than a correctness one, and `chain_getSyncCapability.state_history_floor`
is what a caller reads to resolve it.

## Sequence

0. **Measure the stored account-row count** on the production database and
   record it with its height and timestamp. Re-derive the timing below against
   it. Do not proceed on the value-holding count.
1. Cut the release binary. Verify `validate_account_root_activation` accepts the
   proposed pair and that `ChainParams::validate` enforces the journal ordering.
2. Soak on a testnet whose genesis carries the same two gates at proportionally
   scaled heights.
3. Deploy the binary to both validators, coordinated, well before
   14,200,000. Journal records begin at each node's own upgrade height.
4. Edit both runtime `genesis.json` files with the two heights. Restart each,
   and confirm the restart is ACCEPTED — a refusal here means a gate the chain
   has already passed was touched, and the edit is wrong. Compare
   `chain_getActivationStatus.digest` across both validators. **If they differ,
   stop.**
5. Chain reaches 14,200,000. The pinned journal boundary takes effect. Confirm
   both nodes hold records from at or below it; a node that does not will refuse
   reorgs into the gap.
6. Eight days of margin. Any journal shortfall surfaces here, while the genesis
   can still be corrected.
7. Chain reaches 14,700,000. The root formula changes. A node that did not
   receive the coordinated genesis computes a different root and its blocks are
   refused — the intended, detectable, coordinated split.

## Rollback

Before 14,700,000 is reached: edit both genesis files back, restart, compare
digests. Nothing has been committed to.

After: the root formula has changed and blocks above it were published under
it. Reverting is a consensus change of its own and is not a rollback. The
decision point is step 6.
