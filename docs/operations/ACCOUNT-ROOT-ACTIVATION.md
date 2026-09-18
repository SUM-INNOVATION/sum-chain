# Account-state commitment: activation

The block state root does not cover account balances or nonces. Two nodes can
disagree about every balance on the chain and publish identical block hashes,
and nothing built on the root — light client, fast-sync check, fraud proof — can
tell. `crates/state/tests/account_state_root.rs` reproduces that rather than
asserting it, and `account_root_enabled_from_height` is what closes it.

This document proposes the height, the paired journal height it depends on, and
how both are distributed and verified identical across validators. It is a
proposal: nothing here is set in any `genesis.json` in this tree, and the
production default remains `None`, which is byte-for-byte the root formula an
un-upgraded node computes.

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
| accounts | **18** | transaction-graph closure, cross-checked against `accounted_account_supply` to the base unit |
| `LEGACY_ROOT_COMPATIBILITY_HEIGHT` | 496,720 | `crates/storage/src/candidate.rs` — 12.4M blocks in the past |
| `MAX_REORG_WALK` / `UNDO_RETENTION_FLOOR` | 4,096 | `crates/consensus/src/poa.rs`, `crates/storage/src/pruner.rs` |

The 1,506 ms figure matters and is easy to get wrong. `block_time_ms` is what a
proposer waits for its own slot; with two validators alternating, blocks arrive
at half that. Every node executes every block, so the interval is the budget.

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

### What would change these numbers

Only two things. If the account count begins growing — the trigger is 500,000
accounts, at which the scan costs ~80 ms, 5% of the interval — the activation
should be brought forward, not delayed, because the commitment gets more
expensive to adopt later, not less. And if the validator set grows, the interval
between blocks changes and every day-count above has to be recomputed from a
fresh measurement rather than from this table.

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

### Not yet wired

`activation_digest` is a library function with tests. It is **not** logged at
startup and **not** exposed over RPC. Both belong in `crates/node` and
`crates/rpc`, and until one of them exists the comparison is a manual step an
operator has to remember to perform. That is a gap, and it is the last thing
standing between this document and a procedure.

## Sequence

1. Cut the release binary. Verify `validate_account_root_activation` accepts the
   proposed pair and that `ChainParams::validate` enforces the journal ordering.
2. Soak on a testnet whose genesis carries the same two gates at proportionally
   scaled heights.
3. Deploy the binary to both validators, coordinated, well before
   14,200,000. Journal records begin at each node's own upgrade height.
4. Edit both runtime `genesis.json` files with the two heights. Compare
   `activation_digest` across both validators. **If they differ, stop.**
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
