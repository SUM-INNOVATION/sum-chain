# Owner decision packet: the seventeen remediation activation heights

**This document sets no height.** Every height in the set below is the owner's
decision. What this document does is put, in one place, the facts each decision
needs: what the gate turns on, whether it needs a data migration, what happens
if validators disagree about it, what happens on a rollback, which other gates
it depends on, which tests cover it, and what is risked by activating it and by
leaving it dormant.

The seventeen are the `WIRING` table in `crates/state/tests/remediation_gates.rs:52`.
They are the remedies the activation audit produced
(`docs/lane-a/ACTIVATION-AUDIT.md`), each implemented, each dormant, none set
anywhere.

---

## Part 0 — The facts that apply to all seventeen

### 0.1 The live chain, measured rather than assumed

Queried from this machine against the endpoint
`docs/operations/production-checklist.md:145` documents:

```
$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sum_blockNumber","params":[]}'
{"jsonrpc":"2.0","result":12970055,"id":1}

$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHeight","params":[]}'
{"jsonrpc":"2.0","result":{"height":12970099,"finality":"latest"},"id":1}
```

**VERIFIED: mainnet (`chain_id: 1`) is at height ≈12,970,100 as of 2026-09-18.**

`chain_getChainParams` returns the deployed configuration:

```json
{ "chain_id": 1, "block_time_ms": 3000, "max_block_bytes": 2000000,
  "max_txs_per_block": 1000, "min_fee": 1000, "finality_depth": 6,
  "storage_fee_per_byte": 100, "max_metadata_bytes": 16384,
  "max_access_list_bytes": 16384, "activation_grace_blocks": 50,
  "abandonment_fee_percent": 10, "max_chunk_count_per_file": 1048576,
  "max_chunk_indices_per_tx": 65536, "assignment_replication_factor": 3,
  "v2_enabled_from_height": 5200000,
  "omninode_enabled_from_height": 6000000,
  "education_enabled_from_height": 8900000,
  "governance_enabled_from_height": 8900000,
  "monetary_policy_enabled_from_height": null,
  "service_grants_enabled_from_height": null,
  "governance": { … } }
```

Two things follow immediately, and both matter to this decision.

**(a) The deployed binary is OLDER than this tree.** Two RPC methods this tree
ships do not exist on mainnet:

```
chain_getSyncCapability   → {"code":-32601,"message":"Method not found"}
chain_getActivationStatus → {"code":-32601,"message":"Method not found"}
```

So activating any of the seventeen is not a genesis edit alone; it requires a
**binary rollout first**, because the code behind every one of the seventeen
gates is not on mainnet yet. The genesis edit without the binary would be a
height nothing reads.

**(b) None of the seventeen is visible over RPC, even once set.**
`chain_getChainParams` serializes a fixed subset, and none of the seventeen is
in it. An operator cannot today confirm from outside a node that a validator has
the height they agreed on. The genesis activation digest
(`ChainParams::activation_heights()`, covering all 37 gate fields including all
seventeen — verified below) is the comparison mechanism, and it is compared by
eye from the file, not over the wire. **This is a gap worth closing before the
first coordinated activation**, and it is named here rather than discovered
during one.

### 0.2 The hard floor on every height: strictly above the head

`GATES_PREDATING_ACTIVATION_RECORDING` (`crates/genesis/src/lib.rs:1929`) is a
closed list of eighteen gates that shipped in binaries which produced existing
blocks. A gate on that list may legally sit below the head. Everything else may
not.

Verified mechanically rather than by reading:

```
$ python3 - (parse GATES_PREDATING_ACTIVATION_RECORDING and activation_heights() out of genesis/src/lib.rs)
grandfathered count: 18
of the 17, grandfathered: NONE
of the 17, missing from activation_heights(): NONE
activation_heights() total entries: 37
```

So for each of the seventeen, on the **first start** of an upgraded node
(`retroactive_gates_on_a_first_start`, `crates/genesis/src/lib.rs:2025`):

- a height **at or below** the head → `RetroactivelyOpened` → the node REFUSES
  TO START, naming the gate;
- a height **above** the head → startable.

The boundary is exact and pinned: at the head is still retroactive (that block
already exists), head + 1 is a scheduled activation —
`crates/genesis/tests/activation_digest.rs:525
a_newly_introduced_gate_below_the_head_refuses_a_first_start`.

**With mainnet at ≈12,970,100 and a coordinated restart, every one of the
seventeen must be scheduled above the head at the moment the restart happens,
with enough margin that the chain does not cross the chosen height while the
rollout is in progress.**

### 0.3 A height, once passed, is frozen

On a subsequent restart, `activation_changes` (`crates/genesis/src/lib.rs:1962`)
classifies each moved gate:

| classification | meaning | startable? |
|---|---|---|
| `Retuned` | both the old and the new height are still in the future | **yes** — "a coordinated activation being scheduled, rescheduled or cancelled … noisy, and legitimate" |
| `AlreadyActive` | the old height had already fired | **no** |
| `RetroactivelyOpened` | dormant (or scheduled ahead) and now set at or below the head | **no** |

`ActivationChange::is_permitted` (`:1853`) returns true for `Retuned` only:
"The other two describe a rule being changed underneath blocks that already
exist, which is not a configuration change — it is a different chain wearing
this one's database."

Practical consequence for the owner: **a height may be moved freely right up
until the chain reaches it, and not at all afterwards.** Scheduling
conservatively far ahead costs nothing but delay; scheduling too close costs a
refused start.

### 0.4 Rollback behaviour, identical for all seventeen

Every one of the seventeen is a pure function of `(params, block_height)` —
`matches!(activation(params), Some(h) if block_height >= h)`. There is no
per-gate rollback machinery; `crates/state/src/reorg_undo.rs` contains no gate
references.

- A reorg or `sumchain rollback` **below** `h` re-executes those blocks with the
  gate closed, which is how they were produced. Consistent.
- A reorg **across** `h` re-executes each block under the rule for its own
  height. Consistent.
- Rolling the chain below `h` does **not** make `h` re-editable. A restart with
  a changed height is `AlreadyActive` and refused (§0.3). The recorded height is
  what was already passed, not what the current tip is.

### 0.5 Dependencies: there are none among the seventeen

`ChainParams::validate()` (`crates/genesis/src/lib.rs:1515`) constrains exactly
two things: `compute_pool`/`beacon` must stay dormant (fail-closed), and

```
application_journal_enabled_from_height <= account_root_enabled_from_height
```

**Neither of those two is one of the seventeen.** No gate in this set is
ordered, coupled or validated against any other. Each `…Gates::from_params`
constructor reads its fields independently. Gates 11 and 12 are deliberately
separate fields with an argument in the source for why they must be
independently sequenceable (`crates/state/src/lib.rs:117-131`: "Two different
blast radii; an operator must be able to take one without the other").

That is a design property, not an accident, and it means **the owner may
sequence the seventeen in any order, including all at one height or seventeen
different heights.**

### 0.6 Dormancy today, and the tests that hold it

All seventeen default to `None` — `crates/genesis/src/lib.rs:1431-1461`, pinned
by `crates/state/tests/remediation_gates.rs:250
every_remediation_gate_is_dormant_by_default`, which asserts all seventeen are
`None` and that the list length matches the seventeen-row `WIRING` table.

Three more guards run in the default gate:

- `remediation_gates.rs:179 every_remediation_gate_reads_the_field_it_names` —
  source-level accessor/field pairing, which kills the realistic bug in
  seventeen near-identical three-line functions: two of them reading each
  other's field;
- `remediation_gates.rs:232 the_seventeen_gates_are_seventeen_distinct_fields`;
- `remediation_gates.rs:305 a_genesis_written_before_these_fields_still_parses_dormant`.

And `crates/genesis/tests/activation_digest.rs:47
every_activation_height_is_covered_by_the_digest` scans the source for every
`pub *_from_height: Option<u64>` declaration and asserts set-equality with
`activation_heights()` in both directions — a gate missing from the digest would
let "two validators disagree while their digests agreed".

### 0.7 Two source defects the owner should see before signing anything

**`tax_proof_lifecycle_enabled_from_height` (gate 14) was declared differently
from the other sixteen — FOUND AND FIXED while assembling this packet.**

As found, at `crates/genesis/src/lib.rs:1018`, it was the **only one of the
seventeen without `#[serde(default)]`**, and it had **no doc comment of its
own**: the text describing it was spliced into the middle of gate 13's comment,
immediately after gate 13's last line with no separator, leaving gate 13's
`#[serde(default)]` and declaration stranded below BOTH comments and gate 14
following it bare:

```rust
    /// … One field for both subsystems because it is one rule at one seam …
    /// There is no configuration in which an operator wants one and not the
    /// other.
    /// The Tax proof store and its subject index stop disagreeing.      ← gate 14's doc
    /// …
    #[serde(default)]
    pub subsystem_allocation_bound_enabled_from_height: Option<u64>,     ← gate 13
    pub tax_proof_lifecycle_enabled_from_height: Option<u64>,            ← gate 14, bare
```

That is exactly the "gate lost in a merge" splice the `remediation_gates.rs`
module doc warns about, caught one step short of losing a gate.

It was not a behavioural defect: serde's derive treats a missing field of type
`Option<T>` as `None` regardless, which is why
`a_genesis_written_before_these_fields_still_parses_dormant` passed throughout.
It was worse than that in one specific way — **the documentation an operator
would read before setting gate 14's height was attached to gate 13's field.**
Setting a consensus activation height from a doc comment describing a different
rule is the kind of mistake this packet exists to prevent, so it is repaired
rather than reported: gate 13 now carries its own closing paragraphs and its own
attribute and declaration, and gate 14 carries its own doc comment and its own
`#[serde(default)]`, making all seventeen uniform.

```
cargo test -p sumchain-genesis                       34 + 17 passed; 0 failed
cargo test -p sumchain-state --test remediation_gates 4 passed; 0 failed
```

**No RPC surfaces any of the seventeen** (§0.1b).

### 0.8 How an activation is actually deployed

From `docs/operations/production-checklist.md:27-40` and `RELEASE.md`:

- Production validators boot from the **root runtime `genesis.json`**, not from
  `genesis/mainnet_genesis.json`, whose own first key says "TEMPLATE ONLY".
- Activation heights are "edited into each validator's runtime genesis
  identically, never into the template."
- Consistency check: "confirm the `genesis.json` on every validator hashes
  identically before starting or restarting the network."
- Restart coordination (`:152-165`): PoA round-robin has **no proposer-skip**,
  so restarting a validator stalls that validator's slots until it rejoins.
  Rolling restarts are one validator at a time.
- Governance authority is validator-quorum at 6667 bps — on the current
  2-validator net, **both** validators must sign.

The committed `genesis.json` in this tree carries **no** activation fields at
all (`block_time_ms`, `max_block_bytes`, `max_txs_per_block`, `min_fee`,
`finality_depth`, `max_metadata_bytes`, `storage_fee_per_byte` only). The
deployed file is the base plus edits, and the edited file is not in this tree.

### 0.9 Converting a height to a UTC estimate — MEASURED

`block_time_ms` is **3000** in both the committed `genesis.json` and the live
`chain_getChainParams`. **Using 3000 ms as the block interval is wrong, and the
error is a factor of two.**

Measured directly against the live endpoint, two samples 120 seconds apart:

```
sample A: height=12970111
sample B: height=12970191   (+80 blocks in 120.2 s)
observed block interval = 1.502 s/block
observed rate = 57,524 blocks/day
```

That is not a surprise and it is not a defect. `block_time_ms` is the interval a
proposer waits for **its own slot**; PoA is round-robin and mainnet has two
validators (`sum_getValidators` → 2), so blocks arrive at half the slot time.
The repository already states this, in the one place that had to get it right:

> "The 1,506 ms figure matters and is easy to get wrong. `block_time_ms` is what
> a proposer waits for its own slot; with two validators alternating, blocks
> arrive at half that. Every node executes every block, so the interval is the
> budget."
> — `docs/operations/ACCOUNT-ROOT-ACTIVATION.md:39-43`

and `crates/state/src/account_root.rs:93` carries the same figure in the cost
model. **The live measurement above (1.502 s) independently confirms the
repository's 1,506 ms at a fresh time, from a fresh sample.**

| interval | blocks / hour | blocks / day |
|---|---|---|
| **1.506 s (measured, 2 validators)** | **~2,390** | **~57,400** |
| 3.000 s (`block_time_ms`, one proposer slot) | 1,200 | 28,800 |

**So: height → UTC uses 57,400 blocks/day, not 28,800.**

Two consequences for this decision:

**(a) One published estimate is built on the wrong number.**
`docs/operations/production-checklist.md:136-140` records the head at 8,716,604
on 2026-07-06 and estimates 8,900,000 at "≈2026-07-12" — that is 183,396 blocks
in ~6 days, i.e. ~2.83 s/block, the nominal rate rather than the measured one.
At 57,400 blocks/day those 183,396 blocks are **~3.2 days**, so the gate would
have activated around 2026-07-09, not 2026-07-12. The same 8,716,604 →
12,970,191 over 74 days works out to 1.50 s/block, matching the measurement
exactly. **Any UTC schedule taken from the production checklist's conversion is
roughly 2x too long.**

**(b) The interval is a function of the validator count, not a constant.**
`ACCOUNT-ROOT-ACTIVATION.md:305` says it plainly: "A third validator changes the
interval, and with it both the day-counts and every 'share of a block' figure."
If the validator set changes between this decision and the activation, every UTC
estimate derived here moves. The height does not.

**The safe form of the decision, which does not depend on the rate at all:**
choose the height as *head at rollout time + N*, where N is a block margin
generous enough to cover the rollout at the FASTER plausible rate. Then convert
to UTC only for communication, and re-measure the interval immediately before
the coordinated restart.

### 0.10 What is UNPROVEN in this packet

| gap | what would settle it |
|---|---|
| height→UTC conversion **after the validator set changes** | §0.9 is measured and settled for the CURRENT 2-validator set (1.502 s/block). A third validator halves the rate again; re-measure if the set changes |
| whether the deployed validators can run this tree's binary at all | a testnet rollout of this binary against a copy of mainnet state |
| whether any of the seventeen has an operational consumer (tooling, indexers) that would break | not answerable from this repository; it is a question for whoever runs the indexers |
| gate 2's migration decision (see gate 2) | an owner decision; the repository contains no answer |
| gate 13's effect on rows that are **already** oversized | no test covers it; see gate 13 |

---

## Part 1 — The seventeen

Each section states, in the order the brief asks for: behaviour enabled, data
migration required, mixed-version effect, rollback behaviour, proposed height,
UTC estimate, dependencies, tests, risk if activated, risk if deferred.

**Proposed height** is deliberately left as `— owner decision —` in every
section. **UTC estimate** likewise: §0.9 shows the conversion is not currently
trustworthy, and a UTC estimate derived from an untrustworthy rate is worse than
no estimate.

---

### Gate 1 — `nft_receipt_failure_enabled_from_height`
*accessor `NftExecutor::receipt_failure_activation`, `crates/state/src/nft_executor.rs:205`*

**Behaviour enabled.** Block-level denial becomes a charged failed receipt. From
the field's doc (`crates/genesis/src/lib.rs:715`): "Below the gate, an NFT
operation that violates a block-level rule … returns `StateError::BlockValidation`
and makes the whole block unexecutable. At and above it the same conditions
produce a `Failed` receipt that charges the sender and leaves the block valid."
The conversion set is deliberately narrow — `as_receipt_failure`
(`nft_executor.rs:248`) excludes storage and encoding faults, which still abort.

**Data migration required.** No. Receipt semantics only; no key or row shape
changes.

**Mixed-version effect.** The most severe of the seventeen. The doc states it
directly: "Two nodes that disagree about this height disagree about whether a
block EXISTS, not merely about its root." Pinned by `nft_routing.rs:3139
an_ungated_node_cannot_execute_the_block_a_gated_node_roots`.

**Rollback behaviour.** Per §0.4. Receipts fold into the state root
(`nft_routing.rs:3195`), so a reorg across `h` re-derives the correct receipts
per height.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None. `NftGates::from_params` (`nft_executor.rs:146`) reads
receipt_failure, token_authority and allocation_bound independently.

**Tests.** Open/closed pairs: `nft_routing.rs:2857`, `:2935`, `:3044`, `:3139`.
Closed-side pins: `:1899 a_transaction_naming_an_absent_collection_aborts_the_whole_block`,
`:2002 an_invalid_collection_config_aborts_the_whole_block`.

**Risk if activated.** Senders begin paying for operations that previously cost
them nothing, because the block died instead; nonces advance where they did not.

**Risk if deferred.** Any funded sender can make arbitrary blocks unexecutable
with one malformed NFT transaction, for `min_fee`. A liveness weapon, cheap, and
reachable today.

---

### Gate 2 — `docclass_stake_escrow_enabled_from_height`
*accessor `DocClassExecutor::stake_escrow_activation`, `crates/state/src/docclass_executor.rs:186`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:739`): "Below the gate the stake
debited at registration is credited to nobody and leaves the money supply. At
and above it the stake is held by a keyless escrow address and refunded exactly
once on deactivation." The escrow address is
`blake3("sumchain/docclass/issuer-stake-escrow/v1")` (`docclass_executor.rs:37,118`).
Three call sites: credit on register (`:1586`), `UpdateIssuer` may no longer
restate `stake_amount` (`:1640`), refund-and-zero on deactivate (`:1753-1766`).

**Data migration required. YES IN SUBSTANCE, AND NO MIGRATION EXISTS. This is
the one gate of the seventeen that needs an explicit owner decision beyond a
height.**

Stakes posted below the gate were destroyed — the escrow account holds nothing
for them. Above the gate, `deactivate_issuer` refunds any issuer row with
`stake_amount > 0` via `StateManager::v_deduct(escrow, refund)`
(`docclass_executor.rs:1761`), and `v_deduct` (`crates/state/src/state.rs:214`)
returns `InsufficientBalance` when the escrow is short. So a pre-gate issuer
deactivating after activation attempts to withdraw money that was never
escrowed. Nothing in the repository pre-funds the escrow, zeroes legacy
`stake_amount` fields, or special-cases pre-gate rows: `docclass_stake_escrow_address`
has exactly two non-test references (`crates/state/src/lib.rs:238` re-export and
`docclass_executor.rs`), and `supply.rs` does not know about it.

The owner's options, none of which this document chooses between:
1. pre-fund the escrow with the sum of all live pre-gate `stake_amount` values
   in the same coordinated genesis (requires knowing that sum from production
   state — see §0.10);
2. zero legacy `stake_amount` fields as part of the activation (loses the
   issuers' claim, which was already lost in substance);
3. add a pre-gate carve-out to `deactivate_issuer` before activating;
4. defer the gate.

**Mixed-version effect.** Balances diverge from the registration transaction
onward, so every subsequent root differs. `docclass_routing.rs:4062
a_registration_stake_is_destroyed_below_the_gate_and_escrowed_above_it` asserts
escrow balance 1000 vs 0 across the same transaction.

**Rollback behaviour.** Per §0.4; balances are ordinary account state reverted by
the normal undo path.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None on the other sixteen. It has a **data** dependency on a
decision that does not exist yet.

**Tests.** `docclass_routing.rs:4062`, `:4128 deactivation_refunds_the_escrowed_stake_once_and_only_at_the_gate`,
`:4223 an_update_cannot_inflate_the_recorded_stake_at_the_gate`. Closed-side
pins: `:3175`, `:3055`.

**Risk if activated without a migration.** Legacy issuers' deactivations fail on
escrow underflow; or, if the arithmetic ever succeeds, they drain escrow funded
by newer issuers.

**Risk if deferred.** The money supply keeps shrinking by a sender-chosen amount
at every DocClass issuer registration.

---

### Gate 3 — `docclass_subject_index_split_enabled_from_height`
*accessor `DocClassExecutor::subject_index_split_activation`, `crates/state/src/docclass_executor.rs:217`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:757`): "Below the gate the
identity index shares a 32-byte key space in which two different subjects can
collide. At and above it writes use a tagged 33-byte key no legacy key can
equal; reads still fall back to the legacy key, so a collision committed BEFORE
activation stays." Below the gate the collision is fatal — a credential list
overwrites an identity row and the next identity operation is a hard `Err` that
kills the block (`docclass_routing.rs:3475`).

**Data migration required. No, by construction.** The reader is deliberately
gate-free and tries tagged-then-legacy — `crates/state/src/docclass_view.rs:206
v_get_subject_identity_entries`: "No gate parameter, deliberately: the reader
has to answer correctly on both sides of the activation and for rows written on
either side." Writes are split, driven by `gates.subject_index_split` at seven
`v_put_identity_root` call sites (`docclass_executor.rs:588-914`).

What does **not** migrate: a collision already committed below the gate stays
corrupt forever (`docclass_routing.rs:4495-4504`: "an upgraded node still sees
what a pre-activation block indexed"). Key shape changes for new writes only.
**Any external tooling reading `DOCCLASS_SUBJECT_INDEX` by bare 32-byte key must
learn the 33-byte form.**

**Mixed-version effect.** Rows land at different keys from the first
post-activation identity write, so roots diverge; and below the gate a colliding
pair makes the block unexecutable while above it the same block commits.
`docclass_routing.rs:4325 a_colliding_subject_commitment_ends_the_block_below_the_gate_and_is_harmless_above_it`.

**Rollback behaviour.** Per §0.4. A rollback below `h` re-executes writes to the
legacy key; the tagged-first reader stays correct in both directions, which is
exactly why it has no gate parameter.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `docclass_routing.rs:4325`; closed-side pin `:3475
an_identity_and_a_credential_sharing_a_subject_commitment_break_the_block`.

**Risk if activated.** New identity index rows move key space; downstream
readers keyed on the legacy shape must be updated in step.

**Risk if deferred.** Two cheap transactions arm it and a third detonates it:
any sender can make a block permanently unexecutable for every node. The arming
sequence is pinned at `:3475`.

---

### Gate 4 — `docclass_revocation_standing_enabled_from_height`
*accessor `DocClassExecutor::revocation_standing_activation`, `crates/state/src/docclass_executor.rs:247`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:777`): "Only the issuer may
revoke a DocClass credential. Below the gate revocation standing is unchecked."
The whole revocation family (revoke, suspend, reactivate, supersede) authorizes
through `check_revoke_auth`, which reads only the `issuer` field on the
credential row and never the issuer registry — while the issue paths do consult
it via `v_can_issue_subcode`. Above the gate revocation asks the registry the
same status question, and **status only**, not subcode or jurisdiction:
narrowing an issuer's authorization must not strand credentials nobody can
withdraw (`docclass_routing.rs:4513-4515`).

**Data migration required.** No. Authority check only.

**Mixed-version effect.** A suspended issuer's revocation succeeds on one side
and fails on the other; receipts and rows diverge.
`docclass_routing.rs:4517 a_suspended_issuer_keeps_the_revocation_family_only_below_the_gate`.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `docclass_routing.rs:4517`; closed-side pins `:3596
a_suspended_issuer_can_still_revoke_and_update_itself`, `:3549
a_third_party_cannot_revoke_someone_elses_credential`.

**Risk if activated.** A suspended issuer can no longer withdraw credentials it
validly issued while active.

**Risk if deferred.** Suspension is cosmetic on the withdraw side: a revoked
issuer keeps control of everything it ever issued.

---

### Gate 5 — `healthcare_authorization_enabled_from_height`
*accessor `HealthcareExecutor::authorization_activation`, `crates/state/src/healthcare_executor.rs:213`*

**Behaviour enabled.** Seven distinct defects, one height — the largest
behavioural surface of the six authorization gates. Doc
(`genesis/src/lib.rs:791`, accessor `:195`): below the gate `SupersedeConsent`,
`FillPrescription` and `PartialFillPrescription` check **nothing** about the
sender; `Add/RemoveNetworkAffiliation` check no issuer; `IssuePrescription`
never relates the sender to the named prescriber; a consent's subject cannot
revoke it; and a prescription with zero refills is fillable once more because
its guard is a conjunction. Above the gate each is enforced and the refusal is a
`Failed` receipt. The fill-authority set is deliberately three addresses — the
pharmacy is a `PartyRef`, not an address, so it cannot be authorized from the
row (`healthcare_executor.rs:253+`, recorded rather than papered over).

**Data migration required.** No.

**Mixed-version effect.** Transactions succeed on one side and receipt-fail on
the other; receipts fold into the root. Each named test drives `CLOSED` and
`OPEN` over identical fixtures in one process.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None. `HealthcareGates::from_params` (`healthcare_executor.rs:172`)
reads authorization, `subsystem_block_timestamp` and state_precondition
independently.

**Tests.** `healthcare_routing.rs:3902`, `:3986`, `:4054`, `:4099`, `:4175`,
`:4233`, `:4280`. Closed-side pins: `:2727`, `:2821`, `:2904`, `:2996`, `:3267`.

**Risk if activated.** Previously-valid fill and supersede flows performed by
third parties start failing. Seven behaviours change at once; this is the gate
most likely to break an existing integration.

**Risk if deferred.** Any funded account can fill any prescription and rewrite
any provider's network affiliations.

---

### Gate 6 — `legal_authorization_enabled_from_height`
*accessor `LegalExecutor::authorization_activation`, `crates/state/src/legal_executor.rs:198`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:818`): "Legal consolidate,
transfer and supersession check authority. Below the gate these four operations
accept any sender. Supersession in particular is three conditions and not one:
the sender must hold the old record, the replacement must be issued by the
sender, and it must concern the same subject — otherwise supersession is a way
to overwrite someone else's record." The accessor adds two more: `SupersedeOrder`
has no duplicate guard, so a stranger overwrites an existing order by reusing
its id; and `SupersedeEvent` does not verify the replacement's case exists,
leaving a dangling case-to-event index entry the attacker chose.

**Data migration required.** No — but the dangling index entries created below
the gate are **not** cleaned up by activation.

**Mixed-version effect.** Same-shape divergence; the tests drive both sides.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `legal_routing.rs:3543`, `:3633`, `:3723`. Closed-side pins: `:2751`,
`:2845`, `:2928`, `:3039`.

**Risk if activated.** Supersession workflows that relied on there being no
sender check break.

**Risk if deferred.** Any account can overwrite any court order by reusing its
id.

---

### Gate 7 — `finance_authorization_enabled_from_height`
*accessor `FinanceExecutor::authorization_activation`, `crates/state/src/finance_executor.rs:193`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:827`): "A revoked finance issuer
stops being an issuer. Below the gate revocation is recorded and then ignored by
the operations that should consult it." Every update/revoke path checks only the
address on the row and never rereads the registry, while the creation paths do —
"the asymmetry is exact". `UpdateIssuer` accepts any status the sender asks for,
including `Active` from `Revoked`, walking around the Suspended-only guard in
`ReactivateIssuer`. `SubmitProof` has no authority check at all. Above the gate
all three go through `issuer_in_good_standing` (`finance_executor.rs:207`).

**Data migration required.** No.

**Mixed-version effect.** Both sides driven over the same fixture in each test.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `finance_routing.rs:3352`, `:3457 update_issuer_cannot_walk_around_reactivate_at_the_gate`,
`:3523 submit_proof_requires_a_registered_active_issuer_at_the_gate`.

**Risk if activated.** Suspended and revoked issuers lose mutation rights
immediately, including over rows they created while active.

**Risk if deferred.** Revoking a finance issuer is decorative, and a revoked
issuer can self-reactivate.

---

### Gate 8 — `employment_authorization_enabled_from_height`
*accessor `EmploymentExecutor::authorization_activation`, `crates/state/src/employment_executor.rs:176`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:844`): "A revoked employment
issuer stops being an issuer. Below the gate revocation is recorded and then
ignored." Only `CreateEmployment` and `CreateIncomeAttestation` require an
active issuer; every mutation checks only the address on the row. Above the gate
every mutation asks the same question via `issuer_in_good_standing`
(`employment_executor.rs:189`). Narrower surface than finance; same shape.

**Data migration required.** No.

**Mixed-version effect.** Both sides driven in the test below.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `employment_routing.rs:2606 a_suspended_employment_issuer_loses_its_mutations_only_at_the_gate`.
Closed-side pin named in the accessor doc:
`a_suspended_issuer_can_still_revoke_but_not_create`.

**Risk if activated.** As finance, narrower.

**Risk if deferred.** Suspended employment issuers keep full mutation rights
over everything they issued.

---

### Gate 9 — `property_authorization_enabled_from_height`
*accessor `PropertyExecutor::authorization_activation`, `crates/state/src/property_executor.rs:214`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:861`): "Property operations bind
to the row and the registry. Below the gate an operation need not be performed
by a party the row or the registry gives standing to." Two arms: `MergeAssets`
checks nothing, so any account merges two assets it did not issue and marks the
secondary `Merged`; and `SupersedeTitleEvent` checks nothing, so any account
supersedes any title event, recording a replacement naming itself. Above the
gate each binds to the issuer on the row it changes.

**Data migration required.** No.

**Mixed-version effect.** Both sides driven in the tests below.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `property_routing.rs:3045`, `:3115`. Closed-side pin named in the
accessor doc: `three_operations_check_no_authority_at_all`.

**Risk if activated.** Two arms that accepted any sender start refusing.

**Risk if deferred.** Any funded account can rewrite a property title history.

---

### Gate 10 — `tax_authorization_enabled_from_height`
*accessor `TaxExecutor::authorization_activation`, `crates/state/src/tax_executor.rs:117`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:878`): claim-type registration,
update and deprecation have **no authority check at all** — all three guard only
on row presence or absence, "so any funded account writes the chain's claim-type
registry." Above the gate the sender must be a registered tax issuer whose
status is `Active` (`issuer_in_good_standing`, `tax_executor.rs:158`).

**Data migration required.** No. Claim-type rows written by strangers below the
gate are **not** removed by activation.

**Mixed-version effect.** Both sides driven in the test below.

**Rollback behaviour.** Per §0.4. Named explicitly in
`crates/genesis/tests/activation_digest.rs:547` as a first-start refusal case.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None. `TaxGates::from_params` (`tax_executor.rs:85`) reads
authorization, block_timestamp and proof_lifecycle independently.

**Tests.** `tax_routing.rs:1257 the_claim_type_registry_is_writable_by_anyone_only_below_the_gate`.

**Risk if activated.** Any tooling registering claim types from an unregistered
key stops working.

**Risk if deferred.** The chain-wide claim-type registry is world-writable.

---

### Gate 11 — `subsystem_block_timestamp_enabled_from_height`  *(cross-cutting)*
*accessor `subsystem_block_timestamp_activation`, `crates/state/src/lib.rs:90`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:897`): "Eight subsystems see the
block's timestamp instead of a literal zero. Below the gate eight subsystems are
handed `0` where the block's timestamp belongs, so every time-dependent rule in
them evaluates at the epoch — a prescription validity window, for instance, is
checked at time zero." Switched in one place, `effective_block_timestamp`
(`crates/state/src/lib.rs:105`), reached by eight call sites: messaging
(`messaging_executor.rs:95`), docclass (`:323`), finance (`:258`), tax (`:209`),
healthcare (`:322`), agreement (`:262`), property (`:268`), employment (`:241`).

It moves real validity logic, not only stamps. Messaging's `current_day` buckets
the daily send quota on this value, so at the epoch every message a chain ever
sends counts against day zero (`messaging_routing.rs:1064-1069`).

**Data migration required.** No, but **it re-dates nothing already written**:
existing rows keep their zero stamps, and anything comparing a stored zero
against a real block time changes meaning at `h`. The source's own reason for
one field rather than eight (`crates/state/src/lib.rs:82-85`): "Splitting it per
subsystem would let a chain hold half its rows at zero and half at a real time,
which is worse than either end."

**Mixed-version effect.** Rows differ in content from the first post-activation
write in any of the eight, and time-window decisions flip.

**Rollback behaviour.** Per §0.4. Named in `activation_digest.rs:490` and `:541`
as a first-start refusal case.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None enforced, and none intended. It is read by seven
executors' `Gates::from_params` plus messaging, always as an independent field.
The per-subsystem authorization gates do not depend on it, and nothing orders it
against gates 12 or 13.

**Tests.** `healthcare_routing.rs:4357`, `:4448`, `messaging_routing.rs:1074`.
Closed-side pins: `docclass_routing.rs:2590`, `healthcare_routing.rs:3171`,
`legal_routing.rs:3207`.

**Risk if activated.** The broadest blast radius of the seventeen: time-dependent
rules across eight subsystems fire for the first time. Prescriptions that were
effectively fillable forever begin expiring; messaging quotas begin bucketing
per day. Anything that has been operating inside a window that never closed will
find it closing.

**Risk if deferred.** Every time window in eight subsystems evaluates at the
epoch, so validity and quota rules are inert.

---

### Gate 12 — `subsystem_tx_index_enabled_from_height`  *(cross-cutting)*
*accessor `subsystem_tx_index_activation`, `crates/state/src/lib.rs:133`*

**Behaviour enabled.** Doc (`genesis/src/lib.rs:917`): "Below the gate every
dispatch arm hands the subsystem executors a literal `0` where the transaction's
index within its block belongs. DocClass events are keyed
`height || tx_index || event_index` and messaging events
`recipient || height || tx_index`, so every event a block produces lands at one
key and only the LAST survives … At and above the gate each arm passes the
transaction's real index and the rows stop colliding." Switched in
`effective_tx_index` (`crates/state/src/lib.rs:152`), called from exactly two
dispatch arms (`executor.rs:450`, `:2124`).

**Data migration required.** No backfill, and **it is not recoverable**: events
overwritten below the gate are gone. Activation changes key shape and **row
count** for new blocks only.

**Mixed-version effect.** Row counts and therefore the block write set differ.
The source flags the consensus-visible consequence explicitly
(`crates/state/src/lib.rs:127-130`): "Opening it grows the candidate write set,
which has a ceiling that refuses a block rather than truncating it, so this is
consensus-visible even though nothing reads these rows back."

**This is the only one of the seventeen that can change whether a block is
admissible by VOLUME.**

**Rollback behaviour.** Per §0.4. Named in `activation_digest.rs:491`, `:544`.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None, deliberately. The accessor doc at
`crates/state/src/lib.rs:117-131` is an argument that 11 and 12 are *not* one
rule: "Two different blast radii; an operator must be able to take one without
the other."

**Tests.** `docclass_routing.rs:2799`, `:2853`, `:2898
execute_block_keys_each_docclass_event_by_its_own_transaction_index` (drives
real `ChainParams`), `messaging_routing.rs:1030`, `:1053`.

**Risk if activated.** Blocks near the candidate ceiling grow their write set and
may be refused where they previously fit.

**Risk if deferred.** The DocClass and messaging event families hold one row per
block and silently lose every earlier event in that block.

---

### Gate 13 — `subsystem_allocation_bound_enabled_from_height`  *(cross-cutting)*
*accessor `subsystem_allocation_bound_activation`, `crates/state/src/lib.rs:189`*

**Behaviour enabled.** Three pre-allocation checks fire
(`genesis/src/lib.rs:946`, accessor `crates/state/src/lib.rs:166-188`):

- a subsystem payload longer than `MAX_SUBSYSTEM_PAYLOAD_BYTES` (65,536,
  `lib.rs:212`) is refused **before decode**;
- a stored row whose encoding exceeds `MAX_ACCUMULATING_ROW_BYTES` (1,048,576,
  `lib.rs:232`) is refused **before decode**;
- an NFT `BatchMint` naming more than `MAX_NFT_BATCH_MINT_REQUESTS` tokens is
  refused before the owner-index rebuild loop.

Below the gate the release ceiling (`MAX_BLOCK_WRITE_SET_BYTES`, `1<<28`) bounds
what a block may *commit* and nothing about what one refused transaction may
*allocate*. Measured: one `AddKey` peaks at 4.00x the row size, churns 5.00x,
and grows the row by 1,899,873 bytes for one `min_fee`.

The limits are binary constants, not `ChainParams` fields, deliberately — the
genesis digest covers only `Option<u64>` gates.

**Data migration required.** No rewriting, but there is a **state-shape
consequence on existing rows**, documented at `crates/state/src/lib.rs:227-231`:
"A row already past this limit when the gate opens — there is no way to have one
except by writing it below the gate — becomes **unmodifiable** rather than
unreadable: the mutating operations refuse it with a failed receipt, reads are
untouched. A row may also overshoot by at most one payload, because the check
refuses the NEXT operation rather than the one that crossed."

**This specific case is the one thing in the seventeen with no dedicated test.**
`allocation_bound_gate.rs` seeds rows itself rather than exercising a
pre-existing over-limit row. Stated rather than implied.

**Mixed-version effect.** A previously-admitted oversized transaction becomes a
failed one. The blast radius is identical on the DocClass and NFT sides, which
is why it is one field.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None. Read by `DocClassGates::from_params`
(`docclass_executor.rs:112`) and `NftGates` (`nft_executor.rs:150,173`) from the
same field, precisely so the two subsystems cannot be split.

**Tests.** `allocation_bound_gate.rs:369 the_allocation_bound_gate_refuses_oversized_input_before_it_is_built`
— one `#[test]` by design, because a counting global allocator cannot share a
process. It covers the closed-vs-open pairs and asserts the open side refuses
having allocated at least 4x less and leaves the row byte-for-byte unchanged.
Measurement counterpart: `release_ceiling_allocation.rs`.

**Risk if activated.** Legitimate payloads above 64 KiB and any already-oversized
rows start receipt-failing; a handful of rows become permanently unmodifiable,
and nothing tests that path.

**Risk if deferred.** One `min_fee` transaction peaks above two gibibytes on its
way to being refused, and the row grows toward that in a few hundred blocks.
The clearest node-crash vector of the seventeen.

---

### Gate 14 — `tax_proof_lifecycle_enabled_from_height`
*accessor `TaxExecutor::proof_lifecycle_activation`, `crates/state/src/tax_executor.rs:147`*

> **See §0.7.** This is the gate whose field declaration was missing
> `#[serde(default)]` and whose documentation was spliced into gate 13's
> comment. Both were repaired while assembling this packet; the height decision
> below is unaffected, but anyone who read this field's documentation before
> that repair read gate 13's rule, not this one.

**Behaviour enabled.** Three defects, one height (OV-1/2/3), per
`genesis/src/lib.rs:983` and the accessor at `tax_executor.rs:127-146`:
`IssueClaim` is a blind overwrite — the proof id is sender-chosen, nothing checks
it is taken, so the replaced proof's subject-index entry points at a row whose
subject is now somebody else's; `RevokeClaim` reads its 32-byte payload as a
**proof id** while calling it a subject nullifier; and deleting a proof leaves
the `TAX_SUBJECT_INDEX` entry behind. Above the gate: a duplicate proof id is
refused, `RevokeClaim` resolves through the subject index and revokes every
proof for that subject, and deletions remove the matching index entry.

**Data migration required.** No backfill. Dangling `TAX_SUBJECT_INDEX` entries
and cross-subject index entries written below the gate persist
(`tax_routing.rs:1425-1434`: "the victim's index entry survives under either
gate"). Activation stops new ones; it does not repair old ones.

**Mixed-version effect.** Both sides driven over the same fixture; the index
contents differ (`vec![]` vs `vec![[1;32]]`).

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `tax_routing.rs:1354`, `:1440`. Closed-side pins named at `:1349-1350`:
`deleting_a_proof_leaves_the_subject_index_entry_behind`,
`revoke_claim_keys_the_proof_store_by_nullifier`.

**Risk if activated.** `RevokeClaim` **changes meaning**: a caller that passed a
proof id now gets a subject lookup. Existing revocation tooling would silently
target something different rather than error. Of the seventeen, this is the one
most likely to break a caller *quietly*.

**Risk if deferred.** Any active issuer can overwrite any proof, and the subject
index grows without bound pointing at rows that are gone.

---

### Gate 15 — `nft_token_authority_enabled_from_height`
*accessor `NftExecutor::token_authority_activation`, `crates/state/src/nft_executor.rs:235`*

**Behaviour enabled.** Three defects, one height (OV-12/13/14), per
`genesis/src/lib.rs:1020` and the accessor at `nft_executor.rs:215-234`:
`UpdateMetadata` accepts the token's **creator**, which never changes, so the
minter rewrites the metadata of a token it sold for the life of the token;
`locked` is read by transfer and burn only, so a locked token is still
approvable and rewritable; and `Approve` never reads the collection, so an
approval is recorded on a token in a collection that forbids transfers. Above
the gate: metadata rewrite requires the current owner, both `Approve` and
`UpdateMetadata` refuse a locked token, and `Approve` refuses a
non-transferable collection. Call sites `nft_executor.rs:906`, `:1011`.

**Data migration required.** No. Existing approvals recorded on soulbound tokens
below the gate are not swept.

**Mixed-version effect.** Both sides driven over identical fixtures in each test.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `nft_routing.rs:3282`, `:3354`, `:3436`. Closed-side pins: `:2205`,
`:2257`, `:2682 approve_never_reads_the_collection`.

**Risk if activated.** Minters lose a rewrite capability they have been
exercising; approvals on locked or soulbound tokens stop being creatable.

**Risk if deferred.** A minter can rewrite the metadata of any token it ever
sold, indefinitely.

---

### Gate 16 — `agreement_signature_integrity_enabled_from_height`
*accessor `AgreementExecutor::signature_integrity_activation`, `crates/state/src/agreement_executor.rs:207`*

**Behaviour enabled.** Two halves of one invariant (OV-28/29), per
`genesis/src/lib.rs:1054` and the accessor at `agreement_executor.rs:192-206`: a
signature naming a party the agreement does not bind is stored anyway and
rewrites the agreement row while flipping no flag; and `RevokeSignature` deletes
the signature row and leaves the party's `signed` flag set, so an agreement
stays `Executed` with the signature that executed it gone. Above the gate a
signature must name a bound party, and revoking one clears that party's flag and
walks an `Executed` agreement back to `PendingSignatures`.

**Data migration required.** No. Agreements already stranded in `Executed` with
missing signatures are **not** repaired — the gate changes future revocations
only.

**Mixed-version effect.** Both sides driven over identical fixtures.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None. `AgreementGates::from_params`
(`agreement_executor.rs:181`) reads signature_integrity and block_timestamp
independently.

**Tests.** `agreement_routing.rs:2735`, `:2824`.

**Risk if activated.** An agreement's status can now move **backwards**
(`Executed` → `PendingSignatures`). Any downstream consumer treating `Executed`
as terminal will not expect that.

**Risk if deferred.** `Executed` is not evidence of signature: the signature that
executed an agreement can be deleted and the status stays.

---

### Gate 17 — `healthcare_state_precondition_enabled_from_height`
*accessor `HealthcareExecutor::state_precondition_activation`, `crates/state/src/healthcare_executor.rs:239`*

**Behaviour enabled.** Two write arms that never read the row (OV-17/20), per
`genesis/src/lib.rs:1086` and the accessor at `healthcare_executor.rs:227-238`:
`RenewMembership` sets `status = Active` whatever the status was — reviving a
membership that was suspended, terminated or cancelled, and **bypassing
`ReinstateMembership`, which is the operation with a status guard on it**; and
`RemoveNetworkAffiliation`/`RemoveDependent` write the row and the index whether
or not the thing being removed was ever there, so removing an affiliation a
provider never had **creates an empty index row** and bumps `updated_at` on a
row nothing changed. Above the gate renewal refuses
`Cancelled`/`Terminated`/`Expired`, and both removals become no-ops. Call sites
`healthcare_view.rs:241`, `:427`.

**Data migration required.** No, but the empty index rows written below the gate
remain.

**Mixed-version effect.** One side writes a row and reports success, the other
writes nothing — `healthcare_routing.rs:3865` states it as exactly that.

**Rollback behaviour.** Per §0.4.

**Proposed height.** — owner decision — **UTC estimate.** convert at 57,400 blocks/day (§0.9); the owner sets the height first

**Dependencies.** None.

**Tests.** `healthcare_routing.rs:4542`, `:4647 an_active_membership_renews_under_either_gate`
(the must-not-break case), `:4707`. Closed-side pins: `:3088`, `:1723`.

**Risk if activated.** Renewal on a terminated membership starts failing, so any
flow that used renewal as an undo of termination must move to
`ReinstateMembership`.

**Risk if deferred.** Termination and cancellation are reversible by anyone who
can renew, and the removal arms write garbage index rows on every no-op.

---

## Part 2 — What the owner is actually being asked to decide

Restating, so the seventeen sections above are not mistaken for seventeen equal
decisions:

1. **One binary decision comes first.** Mainnet runs an older binary (§0.1a).
   None of the seventeen exists there. The rollout is binary-then-genesis, or
   the genesis edit is inert.

2. **One gate needs a data decision, not a height.** Gate 2 (docclass stake
   escrow): pre-gate stakes were burned, the escrow holds nothing for them, and
   post-activation `DeactivateIssuer` will try to withdraw from it. Four options
   are laid out in that section; the repository contains no answer.

3. **Three gates have a consequence beyond "the rule changes".**
   - Gate 12 can change block **admissibility** by write-set volume.
   - Gate 13 **freezes** any already-oversized accumulating row, and that path
     has no test.
   - Gate 14 **changes what an existing RPC argument means**, silently.

4. **Two gates are the big behavioural ones.** Gate 11 (eight subsystems start
   seeing real time) and gate 5 (seven healthcare authorization defects at
   once). Both are the kind that break integrations rather than attackers.

5. **The ordering is free.** No gate depends on any other (§0.5). The seventeen
   can be staged in any grouping the owner prefers — including one at a time,
   which the source explicitly argues for.

6. **Every height must be above the head at rollout, and is frozen once passed**
   (§0.2, §0.3). The safe form of the decision is "head at rollout + N", not an
   absolute number chosen today.

7. **Use 57,400 blocks/day, not 28,800** (§0.9). `block_time_ms: 3000` is a
   proposer slot, halved by two validators in round-robin; the measured interval
   is 1.502 s/block, confirming the 1,506 ms the account-root work already uses.
   `docs/operations/production-checklist.md` converts with the nominal 3 s and is
   therefore roughly 2x too long wherever it gives a date. A UTC schedule built
   on that conversion is a coordinated restart that misses.

## Part 2b — Three gates arrived after this packet was written

The packet covers seventeen. Twenty now exist: a later pass added the proof
presence, index-key bound, NFT update-path parity and no-op receipt gates, and
folded one constant into the protocol digest.

They are NOT scheduled below, and the omission is deliberate rather than an
oversight. Each needs the same treatment Part 1 gives the seventeen — behaviour
enabled, migration, mixed-version effect, rollback, risk if activated and risk
if deferred — and writing a wave for a gate that has not had that treatment is
exactly the shortcut this packet exists to prevent. By cost shape they belong in
Wave 1, which is where the next pass should propose them once each has its
section.

## Part 3 — The recommendation: three waves, one deferral

Part 1 gives the owner seventeen independent decisions. Part 2 says what is
being decided. This part is the answer a reviewer asked for: **the fewest waves
that are still safe, with heights.** It is a recommendation, not a setting — no
height is written anywhere in this branch.

### What actually constrains the grouping

§0.5 establishes there are **no dependencies among the gates**: any order is
legal, including all at one height. So the constraint is not correctness, it is
what happens when a wave turns out to be wrong. Two facts decide it:

1. **§0.3 — a height, once passed, is frozen.** Rollback is NOT "move the height
   back". A gate that has fired has fired, and the blocks produced under it are
   the chain. So "reversible" here means *reversible in effect*, not in
   configuration.
2. **Gates differ in what an error costs.** A gate that only REFUSES more
   transactions costs availability, is visible in the next block as failed
   receipts, and writes nothing new. A gate that changes WHERE A ROW LANDS
   writes rows that persist and cannot be unwritten. A gate that changes WHETHER
   A BLOCK EXISTS costs liveness.

Those three cost shapes are the waves. Grouping by subsystem would have been
tidier and would have mixed all three shapes into every wave.

### Wave 0 — compatibility enforcement (a prerequisite, not an activation)

The peer-compatibility enforcement height must be **at or below the first
behavioural activation below**, because from the moment any gate fires, an
undeclared peer is indistinguishable from an incompatible one. This is a
precondition on the schedule rather than a member of it.

### Wave 1 — refusal-only. Recommended height 13,775,436 (head + ~14 days)

Gates 4, 5, 6, 7, 8, 9, 10, 13, 14, 15, 16, 17.

Twelve gates whose entire effect is that some transactions which used to succeed
now produce a failed receipt: the six authorization gates, revocation standing,
the allocation bound, the tax proof lifecycle, NFT token authority, agreement
signature integrity, and the healthcare state preconditions.

  * **Data migration:** none. No existing row changes shape or location.
  * **Mixed-version:** prevented by Wave 0. Absent it, the two sides disagree
    about receipts, and receipts are folded into the state root, so they fork.
  * **Rollback:** none available (§0.3). The mitigation is that the failure mode
    is a refusal — an operation stops working, loudly, and the operator sees
    failed receipts in the next block rather than silent divergence.
  * **Why one wave and not twelve:** they share a failure shape and a diagnosis.
    If legitimate traffic starts failing, the failed receipt names the
    subsystem, so a twelve-gate wave is still diagnosable. That is the argument
    for bundling, and it holds only because of the receipt.

### Wave 2 — data shape. Recommended height 14,580,772 (head + ~28 days)

Gates 3, 11, 12.

The DocClass subject-index split, the block timestamp reaching eight
subsystems, and the transaction index in event keys.

  * **Data migration:** none required, and none possible. Rows written before
    the height keep their old shape; a collision committed before gate 3 fires
    stays collided. Gate 12 changes the number of rows a block writes — one per
    event rather than one per block — so **disk growth changes at this height**
    and that is the one number to watch.
  * **Mixed-version:** as Wave 1.
  * **Rollback:** none, and here it matters more: rows written under the new
    shape persist. This is the irreversible wave.
  * **Why separate from Wave 1:** Wave 1 writes nothing new. This one does, and
    permanently. Bundling them would make a disk-growth surprise indistinguishable
    from an authorization surprise.
  * **Why fourteen days after Wave 1:** long enough that Wave 1's refusal
    behaviour is observed across a full traffic cycle before anything
    irreversible is written.

### Wave 3 — block existence. Recommended height 14,983,440 (head + ~35 days)

Gate 1, `nft_receipt_failure_enabled_from_height`.

Alone, because it is the only gate whose disagreement means a node produces **no
block at all** rather than a different one. Below it, an NFT operation naming an
absent collection makes the whole block unexecutable; at and above, it is a
charged failed receipt.

  * **Data migration:** none. **Rollback:** none.
  * **Why last and alone:** it is the only gate that converts a liveness failure
    into a receipt. If it misbehaves the symptom is a proposer that cannot
    produce, which is the one symptom that must not be confused with anything
    else.

### Deferred — Gate 2, indefinitely, pending a decision this repository cannot make

`docclass_stake_escrow_enabled_from_height`. Part 1 records that it needs a data
decision the repo has no answer to: what happens to stake already destroyed
under the old rule. Activating it starts holding stake correctly and does
nothing about the stake already gone. **That is an owner decision about existing
value, not an engineering one, and it should not be bundled into a wave to make
a schedule look complete.**

### UTC estimates

At the **measured** 1.502 s/block and 57,524 blocks/day (§0.9 — not the nominal
3,000 ms, which is wrong by a factor of two and would double every estimate
here), from head ≈12,970,100 on 2026-09-18:

| wave | height | ≈ elapsed | ≈ UTC |
|---|---|---|---|
| 1 | 13,775,436 | 14 days | 2026-10-02 |
| 2 | 14,580,772 | 28 days | 2026-10-16 |
| 3 | 14,983,440 | 35 days | 2026-10-23 |

**Every height must be re-derived against the head at the moment of decision.**
These are anchored to a head measured on 2026-09-18 and drift by roughly 57,524
blocks per day of delay. A height that has already passed when the genesis is
written is refused at startup (§0.2), which is the safe direction.
