# Owner decision packet: the sixty-one activation heights

**This document sets no height.** No `genesis.json` in this branch is modified
by it, and neither release template (`genesis/mainnet_genesis.json`,
`genesis/testnet_genesis.json`) is touched. Every height below is the owner's
decision. What this document does is put, in one place, the facts each decision
needs.

It replaces an earlier packet that covered seventeen gates. `ChainParams` now
declares **sixty-three**. The set below is regenerated from the field
declarations in `crates/genesis/src/lib.rs`, which are the authority —
`ChainParams::activation_heights()` is generated from them and pinned to them by
test — and **not** from the previous document.

For every one of the sixty-one it covers, Part 1 states the six things the owner
asked for:

1. **affected behaviour** — what changes at the height;
2. **dependency ordering** — what `ChainParams::validate` actually constrains,
   read from the function rather than assumed;
3. **persistent data impact** — what is written differently, and forever;
4. **rollback in effect** — a passed height is FROZEN, so this is what an
   operator can actually do, not "move the height back";
5. **monitoring signal** — the instrument that would show it working, and the
   instrument that would show it misbehaving, named where it exists and named
   as absent where it does not;
6. **recommended wave**.

---

## Part 0a — Two gates arrived after this packet was regenerated

`ChainParams` now declares **sixty-three**. This packet covers sixty-one, and
the two it does not cover are named here rather than left to be discovered by
counting:

  * `subsystem_proof_unsupported_enabled_from_height` — every `VerifyProof` arm
    refuses as unsupported. It also RETIRED `subsystem_proof_presence_enabled_from_height`,
    which still has a section below; that section now describes a gate that
    decides nothing, and a test pins that setting it changes no behaviour.
  * `subsystem_tx_write_set_bound_enabled_from_height` — a per-transaction
    bound on the overlay charge.

**Neither is scheduled below, and that is deliberate.** Each needs the same six
fields Part 1 gives the other sixty-one — behaviour, dependency ordering,
persistent data impact, rollback-in-effect, monitoring signal, recommended wave
— and scheduling a gate that has not had that treatment is the shortcut this
packet exists to prevent. The same note appeared in the previous edition for
three gates, and those three were given their treatment before being scheduled;
these two should be handled the same way.

Nine gates arrived in the wave that outran the previous edition of this
document. **Seven of them were written up** — R29 to R35, in Part 1A — and the
two above are what was left. **A release-closure wave has since added five more,
and they did NOT join that deficit**: R36 to R40 arrive with their six fields
already written, which is the standing this section exists to require. The
deficit is therefore unchanged at two, and it is the same two.

This is the second time a wave has outrun this document, and the third wave did
not. The count in a sentence is not checkable by any tool here, which is why the
two uncovered gates are named: a reader can verify the claim against
`tools/lane-b/gate-structure-check.py`'s output without recounting prose.

## Part 0 — The facts that apply to all sixty-one

### 0.1 How the authoritative list was established

Not by reading the old packet, and not by reading prose. The field declarations
are parsed out of the source and set-compared against the two closed lists:

```bash
cd <worktree>
python3 - <<'EOF'
import re
src = open('crates/genesis/src/lib.rs').read()
gates = re.findall(r'^\s+pub ([a-z_0-9]+): Option<u64>,', src, re.M)
def const(name):
    m = re.search(r'pub const ' + name + r': &\[&str\] = &\[(.*?)\];', src, re.S)
    return re.findall(r'"([a-z_0-9]+)"', m.group(1))
rem = const('REMEDIATION_GATES')
pre = const('GATES_PREDATING_ACTIVATION_RECORDING')
print("total", len(gates), "remediation", len(rem), "predating", len(pre))
print("overlap", set(rem) & set(pre))
print("neither:", [g for g in gates if g not in rem and g not in pre])
print("named but not declared:", [g for g in rem + pre if g not in gates])
EOF
```

Output, reproduced on this tree:

```
total 63 remediation 42 predating 18
overlap set()
neither: ['account_root_enabled_from_height', 'application_journal_enabled_from_height', 'peer_protocol_declaration_required_from_height']
named but not declared: []
```

**63 = 42 + 18 + 3, with no overlap and no orphan.** That is the partition Part 1
uses, and every gate is placed in exactly one of the three classes:

| class | count | what it means | source of truth |
|---|---:|---|---|
| **REMEDIATION** | 42 | produced by the activation audit; each closes a defect; every one dormant | `crates/genesis/src/lib.rs` `REMEDIATION_GATES`, cross-pinned to the 42-row `WIRING` table in `crates/state/tests/remediation_gates.rs` |
| **PREDATING** | 18 | shipped in binaries that produced existing blocks; grandfathered, may legally sit below the head | `crates/genesis/src/lib.rs:2783 GATES_PREDATING_ACTIVATION_RECORDING` |
| **NEITHER** | 3 | introduced by this work, but not remediation: they add or constrain machinery rather than repair a defect | the complement, computed above |

**The packet covers 61 of the 63: 40 + 18 + 3.** The two remediation gates it
does not cover are named in Part 0a, so `40 + 2 = 42` closes the remediation
column and nothing is unaccounted for. Part 1A holds the 40, Part 1B the 18,
Part 1C the 3.

The `WIRING` table was independently extracted and compared:

```bash
python3 -c "
import re
s = open('crates/state/tests/remediation_gates.rs').read()
m = re.search(r'const WIRING: &\[\(&str, &str, &str\)\] = &\[(.*?)\n\];', s, re.S)
rows = re.findall(r'\(\s*\"([^\"]+)\",\s*\"([^\"]+)\",\s*\"([^\"]+)\",?\s*\)', m.group(1))
print(len(rows))"
# 42
```

42 rows, matching `REMEDIATION_GATES` element for element. The accessor each
names is cited per gate in Part 1.

### 0.2 The live chain, re-derived today

The endpoint is reachable from this machine and was queried rather than
remembered.

```
$ date -u +"%Y-%m-%dT%H:%M:%SZ"
2026-09-19T05:35:38Z

$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sum_blockNumber","params":[]}'
{"jsonrpc":"2.0","result":12977656,"id":1}

$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHeight","params":[]}'
{"jsonrpc":"2.0","result":{"height":12977656,"finality":"latest"},"id":1}
```

**HEAD = 12,977,656 at 2026-09-19T05:35:38Z (mainnet, `chain_id: 1`).**
Every height in Part 3 is anchored to that number and that instant.

**The deployed binary is older than this tree.** Two methods this tree ships
answer `Method not found` on mainnet, re-verified today:

```
chain_getSyncCapability   → {"code":-32601,"message":"Method not found"}
chain_getActivationStatus → {"code":-32601,"message":"Method not found"}
```

So every activation below is a **binary rollout first, genesis edit second**. A
height set in a genesis that no deployed binary reads is a number nothing does.

**`chain_getChainParams` serialises 6 of the 63.** The live response carries
`v2`, `omninode`, `education`, `governance`, `monetary_policy` and
`service_grants` heights and no others. The remaining 52 — including all 37
remediation gates and all 3 of the "neither" class — are invisible from outside
a node on the deployed binary. `chain_getActivationStatus`
(`crates/rpc/src/server.rs:1567`) is this tree's answer to that and is the
single most important thing in the rollout, because it is what lets an operator
confirm before the height arrives that every validator holds the same
configuration. It is not deployed yet.

### 0.3 The block interval, measured three ways

`block_time_ms` is **3000** in the committed `genesis.json` and in the live
`chain_getChainParams`. **Using it as the block interval is wrong by a factor of
two.** It is the interval a proposer waits for its own slot; PoA is round-robin
and mainnet has two validators, so blocks arrive at half that.

Three independent derivations today:

| method | window | result |
|---|---|---|
| chain timestamps, `sum_getBlockByHeight` 12,877,656 → 12,977,656 | 100,000 blocks | 150,000.000 s → **1.5000 s/block**, 57,600 blocks/day |
| chain timestamps, 12,377,656 → 12,977,656 | 600,000 blocks | 905,691.433 s → **1.5095 s/block**, 57,236 blocks/day |
| wall-clock sampling, `sum_blockNumber` 240 s apart | 161 blocks | **1.4920 s/block**, 57,910 blocks/day (±1 block ⇒ ±0.6 %) |

```
$ curl -s https://rpc.sumchain.io -H 'content-type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"sum_getBlockByHeight","params":[12877656]}'
  … "timestamp":1789646137430 …
$ curl -s … '{"…","method":"sum_getBlockByHeight","params":[12977656]}'
  … "timestamp":1789796137430 …
(1789796137430 - 1789646137430) / 100000 = 1500.0 ms
```

All three bracket **1.502 s/block and 57,524 blocks/day**, which is the figure
this document converts with and the figure the repository already carries
(`docs/operations/ACCOUNT-ROOT-ACTIVATION.md:39-43`, `crates/state/src/account_root.rs:93`,
both at 1,506 ms). **57,524 blocks/day, not 28,800.** Any UTC estimate taken
from `block_time_ms` — including the one at
`docs/operations/production-checklist.md:136-140` — is roughly twice as long as
it should be.

**The interval is a function of the validator count, not a constant.** A third
validator changes it and every UTC estimate here moves; the heights do not. The
safe form of the decision is *head at rollout + N blocks*, converted to UTC only
for communication, with the interval re-measured immediately before the
coordinated restart.

### 0.4 The hard floor: strictly above the head, for 45 of the 63

On the **first start** of an upgraded node there is no recorded activation
history to compare against — `ACTIVATION_META_KEY` (`crates/node/src/node.rs:432`)
does not exist in the deployed binary, so every upgrading node takes this branch
exactly once. `ChainParams::retroactive_gates_on_a_first_start`
(`crates/genesis/src/lib.rs:2879`) then asks the only question still answerable:

- a gate on `GATES_PREDATING_ACTIVATION_RECORDING` (the 18) **may** sit at or
  below the head — it shipped in the binary that produced those blocks;
- any of the other **45** at or below the head is `RetroactivelyOpened` and the
  node **refuses to start**, naming the gate
  (`crates/node/src/node.rs:486-503`).

The boundary is exact: at the head is still retroactive (that block exists);
head + 1 is a scheduled activation. Pinned by
`crates/genesis/tests/activation_digest.rs:525 a_newly_introduced_gate_below_the_head_refuses_a_first_start`.

**With the head at 12,977,656 and rising 57,524/day, every height chosen for the
42 remediation gates and the 3 "neither" gates must still be above the head at
the moment the coordinated restart happens** — with margin enough that the chain
does not cross it while the rollout is in progress.

### 0.5 A height, once passed, is frozen — and exactly when it unfreezes

On a subsequent restart `ChainParams::activation_changes`
(`crates/genesis/src/lib.rs:2816`) classifies each moved gate against the
recorded value and **the database's current head**:

| classification | condition | startable? |
|---|---|---|
| `Retuned` | neither the old nor the new height is at or below the head | **yes** — "noisy, and legitimate" |
| `AlreadyActive` | the recorded height is at or below the head | **no** |
| `RetroactivelyOpened` | the recorded height was ahead (or absent) and the new one is at or below the head | **no** |

`ActivationChange::is_permitted` returns true for `Retuned` only.

**A correction to the previous packet.** It stated that rolling the chain below
`h` "does not make `h` re-editable" and that such a restart is `AlreadyActive`.
That is not what the code does. The test is

```rust
if matches!(before, Some(h) if h <= current_height) { AlreadyActive }
```

— `current_height` is the database's present head. If the head is rolled back
below `h`, the condition is false, and a genesis carrying a different height for
that gate classifies as `Retuned` and **is permitted**, provided the new height
is also above the rolled-back head.

That does not make rollback an operational lever, and §0.6 says why. It makes
the frozen-height property precise: **a height is frozen while the chain's head
is at or above it, and unfreezes only if every validator's database is rolled
back below it** — which is a reorg past `finality_depth: 6`, i.e. a decision to
abandon finalised blocks, not an operation.

### 0.6 What "rollback" can actually mean, per cost shape

No gate has rollback machinery. Every one is a pure function of
`(params, block_height)` — `matches!(activation(params), Some(h) if block_height >= h)`
— and `crates/state/src/reorg_undo.rs` contains no gate references. A reorg
below `h` re-executes those blocks with the gate closed, which is how they were
produced; a reorg across `h` re-executes each block under the rule for its own
height. Both are consistent. None of that is a rollback of the *decision*.

So "rollback in effect" in Part 1 means one of exactly five things, and each
gate's entry says which apply:

| code | what an operator can actually do | costs |
|---|---|---|
| **A** | stop submitting the affected transaction shape | nothing written is undone; only stops adding to it |
| **B** | ship a **superseding gate at a later height** — a second, forward activation that narrows or replaces the rule | another coordinated rollout; history above `h` keeps the rule it was produced under |
| **C** | keep the **dual-read path** alive permanently, because rows written under the old shape are still there and are not rewritten | a permanent maintenance obligation, not a repair |
| **D** | a **governance transaction** to move value that the gate moved | validator quorum at 6667 bps — on the current two-validator net, both must sign |
| **E** | a **chain-wide rollback below `h` on every validator**, which unfreezes the height (§0.5) | abandons finalised blocks; a social decision, not an operational one |

**B is the realistic one for almost every gate.** A is available for the refusal
shapes. C is an obligation rather than an action. D is available only where the
gate moved balances. E exists and should be understood as the thing it is.

### 0.7 Dependency ordering — read from `ChainParams::validate`, not assumed

`ChainParams::validate` (`crates/genesis/src/lib.rs`) constrains exactly
**five** things. There are no others; every other gate is independent of every
other gate at load time. It constrained four until the release-closure wave
added rule (5), which is the one ordering this packet previously described as a
soft one the code could not enforce — see R30's field 2, which has been corrected
rather than left standing.

**(1) `compute_pool_enabled_from_height` must be `None`.** Any `Some(_)` is
`GenesisError::IncompleteSubsystemActivation`. Not schedulable.

**(2) `beacon_enabled_from_height` must be `None`.** Same. Declaring
`beacon_params` or `beacon_schedule` does **not** open it; those are validated
for internal consistency and the gate stays refused.

**(3) The undo-before-commitment ordering:**

```
application_journal_enabled_from_height <= account_root_enabled_from_height
```

with `(None, Some(account_root))` refused as `AccountRootWithoutJournalGate` and
`(Some(journal), Some(account_root)) if journal > account_root` refused as
`JournalGateAfterAccountRoot`. Both `None` is legal and is the production
default. The argument, from the source: above the account-root gate a node that
cannot RESTORE account rows during a reorg cannot agree about the root either,
and `None` on the journal gate means "observed from chain" — each node's own
first journalled height — which is fine for node-local undo and not fine once
consensus output depends on it, because two validators would hold different
boundaries and find out at a reorg.

**(4) The enforcement-before-divergence ordering:**

```
peer_protocol_declaration_required_from_height <= min(height of any open REMEDIATION_GATES)
```

with `(None, Some((gate, height)))` refused as
`RemediationGateWithoutPeerProtocolEnforcement` and enforcement later than the
floor refused as `PeerProtocolEnforcementAfterRemediationGate`. Both `None` is
legal and is the production default. The floor is computed by
`ChainParams::remediation_activation_floor()` (`:2593`), which iterates
`REMEDIATION_GATES`. The argument, from the source: below the first remediation
activation every node executes the same rules, so admitting a peer that declared
nothing costs nothing; at that height the rules diverge and an undeclared peer
becomes indistinguishable from one running the unremediated binary.

**(5) The healthcare consent-grant ordering:**

```
healthcare_authorization_enabled_from_height <= healthcare_consent_subject_signature_enabled_from_height
```

with `(None, Some(grant))` refused as
`ConsentGrantGateWithoutHealthcareAuthorization` and
`(Some(authorization), Some(grant)) if authorization > grant` refused as
`HealthcareAuthorizationAfterConsentGrantGate`. Both `None` is legal and is the
production default; authorization alone is legal and is strictly stronger than
the default. The argument, from the source: the grant gate makes `GrantConsent`
carry the subject's own signature, and it does not reach `SupersedeConsent`,
which is gated by the AUTHORIZATION height and below it checks nothing about the
sender — so the same record is minted by another arm. `None` there is not
"later", it is never, so the second route would stay open at every height above
the grant gate rather than for a bounded band.

**This is the only rule in this section that constrains two REMEDIATION gates
against each other**, and the sentence in Part 1A's preamble that says no
remediation gate is ordered against another at load time no longer holds without
this exception.

**All of these are LOAD-time checks**, so an inconsistent pair is refused before a block
executes rather than at the boundary a hundred thousand blocks later.

**Consequence for the owner.** Among the 37 remediation gates there is no
ordering constraint whatever: any order, including all at one height, is legal,
and the deliberately-separate fields (e.g. `subsystem_block_timestamp` vs
`subsystem_tx_index`; `nft_receipt_failure` vs `nft_charged_receipt`) exist so
they can be sequenced independently. The only two orderings in the whole system
are (3) and (4), and (4) binds the remediation set as a block: **setting any one
of the 37 forces `peer_protocol_declaration_required_from_height` to be set, at
or below the earliest of them.** That is why Part 3 has a Wave 0.

### 0.8 What can actually be monitored, and what cannot

Named once here, referenced per gate in Part 1.

| id | instrument | where | status |
|---|---|---|---|
| **M1** | `chain_getActivationStatus` → `digest`, `protocol_digest`, `current_height`, `gates[] = {gate, height, active}` | `crates/rpc/src/server.rs:1567`, `crates/rpc/src/types.rs:743` | **in this tree; `Method not found` on mainnet today.** The only per-gate fired/not-fired signal, and the only cross-node agreement check |
| **M2** | `sumchain_block_height`, `sumchain_blocks_produced_total` | `crates/rpc/src/metrics.rs` | exists — liveness; flat means blocks stopped |
| **M3** | `sumchain_block_errors_total` | `metrics.rs`, incremented at `crates/node/src/node.rs:795,801,924,937` | exists and is live |
| **M4** | `sum_getReceipt` (per transaction hash) | `crates/rpc/src/api.rs:202` | exists. **There is no per-block receipts method and no failed-receipt counter**, so watching a refusal-shape gate means walking transactions |
| **M5** | `chain_getSyncCapability.account_rows` | `crates/rpc/src/server.rs:1608` | in this tree; absent from the deployed binary. The row-count signal |
| **M6** | subsystem read RPCs — `docclass_getCredentialsBySubject`, `docclass_getIdentity`, `nft_getTokensInCollection`, `nft_getTokensByOwner`, `tax_listClaimTypes`, `legal_getCase`, `agreement_getExecutorLinksByAgreement`, … | `crates/rpc/src/api.rs` | exist and are deployed. The way to check a known row still reads after a shape change |
| **M7** | `chain_getSupplyInfo.accounted_account_supply` | deployed | the money-supply signal |
| **M8** | `sumchain_peer_count`, `get_peers` | deployed | peer admission |
| **M9** | node log: `warn!("Activation parameter changed (permitted): …")` and `info!("Genesis activation digest … N gates set: …")` | `crates/node/src/node.rs:514,545` | exists; fires once per start |

**Two counters an operator would reach for first are dead.**
`sumchain_tx_execution_errors_total` has **no call site anywhere outside its own
definition**; `sumchain_tx_validation_errors_total` has exactly one, inside a
`#[test]` in `metrics.rs:479`. Verified by grep across `crates/`. So the natural
metric for "did this gate start refusing traffic" does not increment, and M4 —
one RPC call per transaction hash — is what is left. **This is the single
largest monitoring gap in the rollout, and it applies to the nineteen
refusal-only gates as a class.**

There is also no `sumchain_account_rows` gauge, no alert rule
(`deploy/monitoring/prometheus.yml` has `rule_files: []`), and no Grafana panel
for any of this.

### 0.9 How an activation is actually deployed

From `docs/operations/production-checklist.md:27-40` and `RELEASE.md`:

- Production validators boot from the **root runtime `genesis.json`**, not from
  `genesis/mainnet_genesis.json`, whose first key says "TEMPLATE ONLY".
- Heights are "edited into each validator's runtime genesis identically, never
  into the template".
- "Confirm the `genesis.json` on every validator hashes identically before
  starting or restarting the network." M1's `digest` is the machine-checkable
  form of that sentence and is not deployed yet.
- PoA round-robin has **no proposer-skip**, so restarting a validator stalls its
  slots until it rejoins. Rolling restarts are one validator at a time.
- Governance authority is validator-quorum at 6667 bps: on the current
  two-validator net, **both** validators must sign.

The committed `genesis.json` in this tree carries no activation fields at all.
The deployed file is that base plus edits, and the edited file is not in this
tree.

### 0.10 Dormancy today

All 37 remediation gates and all 3 "neither" gates default to `None`
(`crates/genesis/src/lib.rs:2082-2136`), pinned by
`crates/state/tests/remediation_gates.rs:379 every_remediation_gate_is_dormant_by_default`,
which asserts the list length matches the 37-row `WIRING` table. Three further
guards run in the default gate: `every_remediation_gate_reads_the_field_it_names` (`:280`)
(source-level accessor/field pairing — the realistic bug in 37 near-identical
three-line functions is two of them reading each other's field),
`the_thirty_seven_gates_are_thirty_seven_distinct_fields` (`:361`), and
`a_genesis_written_before_these_fields_still_parses_dormant` (`:550`). And
`crates/genesis/tests/activation_digest.rs:47 every_activation_height_is_covered_by_the_digest`
scans the source for every `pub *_from_height: Option<u64>` declaration and
asserts set-equality with `activation_heights()` in both directions.

### 0.11 Source defects found while regenerating this packet

Reported, not repaired: this branch is documentation-only and does not modify
`crates/`.

**(a) Four gate doc comments in `crates/genesis/src/lib.rs` are attached to the
wrong field, and two gates carry only another gate's documentation.**

The previous packet recorded one instance of this (`tax_proof_lifecycle`, §0.7
of that document, since repaired). It has recurred, larger. Verified by parsing
each field's contiguous preceding doc block:

| field | line | topic sentence of the doc block above it | whose body that is |
|---|---:|---|---|
| `docclass_issuer_authority_enabled_from_height` | 1442 | "A DocClass issuer stops being the author of its own authority." (1374) | its own — **followed by a stray second body**, the NFT charged-receipt text at 1411-1441 |
| `nft_charged_receipt_enabled_from_height` | 1509 | "A DocClass credential's revocation history is a history." (1444) | **belongs to `docclass_revocation_record`**; its own body follows at 1478-1508 |
| `docclass_revocation_record_enabled_from_height` | 1538 | "The two NFT token indexes empty the same way." (1511) | **belongs to `nft_index_symmetry`. This field has no documentation of its own anywhere above it.** |
| `nft_index_symmetry_enabled_from_height` | 1655 | "A DocClass identity root records what the chain decided…" (1593) | **belongs to `docclass_identity_binding`**; its own body follows at 1628-1654 |
| `docclass_identity_binding_enabled_from_height` | 1691 | "An NFT collection id stops being a function of the block clock alone." (1657) | **belongs to `nft_collection_id_nonce`. This field has no documentation of its own anywhere above it.** |
| `nft_collection_id_nonce_enabled_from_height` | 1767 | "An NFT collection id stops being a function of the block clock alone." (1733) | its own — but byte-for-byte identical to the block above line 1691 |

Reproduce:

```bash
grep -n "An NFT receipt reports the fee\|revocation history is a history\|\
two NFT token indexes empty\|identity root records what the chain\|\
collection id stops being a function\|author of its own authority" \
  crates/genesis/src/lib.rs
```

Three bodies (NFT charged receipt, NFT index symmetry, NFT collection-id nonce)
appear **twice each**; two bodies (DocClass revocation record, DocClass identity
binding) appear once and on the wrong field. The pattern is a merge that spliced
two branches' additions in the middle of a run of doc blocks.

**This is not a behavioural defect.** `#[serde(default)]` is present on all of
them, the field names are correct, the digest order is correct, and
`REMEDIATION_GATES` names all of them. It is worse than that in one specific
way, which is the same way the previous instance was worse: **the documentation
an operator reads before setting a consensus activation height describes a
different rule.** For `docclass_revocation_record_enabled_from_height` and
`docclass_identity_binding_enabled_from_height` there is no correct text at the
field at all.

**The accessor doc comments in `crates/state/` are correct** — verified for all
six — so Part 1 sources those gates' behaviour from the accessors
(`crates/state/src/nft_executor.rs:337,360,383` and
`crates/state/src/docclass_executor.rs:317,343,394`) rather than from
`genesis/src/lib.rs`. That is the authoritative text for those six until the
splice is repaired.

**(b) Three stale counts in comments.**
`crates/state/tests/remediation_gates.rs:1` says "twenty-five remediation gates";
`:487` says "exactly these twenty fields"; `crates/genesis/src/lib.rs:1363` and
`:2579` say "the twenty `REMEDIATION_GATES`". The slice holds **28** and every
enforcement iterates the slice, so behaviour is correct and only the prose is
wrong. Named because §0.7's ordering rule (4) is stated in one of those
comments, and a reader counting twenty would under-state what the rule binds.

### 0.12 What remains UNPROVEN in this packet

| gap | what would settle it |
|---|---|
| whether the deployed validators can run this tree's binary at all | a testnet rollout of this binary against a copy of mainnet state |
| whether any gate has an operational consumer (tooling, indexers) that would break | not answerable from this repository |
| `docclass_stake_escrow`'s migration decision | an owner decision about existing value; see Part 3 |
| `subsystem_allocation_bound`'s effect on rows that are **already** oversized | no test covers it; `allocation_bound_gate.rs` seeds its own rows |
| the production `cf::STATE` row count, which gates `account_root_enabled_from_height` | `docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md §1.5` — external dependency, with an acceptance threshold |
| height→UTC after the validator set changes | §0.3 is settled for the current two-validator set; re-measure if it changes |
| the refusal-rate signal for the 19 refusal-only gates | §0.8 — the two obvious counters are dead; either wire them or accept M4 |

---
## Part 1A — The 40 REMEDIATION gates

Every one is dormant (`None`) today. Every one is absent from `chain_getChainParams`, so its height is invisible from outside a node until `chain_getActivationStatus` is deployed (§0.2). Every one is subject to the §0.4 floor: **strictly above the head**.

`REMEDIATION_GATES` holds 42; the 40 below are all of them except the two that Part 0a names as deliberately uncovered, which are not scheduled here.

**Exactly ONE pair of remediation gates is ordered against another at LOAD time**, and it is §0.7 rule (5): `healthcare_authorization_enabled_from_height` (R5) must be at or below `healthcare_consent_subject_signature_enabled_from_height` (R30). Every other remediation gate is independent of every other at load time. The constraint that touches all of them is §0.7 rule (4): opening ANY of them forces `peer_protocol_declaration_required_from_height` to be set at or below the earliest. **Two soft orderings are noted — R17 and R24 — arguments from the source, not load-time refusals.** R30's used to be the third and is now rule (5): a genesis that opens it over a closed R5 is refused, on the genesis path and on the restart path alike.

---

### R1 — `nft_receipt_failure_enabled_from_height`
*accessor `NftExecutor::receipt_failure_activation, crates/state/src/nft_executor.rs:252`* — cost shape **BLOCK EXISTENCE**

**1. Affected behaviour.** Below the gate an NFT operation that violates a block-level rule — a bad royalty, a sender drained inside the block — returns `StateError::BlockValidation` and makes the WHOLE BLOCK unexecutable. At and above it the same conditions produce a `Failed` receipt that charges the sender and leaves the block valid. The conversion is deliberately narrow: storage and encoding errors are node-local faults and still abort the block; only conditions an ordinary sender chooses from its own payload are converted (`as_receipt_failure`, `crates/state/src/nft_executor.rs:398`).

**2. Dependency ordering.** None. Deliberately NOT shared with `nft_charged_receipt_enabled_from_height`: that gate changes a number in a receipt of a block that exists either way, this one decides whether the block exists. The source says an operator must be able to sequence them.

**3. Persistent data impact.** A failed receipt row and a fee debit exist where previously no block existed at all. The receipt is folded into the receipts root, so the block hash differs.

**4. Rollback in effect.** **B and E only.** A is useless — the sender choosing the payload is the adversary. If the gate misbehaves the symptom is a proposer that cannot produce; the only forward fix is a superseding gate (B) that re-narrows `as_receipt_failure`, and the only backward one is E.

**5. Monitoring signal.** **M2 is the signal: `sumchain_block_height` stops advancing and `sumchain_blocks_produced_total` goes flat.** M3 (`sumchain_block_errors_total`) rising while M2 is flat is the unambiguous form. Working looks like M2 unchanged and M4 showing charged failed receipts on NFT transactions that previously killed blocks. **This is the only gate in the 40 whose misbehaviour is a liveness failure**, which is why it must not share a height with anything else.

**6. Recommended wave.** Wave 3. **Proposed height:** — owner decision —

---

### R2 — `docclass_stake_escrow_enabled_from_height`
*accessor `DocClassExecutor::stake_escrow_activation, crates/state/src/docclass_executor.rs:231`* — cost shape **VALUE MOVEMENT**

**1. Affected behaviour.** Below the gate the stake debited at registration is credited to nobody and leaves the money supply. At and above it the stake is held by a keyless escrow address — `blake3("sumchain/docclass/issuer-stake-escrow/v1")`, `DOCCLASS_STAKE_ESCROW_DOMAIN`, `crates/state/src/docclass_executor.rs:37` — and refunded exactly once on deactivation. Three call sites: credit on register, `UpdateIssuer` may no longer restate `stake_amount`, refund-and-zero on deactivate.

**2. Dependency ordering.** None at load. It has a **data** dependency on a decision that does not exist in this repository — see Part 3. Note `docclass_issuer_authority_enabled_from_height`'s source calls this gate "the stake half of the same wholesale write", so the two are conceptually paired even though neither constrains the other.

**3. Persistent data impact.** An escrow account balance row is written and later drawn down. The total money supply stops shrinking at each registration. This is ordinary account state and is folded by the account digest if `account_root_enabled_from_height` is ever opened.

**4. Rollback in effect.** **D, and only D.** Value that moved cannot be moved back by a gate; a governance transaction at validator quorum is the only instrument. B cannot help — a superseding gate stops future escrow, it does not restore a refund that failed.

**5. Monitoring signal.** **M7 (`chain_getSupplyInfo.accounted_account_supply`) is the signal**: below the gate it falls at every DocClass issuer registration; at and above it stops falling. Misbehaving looks like `DeactivateIssuer` transactions failing on `InsufficientBalance` against the escrow address (`v_deduct`, `crates/state/src/state.rs:208`) — visible only through M4, one receipt at a time, because no counter exists.

**6. Recommended wave.** **NONE — DEFERRED INDEFINITELY.** This gate is not in
a wave and deliberately has no proposed height: it is blocked on an owner
decision about value that has already been destroyed, not on a schedule. See
Part 3.1, which carries the reasoning forward in full.

---

### R3 — `docclass_subject_index_split_enabled_from_height`
*accessor `DocClassExecutor::subject_index_split_activation, crates/state/src/docclass_executor.rs:262`* — cost shape **KEY SPACE**

**1. Affected behaviour.** Below the gate the DocClass identity index shares a 32-byte key space in which two different subjects can collide. At and above it writes use a tagged 33-byte key no legacy key can equal. **Reads still fall back to the legacy key**, so a collision committed before activation stays collided.

**2. Dependency ordering.** None.

**3. Persistent data impact.** New rows land at 33-byte keys; old rows keep their 32-byte keys and their bytes. The index permanently holds two key widths. Row count grows where a collision previously merged two subjects into one row.

**4. Rollback in effect.** **C is mandatory and permanent** — the dual-read path is the design, not a transitional measure, and removing it later would orphan every pre-gate row. B could add a third width; nothing removes the second.

**5. Monitoring signal.** **M5 (`chain_getSyncCapability.account_rows`) does not cover this family**, so the signal is M6: `docclass_getIdentity` / `docclass_getIdentityByController` must keep answering for identities anchored before the height, and must start distinguishing two subjects that previously returned the same row. Misbehaving looks like a pre-gate identity becoming unreadable — which is the dual-read path failing, and is silent in every metric.

**6. Recommended wave.** Wave 2a. **Proposed height:** — owner decision —

---

### R4 — `docclass_revocation_standing_enabled_from_height`
*accessor `DocclassExecutor::authorization_activation, crates/state/src/docclass_executor.rs:292`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate revocation standing is unchecked: any sender can revoke any DocClass credential. At and above it only the issuer may.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R5 — `healthcare_authorization_enabled_from_height`
*accessor `HealthcareExecutor::authorization_activation, crates/state/src/healthcare_executor.rs:219`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate the authorization rules in the Healthcare specification are not enforced, so an operation can be performed by a party with no standing to perform it — any funded account can fill any prescription. At and above it the operation checks the authority it was specified with.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R6 — `legal_authorization_enabled_from_height`
*accessor `LegalExecutor::authorization_activation, crates/state/src/legal_executor.rs:216`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate Legal consolidate, transfer and supersession accept any sender. At and above it supersession is three conditions and not one: the sender must hold the old record, the replacement must be issued by the sender, and it must concern the same subject — otherwise supersession is a way to overwrite someone else's court order.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R7 — `finance_authorization_enabled_from_height`
*accessor `FinanceExecutor::authorization_activation, crates/state/src/finance_executor.rs:205`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate a finance issuer's revocation is recorded and then ignored by the operations that should consult it. At and above it a revoked finance issuer stops being an issuer.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R8 — `employment_authorization_enabled_from_height`
*accessor `EmploymentExecutor::authorization_activation, crates/state/src/employment_executor.rs:182`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate an employment issuer's revocation is recorded and then ignored. At and above it a revoked employment issuer stops being an issuer, and suspended issuers stop holding full mutation rights.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R9 — `property_authorization_enabled_from_height`
*accessor `PropertyExecutor::authorization_activation, crates/state/src/property_executor.rs:220`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate a Property operation need not be performed by a party the row or the registry gives standing to — any funded account can rewrite a property title history. At and above it the operation binds to the row and the registry.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R10 — `tax_authorization_enabled_from_height`
*accessor `TaxExecutor::authorization_activation, crates/state/src/tax_executor.rs:141`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Below the gate a Tax operation need not be performed by a party the row or the registry gives standing to; the chain-wide claim-type registry is world-writable. At and above it the operation binds to the row and the registry.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead; the state it would have written is simply not written.

**4. Rollback in effect.** **A and B.** Stop submitting the refused shape, or ship a superseding gate at a later height that narrows the authority rule. Nothing written under the gate needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on the subsystem's transactions — a failed receipt naming the subsystem is the working signal and the misbehaving signal, distinguished only by whether the refused sender had legitimate standing. **No counter exists** (§0.8: `sumchain_tx_execution_errors_total` is dead), so this is per-transaction inspection. M1 `gates[].active` confirms the gate fired at all. M6 confirms the rows it protects still read.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R11 — `subsystem_block_timestamp_enabled_from_height`
*accessor `subsystem_block_timestamp_activation, crates/state/src/lib.rs:91`* — cost shape **ROW CONTENT**

**1. Affected behaviour.** Below the gate eight subsystems are handed a literal `0` where the block's timestamp belongs, so every time-dependent rule in them evaluates at the epoch — a prescription validity window is checked at time zero. At and above it they receive the real block timestamp.

**2. Dependency ordering.** None at load. But `docclass_identity_binding_enabled_from_height`'s source names this gate explicitly as a reason it does NOT write `created_at`/`updated_at`: "the executor's own clock is zero until `subsystem_block_timestamp_enabled_from_height` opens, so writing them here would make this gate's repair depend silently on another gate's height". **That is a soft ordering the owner should honour: open this gate at or before the identity-binding gate**, or the identity-binding repair lands with a zero clock.

**3. Persistent data impact.** **Changes the contents of rows written across eight subsystems** (stored `created_at` / `updated_at` / validity fields), and flips the outcome of every time-dependent comparison. Rows written below the gate keep their zeros forever; nothing rewrites them.

**4. Rollback in effect.** **C.** Every reader must forever handle a row whose timestamp is 0 and a row whose timestamp is real, and must not infer "unset" from either. B can change which clock is used going forward; nothing repairs the zeros.

**5. Monitoring signal.** M6 across the eight subsystems: a validity window queried just after the height should start answering on real time. **The misbehaviour to watch for is the opposite of the defect** — a credential that was valid below the gate (because everything compared against zero) becoming expired at the height. Visible only as failed receipts through M4, or as a read-side status flip through M6. No counter.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R12 — `subsystem_tx_index_enabled_from_height`
*accessor `subsystem_tx_index_activation, crates/state/src/lib.rs:134`* — cost shape **KEY SPACE**

**1. Affected behaviour.** Below the gate every dispatch arm hands the subsystem executors a literal `0` where the transaction's index within its block belongs. DocClass events are keyed `height || tx_index || event_index` and messaging events `recipient || height || tx_index`, so every event a block produces lands at one key and **only the LAST survives**: the family holds one row per block and every earlier event is silently overwritten. At and above it each arm passes the real index and the rows stop colliding.

**2. Dependency ordering.** None. Deliberately distinct from `subsystem_block_timestamp_enabled_from_height`: that gate changes row CONTENTS across eight subsystems, this one changes KEYS and COUNT in two families. Different blast radii; the source says an operator must be able to sequence them.

**3. Persistent data impact.** **Changes both the keys and the COUNT of rows in two families** — the DocClass event family and the messaging event family. One row per block becomes one row per event. **Disk growth changes at this height**, and so does the size of a block's write set, which the candidate ceiling can refuse.

**4. Rollback in effect.** **C, and it is the expensive one.** Events lost below the gate are lost — there is no record of them to recover. Readers must handle both the one-row-per-block region and the one-row-per-event region forever. B can change the key again; nothing back-fills the overwritten events.

**5. Monitoring signal.** **The one number to watch is disk growth rate**, per node, across the height. No metric exposes per-family row counts (M5 covers `cf::STATE` account rows only), so this is node-level disk usage plus M6: `messaging_getMessages` / `messaging_getMessagesInBlock` should start returning every message in a multi-message block rather than one. Misbehaving looks like block write-sets hitting the candidate ceiling — which surfaces as refused transactions through M4, not as a counter.

**6. Recommended wave.** Wave 2a. **Proposed height:** — owner decision —

---

### R13 — `subsystem_allocation_bound_enabled_from_height`
*accessor `subsystem_allocation_bound_activation, crates/state/src/lib.rs:190`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Three pre-allocation checks fire: a subsystem payload longer than `MAX_SUBSYSTEM_PAYLOAD_BYTES` (65,536) is refused BEFORE decode; a stored row whose encoding exceeds `MAX_ACCUMULATING_ROW_BYTES` (1,048,576) is refused before decode; an NFT `BatchMint` naming more than `MAX_NFT_BATCH_MINT_REQUESTS` tokens is refused before the owner-index rebuild loop. Below the gate the release ceiling bounds what a block may COMMIT and nothing about what one refused transaction may ALLOCATE: measured, one `AddKey` peaks at 4.00x the row size, churns 5.00x, and grows the row by 1,899,873 bytes for one `min_fee`. Readers: the DocClass bound, the NFT owner index, and Agreement's party and executor indexes.

**2. Dependency ordering.** None. One field for both DocClass and NFT deliberately, because a partial activation leaves the cheapest vector open. The limits are binary constants, not `ChainParams` fields, because the genesis digest covers only `Option<u64>` gates.

**3. Persistent data impact.** No row changes shape. **There is a state-shape consequence on existing rows**: a row already past the limit when the gate opens — which can only exist by having been written below the gate — becomes UNMODIFIABLE rather than unreadable. Mutating operations refuse it with a failed receipt; reads are untouched. A row may also overshoot by at most one payload, because the check refuses the NEXT operation rather than the one that crossed. **No test exercises a pre-existing over-limit row**; `allocation_bound_gate.rs` seeds its own.

**4. Rollback in effect.** **A and B**, plus an unusual obligation: a row made unmodifiable can only be freed by a superseding gate that raises the limit or adds a shrink path. Nothing in this tree has one.

**5. Monitoring signal.** M4 on DocClass, NFT and Agreement transactions. The working signal is an oversized payload receipt-failing; the misbehaving signal is a legitimate payload above 64 KiB doing the same, and **the two are indistinguishable in the receipt** — which is why this gate's risk is concentrated in whether any real traffic is above the limit. That is not answerable from this repository. Node memory (RSS) across the height is the secondary signal: it should stop spiking.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R14 — `tax_proof_lifecycle_enabled_from_height`
*accessor `TaxExecutor::proof_lifecycle_activation, crates/state/src/tax_executor.rs:171`* — cost shape **ROW CONTENT/EXISTENCE**

**1. Affected behaviour.** Rows OV-1, OV-2, OV-3. At and above the gate `IssueClaim` refuses a proof id already present; `RevokeClaim` resolves its payload through the subject index and revokes EVERY proof recorded for that subject; each deletion removes the matching index entry. Below the gate deletion removes the proof row and leaves the subject-index entry, so the index grows without bound, and any active issuer can overwrite any proof.

**2. Dependency ordering.** None externally. The three halves are welded to one height: index cleanup without the keying fix cleans the wrong subject, and the keying fix without index cleanup makes the dangling entries accumulate faster.

**3. Persistent data impact.** **Both.** Index entries are now deleted where before they accumulated; one revocation now deletes multiple proof rows where before it deleted one. Dangling index entries written below the gate are not collected by activation — they stay.

**4. Rollback in effect.** **A, B and C.** The dangling pre-gate index entries are permanent unless a superseding gate adds a sweep. Proof rows deleted above the gate are gone.

**5. Monitoring signal.** M6: `tax_listClaimTypes`, `tax_getPolicy` and the proof read paths should stop returning entries whose proof row is absent. **The working signal is the subject index ceasing to grow faster than the proof store.** No metric measures either; this is a read-side comparison an operator must run deliberately. Misbehaving looks like a `RevokeClaim` deleting more proofs than intended — visible in M4 only as a success.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R15 — `nft_token_authority_enabled_from_height`
*accessor `NftExecutor::token_authority_activation, crates/state/src/nft_executor.rs:282`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows OV-12, OV-13, OV-14. At and above the gate `UpdateMetadata` requires the current OWNER rather than the immutable creator; both `Approve` and `UpdateMetadata` refuse a locked token; and `Approve` refuses a non-transferable collection. Below it a minter can rewrite the metadata of any token it ever sold, indefinitely.

**2. Dependency ordering.** None. Subset activation is rejected in the source: a lock check on approval is worth nothing while the collection that forbids transfers is never read.

**3. Persistent data impact.** **None.** It changes which writes are allowed, not what a permitted write records.

**4. Rollback in effect.** **A and B.**

**5. Monitoring signal.** M4 on NFT transactions, plus M6 (`nft_getToken`, `nft_ownerOf`) to confirm a token's metadata stops changing under a creator who no longer owns it. The misbehaving signal is a legitimate owner's `UpdateMetadata` failing — indistinguishable from the working signal except by knowing who sent it. No counter.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R16 — `agreement_signature_integrity_enabled_from_height`
*accessor `AgreementExecutor::signature_integrity_activation, crates/state/src/agreement_executor.rs:237`* — cost shape **ROW CONTENT**

**1. Affected behaviour.** Rows OV-28, OV-29. At and above the gate a signature must name a bound party, and revoking one clears that party's `signed` flag and returns an agreement that was `Executed` only because it was fully signed to `PendingSignatures`. Below it `Executed` is not evidence of signature, and termination and cancellation are reversible by anyone who can add a signature row.

**2. Dependency ordering.** None. The halves cannot be split: flag-clearing without the party check can clear a flag some other signature set.

**3. Persistent data impact.** **Both.** The reject half stops an unbound-party signature being stored and stops it rewriting the agreement row while flipping no flag. The write half newly mutates the party's `signed` flag and the agreement's status field. Agreements that reached `Executed` below the gate keep that status; nothing recomputes them.

**4. Rollback in effect.** **B and C.** Agreements that are `Executed` on the strength of an unbound signature stay `Executed` — a superseding gate could add a re-evaluation path; none exists.

**5. Monitoring signal.** M6: `agreement_getExecutorLinksByAgreement` and the agreement read paths — a revocation should now move status back to `PendingSignatures`. **The working signal is a status transition that previously never happened.** Misbehaving looks like a legitimate signature being refused as unbound, visible only through M4.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R17 — `healthcare_state_precondition_enabled_from_height`
*accessor `HealthcareExecutor::state_precondition_activation, crates/state/src/healthcare_executor.rs:245`* — cost shape **ROW EXISTENCE**

**1. Affected behaviour.** Rows OV-17, OV-20. At and above the gate `RenewMembership` refuses a membership that is `Cancelled`, `Terminated` or `Expired`, and `RemoveNetworkAffiliation` / `RemoveDependent` are no-ops when there is nothing to remove. Below the gate suspension is cosmetic on the withdraw side.

**2. Dependency ordering.** None. One height because a write arm must read the row before it decides.

**3. Persistent data impact.** **Both.** The renewal half is accept/reject. The removal half stops CREATING an empty index row and stops bumping `updated_at` on a row nothing changed. Empty index rows written below the gate are not collected.

**4. Rollback in effect.** **A, B and C.** The empty index rows are permanent.

**5. Monitoring signal.** M6 (`healthcare_getInstitutionalProvider`, `healthcare_getActiveInstitutionalProviders`): the working signal is that a removal of something absent stops producing a row. The misbehaving signal is a legitimate renewal of a membership the chain believes expired — which depends on gate 11, because below `subsystem_block_timestamp` every expiry is evaluated at time zero. **If this gate opens before gate 11, expiry is still being judged at the epoch.** Owner should not sequence this one earlier than gate 11.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R18 — `subsystem_proof_presence_enabled_from_height`
*accessor `subsystem_proof_presence_activation, crates/state/src/lib.rs:271`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows AU-6, AU-12, AU-17, AU-20, AU-26, AU-29. Below the gate the `VerifyProof` arms deduct, credit, increment and return SUCCESS without reading the payload at all. At and above it the payload must be the 32 bytes of a proof id and that proof must be present in the subsystem's proof family, or the operation is a failed receipt. **The source is emphatic that this does not make anything verify a proof** — presence is not verification, and those audit rows stay open.

**2. Dependency ordering.** None — the source says "there is nothing to sequence". One field for six subsystems, on the same argument as gate 11.

**3. Persistent data impact.** **None.** A success receipt becomes a failed one; the subsystem's proof family is read, never written.

**4. Rollback in effect.** **A and B.**

**5. Monitoring signal.** M4 on `VerifyProof` transactions across the six subsystems. **The working signal is that `VerifyProof` starts failing at all** — below the gate it cannot fail, so any failure above it is the gate working. The misbehaving signal is a `VerifyProof` failing for a proof that genuinely exists, which would be a proof-family read fault. No counter.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R19 — `nft_update_path_parity_enabled_from_height`
*accessor `NftExecutor::update_path_parity_activation, crates/state/src/nft_executor.rs:314`* — cost shape **VALUE MOVEMENT**

**1. Affected behaviour.** Row OV-10 and the first half of RY-2. At and above the gate `UpdateMetadata` and `BatchMint` enforce the metadata size limit and the per-byte storage fee, and `UpdateCollectionConfig` refuses a recipient for a royalty of zero. **The source is explicit that this does not make a royalty payable** — RY-1 is untouched.

**2. Dependency ordering.** None — the source says neither half can abort a block, so there is nothing to sequence. Subset activation is rejected: metadata-only and royalty-only each leave an asymmetry.

**3. Persistent data impact.** Mostly refusal, **but the metadata half newly CHARGES `storage_fee_per_byte` (100) on two arms**, so balances move differently on transactions that still succeed. The relevant `ChainParams` values are set in the release `genesis.json`: `max_metadata_bytes: 16384`, `storage_fee_per_byte: 100`.

**4. Rollback in effect.** **A, B and D.** Fees charged are fees charged; a superseding gate stops future charging and D is the only way to return anything.

**5. Monitoring signal.** **M7 plus per-sender balances**: the working signal is NFT metadata updates becoming more expensive by exactly `100 × bytes`. Misbehaving looks like a legitimate metadata update failing on insufficient balance where it previously succeeded free — visible through M4. This gate is in its own wave with gate 26 precisely because fee accounting surprises must not be attributed to a row-shape change.

**6. Recommended wave.** Wave 2c. **Proposed height:** — owner decision —

---

### R20 — `subsystem_no_op_receipt_enabled_from_height`
*accessor `subsystem_no_op_receipt_activation, crates/state/src/lib.rs:228`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows OV-6, OV-25, OV-30. Legal `ConsolidateCase` on an already-consolidated pair, DocClass `UpdateCredential` (which writes nothing at all — no `v_put_*` of any kind and no event), and Agreement `AddParty`/`RemoveParty`. At and above the gate each returns a failed receipt instead of a success. **A failed receipt, not an implementation**: it does not make `AddParty` add a party or `UpdateCredential` update a credential.

**2. Dependency ordering.** None. One height for three subsystems on gate 11's argument rather than the per-subsystem one.

**3. Persistent data impact.** **None.** A success receipt becomes a failed one, and no block can abort.

**4. Rollback in effect.** **A and B.** The forward fix for the underlying defect is an implementation, not a gate.

**5. Monitoring signal.** M4 on the three subsystems. **The working signal is an operation that always reported success starting to report failure** — which is exactly what an integrator's tooling will notice first, and is the most likely source of a false alarm in Wave 1. M1 confirms the gate fired, which is how an operator distinguishes this from a regression.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R21 — `docclass_issuer_authority_enabled_from_height`
*accessor `DocClassExecutor::issuer_authority_activation, crates/state/src/docclass_executor.rs:317`* — cost shape **ROW CONTENT**

**1. Affected behaviour.** Row AU-34. Below the gate `UpdateIssuer` deserializes a whole `DocClassIssuer` from the sender's payload and writes it over the registry row, so an issuer grants itself any subcode, any jurisdiction, and **a SUSPENDED issuer restores itself to `Active` with one transaction**. At and above it `UpdateIssuer` keeps the recorded values of the five fields that decide what an issuer may do — `status`, `authorized_subcodes`, `jurisdictions`, `issuer_type`, `registered_at` — and writes only the descriptive ones the registry does not consult. **No legitimate authority-change path is added**: above the gate an issuer's authority is fixed at registration and can be ended by the admin's `DeactivateIssuer` and in no other way, because a one-way narrow with no granting counterpart would be a trapdoor.

**2. Dependency ordering.** None at load. The source notes the stake half of the same wholesale write is closed under `docclass_stake_escrow_enabled_from_height`, which is deferred (Part 3), so this gate closes the authority half alone.

**3. Persistent data impact.** The same write still happens to the DocClass issuer registry row; five fields are now preserved from the stored row instead of taken from the payload. Registry rows already self-elevated below the gate keep their elevated values — **activation does not demote anyone**.

**4. Rollback in effect.** **B and C.** An issuer that granted itself subcodes below the gate keeps them; only `DeactivateIssuer` ends it. A superseding gate would be needed to add a legitimate authority-change path, and the source argues deliberately against one.

**5. Monitoring signal.** M6: `docclass_getIssuer`, `docclass_getIssuers`, `docclass_canIssue`. **The working signal is a suspended issuer staying suspended across an `UpdateIssuer`.** The misbehaving signal is an issuer unable to update its own name or keys, which is a failed receipt through M4. **Before activating, the owner should enumerate current issuers via `docclass_getIssuers` and check whether any holds authority it granted itself** — activation freezes whatever is there.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R22 — `docclass_revocation_record_enabled_from_height`
*accessor `DocClassExecutor::revocation_record_activation, crates/state/src/docclass_executor.rs:343`* — cost shape **KEY SPACE**

**1. Affected behaviour.** **Sourced from the accessor doc, not from `genesis/src/lib.rs` — see §0.11(a); the field there carries another gate's text.** Below the gate a revocation record is keyed by the legacy 40-byte `credential_id || revoked_at_height`, so a block that writes two records for one credential silently replaces the earlier with the later, and `Revoked`/`Superseded` are not terminal. At and above it the key is widened to 44 bytes by including the transaction, so two records in one block leave two rows, and `Revoked`/`Superseded` become terminal — suspend refuses them.

**2. Dependency ordering.** None.

**3. Persistent data impact.** **A new key width.** 44-byte keys are new keys: records written before activation keep their 40-byte keys and their bytes, and both readers accept either width and order by the key. Row count rises where a block previously collapsed two records to one. Revocation history lost below the gate is not recoverable.

**4. Rollback in effect.** **C, permanently** — two key widths coexist forever. B can widen again.

**5. Monitoring signal.** M6 on the DocClass revocation read paths: the working signal is two revocation records surviving a block that would previously have kept one, and a suspend of an already-`Revoked` credential starting to fail. Failures surface through M4 only. No counter, no row-count metric for this family.

**6. Recommended wave.** Wave 2a. **Proposed height:** — owner decision —

---

### R23 — `docclass_credential_schema_enabled_from_height`
*accessor `DocClassExecutor::credential_schema_activation, crates/state/src/docclass_executor.rs:369`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows OV-27 and D-19b, welded to one height. Below the gate `IssueCredential` selects its family by TRIAL DECODE — it tries `AcademicCredential`, falls through to `EligibilityAttestation`, discards the first error, and never consults the `DocSubcode` the envelope declares — and the schema validator has arms for subcodes 810/811/812 and returns `Valid` for everything else, so eligibility attestations are never schema-checked on any path at any height. At and above it the envelope's subcode selects the family, the credential's own `subcode` field must agree with the envelope's, and 813/814/815 plus the eligibility family get the same core-field bounds checks.

**2. Dependency ordering.** None between gates. One non-gate interaction: the validator's own `activation_height` of 385,000 is untouched — below this gate the three covered subcodes are validated at that height exactly as before. Activating either half alone would leave the subsystem inconsistent in a way it is not today.

**3. Persistent data impact.** **None.** It changes which `IssueCredential` transactions are refused and which decoder shape is used.

**4. Rollback in effect.** **A and B.**

**5. Monitoring signal.** M4 on `IssueCredential`. **The working signal is a credential whose declared subcode disagrees with its body starting to fail.** The misbehaving signal is a credential that decoded fine by trial-and-error now failing because its envelope subcode was always wrong and nobody noticed — which is the most likely real-traffic surprise in Wave 1. M6 (`docclass_getCredential`, `docclass_isCredentialValid`) confirms existing credentials still read; the gate does not re-validate them.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R24 — `docclass_identity_binding_enabled_from_height`
*accessor `DocClassExecutor::identity_binding_activation, crates/state/src/docclass_executor.rs:394`* — cost shape **ROW CONTENT**

**1. Affected behaviour.** **Sourced from the accessor doc — see §0.11(a).** Row AU-35, in part. Below the gate `create_identity_root` checks only that `controller == sender` and then stores the deserialized payload struct verbatim, so any funded account anchors a root claiming any `subject_commitment`, in any `status`. At and above it a commitment another controller already anchored is refused, and `status` is written as `Active` by the executor rather than taken from the payload. **Nothing binds the commitment to a PERSON** — this is squatting resistance, not authentication, and row AU-35 stays open.

**2. Dependency ordering.** **A soft ordering the source names explicitly**: `created_at`/`updated_at` are left from the payload specifically so this gate's repair does not depend silently on `subsystem_block_timestamp_enabled_from_height`. That is an argument for opening gate 11 first, not a load-time constraint.

**3. Persistent data impact.** Both a written field (`status` forced to `Active` on the identity-root row) and a read against existing rows (duplicate `subject_commitment` refused). `created_at`/`updated_at` are deliberately still taken from the payload, because the executor's clock is zero until gate 11 opens. Identity roots anchored below the gate keep whatever `status` their payload claimed.

**4. Rollback in effect.** **B and C.** Squatted commitments anchored below the gate keep their rows and their claimed status; the gate only stops new ones. No sweep exists.

**5. Monitoring signal.** M6: `docclass_getIdentity`, `docclass_getIdentityByController`. **The working signal is a second `CreateIdentityRoot` for an already-anchored commitment failing.** Before activating, the owner should enumerate existing identity roots and accept that whatever is anchored is frozen as anchored. Failures surface through M4.

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R25 — `docclass_issuer_stake_requirement_enabled_from_height`
*accessor `DocClassExecutor::issuer_stake_requirement_activation, crates/state/src/docclass_executor.rs:417`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row AU-37, in part. Below the gate `DocClassParams::require_issuer_stake` is declared, defaulted to `true`, reported by `docclass_getConfig`, and read by no execution path: `register_issuer` enforces `min_issuer_stake` whenever it is non-zero, whatever the flag says. At and above it the minimum-stake check runs only when `require_issuer_stake` is true, which is what the field says. **Note the direction: this gate can make registration EASIER**, if the deployed config has the flag false and a non-zero minimum.

**2. Dependency ordering.** None between gates. Two AU-37 fields are deliberately left open: `max_credential_validity` (documented "in seconds" while the chain's `Timestamp` is milliseconds — a wrong guess would be a consensus rule refusing lawful credentials, and it needs the unit settled first, which is a specification decision) and `initial_issuers` (genesis STATE rather than a rule an executor can apply — honouring it means writing issuer rows into the genesis state, a path this tree does not have).

**3. Persistent data impact.** **None.** It changes whether `register_issuer` refuses an under-staked registration.

**4. Rollback in effect.** **A and B.**

**5. Monitoring signal.** **Read `docclass_getConfig` BEFORE activating**: it reports `require_issuer_stake` and `min_issuer_stake`, and those two values determine whether this gate tightens or loosens registration. M4 on `RegisterIssuer` afterwards. This is the one gate in Wave 1 whose direction of effect depends on deployed configuration rather than on code.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R26 — `nft_charged_receipt_enabled_from_height`
*accessor `NftExecutor::charged_receipt_activation, crates/state/src/nft_executor.rs:337`* — cost shape **VALUE MOVEMENT**

**1. Affected behaviour.** Row OV-9. `NftExecutor::execute_ungated` calls `deduct_fee` before the dispatch match, so a refused NFT transaction has its fee spent and its nonce advanced while the receipt says `fee_paid: 0` — the balance moved, the proposer was credited, and the receipt denies it. At and above the gate a failed NFT receipt carries the fee actually taken; it is still `0` for insufficient balance, because there the receipt's zero is true.

**2. Dependency ordering.** None. Explicitly NOT shared with `nft_receipt_failure_enabled_from_height`: that gate decides whether a block EXISTS, this one changes a number in a receipt of a block that exists either way.

**3. Persistent data impact.** **Changes a written value — `fee_paid` in receipt rows — and the receipts root is in the header, so this is a consensus change.** No new rows, no new family; state rows are unchanged. Receipts written below the gate keep their false zeros.

**4. Rollback in effect.** **B only.** The receipts are in the chain; nothing rewrites a receipts root. D is not applicable — the fees were correctly taken, only mis-reported.

**5. Monitoring signal.** M4 on refused NFT transactions: **the working signal is `fee_paid` on a failed NFT receipt becoming non-zero.** That is a one-call check and is the cleanest confirmation of any gate in the 40. Misbehaving would be a mismatch between `fee_paid` and the sender's actual balance delta — which requires comparing `sum_getBalance` across the block and has no instrument. Paired with gate 19 in Wave 2c because both move fee accounting.

**6. Recommended wave.** Wave 2c. **Proposed height:** — owner decision —

---

### R27 — `nft_index_symmetry_enabled_from_height`
*accessor `NftExecutor::index_symmetry_activation, crates/state/src/nft_executor.rs:360`* — cost shape **ROW EXISTENCE**

**1. Affected behaviour.** **Sourced from the accessor doc — see §0.11(a).** Row OV-15. Below the gate emptying an owner's token list DELETES the row while emptying a collection's token list WRITES an empty list, so two families that hold the same kind of value disagree about what "no entries" looks like, a node reasoning about state by row presence gets a different answer from each, and the empty rows accumulate one per collection ever emptied and are never collected. At and above it both delete.

**2. Dependency ordering.** None; its own height rather than the receipt gates'.

**3. Persistent data impact.** **Changes which ROWS exist**, so it moves the state root for a transaction whose receipt is unchanged. The source says this is the only one of the NFT gates that does. Empty collection rows written below the gate stay.

**4. Rollback in effect.** **B and C.** The accumulated empty rows are permanent unless a superseding gate adds a sweep.

**5. Monitoring signal.** M6: `nft_getTokensInCollection` on a collection emptied after the height should behave the same as `nft_getTokensByOwner` on an emptied owner. **This gate is the one whose misbehaviour is most likely to be silent** — a pruner or archive comparison that relied on the empty row being present would change answers without any transaction failing. If any such consumer exists, it is outside this repository (§0.12).

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R28 — `nft_collection_id_nonce_enabled_from_height`
*accessor `NftExecutor::collection_id_nonce_activation, crates/state/src/nft_executor.rs:383`* — cost shape **KEY SPACE**

**1. Affected behaviour.** Row CI-1. Below the gate `CollectionId::new(sender, name, nonce)` takes the BLOCK TIMESTAMP as its whole nonce, so two blocks sharing a timestamp yield one sender the same id for the same name and the second creation is refused as `Collection already exists` — naming a collection the sender does not have. At and above it the sender's account nonce joins the preimage, already incremented by `deduct_fee` before the creation arm runs.

**2. Dependency ordering.** None. Note it depends on the block timestamp today, and gate 11 changes what that timestamp is — below gate 11 the nonce is literally zero for the eight gated subsystems. NFT is not among them, so there is no coupling, but the owner should confirm that before sequencing this one before gate 11.

**3. Persistent data impact.** **This changes collection IDs.** Every id minted at or above the height is a different 32 bytes from what the same transaction would have produced below it — a new address space for collections created after the height. **Existing collections are untouched: nothing recomputes an id.**

**4. Rollback in effect.** **C, permanently.** Two id derivations coexist forever, and any off-chain tool that recomputes a `CollectionId` must know the height to know which formula applies. **That is the most likely integration break in the whole set**, and it is invisible on-chain.

**5. Monitoring signal.** M6: `nft_getCollection` for a collection created just after the height, compared against an off-chain recomputation. **Before activating, the owner should establish whether any tooling recomputes collection ids** — the answer is not in this repository (§0.12). The working signal is two collections with the same name from the same sender in adjacent blocks both succeeding.

**6. Recommended wave.** Wave 2a. **Proposed height:** — owner decision —

---

### R29 — `agreement_party_authority_unsupported_enabled_from_height`
*accessor `AgreementExecutor::party_authority_unsupported_activation, crates/state/src/agreement_executor.rs:286`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows AU-9, AU-10, AU-11. Below the gate a signature names its party in its own payload and nothing compares that party to the sender, so any funded account signs on behalf of any party and carries a two-party agreement to `Executed` alone (AU-9); the `signature` bytes it supplies are stored and checked against nothing (AU-10); and any funded account terminates, voids or supersedes any agreement, revokes any IP action, and drives any executor link through its whole lifecycle (AU-11). At and above it **fourteen arms** return a FAILED receipt carrying `AGREEMENT_PARTY_AUTHORITY_UNSUPPORTED` (`crates/state/src/lib.rs:486`) **before the deduct**, where this executor's other refusals already return, so a refused Agreement transaction writes nothing and costs nothing exactly as `Agreement not found` already does: `UpdateAgreement`, `TerminateAgreement`, `VoidAgreement`, `SupersedeAgreement`, `SignAgreement`, `RevokeSignature`, `UpdateIpAction`, `TerminateIpAction`, `RevokeIpAction` and the five executor-link arms. **Ten arms stay reachable** — `CommitAgreement`, `AddParty`, `RemoveParty`, `RecordIpAction`, `LinkExecutor`, `SubmitProof`, `VerifyProof` and the three attestation arms, which already check `issuer_address == sender` and are the reason the defect is specific rather than architectural. So the family is not stranded: an agreement can still be RECORDED; what it can no longer do is CHANGE, which is the half that today any stranger can do. **`UpdateAgreement` is in the gate although AU-11 does not name it** — it takes an `AgreementStatus` straight from the payload with `Agreement not found` as its only guard, so it reaches the three states AU-11 is about, and a gate that closed the named arms while leaving it open would close nothing. `RevokeSignature` is in for the matching reason on AU-9's side.

**2. Dependency ordering.** None at load: `ChainParams::validate` constrains five things (§0.7) and this is not among them. §0.7 rule (4) applies as it does to every remediation gate — opening this forces `peer_protocol_declaration_required_from_height` to be set at or below its height. **This is a refusal and not a guard, and the source is explicit about what that depends on**: `AgreementCommitment` carries no address at all and `PartyRef` is either a 32-byte commitment or a 32-byte subject id, so there is nothing to compare a sender to; verifying the stored `signature` would need a canonical signing input this subsystem does not define. Both repairs are wire changes to `crates/sumchain-wire/src/agreement.rs`. Nothing in this schedule supplies them, so no later gate relaxes this one.

**3. Persistent data impact.** **None.** No row changes shape, key or location. A transaction that used to succeed produces a failed receipt instead, and the state it would have written is simply not written. **Rows written below the gate keep whatever a stranger put in them** — an agreement carried to `Executed` by somebody with no standing stays `Executed`, and a stored `signature` that was never checked stays stored. Activation repairs nothing that already exists.

**4. Rollback in effect.** **A and B.** A is real here: the fourteen arms simply stop being submitted. B means defining a `PartyRef`-to-`Address` mapping or a canonical signing input, which is a wire change and a specification decision, not a patch — so the realistic reading is that this gate is one-way until the Agreement wire format is revised.

**5. Monitoring signal.** M4 on Agreement transactions; the refusal reason names the subsystem and the cause. **M6 does not cover the rows this gate protects**: the Agreement RPC surface is `agreement_getExecutorLink`, `agreement_getExecutorLinksByAgreement`, `agreement_getExecutorLinksByExecutor` and `agreement_getActiveExecutorLinks` — executor links only, with no read method for an agreement, a party or a signature — so an operator cannot read an agreement row over RPC before or after the height. The working signal is a stranger's `TerminateAgreement` starting to fail; the misbehaving signal is a legitimate party's, and **the two are indistinguishable in the receipt**, because the chain does not know which sender was a party. No counter (§0.8). Pinned by `a_stranger_signs_and_terminates_below_the_gate_and_neither_above_it` and `every_agreement_arm_that_needs_a_party_refuses_and_only_those` (`crates/state/tests/structural_refusal_gates.rs:214,344`).

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R30 — `healthcare_consent_subject_signature_enabled_from_height`
*accessor `HealthcareExecutor::consent_subject_signature_activation, crates/state/src/healthcare_executor.rs:350`* — cost shape **REFUSAL ONLY** (and a transaction-payload wire change, which no other gate in this class carries)

**1. Affected behaviour.** Row AU-3, the GRANT half. Below the gate `GrantConsent` checks `issuer_address == sender` and nothing else, so a disclosure authorization naming any person is recorded by the issuer alone and the person it is about never participates. The REVOCATION half is already remedied under `healthcare_authorization_enabled_from_height` (R5), so today **a subject can withdraw a consent they were never asked to give.** At and above the gate the payload is a `ConsentGrantRequest` (`crates/sumchain-wire/src/healthcare.rs:853`): the envelope, the subject's ed25519 public key, and the subject's signature over `ConsentEnvelope::grant_signing_input` — a domain-separated blake3 digest that binds what is being disclosed, about whom, to whom, under what rule, for how long and what it replaces, and deliberately does not bind `status`, `created_at`, `updated_at`, `recorded_at_height`, `revocation_ref` or `attachments`, because binding a field the chain itself rewrites would leave a stored consent whose signature no longer verifies against its own row. The key must derive to the envelope's own `subject_address` and the signature must verify. **The issuer still has to be the sender, so the transaction carries BOTH parties**: the issuer signs the transaction, the subject signs the consent. Three distinct refusals, one per condition, all before the deduct: `CONSENT_GRANT_REQUEST_REQUIRED` (which says in its own text that it is a client-version fact), `CONSENT_SUBJECT_KEY_MISMATCH`, `CONSENT_SUBJECT_SIGNATURE_INVALID` (`crates/state/src/lib.rs:521,531,536`). The cheap repair — require the SUBJECT to send the transaction — was written out and rejected: it would leave `issuer_address` unverified and trade a false claim about the subject for a false claim about the issuer, and a `SignedTransaction` carries exactly one signature, so no sender check can make a two-party record out of a one-party transaction.

**2. Dependency ordering.** **A LOAD-TIME CONSTRAINT, and the only one that orders two remediation gates against each other.** §0.7 rule (5): `healthcare_authorization_enabled_from_height` (R5) must be `Some(a)` with `a <= this height`. A genesis that opens this gate with R5 closed is REFUSED, as `ConsentGrantGateWithoutHealthcareAuthorization`; one that opens R5 later is refused as `HealthcareAuthorizationAfterConsentGrantGate`. Both paths refuse: the genesis path through `Genesis::validate`, and the restart path through `sumchain_state::account_root::validate_runtime_activation`, which is what `Node::new` actually calls — pinned by `the_consent_grant_gate_cannot_open_over_a_closed_healthcare_authorization`, `a_healthcare_authorization_gate_later_than_the_consent_grant_gate_is_refused` and `the_restart_path_refuses_a_consent_grant_gate_its_authorization_does_not_cover`. **This edition of the packet corrects the previous one**, which said the pair was not constrained and that an operator could open this gate alone: that was true of the tree it described and is no longer true of this one. The reason it became a refusal is unchanged and is the reason to read it: `SupersedeConsent` carries a replacement envelope, is not gated here, and **with `authorization` closed checks NOTHING about the sender (row AU-1)** — so a stranger supersedes any consent that exists with a replacement naming any subject they like and the widest scope there is, **which mints exactly the record `GrantConsent` has just been stopped from minting.** Asserted by `the_grant_gate_alone_does_not_close_supersession` (`crates/state/tests/consent_subject_signature_gate.rs:407`), which runs both halves. An equal height satisfies the rule: at block `h` both are open, the same construction §2.3 uses for R11/R17/R24, and Wave 1 holds R5. The fields stay deliberately separate — R5 changes which SENDER an arm accepts and changes no payload, this one changes what a `GrantConsent` payload IS — but separate FIELDS never meant separate heights, and the ordering is now enforced rather than advised. **What stays open even with both:** an issuer can still re-scope a consent the subject did agree to, via `SupersedeConsent`, without a fresh signature. That is AU-1's arm and AU-1's row, and this height does not close it.

**3. Persistent data impact.** **No stored row changes.** `ConsentEnvelope` is what the consent family stores and what `healthcare_store` encodes; the gate WRAPS it rather than appending to it, so no already-written encoding decodes to anything different on disk, and an accepted grant stores the same envelope bytes it always stored. What changes is the TRANSACTION payload, and **that reaches outside the node binary**: `ConsentGrantRequest` is a new public wire type in `sumchain-wire` **0.5.0**, a crate whose manifest description calls it "Byte-frozen on-chain wire formats for SUM Chain" and which carries an explicit hand-written package `include` allowlist because it is packaged for publication (`crates/sumchain-wire/Cargo.toml`). The addition is additive — a new struct beside the existing ones, no change to any existing type's field order or width, no new transaction ordinal, and the crate's frozen golden fixtures are untouched — and the wire tests pass. **But the publish and version decision is not made in this branch, and this packet does not make it.** An owner scheduling this height is also deciding that a published byte-frozen crate gains a public type; that decision should be recorded before the height is, and it is the only item in Part 1 that is not settled inside a node.

**4. Rollback in effect.** **A and B**, plus a rollout obligation that is not a rollback. Below the gate the payload is a bare envelope, at and above it the wrapper, and **each side fails to decode the other rather than silently reinterpreting it** — so every client that submits `GrantConsent` must be upgraded before the height, and a client that is not upgraded gets A by accident: it stops being able to grant at all. Consents written below the gate keep their bytes, are not re-verified and are not re-signed; the gate stops new unsigned grants and reverses none.

**5. Monitoring signal.** M4 on `GrantConsent`, and the three refusal reasons exist so that the receipt itself distinguishes the cases: `CONSENT_GRANT_REQUEST_REQUIRED` is an un-upgraded client, `CONSENT_SUBJECT_KEY_MISMATCH` is a wrong key, `CONSENT_SUBJECT_SIGNATURE_INVALID` is a bad signature. **The working signal is a bare-envelope grant starting to fail with the client-version reason. The misbehaving signal is an UPGRADED client hitting `CONSENT_SUBJECT_SIGNATURE_INVALID`**, which would mean the signing input is computed differently on the two sides — the single failure mode that would strand legitimate traffic. **M6 does not cover this family at all**: the Healthcare RPC surface is an explicit allowlist of institutional provider types and carries "no memberships, consents, prescriptions, proofs, events, or member/patient/subject data" (`crates/rpc/src/api.rs:1529-1533`), so a consent row cannot be read over RPC before or after the height and there is nothing to compare across it. M1 `gates[].active` confirms the gate fired. No counter.

**6. Recommended wave.** Wave 1, **at the same height as R5 and never earlier** (field 2). The client upgrade belongs with Wave 0's binary rollout, not with the height. **Proposed height:** — owner decision —

---

### R31 — `subsystem_issuer_self_registration_unsupported_enabled_from_height`
*accessor `subsystem_issuer_registration_activation, crates/state/src/lib.rs:452`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows AU-18 (Tax) and AU-21 (Finance). Below the gate `RegisterIssuer` in both subsystems takes the applicant's own payload and writes it into the issuer registry: the guards are `address == sender` and "not already registered", and **the CLASS and the STATUS come from the payload.** So any funded account registers itself as an ACTIVE `TaxAuthority`, or an ACTIVE `CentralBank`, in one transaction — and the registry is publicly readable and is what every other authorization rule in those subsystems resolves against. At and above the gate both arms return a FAILED receipt carrying `ISSUER_SELF_REGISTRATION_UNSUPPORTED` (`crates/state/src/lib.rs:473`), before the deduct, where each subsystem's other registration refusals already return. **Refusal and not a registrar, because there is no registrar to name**: no `ChainParams` field names one for either subsystem, nothing in `genesis.json` seeds either registry, and no governance path in this tree writes to them. Inventing an authority inside an executor would be a rule nobody set, and choosing WHICH classes may self-assert would be the same invention in a smaller font. **What it costs, stated plainly and taken from the source:** with no registrar, a chain at this height has no way to get a Tax or Finance issuer at all, so the arms that require one can never be satisfied and **those two subsystems are deferred rather than repaired.** That is the intended trade — a deferred subsystem records nothing, an open one records an authority that authorized itself — and nothing that ever worked is stranded, because there has never been a lawful issuer to strand. ONE field for two subsystems, on the same argument `subsystem_proof_unsupported_enabled_from_height` is one field for seven: one rule, two identical bodies, the same blast radius on each side.

**2. Dependency ordering.** None at load, and the source names no soft ordering. §0.7 rule (4) applies. **One interaction the owner should read rather than discover:** `tax_authorization_enabled_from_height` (R10) and `finance_authorization_enabled_from_height` (R7) resolve authority against the same registry this gate stops growing, and all three are in Wave 1 — so the registry stops taking new self-assertions at the same height its contents start being enforced. That is an observation about the schedule, not a constraint: any order of the three is legal.

**3. Persistent data impact.** **None.** No row changes shape or key; a registration that used to write an issuer row does not write one. **Registry rows written below the gate stay, with whatever class and status they asserted — activation deregisters nobody.** **Before activating, the owner should enumerate `tax_getActiveIssuers` and `finance_getActiveIssuers`**: whatever is in those lists at the height is frozen as an authority, and after the height there is no path that adds to them or removes from them.

**4. Rollback in effect.** **A and B.** A is the operator's only immediate lever. B here is not a patch: it means naming a registrar — a `ChainParams` field, a governance action, or a genesis-seeded set — and none of the three exists in this tree, so B is a design decision with a rollout attached. There is no D: nothing this gate touches moves value.

**5. Monitoring signal.** M4 on `RegisterIssuer` in Tax and Finance. M6 on the registry reads — `tax_getIssuer`, `tax_getActiveIssuers`, `tax_getIssuersByClass`, `finance_getIssuer`, `finance_getActiveIssuers`, `finance_getIssuersByJurisdiction`: **the working signal is that the active-issuer lists stop growing at the height** and that existing rows still read. The misbehaving signal is an operator with a legitimate claim to be an issuer being unable to register — which is the intended cost rather than a fault, and is indistinguishable from the working signal in the receipt. No counter. Pinned by `a_tax_authority_registers_itself_below_the_gate_and_not_above_it` and `a_central_bank_registers_itself_below_the_gate_and_not_above_it` (`crates/state/tests/structural_refusal_gates.rs:397,480`).

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R32 — `property_proof_submission_unsupported_enabled_from_height`
*accessor `PropertyExecutor::proof_submission_unsupported_activation, crates/state/src/property_executor.rs:473`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row AU-32. Below the gate `SubmitProof` checks nothing about the sender and nothing about the proof: its only guard is a duplicate id, and everything else — the profile, the policy ids, the subject nullifier, the validity window and the proof bytes — is written from the payload verbatim. **So any funded account writes any row into the Property proof family, under any subject it likes.** At and above the gate the arm returns a FAILED receipt carrying `PROPERTY_PROOF_SUBMISSION_UNSUPPORTED` (`crates/state/src/lib.rs:498`), before the deduct, where its own duplicate-id refusal already returns. **Refusal and not an issuer check:** `PropertyProofEnvelope` carries no issuer address, Property has no issuer registry at all — no `v_get_issuer` exists in `property_executor.rs` or `property_view.rs` — and no `ChainParams` field names a Property registrar. There is neither an address in the payload to check nor a registry to check it against.

**2. Dependency ordering.** None at load, and deliberately NOT sharing a height with `subsystem_proof_unsupported_enabled_from_height`: that gate is about a verifier this tree does not have, this one about an issuer this subsystem does not record; an operator must be able to sequence them, and a reader of either receipt must be able to tell which claim was refused. **One consequence the owner should see, because it turns on a gate this packet does not schedule.** The source's argument that refusing a submission "takes no capability with it" rests on the only consumer of a Property proof row — `PropertyOperation::VerifyProof` — already refusing under `subsystem_proof_unsupported_enabled_from_height`, and that gate is one of the two Part 0a names as not covered here. So at this height, with that one closed, `VerifyProof` is still reachable: under `subsystem_proof_presence_enabled_from_height` (R18, Wave 1) it succeeds only for a proof row that is present, and with R18 also closed it succeeds without reading the payload at all. **The gate is still the right refusal — it removes an unauthenticated write either way — but the "nothing downstream is stranded" claim is conditional on a height that is not in this schedule**, and it should be read that way.

**3. Persistent data impact.** **None.** The Property proof family is not written at or above the height. **Rows written below it stay, unauthenticated, and nothing sweeps them** — presence in that family has never meant anybody was checked, only that somebody paid a fee, and activation does not change what the existing rows mean. A reader must not infer authentication from presence at any height.

**4. Rollback in effect.** **A and B.** B means giving Property an issuer registry, or putting an issuer address into `PropertyProofEnvelope` — a wire change in the first instance, a new state family in the second — so, as with R29 and R31, B is a design decision rather than a patch. Nothing written needs undoing, because the gate's whole effect is that less is written.

**5. Monitoring signal.** M4 on Property `SubmitProof`. **M6 does not cover this family**: the Property RPC surface is `property_getAsset`, `property_getActiveAssets` and `property_getAssetsByJurisdiction`, with no proof read method, so a proof row cannot be read over RPC before or after the height. **The working signal is `SubmitProof` starting to fail at all** — below the gate it can only fail on a duplicate id, so any other failure above it is the gate working. The misbehaving signal is a legitimate submitter losing a capability, which is the intended cost and is not distinguishable in the receipt. No counter. Pinned by `a_stranger_submits_a_property_proof_below_the_gate_and_not_above_it` (`crates/state/tests/structural_refusal_gates.rs:566`).

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R33 — `nft_unpayable_royalty_refused_enabled_from_height`
*accessor `NftExecutor::unpayable_royalty_refused_activation, crates/state/src/nft_executor.rs:435`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row RY-1. Below the gate `CreateCollection` stores `royalty_bps` and `royalty_recipient` from the payload, both are returned over JSON-RPC by `nft_getCollection`, and **no execution path consults either**: `execute_transfer` and `v_transfer_token` move a token and no balance at all. A marketplace reading the chain is told a royalty exists that the chain has no code to pay. At and above the gate a creation whose `royalty_bps` is non-zero returns a FAILED receipt carrying `UNPAYABLE_ROYALTY_UNSUPPORTED` (`crates/state/src/lib.rs:510`) — refused AFTER `validate()`, so a malformed config is still reported as malformed, and BEFORE the id is computed, so a refused creation consumes no collection id. A collection with no royalty is created exactly as before. **Refusal and not payment**, and the source gives the reason in full: a transfer carries no consideration for a royalty to be a fraction of; adding a price field would not be enough, because a `Transfer` is signed by the SELLER and names the buyer while `SignedTransaction` carries one signature checked against `from`, so a price alone would authorise debiting an account whose holder signed nothing. Paying a royalty needs a two-sided order, a standing listing or an escrowed bid — a new wire type and, for two of the three, a new state family. **What the gate closes is the CLAIM, not the payment.** It reaches CREATION only, because creation is the only place `royalty_bps` can be set: `NftUpdateCollectionConfigData` has no `new_royalty_bps` field at all (RY-2's second half).

**2. Dependency ordering.** None at load. One interaction the source names: the other half of RY-2 — a recipient recorded on a zero-royalty collection — is already refused by `nft_update_path_parity_enabled_from_height` (R19), which this packet puts in Wave 2c. The two do not overlap, and neither constrains the other: R19 refuses a recipient without a royalty, this one refuses a royalty at creation. Opening this one first, as Wave 1 does, closes the creation half before the update half, and that is a schedule fact rather than a requirement.

**3. Persistent data impact.** **None at or above the height.** But the residue is unusually visible: **collections created BELOW it keep the royalty they recorded, and `nft_getCollection` keeps publishing it.** A gate changes what a node does next, not what a chain already wrote — so the misleading claim this gate exists to stop is permanent for every collection already carrying one, and activation retracts nothing. An owner should not read this height as "the chain stops advertising unpayable royalties"; it stops ACCEPTING new ones.

**4. Rollback in effect.** **A and B.** A is the real lever and is unusually clean: a creator who wants a collection submits `royalty_bps: 0`. B is the royalty protocol itself, which the source says is a protocol and not a field, so it is a future design rather than a superseding narrow. Nothing moved value, so there is no D — **no royalty has ever been paid on this chain, which is the whole point.**

**5. Monitoring signal.** M4 on `CreateCollection`, and M6 `nft_getCollection`: **the working signal is that no collection created at or above the height carries a non-zero `royalty_bps`**, checkable in one call against any collection minted after it. The refusal test is exactly `royalty_bps != 0`, so there is no configuration in which a creator who intended no royalty is refused; **the only real failure mode is demand for a feature the chain never had**, which makes this the one gate in the set whose "misbehaviour" is a product decision rather than a fault. No counter. Pinned by `a_collection_records_an_unpayable_royalty_below_the_gate_and_not_above_it` (`crates/state/tests/structural_refusal_gates.rs:666`).

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R34 — `property_state_precondition_enabled_from_height`
*accessor `PropertyExecutor::state_precondition_activation, crates/state/src/property_executor.rs:319`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row OV-21. Below the gate three arms guard on the state they read — `ReinstateCoverage` accepts only `Suspended`, `PayClaim` only `Approved` or `PartiallyApproved`, `ReopenClaim` only `Closed` or `Denied` — and **every other transition applies from any prior status whatever.** So `UpdateAsset` returns a `Deregistered` asset to `Active`; a `Merged` asset is merged again into a third; `UpdateCoverage` sets a `Cancelled` coverage back to `Active` without ever meeting the `Suspended` requirement `ReinstateCoverage` exists to impose; and **a `Paid` claim is closed, reopened, re-approved and PAID A SECOND TIME**, which is the sharpest of them because the cycle walks around both of the guards the subsystem does have. At and above the gate a row whose status is FINAL accepts no further operation, at 22 call sites across five families, each returning the one phrasing `"<row> is <status>, which is final: no further operation applies to it"` — with the status in it, because the remedy for a final row is never "retry", it is a different row. **Final is not a judgement made in the executor**; it is the status a NAMED operation writes and that no named operation leaves: asset `Merged`/`Subdivided`/`Deregistered`; title event `Superseded`/`Voided`; encumbrance `Released`/`Foreclosed`; coverage `Cancelled`, and NOT `Suspended`, which `ReinstateCoverage` is the named way out of; claim `Paid` and `Withdrawn`, and NOT `Closed` or `Denied`, which `ReopenClaim` is the named way out of. Statuses reachable only through a free-form `Update*` arm — `AssetStatus::Destroyed`, `EncumbranceStatus::Voided`, `CoverageStatus::Expired` — are deliberately NOT final, because a gate that made them final would be choosing a lifecycle inside an executor rather than enforcing the one the arms already describe. **ONE field for five row types**, because it is one rule and the five are the same sentence about different families.

**2. Dependency ordering.** None at load. **Deliberately a separate height from R35** (`property_asset_relationship`), and the source says why: that gate decides what an operation that does apply RECORDS, this one decides whether the operation APPLIES; they fail differently — one lets a dead row move, the other loses a fact a live row asserted — and either is coherent without the other, so sharing a height would mean an operator could not have the one it had reviewed. Pinned by `each_new_height_opens_its_own_gate_and_neither_opens_the_other` (`crates/state/tests/property_decided_state_gates.rs:1336`). `property_authorization_enabled_from_height` (R9) is a different rule again — WHO may act, not whether the row still accepts an action — and is not ordered against this one.

**3. Persistent data impact.** **None written.** No row changes shape, key or location; a transition that used to apply from a final status is a failed receipt instead, so the state it would have written is simply not written. **What already happened is not repaired**: an asset returned from `Deregistered` to `Active` below the gate is `Active` at the height and stays so, and a claim paid twice keeps the record of the second payment. Note the second payment moved no chain balance — `PayClaim` writes a `paid_amount_commitment` and not a transfer — so this is a false RECORD rather than value that left, and §0.6's D does not apply.

**4. Rollback in effect.** **A and B.** No row shape changes, so C is not an obligation in the usual sense; what persists is a read-side fact rather than a dual path — every consumer must keep accepting rows whose history walked through a final status, because the gate stops new walks and reverses none. B would mean narrowing or widening the final-status list at a later height, which is a consensus change of the same size as this one.

**5. Monitoring signal.** M4 on Property transactions: the refusal names the family and the status, which is deliberate, so a receipt attributes the refusal precisely without any other instrument. **M6 covers one of the five families**: `property_getAsset`, `property_getActiveAssets` and `property_getAssetsByJurisdiction` read assets, and title events, encumbrances, coverages and claims have no read method at all, so four fifths of what this gate guards is invisible over RPC. The working signal is an `UpdateAsset` on a `Deregistered` asset starting to fail. The misbehaving signal is a legitimate operation on a row the executor believes final, which would mean the final-status list is wrong — and the list is pinned per family by the five `the_final_*_statuses_are_the_ones_a_named_operation_writes_and_none_leaves` tests (`crates/state/tests/property_decided_state_gates.rs:549,632,705,777,855`), with the double-payment cycle itself pinned by `a_paid_claim_is_closed_reopened_approved_and_paid_again_only_below_the_gate` (`:946`). No counter.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R35 — `property_asset_relationship_enabled_from_height`
*accessor `PropertyExecutor::asset_relationship_activation, crates/state/src/property_executor.rs:343`* — cost shape **ROW CONTENT**

**1. Affected behaviour.** Row OV-22, the merge half. Below the gate `MergeAssets` writes `AssetStatus::Merged` onto the secondary and NOTHING else: the primary asset row is not touched at all, and `AssetAnchor.related_assets` — the field the wire type carries, in its own words, "for subdivisions, mergers" — stays empty on both sides. `PropertyAssetStore::add_related_asset` is the writer that would record it and **has no caller anywhere in the tree** (row DE-7). A `Merged` asset therefore names nothing it was merged INTO, the asset that absorbed it says nothing about the absorption, and the merge is unreadable from either row afterwards. At and above the gate a merge links both rows: the primary gains the secondary's id and the secondary gains the primary's, each idempotently — `contains`, then push — and both carry the block's `updated_at`. BOTH directions, because the audit row names both halves of the omission; one direction would leave a `Merged` row still pointing nowhere. The status write comes first and the links second, so **a reader that sees `Merged` never sees it without the link in the same candidate.** **The write brings its own bound.** `related_assets` becomes an accumulating list — decoded, appended to and re-encoded on every merge — which is precisely the shape row AL-6 files as a defect wherever it already exists, so at the gate a merge is refused, **before the fee**, when either stored asset row already exceeds `MAX_ACCUMULATING_ROW_BYTES` (1,048,576), measured without decoding by `PropertyView::v_asset_row_len`. The bound belongs to THIS height rather than to `subsystem_allocation_bound_enabled_from_height` (R13) because an operator who opened this gate alone would otherwise be running the one accumulating row in the tree that nothing bounds. What this does NOT close: `SubdivideAsset` still creates no children and `TransferAsset` still moves no ownership — both stay BLOCKED, STRUCTURAL, because the subdivide payload names no child to create and an asset row has no owner field to move, and both are wire changes rather than executor changes.

**2. Dependency ordering.** None at load, and the source states explicitly that neither this gate nor R34 requires the other: linking merges of any two assets is an improvement even where dead assets can still be merged, and refusing dead assets is an improvement even where no link is written. Pinned by `each_new_height_opens_its_own_gate_and_neither_opens_the_other`. **One observation this packet adds, marked as such rather than taken from the source:** R34's final-status rule is what stops a `Merged` asset being merged again, and repeated merges are what make `related_assets` grow, so R34 at or before this height bounds the accumulation by a second route. The schedule already does that — R34 in Wave 1, this in Wave 2b — and nothing is constrained either way.

**3. Persistent data impact.** **Changes the CONTENTS of rows that already exist, and changes which rows a merge writes at all.** Two asset rows per merge are decoded, appended to and re-encoded, both carry a new `updated_at`, and **the primary asset row becomes written by a merge when below the gate it was never touched** — so a merge's write set roughly doubles and the asset row stops being fixed-size. That is a disk-growth change and a candidate write-set change on a family that previously had neither. **Merges committed below the gate are not repaired**: a `Merged` asset anchored below the height names nothing forever, and nothing back-fills `related_assets`. And an asset row already over `MAX_ACCUMULATING_ROW_BYTES` when the gate opens becomes **unmergeable rather than unreadable** — the same unusual obligation R13 carries, and as there, no test exercises a pre-existing over-limit row; `property_decided_state_gates.rs` seeds its own.

**4. Rollback in effect.** **B and C.** C is the obligation and it is permanent: two shapes of `Merged` asset coexist forever — one that names its counterpart and one that names nothing — so **any reader that infers "this merge recorded no relationship" from an empty `related_assets` will be wrong for every row written below the height**, and must know the height to read the family correctly. B could change the link format or raise the bound; nothing back-fills a merge that was never recorded.

**5. Monitoring signal.** **M6 `property_getAsset` on both ids of a merge performed just after the height: each should now name the other.** That is the whole working signal, and it has to be, because **the state root moves for a transaction whose receipt is unchanged** — a merge succeeds either way — which is exactly the 2b sub-shape §2.2 describes. The misbehaving signal is a merge refused for the row bound when neither row is genuinely near 1 MiB, visible only through M4, one receipt at a time. Disk growth on the Property asset family is the secondary signal and **no metric exposes it** (M5 covers `cf::STATE` account rows only). Pinned by `a_merge_links_both_rows_only_above_the_relationship_gate`, `merging_the_same_pair_twice_adds_no_second_entry` and `a_merge_is_refused_when_either_stored_asset_row_is_already_over_the_bound` (`crates/state/tests/property_decided_state_gates.rs:1114,1181,1261`), and the final-status interaction by `a_merge_is_refused_above_the_gate_when_either_asset_is_already_final` (`:1054`).

**6. Recommended wave.** Wave 2b. **Proposed height:** — owner decision —

---

### R36 — `docclass_signature_unsupported_enabled_from_height`
*accessor `DocClassExecutor::signature_unsupported_activation, crates/state/src/docclass_executor.rs:478`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row AU-33. Below the gate **no signature is verified anywhere in DocClass**: an `IssueCredential` carrying sixty-four bytes of nonsense in `issuer_signature`, under an `issuer_key_id` naming a key the issuer has never held, is ACCEPTED and both are STORED verbatim — there is no `verify` or `ed25519` call in `docclass_executor.rs` at all. At and above the gate that credential returns a FAILED receipt carrying `DOCCLASS_SIGNATURE_UNSUPPORTED` (`crates/state/src/lib.rs:594`), before the deduct, where the arm's own duplicate-id refusal returns. **Both halves of the claim are refused** — a non-zero `issuer_signature` and a non-empty `issuer_key_id` — because they are two different assertions: that something was signed, and that a particular key signed it. A credential with an all-zero signature and an empty key id asserts nothing and is issued exactly as before, on both credential families. **The gate closes the CLAIM, not the credential.** **Verification was attempted first and refused, against the tree's own convention rather than in the abstract.** The convention is R30's: a domain separator, a blake3 digest over an explicitly enumerated fixed-width field set built ON the wire type (`ConsentEnvelope::grant_signing_input` under `SRC874-CONSENT-GRANT:v1:`), and an ed25519 check whose public key is IN the payload and must derive to an address IN the payload. DocClass satisfies none of the three: it carries `issuer: Address` and `issuer_key_id: String`, a NAME whose resolution against `DocClassIssuer.keys` no rule states — the list carries `active`, `is_primary` and `expires_at`, and nothing says whether a signature made under a key later rotated out still verifies — and its credentials are half variable-length `String` (`jurisdiction`, `institution_id`, `payload_hint`, `issuer_key_id`, an arbitrary attribute list) with no framing convention. A rule that computes the wrong preimage refuses every LAWFUL credential, which is worse than the gap.

**2. Dependency ordering.** None at load: §0.7 constrains five things and this is not among them. Rule (4) applies as to every remediation gate. **One interaction worth reading rather than discovering:** R38 (`docclass_unknown_attribute_refused`) refuses a different field of the same payload, so a client fixing one and not the other still fails; the two are independent and either order is legal.

**3. Persistent data impact.** **None at or above the height** — a refused issuance writes no row. The residue is on both sides of it and should be read as permanent: **every credential issued BELOW the height keeps the signature and key id it recorded**, and `docclass_getCredential` keeps publishing them, so the decorative-signature claim this gate exists to stop is permanent for every credential already carrying one. Activation stops new ones. **And the half the gate cannot reach:** `RevokeCredential` still writes `[0u8; 64]` into `RevocationRecord.signature`, a field the wire type documents as "Signature over the revocation". Repairing that means changing the stored encoding — a consensus change with nothing to put there — or the wire type. Zero is at least the honest value, and it is pinned by `docclass_signatures_are_written_as_zero_and_checked_as_nothing`.

**4. Rollback in effect.** **A and B.** A is the lever and it is a CLIENT change, not an operator one: an issuer who wants a credential submits an all-zero `issuer_signature` and an empty `issuer_key_id`. That has to happen before the height, on every issuing client, which makes this one of the gates whose real cost is a rollout rather than a genesis edit. B is a DocClass signing standard: if one is later defined, a further height can start verifying, and this gate becomes the interval in which the chain declined to pretend. There is no D — nothing moved value.

**5. Monitoring signal.** M4 on `IssueCredential`: the refusal names VERIFICATION as unsupported, so a receipt attributes it without any other instrument. **M6 covers this family** — `docclass_getCredential` returns `issuer_signature` and `issuer_key_id` — so the working signal is checkable in one call: **no credential issued at or above the height carries a non-zero signature or a non-empty key id.** The misbehaving signal is an issuer who cannot issue at all, which is the intended cost and is not distinguishable in the receipt from a client that has simply not been upgraded. No counter. Pinned by `a_credential_asserts_an_uncheckable_signature_below_the_gate_and_not_above_it` and `either_half_of_the_signature_claim_is_refused_on_either_credential_family` (`crates/state/tests/docclass_closure_gates.rs`).

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R37 — `docclass_credential_validity_bound_enabled_from_height`
*accessor `DocClassExecutor::credential_validity_bound_activation, crates/state/src/docclass_executor.rs:506`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row AU-37, the `max_credential_validity` third. Below the gate the field is declared, defaulted, reported over `docclass_getConfig` and **read by no execution path**, so a credential declaring `valid_from: 0` and `expires_at: u64::MAX` is accepted against a configured ten-year maximum and the unbounded window is STORED. At and above the gate an issuance whose `expires_at - valid_from` exceeds a non-zero `max_credential_validity` returns a FAILED receipt carrying `DOCCLASS_CREDENTIAL_VALIDITY_TOO_LONG` (`crates/state/src/lib.rs:606`), before the deduct. **The blocker was the UNIT, and the unit is settled from the code rather than guessed from the field name.** The chain's canonical block timestamp is MILLISECONDS since the epoch: `PoaEngine::current_timestamp` builds it with `SystemTime::now().duration_since(UNIX_EPOCH).as_millis()` (`crates/consensus/src/poa.rs`), and `BlockHeader::timestamp` documents itself "(ms since epoch)". A credential's `valid_from` and `expires_at` are the same `Timestamp` alias as that field, so their difference is a duration in milliseconds and the bound is one too. The field's own doc comment said "in seconds" — a unit matching no clock in this tree — and now says milliseconds and names where that comes from. **Two configurations pass through untouched, each because the field's own documentation says so:** `max_credential_validity == 0` is NO LIMIT and is the default, so an operator who has configured nothing sees no change at the height; `expires_at == 0` is NO EXPIRY, so bounding it would refuse the credential the wire type calls unexpiring.

**2. Dependency ordering.** None at load; §0.7 rule (4) applies. **This is the only gate in the packet whose effect depends on a NON-GATE genesis field**, and that is worth stating: with `docclass.max_credential_validity` left at its default of 0 the height changes nothing at all. An owner scheduling it is scheduling a rule that does nothing until a second, separate edit to `DocClassParams` is made — and that second edit is NOT itself gated, so it takes effect on the block after the genesis is reloaded, at whatever height that is. The gate bounds WHETHER the field is read; the field bounds WHAT it refuses.

**3. Persistent data impact.** **None at or above the height.** Credentials issued BELOW it keep whatever window they recorded, including unbounded ones, and nothing re-examines them: the rule is applied at ISSUANCE and never at read, so an over-long credential written below the height stays valid, stays readable and stays unexpiring for ever. An owner should not read this height as "no credential on this chain outlives the maximum".

**4. Rollback in effect.** **A and B**, and A here is unusually clean because it is an OPERATOR lever rather than a client one: setting `max_credential_validity` back to 0 disables the rule without touching the height. That makes this the one gate in the set whose effect can be withdrawn after its height has passed, and the reason is that the height gates a READ of a mutable parameter rather than a rule with its own constant. B would be a different bound. No C — no row changes shape. No D.

**5. Monitoring signal.** M4 on `IssueCredential`, and the refusal names the bound's UNIT, deliberately: milliseconds is the one thing a submitter cannot infer from the wire type, where `valid_from` and `expires_at` are bare `u64`s. **M6 covers the check's inputs** — `docclass_getCredential` returns both timestamps and `docclass_getConfig` returns the configured bound — so the working signal is arithmetic an operator can do from two RPC calls. The misbehaving signal is the one that matters and it is the row's own warning: a LAWFUL credential refused because the bound is being read in the wrong unit. That is what the boundary case in `the_validity_bound_is_read_and_is_read_in_milliseconds` (`crates/state/tests/docclass_closure_gates.rs`) exists to catch — a window exactly equal to the bound is accepted and one MILLISECOND more is not, so the comparison's granularity is pinned as a number rather than asserted as prose. No counter.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R38 — `docclass_unknown_attribute_refused_enabled_from_height`
*accessor `DocClassExecutor::unknown_attribute_refused_activation, crates/state/src/docclass_executor.rs:534`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row D-19b, the half no height closed. R23 (`docclass_credential_schema`) extends the core field bounds, the attribute NAME cap and the per-attribute VALUE cap to every academic subcode, and deliberately leaves the attribute KEYS unrestricted for the subcodes whose standard lists none — 813 professional licence, 814 government id, 815 employment verification, and any later academic subcode — because inventing three allowlists in a remediation pass would be writing standard. So **above R23 an SRC-813 carrying an attribute named `ssn` is VALID**, while the same key on an SRC-810 transcript is refused by the allowlist that subcode does have. This gate invents no allowlist either. It takes the other reading of "no allowlist exists": a subcode whose standard names no public attribute classifies no key, so EVERY key on it is unknown, and an unknown key fails closed. At and above the height a credential on an uncovered subcode carrying ANY attribute returns a FAILED receipt carrying `DOCCLASS_UNKNOWN_ATTRIBUTE_REFUSED` (`crates/state/src/lib.rs:617`) before the deduct; one carrying NO attributes is issued exactly as before; and 810, 811 and 812 keep the lists they already have and keep taking the keys those lists classify. **The policy decision the row says is a policy decision is left open**, for a later standard to make by supplying an allowlist — at which point this gate stops refusing that subcode without any further height.

**2. Dependency ordering.** None at load; §0.7 rule (4) applies. **A real soft ordering against R23, in the opposite direction from the obvious one:** this gate does NOT require R23, and the two are about different things — R23 extends checks that already existed to families that lacked them, this one refuses a family's attributes outright. Opening this alone is coherent and is strictly stronger on the uncovered subcodes than opening R23 alone. The packet puts both in Wave 1 (R23 and this one), which means an operator gets the caps and the key refusal at the same block; that is a schedule fact and not a requirement.

**3. Persistent data impact.** **None at or above the height.** Credentials issued below it keep the attributes they recorded — including keys on this module's own explicitly-disallowed PII list — and nothing removes them. **That is the residue an owner should weigh**, because it is the whole reason the row exists: the gate stops new PII-shaped keys reaching an uncovered subcode and retracts none of the ones already there.

**4. Rollback in effect.** **A and B.** A is a client change: an issuer on an uncovered subcode submits the credential with an empty attribute list, which costs them the attributes and nothing else. B is the real exit and is the one to plan for: **defining an allowlist for 813, 814 or 815 narrows this gate without a further height**, because the refusal is keyed on the subcode having no list rather than on a constant. That makes this the only gate in the set that a later standard can relax by addition. No C, no D.

**5. Monitoring signal.** M4 on `IssueCredential`: the refusal names the SUBCODE's missing allowlist rather than the key, because no other key would have been accepted either. **M6 covers it** — `docclass_getCredential` returns `metadata.attributes` — so the working signal is that no credential on an uncovered subcode issued at or above the height carries any attribute at all. The misbehaving signal is an issuer with a legitimate, non-PII attribute losing the ability to record it; that is the intended cost, it is not distinguishable in the receipt, and the remedy is B rather than a rollback. No counter. Pinned by `an_unclassified_attribute_is_stored_below_the_gate_and_refused_above_it` (`crates/state/tests/docclass_closure_gates.rs`), which runs the SAME attribute key against an uncovered subcode and a covered one so the assertion is about the subcode and not about a validator that refuses everything.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R39 — `subsystem_ambiguous_policy_id_refused_enabled_from_height`
*accessor `subsystem_policy_id_activation, crates/state/src/lib.rs:550`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Row AU-8. Thirteen wire types across three subsystems carry a `policy_id: [u8; 32]` — Healthcare `ProviderProfile`, `MembershipRecord`, `ConsentEnvelope`, `Prescription`; Property `AssetAnchor`, `TitleEvent`, `Encumbrance`, `InsuranceCoverage`, `InsuranceClaim`; Agreement `AgreementCommitment`, `AttestationPacket`, `IpRightsAction`, and `ExecutorLink`'s `activation_policy_id` — and below the gate every one is written from the payload and consulted by no guard. **What makes that unsafe rather than merely unused is that nothing in this tree says WHICH NAMESPACE the value is in:** a policy-ACCOUNT id, which `PolicyAccountExecutor::v_get_policy_account` could resolve and which is mechanically reachable from the state crate, or a COMMITMENT to an off-chain policy document, which it could not. The two are typed identically so the compiler cannot tell them apart, no subsystem executor names `PolicyAccount` at all, and no `policy_id` in any fixture is a policy-account key. Binding them would be inventing the binding; binding them WRONG would refuse every lawful transaction of the other kind. At and above the gate a NON-ZERO `policy_id` returns a FAILED receipt carrying `AMBIGUOUS_POLICY_ID_UNRESOLVABLE` (`crates/state/src/lib.rs:581`), before the deduct, in **sixteen** arms. Sixteen and not thirteen: the three SUPERSESSION arms write a replacement of the same type, and a gate that refused the claim on creation while leaving supersession open would close nothing — the same lesson §0.7 rule (5) encodes for R30. `[0u8; 32]` is this tree's absent sentinel, the same null `Address::ZERO` and `Hash::ZERO` are, and stays accepted at every height, so an operation that names no policy is untouched. **The three proof envelopes are deliberately out of reach** — `HealthcareProofEnvelope`, `PropertyProofEnvelope` and `AgreementProofEnvelope` carry `policy_ids: Vec<PolicyId>` — because Property `SubmitProof` already refuses under R32 and every `VerifyProof` under `subsystem_proof_unsupported`, so a third refusal on an operation two gates already refuse would say nothing new.

**2. Dependency ordering.** None at load; §0.7 rule (4) applies. **This is the widest-blast-radius gate in the packet and the ordering that matters is not a load rule but a reach one:** it touches three subsystems at once, on one field, and it is ONE field deliberately — there is no configuration in which an operator wants a `policy_id` to be unresolvable in Property and meaningful in Healthcare, because the ambiguity is a fact about the tree and not about a subsystem. An owner who wants a narrower blast radius does not get it by scheduling differently; they get it by resolving the namespace, which is the B exit below.

**3. Persistent data impact.** **None at or above the height.** Every row already carrying a non-zero `policy_id` keeps it, and every RPC that returns one keeps returning it, so the unresolvable claim is permanent for everything already written — this gate stops new ones. **No row changes shape and no read path changes**, so a consumer reading `policy_id` sees exactly what it saw before, on old rows and on the zero-valued new ones alike.

**4. Rollback in effect.** **A and B.** A is a client change across three subsystems: submit `[0u8; 32]`. That is the widest client-side rollout item in the packet and should be costed as such — every issuer, every registrar and every agreement party has to stop sending a value the chain has been storing since genesis. B is the real exit: **deciding what a `policy_id` names**, which would let a later height resolve rather than refuse. Nothing in this schedule supplies that decision. No C — no row shape changes. No D — nothing moved value.

**5. Monitoring signal.** M4 on all three subsystems: the refusal names the AMBIGUITY and not the value, so a receipt is unambiguous about which claim was refused. **M6 covers part of it** — `property_getAsset`, `healthcare_getProvider` and their siblings return `policy_id` — so the working signal is that no row created at or above the height carries a non-zero one. The misbehaving signal is a lawful operation that genuinely needed to name a policy being unable to; that is the intended cost, and because it is intended there is no instrument that distinguishes it from the gate working. No counter. Pinned behaviourally by `a_property_asset_claims_an_unresolvable_policy_below_the_gate_and_not_above_it`, `a_healthcare_provider_...` and `an_agreement_...`, and structurally by `every_arm_that_stores_a_policy_id_calls_the_refusal`, which reads the three executors and requires all sixteen arms to call the guard (`crates/state/tests/ambiguous_policy_id_gate.rs`). The structural test is the one that matters for reach: the realistic failure in sixteen near-identical guards is a missing one, not a wrong one.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

### R40 — `nft_royalty_operation_unsupported_enabled_from_height`
*accessor `NftExecutor::royalty_operation_unsupported_activation, crates/state/src/nft_executor.rs:479`* — cost shape **REFUSAL ONLY**

**1. Affected behaviour.** Rows RY-2 and RY-3, the residue the two existing royalty gates leave between them. R33 (`nft_unpayable_royalty_refused`) refuses a non-zero `royalty_bps` at CREATION, which is the only place `royalty_bps` can be set. R19 (`nft_update_path_parity`) refuses a `new_royalty_recipient` only for a collection whose `royalty_bps` is ZERO, which is the rule creation applies. **Neither reaches a collection created BELOW R33 with a non-zero `royalty_bps`**: its recipient stays settable, re-settable and published by `nft_getCollection`, for ever. At and above this height an `UpdateCollectionConfig` carrying a `new_royalty_recipient` returns a FAILED receipt carrying `ROYALTY_OPERATION_UNSUPPORTED` (`crates/state/src/lib.rs:630`), for EVERY collection, before any field is written — and an update carrying only `new_base_uri` is applied exactly as before, so the arm is not shut down. **The ground is the same as R33's and is re-established rather than inherited:** `NftTransferData` is `{ to }`, `execute_transfer` and `v_transfer_token` move a token and no balance, and **nothing anywhere in the tree computes a royalty amount** — so the recipient field records who would be paid out of a price that does not exist.

**2. Dependency ordering.** None at load; §0.7 rule (4) applies. **Deliberately a separate height from R19, and the reason is what each one claims:** parity says the update path should apply the rule CREATION applies, and would be right even if royalties were paid; this says the operation is unpayable at all. An operator must be able to take the first without the second, and a reader of either receipt must be able to tell which claim was refused. The refusal here is placed AHEAD of the parity refusal in the arm, because it is the wider claim. Together with R33 the three cover the whole royalty surface: creation, the zero-royalty update, and the paying-collection update.

**3. Persistent data impact.** **None at or above the height** — a refused update writes nothing, and the collection keeps whatever recipient it already held. **The residue is the same one R33 carries and is worth repeating because this gate does not fix it either:** every collection created below R33 keeps its `royalty_bps` and its `royalty_recipient`, and `nft_getCollection` keeps publishing both. A marketplace reading the chain after both heights is still told a royalty exists on those collections. What the pair stops is new claims and changes to old ones.

**4. Rollback in effect.** **A and B.** A is a client change and a narrow one: submit an `UpdateCollectionConfig` with `new_royalty_recipient: None`. B is the royalty protocol itself — a two-sided order, a standing listing or an escrowed bid, which is a new wire type and for two of the three a new state family — and R33 already records that as a future design rather than a superseding narrow. No C. **No D, and the reason is the point of the whole royalty group: no royalty has ever been paid on this chain, so no recipient loses income.**

**5. Monitoring signal.** M4 on `UpdateCollectionConfig`, and **M6 `nft_getCollection`**: the working signal is that no collection's `royalty_recipient` changes at or above the height, checkable against any collection an operator is watching. The misbehaving signal is demand for a feature the chain never had, which makes this — like R33 — a gate whose "misbehaviour" is a product decision rather than a fault. No counter. Pinned by `a_royalty_recipient_stops_being_recordable_on_any_collection` (`crates/state/tests/nft_update_path_parity_gate.rs`), which uses a collection paying 250 bps precisely so the refusal cannot be R19's.

**6. Recommended wave.** Wave 1. **Proposed height:** — owner decision —

---

## Part 1B — The 18 PREDATING gates

`GATES_PREDATING_ACTIVATION_RECORDING` (`crates/genesis/src/lib.rs:2783`) is a **closed** list: it names the gates that shipped in binaries which produced existing blocks, which is a historical fact and cannot grow. A gate on it **may legally sit at or below the head**; every other gate may not (§0.4).

Eight of the eighteen have a passed height. Two are confirmed dormant over RPC. **Eight are neither RPC-visible nor named in the production checklist's genesis**, so their deployed value cannot be established from outside a node today. That is a consequence of `chain_getChainParams` serialising only six of the sixty-three, and it is exactly what `chain_getActivationStatus` exists to fix.

For the eight that have passed, fields 1-3 are history rather than a decision, and field 6 is "nothing to schedule". They are stated anyway, because an owner reading a 56-gate table needs to know which rows are already spent.

---

### P1 — `v2_enabled_from_height`
*declared `crates/genesis/src/lib.rs:342`* — deployed value: 5,200,000 — **PASSED** (RPC-confirmed)

**1. Affected behaviour.** SNIP V2 storage transactions (`NodeRegistryV2`, `StorageMetadataV2`) are valid. Below it every V2 transaction receipts as `TxStatus::Failed(40)` without consuming the sender's fee.

**2. Dependency ordering.** None.

**3. Persistent data impact.** V2-shaped storage metadata has been written since height 5,200,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** M1 `gates[].active` once deployed; today `chain_getChainParams.v2_enabled_from_height` is the only external confirmation, and it reads `5200000`. Operationally settled.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P2 — `omninode_enabled_from_height`
*declared `crates/genesis/src/lib.rs:355`* — deployed value: 6,000,000 — **PASSED** (RPC-confirmed)

**1. Affected behaviour.** The OmniNode `InferenceAttestation` subprotocol is active; v1 attestation (`sender == verifier`) is governed by this gate exclusively.

**2. Dependency ordering.** None. The sponsored-attestation gate below is independent of it.

**3. Persistent data impact.** Attestation rows have been written since height 6,000,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `chain_getChainParams` reads `6000000`; `sum_listInferenceAttestations` / `sum_getInferenceAttestation` are the read-side confirmation.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P3 — `omninode_sponsored_attestation_enabled_from_height`
*declared `crates/genesis/src/lib.rs:365`* — deployed value: **not serialised by RPC; absent from the production checklist's genesis → presumed `None`, unverifiable from outside**

**1. Affected behaviour.** Sponsored / relayed v2-envelope attestation submission (issue #79). Dormant, `TxPayload::InferenceAttestationV2` is rejected free (`Failed(54)`, no fee).

**2. Dependency ordering.** None. Explicitly independent of `omninode_enabled_from_height`: v1 attestation is unaffected either way.

**3. Persistent data impact.** Changes who PAYS to submit, not who made the attestation. No new attestation data shape.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires.

**5. Monitoring signal.** M1 is the only instrument that would report its height, and it is not deployed. **Its current value cannot be established from outside a node today** — that is a gap, not a finding.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P4 — `education_enabled_from_height`
*declared `crates/genesis/src/lib.rs:379`* — deployed value: 8,900,000 — **PASSED** (RPC-confirmed)

**1. Affected behaviour.** The SRC-817/818 Education-LMS suite is executable.

**2. Dependency ordering.** None.

**3. Persistent data impact.** Education subsystem rows have been written since height 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `chain_getChainParams` reads `8900000`; `src817_*` / `src818_*` read methods confirm.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P5 — `contracts_enabled_from_height`
*declared `crates/genesis/src/lib.rs:395`* — deployed value: 8,900,000 per `docs/operations/production-checklist.md:115` — **PASSED**, but **not serialised by RPC**, so unconfirmable from outside

**1. Affected behaviour.** Production-capable smart contracts: persistent storage, reorg-reversible contract state, root-committed. `ContractDeploy`/`ContractCall` execute; below the gate they are rejected free.

**2. Dependency ordering.** None at load. **Note the interaction with the account-root gate**: `contract_executor.rs` credits the CONTRACT address on a value-carrying deployment, an address no transaction index reaches — which is one of the two reasons the production `cf::STATE` row count is unknown (`docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md §1.2`).

**3. Persistent data impact.** **Activation changed the block state-root formula.** Contract state has been written and root-committed since 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `contract_isContract` / `contract_getCodeHash` confirm the subsystem is live. **The height itself is not RPC-visible**, so the checklist is the only record of it; M1 would settle it.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P6 — `governance_enabled_from_height`
*declared `crates/genesis/src/lib.rs:449`* — deployed value: 8,900,000 — **PASSED** (RPC-confirmed)

**1. Affected behaviour.** On-chain governance v1: `TxPayload::Governance` operations execute.

**2. Dependency ordering.** Not a gate ordering, but a hard companion dependency: the separate `governance: Option<GovernanceParams>` field must be present or governance operations are rejected even above the height. It is present on mainnet (`validator_authority_threshold_bps: 6667`, quorum 2000 bps, pass 5000 bps, voting period 201,600 blocks).

**3. Persistent data impact.** Proposal and vote state has been written since 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `gov_listActiveProposals`, `gov_getTally`, `gov_getVotingPower`. **This is the gate that makes rollback lever D possible at all** — a governance transaction at validator quorum, which on the two-validator net needs both signatures.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P7 — `archive_unbonding_enabled_from_height`
*declared `crates/genesis/src/lib.rs:474`* — deployed value: 8,900,000 per the production checklist — **PASSED**, not RPC-visible

**1. Affected behaviour.** Archive-node stake withdrawal (issue #20): `BeginUnstake` / `WithdrawUnbonded` execute.

**2. Dependency ordering.** None between gates. `archive_unbonding_period_blocks` is consulted only once this gate is set; it is distinct from validator staking's `unbonding_period`.

**3. Persistent data impact.** Unbonding and stake rows have been written since 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `storage_getArchiveUnbonding`.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P8 — `archive_reassignment_enabled_from_height`
*declared `crates/genesis/src/lib.rs:489`* — deployed value: 8,900,000 per the production checklist — **PASSED**, not RPC-visible

**1. Affected behaviour.** Archive-node chunk reassignment (issue #62): `ReassignChunksV2` and post-activation `AcceptAssignmentV2` re-attestation execute.

**2. Dependency ordering.** None. Distinct from the two PoR targeting gates below.

**3. Persistent data impact.** Assignment and epoch rows have been written since 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `storage_getAssignmentCoverageV2`, `storage_buildReassignChunksV2`.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P9 — `por_assignment_targeting_enabled_from_height`
*declared `crates/genesis/src/lib.rs:504`* — deployed value: **not serialised by RPC; absent from the checklist genesis → presumed `None`**

**1. Affected behaviour.** Assignment-aware PoR challenge targeting (issue #97, Phase 1). Legacy behaviour draws `target_node` from ALL globally-active archives, which can challenge and slash a bystander not assigned to the challenged `(file, chunk)`. Gated, the target is drawn only from archives assigned to that chunk under the file's latest assignment epoch and currently Active; if none, the challenge is skipped for that interval.

**2. Dependency ordering.** None. Distinct from `archive_reassignment_enabled_from_height` (#62) and from the Phase 2 scheduler gate (#100).

**3. Persistent data impact.** No new data shape. It changes WHICH node is targeted and whether a challenge is emitted at all — hence which challenge and slashing rows come into existence.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires. Slashing records written under the legacy targeting are not revisited.

**5. Monitoring signal.** `storage_getActiveChallenges`, `slashing_getRecentRecords`, `slashing_getSummary`. **The working signal is slashing records stopping for nodes not assigned to the challenged chunk.** Its current value is unverifiable from outside (M1 not deployed).

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P10 — `service_grants_enabled_from_height`
*declared `crates/genesis/src/lib.rs:513`* — deployed value: `null` — **DORMANT** (RPC-confirmed)

**1. Affected behaviour.** Service-grant claiming (the 800B supply correction). Dormant, all `Supply` transactions (grant claim / unlock) are rejected free (`Failed(380)`, no fee, no state).

**2. Dependency ordering.** None. **Important scope note from the source**: the one-time supply correction and earned-credit/milestone ACCRUAL are INDEPENDENT of this gate — they key off the persisted correction marker — so accrual writes happen whether or not the gate is open.

**3. Persistent data impact.** Claiming only. Accrual is already writing.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires. Once claims are paid, **D** is the only instrument.

**5. Monitoring signal.** `chain_getServiceGrant`, `chain_getServiceGrantEligibility`, and **M7** — claimed grants move the accounted supply. The source says to set it "once final pool/cohort numbers are ratified", which is an owner decision this document does not make.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P11 — `monetary_policy_enabled_from_height`
*declared `crates/genesis/src/lib.rs:522`* — deployed value: `null` — **DORMANT** (RPC-confirmed)

**1. Affected behaviour.** Dormant, `ReserveRelease*` and `MonetaryPolicyMint` governance proposals cannot be created or executed (fail-closed). Set, those classes remain executable ONLY through NativeEligibility (native Koppa consensus) governance at the hardcoded 6667 bps threshold — never validator-quorum, never SRC-20/equity governance.

**2. Dependency ordering.** None between gates. It presupposes `governance_enabled_from_height` in substance (there are no proposals without governance), and that gate is passed.

**3. Persistent data impact.** Accept/reject of proposal creation and execution. Once executed, a mint moves the supply permanently.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires. An executed mint is undone only by **D**.

**5. Monitoring signal.** `gov_getNativeEligibility`, `gov_listProposals`, `chain_getProtocolReserve`, and **M7**. **This is the highest-value dormant gate in the 18** — it is the one whose activation can change the money supply — and it is fail-closed today, which is the right default.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P12 — `assignment_aware_por_scheduler_enabled_from_height`
*declared `crates/genesis/src/lib.rs:555`* — deployed value: **not serialised by RPC; presumed `None`**

**1. Affected behaviour.** Bounded assignment-aware PoR scheduler (issue #100, Phase 2). Dormant, challenge generation is exactly the post-#101 single-challenge path. Open, each challenge interval emits a bounded deterministic SET of assignment-aware challenges instead of one.

**2. Dependency ordering.** None. Explicitly never shared with `por_assignment_targeting_enabled_from_height` (#97 Phase 1). Its three cap parameters (`max_assignment_aware_challenges_per_block`, `max_files_sampled_per_interval`, `max_chunks_sampled_per_file`) are consulted only when the gate is open.

**3. Persistent data impact.** **Changes the NUMBER of challenge records produced per interval** — more rows per block, bounded by the cap parameters. Not an accept/reject of user transactions.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires. **C** applies: the extra challenge rows are permanent.

**5. Monitoring signal.** `storage_getActiveChallenges` row count per interval, and node disk growth. **The caps are the thing to set before the height**, because an unbounded increase in challenges per block is a write-set growth the candidate ceiling can refuse.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P13 — `inference_settlement_enabled_from_height`
*declared `crates/genesis/src/lib.rs:579`* — deployed value: 8,900,000 per the production checklist — **PASSED**, not RPC-visible

**1. Affected behaviour.** OmniNode Inference Settlement (issue #61). Dormant, all settlement operations reject free (`Failed(350)`, no fee).

**2. Dependency ordering.** Separate from `omninode_enabled_from_height` — attestation recording is unaffected either way. Its bound parameters are consulted only once settlement is enabled. **Disputes additionally require `inference_settlement_dispute_threshold_bps` to be `Some(bps)`** or `OpenDispute`/`ResolveDispute` are rejected; mainnet has it at 6667.

**3. Persistent data impact.** Session and escrow state has been written since 8,900,000.

**4. Rollback in effect.** **Frozen. Nothing to roll back and nothing to schedule.** The height is at or below the head, so `activation_changes` classifies any change to it as `AlreadyActive` and the node refuses to start (§0.5). The only levers are **B** — a superseding gate at a later height — and **E**.

**5. Monitoring signal.** `omninode_getInferenceSession`, `omninode_getInferenceClaims`, `omninode_getInferenceDisputes`.

**6. Recommended wave.** **Nothing to schedule** — the height has passed and is frozen.

---

### P14 — `inference_settlement_consistency_enabled_from_height`
*declared `crates/genesis/src/lib.rs:610`* — deployed value: **not serialised by RPC; presumed `None`**

**1. Affected behaviour.** Consistency / plurality settlement mode (issue #77). Dormant, an `OpenSession` requesting a consistency config is rejected `Failed(361)` and existing single-verifier v1 claims are unaffected. Open, sessions may opt into a consistency rule and matured claims are evaluated against it.

**2. Dependency ordering.** Independent of `inference_settlement_enabled_from_height`, though layered on it: it is a stricter claim rule on top of enabled settlement, not a new family.

**3. Persistent data impact.** Accept/reject of consistency-config sessions plus a stricter claim-evaluation rule. Claims settled below the gate are not re-evaluated.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires.

**5. Monitoring signal.** `omninode_getInferenceConsistency`, `omninode_getClaimableReward`. The working signal is a consistency-config `OpenSession` ceasing to fail `361`.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P15 — `inference_verifier_bonding_enabled_from_height`
*declared `crates/genesis/src/lib.rs:621`* — deployed value: **not serialised by RPC; presumed `None`**

**1. Affected behaviour.** Verifier bonding and slashing (issue #78). Dormant, bond-registry operations reject free (`Failed(364)`) and a session requesting a `bond_requirement` fails `364`; sessions without a bond requirement are unaffected. Open, verifiers may register bonds and bond-required sessions enforce and slash.

**2. Dependency ordering.** Independent of `inference_settlement_enabled_from_height` (it layers on enabled settlement). `inference_verifier_unbonding_period_blocks` is consulted only once bonding is enabled.

**3. Persistent data impact.** **Both**: refusal below, and above it a bond registry is written and **slashing moves balances**.

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires. Slashed bonds are recovered only by **D**.

**5. Monitoring signal.** `omninode_getVerifier`, `omninode_buildAddVerifierBond`, and **M7** for the balance movement. Set the unbonding period before the height, not after.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

### P16 — `compute_pool_enabled_from_height`
*declared `crates/genesis/src/lib.rs:642`* — deployed value: `None` — **REFUSED AT LOAD; NOT SCHEDULABLE**

**1. Affected behaviour.** Compute-pool subprotocol. `ChainParams::validate` returns `GenesisError::IncompleteSubsystemActivation` for any `Some(_)` (§0.7 rule 1). Blocked on the `ComputePoolParams` surface existing (B0 #123 + C1 #130).

**2. Dependency ordering.** **It is itself the constraint.** Any height refuses the genesis at load.

**3. Persistent data impact.** None — nothing is activatable.

**4. Rollback in effect.** Not applicable. A genesis carrying a height here never starts a node.

**5. Monitoring signal.** None needed. The working signal is that `Genesis::validate()` refuses the configuration, which is the point.

**6. Recommended wave.** **Not schedulable** — refused at load (§0.7).

---

### P17 — `beacon_enabled_from_height`
*declared `crates/genesis/src/lib.rs:706`* — deployed value: `None` — **REFUSED AT LOAD; NOT SCHEDULABLE**

**1. Affected behaviour.** Threshold-BLS beacon. Same hard refusal (§0.7 rule 2). Blocked on the BR1 #127 parameter surface.

**2. Dependency ordering.** **Declaring `beacon_params` or `beacon_schedule` does NOT open it.** Both MAY be declared while the gate stays dormant, and `validate()` checks each for internal consistency (§7.4 inequalities; `epoch_length >= 1`, strictly-ordered phase offsets) and still refuses any `Some(_)` on the gate.

**3. Persistent data impact.** None.

**4. Rollback in effect.** Not applicable.

**5. Monitoring signal.** None needed. A declared-but-dormant parameter surface that passes `validate()` is the intended state.

**6. Recommended wave.** **Not schedulable** — refused at load (§0.7).

---

### P18 — `messaging_sponsored_registration_enabled_from_height`
*declared `crates/genesis/src/lib.rs:750`* — deployed value: **not serialised by RPC; presumed `None`**

**1. Affected behaviour.** SRC-201 sponsored public-key registration (issue #145). Dormant, `RegisterPublicKeySponsoredV1` rejects free (`Failed(390)`, no fee, no state). **The source is explicit that this is a fully-implemented ACTIVATION gate, not a dormant-until-built one** — unlike compute-pool and beacon.

**2. Dependency ordering.** Explicitly excluded from the reject-all arm of `ChainParams::validate`, which guards only subsystems whose typed parameter surface does not exist. Enforcement is in the state executor's gate check, mirroring `omninode_sponsored_attestation_enabled_from_height`.

**3. Persistent data impact.** Accept/reject below; above it, keys registered via the sponsored path. The source adds: "Never set to `Some(_)` in a committed genesis in this branch."

**4. Rollback in effect.** **Not applicable while dormant.** If the owner ever opens it, the §0.4 floor applies from that moment (it is grandfathered against a height BELOW the head, not against a retroactive one), and **B** becomes the only forward lever once it fires.

**5. Monitoring signal.** `account_getPublicKey`, `messaging_registerSponsored`, `messaging_getConfig`. It is the one gate in the 18 that is ready to schedule and simply has not been.

**6. Recommended wave.** **Out of band.** Not a member of any wave below: the waves group the remediation set by cost shape, and this gate is a subsystem activation with its own readiness question. **Proposed height:** — owner decision —

---

## Part 1C — The 3 gates that are NEITHER

These three are introduced by this work, so §0.4's floor applies to them in
full, but none is a remediation gate: they add or constrain machinery rather
than repair a subsystem defect. **All three of the system's load-time ordering
constraints (§0.7 rules 3 and 4) live in this group**, and two of the three are
coupled to each other. They are therefore scheduled out of band from the
cost-shape waves, not inside them.

---

### N1 — `peer_protocol_declaration_required_from_height`
*declared `crates/genesis/src/lib.rs:1373`; default `None`* — cost shape **PEER ADMISSION**

**1. Affected behaviour.** From this height, a peer must have DECLARED a
protocol digest equal to ours before it may take part in consensus. Today
`sumchain_state::protocol_digest` (`crates/state/src/protocol_digest.rs:346`)
refuses a peer that declares a DIFFERENT digest and admits a peer that declares
NOTHING. Below the height, or unset, an undeclared peer may participate exactly
as today; at or above it, it **may not propose, vote, or move fork choice**.
Matching-digest peers participate in both phases; different-digest peers in
neither. `None` does not mean "always enforce" — it means **phase one forever**:
no peer is ever refused for silence.

**2. Dependency ordering.** **This is one half of §0.7 rule (4), and it is the
only gate in the 63 whose height is constrained by the heights of other gates at
load time:**

```
peer_protocol_declaration_required_from_height <= min(height of any open REMEDIATION_GATES)
```

Both directions are refused at load, because both produce the same band of
heights in which the guarantee is absent: enforcement set LATER than the first
remediation gate leaves an explicit window; enforcement left `None` leaves an
unbounded one. `remediation_activation_floor()` (`:2593`) computes the right
hand side. **Setting any one of the 37 forces this field to be set.** Both
`None` is legal and is the production default.

**3. Persistent data impact.** **None.** It changes peer admission and consensus
participation, not transaction acceptance and not written state. It is folded
into the activation digest and therefore into the protocol digest, so changing
it changes the value peers compare.

**4. Rollback in effect.** **B and E.** A mis-set enforcement height that
excludes a validator cannot be lowered once passed. The practical mitigation is
not rollback but preparation: every validator must be running a binary that
declares a matching digest *before* the height, and that is checkable in advance
through M1's `protocol_digest`.

**5. Monitoring signal.** **M1 is the pre-flight instrument and M8 is the
post-flight one.** `chain_getActivationStatus.protocol_digest` answers "do our
nodes enforce the same rules" — two binaries from different commits can report
the same `digest` and a different `protocol_digest`, and it is the same value
peers compare at the sync handshake, so a monitor scraping it sees exactly what
the nodes see. After the height, `sumchain_peer_count` dropping and `get_peers`
shrinking is the gate working if the dropped peers are undeclared, and the gate
misfiring if they are not. **With PoA round-robin and no proposer-skip
(§0.9), excluding one of two validators stops half the slots**, so M2 is the
failure signal.

**6. Recommended wave.** **Wave 0 — a prerequisite, not an activation.** See
Part 2. **Proposed height:** — owner decision —, subject to `<=` the earliest
remediation height chosen.

---

### N2 — `application_journal_enabled_from_height`
*declared `crates/genesis/src/lib.rs:698`; default `None`* — cost shape **NODE-LOCAL UNDO AUTHORITY**

**1. Affected behaviour.** Unusual, and the inversion matters: **it does not gate
WRITING.** `AcceptedCandidate::publish` writes a journal record for every block
it publishes, with no gate to leave unset — pinned by
`crates/storage/tests/application_journal.rs:761 the_write_side_is_ungated_so_no_configuration_can_leave_it_unwritten`.
What it gates is the height from and above which a REVERT must find a record,
and above which the generic journal — not the four legacy per-subsystem diffs —
is the authoritative undo record for a block.

`None` is **not "off"; there is no off.** It means the boundary is OBSERVED FROM
CHAIN: the lowest height for which this database holds a record, which is
per-node. `Some(h)` pins a uniform, operator-visible, genesis-defined boundary.

**2. Dependency ordering.** **This is one half of §0.7 rule (3):**

```
application_journal_enabled_from_height <= account_root_enabled_from_height
```

`(None, Some(account_root))` is refused as `AccountRootWithoutJournalGate`;
`journal > account_root` is refused as `JournalGateAfterAccountRoot`. Both `None`
is legal and is the production default. It deliberately does NOT reuse the
compute-pool or beacon gates, and unlike those two, `Genesis::validate` **admits**
`Some(_)` here.

**3. Persistent data impact.** **None to what is written** — the write side is
unconditional. It changes revert authority and whether a reorg is REFUSED.
**Explicitly not consensus:** journal records are node-local, never hashed into a
block, never folded into a state root, never sent over the wire. Two nodes that
disagree about this height cannot fork; one of them simply refuses a reorg the
other would perform.

**4. Rollback in effect.** **B**, and uniquely among the 63, a genuine operational
option: because the value is not consensus, a node that refuses a reorg can be
restarted under a corrected genesis without the chain caring — subject to §0.5's
freeze, which still applies because the field is in the activation digest.

**5. Monitoring signal.** There is **no direct instrument.** The failure is a
node that declines a reorg it should have performed, which surfaces as that node
falling behind: **M2 (`sumchain_block_height` for that node diverging from the
network's) and M3 (`sumchain_block_errors_total`)**, plus the node log. M1 would
report the height once deployed. **The absence of a journal-coverage RPC is worth
noting before this is set**, because `Some(h)` is a promise that every node holds
records from `h`, and nothing verifies that claim from outside.

**6. Recommended wave.** **Out of band, and only as the lower half of the
account-root pair.** Setting it alone buys a uniform boundary and nothing else;
its reason to exist is rule (3). **Proposed height:** — owner decision —, subject
to `<=` the account-root height.

---

### N3 — `account_root_enabled_from_height`
*declared `crates/genesis/src/lib.rs:433`; default `None`* — cost shape **ROOT FORMULA**

**1. Affected behaviour.** Folds the ACCOUNT-STATE COMMITMENT — balances and
nonces — into the block state root. This **closes a consensus hole rather than
enabling a subprotocol**: below the gate `compute_block_state_root` never reads
the account rows, so two nodes can disagree about every balance on the chain and
still publish identical block hashes.

**2. Dependency ordering.** The upper half of §0.7 rule (3): it requires
`application_journal_enabled_from_height` to be `Some(_)` and at or below it.
The argument, from the source: above this gate a node that cannot RESTORE
account rows during a reorg cannot agree about the root either — it is stuck
with a state it can neither revert nor justify — and the generic journal is the
only record that restores every family a block wrote. A node-local observed
boundary is not something a consensus commitment may rest on: two validators
would hold different boundaries and find out at a reorg.

**3. Persistent data impact.** It changes **what is COMMITTED**, not which rows
are written; the account rows already exist. Consequently an un-upgraded node
above the height computes a different root for the same block and rejects it.

**4. Rollback in effect.** **B and E only, and B is expensive.** The domain
separator is versioned (`b"sumchain/account-state/v1"`,
`crates/state/src/account_root.rs:234`), so a `v2` domain can replace the fold at
a second, later height — that is the intended forward path, and it is also how
the eventual trie replacement would land. Nothing un-commits a root.

**5. Monitoring signal.** This gate has **the best-instrumented cost model in the
repository and the worst-established precondition.**

- Cost: the fold is an O(n) scan of `cf::STATE` account rows. Measured on a dev
  Mac: 100k rows → 13.4 ms, 1M → 159 ms, 10M → 1.586 s warm / 1.765 s cold-page,
  against a **1,502 ms** inter-block interval (§0.3). **At ten million rows it
  does not fit inside a block interval.**
- Thresholds: `ACCOUNT_ROW_WARN_THRESHOLD = 250_000`
  (`account_root.rs:471`) and `ACCOUNT_ROW_ACT_THRESHOLD = 500_000` (`:484`).
- Instruments: **M5** (`chain_getSyncCapability.account_rows`, backed by
  `account_row_count` at `account_root.rs:499`) and the node's startup log line
  `Account rows: N (warn at 250000, act at 500000)`. **There is no Prometheus
  gauge, and that absence is deliberate** — `account_rows` IS the O(n) scan, so
  polling it at a 15 s scrape interval would add a full account scan to every
  node every 15 seconds. The runbook prescribes once at startup, then at most
  every 15 minutes from one node.
- Post-activation, the signal that it is working is that block production time
  rises by the scan cost and no more; the signal that it is not is nodes
  rejecting each other's blocks, i.e. M2 flat and M3 rising.

**The precondition is not met.** The production `cf::STATE` row count is
**UNPROVEN** — see `docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md §1`, which
carries the exact command, the endpoint requirement, the expected output, what
must be recorded alongside it, and an acceptance threshold.
`docs/operations/ACCOUNT-ROOT-ACTIVATION.md` makes that measurement Sequence
step 0 and says the activation "should not be scheduled until it has been"
measured. **This document does not weaken that, and does not propose a height.**

**6. Recommended wave.** **Out of band, blocked on an external measurement.**
Not a member of any wave below. **Proposed height:** — owner decision —, and not
before the row count is measured.

---
## Part 2 — The recommendation: one prerequisite, five waves, one deferral, two out of band

Part 1 gives the owner 61 rows. This part is the schedule: **the fewest waves
that are still safe, with heights.** It is a recommendation, not a setting — no
height is written anywhere in this branch.

### 2.1 What the previous packet argued, and why it is kept

The earlier packet grouped seventeen gates into three waves **by cost shape** —
refusal-only, data-shape, block-existence — and argued that grouping against the
frozen-height property: since a passed height cannot be moved (§0.5), "reversible"
means *reversible in effect*, and gates differ in what an error costs. A gate
that only REFUSES more transactions costs availability, is visible in the next
block as failed receipts, and writes nothing new. A gate that changes WHERE A ROW
LANDS writes rows that persist and cannot be unwritten. A gate that changes
WHETHER A BLOCK EXISTS costs liveness.

**That argument is correct and is kept.** Grouping by subsystem would have been
tidier and would have mixed all three shapes into every wave.

### 2.2 Why three waves do not survive the set growing to 35

The argument for bundling twelve gates into one wave was explicitly conditional:
"they share a failure shape and a diagnosis. If legitimate traffic starts
failing, the failed receipt names the subsystem, so a twelve-gate wave is still
diagnosable. **That is the argument for bundling, and it holds only because of
the receipt.**"

Sorting the current 35 by cost shape gives **19 refusal-only, 15 data-shape, 1
block-existence**. Applied unchanged, the old scheme puts fifteen irreversible
gates at one height — and the diagnosability argument does not transfer, because
a data-shape gate's symptom is not a receipt. It is a row that landed somewhere
else, a disk-growth rate that changed, or a state root that moved for a
transaction whose receipt is unchanged (R27 and R35 say exactly that). **Fifteen
simultaneous shape changes share no single symptom, so a surprise cannot be
attributed to one of them.**

So the extension is: **keep the three cost shapes, and split the data-shape wave
by which persistent artefact moves** — because that is the axis along which a
surprise is actually attributed.

| sub-shape | what moves | the one symptom to watch |
|---|---|---|
| **2a — key space** | a row lands at a different key, or an id is computed differently | **row count and disk growth rate**, plus reads by an old key |
| **2b — row content / existence** | same keys, different contents or presence | **state root moves for a transaction whose receipt is unchanged**; subsystem read paths change answers |
| **2c — value and fee** | balances, fees, or the receipts root | **fee accounting and the money supply** (M7) |

Each sub-wave has one signal that attributes a surprise to it. That is the
property the original three-wave scheme had at seventeen gates and loses at 35,
and recovering it is the reason for the split.

**What the split costs:** two more coordinated restarts. On a two-validator PoA
net with no proposer-skip (§0.9) each restart stalls half the slots for the
duration of a rolling restart. That is the trade, stated rather than buried: two
extra restarts against the ability to name which gate caused an irreversible
surprise.

### 2.3 The waves

Heights are derived from **head 12,977,656 at 2026-09-19T05:35:38Z** and
**57,524 blocks/day** (§0.3). Every one must be re-derived against the head at
the moment of decision.

#### Wave 0 — compatibility enforcement. A prerequisite, not an activation.

`peer_protocol_declaration_required_from_height` (N1).

**This is not a choice.** §0.7 rule (4) refuses the genesis at load unless this
field is set at or below the earliest open remediation gate. It must therefore
be decided *with* Wave 1 and not after it.

Recommended: **the same height as Wave 1**, or earlier. Equal satisfies `<=`.

Wave 0 also contains the thing that is not a height at all: **the binary
rollout.** Every one of the 40 is code that is not on mainnet (§0.2). A genesis
edit without the binary is a number nothing reads. **R30 adds a second rollout
item that is not a binary:** every client that submits `GrantConsent` must be
upgraded to the `ConsentGrantRequest` payload before that height. **The
`sumchain-wire` VERSION half of that item is settled**: the crate is 0.5.0, not
0.4.0, and the workspace dependency spec moves with it, because a byte-frozen
published crate gaining a public type is the next API and not a patch of the
current one. The PUBLISH half is still not decided in this branch.

**Five of the 40 are new in the release-closure wave — R36 to R40 — and four of
them add a second client-side rollout item each**, which an owner scheduling
them should read as a rollout cost rather than a genesis edit: R36 refuses a
credential carrying a signature or a key id, R37 refuses one whose validity
window exceeds the configured maximum, R38 refuses an attribute on an
unclassified subcode, and R39 refuses a non-zero `policy_id` in sixteen arms
across three subsystems. Every one of those is a payload a client sends today
and will have to stop sending. R40 is the exception: it refuses an operator
action on a collection, not a routine client payload.

#### Wave 1 — refusal-only. 24 gates. Recommended height **13,782,992** (head + 14 days, ≈2026-10-03)

R4, R5, R6, R7, R8, R9, R10, R13, R15, R18, R20, R23, R25, R29, R30, R31, R32,
R33, R34, R36, R37, R38, R39, R40.

The five added by the release-closure wave are all refusal-only and all take the
same shape as the nineteen before them — a failed receipt ahead of the deduct,
no row written, no state-root movement on the refusal — so they belong in this
wave for the reason the others do. **R30 and R5 must be in the same wave or R5
earlier**, which Wave 1 satisfies by holding both; that is now a load rule
(§0.7 rule 5) rather than a scheduling note.

The six subsystem authorization gates, DocClass revocation standing, the
allocation bound, NFT token authority, subsystem proof presence, the no-op
receipt gate, the credential-schema gate, the issuer-stake-requirement gate, the
four structural refusals (Agreement party authority, Tax/Finance issuer
self-registration, Property proof submission, the unpayable NFT royalty), the
Property state preconditions, and the consent subject signature.

- **Data migration:** none. No existing row changes shape or location.
- **Mixed-version:** prevented by Wave 0. Absent it, the two sides disagree about
  receipts, and receipts are folded into the state root, so they fork.
- **Rollback:** A and B (§0.6). The mitigation is that the failure mode is a
  refusal — an operation stops working, loudly.
- **Why one wave and not thirteen:** they share a failure shape and a diagnosis,
  and the failed receipt names the subsystem. **That argument now carries a
  caveat it did not carry before:** §0.8 establishes that
  `sumchain_tx_execution_errors_total` is dead, so "visible in the next block as
  failed receipts" means one `sum_getReceipt` call per transaction hash, not a
  metric. **If the owner wants the thirteen-gate bundle, wiring that counter
  first is the cheapest thing in this document.**
- **The four to watch:** R20 (`subsystem_no_op_receipt`) turns operations that
  ALWAYS reported success into failures, which is what integrators notice first;
  R25 (`docclass_issuer_stake_requirement`) is the one gate whose direction
  of effect depends on deployed configuration — read `docclass_getConfig` first;
  R30 (`healthcare_consent_subject_signature`) is the only one that changes a
  transaction PAYLOAD, so an un-upgraded client stops being able to grant at all,
  and **its guarantee is void unless R5 is open at or below the same height** —
  a shared Wave 1 height satisfies that, and nothing in the code enforces it;
  and R31 (`subsystem_issuer_self_registration_unsupported`) DEFERS the Tax and
  Finance issuer registries rather than repairing them, so after this height
  neither subsystem can gain an issuer at all — enumerate
  `tax_getActiveIssuers` and `finance_getActiveIssuers` first, because whatever
  is there is frozen as an authority.

#### Wave 2a — key space. 4 gates. Recommended height **14,588,328** (head + 28 days, ≈2026-10-17)

R3, R12, R22, R28.

DocClass subject-index split, the subsystem transaction index, the DocClass
revocation-record key widening, and the NFT collection-id nonce.

- **Data migration:** none required, and none possible. Rows written before the
  height keep their old keys; a collision committed before R3 stays collided;
  revocation records lost under R22's 40-byte key are not recoverable.
- **Rollback:** C, permanently. Every one of the four leaves two key shapes in
  the database forever.
- **The one number to watch:** **disk growth rate.** R12 changes one row per
  block into one row per event in two families; R3 and R22 add rows where
  collisions previously merged them. No metric exposes per-family row counts, so
  this is node-level disk usage.
- **The one integration risk:** R28 changes how a `CollectionId` is derived.
  Anything off-chain that recomputes one must know the height. That is invisible
  on-chain and is the single most likely silent break in the whole schedule.
- **Why 14 days after Wave 1:** long enough that Wave 1's refusal behaviour is
  observed across a full traffic cycle before anything irreversible is written.

#### Wave 2b — row content and existence. 8 gates. Recommended height **15,393,664** (head + 42 days, ≈2026-10-31)

R11, R14, R16, R17, R21, R24, R27, R35.

The block timestamp reaching eight subsystems, the tax proof lifecycle, agreement
signature integrity, healthcare state preconditions, DocClass issuer authority,
DocClass identity binding, NFT index symmetry, and the Property merge
relationship record.

- **Two soft orderings are satisfied by putting these at ONE height.** R17 should
  not precede R11 (expiry judged at the epoch otherwise) and R24's source names
  R11 explicitly. A shared height satisfies "at or before": at block `h` both
  gates are open, so the executor's clock is real when the identity-binding and
  precondition checks run.
- **Data migration:** none possible. Rows written below the height keep their
  zeros (R11), their dangling index entries (R14), their `Executed` status
  (R16), their empty index rows (R17), their self-granted authority (R21), their
  squatted commitments (R24), their empty collection rows (R27), and their
  merges that name nothing (R35). **Activation repairs nothing that already
  exists.**
- **Rollback:** B and C. This is the wave with the most permanent residue.
- **The signal:** the state root moves for transactions whose receipts are
  unchanged. The practical check is M6 across the seven subsystems — a known row
  read before and after the height.
- **What the owner should do before it:** enumerate `docclass_getIssuers` (R21 —
  activation freezes whatever authority is there) and the identity roots (R24 —
  activation freezes whatever is anchored).

#### Wave 2c — value and fee. 2 gates. Recommended height **16,199,000** (head + 56 days, ≈2026-11-14)

R19, R26.

NFT update-path parity (which newly charges `storage_fee_per_byte`) and the NFT
charged receipt (which puts the real fee in `fee_paid` and therefore moves the
receipts root).

- **Why separate from 2b:** fee-accounting surprises must not be attributable to
  a row-shape change. These two move money and the money's record; 2b moves rows.
  Bundling them makes a supply anomaly indistinguishable from an index anomaly.
- **Why only two and not alone each:** they share a signal — M7 plus a
  balance-delta comparison across the height — and R26's check is a one-call
  confirmation (`fee_paid` on a failed NFT receipt becoming non-zero), which is
  the cleanest working signal of any gate in the 40. It makes 2c self-diagnosing
  in a way 2b is not.
- **Rollback:** B for R26 (the receipts are in the chain), A/B/D for R19.

#### Wave 3 — block existence. 1 gate. Recommended height **17,004,336** (head + 70 days, ≈2026-11-28)

R1, `nft_receipt_failure_enabled_from_height`.

Alone, because it is the only gate whose disagreement means a node produces **no
block at all** rather than a different one. Below it, an NFT operation naming an
absent collection makes the whole block unexecutable; at and above, it is a
charged failed receipt.

- **Data migration:** none. **Rollback:** B and E only.
- **Why last and alone:** it is the only gate that converts a liveness failure
  into a receipt. If it misbehaves the symptom is a proposer that cannot produce
  — the one symptom that must not be confused with anything else. It is also the
  only gate in the 40 whose monitoring signal is a metric that actually works
  (M2 / M3), which is a reason to put it where an operator is watching for
  exactly that and nothing else.

### 2.4 The schedule

| wave | gates | height | ≈ elapsed | ≈ UTC | cost shape |
|---|---:|---:|---:|---|---|
| **0** | N1 + the binary rollout | ≤ Wave 1 | — | — | prerequisite (load-enforced) |
| **1** | 24 | **13,782,992** | 14 days | 2026-10-03 | refusal only |
| **2a** | 4 | **14,588,328** | 28 days | 2026-10-17 | key space |
| **2b** | 8 | **15,393,664** | 42 days | 2026-10-31 | row content / existence |
| **2c** | 2 | **16,199,000** | 56 days | 2026-11-14 | value and fee |
| **3** | 1 | **17,004,336** | 70 days | 2026-11-28 | block existence |
| **deferred** | 1 | — | — | — | see Part 3 |
| **out of band** | N2 + N3 | — | — | — | blocked on a measurement |
| **not schedulable** | P16, P17 | — | — | — | refused at load |
| **already passed** | 8 of the 18 | — | — | — | frozen |

24 + 4 + 8 + 2 + 1 + 1 = **40**. Plus N1 in Wave 0, N2 and N3 out of band, and
the 18 predating = **61**, which is what Part 1 covers. `ChainParams` declares
**63**; the difference is the two remediation gates Part 0a names as deliberately
uncovered, which are not scheduled and are not counted here.

**Every height must be re-derived against the head at the moment of decision.**
These are anchored to head 12,977,656 measured at 2026-09-19T05:35:38Z and drift
by roughly 57,524 blocks per day of delay. A height that has already passed when
the genesis is written is refused at startup (§0.4), which is the safe
direction.

---

## Part 3 — The deferrals, carried forward with their reasoning

A deferral in this document is a positive decision not to schedule, with a
reason. It is not an omission, and it is not a row waiting to be filled in to
make a table look complete.

### 3.1 `docclass_stake_escrow_enabled_from_height` — deferred INDEFINITELY

**Carried forward from the previous packet with its reasoning intact.**

The gate needs a data decision this repository has no answer to: **what happens
to stake already destroyed under the old rule.**

Stakes posted below the gate were destroyed — the escrow address holds nothing
for them. Above the gate, `deactivate_issuer` refunds any issuer row with
`stake_amount > 0` via `StateManager::v_deduct(escrow, refund)`
(`crates/state/src/docclass_executor.rs`), and `v_deduct`
(`crates/state/src/state.rs:208`) returns `InsufficientBalance` when the escrow
is short. So a pre-gate issuer deactivating after activation attempts to
withdraw money that was never escrowed. Nothing in the repository pre-funds the
escrow, zeroes legacy `stake_amount` fields, or special-cases pre-gate rows.

The owner's options, none of which this document chooses between:

1. pre-fund the escrow with the sum of all live pre-gate `stake_amount` values
   in the same coordinated genesis — which requires knowing that sum from
   production state, and nothing in this tree can read it;
2. zero legacy `stake_amount` fields as part of the activation, losing the
   issuers' claim, which was already lost in substance;
3. add a pre-gate carve-out to `deactivate_issuer` before activating;
4. defer the gate.

**That is an owner decision about existing value, not an engineering one, and it
should not be bundled into a wave to make a schedule look complete.** The cost of
deferring is stated and not minimised: the money supply keeps shrinking by a
sender-chosen amount at every DocClass issuer registration, and M7
(`chain_getSupplyInfo.accounted_account_supply`) will keep recording it.

A related consequence, now visible because R21 exists: `docclass_issuer_authority`
closes the authority half of the same wholesale `UpdateIssuer` write, while this
gate — the stake half — stays open. **Wave 2b therefore ships half of that
repair.** That is a consequence of the deferral, not an argument against it.

### 3.2 The deferral the previous packet recorded in Part 2b — RESOLVED, not carried

The previous packet deferred scheduling for gates that "arrived after this packet
was written", on the explicit ground that "writing a wave for a gate that has not
had that treatment is exactly the shortcut this packet exists to prevent."

**That deferral is discharged rather than carried forward.** Every gate that
arrived since — and every other gate this packet covers — now has the six-field treatment
in Part 1, which is the condition the previous packet set for lifting it. Where
the previous packet guessed that those gates "by cost shape belong in Wave 1",
the per-gate analysis puts three of them elsewhere: R19 and R26 in Wave 2c
(they move money), and R27 in Wave 2b (it moves the state root). **The guess was
wrong for three of them, which is the reason the previous packet declined to
make it.**

### 3.3 `account_root_enabled_from_height` — deferred pending an external measurement

Not a new deferral; recorded here because it is a height the owner might
otherwise expect to find in Part 2.

`docs/operations/ACCOUNT-ROOT-ACTIVATION.md` makes measuring the production
`cf::STATE` row count Sequence step 0 and says the activation "should not be
scheduled until it has been" measured. That count is **UNPROVEN**:
`docs/lane-a/ACCOUNT-ROOT-RELEASE-EVIDENCE.md §1` records the exact command, the
endpoint requirement, the expected output, what must be recorded alongside it,
and the acceptance threshold. **This packet proposes no height for it and does
not weaken that precondition.**

Its partner `application_journal_enabled_from_height` is deferred with it, for
the arithmetic reason that §0.7 rule (3) makes a journal height meaningful only
in relation to an account-root height.

### 3.4 `compute_pool_enabled_from_height` and `beacon_enabled_from_height` — not deferrals

They are **refused at load** (§0.7 rules 1 and 2). There is no height for the
owner to decline to set; a genesis carrying one does not start a node. Recorded
here only so that a reader counting the 63 does not mistake their absence from
the schedule for an oversight.

---

## Appendix — the 63, in one table

Order is `activation_heights()` order, which is the digest's order and must never
be permuted.

| # | gate | class | today | wave |
|---:|---|---|---|---|
| 1 | `v2_enabled_from_height` | PREDATING | 5,200,000 (passed) | frozen |
| 2 | `omninode_enabled_from_height` | PREDATING | 6,000,000 (passed) | frozen |
| 3 | `omninode_sponsored_attestation_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 4 | `education_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 5 | `contracts_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 6 | `account_root_enabled_from_height` | **NEITHER** | `None` | out of band — blocked on a measurement |
| 7 | `governance_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 8 | `archive_unbonding_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 9 | `archive_reassignment_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 10 | `por_assignment_targeting_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 11 | `service_grants_enabled_from_height` | PREDATING | `None` (confirmed) | out of band |
| 12 | `monetary_policy_enabled_from_height` | PREDATING | `None` (confirmed) | out of band |
| 13 | `assignment_aware_por_scheduler_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 14 | `inference_settlement_enabled_from_height` | PREDATING | 8,900,000 (passed) | frozen |
| 15 | `inference_settlement_consistency_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 16 | `inference_verifier_bonding_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 17 | `compute_pool_enabled_from_height` | PREDATING | `None` | **not schedulable** |
| 18 | `application_journal_enabled_from_height` | **NEITHER** | `None` | out of band — pairs with #6 |
| 19 | `beacon_enabled_from_height` | PREDATING | `None` | **not schedulable** |
| 20 | `messaging_sponsored_registration_enabled_from_height` | PREDATING | presumed `None` | out of band |
| 21 | `nft_receipt_failure_enabled_from_height` | REMEDIATION | `None` | **Wave 3** |
| 22 | `docclass_stake_escrow_enabled_from_height` | REMEDIATION | `None` | **DEFERRED** |
| 23 | `docclass_subject_index_split_enabled_from_height` | REMEDIATION | `None` | **Wave 2a** |
| 24 | `docclass_revocation_standing_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 25 | `healthcare_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 26 | `legal_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 27 | `finance_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 28 | `employment_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 29 | `property_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 30 | `tax_authorization_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 31 | `subsystem_block_timestamp_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 32 | `subsystem_tx_index_enabled_from_height` | REMEDIATION | `None` | **Wave 2a** |
| 33 | `subsystem_allocation_bound_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 34 | `subsystem_tx_write_set_bound_enabled_from_height` | REMEDIATION | `None` | **NOT COVERED** — see Part 0a |
| 35 | `tax_proof_lifecycle_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 36 | `nft_token_authority_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 37 | `agreement_signature_integrity_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 38 | `healthcare_state_precondition_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 39 | `subsystem_proof_presence_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 40 | `nft_update_path_parity_enabled_from_height` | REMEDIATION | `None` | **Wave 2c** |
| 41 | `subsystem_no_op_receipt_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 42 | `peer_protocol_declaration_required_from_height` | **NEITHER** | `None` | **Wave 0** (load-enforced) |
| 43 | `docclass_issuer_authority_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 44 | `nft_charged_receipt_enabled_from_height` | REMEDIATION | `None` | **Wave 2c** |
| 45 | `docclass_revocation_record_enabled_from_height` | REMEDIATION | `None` | **Wave 2a** |
| 46 | `docclass_credential_schema_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 47 | `nft_index_symmetry_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 48 | `docclass_identity_binding_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 49 | `docclass_issuer_stake_requirement_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 50 | `nft_collection_id_nonce_enabled_from_height` | REMEDIATION | `None` | **Wave 2a** |
| 51 | `subsystem_proof_unsupported_enabled_from_height` | REMEDIATION | `None` | **NOT COVERED** — see Part 0a |
| 52 | `property_state_precondition_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 53 | `property_asset_relationship_enabled_from_height` | REMEDIATION | `None` | **Wave 2b** |
| 54 | `agreement_party_authority_unsupported_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 55 | `healthcare_consent_subject_signature_enabled_from_height` | REMEDIATION | `None` | **Wave 1** (never before R5 — §0.7 rule 5, refused at load) |
| 56 | `subsystem_issuer_self_registration_unsupported_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 57 | `property_proof_submission_unsupported_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 58 | `nft_unpayable_royalty_refused_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 59 | `docclass_signature_unsupported_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 60 | `docclass_credential_validity_bound_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 61 | `docclass_unknown_attribute_refused_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 62 | `subsystem_ambiguous_policy_id_refused_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |
| 63 | `nft_royalty_operation_unsupported_enabled_from_height` | REMEDIATION | `None` | **Wave 1** |

**42 REMEDIATION + 18 PREDATING + 3 NEITHER = 63**, matching §0.1. Sixty-one of
the sixty-three have a section in Part 1; the two marked NOT COVERED are the
ones Part 0a names, and they are the whole of the difference.
