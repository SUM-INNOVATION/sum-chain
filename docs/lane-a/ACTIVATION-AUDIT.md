# Lane A: activation audit — what a release-configured node can actually reach

`docs/lane-a/DEPLOYMENT-BLOCKERS.md` says what is broken. It does not say which
of it a node running the intended release configuration can reach. This file is
that second question, and only that question. It adds no defect and removes
none; it classifies each one against the configuration a production node
actually boots with.

Four verdicts, and the decision rule that uses them:

  * **REACHABLE** — a transaction an ordinary funded sender can submit to a
    release-configured node reaches the code. Release-blocking.
  * **GATED OFF** — the path exists but an activation height, feature flag or
    config value the release sets makes it unreachable. Every GATED OFF row
    names the gate, where it is set, and what re-exposes it. A gate that cannot
    be pointed at is not a gate and is not this verdict.
  * **UNREACHABLE** — no dispatch path reaches it: dead code, an unused store
    method, a reader nothing calls.
  * **UNDETERMINED** — could not be established from source and configuration.
    Every such row states what evidence would settle it. **UNDETERMINED blocks
    deployment exactly as REACHABLE does.** It is not a hedge and it is not a
    softer GATED OFF; a false GATED OFF is how a release ships a reachable
    defect.

## Remediation status, and why it does not move the count

This document has been worked since it was written. Thirty-five rows now have a
remedy implemented and tested in the tree, and two more are half-remedied. **None of it changes a single
verdict, and the blocking count is what it was less the one row the integration
pass CLOSED outright.** That is not a formality; it is the finding of the
remediation pass.

Every one of the forty-eight is a CONSENSUS CHANGE — it changes which
transactions succeed, which blocks exist, or what an account balance is, and
receipts are folded into the state root — so none of them may simply be applied.
Each is implemented behind an activation height, exactly as the other
`*_enabled_from_height` gates in `ChainParams` are. **All twelve fields now
exist** — eleven were added to `ChainParams` in the integration commit that
records this paragraph and a twelfth,
`subsystem_tx_index_enabled_from_height`, with the `tx_index` remedy; all are
covered by `activation_heights` (and therefore by
the genesis activation digest and by the startup change detection), and are
read by the twelve accessors that previously ignored their parameter. The
pairing between accessor and field is pinned by
`state/every_remediation_gate_reads_the_field_it_names`, because twelve
near-identical three-line functions fail by reading each other's field rather
than by being absent — and the twelfth's neighbour,
`subsystem_block_timestamp_enabled_from_height`, is exactly the field a
copy-paste would have left it reading.

**Every one of them defaults to `None`, and none is set anywhere in this
branch.** Adding a field is not opening a gate. A dormant gate means a
release-configured node executes precisely the code it executed before —
which is what the pinning tests, all of which still pass unchanged, prove, and
what `state/every_remediation_gate_is_dormant_by_default` asserts directly.

**A gate that is not set is not GATED OFF.** This document's decision rule is
that a GATED OFF row must name "the gate, where it is set". These rows can now
name the gate, which they could not before; they still cannot name where it is
set, because nowhere is. The defective behaviour is what a release node runs.
So the verdict stays REACHABLE, and the blocking count stays 120 — 121 at the
audit, less OC-2, which the integration pass closed outright rather than gated.
(A later census pass took it to 114; see Counts. That pass moved no gate and no
line of executing code, which is why this paragraph's claim is untouched by it.)

What changed is the SHAPE of the remaining precondition, and that is worth
stating plainly rather than burying in an unchanged number. Before, forty-eight
rows were blocked on code in a crate nobody had written. Now they are blocked on
a deployment decision: setting twelve heights in the runtime `genesis.json` of
every validator, as one coordinated consensus-breaking activation. That decision
is the owner's and is deliberately not taken here — the field documentation says
"never `Some(_)` in a committed genesis in this branch", and a committed default
is not a coordinated validator upgrade.

A third status is therefore recorded alongside the verdict, orthogonal to it:

  * **REMEDIED, PENDING ACTIVATION** — the corrected behaviour exists, is reachable
    through a named seam, and is covered by tests that drive an ungated node and
    a gated node over the same transaction and assert that they disagree. It
    becomes live the moment the named `ChainParams` field lands and an operator
    sets it. Thirty-five rows fully; AU-3 and AU-34 in part, and the
    tables say which part.
  * **BLOCKED, STRUCTURAL** — the defect cannot be closed by a guard at all,
    because the subsystem records no address, no registry or no signature to
    authorize against. A wire change or a new registry is needed. Stated rather
    than papered over, because a rule that pretends to check something it cannot
    see is worse than one that says it cannot. Six rows.
  * unmarked — untouched by this pass.

**A later Employment-and-Finance pass added NO gate, and that is the finding
rather than an omission.** Of its twelve rows, two (AL-2 and AL-4's unbounded
half) are a FOURTH and FIFTH reader of
`subsystem_allocation_bound_enabled_from_height`, added on the argument that
field's own doc comment already makes twice — one rule at one seam, and an
attacker refused by one bound moves to the cheapest one still open — so the gate
count is unchanged at twenty-eight and no new constant was introduced. Four
(OV-4, OV-5, OV-7 and OV-8) had their stated CONSEQUENCE tested against source
and WITHDRAWN by OV-16's route: in each the mechanism the row names is real and
is the subsystem working. Two (AU-24, AU-28) were re-tested rather than
inherited and are unchanged, with the invariant behind them now asserted instead
of read. Four (AU-26, AU-29 and their PR restatements, plus PR-8 and PR-9) were
not touched: every `VerifyProof` arm and the proof-family reads belong to a
concurrent track, and AU-26's and AU-29's remaining half — that the operation
still verifies nothing — needs a proof verifier that exists nowhere in this
tree. No verdict moved and the blocking count is what it was.

**The census pass that followed added no gate either, and moved six verdicts.**
It was asked one question about six rows — is this row blocking because of
evidence, or because nobody has checked? — and the answer for all six was the
second. Four (OV-4, OV-5, OV-7, OV-8) had already had their stated consequence
WITHDRAWN and the withdrawal pinned by tests, and were then left REACHABLE and
blocking anyway, on the bookkeeping rule "a withdrawn consequence is a finding,
not a closure". A finding it is; blocking it is not, and the two are different
questions. They are now RETIRED, in place, with each row naming the test that
would fail if it became a defect again. Two (AU-24, AU-28) name a branch that no
input can reach; the previous pass ESTABLISHED that behaviourally, from the
paths that exist today, which is an observation and not a proof. It is now a
proof: `no_write_path_can_make_an_issuer_row_whose_key_is_not_its_own_address`
fails if a route is ever added, and the rows are UNREACHABLE. **No code changed,
no transaction's validity changed, and no gate was added — the only thing that
moved is what this document claims to know.** Blocking falls from 120 to 114;
the derivation is in the Counts section.

### The `ChainParams` fields the remediation needs

Twelve. Eleven could not be added from the track that implemented the behaviour
behind them; each is specified in full — name, type, semantics and the one-line
function body that replaces the seam — in the doc comment of its activation
function. All follow the existing `#[serde(default)] Option<u64>` idiom, so an
absent field resolves to `None` and the gate is closed, which is what makes the
dormant state safe.

| field | rows it governs | seam |
|---|---|---|
| `nft_receipt_failure_enabled_from_height` | BD-1, BD-2, BD-3, BD-4, BD-5 | `NftExecutor::receipt_failure_activation`, `crates/state/src/nft_executor.rs` |
| `docclass_stake_escrow_enabled_from_height` | OV-26, and the stake half of AU-34 | `DocClassExecutor::stake_escrow_activation` |
| `docclass_subject_index_split_enabled_from_height` | BD-6 | `DocClassExecutor::subject_index_split_activation` |
| `docclass_revocation_standing_enabled_from_height` | AU-36 | `DocClassExecutor::revocation_standing_activation` |
| `healthcare_authorization_enabled_from_height` | AU-1, AU-2, AU-4, AU-5, the revocation half of AU-3, OV-18 | `HealthcareExecutor::authorization_activation` |
| `legal_authorization_enabled_from_height` | AU-13, AU-14, AU-15, AU-16 | `LegalExecutor::authorization_activation` |
| `finance_authorization_enabled_from_height` | AU-22, AU-23, AU-25 | `FinanceExecutor::authorization_activation` |
| `employment_authorization_enabled_from_height` | AU-27 | `EmploymentExecutor::authorization_activation` |
| `property_authorization_enabled_from_height` | AU-30, AU-31 | `PropertyExecutor::authorization_activation` |
| `tax_authorization_enabled_from_height` | AU-19 | `TaxExecutor::authorization_activation` |
| `subsystem_block_timestamp_enabled_from_height` | TS-1 to TS-9, and the timestamp half of TS-10 | `subsystem_block_timestamp_activation`, `crates/state/src/lib.rs` — one field for eight subsystems, because it is one rule |
| `subsystem_tx_index_enabled_from_height` | the `tx_index` half of TS-10, and the same collision on the Messaging arm of TS-11 | `subsystem_tx_index_activation`, `crates/state/src/lib.rs` — its own field, because it is its own rule: the timestamp gate changes what a row SAYS, this one changes what KEY it lands at and therefore how many rows a block writes |

Twelve fields: seven per-subsystem authorization heights, three per-defect, and two
shared rules. They are separate rather than one because activating
them is separate: an operator coordinating a validator upgrade for the NFT
block-denial rule should not be forced to activate the healthcare consent rules
in the same block, and a subsystem whose remediation is later found wanting must
be able to stay dormant without holding the others back.

### What the mixed-version evidence actually shows

Every remediated row is covered by a test that runs the SAME transaction under
both gate values through one entry point — `execute_with_gate` on the NFT
executor, `execute_with_gates` on the other seven — and asserts that the two
nodes produce different results. The difference is always observable, and for
the NFT rows it is stronger than a differing digest: an ungated node cannot
execute the block AT ALL (`execute_block` returns `Err` before `receipts.push`),
where a gated node executes it and records a `Failed` receipt. A node on the
wrong side of that height halts against its peers rather than forking quietly
behind them, which is the failure mode a consensus change should have. For the
other rows the difference is a receipt's success bit and the rows it did or did
not write, and receipts are folded into the root at
`crates/state/src/executor.rs:3633-3637`.

One methodological point governs every row. **A pinning test proves the
behaviour; it does not prove the path is reachable in production.** A test
constructs its own `ChainParams`, its own ceiling and its own height, and can
therefore drive code a release configuration gates off — and, in the other
direction, can measure a refusal under a ceiling the release does not use. Both
directions occur below. Where a test's configuration differs from the release's,
the row says so and the verdict follows the release.

## The intended release configuration, and how it was derived

Not assumed. Traced from the binary's entry point to the struct the executor
reads, then compared against the operator documentation that describes the live
chain.

### The chain of custody from file to executor

  1. `crates/node/src/config.rs:141` declares `NodeSettings.genesis: PathBuf`,
     and `crates/node/src/config.rs:151` defaults it to `genesis.json` — the
     file at the repository root. The committed sample config agrees:
     `config.toml:2` sets `genesis = "genesis.json"`.
  2. `crates/node/src/main.rs:371-373` loads exactly that path through
     `Genesis::from_file`.
  3. `crates/genesis/src/lib.rs:1056-1061` parses it with serde and calls
     `genesis.validate()`, which reaches `ChainParams::validate`
     (`crates/genesis/src/lib.rs:941-969`). That method is fail-closed for two
     gates only — `compute_pool_enabled_from_height` and
     `beacon_enabled_from_height` — and rejects any `Some(_)` for them.
  4. `crates/node/src/node.rs:180` and `crates/node/src/node.rs:191` set
     `params: Arc::new(genesis.params.clone())`. **The executor's `ChainParams`
     is the genesis file's `params` object verbatim.** There is no second
     source, no CLI override of a params field, and no environment variable.

So "the intended release configuration" is precisely: the `params` object of the
runtime `genesis.json`, plus whatever is hardcoded in the binary.

### What the committed runtime genesis contains

`genesis.json` at the repository root carries `chain_id: 1` and exactly seven
params keys:

```
block_time_ms 3000   max_block_bytes 2000000   max_txs_per_block 1000
min_fee 1000   finality_depth 6   max_metadata_bytes 16384
storage_fee_per_byte 100
```

Every `*_enabled_from_height` field is **absent**. Each is declared
`#[serde(default)] pub …: Option<u64>` (`crates/genesis/src/lib.rs:271, 284,
294, 308, 324, 340, 365, 380, 395, 404, 413, 446, 470, 501, 512, 533, 541,
585`), so absence resolves to `None`, which every gate helper reads as closed —
e.g. `v2_gate_open` at `crates/state/src/executor.rs:85`,
`sponsored_attestation_gate_open` at `:112`,
`messaging_sponsored_registration_gate_open` at `:198`.

`genesis/mainnet_genesis.json` is **not** the release configuration. Its own
first key says so — `"_comment": "TEMPLATE ONLY — production validators boot
from the root runtime genesis.json, NOT this file."` — and
`docs/operations/production-checklist.md:27-35` repeats it: the root runtime
`genesis.json` is what production boots from, and "any subprotocol activation
heights are edited into each validator's runtime genesis identically, never into
the template."

### The ambiguity, stated rather than resolved

That last sentence is the ambiguity, and it is material. The committed
`genesis.json` is the *base*; the deployed one is the base plus activation
heights edited in by operators, and the edited file is not in this tree.
`docs/operations/production-checklist.md:100-130` records what those edits
currently are, "verified at height 8,716,604 · 2026-07-06":

```
v2_enabled_from_height                    5200000
omninode_enabled_from_height              6000000
education_enabled_from_height             8900000
contracts_enabled_from_height             8900000
governance_enabled_from_height            8900000
archive_unbonding_enabled_from_height     8900000
archive_reassignment_enabled_from_height  8900000
inference_settlement_enabled_from_height  8900000
inference_settlement_dispute_threshold_bps   6667
```

Everything else in that block — `chain_id 1`, `min_fee 1000`,
`max_txs_per_block 1000`, `finality_depth 6`, `storage_fee_per_byte 100`,
`max_metadata_bytes 16384` — matches the committed `genesis.json` exactly, which
is good evidence that the committed file is the true base and not a stale
artefact.

Two plausible readings follow, and every row below is answered under both:

  * **Reading A — live mainnet.** chain_id 1 at height ≈8.7 million, the nine
    gates above set, all other gates `None`.
  * **Reading B — the committed file as it stands.** A chain booted from the
    repository's `genesis.json` unedited: height starts at 0, **every** gate
    `None`.

The two readings differ for exactly one row in this audit (the DocClass schema
gate, D-19). For every other row the verdict is identical under both, because
**no gate in `ChainParams` covers any of the eleven subsystems this audit is
about.**

### The decisive negative finding

Searching `crates/genesis/src/lib.rs` for every `pub *_enabled_from_height`
field returns the eighteen listed above. There is no `nft_enabled_from_height`,
no `docclass_…`, `healthcare_…`, `property_…`, `agreement_…`, `legal_…`,
`finance_…`, `employment_…`, `tax_…` or `policy_account_…`. The dispatch arms
confirm it: `crates/state/src/executor.rs:494` (Nft), `:692` (Messaging),
`:755` (DocClass), `:795` (Tax), `:868` (Agreement), `:907` (Legal), `:943`
(Property), `:982` (Healthcare), `:1021` (Employment), `:1060` (Finance) and
`:1099` (PolicyAccount) go from the `match` straight to their executor with **no
gate check of any kind**. Compare the arms that do have one:
`crates/state/src/executor.rs:565` (`contracts_gate_open`), `:1285`
(`v2_gate_open`), `:1296` (archive reassignment), `:1538` (sponsored
attestation).

`validate_tx` (`crates/state/src/executor.rs:350-400`) checks chain id, signer,
signature, nonce, balance and `min_fee` — and nothing about the payload type. An
ordinary funded account paying 1000 units can submit any of these payloads.

There are no feature flags in play either. The only `[features]` block in the
execution path is `crates/state/Cargo.toml:36-39`, declaring `legacy_tests` for
test modules alone; `crates/node/Cargo.toml` and `crates/rpc/Cargo.toml` declare
none, and there is no `cfg(feature …)` anywhere in `crates/state/src`,
`crates/rpc/src` or `crates/nft/src`.

### Two hardcoded values that are part of the release configuration

Neither comes from genesis, and both change verdicts below.

  * **The candidate write-set ceiling is 1 GiB.**
    `crates/state/src/executor.rs:269` defines
    `const CANDIDATE_LIMIT_SCAFFOLD: u64 = 1 << 30`, and
    `crates/state/src/executor.rs:3074` is the single production construction
    site: `CandidateExecution::new(&self.db, CANDIDATE_LIMIT_SCAFFOLD)`. Its own
    doc comment calls it "SCAFFOLDING … must be replaced before publication".
    This matters because the allocation-class pinning tests measured refusals
    under ceilings of 4,096 and 8,192 bytes, which the release does not use.
  * **The DocClass schema activation height is 385,000, and it is not
    configurable.** `crates/state/src/schema_validator.rs:56-63` hardcodes
    `activation_height: 385000, enabled: true` in
    `SchemaValidatorConfig::default()`, and the only two production
    construction sites — `crates/state/src/docclass_executor.rs:746` and
    `crates/state/src/employment_executor.rs:129` — call
    `SchemaValidator::new()`, which takes that default
    (`crates/state/src/schema_validator.rs:71-77`). `ChainParams.docclass`
    exists (`crates/genesis/src/lib.rs:224`) but is absent from `genesis.json`
    and is read by no execution path. This is the one gate in the audit that is
    real, and it is the one row where Readings A and B diverge.

### RPC exposure is part of the configuration too

For the scan class the relevant configuration is the RPC server's, and it gates
nothing. `crates/rpc/src/server.rs:428` registers the entire `SumChainApi` trait
in one call — `server.start(self.into_rpc())` — so every `#[method(...)]`
declared in `crates/rpc/src/api.rs` is live. There is no namespace flag, no
allowlist and no admin-method set. Authentication machinery exists
(`crates/rpc/src/auth.rs`, `ApiKeyValidator::authorize`) but is never wired into
the request path: the validator is constructed at
`crates/rpc/src/server.rs:296`, stored at `:181`, and thereafter only read to
print a log line at `:399`. The same is true of the rate limiter (`:182`,
logged at `:404`). The jsonrpsee server is built at
`crates/rpc/src/server.rs:417-428` with body/connection limits only and no
middleware layer. The release default binds loopback
(`crates/node/src/config.rs:199-209`, `addr = "127.0.0.1:8545"`) with
`api_key = None` and `rate_limit_enabled = false`, so the only restriction on
any of it is the bind address — which `crates/node/src/config.rs:380-385` shows
is an ordinary operator-settable value.

## Class 1 — Block-level denial

The class where reachability is the whole question. A guard that returns a
failure result costs the sender a fee; a guard that returns `Err` costs everyone
the block. `crates/state/src/executor.rs:3133-3140` calls
`execute_tx_with_validators(…)?` inside the transaction loop of `execute_block`
(fn at `:3028`, returning `Result<BlockExecution<'_>>` at `:3035`), so any
`Err` ends block execution before `receipts.push` at `:3179`. The producer
cannot build the block and no importer can validate it.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| BD-1 | NFT `Collection not found` aborts the block — mint, batch mint, transfer, burn, metadata update, collection-ownership transfer, config update | NFT §block-level denial | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_receipt_failure_enabled_from_height`, implemented and dormant | `crates/state/src/nft_executor.rs:308, 417, 492, 588, 632, 673, 708`; propagated at `crates/state/src/executor.rs:504`; block-level at `:3140` | `NftExecutor::execute` returns `Result` (`nft_executor.rs:109`); the Nft arm at `executor.rs:494` has no gate check; any funded sender names an absent collection id for `min_fee` 1000 |
| BD-2 | NFT `Token not found` aborts the block — transfer, approve, burn, metadata update, lock, unlock | NFT §block-level denial | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_receipt_failure_enabled_from_height`, implemented and dormant | `crates/state/src/nft_executor.rs:502, 554, 598, 642, 748, 782` | same propagation path as BD-1; reachable inside one block by burning a token and then naming it |
| BD-3 | NFT `Invalid config` (royalty above 2500bps in the payload) aborts the block | NFT §block-level denial | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_receipt_failure_enabled_from_height`, implemented and dormant | `crates/state/src/nft_executor.rs:246`; validation `crates/nft/src/collection.rs:123-127` | a payload field the sender chooses freely |
| BD-4 | NFT undecodable payloads abort the block — collection, mint, transfer, approve, batch, config data | NFT §block-level denial | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_receipt_failure_enabled_from_height`, implemented and dormant | `crates/state/src/nft_executor.rs:240, 325, 429, 522, 564, 685, 720` | any byte string bincode cannot decode; the cheapest of the four |
| BD-5 | NFT `deduct_fee` insufficient balance is an `Err`, not a failed receipt | found while auditing BD-1..4; not separately listed in the blocker document | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_receipt_failure_enabled_from_height`, implemented and dormant | `crates/state/src/nft_executor.rs:208` returns `Err(StateError::InsufficientBalance{..})` | same propagation; noted because it widens BD-1..4 rather than adding a new class |
| BD-6 | DocClass subject-index shape collision makes the next identity operation a block-level error | DocClass §one column family, two incompatible value shapes | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_subject_index_split_enabled_from_height`, implemented and dormant | collision write `crates/state/src/docclass_view.rs:217-243` vs `:152-182`; pinned by `an_identity_and_a_credential_sharing_a_subject_commitment_break_the_block`, `crates/state/tests/docclass_routing.rs:3252-3319`, whose final assertion is `outcome.expect_err(…)` at `:3300` | the subject commitment is an arbitrary 32-byte payload value (`create_identity_root` stores the struct verbatim, `crates/state/src/docclass_executor.rs:278-293`), so an attacker picks the colliding key; two cheap transactions arm it and a third detonates it |

**BD-6 is a second block-denial vector the blocker document files under a
different heading.** It is filed there as a data-shape defect, and it is one,
but its pinned consequence is an `Err` out of `execute_tx` — the same shape as
BD-1..4 and the same blast radius. It belongs in this class.

One nuance that narrows nothing: the pinning tests for BD-1..4 and BD-6 run
through `execute_tx`/`execute_tx_v2` directly rather than through
`execute_block`, so they prove the `Err` and not the block abort. The block
abort is established here from `crates/state/src/executor.rs:3140` instead,
which is the production call site.

## Class 2 — Literal zero timestamps and transaction indexes

The blocker document says of six subsystems that "both dispatch arms" pass a
literal `0`. Both arms do. **Only one of them is reachable**, and the audit has
to say which, because the distinction changes nothing about the verdict and
everything about where a fix has to land.

`crates/state/src/executor.rs` has two payload matches:

  * `execute_tx_with_validators` (fn at `:424`) — called by `execute_block` at
    `:3133`. **This is the production arm.**
  * `execute_tx_v2` (fn at `:2081`) — `pub`, and called by nothing outside
    `crates/state/tests/`. A repo-wide search for `execute_tx_v2` returns the
    definition and test call sites only. Several test files say so in their own
    comments, e.g. `crates/state/tests/legal_routing.rs:2643` ("`execute_tx_v2`
    is `pub` with no production caller"). **This arm is UNREACHABLE.**

The zero placeholders on the production arm are at
`crates/state/src/executor.rs:725-726` (Messaging), `:765-766` (DocClass),
`:803-804` (Tax), `:838-839` (Equity), `:877-878` (Agreement), `:916-917`
(Legal), `:952-953` (Property), `:991-992` (Healthcare), `:1030-1031`
(Employment), `:1069-1070` (Finance). The mirror set on the dead arm is at
`:2452-2453` through `:2788-2789`.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| TS-1 | Employment: every `updated_at` a status update writes is zero | Employment 1 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:1030-1031`; pinned by `every_status_update_records_a_zero_timestamp_through_dispatch` | production arm; ungated subsystem |
| TS-2 | Legal: every status transition stamps `updated_at = 0`, `tx_index = 0` | Legal 6 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:916-917`; pinned by `a_status_transition_stamps_a_zero_timestamp` | as above |
| TS-3 | Finance: every routed update, suspension, revocation, reactivation stamps `updated_at = 0` | Finance 10 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:1069-1070` | as above; no test named by the source message |
| TS-4 | Tax: both paths pass timestamp 0, so status changes persist an incorrect `updated_at` | Tax 8 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:803-804` | as above |
| TS-5 | Agreement: timestamp 0 and tx index 0 on every executor-written timestamp | Agreement §untrusted payload metadata | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:877-878`; pinned by `the_block_timestamp_reaching_agreement_operations_is_always_zero` | as above |
| TS-6 | Property: timestamp 0 and tx index 0 | Property §untrusted payload metadata | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:952-953`; pinned by `the_block_timestamp_reaching_property_operations_is_always_zero` | as above |
| TS-7 | Property: `TitleEvent` has no `updated_at`, so a transition writes the (zero) timestamp into `created_at`, destroying the creation time | Property §untrusted payload metadata | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | same arm as TS-6; same pinning test | compounding of TS-6, not independent of it |
| TS-8 | Healthcare: timestamp 0 and tx index 0 — **and `Prescription::is_valid` is therefore evaluated at time zero**, so an expired prescription is fillable forever and one with a non-zero `effective_from` can never be filled | Healthcare §untrusted payload metadata | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:991-992`; pinned by `the_block_timestamp_reaching_healthcare_operations_is_always_zero` | the only member of this class with a direct authorization consequence; ranked accordingly below |
| TS-9 | DocClass: timestamp 0 on `IdentityRoot.updated_at`, `DocClassIssuer.updated_at`, `RevocationRecord.revoked_at` | DocClass §untrusted payload metadata | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_block_timestamp_enabled_from_height`, implemented and dormant | `crates/state/src/executor.rs:765-766`; pinned by `the_block_timestamp_reaching_docclass_operations_is_always_zero` | as above |
| TS-10 | DocClass: because `tx_index` is also 0, every event in a block lands at key `height ‖ 0 ‖ 0` and the family holds one row per block — the last event | DocClass §untrusted payload metadata | **REACHABLE** | none. **REMEDIED, PENDING ACTIVATION:** the TIMESTAMP half on `subsystem_block_timestamp_enabled_from_height`; the `tx_index` half — the one that silently destroys data — on its own `subsystem_tx_index_enabled_from_height`. `execute_tx_with_validators` and `execute_tx_v2` now take the transaction's index, `execute_block` passes the same `idx` its receipts are built from, and both arms reduce it through one `effective_tx_index` that yields the literal `0` while the gate is closed | `crates/state/src/executor.rs`; write at `crates/state/src/docclass_view.rs::v_put_docclass_event`; pinned by `every_docclass_event_in_a_block_lands_at_one_key`, `the_same_two_events_still_collide_below_the_gate`, `two_docclass_events_in_a_block_land_at_two_keys_at_the_gate` and `execute_block_keys_each_docclass_event_by_its_own_transaction_index` | the one place where `tx_index = 0` silently destroys data rather than only mis-stamping it |
| TS-11 | Messaging: timestamp/tx-index placeholders on the messaging arm | not listed as a defect in the blocker document (messaging carries no deferred-defect inventory) | **REACHABLE** | none. **REMEDIED, PENDING ACTIVATION:** both arms now pass the block's timestamp and the transaction's index; `MessagingExecutor::execute` reduces the timestamp through `effective_block_timestamp` on `subsystem_block_timestamp_enabled_from_height`, and the index is reduced by the dispatch on `subsystem_tx_index_enabled_from_height` | `crates/state/src/executor.rs`, `crates/state/src/messaging_executor.rs` | not cosmetic: `current_day` buckets the daily send quota by this timestamp, so at the epoch every message a chain ever sends counts against day zero; and two messages to one recipient in a block were one row |
| TS-12 | The same literal zeros on the second dispatch arm, for all of the above | the "both dispatch arms" half of Employment 1, Legal 6, Finance 10, Tax 8, Agreement, Property, Healthcare, DocClass | **UNREACHABLE** | — | `crates/state/src/executor.rs:2452-2789`; fn `execute_tx_v2` at `:2081` has no caller outside `crates/state/tests/` | dead public API; a fix must still change both, because `pub` means a future caller can appear, but nothing today reaches it |

NFT is **not** in this class. The NFT arm passes the real block timestamp —
`crates/state/src/executor.rs:503` forwards `block_timestamp`, sourced from
`block.header.timestamp` at `:3138`. That is what makes CI-1 below a real defect
rather than a second instance of this one.

Contract deploy/call also pass a zero timestamp (`crates/state/src/executor.rs:580,
627`) but are gated; see GATED-1.

## Class 3 — Absent authorization

Every executor named below is reached from the production dispatch arm with no
gate: `crates/state/src/executor.rs:755` (DocClass), `:795` (Tax), `:868`
(Agreement), `:907` (Legal), `:943` (Property), `:982` (Healthcare), `:1021`
(Employment), `:1060` (Finance). So for this whole class the reachability
question reduces to "is the operation a live arm of its executor's `match`",
and for every row below it is.

**Two rows below are the exception, and they are exceptions to the second step
rather than the first.** AU-24 and AU-28 name a BRANCH INSIDE a live arm, not an
arm, and a live arm does not make every branch in it reachable. Both are
UNREACHABLE, both say why in their own row, and the proof is structural rather
than a reading of today's call graph.

### Healthcare — the subsystem where this class is least tolerable

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-1 | `SupersedeConsent` checks **nothing** about the sender: any account marks any consent `Superseded` and stores a replacement whose subject, recipient, disclosure scope and issuer all come from its own payload | Healthcare §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/healthcare_executor.rs:673`; sole guard is old-consent existence at `:682`; nothing in `:673-703` compares `sender`; pinned by `any_sender_can_supersede_any_consent_with_one_of_their_own` | complete bypass of the consent lifecycle by one ordinary transaction |
| AU-2 | `FillPrescription` and `PartialFillPrescription` check no sender at all — not patient, prescriber, pharmacy or issuer | Healthcare §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height`, implemented and dormant | arms `crates/state/src/healthcare_executor.rs:772` and `:802`; guards are only validity `:786`/`:816` and refills `:790`; pinned by `any_sender_can_fill_any_prescription` | a stranger fills anyone's prescription, controlled substances included |
| AU-3 | A consent's subject is never consulted in either direction: `GrantConsent` compares only issuer to sender, `RevokeConsent` requires the issuer, so the subject can neither grant nor withdraw | Healthcare §missing authorization | **REACHABLE** | none today. **PARTLY REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height (REVOCATION half only; the GRANT half is BLOCKED, STRUCTURAL -- a subject cannot participate in granting without a signature `ConsentEnvelope` does not carry)` | `crates/state/src/healthcare_executor.rs:596` guard `:600`; `:643` guard `:656`; `subject_address`/`subject_ref` declared at `crates/sumchain-wire/src/healthcare.rs:631,637` and read by no guard; pinned by `the_subject_of_a_consent_can_neither_grant_nor_revoke_it` | disclosure authorizations about a person are recorded without their participation |
| AU-4 | `AddNetworkAffiliation` / `RemoveNetworkAffiliation` have no issuer check | Healthcare §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height`, implemented and dormant | arms `crates/state/src/healthcare_executor.rs:298` and `:322`; only guard is provider existence `:307`/`:331`; pinned by `any_sender_can_change_a_providers_network_affiliations` | a stranger moves any provider between plan networks |
| AU-5 | `IssuePrescription` never relates the sender to the named prescriber or to the patient | Healthcare §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/healthcare_executor.rs:708`; guards `:712` (issuer == sender), `:717` (prescriber exists), `:721` (duplicate id) | anyone who can register a provider issues prescriptions naming any other registered provider |
| AU-6 | Healthcare `VerifyProof` verifies nothing | Healthcare §missing authorization | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/healthcare_executor.rs:955`; body `:957-961` is deduct/credit/increment, no proof read; pinned by `verify_proof_succeeds_for_a_proof_that_does_not_exist` | see Class 5 |
| AU-7 | Issuer identity is self-asserted: where a check exists it is `issuer_address == sender`, and `issuer_address` comes from the payload on every creation path; no issuer registry is consulted | Healthcare / Property §missing authorization | **REACHABLE** | none | Healthcare creation guards e.g. `crates/state/src/healthcare_executor.rs:600, 712`; Property `AnchorAsset` guard `asset.issuer_address != *sender` in `crates/state/src/property_executor.rs`, with no `v_get_issuer` call anywhere in `property_executor.rs` or `property_view.rs`; **pinned by `any_funded_account_is_an_issuer_of_any_class_it_names_for_itself` and `an_issuer_address_that_is_not_the_sender_is_the_one_thing_refused`** | the check binds a row to whoever created it and to nothing else. **Pinned, not remedied, and deliberately so:** an issuer registry is a rule about WHO may write, so adding one changes which transactions succeed and is a consensus change that may not arrive ungated -- and this tree has no Property or Healthcare issuer registry for an executor to consult, so supplying one means writing standard, which is the AU-8 and AU-33 blocker in another subsystem. The pin states the row in the direction a regression would trip: a key that has registered nothing, staked nothing and been admitted by nobody anchors an asset declaring itself a `LandRegistry` and succeeds, the self-asserted class is what gets STORED, and a SECOND unrelated account claims the same class on its own asset and also succeeds -- so there is no admission and nothing to be admitted to. The second test is the discriminator that keeps the first honest: an `issuer_address` naming an address other than the sender IS refused and writes nothing, which is exactly the row's sentence that where a check exists it is `issuer_address == sender` and nothing more |
| AU-8 | `policy_id` carried on providers, memberships, consents, prescriptions (and on Property assets, title events, encumbrances, coverage, claims; and on Agreement commitments, attestations, IP actions, executor links) — stored, consulted by no guard | Healthcare / Property / Agreement | **REACHABLE** | none. **EXAMINED AND LEFT, with the blocker named: making the field gate anything requires deciding WHAT it names, and the one registry it could plausibly resolve against is a different namespace.** `PolicyAccountExecutor::v_get_policy_account` exists and is reachable from the state crate (`crates/state/src/policy_account_view.rs:46`), so "consult the registry" is mechanically available; what is missing is any statement that a membership's `policy_id` is a policy ACCOUNT id rather than a commitment to an off-chain policy document. No subsystem executor names `PolicyAccount` at all, no `policy_id` value in any fixture is a policy-account key, and the two are typed identically (`[u8; 32]`) so the compiler cannot tell them apart either. Binding them would be inventing the binding, and binding them WRONG refuses every lawful transaction whose `policy_id` is a document commitment — the AU-33 failure mode | in the state crate `policy_id` appears only at `crates/state/src/agreement_executor.rs:684`, inside the `#[cfg(all(test, feature = "legacy_tests"))]` module opening at `:634`; the candidate registry it does NOT resolve against is `crates/state/src/policy_account_view.rs`; **pinned by `a_policy_id_that_resolves_to_nothing_is_accepted_and_changes_no_decision`** | the field exists, is written, and gates nothing — and it cannot be made to gate anything until the tree says which namespace it is in. **The row stays EXAMINED AND LEFT and is now PINNED**, in three parts, the third of which is what makes it a pin on the FIELD rather than on one value of it: a Property `AnchorAsset` whose `policy_id` names no policy account succeeds and the id is STORED; `PolicyAccountExecutor::v_get_policy_account`, called from the test at that same id, reports it absent -- so the accessor is reachable, would have answered, and simply is not called on the execution path; and two anchors differing ONLY in `policy_id` produce rows that differ only in `policy_id`, so nothing downstream of the field reads it. A guard that begins resolving the field fails the first assertion; a field that begins reaching any other stored value fails the third |

### Agreement — no authorization outside attestations

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-9 | A signature's party reference comes from the payload and is never compared to the sender, so any sender signs on behalf of any party and carries a two-party agreement to `Executed` alone | Agreement §missing authorization | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- `AgreementCommitment` carries no address at all and `PartyRef` is a commitment or a 32-byte subject id, so there is nothing to compare a sender to. Needs an `Address` on the commitment or an address-bearing `PartyRef` variant, in `crates/sumchain-wire/src/agreement.rs`** | arm `crates/state/src/agreement_executor.rs:275`; `party_ref` deserialized at `:294`, used at `:297`; guards are agreement existence `:280` and duplicate signature `:284` only; pinned by `any_sender_can_sign_on_behalf_of_any_party` | consent itself is forgeable in one transaction |
| AU-10 | The `signature` bytes are stored and never verified against `signer_key` or anything else | Agreement §missing authorization | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- verifying the stored `signature` against `signer_key` needs a canonical signing input this subsystem does not define. A wire change, not a guard** | field `crates/sumchain-wire/src/agreement.rs:289`, stored via `v_put_signature` `crates/state/src/agreement_executor.rs:296`; no `verify`/`ed25519` call exists in `agreement_executor.rs` or `agreement_view.rs` | nothing in the executor checks a signature |
| AU-11 | Any sender may terminate, void or supersede any agreement, revoke any IP action, and activate, pause, resume, terminate or complete any executor link | Agreement §missing authorization | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- same missing address as AU-9; none of the eight arms has anything to authorize against** | arms and their sole existence/state guards: `crates/state/src/agreement_executor.rs:212`/`:220`, `:242`/`:251`, `:424`/`:432`, `:472`/`:480`, `:502`/`:510`, `:526`/`:534`, `:555`/`:563`, `:579`/`:587`; pinned by `any_sender_can_terminate_void_and_revoke_anything` | none of the eight compares the sender |
| AU-12 | Agreement `VerifyProof` verifies nothing | Agreement §missing authorization | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/agreement_executor.rs:621`, body `:623-627`; pinned by `verify_proof_succeeds_for_a_proof_that_does_not_exist` | see Class 5. **The remaining half was re-tested against source rather than inherited, and is confirmed structural: `public_inputs` is DECLARED in seven wire structs and READ in exactly two places, both of which hash it into a commitment (`crates/sumchain-wire/src/tax.rs:825-832`, `crates/sumchain-wire/src/equity.rs:1244-1251`). Every other occurrence outside tests is a COMMENT in an executor saying no verifier exists. Nothing in this tree checks `proof_data` against `public_inputs` in any subsystem, so the row's own sentence -- it verifies NOTHING -- cannot be made false by an executor change** |

The attestation exception is real and worth recording because it shows the gap
is specific rather than architectural: `crates/state/src/agreement_executor.rs:332`
guards at `:336`, `:353` at `:366`, `:381` at `:395` — pinned by
`only_the_issuer_may_revoke_or_update_its_own_attestation`.

### Legal

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-13 | `ConsolidateCase` has no authority check: any funded account attaches one stranger's case to another's and moves the second to `Consolidated` | Legal 1 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `legal_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/legal_executor.rs:273`; guards only case existence `:281` and related-case existence `:284`; pinned by `consolidate_case_has_no_authority_check` | contrast `CloseCase`, which does check |
| AU-14 | `TransferCase` has no authority check | Legal 2 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `legal_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/legal_executor.rs:302`; only guard is case existence `:310`; pinned by `transfer_case_has_no_authority_check` | as above |
| AU-15 | `SupersedeOrder` has no authority check **and** no duplicate guard, so a stranger supersedes an order and overwrites a different existing order by reusing its id in the same transaction | Legal 3 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `legal_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/legal_executor.rs:550`; only guard is old-order existence `:559`; `v_put_order(&d.new_order)` at `:577` with no existence check; pinned by `supersede_order_overwrites_an_existing_order_without_a_guard` | both halves reachable from one transaction |
| AU-16 | `SupersedeEvent` does not verify the new event's case exists, creating a dangling case→event index entry | Legal 4 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `legal_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/legal_executor.rs:378`; guard `:387` only; stored at `:404` with no `v_get_case` (contrast `RecordEvent` at `:336`); pinned by `supersede_event_indexes_under_a_case_that_need_not_exist` | attacker chooses the unanchored case id |
| AU-17 | Legal `VerifyProof` verifies nothing, for a payload that is not even a proof id | Legal 5 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/legal_executor.rs:768`, body `:770-774`; pinned by `verify_proof_verifies_nothing_and_still_charges_the_fee` | see Class 5 |

### Tax

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-18 | Anyone self-registers an ACTIVE issuer with an arbitrary class, `TaxAuthority` included, and then issues claims | Tax 1 | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- the registry authorizes nothing it does not take from the applicant, and no `ChainParams` field names a tax registrar. Needs a registrar the chain does not have** | arm `crates/state/src/tax_executor.rs:117`; guards are `issuer.address != *sender` `:121` and "already registered" `:125`; `tax_class` and `status` come from the payload (`crates/sumchain-wire/src/tax.rs:413, 425`), and `TaxIssuerClass::TaxAuthority` is a plain variant at `crates/sumchain-wire/src/tax.rs:314` | the registry authorizes nothing it does not take from the applicant |
| AU-19 | Claim-type registration, update and deprecation have no authority check | Tax 2 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `tax_authorization_enabled_from_height`, implemented and dormant | arms `crates/state/src/tax_executor.rs:67`, `:83`, `:98`; all three guard only on row presence or absence | no sender comparison and no issuer row consulted |
| AU-20 | Tax `VerifyProof` performs no verification: it charges the fee and reports success | Tax 6 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/tax_executor.rs:275`, body `:277-281` | see Class 5 |

### Finance

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-21 | Any sender self-registers as any finance issuer class, `CentralBank` included, and attests KYC in the same block | Finance 1 | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- same shape as AU-18, for finance issuer classes** | arm `crates/state/src/finance_executor.rs:148`; guards `:152` (profile names sender) and `:156` (duplicate); `issuer_class` deserialized from the payload at `:149` | source-only in the blocker document; established here from source |
| AU-22 | `UpdateIssuer` accepts any status the sender asks for, `Active` from `Revoked` included — the guard `ReactivateIssuer` exists to enforce, walked around | Finance 2 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `finance_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/finance_executor.rs:169`; status taken from payload `:171-175`, applied `:190` with no current-status check; contrast `ReactivateIssuer`'s Suspended-only guard at `:234` | as above |
| AU-23 | Update and revoke paths never recheck the issuer, so a REVOKED issuer keeps full control of everything it ever issued | Finance 3 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `finance_authorization_enabled_from_height`, implemented and dormant | arms `crates/state/src/finance_executor.rs:294`, `:357`, `:383`, `:451`, `:477` with guards `:304`, `:370`, `:396`, `:464`, `:490` — none calls `v_get_issuer`; creation paths do, at `:259`, `:330`, `:423` | the asymmetry is exact and specific |
| AU-24 | `UpdateIssuer`'s `issuer.issuer_address != *sender` check is a no-op | Finance 4 | **UNREACHABLE, and RETIRED from the blocking set.** Live code that no input reaches, which is this document's own definition of UNREACHABLE. The row never claimed otherwise -- its own note said "removing it would close nothing" -- so the REACHABLE verdict it carried was caution rather than evidence. What has changed is that the unreachability is now PROVED structurally instead of argued from the paths that happen to exist | none, and none possible: there is no payload, no state and no sender for which the branch is taken. Not a deferral -- there is no unsafe operation left reachable to defer | row fetched by sender key at `crates/state/src/finance_executor.rs:396`, compared at `:401`; the family's only creating `put` keys by `issuer_key(&issuer.issuer_address)` at `crates/state/src/finance_view.rs:98`; registration refuses `issuer.issuer_address != *sender` at `crates/state/src/finance_executor.rs:340`, before the fee. (The line numbers this row carried -- `:177`, `:182`, `:98`, `:152` -- had drifted and are corrected here) | two tests, doing two different jobs. `the_issuer_sender_check_fires_only_on_a_row_no_transaction_can_write` is BEHAVIOURAL: the comparison DOES fire against a hand-planted row whose key and `issuer_address` differ -- so it is live code and not something a compiler removed -- and after registration and after every status-changing operation the row reachable at the sender's key always names the sender. That is a statement about the paths that exist TODAY, and on its own it would still pass the day someone added a new write. `no_write_path_can_make_an_issuer_row_whose_key_is_not_its_own_address` is STRUCTURAL and is what the retirement rests on. It enumerates every use of `FINANCE_ISSUERS` and `EMPLOYMENT_ISSUERS` under `crates/*/src` -- matched BARE, so importing the constant cannot hide one -- and fails on a new one or a changed key; it requires every `put` into either family to key by `issuer_key(&issuer.issuer_address)` or by the address it just read; it fails if any code under `crates/state/src` or `crates/storage/src` assigns to an `issuer_address` field; it requires EVERY `v_get_issuer` call in either executor to key by `sender`; and it RUNS `issuer_key` to check it is injective and address-derived. **What it would catch:** a new write path keyed by anything else, a read-modify-write that rewrites the address, a read keyed by a payload field, or a key builder that collided -- each of which would make the branch reachable and this retirement wrong. Three of the four were confirmed by mutating the source, watching the test fail, and reverting. Both under `cargo test -p sumchain-state --test revocation_index_meaning` |
| AU-25 | `SubmitProof` has no authority check at all — no issuer, no credential reference validation, no signature | Finance 6 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `finance_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/finance_executor.rs:511`; only guard is duplicate proof id `:515` | anyone who pays writes any proof envelope |
| AU-26 | Finance `VerifyProof` succeeds for a proof id that does not exist | Finance 7 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/finance_executor.rs:528`, body `:530-534` | see Class 5 |

### Employment

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-27 | Only `CreateEmployment` and `CreateIncomeAttestation` require an active issuer; every mutation checks only the recorded issuer, so a suspended or revoked issuer keeps full control of everything it ever issued | Employment 4 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `employment_authorization_enabled_from_height`, implemented and dormant | active-issuer checks at `crates/state/src/employment_executor.rs:249-256` and `:422-429` only; mutation guards at `:311`, `:342`, `:372`, `:402`, `:472`; pinned by `a_suspended_issuer_can_still_revoke_but_not_create` | the pinning test's name states the asymmetry exactly |
| AU-28 | `UpdateIssuer`'s `issuer.issuer_address != *sender` cannot fire | Employment 5 | **UNREACHABLE, and RETIRED from the blocking set** -- identical to AU-24, in Employment, and retired on the same proof | none, and none possible, for AU-24's reason | row fetched by sender at `crates/state/src/employment_executor.rs:420`, compared `:425`; equality forced at registration `:381`; the family's only `put` is `EmploymentExecutor::v_write_issuer_row` (`crates/state/src/employment_view.rs:112`), keyed by its `issuer_address` parameter, and its two callers pass `&issuer.issuer_address` and the address just read. (Line numbers corrected from `:177`, `:182`, `:141`) | the one item of the eleven the source message states without a test; confirmed from source, then pinned behaviourally by `the_issuer_sender_check_fires_only_on_a_row_no_transaction_can_write`, which covers the Employment half beside the Finance half. The RETIREMENT rests on the structural test AU-24 names, which covers both families in one pass and additionally pins `v_write_issuer_row`'s CALLERS, because Employment writes through a private helper whose key parameter is only as good as whoever calls it: a new caller, or a changed key argument, is a new write path into `EMPLOYMENT_ISSUERS` and fails the test |
| AU-29 | Employment `VerifyProof` charges the fee, advances the nonce and verifies nothing — not even that the proof exists | Employment 6 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | arm `crates/state/src/employment_executor.rs:506`, body `:508-512`; pinned by `verify_proof_charges_a_fee_and_verifies_nothing` | see Class 5 |

### Property

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-30 | `MergeAssets` checks nothing about the sender: any account merges two assets it did not issue, marking the secondary `Merged` | Property §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `property_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/property_executor.rs:252`; guards `:261`, `:264` are both existence only; pinned by `three_operations_check_no_authority_at_all` | — |
| AU-31 | `SupersedeTitleEvent` checks nothing about the sender: any account supersedes any title event and records a replacement naming itself | Property §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `property_authorization_enabled_from_height`, implemented and dormant | arm `crates/state/src/property_executor.rs:393`; guard `:402` only; same pinning test | — |
| AU-32 | Property `SubmitProof` checks nothing about the sender and verifies nothing about the proof; the only guard is duplicate id | Property §missing authorization | **REACHABLE** | none. **BLOCKED, STRUCTURAL -- `PropertyProofEnvelope` carries no issuer address and Property has no issuer registry at all (no `v_get_issuer` in `property_executor.rs` or `property_view.rs`)** | arm `crates/state/src/property_executor.rs:1019`; guard `:1023`; same pinning test | see Class 5 |

### DocClass — the identity and credential subsystem

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AU-33 | No signature is ever verified anywhere in DocClass; the revocation record the executor builds sets `signature: [0u8; 64]` on every path | DocClass §missing authorization | **REACHABLE** | none. **EXAMINED AND LEFT, with the blocker named rather than deferred: verifying requires a canonical signing payload this tree does not define for DocClass, and inventing one is writing standard, not closing a defect.** The tree HAS a convention for this — `*_signing_bytes` functions that build a domain-separated canonical byte string, at `crates/sumchain-wire/src/validator_authority.rs:48, 65, 75, 92` and `crates/sumchain-wire/src/policy_account.rs:50` — and DocClass has none. Supplying one means deciding which fields are covered, in what order, under what domain separator, and with `issuer_signature` necessarily excluded from its own preimage; and `issuer_key_id: String` names a key that must then be resolved against the issuer's key list under an algorithm nothing states. This is the class of blocker AU-37's `max_credential_validity` units and D-19b's allowlists are in, and it fails the same way: a verification rule that computes the wrong preimage refuses every LAWFUL credential, so a wrong guess here is worse than the gap. The half that is not a specification decision — the executor writing `[0u8; 64]` into a field documented "Signature over the revocation", asserting a signature that does not exist — cannot be repaired without either changing the stored bytes (a consensus change with nothing to put there) or the wire type (outside this track) | `signature: [0u8; 64]` is written on every revocation path (`crates/state/src/docclass_executor.rs:1601, 1692, 1765, 1833` and the eligibility siblings at `:2451, 2555, 2683`); no `verify`/`ed25519` call in the file; the absent convention is `crates/sumchain-wire/src/docclass.rs:450-454, 563, 605-607, 919-921`, four signature fields and no signing-bytes builder for any of them; **pinned by `docclass_signatures_are_written_as_zero_and_checked_as_nothing`** | every signature field in the subsystem is decorative — and the reason it stays that way is that the tree never said what they sign. **PINNED THIS PASS, in BOTH directions, and still left.** The pin asserts the checking half — a credential carrying 64 bytes of nonsense in `issuer_signature` under an `issuer_key_id` naming a key the issuer has never held is ACCEPTED, and both are stored verbatim — and the asserting half, that `RevokeCredential` writes sixty-four zeroes into a field the wire type documents as "Signature over the revocation". Either would fail if a verification arrived ungated, which is what the pin is for: a verification rule is a consensus change and a rule that computes the WRONG preimage refuses every lawful credential, so a guess here is worse than the gap |
| AU-34 | A registered issuer rewrites its own registry row wholesale — subcodes, jurisdictions, status and declared stake all from the payload — so it grants itself any subcode, declares any stake for free, and a SUSPENDED issuer restores itself to `Active` with one `UpdateIssuer` | DocClass §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_stake_escrow_enabled_from_height` (the STAKE half: `UpdateIssuer` can no longer restate the recorded amount) and `docclass_issuer_authority_enabled_from_height` (the subcode, jurisdiction and self-reactivation halves: `UpdateIssuer` keeps the recorded `status`, `authorized_subcodes`, `jurisdictions`, `issuer_type` and `registered_at`, so a SUSPENDED issuer no longer restores itself and no issuer grants itself an authority the registry did not record), implemented and dormant. Two heights because the stake half was closed by an earlier pass under a gate whose subject is the escrow balance, and retrofitting this half onto it would change what an already-documented height means. `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` and `a_suspended_issuer_can_still_revoke_and_update_itself` still pass unchanged, which is what dormancy means; `a_suspended_issuer_reactivates_itself_only_below_the_gate` and `an_update_cannot_grant_itself_authority_at_the_gate` are the disagreeing pair. **Not offered above the gate:** any path that legitimately narrows or widens an issuer's authority. There is none in this tree, so above the gate authority is fixed at registration and ended only by the admin's `DeactivateIssuer`; a one-way narrow with no granting counterpart would be a new governance surface rather than a repair | arm `crates/state/src/docclass_executor.rs:232` → `:1211`; guards `:1223`, `:1227` only; wholesale write `:1236`; `min_issuer_stake` checked only at registration `:1184-1188`; `can_issue()` at `crates/state/src/docclass_view.rs:517`; pinned by `an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself` and `a_suspended_issuer_can_still_revoke_and_update_itself` | suspension is self-reversible |
| AU-35 | Nothing binds a `subject_commitment` to anybody: any funded account anchors an identity root claiming any subject, with any status, timestamps and schema hash, all from the payload | DocClass §missing authorization | **REACHABLE** | none today. **PARTLY REMEDIED, PENDING ACTIVATION:** `docclass_identity_binding_enabled_from_height`, implemented and dormant -- two halves only. Above the gate a `subject_commitment` some OTHER controller has already anchored is refused, so a commitment is bound to the address that anchored it first and a stranger can no longer anchor a root over a subject that is spoken for; and `status` is written as `Active` by the executor rather than taken from the payload, so a root cannot be created into a lifecycle state that `DeactivateIdentity` and `ReactivateIdentity` exist to reach. It stays PARTLY, and the row's own sentence stays true, because **nothing binds the commitment to a PERSON**: there is no signature, no external identity registry and no attestation in this tree to bind it to, so first-anchor is squatting resistance and not authentication. The timestamps are also left from the payload, deliberately: the executor's clock is zero until `subsystem_block_timestamp_enabled_from_height` opens, and writing them here would make this gate's repair depend silently on another gate's height | `crates/state/src/docclass_executor.rs:278-293` stores the deserialized struct verbatim after one check (`controller == sender`, `:281`); `subject_commitment` only copied into events at `:771, 819`; pinned by `an_identity_root_is_stored_exactly_as_the_sender_supplied_it` for the ungated behaviour and, on BOTH sides of the gate, by `a_subject_commitment_is_claimed_by_a_stranger_only_below_the_gate` and `an_identity_is_created_in_the_payloads_status_only_below_the_gate` — **all three re-run and passing in this pass** | this is also what arms BD-6. **Closed as far as this tree allows, and the residue is named rather than deferred:** the two halves that ARE mechanical are gated and pinned on both sides, and the half that is not — binding a commitment to a PERSON — has nothing in this tree to bind to. There is no signature, no external identity registry and no attestation, so first-anchor is squatting resistance and not authentication, and the row's own sentence stays true for that reason and not for want of work |
| AU-36 | The revocation family never consults the issuer registry, so a suspended or revoked issuer can still revoke, suspend, reactivate and supersede its credentials | DocClass §missing authorization | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_revocation_standing_enabled_from_height`, implemented and dormant | arms `crates/state/src/docclass_executor.rs:870, 938, 1006, 1077` all authorize through `check_revoke_auth` at `:1144-1156`, which reads only the row's `issuer` field; no `v_get_docclass_issuer` / `v_can_issue_subcode` in that family | — |
| AU-37 | `DocClassParams.require_issuer_stake`, `initial_issuers` and `max_credential_validity` are declared, defaulted and read by no execution path, while the RPC reports `require_issuer_stake: true` and a ten-year `max_credential_validity` as hardcoded literals | DocClass §missing authorization | **REACHABLE** | none today. **PARTLY REMEDIED, PENDING ACTIVATION:** `docclass_issuer_stake_requirement_enabled_from_height`, implemented and dormant, for `require_issuer_stake` only: above the gate the minimum-stake check at registration runs only when the flag says to, which is what the field says and what the RPC reports. The RPC half is fixed OUTRIGHT and ungated, because reporting a configuration is not a consensus change: `docclass_getConfig` now reads `self.chain_params.docclass` the way `chain_getChainParams` reads its own values, so the node reports the operator's configured `min_issuer_stake`, `require_issuer_stake`, `max_credential_validity` and `admin` instead of three hardcoded literals. It stays PARTLY on the other two fields, with the reasons stated rather than deferred: **`max_credential_validity`** is documented "in seconds" while the chain's `Timestamp` is milliseconds and a credential's `valid_from`/`expires_at` are payload values bound to no clock at all, so bounding their difference against it would bake in a unit contract this tree does not state and a wrong guess is a consensus rule that refuses lawful credentials -- it needs the unit settled, which is a specification decision; **`initial_issuers`** is genesis STATE rather than a rule an executor can apply, and honouring it means writing issuer rows into the genesis state, a path this tree does not have | declarations `crates/genesis/src/lib.rs:2090-2103`; the RPC now reads `self.chain_params.docclass` at `crates/rpc/src/server.rs:4267-4269`; the only params field any DocClass execution path reads is `min_issuer_stake` (`crates/state/src/docclass_executor.rs:1934`); **the two that stay open are pinned by `max_credential_validity_bounds_nothing_and_initial_issuers_admits_nobody`** | an operator querying the node is told about rules the chain does not apply. **The two remaining fields are now PINNED, each in the direction a later pass would break.** With `max_credential_validity` configured to ten years, a credential declaring `valid_from: 0` and `expires_at: u64::MAX` is accepted and the unbounded window is STORED — no execution path reads the field, and bounding the difference would bake in a unit contract this tree does not state (the field is documented in seconds; `Timestamp` is milliseconds; `valid_from` and `expires_at` are payload values bound to no clock at all). With an address named in `initial_issuers`, that address is still refused as an issuer and nothing is written for it — listing is not registering, because the field is genesis STATE rather than a rule an executor can apply, and honouring it means writing issuer rows into the genesis state, a path this tree does not have |

The two DocClass checks that do bite are recorded so the gap is not overstated:
registration must name the sender's own address and an identity root must name
the sender as controller (`crates/state/src/docclass_executor.rs:281`), pinned by
`registration_and_identity_creation_are_bound_to_the_sender`; and only a
credential's recorded issuer may revoke it, pinned by
`a_third_party_cannot_revoke_someone_elses_credential`.

## Class 4 — Allocation ahead of overlay accounting

Thirty-plus accumulating structures. For this class the reachability question is
not only "does the code run" but "does an attacker control the size", and there
is a configuration finding that changes the answer for all of them at once.

**The release ceiling is 1 GiB, not the 4,096 or 8,192 bytes the pinning tests
used.** `crates/state/src/executor.rs:269` defines
`CANDIDATE_LIMIT_SCAFFOLD: u64 = 1 << 30`; `crates/state/src/executor.rs:3074`
is its only production construction site. The measurements transcribed in the
blocker document — every "refused by a 4,096-byte ceiling", every "under an
8,192 B ceiling" — were taken against a ceiling five to six orders of magnitude
smaller. Those tests prove the refusal *mechanism* works. **They do not describe
release behaviour**, where nothing is refused until a block's logical write set
reaches a gibibyte. This is the sharpest instance in the audit of a pinning test
proving a behaviour that the release configuration does not exhibit.

The sizing inputs an attacker controls are bounded only by
`max_block_bytes: 2000000` and `max_txs_per_block: 1000`, enforced at
`crates/state/src/executor.rs:3996` and `:3986`, at `min_fee: 1000` per
transaction.

**Those two limits were re-derived and the enforcement site corrected.** They
come from this repository's own `genesis.json`, not from `ChainParams::default()`
(which carries `max_block_bytes: 1_000_000`). They are enforced in
`BlockExecutor::validate_block` at `crates/state/src/executor.rs:4061` and
`:4071` — not `:3986`/`:3996`, which are inside `validate_header` — and
`PoaEngine::do_import_block` calls `validate_block` BEFORE `execute_block`
(`crates/consensus/src/poa.rs:627`), so a payload really is bounded by the block
limit before any executor decodes it. There is no per-transaction size limit
anywhere in the tree.

**A measurement at the release configuration, run for this audit.**
`crates/state/tests/release_ceiling_allocation.rs` measures a 1 GiB ceiling and
a 2,000,000-byte block limit, and reports peak LIVE bytes — the high-water mark
of allocated minus deallocated — alongside the cumulative churn every earlier
file in this class reported. The two are not the same number and only the first
decides whether a validator survives; every "allocated N B" figure transcribed
above is cumulative churn and overstates footprint.

What it found, measured:

  * At the release ceiling the transactions the `*_index_allocation` files show
    being REFUSED are **admitted, and commit**. The closed-gate half of every
    pair in this class is a successful transaction, not a refused one.
  * One `CreateIdentityRoot` at the block-size limit (1,900,160 B payload) is
    admitted and peaks at 12,582,144 B live — **6.6x its payload**, 12.3x
    cumulative — for one `min_fee`, from an empty chain.
  * One `AddKey` against a committed identity row peaks at **4.00x the row** and
    churns **5.00x**, and the candidate is charged 2.00x. Linear across 1, 4, 16
    and 64 MiB — six doublings — so the factor is a slope, not a point.
  * Nothing in `docclass_executor.rs` bounds the length of an `IdentityKey`'s
    `key_id`, so one `AddKey` grows a row by **1,899,873 B** for one `min_fee`.

Extrapolated from those points, and labelled as such in the test's own output: a
single `put` charges its value AND the captured pre-image, so the largest row one
write can still commit is about 536,870,912 B; at 1,899,873 B per transaction a
row reaches that in about 282 blocks — roughly fourteen minutes at a 3,000 ms
block time, for about 282,000 units of fee — and the next `AddKey` against it
peaks at about 2.0 GiB live before the ceiling refuses it. The refusal is what
costs the memory, which is the class.

**Why three rows and not thirteen.** The measurement separates this class into
two populations, and the separator is whether the attacker controls the LENGTH of
what is appended. AL-9, AL-10 and AL-11 do: a DocClass `key_id`, `service_id` or
`endpoint` is a `String` with no length check, so one transaction adds as much as
a block may carry, and a `BatchMint` request count is a number the payload
declares. AL-1 through AL-6 do not: every entry is a fixed 32-byte id,
so one transaction adds 32 bytes. **AL-8 is on BOTH sides and the preamble
was wrong to put it wholly on the second**, corrected here rather than
left: its five INDEX families are fixed-width like AL-1 through AL-6, but
its two IN-ROW accumulators are not, because `IssueMembership` and
`IssuePrescription` store a `MembershipRecord` and a `Prescription`
deserialized from the payload VERBATIM, `dependents` and `fill_history`
included. That is the `CreateIdentityRoot` shape of AL-10 twice over --
one transaction bounded only by `max_block_bytes` decides how large the
record every later `AddDependent` or `PartialFillPrescription` decodes,
rebuilds and re-encodes is -- and it is demonstrated, not argued, by
`a_membership_row_is_seeded_over_the_payload_bound_by_one_transaction`. That difference is not a nuance, it is four
orders of magnitude — DERIVED, not measured, from the same ceiling arithmetic.
A row of `R` bytes costs about `2R` per write (value plus pre-image), so a block
admits `k <= 2^29 / R` writes of it, and a 32-byte-per-write accumulator grows as
`R^2 / 2^35` blocks. Reaching 536,870,912 B takes about 8.4 million blocks —
roughly 291 days of uninterrupted, dedicated blocks at about 8.4 x 10^12 units of
fee — against 282 blocks and 282,000 units for AL-10. The fixed-width rows are
real and still unbounded across time; they are not the rows one transaction can
reach, and they are left `none` deliberately rather than by omission.

Two rows sit on the fixed side of that line and were still not taken. **AL-7** is
attacker-length-controlled like AL-10 — `AssetAnchor.jurisdiction_code` is a
free-form `String` that becomes the index KEY, so the attacker chooses both the
width of the key and how many distinct keys the family holds — and it is
UNTOUCHED here for scope, not because the analysis exempts it. It is the next row
this gate should cover, and covering it needs nothing new: a length check on
`jurisdiction_code` before the key is built, read from the same activation
height. **AL-12** is now CLOSED: the payload bound applied to the DocClass and
NFT dispatches only, and AL-12 names five subsystems; Agreement, Property and
Healthcare now carry the same check, read from the same height. **AL-3 and AL-6
are closed too, and the argument for taking them is the one this preamble's
own arithmetic makes against them**: they are fixed-width slow leaks, and so
are AL-1, AL-2, AL-4 and AL-5, which were gated. Leaving two of six ungated
while gating four is the inconsistency, not the caution -- and the bound costs
one length comparison on a path that was never the problem.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| AL-1 | Tax subject index: `v_add_to_subject_index` decodes an accumulating `Vec<ProofId>`, linear-searches, appends, reserializes — per claim, unbounded across blocks | Tax §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME height AL-7, AL-10 and AL-11 sit behind, for the reason AL-7's row gives: that gate's rule is already "bound the input before building the value", and a partial activation leaves the cheapest vector open. Two bounds, the two AL-10 needed: a Tax payload over 65,536 B is refused before it is decoded, and a stored `TAX_SUBJECT_INDEX` row over 1,048,576 B is refused before it is decoded, appended to and re-encoded -- the stored LENGTH is compared, so the refusal costs one comparison and lands before the fee | `crates/state/src/tax_view.rs:139-143`; reached from `IssueClaim`, arm `crates/state/src/tax_executor.rs:227`; pinned at one size by `a_640_kib_subject_index_is_refused_by_the_ceiling_without_canonical_change` | attacker controls entry count by repeating `IssueClaim`; the ceiling that refused in the test is not the release ceiling |
| AL-2 | Employment: five index values are `Vec<[u8; 32]>` decoded, linear-searched, appended and reserialized on every write | Employment 8 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME field DocClass (AL-10, AL-11), NFT (AL-9) and Agreement (AL-5) read, on the argument that field's own doc comment gives: one rule at one seam, and an attacker refused by any of the other three bounds moves to this one for the price of one `min_fee`. At and above the gate every index row `v_put_credential` (three) and `v_put_attestation` (two) would append to is refused by its stored LENGTH when it exceeds `MAX_ACCUMULATING_ROW_BYTES`, before it is decoded, appended to and re-encoded. No new gate, no new constant: this is a FOURTH reader of the existing rule | append order pinned at `crates/state/src/employment_view.rs:164, 378`; pinned at one size by `a_640_kib_employee_index_is_refused_by_the_ceiling_without_canonical_change`; remedy `crates/state/src/employment_executor.rs::credential_indexes_within_bound` and `::attestation_indexes_within_bound`, length probes `crates/state/src/employment_view.rs::v_employee_index_row_len` and its four siblings; mixed-version `employment_employee_index_stops_growing_an_unbounded_accumulating_row` and four more, plus `an_open_gate_over_small_rows_refuses_nothing` and `a_corrupt_index_row_behaves_the_same_below_the_gate_and_is_length_refused_above` (`sumchain-state --test employment_finance_allocation_bound_gate`) | the source message's own words: "a measurement of one point, not a bound" -- which is why the remedy is a BOUND read from a coordinated height rather than a second measurement. The bound is checked ahead of `v_deduct`, where every other Employment refusal is checked, so a refused transaction in this subsystem still writes nothing at all |
| AL-3 | Legal: three index families are unbounded accumulating `Vec<[u8; 32]>` with a linear `contains` on every append | Legal 9 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME field AL-1, AL-2, AL-4, AL-5, AL-9, AL-10 and AL-11 read, a SIXTH reader of one rule rather than a sixth rule, and the argument is the one the class preamble's own arithmetic makes: AL-3 is a fixed-width slow leak and so are AL-1, AL-2, AL-4 and AL-5, which were gated on exactly this field. At and above the gate each of the three index rows a creation arm would append to -- jurisdiction (written by BOTH `AnchorCase` and `DetermineBenefit`, kept apart only by the `":benefit"` suffix), case-event and case-order -- is refused by its stored LENGTH when it exceeds `MAX_ACCUMULATING_ROW_BYTES`, before it is decoded, appended to and re-encoded. The jurisdiction family is now read by BOTH halves of this gate and they are independent: `MAX_INDEX_KEY_TEXT_BYTES` bounds the KEY, `MAX_ACCUMULATING_ROW_BYTES` bounds the VALUE, and an attacker refused by the first still reaches the second by reusing one short lawful code | `crates/state/src/legal_view.rs:145` (the `contains` gate); pinned at one size by the three `a_640_kib_*_index_is_refused_by_the_ceiling_then_appended_to` tests; remedy `crates/state/src/legal_executor.rs::jurisdiction_index_within_bound`, `::case_event_index_within_bound` and `::case_order_index_within_bound`, length probes `crates/state/src/legal_view.rs::v_jurisdiction_index_row_len` and its two siblings; mixed-version `legal_jurisdiction_index_stops_growing_an_unbounded_accumulating_row`, `legal_jurisdiction_index_is_the_same_row_for_benefits_and_is_bounded_there_too`, `legal_case_event_index_stops_growing_an_unbounded_accumulating_row` and `legal_case_order_index_stops_growing_an_unbounded_accumulating_row` (`sumchain-state --test legal_property_healthcare_allocation_bound_gate`) | as above. The bound is checked ahead of `v_deduct`, where every other Legal refusal is checked, so a refused transaction in this subsystem still writes nothing at all |
| AL-4 | Finance: four index values unbounded; nothing ever removes an entry — revocation rewrites the credential in place and the id stays indexed | Finance 12 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION** on the UNBOUNDED half: `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME field AL-5, AL-9, AL-10, AL-11 and now AL-2 read, a FIFTH reader of one rule rather than a fifth rule. At and above the gate each of the four index rows a creation arm would append to is refused by its stored LENGTH when it exceeds `MAX_ACCUMULATING_ROW_BYTES`, before it is decoded, appended to and re-encoded. The jurisdiction index is now read by BOTH halves of this gate and they are independent: `MAX_INDEX_KEY_TEXT_BYTES` bounds the KEY, `MAX_ACCUMULATING_ROW_BYTES` bounds the VALUE. **The SECOND clause -- "nothing ever removes an entry" -- is WITHDRAWN, not gated**, for the reason OV-7's row now gives: the index means "every issuer ever registered", the subsystem says so through its own reader pair, and removing the entry would be the defect rather than the remedy | index written only by `v_put_issuer` at `crates/state/src/finance_view.rs:102`; `v_update_issuer_status` writes only `cf::FINANCE_ISSUERS` at `:107-129`; remedy `crates/state/src/finance_executor.rs::index_row_within_bound`, length probes `crates/state/src/finance_view.rs::v_jurisdiction_index_row_len` and its three siblings; mixed-version `finance_jurisdiction_index_stops_growing_an_unbounded_accumulating_row` and three more, plus `a_short_jurisdiction_code_naming_an_over_long_row_is_still_refused` (`sumchain-state --test employment_finance_allocation_bound_gate`) | the four tests the source message describes are named nowhere in it; the behaviour is established here from source instead. The row's two clauses turned out to be two different findings and are answered separately, which is why one is gated and one is withdrawn |
| AL-5 | Agreement: both accumulating indexes serialize their entire value before `view.put` accounts for a byte — measured 3,204,756 B allocated, 1,280,000 B largest single, 446 B accounted | Agreement §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant — the SAME field DocClass (AL-10, AL-11) and NFT (AL-9) read, on the argument that field's own doc comment gives: one rule at one seam, and an attacker refused by either of the other two bounds simply moves to this one for the price of one `min_fee`. At and above the gate a party-index or executor-index row longer than `MAX_ACCUMULATING_ROW_BYTES` is refused by its stored LENGTH, before it is decoded, appended to and re-encoded | pinned by `both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses`; remedy `crates/state/src/agreement_executor.rs::party_index_within_bound` and `::executor_index_within_bound`, length probes `crates/state/src/agreement_view.rs::v_party_index_row_len` and `::v_executor_index_row_len`; mixed-version `the_allocation_bound_gate_refuses_an_oversized_agreement_index_row` (`sumchain-state --test agreement_allocation_bound_gate`) measures a 2,240,008 B row costing 10,918,943 B peak / 16,305,006 B churn below the gate against 2,240,069 B peak at it | the 1,280,000 B single allocation is `Vec` capacity doubling 20,000→40,000 before the encode. The bound is checked ahead of `v_deduct`, where every other Agreement refusal is checked, so a refused transaction in this subsystem still writes nothing at all |
| AL-6 | Property: all five accumulating indexes, same shape, measured at 3,204,575–3,205,320 B allocated each | Property §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME field AL-3 now reads, a SEVENTH reader of one rule, on the identical argument. At and above the gate each of the five index rows a creation arm would append to -- jurisdiction, asset-title, asset-encumbrance, asset-coverage and coverage-claim -- is refused by its stored LENGTH when it exceeds `MAX_ACCUMULATING_ROW_BYTES`, before it is decoded, appended to and re-encoded, and the jurisdiction family carries BOTH halves of the gate for the reason AL-3's row gives | pinned by `all_five_indexes_allocate_their_whole_value_before_the_ceiling_refuses`; remedy `crates/state/src/property_executor.rs::jurisdiction_index_within_bound` and its four siblings, length probes `crates/state/src/property_view.rs::v_jurisdiction_index_row_len` and its four siblings; mixed-version `property_jurisdiction_index_stops_growing_an_unbounded_accumulating_row` and four more (`sumchain-state --test legal_property_healthcare_allocation_bound_gate`) | the measurement this row records is cumulative churn at a 4,096-byte ceiling, not the release configuration; what the gate changes is that at the release ceiling these transactions are ADMITTED rather than refused, so the allocation happens on the way to a transaction that succeeds |
| AL-7 | Property jurisdiction index compounds it: its KEY is the raw UTF-8 of `AssetAnchor.jurisdiction_code`, taken from the payload with no length or character validation | Property §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME height AL-10 and AL-11 sit behind, because that gate's rule is already "bound the input before building the value" and a partial activation leaves the cheapest vector open. The same defect at the same seam in Legal (`CaseAnchor.jurisdiction_code`, `BenefitDetermination.jurisdiction_code`) and Finance (`FinanceIssuerProfile.jurisdiction_code`) was found while closing this row and is bounded under the same height; neither is a row of this audit | anchor arm `crates/state/src/property_executor.rs:176` stores the payload struct; no validation of `jurisdiction_code` in `property_executor.rs` | the attacker chooses both the width of the key and the number of distinct keys in the family — the only row in this class where attacker control extends to the key space |
| AL-8 | Healthcare: seven accumulating structures — five index families plus `membership.dependents` and `prescription.fill_history` accumulating INSIDE a primary row, so the rebuilt buffer is the entire record; `PartialFillPrescription` rebuilds it twice in one transaction | Healthcare §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant -- the SAME field AL-3 and AL-6 now read, an EIGHTH reader of one rule. BOTH halves of the row are covered and they are different defects: the five INDEX families are refused by their stored LENGTH like AL-3's and AL-6's, and the two IN-ROW cases are refused by the stored length of the WHOLE RECORD, checked **before the arm's own `v_get_*`** -- because the decode of the record is the cost the bound exists to refuse, and a check placed after it would refuse the write having already paid for the read. **The class preamble's assignment of this row to the fixed-32-bytes-per-transaction side is corrected there**: `IssueMembership` and `IssuePrescription` store the payload struct verbatim, so the in-row half is single-transaction seedable and is AL-10's shape, not AL-1's, which is also why the payload bound (AL-12) matters here more than anywhere else in this class | pinned by `every_healthcare_accumulator_allocates_its_whole_value_before_the_ceiling_refuses`; in-row cases measured at 4,483,696 B and 4,483,993 B allocated against 168 B accounted; remedy `crates/state/src/healthcare_executor.rs::network_indexes_within_bound` and its five siblings, length probes `crates/state/src/healthcare_view.rs::v_network_index_row_len` and its six siblings; mixed-version `healthcare_provider_network_index_stops_growing_an_unbounded_accumulating_row` and four more, plus `healthcare_membership_row_is_refused_before_a_dependent_decodes_it`, `healthcare_prescription_row_is_refused_before_a_fill_decodes_it` and `a_membership_row_is_seeded_over_the_payload_bound_by_one_transaction` (`sumchain-state --test legal_property_healthcare_allocation_bound_gate`) | the worst accounted-to-allocated ratio in the inventory: 26,700:1 — and the only row in the class where one transaction both seeds the record and is charged for rebuilding it |
| AL-9 | NFT: owner index and collection index, neither ever compacted; owner index grows by one `(collection id, token id)` pair per token held, collection index by one `u64` per token ever minted | NFT §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant | appends `crates/state/src/nft_view.rs:171-190` and `:234-251`, called from `crates/state/src/nft_executor.rs:387-388` (mint) and `:461-462` (batch mint, inside the unbounded loop at `:442`); pinned by `both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses` | `BatchMint` takes any number of requests (see OV-10), so one transaction drives many appends. **Measured at the release configuration** by `the_allocation_bound_gate_refuses_oversized_input_before_it_is_built`: a `BatchMint` of 2,000 requests, a 56,008-byte payload that fits inside a block many times over, churns **641,483,444 B** because the loop rebuilds both indexes once per request -- quadratic in a count the payload declares. Bounded to 512 requests, checked before the loop, the same transaction churns 98,109 B and writes no token row |
| AL-10 | DocClass: seven structures, only three of them indexes; the four row-field cases (`IdentityRoot.keys`, `.additional_controllers`, `.services`, `DocClassIssuer.keys`) allocate twice over because the read decodes the whole row into owned values before the encode rebuilds it — up to 7,475,754 B allocated against 168 B accounted | DocClass §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant | pinned by `all_seven_accumulating_structures_allocate_their_whole_value_before_the_ceiling_refuses`; `create_identity_root` stores the payload struct verbatim at `crates/state/src/docclass_executor.rs:278-293` | **one transaction seeds the row.** `CreateIdentityRoot` deserializes the whole `IdentityRoot` — keys, controllers and services included — from a payload bounded only by the 2,000,000-byte block limit, so the attacker does not need 20,000 transactions to reach a large row; every subsequent `AddKey`/`UpdateService` then re-decodes and re-encodes it. **Measured at the release configuration** by `release_ceiling_allocation.rs`: at the 1 GiB ceiling these transactions are not refused at all, they are ADMITTED and commit; one `AddKey` peaks at 4.00x the row and churns 5.00x, linear over six doublings, and one `AddKey` with a 1,899,800-byte `key_id` grows the row by 1,899,873 B for one `min_fee`. Two bounds close it: a payload over 65,536 B is refused before it is decoded (measured peak 84 B against the closed gate's 12,649,814 B) and a stored row over 1,048,576 B is refused before it is decoded (the 2 MiB decode never runs) |
| AL-11 | `UpdateService` and `RotateIssuerKey` linear-scan their list on every append, `RotateIssuerKey` twice | DocClass §unrestricted allocation | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant | same structures as AL-10 | quadratic in a row whose size AL-10 shows is single-transaction seedable. Bounding the row's BYTES subsumes bounding its entry count -- every entry costs at least its own encoding -- so the same `MAX_ACCUMULATING_ROW_BYTES` that closes AL-10 bounds the scans here, and a second limit would be a second thing to keep consistent for no more safety |
| AL-12 | Every subsystem payload is `bincode::deserialize`d from transaction data with no size or shape limit ahead of it, so the same exposure applies at the decode boundary | Agreement / Property / Healthcare / NFT / DocClass §unrestricted allocation | **REACHABLE**, with a measured bound | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_allocation_bound_enabled_from_height`, implemented and dormant. All five subsystems the row names now refuse a payload over `MAX_SUBSYSTEM_PAYLOAD_BYTES` before it is deserialized: NFT and DocClass already did, and Agreement, Property and Healthcare now do. The refusal charges nothing and does not advance the nonce, because every arm below deducts the fee itself and every pre-existing `failure()` ahead of that deduction is already free | e.g. `crates/state/src/agreement_executor.rs:171, 193, 217, …`; no `with_limit` call exists in any `crates/state/src/*_executor.rs`; remedy at the head of `AgreementExecutor::execute_with_gates`, `PropertyExecutor::execute_with_gates` and `HealthcareExecutor::execute_with_gates`; mixed-version `an_oversized_payload_is_refused_before_it_is_deserialized_in_all_three_subsystems` and `a_membership_row_is_seeded_over_the_payload_bound_by_one_transaction` (`sumchain-state --test legal_property_healthcare_allocation_bound_gate`) | see the empirical note below — reachable, but the amplification is bounded in a way the blocker document does not record. **The decode boundary was never the serious half of this row and the note below says so**; what closing it actually removes is the SEEDING, which is why the Healthcare case is demonstrated rather than asserted: below the gate one `IssueMembership` commits a record larger than the payload bound for one `min_fee`, and that record is what AL-8's in-row accumulators must decode forever after |
| AL-13 | The claim these measurements cannot support: that arbitrary input never reaches an allocator abort, because the replacement value is built before the ceiling is charged | stated as a scope limit by Tax, Legal, Finance, Agreement, Property, Healthcare, NFT and DocClass | **UNDETERMINED** | — | the eight measurements are each one point; the release ceiling is 1 GiB (`crates/state/src/executor.rs:269`), not the 4,096/8,192 B the measurements used | **what would settle it:** a growth-to-abort analysis at the release ceiling — the maximum row size reachable under `max_block_bytes: 2000000` and a 1 GiB write-set ceiling, multiplied by the 2× (index) and 3× (in-row) allocation factors these measurements establish, compared against the memory a validator is specified to have. **Two of those three numbers are now measured** (see the preamble): the growth rate is 1,899,873 B per transaction against a DocClass identity row, and the allocation factor is 4.00x peak / 5.00x cumulative for the row-field cases, linear over six doublings. The third is still absent — this tree states no memory a validator is required to have — so the row stays UNDETERMINED, but it is now undetermined for ONE missing number rather than three. The gate below removes the growth rate from the question for AL-9, AL-10 and AL-11; it does not remove it for the rows that are still `none`. **Re-checked for this pass, and the third number is STILL ABSENT**: `docs/`, `README.md`, `RELEASE.md`, `configs/` and `deploy/` state no minimum memory a validator is required to have, so the row does not move. What HAS changed is the size of the remainder: with AL-1 through AL-12 now all reading `subsystem_allocation_bound_enabled_from_height`, the growth rate is removed from the question for EVERY row in this class rather than for three of them, and no row in it carries an unbounded growth rate at activation. The row stays UNDETERMINED because the question it asks is about the CEILING and the hardware, not about the accumulators: bounding every accumulator does not tell you whether a 1 GiB write set multiplied by a 4.00x peak factor fits in the memory a validator has, when nothing states what that is. **Re-checked again in the findings pass, and the third number has NOT arrived — but the search now returns something, and what it returns sharpens the row rather than settling it.** `docs/b0-pre/protocol/b0-pre-protocol-v1.json` carries `reference_memory_bytes: 4294967296` (4 GiB) under `qualification_gates`, attached to validators, and it is the only validator-attached memory figure in this tree. **It is not the missing number and its own text forbids reading it as one**: the same object says the figure is "only the controlled candidate-comparison envelope, not a deployment or consensus hardware minimum", its `scope` repeats "This is a candidate-comparison envelope, not a validator hardware minimum", and its `validator_eligibility` states outright that qualification is "performance-based, not hardware-class-based: no minimum physical cores or RAM, and detected host hardware is never an eligibility gate. A node of any CPU/RAM configuration may participate." `docs/b0-pre/venue/VENUE.md:297` and the schema at `:920` say the same. So the position is stronger than "the number is absent": **the tree affirmatively states that no validator RAM minimum exists**, which means the comparison this row asks for has no right-hand side to be supplied from the tree's own statements, and inventing one — by promoting the 4 GiB envelope, which is the one figure a careless pass would reach for — would be manufacturing the very specification the document refuses to make. **This row therefore CANNOT be closed from source and configuration, in this pass or any other that stays inside the tree.** Settling it is a specification decision: either the project states a validator memory floor, at which point the growth-to-abort analysis becomes arithmetic over three known numbers, or the eight subsystems stop making the claim their measurements cannot support. Both are outside a remediation track's authority. It is recorded here as blocking, with the reason, rather than left to be re-searched each pass |

**An empirical note on AL-12, run for this audit.** The decode-boundary claim is
about a payload whose declared length is far larger than the payload itself.
bincode 1.3.3 (`Cargo.toml:52`, `Cargo.lock:295-297`) was measured directly in a
scratch project outside this worktree, with a tracking global allocator: an
8-byte payload declaring a `Vec<u8>` of 2³⁰ elements produced a peak of
1,049,220 B and a largest single allocation of 1,048,576 B before erroring;
`Vec<[u8; 32]>` at 2³⁰ and `Vec<u8>` at 2⁴⁰ produced the same 1,048,576 B
ceiling; a `String` produced 40 B. So bincode reads in 1 MiB chunks and does
**not** pre-allocate the declared length. The decode boundary is an amplification
of roughly 131,000× from an 8-byte payload, **bounded at about 1 MiB per decode
attempt and freed on the error**. That is a real cost multiplier at 1000
transactions per block and it is not an out-of-memory vector on its own. The
row-growth vector (AL-10) is the serious one, and it is serious because the row
is real data, not a declared length.

This measurement narrows AL-12; it does not close AL-13, which is about
accumulated row size rather than about decode.

## Class 5 — Proof verifiers that verify nothing

Seven subsystems ship a `VerifyProof` operation. All seven charge a fee, advance
the nonce and return success without reading a proof. All seven are live arms of
an ungated executor, so all seven are reachable; they are collected here rather
than repeated because the shape is identical.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| PR-1 | Tax `VerifyProof` (= AU-20) | Tax 6 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/tax_executor.rs:275`, body `:277-281` | no proof read of any kind |
| PR-2 | Employment `VerifyProof` (= AU-29) | Employment 6 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/employment_executor.rs:506`, body `:508-512` | does not even check the proof exists |
| PR-3 | Legal `VerifyProof` (= AU-17) | Legal 5 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/legal_executor.rs:768`, body `:770-774` | succeeds for a payload that is not a proof id |
| PR-4 | Finance `VerifyProof` (= AU-26) | Finance 7 | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/finance_executor.rs:528`, body `:530-534` | succeeds for a proof id that does not exist |
| PR-5 | Agreement `VerifyProof` (= AU-12) | Agreement | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/agreement_executor.rs:621`, body `:623-627` | does not deserialize the payload |
| PR-6 | Healthcare `VerifyProof` (= AU-6) | Healthcare | **REACHABLE** | none today. **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION:** `subsystem_proof_unsupported_enabled_from_height (at and above the height the arm returns a FAILED receipt reading "VerifyProof is unsupported: this chain implements no verifier for subsystem proofs", for EVERY payload, before the deduct. It still verifies NOTHING -- no verifier is IMPLEMENTABLE from what this tree holds, which was re-established from source rather than inherited: no proof system is in the workspace dependency graph, the risc0/sp1 crates living only under `tools/`, which the root `Cargo.toml` EXCLUDES; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/`; `crates/sumchain-wire` declares no verification-REQUEST type; and `proof_data` / `public_inputs` are read in exactly four non-test places, all of which hash them into an identifier -- but the operation no longer REPORTS a verification. The row's own sentence stays true and stops being something a receipt contradicts. This SUPERSEDES `subsystem_proof_presence_enabled_from_height`, whose branch is retired from the arms: above THAT gate a payload naming a proof the subsystem happened to hold still returned SUCCESS, and presence reported as verification is the same false claim in a narrower form)` | `crates/state/src/healthcare_executor.rs:955`, body `:957-961` | — |
| PR-7 | Property `SubmitProof` verifies nothing (= AU-32); ~~Property has no separate `VerifyProof`~~ **— that clause is WRONG and is corrected here: `PropertyOperation::VerifyProof = 51` exists, decodes, dispatches and below the gate is the same deduct/credit/increment/success as the six arms the audit does name. No AU or PR row names it, and the retired presence gate covered six of seven for exactly that reason. It is now the seventh arm behind `subsystem_proof_unsupported_enabled_from_height`** | Property | **REACHABLE** | `SubmitProof` none. Property `VerifyProof`: **REMEDIED AS UNSUPPORTED, PENDING ACTIVATION** under `subsystem_proof_unsupported_enabled_from_height` | `crates/state/src/property_executor.rs:1019`, guard `:1023`; the unnamed `VerifyProof` arm at `crates/state/src/property_executor.rs:1197`, reachable and pinned by `verify_proof_succeeds_for_a_proof_that_does_not_exist` in `property_routing.rs` | duplicate-id check only; and one arm the audit denied existed |
| PR-8 | Finance `FINANCE_PROOFS` is read only through a presence check, so nothing on the execution path ever decodes a `FinanceProofEnvelope` | Finance 9 | **REACHABLE** | none | the `SubmitProof` duplicate guard is the only read of `cf::FINANCE_PROOFS` on any execution path (`crates/state/src/finance_executor.rs::SubmitProof` → `v_proof_exists`, `crates/state/src/finance_view.rs:604-607`, a `view.contains`); the only other touch of the family is `v_put_proof` below it; **pinned by `a_corrupt_proof_row_is_read_as_present_and_refuses_the_submission`** in `finance_routing.rs` | the blocker document records this item's pin as "a forward reference to a backward reference"; the behaviour is established here from source, so the circularity no longer blocks classification — **and the pin named above closes the circularity behaviourally rather than by citation.** A row of `b"not a valid row"` under a proof id refuses the submission as a duplicate; a decode would have ERRORED instead, so the refusal is itself the proof that no decode happens, and the same submission at an unseeded id succeeds, which is what stops the assertion from also passing on a simply-broken arm. **Preserved, not fixed, and for CO-1's reason:** upgrading the guard to a `get` converts today's refusal into a block-level error of the BD class. Any later change that makes this path decode an envelope fails this test |
| PR-9 | Employment `SubmitProof`'s only proof-family read is a `contains` that never decodes, so a corrupt row refuses the submission instead of erroring | Employment 7 | **REACHABLE** | none | arm `crates/state/src/employment_executor.rs:489`, guard `:493` → `view.contains(...)` at `crates/state/src/employment_view.rs:516-519`; pinned by `a_corrupt_proof_row_refuses_the_submission_rather_than_erroring`, **re-run and passing in this pass** | the safe direction, and reachable; changing it would create new block-level errors of the BD class. The pin asserts both halves and is what a regression would trip: `EmploymentExecutor::v_get_proof` ERRORS on the corrupt row when called directly -- so the refusal below it is a read that never decodes, not a swallowed decode -- while the submission through dispatch returns the employment failure code, and the same submission at an unseeded id succeeds |
| PR-10 | DocClass verifies no signature on any credential, attestation, identity key, issuer key or revocation record (= AU-33) | DocClass | **REACHABLE** | none | `crates/state/src/docclass_executor.rs:906, 974, 1046, 1113` | the whole subsystem's cryptographic binding is absent |
| PR-11 | `PropertyProofStore::is_valid` compares `expires_at` to a caller-supplied time and nothing else; no SRC-86X proof is ever cryptographically checked | Property §corruption handling | **UNREACHABLE** | — | `crates/storage/src/property_store.rs:922-927`; no dispatch path calls it | dead store method — the "verifies nothing" claim is true and the method is never invoked, so it adds no production exposure beyond PR-7 |
| PR-12 | `DocClassStore::verify_credential` checks expiry, validity window, revocation status and issuer capability, but no signature and no proof — and no execution path calls it | DocClass §corruption handling | **UNREACHABLE** | — | `crates/storage/src/docclass_store.rs:899`; repo-wide grep returns the definition only | as above |

## Class 6 — Royalties stored and never paid

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| RY-1 | `royalty_bps` and `royalty_recipient` are stored, returned by the RPC readers, and consulted by no execution path; a transfer pays the recipient nothing | NFT §royalties and config | **REACHABLE** | none. **BLOCKED, STRUCTURAL — ESTABLISHED FROM SOURCE, AND DEEPER THAN THE EARLIER NOTE CLAIMED.** The earlier note ("a transfer carries no consideration for a royalty to be a fraction of") was flagged untested; it is now tested and it holds, on three levels rather than one. (1) **No price on the wire.** `NftTransferData` is `{ to: Address }` (`crates/nft/src/ops.rs:63-66`); `NftTxData` is `{ collection_id, token_id, operation, data }` (`crates/sumchain-wire/src/transaction.rs:179-188`); `TransactionV2` is `{ chain_id, from, fee, nonce, payload }` (`:450-461`) and its only value-bearing variant is `TxPayload::Transfer { to, amount }` (`:467-472`), which is a NATIVE transfer and carries no NFT. There is no field anywhere on the path a royalty could be a percentage OF. (2) **Adding one is not sufficient.** A `Transfer` is signed by the token's owner or an approved address (`crates/state/src/nft_executor.rs::execute_transfer`) and NAMES the recipient; the payer would be `to`, who did not sign it. `SignedTransaction` carries exactly one signature and one public key (`crates/sumchain-wire/src/transaction.rs:993-1001`) and `validate_tx` checks it against `from`, so a price field alone would authorise an executor to debit an account whose holder signed nothing. (3) **So the remedy is a protocol, not a field.** Three shapes, each of which is a design decision this audit is not entitled to make inside an executor: a two-sided ORDER carrying both signatures (a new wire type and a second signature slot on the transaction); a buyer-initiated `Buy` against a seller's standing LISTING (a new wire type AND a new state family keyed by `(collection, token)`); or an escrowed bid (a new wire type, a new family, and a refund path). **Honest outcome: a design package, recorded here, and no implementation.** What IS closable without any of it, and has been, is the half of RY-2 that does not need a price | written `crates/state/src/nft_executor.rs:272-277` and `:723`; schema `crates/storage/src/schema.rs:938, 940`; read only for display at `crates/rpc/src/server.rs:1998-1999`, `:8142-8143` and `crates/wallet/src/main.rs:1521-1522`; `execute_transfer` (`crates/state/src/nft_executor.rs:483-542`) and `v_transfer_token` (`crates/state/src/nft_view.rs:279-297`) move no balance at all; pinned by `royalties_are_recorded_and_never_paid` | the field is publicly readable over RPC (`nft_getCollection`, `crates/rpc/src/api.rs:604`), so a marketplace is told a royalty exists that the chain will never pay |
| RY-2 | Creation zeroes `royalty_recipient` when `royalty_bps == 0`; `UpdateCollectionConfig` has no such rule and sets one anyway, and has no field for `royalty_bps` at all, so a royalty can never be changed after creation | NFT §royalties and config | **REACHABLE** | none today. **PARTLY REMEDIED, PENDING ACTIVATION:** `nft_update_path_parity_enabled_from_height (the RECIPIENT half only: `UpdateCollectionConfig` refuses a recipient for a collection whose `royalty_bps` is zero, which is the rule creation applies. The second half -- that `NftUpdateCollectionConfigData` carries no `new_royalty_bps` at all, so a royalty can never be CHANGED after creation -- is a wire change and is untouched)` | creation rule `crates/state/src/nft_executor.rs:273-277`; unconditional update `:722-724`; payload struct `crates/nft/src/ops.rs:82-83` has `new_royalty_recipient` and `new_base_uri` and no `new_royalty_bps`; pinned by `a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty` | **the second half re-examined and still open, with the wire change now named.** `NftUpdateCollectionConfigData` is wire-frozen: `crates/nft/src/ops.rs:16-18` says field order and types are byte-identical to the historical executor-private structs and that bincode is positional, and `crates/nft/tests/ops_fixtures.rs:38-41` locks the two-field layout. Appending `new_royalty_bps: Option<u16>` changes what an existing two-field encoding decodes to, so the change is a VERSIONED payload (try the three-field decode, fall back to the two-field one) behind its own height, not an added field. It is also the smaller of the two royalty questions: a `royalty_bps` nobody can change is only worth changing if a royalty is ever paid, and RY-1 above establishes that it is not. **Re-examined once more in the findings pass and unchanged, with the split stated plainly so the row is not ambiguously actionable:** the RECIPIENT half is CLOSED behind `nft_update_path_parity_enabled_from_height` and pinned on both sides by `a_royalty_recipient_stops_being_settable_on_a_collection_that_pays_none`, with the ungated behaviour pinned by `a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty` -- both re-run and passing. The `new_royalty_bps` half is NOT closable in a remediation track at all: it is a versioned wire payload behind its own height, and the owner has forbidden unscheduled new gates, so it needs a scheduled height rather than more analysis |
| RY-3 | Transferring a collection moves no token and hands the new owner `owner_only_minting` rights over every future token in it | NFT §royalties and config | **REACHABLE** | none for the row's own sentence. **LOOKED AT AND LEFT, for the reason OV-16 is left: the remedy would be a decision about what collection ownership MEANS, not a behaviour change.** The arm reads the collection, checks `collection.owner == sender`, writes exactly one field and returns — verified: `execute_transfer_collection` touches no token row, no index and no other config field. That is the ordinary Ownable semantics, and nothing in this tree states a different rule for it to violate; "the new owner can mint" IS what `owner_only_minting` plus a new owner means. Refusing the transfer while tokens are live, or moving them with it, would each be a rule nobody set, chosen inside an executor. Recorded rather than skipped. **The hazard recorded alongside the row IS now remedied, PENDING ACTIVATION**, under the existing `nft_update_path_parity_enabled_from_height` rather than behind a height of its own: `execute_create_collection` writes `owner: *sender`, an address that signed the transaction, so no collection is ever CREATED ownerless, while `TransferCollectionOwnership` accepted `Address::ZERO` — this tree's null sentinel, the value the same creation arm writes into `royalty_recipient` to mean "no recipient" — leaving a collection that can never be reconfigured and, while `owner_only_minting` is set, never minted in again, by anybody, at any height, with no operation in the subsystem that undoes it. That is the same asymmetry the parity gate already carries for OV-10 and RY-2 — an invariant the creation arm establishes that a later-write arm does not preserve — so it is the same height and not a further field. Above the gate the transfer to the zero address is a failed receipt and the collection stays where it was; below it, it still succeeds byte for byte | arm `crates/state/src/nft_executor.rs::execute_transfer_collection`; pinned by `transferring_a_collection_moves_no_token` and, for the zero-owner hazard on both sides of the gate, by `a_collection_stops_being_transferable_to_the_zero_address` | the row's own sentence is unchanged and stays REACHABLE; the one concrete hazard found alongside it — a collection nobody can ever mint in or reconfigure — is now gated |

## Class 7 — Unpaginated whole-family readers, and their RPC exposure

The blocker document asks whether these readers are unbounded. The release
question is narrower and sharper: **is the reader reachable from a public RPC
method?** `crates/rpc/src/server.rs:428` registers the entire `SumChainApi`
trait in one `server.start(self.into_rpc())` call, so every method declared in
`crates/rpc/src/api.rs` is live, with no namespace flag and no allowlist. The
authentication path is built but never wired in — the validator is constructed
at `crates/rpc/src/server.rs:296`, stored at `:181`, and thereafter only logged
at `:399`; the rate limiter likewise at `:182` and `:404`; the jsonrpsee server
at `:417-428` carries body and connection limits and no middleware. Release
defaults are `api_key = None` and `rate_limit_enabled = false`
(`crates/node/src/config.rs:199-209`).

So a reader's verdict here turns on one thing: does a method call it.

**SC-1 to SC-7 are now closed, and closed WITHOUT an activation height.** That
is deliberate and it is the only place in this document where a class is closed
outright rather than gated. Every gate in the other classes exists because the
remedy changes what a transaction does, and two nodes that disagree about that
disagree about the chain. These are read paths: no transaction's validity
depends on them, no state root folds them, and `crates/state` calls none of
them, so a node that pages and a node that does not still agree about every
block. There is nothing to coordinate across validators, and applying the gate
pattern here would have been cargo-culting. A previous pass reached the same
conclusion and recorded it without acting on it; this one acted.

Each bounded reader gets the same four properties, from one helper on each side
— `crates/storage/src/page.rs` and `crates/rpc/src/pagination.rs`:

  * a **bounded default** of 100 rows when the caller names no page, so an
    existing caller keeps working and simply stops receiving an answer whose
    size the chain's writers chose;
  * **explicit `limit`/`offset` pagination**, appended as trailing optional
    parameters so no existing JSON-RPC call shape breaks;
  * a **maximum** of 1000 rows and an offset maximum of 1,000,000, REFUSED with
    `-32004` rather than clamped — for the same reason `-32003` exists for the
    history floor, which is that an answer the node quietly shortened is
    indistinguishable from a complete one;
  * **deterministic ordering** — RocksDB key order for a scan, index order for
    an index read — so two calls with the same offset return the same page and a
    page boundary is a position rather than an artefact.

**What is NOT claimed.** A page bounds the response and the peak result
allocation, which fall from one decoded row per family member to at most
`limit`. It does not bound ITERATION for a filtered reader, because none of
these families has an index that can seek to the Nth match; that cost is
unchanged rather than made worse, and it is written down here rather than
claimed away. Three readers needed something other than a page, because for them
a bound would have made the answer WRONG rather than short — a count, a
yes/no verification, and a single-row lookup — and each row below says what it
got instead.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| SC-1 | Tax RPC list methods scan whole column families into `Vec`s with no pagination | Tax §unbounded reads | **WAS REACHABLE; CLOSED** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | all four methods now take trailing optional `limit`/`offset`: `tax_listClaimTypes` `crates/rpc/src/api.rs:1247`, `tax_getActiveIssuers` `:1267`, `tax_getIssuersByClass` `:1280`, `tax_listPolicies` `:1301`, each resolved through `crates/rpc/src/pagination.rs::page_of` and served by `crates/storage/src/tax_store.rs:162, 279, 294, 364`; pinned by `tax_list_methods_return_one_bounded_page_instead_of_the_family`, `tax_pages_are_disjoint_deterministic_and_cover_the_family` and `a_tax_page_over_the_maximum_is_refused_and_never_clamped` | `tax_getIssuersByClass` is bounded too although the row names only three: it is the same store, the same scan and equally public. Default 100 rows, maximum 1000, offset maximum 1,000,000; above either is `-32004` and never a silent clamp |
| SC-2 | `employment_list_issuers` scans the whole issuer family; seven `get_by_*` readers decode an entire index vector and then collect every referenced record into a second vector, with the `active`/`valid` variants building the full list before filtering | Employment 11 | **WAS REACHABLE; CLOSED** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | `employment_listIssuers` `crates/rpc/src/api.rs:1763` → `crates/storage/src/employment_store.rs:227`; the index-driven readers → `employment_store.rs:362, 378, 692` and their address/valid siblings; the `active`/`valid` variants now apply their predicate INSIDE the walk rather than over a fully built list. Pinned by `employment_list_and_index_reads_are_bounded` | **two of the eight are deliberately NOT paged, because for them a page would make the answer WRONG rather than short.** `employment_verifyEmployment` (`api.rs:1820`) is a yes/no question: a bounded list would answer "not employed" for an employee whose matching credential fell past the boundary, so the `.find()` moved into the store walk instead (`employment_store.rs:402`) — it stops at the first match, retains one credential, and returns the identical answer for every input. `employment_getSummary` (`api.rs:1833`) returns three COUNTS and a list; the counts stay exact and are folded one credential at a time (`employment_store.rs:425`), and only the list is paged. Pinned by `employment_verification_is_not_paged_and_still_finds_the_last_credential` (the matching credential is the 250th of 250) and `employment_summary_counts_the_whole_set_and_pages_only_its_list` |
| SC-3 | `FinanceStore::issuers().list_active()` and `get_by_jurisdiction()` are unpaginated and unbounded | Finance 13 | **WAS REACHABLE; CLOSED** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | `finance_getActiveIssuers` `crates/rpc/src/api.rs:1480` → `crates/storage/src/finance_store.rs:238`; `finance_getIssuersByJurisdiction` `api.rs:1493` → `finance_store.rs:254`; pinned by `finance_issuer_reads_are_bounded_paged_and_refuse_an_over_large_page` | `get_by_jurisdiction` is an index read, so the bound is on the POINT-READS — at most `offset + limit` of them against one per index entry. The index ROW is still decoded whole; that is one row, and bounding it is AL-4's problem rather than this one (it was recorded here as OV-7's, and OV-7 turned out to be about the index's MEANING rather than its size). AL-4's bound is on the WRITE path, so it stops the row growing past `MAX_ACCUMULATING_ROW_BYTES` once activated and does not retroactively bound a row already larger — a read of such a row is still one whole decode |
| SC-4 | Agreement `list_active` and `get_by_agreement` walk every row in their column family and return one `Vec` | Agreement §unbounded reads | **WAS REACHABLE; CLOSED** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | `agreement_getActiveExecutorLinks` `crates/rpc/src/api.rs:1414` → `crates/storage/src/agreement_store.rs:671`; `agreement_getExecutorLinksByAgreement` `api.rs:1386` → `agreement_store.rs:645`; `agreement_getExecutorLinksByExecutor` → `agreement_store.rs:661`; pinned by `agreement_executor_link_reads_are_bounded_including_the_full_scan_filter`. The pinning test `the_committed_agreement_readers_return_two_thousand_rows_whole` is unchanged and still passes, because the unpaginated readers survive for in-process callers | `get_by_agreement` is a full scan plus filter and remains one: there is no by-agreement index, so the walk is still O(family). What the page bounds is the RESPONSE and the decoded links held at once — from one per family member to at most `limit`. Stated rather than claimed away |
| SC-5 | Property `list_active` walks every row; the four `get_by_*` readers resolve an index list and point-read every id | Property §unbounded reads | **WAS REACHABLE for two and UNREACHABLE for the rest; CLOSED for both, with different claims** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | REACHABLE half: `property_getActiveAssets` `crates/rpc/src/api.rs:1440` → `crates/storage/src/property_store.rs:281`; `property_getAssetsByJurisdiction` `api.rs:1453` → `property_store.rs:271`; pinned by `property_asset_reads_are_bounded_and_refuse_an_over_large_page`. UNREACHABLE half: `TitleEventStore::get_by_asset_paged`, `EncumbranceStore::{get_by_asset,get_active_by_asset}_paged`, `CoverageStore::{get_by_asset,get_active_by_asset}_paged`, `ClaimStore::{get_by_coverage,get_open_by_coverage}_paged` in `crates/storage/src/property_store.rs`, tested through the store by `the_unreachable_property_readers_are_bounded_at_the_store` because there is no method to test them through | the split verdict is kept rather than averaged, and so is the split CLAIM. Bounding the two reachable readers closes a live vector; bounding the rest means a future `#[method]` cannot expose an unbounded reader. Those are different claims and the row says which is which. The pinning test `the_committed_property_readers_return_two_thousand_rows_whole` is unchanged and still passes |
| SC-6 | Healthcare `list_active` walks every row; `get_by_network`, `get_by_member`, `get_by_subject`, `get_by_patient`, `get_by_prescriber` each resolve a whole index list row by row | Healthcare §unbounded reads | **WAS REACHABLE for `list_active` and UNREACHABLE for the five `get_by_*`; CLOSED for both, with different claims** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | REACHABLE half: `healthcare_getActiveInstitutionalProviders` `crates/rpc/src/api.rs:1550` → `crates/storage/src/healthcare_store.rs:323`. UNREACHABLE half: `healthcare_store.rs:307, 564, 708, 905, 915`, tested through the store by `the_unreachable_healthcare_readers_are_bounded_at_the_store`. Pinned by `healthcare_institutional_providers_page_over_rows_the_caller_receives` | **the institutional allowlist moved INSIDE the scan.** It used to run over a fully built `list_active()`, so a page applied after it would have been a page of the wrong thing — `limit` would have counted rows the scan considered rather than rows the caller receives. The test seeds 250 providers of which half are non-institutional and asserts the page holds 100 institutional ones, not 50. The five patient- and subject-facing readers are still the sensitive ones and still have no method; that is the one place the RPC surface is narrower than the storage surface, and it stays recorded |
| SC-7 | DocClass `get_all`, `get_active`, `get_by_jurisdiction`, `get_by_controller`, `get_by_subcode`, `get_by_revoker` each walk a whole family and return one `Vec` | DocClass §unbounded reads | **WAS REACHABLE for four and UNREACHABLE for two; CLOSED for both, with different claims** | none, and none is wanted: **these are read paths outside consensus.** No transaction's validity depends on them, no state root folds them, and `crates/state` calls none of them, so a node that pages and a node that does not still agree about every block. There is nothing to coordinate across validators, so the gate pattern every other class uses would be ceremony here. The bound is applied directly, at the store and at the RPC | `docclass_getIssuers` `crates/rpc/src/api.rs:1208` → `crates/storage/src/docclass_store.rs:949`; `docclass_getIssuersByJurisdiction` `api.rs:1221` → `docclass_store.rs:974`; `docclass_getAcademicCredentialsByHolder` `api.rs:1973` → `docclass_store.rs:581`; `docclass_getIdentityByController` `api.rs:1162` → `docclass_store.rs:268`; `docclass_getSummary` `api.rs:1149` → `docclass_store.rs:933`. UNREACHABLE half: `get_active` (`docclass_store.rs:961`), issuer `get_by_subcode` (`:995`) and `get_by_revoker` (`:811`). Pinned by `docclass_get_issuers_bounds_the_read_and_not_only_the_response`, `docclass_summary_still_counts_the_whole_family` and `docclass_identity_by_controller_still_answers_from_a_page_of_one` | **three of these needed something other than a page, and each got what it needed.** (a) `docclass_getIssuers` was the one method in the whole audit that already took `limit`/`offset` — and applied them to a `Vec` `get_all` had already filled with the family, so the bound was on the response and never on the read; the skip and the take now happen inside the scan, and an over-large `limit` is refused instead of accepted. (b) `docclass_getSummary` wanted a COUNT: `get_all().len()` built every issuer to produce one `u64`, and a page would have made that number wrong rather than short, so it now retains nothing instead of returning less. (c) `docclass_getIdentityByController` returns ONE identity and always did, by taking `.next()` off a `Vec` of every match; it asks for a page of one, gains no parameter, and gives every caller the identical answer. `docclass_getAcademicCredentialsByHolder` was three full family scans per call, one per academic subcode, each filtered by holder afterwards; both predicates moved into one bounded scan, and a read error there no longer becomes an empty list |
| SC-8 | The claim that the release RPC surface is safe to expose publicly at all | not asserted in the blocker document; raised by this audit | **UNDETERMINED, and unchanged** | — | auth built (`crates/rpc/src/auth.rs`, `ApiKeyValidator::authorize`) and never called on the request path — `crates/rpc/src/server.rs:181, 296, 399`; rate limiting likewise `:182, 404`; default bind `127.0.0.1:8545` (`crates/node/src/config.rs:201`) | **what would settle it is still the deployed operator configuration, and the tree still cannot answer it.** This row does NOT move, and saying so is the point: bounding the readers changed the MAGNITUDE of what a public bind would expose and none of the facts this row turns on. What did change is that the fourteen scans SC-1..SC-7 name are no longer an unbounded-response amplification surface — a request can no longer return a response whose size the chain's writers chose. An unauthenticated, unrate-limited endpoint under a public bind is still an unauthenticated, unrate-limited endpoint, and the remaining residual is stated in the rows above: a filtered reader's ITERATION is still O(family) because no index can seek to the Nth match |

## Class 8 — Overwrite, invalid transition, fee accounting and identity

The remaining entries in the seven audited classes, plus the lifecycle items
that compound them. Same reachability argument throughout: ungated subsystem,
live executor arm.

**Four rows here are CLOSED rather than REACHABLE, and the distinction is not
about reachability at all.** OV-4, OV-5, OV-7 and OV-8 name behaviour a node
does reach, on every revocation, permissionlessly. Each was retired because its
stated CONSEQUENCE was tested and withdrawn: the mechanism is the subsystem
working, the remedy each row implies would be a worse defect than the one it
names, and each row now names the test that would fail if that ceased to be
true. They are kept in place, in full.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| OV-1 | Tax `IssueClaim` can overwrite an existing proof id, leaving the old subject index pointing at the replacement | Tax 3 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `tax_proof_lifecycle_enabled_from_height`, implemented and dormant | arm `crates/state/src/tax_executor.rs:227`, guards `:231`, `:235`; no proof-id existence check before `v_put_proof` at `:245`; `v_put_proof` is a blind overwrite at `crates/state/src/tax_view.rs:139-144` | attacker picks the proof id |
| OV-2 | Tax `RevokeClaim` passes a `subject_nullifier` where the proof store expects a `proof_id`; both are `[u8; 32]`, so it compiles and keys the wrong row | Tax 4 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `tax_proof_lifecycle_enabled_from_height`, implemented and dormant | arm `crates/state/src/tax_executor.rs:249`, field read `:251`, passed to `v_get_proof` `:265` and `v_delete_proof` `:271`, both keyed by `proof_key` at `crates/state/src/tax_view.rs:148-151` | the source message names a pinning test for this and for OV-3 but names neither test; the behaviour is established here from source |
| OV-3 | Tax proof deletion leaves the subject index dangling and permanently growing: `v_delete_proof` removes only the proof row | Tax 5 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `tax_proof_lifecycle_enabled_from_height`, implemented and dormant | `crates/state/src/tax_view.rs:148-151`; the `TAX_SUBJECT_INDEX` entry written by `v_put_proof` at `:143` is left; the only dispatch caller is `RevokeClaim` at `crates/state/src/tax_executor.rs:271` | reachable, and the index it strands is AL-1's |
| OV-4 | Employment `update_status` and `revoke` rewrite only the credential row; the three indexes built at creation keep pointing at a credential that is now `Ended` | Employment 2 | **WAS REACHABLE; CLOSED and RETIRED from the blocking set, the consequence having been withdrawn and the withdrawal pinned.** The code runs and the fact the row states is exactly right; the fact is the subsystem working rather than failing. The earlier pass kept it "in the blocking count's denominator the way OV-16 does". That is the caution this census exists to remove: a row whose remedy is "none, and none is wanted" is not what stands between this tree and a release, and counting it as blocking overstates what does. The finding stays -- in place, in full, and with the mechanism still pinned; only the verdict moves. | none, and none is wanted | pinned by `revoking_a_credential_leaves_all_three_index_entries_behind` and `an_update_and_a_revoke_rewrite_only_the_credential_row`; the WITHDRAWAL is pinned by `the_employee_index_is_what_the_ended_count_is_computed_from`, `the_status_filter_is_at_the_reader_and_the_unfiltered_reader_is_public` and `an_ended_credential_can_be_restored_so_removing_its_index_entry_would_be_irreversible` (`sumchain-state --test revocation_index_meaning`) | the second test is in the codec-parity suite, which asserts storage bytes rather than driving dispatch — it proves the row shape, not the route. **The behaviour is correct and the row's implied remedy is the defect.** `EmploymentCredentialStore::summarize_by_employee` computes `employment_getSummary`'s `ended` count by walking the employee index, so an index that dropped the entry would report `ended = 0` for every employee who has ever left a job; every reader is PAIRED (`get_by_employee` beside `get_active_by_employee`, and both reach the RPC as separate methods), which is only coherent over an index that holds everything; and `UpdateEmployment` accepts any status including `Active`, while no path on the execution side ever re-adds an index entry, so a removal would be irreversible **What the withdrawal tests would catch if the row became a defect again:** `the_employee_index_is_what_the_ended_count_is_computed_from` fails if `summarize_by_employee` stops computing `ended` by walking the employee index, or if the ended credential's id stops appearing in that index row -- either would mean no reader depends on the surviving entry, and the removal this row implies would become defensible. `the_status_filter_is_at_the_reader_and_the_unfiltered_reader_is_public` fails if either half of a reader pair stops being the all/filtered pair it is. `an_ended_credential_can_be_restored_so_removing_its_index_entry_would_be_irreversible` fails if `UpdateEmployment` stops accepting `Active` for an ended credential, under either gate setting. Any one of the three collapses the withdrawal and the row blocks again |
| OV-5 | Employment income attestation revocation touches neither income index | Employment 3 | **WAS REACHABLE; CLOSED and RETIRED from the blocking set, the consequence having been withdrawn and the withdrawal pinned.** On OV-4's evidence and by OV-4's spelling. The earlier pass kept it "in the blocking count's denominator the way OV-16 does". That is the caution this census exists to remove: a row whose remedy is "none, and none is wanted" is not what stands between this tree and a release, and counting it as blocking overstates what does. The finding stays -- in place, in full, and with the mechanism still pinned; only the verdict moves. | none, and none is wanted | pinned by `a_revoked_attestation_keeps_its_key_and_its_two_index_rows`, also a codec-parity test; the WITHDRAWAL is pinned by `the_two_income_indexes_are_read_by_the_same_all_and_valid_pair` (`sumchain-state --test revocation_index_meaning`) | same caveat as OV-4, and withdrawn on OV-4's evidence: `get_by_subject`/`get_valid_by_subject` and `get_by_holder_address`/`get_valid_by_holder_address` are the same all-and-valid pairs, so the two income indexes are the "all" half by the subsystem's own construction **What the withdrawal test would catch:** `the_two_income_indexes_are_read_by_the_same_all_and_valid_pair` revokes one of two attestations and asserts 2-against-1 on BOTH pairs. It fails if `get_by_subject` or `get_by_holder_address` starts filtering -- the two halves of each pair would then be the same query and the "all" reading would have nothing supporting it -- or if either `get_valid_*` sibling stops filtering |
| OV-6 | Legal repeated `ConsolidateCase` is a paid no-op: the append is skipped when the relation is recorded, and `updated_at` is written only inside that branch | Legal 7 | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_no_op_receipt_enabled_from_height`, implemented and dormant | `v_add_related_case` is `contains`-gated at `crates/state/src/legal_view.rs:145`; the arm still charges at `crates/state/src/legal_executor.rs:289-291`; pinned by `a_repeated_consolidation_is_a_paid_no_op` | — |
| OV-7 | Finance status change never rewrites the jurisdiction index, so a revoked issuer stays listed and `get_by_jurisdiction` keeps returning it | Finance 5 | **WAS REACHABLE; CLOSED and RETIRED from the blocking set, the consequence having been withdrawn and the withdrawal pinned.** By OV-4's spelling. The SIZE of the same index row is a separate finding, is NOT withdrawn, and stays gated under AL-4. The earlier pass kept it "in the blocking count's denominator the way OV-16 does". That is the caution this census exists to remove: a row whose remedy is "none, and none is wanted" is not what stands between this tree and a release, and counting it as blocking overstates what does. The finding stays -- in place, in full, and with the mechanism still pinned; only the verdict moves. | none, and none is wanted | `v_update_issuer_status` writes only `cf::FINANCE_ISSUERS` at `crates/state/src/finance_view.rs:107-129`; index written only by `v_put_issuer` at `:102`; the WITHDRAWAL is pinned by `the_jurisdiction_index_is_the_all_half_of_a_pair_and_removal_would_be_irreversible` and `the_finance_reader_pair_puts_the_status_filter_where_employment_puts_it` (`sumchain-state --test revocation_index_meaning`) | compounds SC-3, which is the public method that returns it — and SC-3's own resolution is where the answer was. `FinanceIssuerStore::list_active` filters on `status.is_active()` and `get_by_jurisdiction` does not; `finance_getIssuersByJurisdiction` documents itself as issuers "registered in a jurisdiction" and returns `status` on every row. That is the same all-and-filtered pair Employment makes, so the jurisdiction index is the "all ever registered" half. And `ReactivateIssuer` restores a suspended issuer through a write path that touches no index, so an entry removed on a status change would never return — a NEW defect, worse than the one this row describes. **The ROW SIZE half of the same index is a different question and IS gated**, under AL-4 **What the withdrawal tests would catch:** `the_finance_reader_pair_puts_the_status_filter_where_employment_puts_it` fails if `get_by_jurisdiction` starts filtering on `status.is_active()`, or if `list_active` stops. `the_jurisdiction_index_is_the_all_half_of_a_pair_and_removal_would_be_irreversible` fails if a suspended issuer can no longer be reactivated into the index row it is already named in. Either collapses the withdrawal |
| OV-8 | Finance `UpdateAddressProof` refuses BEFORE the fee and nonce writes, so unlike every other refusal in the subsystem it charges nothing | Finance 8 | **WAS REACHABLE; CLOSED and RETIRED from the blocking set, the row's second clause having been withdrawn and the withdrawal pinned.** The first clause holds: the arm does return before `v_deduct`. The consequence does NOT. **No** refusal in this subsystem charges anything — every `failure(...)` in `finance_executor.rs` returns ahead of `v_deduct`, the Employment executor is the same, and `executor.rs` reports `fee_paid: 0` for `Failed(16)` — so `UpdateAddressProof` is not unlike its neighbours, it is identical to them, and there is no asymmetry to gate. What IS true of this arm is a different sentence: it is UNCONDITIONAL, with no payload read, no state read and no input that succeeds, and its character-for-character twin is Employment `UpdateIncomeAttestation`, which this row does not name. That is the shape `subsystem_no_op_receipt_enabled_from_height` exists for — "a failed receipt, not an implementation" — and both arms are ALREADY in the state that gate produces, reached by accident rather than by decision. The row is retired rather than left open: with the alleged asymmetry gone there is nothing here that a release ships and should not, and "no gate wanted" beside "still blocking" is the combination this census exists to remove. | none, and none wanted. A charge here would be the one exception in two subsystems, which is the inverse of what the row asks for. **This row was also MALFORMED -- six cells in a seven-column table, its `gate` column swallowed into the verdict -- and is repaired here.** | arm `crates/state/src/finance_executor.rs:289`, `failure(...)` returned at `:291` before any `v_deduct`/`v_increment_nonce`; the withdrawal is pinned by `no_finance_or_employment_refusal_charges_a_fee_or_advances_a_nonce` (`sumchain-state --test revocation_index_meaning`), which runs a conditional refusal, a not-found refusal and this arm against the same account and finds all three free | recorded as "a free-retry asymmetry rather than an overcharge" — and the free retry is the subsystem's rule for every refusal, not this arm's exception. A charge here would be the one exception, which is the inverse of what the row asks for. **What the withdrawal test would catch:** `no_finance_or_employment_refusal_charges_a_fee_or_advances_a_nonce` drives a conditional refusal, a not-found refusal and this unconditional arm against one funded account and asserts balance and nonce are untouched by all three. It fails the moment any refusal in either subsystem starts charging -- which is exactly the asymmetry the row alleged, and would make the row true again |
| OV-9 | NFT `deduct_fee` runs before the dispatch match, so every guard below refuses a transaction whose fee is spent and whose nonce has advanced, while the receipt reports `fee_paid: 0` | NFT §fee accounting | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_charged_receipt_enabled_from_height`, implemented and dormant. At and above the gate a failed NFT receipt carries the fee the executor actually took, and still zero for an insufficient balance, where the zero is true. The fee itself is untouched — `deduct_fee` still runs first, deliberately, because an unpaid refusal is the cheaper transaction to spam; what changes is only what the receipt SAYS about a payment that already happened. Its own height rather than `nft_receipt_failure_enabled_from_height`'s: that one decides whether a block EXISTS, this one changes a number in a receipt of a block that exists either way | remedy `NftExecutionResult::fee_charged` stamped at `crates/state/src/nft_executor.rs::execute_ungated`, read at `crates/state/src/executor.rs` in both NFT arms; mixed-version `a_refused_nft_receipt_starts_reporting_the_fee_it_charged`, `below_the_gate_the_nft_receipt_and_the_balance_disagree` and `deduct_fees_own_balance_refusal_carries_zero_while_a_later_one_carries_the_fee` (`sumchain-state --test nft_charged_receipt_gate`) | `crates/state/src/nft_executor.rs:111` precedes the `match` at `:113`; debit and nonce at `:216-218`, proposer credit `:223-224`; receipt reports zero at `crates/state/src/executor.rs:524`; pinned by `a_refused_nft_operation_has_already_charged_the_fee` | the receipt and the state disagree on every failed NFT transaction |
| OV-10 | NFT `UpdateMetadata` takes the payload verbatim as the new metadata, undecoded, with no size limit and no per-byte fee; `BatchMint` checks neither, for any number of requests | NFT §metadata size | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_update_path_parity_enabled_from_height`, implemented and dormant | enforcement exists only in `execute_mint` at `crates/state/src/nft_executor.rs:329` and `:337-338`; `execute_update_metadata` `:623-662` writes `token.metadata = data.to_vec()` at `:652` with no check; `execute_batch_mint` `:408-480` clones per-request metadata at `:450` with no check; `validate_metadata_size` and `calculate_nft_storage_fee` have exactly one non-test call site each; pinned by `update_metadata_accepts_any_size_and_charges_no_storage_fee` and `batch_mint_ignores_the_metadata_size_limit_and_the_storage_fee` | `max_metadata_bytes: 16384` and `storage_fee_per_byte: 100` are both set in the release `genesis.json` and both bypassed on two of three write paths — a configured limit that the configuration cannot enforce |
| OV-11 | NFT `SetApprovalForAll` is unimplemented: charges the fee, advances the nonce, returns a failure; operator approvals do not exist | NFT §fee accounting | **REACHABLE** | none. **BLOCKED, STRUCTURAL — RE-TESTED AGAINST SOURCE AND CONFIRMED, ON TWO LEGS RATHER THAN ONE.** (a) No storage: the NFT families are `NFT_COLLECTIONS`, `NFT_TOKENS`, `NFT_OWNER_INDEX`, `NFT_COLLECTION_INDEX` and `ISSUER_REGISTRY` (`crates/storage/src/db.rs:58-66`, and `ALL_CFS` at `:585-596`); no column family anywhere in `crates/storage` is keyed by `(owner, operator)`, and the only allowance-shaped family is SRC-20's `TOKEN_ALLOWANCES` (`:72`). (b) No WIRE: `crates/nft/src/ops.rs` declares no payload struct for this operation and says so at `:21`; `NftTxData` (`crates/sumchain-wire/src/transaction.rs:179-188`) carries `collection_id`, `token_id`, `operation` and free `data`, and nothing in it names an operator. `NftAction::SetApprovalForAll` (`crates/nft/src/transaction.rs:78-85`) has an `operator` field but is a display type with no executor path. So the operation has neither a place to write nor anything to write — two structural gaps, not one. **The proposed alternative was examined and rejected on the facts:** making it REFUSE is already what it does — the arm returns `NftExecutionResult::failure` and the pinning test asserts `TxStatus::Failed(2)` with no family changed, so there is no silent success to remove. Refusing EARLIER, ahead of `deduct_fee`, is the only remaining change, and it would make the one operation that can never succeed the only free transaction in the subsystem — the cheapest thing on the chain to spam | `crates/state/src/nft_executor.rs::execute_after_fee`, `SetApprovalForAll` arm; pinned by `set_approval_for_all_charges_a_fee_and_does_nothing` | under `nft_charged_receipt_enabled_from_height` its receipt at least stops reporting `fee_paid: 0` for a fee it took, which is OV-9's remedy reaching this row without implementing it |
| OV-12 | NFT creator may rewrite the metadata of a token it no longer owns, for the life of the token | NFT §authority | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_token_authority_enabled_from_height`, implemented and dormant | guard `crates/state/src/nft_executor.rs:645` is `token.owner != *sender && token.creator != *sender`; wholesale overwrite `:652`; pinned by `the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns` | `creator` never changes |
| OV-13 | NFT `locked` flag is consulted by transfer and burn only; a locked token can still be approved and have its metadata rewritten | NFT §authority | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_token_authority_enabled_from_height`, implemented and dormant | consulted at `crates/state/src/nft_executor.rs:515` and `:606` only; not at `:545` (approve), `:623` (update metadata) or `:665` (collection transfer); pinned by `a_locked_token_can_still_be_approved_and_rewritten` | — |
| OV-14 | NFT `Approve` never reads the collection, so an approval can be recorded on a token in a non-transferable collection | NFT §authority | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_token_authority_enabled_from_height`, implemented and dormant | `execute_approve` `crates/state/src/nft_executor.rs:545-577` makes no `v_get_collection` call; only guard is `token.owner != *sender` at `:557`; pinned by `approve_never_reads_the_collection` | — |
| CI-1 | NFT `CollectionId::new(sender, name, block_timestamp)` — the block timestamp is the only nonce, so two blocks sharing a timestamp give the same sender the same id for the same name and the later creation is refused as a duplicate | NFT §collection identity | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_collection_id_nonce_enabled_from_height`, implemented and dormant. At and above the gate the sender's ACCOUNT NONCE joins the preimage (`CollectionId::new_with_account_nonce`, `crates/nft/src/collection.rs`): it is consensus state read from the same view the transaction executes against, `deduct_fee` has already incremented it by the time the creation arm runs so two creations in one block see two values, and it only ever goes up so the clock no longer has to advance for the id to. The nonce is APPENDED, so the two rules hash preimages differing in length by exactly eight bytes with a shared prefix and ids minted under them live in disjoint spaces — activating this is a change of address space for collections created after the height, not a rule that could collide with what the chain already holds. Nothing is renumbered and nothing migrates. Mixed-version `the_same_creator_can_take_the_same_name_twice_under_one_timestamp`, `the_id_at_the_gate_is_the_account_nonce_preimage`, `two_creators_still_get_two_ids_for_one_name_on_both_sides` and `the_configured_height_is_what_switches_the_collection_id` (`sumchain-state --test nft_collection_id_nonce_gate`) | `crates/nft/src/collection.rs:16`; call `crates/state/src/nft_executor.rs:249-250` with `now_ms` an identity passthrough at `:95-97`; the NFT arm forwards the **real** timestamp (`crates/state/src/executor.rs:503`, sourced `:3138`), duplicate refusal at `:253-257`; pinned by `the_block_timestamp_is_the_only_nonce_in_a_collection_id` | the only subsystem where the real timestamp reaching the executor is itself the problem — it is why NFT is absent from Class 2 |
| OV-15 | NFT removal is asymmetric: emptying an owner's list DELETES the row, emptying a collection's list WRITES an empty list | NFT §index shape | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `nft_index_symmetry_enabled_from_height`, implemented and dormant. At and above the gate emptying a collection's list deletes its row, as the owner index already does. Its own height because it is the only NFT remediation gate that changes which ROWS exist rather than what a receipt says: the same burn produces the same receipt and a different state root | `crates/state/src/nft_view.rs::v_remove_from_owner_index` vs `::v_remove_from_collection_index`, whose `delete_when_empty` parameter is the gate; pinned by `removal_is_asymmetric_between_the_two_indexes` and `burning_the_last_token_deletes_one_index_row_and_writes_the_other_empty`; mixed-version `emptying_the_collection_index_starts_deleting_its_row`, `a_burn_that_leaves_entries_writes_the_same_row_on_both_sides` and `the_configured_height_is_what_switches_the_collection_index_row` (`sumchain-state --test nft_index_symmetry_gate`) | both readers decode an absent row as an empty list, so the RPC surface cannot tell the two spellings apart — which is why this survived, and why the empty rows accumulate one per collection ever emptied with nothing that collects them |
| OV-16 | NFT `next_token_id` never goes back: a burn decrements `total_supply` with `saturating_sub` and leaves `next_token_id`, so a collection with `max_supply` can be permanently exhausted by minting and burning | NFT §index shape | **REACHABLE, AND THE ROW'S SECOND CLAUSE IS WITHDRAWN.** The first clause holds and is pinned. The consequence does NOT: both `max_supply` comparisons in `nft_executor.rs` read `total_supply`, which the burn decrements, and `next_token_id` is compared to nothing anywhere — `Collection::can_mint` (`crates/nft/src/collection.rs:195-200`) reads `total_supply` too and is never called by the executor. Minting and burning exhausts nothing; the slot comes back every time. **What the source shows instead is the opposite defect, and the sharper one:** `max_supply` bounds how many tokens a collection holds AT ONCE, not how many it ever issues, so a collection declaring `max_supply: 1` — the on-chain form of a one-of-one — can issue an unbounded number of distinct tokens over its life, one at a time, each with its own id and metadata, while the config field a marketplace reads as scarcity never says so. **NO GATE, and the decision is now MADE rather than deferred: the field means LIVE supply, this tree says so in its own words, and the implementation already matches.** `CollectionConfig.max_supply` is documented "Maximum number of tokens (0 = unlimited)" and `Collection.total_supply` is documented "Current token count" (`crates/nft/src/collection.rs:88-90`, and the `Collection` struct the second field lives on) — a CURRENT count compared against a MAXIMUM count is internally consistent, and both executor comparisons implement exactly that. So this is not an unset rule an executor would have to guess at; it is a set rule, stated in the doc comments of the two fields the comparison is BETWEEN, and changing it to bound lifetime issuance would OVERRULE the tree's own documentation rather than complete it. The one-of-one reading is a marketplace convention imported from outside and the chain never asserted it. What remains true is narrower and is not a consensus matter: `docs/rpc/api-reference.md:617` and `:729` call the field "Maximum supply" without saying maximum of WHAT, which is the ambiguity that made this row readable two ways; the struct is not ambiguous. Noted rather than gated: a cycle requires the token to be BURNED, so it is the holder's own act and not a permissionless one, and because `next_token_id` never goes back no id is ever reused | increments `crates/state/src/nft_executor.rs:392` (`+= 1`) and `:467` (`+= count`); burn touches only `total_supply` at `crates/state/src/nft_view.rs:317`; pinned by `a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together` | note on the plain `+=`: `Cargo.toml:138-141` sets no `overflow-checks` for `[profile.release]`, so a release binary wraps rather than panics — with `panic = "abort"` at `:141`, a debug build would take the node down instead |
| OV-17 | Healthcare `RenewMembership` sets status `Active` unconditionally, so a membership terminated a transaction earlier is active again by the end of the block | Healthcare §invalid transition | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_state_precondition_enabled_from_height`, implemented and dormant | arm `crates/state/src/healthcare_executor.rs:411`, issuer guard `:425`, then `v_renew_membership` writes `status = Active` at `crates/state/src/healthcare_view.rs:356` with no prior-status check; pinned by `renewing_a_terminated_membership_makes_it_active_again` | — |
| OV-18 | Healthcare fill guard is `refills_remaining == 0 && status != Active`, so a prescription authorizing ZERO refills whose status is `Active` passes and is filled once more | Healthcare §invalid transition | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_authorization_enabled_from_height`, implemented and dormant | `crates/state/src/healthcare_executor.rs:790` — the conjunction is the defect; pinned by `a_prescription_with_no_refills_but_active_status_can_be_filled_once_more` | compounds AU-2 (anyone may fill) and TS-8 (validity evaluated at time zero) |
| OV-19 | Healthcare `is_controlled` is read in exactly one place, covering exactly one status value: `UpdatePrescription` refuses `TransferRequested`; the same prescription can be filled, held, released and cancelled like any other | Healthcare §invalid transition | **REACHABLE, AND THE ROW'S SECOND CLAUSE IS WITHDRAWN.** The first clause holds and is pinned. The consequence does NOT: `PrescriptionStatus::TransferRequested` is the ONLY transfer state the enum has, SRC-876 calls itself "NON-TRANSFERABLE for controlled substances" and says nothing else about `is_controlled`, and a prescription that could not be filled, held, released or cancelled would be a prescription for nothing. Those four are not transfers, so "like any other" describes correct behaviour rather than a defect. **What the source shows instead is a live bypass of the one rule the subsystem does state:** `UpdatePrescription` enforces it on the path that MOVES a prescription, and `IssuePrescription` stores the payload's `status` VERBATIM — so the state the guard exists to keep a controlled prescription out of is reached by issuing it there in the first place, for one `min_fee`, by the same issuer the guard would have refused. That is the AU-35 shape in Healthcare | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_state_precondition_enabled_from_height`, implemented and dormant — the SAME field OV-17 and OV-20 read, a THIRD reader of one rule rather than a third rule, on that gate's own argument: an arm reaching a lifecycle state by walking around the guarded operation that exists to reach it, which is word for word what OV-17's `RenewMembership` does to `ReinstateMembership`. At and above the gate the creation path carries the update path's check, in the update path's own words. Deliberately NOT a normalization of `status` to `Active`: which initial states are lawful for a prescription is a policy this tree does not state, and inventing one would refuse lawful `Pending` issuance to close a hole that is about one state | sole production read `crates/state/src/healthcare_executor.rs:753`; the only other repo occurrence is a test fixture at `crates/storage/src/healthcare_store.rs:1151`; pinned by `the_controlled_substance_guard_covers_only_the_transfer_status`; every other writer of the field passes a hardcoded status that is not `TransferRequested` (`v_record_fill`, and the `Cancelled`/`OnHold`/`Active`/`PartiallyFilled` arms), which is what makes `IssuePrescription` the only other path; mixed-version `a_controlled_prescription_is_issued_straight_into_transfer_requested_until_the_gate` (`sumchain-state --test healthcare_routing`) | with AU-2, the controlled-substance handling is a single status check — and the finding is not that the check is too narrow but that it was on one of the two paths to the state it guards |
| OV-20 | Healthcare `RemoveNetworkAffiliation` writes the index unconditionally, so removing an affiliation the provider never had creates an empty list row where there was none and rewrites the provider row with a bumped `updated_at`; `RemoveDependent` is likewise unconditional | Healthcare §invalid transition | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `healthcare_state_precondition_enabled_from_height`, implemented and dormant | `crates/state/src/healthcare_view.rs:224-241` (contrast the `contains`-gated add at `:200-219`) and `:400-420`; pinned by `removing_an_affiliation_that_was_never_there_still_writes_an_empty_index` and `..._still_stages_an_empty_index` | with AU-4 (no issuer check) this is an attacker-driven row-creation primitive |
| OV-21 | Property: only `ReinstateCoverage`, `PayClaim` and `ReopenClaim` guard on the state they read; every other transition applies from any prior status | Property §invalid transition | **REACHABLE** | none | arms in `crates/state/src/property_executor.rs`; guarded exceptions only | a `Deregistered` asset returns to `Active`; a `Paid` claim moves anywhere |
| OV-22 | Property `MergeAssets` records no relationship and never writes the primary asset; `SubdivideAsset` creates no children; `TransferAsset` moves no ownership — an asset row has no owner field | Property §invalid transition | **REACHABLE** | none | `crates/state/src/property_executor.rs:252` writes only `AssetStatus::Merged` at `:272-277`; `:280` writes only `Subdivided` at `:300-305`; `:223` writes only `PendingTransfer` at `:243-248`; pinned by `merge_subdivide_and_transfer_record_a_status_and_nothing_else` | three operations that name an effect and produce a status |
| OV-23 | DocClass revocation is reversible: revoke, then suspend, then reactivate returns a revoked credential to `Active`, and the mirrored `revocation_status` follows | DocClass §revocation lifecycle | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_revocation_record_enabled_from_height`, implemented and dormant -- the SAME height OV-24 sits behind, because the guard this row needs reads its answer out of the record series OV-24 repairs, and a terminal-state guard fed by a series in which only the last write at a height survives is a guard nobody can reason about | `suspend_credential` at `crates/state/src/docclass_executor.rs:938` has no current-status guard (only auth at `:957`); `reactivate_credential`'s `status != Suspended` check at `:1027` then passes and writes `Active` at `:1040`; pinned by `a_revoked_credential_can_be_suspended_and_then_reactivated` | three ordinary transactions by the recorded issuer, which AU-34 shows can be a self-restored suspended issuer |
| OV-24 | DocClass revocation records are keyed by `credential_id ‖ revoked_at_height`, so two records for one credential at one height are one row and the later write silently replaces the earlier | DocClass §revocation lifecycle | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_revocation_record_enabled_from_height`, implemented and dormant -- the same height as OV-23, and the key it widens is a NEW 44-byte key (`credential_id ‖ height_be ‖ sequence_be`) so every record written before activation keeps its bytes; both readers accept either width and order by the key, under which a legacy record at a height sorts before a sequenced one at that height. The sequence is read out of state rather than from `tx_index`, which reaches a subsystem arm already reduced to `0` whenever `subsystem_tx_index_enabled_from_height` is closed | `v_put_revocation_record` keys via `revocation_key` at `crates/state/src/docclass_view.rs:415`, defined `credential_id ‖ height_be` at `crates/storage/src/docclass_store.rs:92-97`; pinned by `two_revocations_at_one_height_are_one_row` | a revoke and a reactivation in the same block leave one record |
| OV-25 | DocClass `UpdateCredential` charges the fee, advances the nonce and writes nothing at all — not the credential, not an event | DocClass §revocation lifecycle | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_no_op_receipt_enabled_from_height`, implemented and dormant -- a failed receipt, not an implementation: the payload carries nothing but a credential id, so there is no field an update could apply | arm `crates/state/src/docclass_executor.rs:175` → `:830`; after the auth check at `:845-856` it deducts, credits and increments at `:858-860` and returns at `:862` with no `v_put_*`; pinned by `update_credential_charges_a_fee_and_writes_nothing` | — |
| OV-26 | The DocClass registration stake is deducted from the sender and paid to nobody: `RegisterIssuer` deducts `fee + stake_amount` and credits only `fee`; `DeactivateIssuer` refunds nothing and `UpdateIssuer` can raise the recorded stake without moving balance | DocClass §the registration stake | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_stake_escrow_enabled_from_height`, implemented and dormant | `crates/state/src/docclass_executor.rs:1190` computes `fee.saturating_add(issuer.stake_amount)`, `:1191` deducts it, `:1192` credits the proposer only `fee`; no escrow row written; pinned by `the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody` | tokens are destroyed, which is a supply effect and not only a user-facing loss |
| OV-27 | DocClass `IssueCredential` selects its family by trial decode: `AcademicCredential` first, `EligibilityAttestation` on failure, first error discarded; the tx envelope's `DocSubcode` is not consulted | DocClass §family selection | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `docclass_credential_schema_enabled_from_height`, implemented and dormant -- the SAME height D-19b sits behind: widening the validator while the family is still chosen by trial decode hands the wider validator whichever shape happened to decode first, and making the envelope authoritative while the validator still returns `Valid` for everything outside 810--812 makes the chain insist on a declared type it does not then check. Above the gate the envelope's subcode selects the family and the credential's own `subcode` field must agree with it | `crates/state/src/docclass_executor.rs:683-716`; pinned by `issue_credential_picks_its_family_by_trying_to_decode_and_falling_through` | "the two schemas do not currently cross-decode, and nothing enforces that they never will" — the risk is a future schema change, which is a release-process hazard rather than a today-exploitable one |
| OV-28 | Agreement: a signature naming a party not bound to the agreement is stored anyway and rewrites the agreement row while flipping no flag | Agreement §overwrite | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `agreement_signature_integrity_enabled_from_height`, implemented and dormant | arm `crates/state/src/agreement_executor.rs:275`; pinned by `a_signature_for_a_party_outside_the_agreement_is_still_recorded` | — |
| OV-29 | Agreement `RevokeSignature` deletes the signature row and leaves the party's `signed` flag set, so an `Executed` agreement stays executed with a signature gone; no path recomputes the status | Agreement §overwrite | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `agreement_signature_integrity_enabled_from_height`, implemented and dormant | arm `crates/state/src/agreement_executor.rs:303` → `v_delete_signature` deletes only the `AGREEMENT_SIGNATURES` row (`crates/state/src/agreement_view.rs:242-248`); `signed`/`signed_at` set at `:182-183` is never cleared and the `Executed` promotion at `:191` is never reversed; pinned by `revoking_a_signature_leaves_the_party_marked_signed` | — |
| OV-30 | Agreement `AddParty` and `RemoveParty` charge a fee, advance the nonce and do nothing | Agreement §overwrite | **REACHABLE** | none today. **REMEDIED, PENDING ACTIVATION:** `subsystem_no_op_receipt_enabled_from_height`, implemented and dormant -- a failed receipt, not an implementation: `AgreementCommitment` defines no add-party or remove-party semantics | arm `crates/state/src/agreement_executor.rs:322`, body `:324-328`; pinned by `add_party_and_remove_party_charge_a_fee_and_do_nothing` | — |
| CO-1 | Duplicate and existence guards use `contains`, never `get`, across Legal, Finance, Agreement, Healthcare, NFT and DocClass, so a corrupt row reads as present and refuses rather than erroring | Legal 8, Finance 9, Agreement, Healthcare, NFT, DocClass §corruption handling | **REACHABLE** | none | e.g. `crates/state/src/employment_view.rs:516-519`; pinned by `a_presence_guard_reads_a_corrupt_row_as_present_not_absent`, `a_corrupt_proof_row_is_read_as_presence_not_as_corruption`, `a_corrupt_issuer_row_is_read_as_presence_not_as_corruption`, `a_malformed_row_is_an_error_from_every_decoding_reader` -- **all six re-run and passing in this pass**, across Legal, Finance, Employment, Property, Agreement, Healthcare and DocClass | reachable and **deliberately preserved as the safe direction**: upgrading it converts today's refusals into block-level errors of the BD class. Recorded as reachable because it is, and flagged as the one row in this audit where a fix is more dangerous than the defect |
| MD-1 | Payload-supplied metadata stored without reconciliation against the block: `recorded_at_height`, `created_at`, `updated_at`, `valid_from`, `expiry`, `anchored_at_height`, `effective_from`, `date_of_loss`, `date_filed`, `date_written`, `issued_at`, `expires_at`, `registered_at`, `revocation_status`, `registered_at_height` | Finance 11, Agreement, Property, Healthcare, DocClass §untrusted payload metadata | **REACHABLE** | none | creation paths store the deserialized struct verbatim, e.g. `crates/state/src/docclass_executor.rs:278-293`, `crates/state/src/property_executor.rs` (`AnchorAsset`), `crates/state/src/healthcare_executor.rs:596`; **pinned by `a_creation_stores_times_and_a_height_that_contradict_its_own_block`** and, for the DocClass instance, by `an_identity_root_is_stored_exactly_as_the_sender_supplied_it` | a DocClass credential may be issued already expired, already revoked, or valid from before the chain existed. **Pinned rather than reconciled, and the reason is a dependency this audit will not hide:** reconciling any of these against the block means writing the executor's clock into the row, and the executor's clock is ZERO until `subsystem_block_timestamp_enabled_from_height` opens -- so a reconciliation shipped now would either bake a zero into every row or make this repair depend silently on another gate's height. That is the same reasoning AU-35 gives for leaving its timestamps from the payload. The pin executes an anchor in a block at height 1 and timestamp 1000 whose payload claims `created_at: 1`, `updated_at: 4_000_000_000` and `anchored_at_height: 999_999`, requires the transaction to SUCCEED, and requires all three to be stored verbatim -- so the row's own account of when it was anchored is unrelated to when it was anchored, and any later pass that starts overwriting or refusing them fails the test |
| MD-2 | `recipient`, `_tx_index` and `_tx_hash` accepted and ignored across Tax, Employment, Legal, Finance, Agreement, Property, Healthcare, DocClass (DocClass additionally ignores `subcode`) | Tax 9, Employment 9, Legal 10, Finance 14, Agreement, Property, Healthcare, DocClass | **REACHABLE** | none | `TaxTxData.recipient` declared `crates/sumchain-wire/src/tax.rs:1059`; no `.recipient` read anywhere in `crates/state/src` outside `messaging_executor.rs`; `tx_index` and `tx_hash` are taken by every subsystem executor's entry point and bound to `_`-prefixed names, e.g. `PropertyExecutor::execute_with_gates`; DocClass subcode unused (see OV-27); **pinned by `recipient_tx_index_and_tx_hash_reach_no_stored_row`** | accepted-and-ignored fields, reachable in the sense that every transaction carries them; no state effect — **and that "no state effect" is now an assertion rather than a reading.** The pin varies each of the three while holding everything else fixed and requires the resulting rows to be byte-identical: `recipient` through the ordinary signed-transaction path, so dispatch is covered as well as the executor, and `tx_index` / `tx_hash` at the `execute_with_gates` seam, which is where the executor takes them. Varying `tx_index` by 7,777 and `tx_hash` by a whole hash changes no byte. Kept rather than removed: the fields are on wire types, and removing one is a wire change |
| PA-1 | The submit-proposal RPC helper derives a proposal id from the account's COMMITTED nonce while building a transaction, and the executor recomputes the id at execution time against the nonce the candidate holds | PolicyAccount, `855ec009` | **REACHABLE**, and not consensus-relevant | none | public method `policy_build_submit_proposal` `crates/rpc/src/api.rs:2019` → `crates/rpc/src/server.rs:7882`; committed read of the policy account and its nonce inside that body; id derived by `Proposal::compute_id(&policy_account_id, account.nonce, &action_hash)` and returned as an advisory field on `PolicyBuildResponse`; **pinned by `server::policy_rpc_tests::the_built_proposal_id_is_advisory_and_stale_once_the_nonce_moves`** | the path is publicly reachable. The value it returns is advisory — it is not signed into the transaction and not consumed by block execution — so the consequence is a client-side id mismatch when the account's nonce advances between build and inclusion. The blocker document explicitly declines to call this a defect; this audit reports the reachability and leaves that judgement where the source left it. **The behaviour is now FIXED IN PLACE rather than only read**, so that judgement can be re-made against something checkable. The pin asserts three things: the returned id is the one derived against the COMMITTED nonce; the id appears nowhere in the `ExecSubmit` payload the sender signs — which is the whole of "not consensus-relevant", since nothing signs it and execution consumes none; and advancing the account's policy nonce makes the SAME action against the SAME account derive a different id, while every other byte of the built transaction is unchanged. So the mismatch is an ID mismatch and not a different transaction. No remedy is applied: making the id correct would mean deriving it against a nonce the builder cannot see, and removing it would be an RPC surface change |

## Class 9 — Out-of-consensus writes, and the journal re-key

Two items outside normal execution, and therefore outside any claim made about
the execution path. They are classified here on the same four verdicts.

### What the state root actually covers, established first

Both verdicts below turn on one fact, so it is established before them.
`compute_block_state_root` (`crates/state/src/executor.rs:3610-3687`) hashes:
block height, parent hash, timestamp and `tx_root`; each receipt's tx hash,
success bit and `fee_paid` (`:3633-3637`); the contract digest **only** when
`contracts_gate_open` (`:3641-3643`); the supply digest when the correction is
applied (`:3652-3654`); the compute-pool digest **only** when
`compute_pool_gate_open` (`:3668-3671`); the beacon digest **only** when the
beacon gate is open (`:3675-3678`); then the previous root (`:3684`).

**It hashes no application column family.** Not `MESSAGING_*`, not
`STATE_DIFFS`, not any of the eleven subsystems' families. Receipts are in the
root; the rows the receipts were computed from are not.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| OC-1 | Startup index backfill writes `MESSAGING_SENDER_EVENTS` and `MESSAGING_PAYMENTS_BY_RECIPIENT` directly through `Database::put`, outside any candidate and outside block execution | designated blocker (out-of-consensus messaging writes) | **REACHABLE**, not consensus-divergent | none — the marker at `config_keys::INDEX_BACKFILL_V1` is an idempotency flag, not an activation gate | called unconditionally at node startup, `crates/node/src/node.rs:148-150`, before the state manager is constructed at `:159`; body `crates/storage/src/messaging_store.rs:712-800`, raw writes at `:748` and in the payments loop following; failure fails startup; pinned by `neither_backfill_scan_drops_a_read_error` | **every release node runs this on every boot** until the marker is set, so reachability is not in question. The two families it writes are pure indexes: neither is read by `messaging_executor.rs` or `executor.rs`, and neither is in the root (see above). So it cannot diverge consensus — but it is an unversioned, ungated, full-family rewrite performed outside the candidate, and the write set is proportional to `MESSAGING_EVENTS`, which is unbounded. **One half of it IS fixed here, OUTRIGHT and ungated, because it is not a consensus change** — nothing this loop writes reaches the root, so changing when it fails changes no transaction's validity. Both scans read the column family through `Database::full_iter`, which ends in `.filter_map(|r| r.ok())`: a mid-scan RocksDB read error ended the iteration SILENTLY and the loop fell out of its body exactly as it does on an exhausted family, after which the marker write below it stamped a PARTIAL index complete — breaking the invariant the loop's own comment states three lines above it ("a partial index must not be marked complete") through the single failure mode that comment was written against. `INDEX_BACKFILL_V1` is one-time and has no reset path, so the stamp is permanent and the index rows the truncated scan never reached are never written by any later boot. Both loops now use `iter_checked_from`, so a read error reaches the caller and fails startup with the marker still unset, which is the retry the comment promises. The **ungated, out-of-candidate, unbounded** character of the write is untouched and is what keeps the row REACHABLE |
| OC-2 | The `ImportRegisteredKeys` operator command writes `MESSAGING_PUBLIC_KEYS` directly, and that family **is** read by consensus | designated blocker (out-of-consensus messaging writes) | **WAS REACHABLE and consensus-divergent; CLOSED** by option (b) below — the command now refuses above genesis height and into a non-empty registry, and records a permanent marker | none, and none possible: this is an operator path, not a transaction path, so there is no height at which a gate could open it | CLI subcommand declared `crates/node/src/main.rs:257-270`, write loop `:1073-1084` calling `MessagingStore::set_public_key` (`crates/storage/src/messaging_store.rs:908`); the same family is read by the executor at `crates/state/src/messaging_executor.rs:321` (SendMessage requires a registered key), `:750` (RegisterPublicKey duplicate guard) and `crates/state/src/executor.rs:2030` (sponsored-registration duplicate guard) | **this is the halt shape.** A validator that has run the import accepts a `SendMessage` its peers refuse, or refuses a `RegisterPublicKey` its peers accept. Receipts differ; receipts are folded into the root at `crates/state/src/executor.rs:3633-3637`; the roots differ. Nothing in the tree prevents one validator running it and others not — the command requires only a stopped node and write access to the data directory |
| OC-3 | The remaining out-of-consensus write sites in the designated inventory — roughly seven operator, two genesis, one snapshot and three raw reorg | designated blocker (out-of-consensus messaging writes) | **UNDETERMINED** | — | an exhaustive search of this worktree for writes into `MESSAGING_*` families returns raw `put`/`delete` statements in exactly two files, `crates/storage/src/messaging_store.rs` (8) and `crates/state/src/messaging_view.rs` (4), and exactly **two** non-test callers of any writing store method: `crates/node/src/node.rs:149` (OC-1) and `crates/node/src/main.rs:1082` (OC-2). `crates/state/src/state.rs`, `crates/state/src/snapshot.rs` and `crates/consensus/src/` contain no `MESSAGING` reference at all; every `MessagingStore::new` site in `crates/rpc/src/server.rs` (`:3193, 3215, 3262, 3292, 3325, 3363, 3385, 3473, 3496`) was read and all are reads; **the two-caller inventory is now derived by the tree on every test run, by `the_non_test_callers_of_a_messaging_write_are_exactly_the_two_audited_rows`, with `the_scan_can_see_a_caller_it_is_not_expecting` as its discriminator** | **what would settle it:** the tree or branch the designated count of thirteen was taken against, or its enumeration with file and line. This worktree does not contain thirteen such sites, and I will not manufacture the difference by counting statements inside the store as call sites. Until the source of that count is reconciled, the gap between two and thirteen is unestablished, and it blocks — **the row stays UNDETERMINED and is NOT closed here.** What has changed is that the enumeration is no longer a reading someone has to repeat. The test derives the writing-method set from `messaging_store.rs` itself — every `pub fn` whose body puts or deletes, so a method that GAINS a write is covered without anyone remembering — then walks every `crates/*/src` file, drops `//` lines and `#[cfg(test)]` module bodies, and requires the resulting caller set to be exactly two. It requires the file to name `MessagingStore` as well as the method, because several names collide with unrelated private methods: `messaging_executor.rs` has its own `add_contact`, `block_sender` and `set_daily_quota`, none of them this store and all of them inside the candidate. **One correction the mechanical scan forced, and it is this entry's own:** the second caller is no longer `set_public_key` at `crates/node/src/main.rs:1082`. OC-2's remediation replaced that loop, and the call the tree now contains is `MessagingStore::seed_registry_at_genesis` at `crates/node/src/main.rs:1257`. The count of two is unchanged; the name in it was stale. A third entry in that list is a NEW out-of-consensus write site and fails the test, which is the one direction of this row that could be made non-ambiguous without the missing evidence |
| JR-1 | The per-block undo journal key changed shape — from height alone to `height ‖ block_hash` — with no activation gate in the tree | designated blocker (journal re-keying without activation) | **REACHABLE, and not consensus-relevant** | none, and none required | new key `crates/storage/src/schema.rs:43-48`, written at `:362`; legacy key retained at `:56-58`; **reads fall back** to the legacy form at `:377` and `:421`, and **deletes remove both** forms at `:394` and `:442`; the families are `cf::STATE_DIFFS` and `cf::CONTRACT_STATE_DIFFS`, neither of which appears in `compute_block_state_root`; both directions now pinned by `a_journal_written_under_the_old_key_is_still_read_and_still_deleted` and `a_journal_written_under_the_new_key_is_invisible_to_the_old_one` | the new key is used on every block a release node executes, so the path is reachable. It is **not** a consensus change, and this audit confirms the claim the code makes about itself at `crates/storage/src/schema.rs:40-42` rather than taking it on trust: the journals are node-local undo data and no application family reaches the root. The upgrade direction is handled — an old journal is still readable and still deletable. The residual hazard is the **downgrade** direction: a journal written by the new binary is invisible to an old one, so a rollback after a re-keyed block has been executed loses that block's undo record. That is a rollback-coordination item for `docs/operations/production-checklist.md`, not an activation-height item — **and it is now written there**, as step 5 of the restart procedure, with the instruction that a rollback be done by restoring a data directory snapshot taken before the new binary first produced or imported a block rather than by pointing the old binary at the new directory. **CLOSED as far as this audit's own decision rule allows**: the verdict stays REACHABLE because the re-keyed path is what a release node runs, and no code change can close the downgrade direction from this side — the binary doing the looking is the old one — so the remedy is operational by construction. The two tests above assert the asymmetry rather than only its comfortable half; the second one, a NEGATIVE the tree previously asserted only in prose, is what makes the checklist entry a claim about this code |
| JR-2 | Both journal activation gates are `None`, so neither the compute-pool nor the beacon journal is ever written in production | designated blocker (journal re-keying without activation), second direction | **GATED OFF**, and the gate cannot be opened by configuration alone | `compute_pool_enabled_from_height` and `beacon_enabled_from_height`, both absent from `genesis.json` and therefore `None` (`crates/genesis/src/lib.rs:533, 541`) | the gates are consulted at `crates/state/src/executor.rs:3668` and `:3675` for the root fold, and the journals are bound at `:3315-3318` with the comment "Both gates are `None` in production, so neither journal is ever written; presence, not the gate, drives the revert"; revert is presence-driven at `crates/state/src/state.rs:359-381` and `:457` | **this is the strongest gate in the audit, and the only one that is fail-closed in the loader.** `ChainParams::validate` (`crates/genesis/src/lib.rs:941-969`) rejects `Some(_)` for **both** gates outright, so a genesis admitted through `Genesis::from_file` (`:1056-1061`) — the only path `crates/node/src/main.rs:372` uses — cannot open them. **What would re-expose it:** not a config edit. It takes a code change to `ChainParams::validate` removing those two rejections, shipped alongside the `ComputePoolParams` and `BeaconParams` surfaces they are waiting on, and then a coordinated genesis edit. The "defect of writing nothing" is therefore real, deliberate, and unreachable by configuration; the revert path is driven by journal presence rather than by the gate, so a dormant chain has nothing to revert and nothing to get wrong |

### The four designated blockers, answered directly

  1. **NFT permissionless block-level denial** — **REACHABLE**, and
     **REMEDIED, PENDING ACTIVATION.** Rows BD-1 to
     BD-5. Twenty-one `StateError::BlockValidation` sites in
     `crates/state/src/nft_executor.rs`, propagated by `?` at
     `crates/state/src/executor.rs:504` and again at `:3140` inside
     `execute_block`'s transaction loop, so no receipt is produced and the block
     is unexecutable for producer and importer alike. The NFT arm at
     `crates/state/src/executor.rs:494` carries no gate check, there is no
     `nft_enabled_from_height` field in `ChainParams`, and `validate_tx`
     (`:350-400`) inspects no payload type. The cheapest instance is BD-4: any
     byte string bincode cannot decode, at `min_fee: 1000`. **A
     release-configured node dispatches these paths at height 0 and at every
     height, under both readings of the configuration.**
  2. **DocClass registration destroying stake** — **REACHABLE**, and
     **REMEDIED, PENDING ACTIVATION.** Row OV-26.
     `crates/state/src/docclass_executor.rs:1190-1192`: `fee + stake_amount`
     deducted from the sender, `fee` alone credited to the proposer, no escrow
     row written, no refund path. `RegisterIssuer` is a live arm of an ungated
     executor reached from `crates/state/src/executor.rs:755`. **Dispatchable in
     the release configuration**, under both readings.
  3. **Journal re-keying without activation** — rows JR-1 and JR-2, and they
     answer in opposite directions. The re-key is **REACHABLE and correctly
     ungated**: the journals are node-local, the root formula does not touch
     them, and the compatibility path for an in-place upgrade is present and
     symmetric. The two dormant journals are **GATED OFF by a loader-enforced,
     fail-closed gate** that no genesis edit can open. The honest residual is a
     downgrade hazard, recorded in JR-1.
  4. **Out-of-consensus writes into messaging families** — split. OC-1 is
     **REACHABLE** and runs on every boot but touches only executor-unread
     indexes. OC-2 **was REACHABLE and consensus-divergent**, and was the one
     that reproduced the previous halt's shape; it is now **CLOSED** — the
     import refuses above genesis height and into a non-empty registry, and
     records a digest-carrying marker reported at startup and on
     `chain_getSyncCapability`. See "OC-2: closed, by option (b) with a digest"
     below, including the residual it does not close. OC-3, the remainder of the
     designated inventory, is **UNDETERMINED**: I could not find thirteen sites
     in this worktree and will not report a count I cannot cite.

### OC-2: the change required, in files this track does not own

OC-2 is the one designated blocker with the previous halt's exact shape, and it
cannot be remedied from the subsystem executors. The writing path is
`crates/node/src/main.rs`, which belongs to another track. The required change
is stated here precisely rather than attempted:

  * **The symptom.** `ImportRegisteredKeys` (`crates/node/src/main.rs:257-270`,
    write loop `:1073-1084`) calls `MessagingStore::set_public_key`
    (`crates/storage/src/messaging_store.rs:908`), which writes
    `cf::MESSAGING_PUBLIC_KEYS` through `Database::put` — outside any candidate
    and outside block execution. That family **is** read by consensus:
    `crates/state/src/messaging_executor.rs:321` (a `SendMessage` requires a
    registered key), `:750` (the `RegisterPublicKey` duplicate guard), and
    `crates/state/src/executor.rs:2030` (the sponsored-registration duplicate
    guard). Two nodes given different imports therefore produce different
    receipts for identical blocks, and receipts are folded into the state root
    at `crates/state/src/executor.rs:3633-3637`. That is a fork, produced by an
    operator command, with no consensus event to explain it.
  * **Why the OC-1 argument does not apply.** The startup backfill writes
    `MESSAGING_SENDER_EVENTS` and `MESSAGING_PAYMENTS_BY_RECIPIENT`, which no
    executor reads. `MESSAGING_PUBLIC_KEYS` is read by three execution sites.
    The distinction is the whole verdict.
  * **What the node track must do.** Either (a) delete the subcommand, or
    (b) make the import refuse unless the node is at genesis height with an
    empty `MESSAGING_PUBLIC_KEYS` family — a restore path rather than a
    mutation path — and have it record a marker the node reports at startup and
    on every RPC health response, so an operator can see that this node's
    messaging state did not come from its own execution. Option (b) is only
    safe with the refusal: an import into a node that has already executed
    blocks is unrecoverable by any means short of resync, because there is no
    record of which keys were imported and which were registered.
  * **What this track can offer from `crates/storage`.** Nothing that helps
    without (a) or (b). `MessagingStore::set_public_key` cannot tell an operator
    import from the execution path, because the execution path does not go
    through it — `crates/state/src/messaging_view.rs` writes the family through
    the candidate. So the guard has to live at the caller, in
    `crates/node/src/main.rs`. Narrowing the store method's visibility would
    move the problem rather than solve it.
  * **Until one of those lands, OC-2 stays REACHABLE and consensus-divergent**,
    and is counted as blocking.

### OC-2: closed, by option (b) with a digest

Option (b) landed. What was implemented, and the one place it goes further than
the requirement above:

  * **The refusal.** The write now goes through
    `MessagingStore::seed_registry_at_genesis`
    (`crates/storage/src/messaging_store.rs`), which refuses unless the database
    has executed no block above genesis (`BlockStore::get_latest_height()` is
    `None` or `Some(0)`), the registry holds no row of its own, and no seed has
    already been recorded. `crates/node/src/main.rs` checks the same three
    questions first so the operator is refused with a reason rather than asked to
    confirm an operation that cannot succeed, but the library copy is the one
    that makes the unsafe write unreachable — including from any caller written
    later. The `--skip-existing` merge flag is gone with the merge: a registry
    that must be empty has nothing to skip.
  * **The marker.** The rows and a `cf::META` row recording the seed go in ONE
    batch, so no crash can leave a seeded registry that does not say it was
    seeded. It is read back by `sumchain_state::sync_capability`, warned at every
    later startup by `Node::report_sync_capability`, and served on
    `chain_getSyncCapability` as `messaging_registry_seed`. A node that ran the
    seed and restarted still says so.
  * **Why a digest, which the requirement did not ask for.** The refusal closes
    the mid-chain write. It does not close the remaining hazard, and stating the
    hazard is the point of this row: two validators can still seed **different
    sets at genesis** and be forked from block one, because the rows look
    identical either way and neither node has executed anything yet to disagree
    about. A seed is a coordinated initial condition, exactly like a genesis
    edit, and the audit's own rule for those is a byte-identical artefact
    compared across the set. So the marker carries a blake3 over the seeded
    registrations **in address order** — a property of the set, not of the
    operator's file order — and that digest is what two validators compare
    through `chain_getSyncCapability` before the first messaging transaction,
    rather than inferring the divergence from a diverged root afterwards.
  * **What was considered and rejected: deleting the subcommand.** The argument
    for deletion is real and worth recording, because it is nearly decisive:
    `cf::MESSAGING_PUBLIC_KEYS` is fully reconstructible by executing the chain,
    so any import produces a state execution would not — including at genesis,
    where replay produces an *empty* family. On that reading every import
    diverges and only the block at which it shows up differs. What defeats it is
    that the coordinated-genesis case is a real launch-time operation (it is why
    `ExportRegisteredKeys` exists at all), and deleting the supported half of an
    export/import pair does not remove the capability — an operator with write
    access to the data directory still has it, and now without the marker. The
    refusal plus the digest keeps the one sound use, makes the unsound ones
    unreachable, and makes the residual coordination requirement checkable.
    Deletion would have kept none of that.
  * **Residual, stated plainly.** A genesis seed is still a coordination
    obligation on the operators, not a fact the chain enforces: nothing refuses a
    node whose digest differs from its peers'. This row claims only that the
    divergence is now *visible before it matters*, not that it is prevented.
    Enforcing it would mean folding the digest into the genesis artefact, which
    is a `crates/genesis` change and a consensus surface this track does not
    own.
  * **Pinned by** `crates/storage/tests/messaging_registry_seed.rs` (the
    refusals, that a refusal writes nothing, the marker across a reopen, the
    digest's set-identity), `crates/node/tests/import_registered_keys_guard.rs`
    (the real binary: non-zero exit above genesis, the supported shape, the
    marker in the *next* process), `crates/rpc/tests/operator_visible_activation_and_history.rs::a_seeded_messaging_registry_is_visible_to_a_peer_and_two_seeds_are_comparable`
    (the peer-visible surface) and
    `crates/state/tests/execution_closure.rs::operator_tooling_writes_are_declared_deployment_blockers`
    (that the operator door into a `MESSAGING_*` family is the guarded one and
    nothing else).

## Class 10 — The rows where a gate actually decides the answer

Four rows in the whole audit. Each names its gate, where it is set, and what
re-exposes it.

| id | defect | source | verdict | gate | evidence | justification |
|---|---|---|---|---|---|---|
| D-19a | DocClass `SchemaValidator` — the only consensus-level content check in the subsystem — returns `Valid` for every credential below its activation height without looking at it, so a credential carrying an attribute named `student_ssn` is accepted | DocClass §schema validation does not run | **Reading A: GATED OFF (the gate has passed, validation runs). Reading B: REACHABLE** | `SchemaValidatorConfig::default().activation_height = 385000`, hardcoded at `crates/state/src/schema_validator.rs:56-63` — **not** a `ChainParams` field and not settable from `genesis.json` | checks at `crates/state/src/schema_validator.rs:94, 365, 396, 428`; production constructors `crates/state/src/docclass_executor.rs:746` and `crates/state/src/employment_executor.rs:129` both call `SchemaValidator::new()` (`:71-77`), taking the default; pinned by `schema_validation_is_inactive_below_its_activation_height`, `crates/state/tests/docclass_routing.rs:3146-3199` | **the one row where the two readings diverge.** Reading A: `docs/operations/production-checklist.md:100` records height 8,716,604 on 2026-07-06, so 385,000 passed years of chain-time ago and the allowlist runs — the pinning test drives a height the release configuration cannot be at. Reading B: a chain booted from the committed `genesis.json` starts at height 0 and stays below 385,000 for 385,000 blocks ≈ 13.4 days at `block_time_ms: 3000`, during which PII is accepted on-chain and is then permanent. **What re-exposes it under Reading A:** nothing an operator can do — but also nothing an operator can do to close it under Reading B, because the height is a code constant. Changing it is a code change |
| D-19b | The same validator covers only three SRC-81X subcodes and nothing in SRC-80X; eligibility attestations are never schema-checked at any height | DocClass §schema validation does not run | **REACHABLE** under both readings | none today. **PARTLY REMEDIED, PENDING ACTIVATION:** `docclass_credential_schema_enabled_from_height`, implemented and dormant -- the same height OV-27 sits behind. Above the gate the three subcodes with no validator arm (813, 814, 815) get the core field bounds and the per-attribute value and name caps the covered three already apply, every academic subcode gets `validate_storage_hint` on `payload_hint`, and eligibility attestations -- which no path validated at any height, the "nothing in SRC-80X" half -- get their `jurisdiction` bounded and their `payload_hint` checked. It stays PARTLY because the ALLOWLISTS are not extended: an allowlist is a policy decision about which public attributes a credential type may carry, and inventing three of them in a remediation pass would be writing standard rather than closing a defect, so the attribute KEYS stay unrestricted for the subcodes whose standard does not list them | `crates/state/src/schema_validator.rs:126-135` dispatches on `credential.subcode` and returns `Valid` for `_ if credential.subcode.is_academic_class()` and for every non-academic subcode; the gated counterpart is `validate_academic_credential_wide` at `:164`; **the un-extended allowlists are pinned by `the_uncovered_subcodes_still_take_any_attribute_key_above_the_schema_gate`** | passing the height gate does not close this. It is the half of the item that no configuration affects, and it is why D-19 is split rather than answered once. **That half is now PINNED rather than only described.** Above the gate an SRC-813 credential carrying an attribute named `ssn` — a key on this module's own explicitly-disallowed PII list — is VALID, while the SAME key on an SRC-810 transcript is refused by the allowlist that subcode does have; so the assertion is about the SUBCODE and not about a validator that passes everything. The caps the uncovered subcodes DO gain above the gate are asserted in the same test (attribute name and per-attribute value), so it is not about a validator that refuses nothing either, and the whole of it is asserted inert below the height. Extending the allowlists stays out: an allowlist is a policy decision about which public attributes a credential type may carry, and inventing three of them would be writing standard |
| GATED-1 | Contract deploy and call pass a literal `0` where the block timestamp belongs | not in the blocker document's eleven inventories; found while enumerating Class 2 | **Reading A: REACHABLE. Reading B: GATED OFF** | `contracts_enabled_from_height`, consulted by `contracts_gate_open` at `crates/state/src/executor.rs:565` (arm) and `:3641` (root fold) | placeholders at `crates/state/src/executor.rs:580` and `:627`; gate field `crates/genesis/src/lib.rs:324` | **this row is why the audit answers under both readings rather than picking one.** Reading B: the field is absent from the committed `genesis.json`, so `None`, so the arm rejects free and the placeholder is unreachable. Reading A: `docs/operations/production-checklist.md:115` sets it to `8900000`, which `:137` says activates "≈2026-07-12" — and the chain was at 8,716,604 on 2026-07-06, roughly 183,000 blocks and about six days short. **At today's date that gate has been open for months.** A "gated off" answer that was correct in July is wrong now, which is the precise failure mode this audit exists to avoid. The same reasoning applies to `education_enabled_from_height`, `governance_enabled_from_height`, `archive_unbonding_…`, `archive_reassignment_…` and `inference_settlement_…`, all set to the same height; none of those subsystems carries a defect in the seven audited classes, so none gets its own row |
| GATED-2 | Messaging sponsored public-key registration (`RegisterPublicKeySponsoredV1`) | Messaging, `e293b03a` | **GATED OFF** under both readings | `messaging_sponsored_registration_enabled_from_height` | field `crates/genesis/src/lib.rs:585`; gate helper `crates/state/src/executor.rs:198-201`; consulted inside `execute_sponsored_register_v1`, routed ahead of the generic messaging executor at `crates/state/src/executor.rs:702-715` | absent from the committed `genesis.json` and **absent from the mainnet parameter block at `docs/operations/production-checklist.md:104-128`**, so `None` under both readings. **What re-exposes it:** an operator setting the field to a height in a coordinated byte-identical genesis edit per `docs/operations/production-checklist.md:33-35`. Recorded because it is the only subsystem-level operation in the eleven that is genuinely gated, and because the same message's fixed defects (`is_admin` returning `bool`, `has_public_key` asked of the database) were fixed rather than deferred |

## Class 11 — Dead code: reached by nothing

Recorded so that no effort is spent on them and, equally, so that none is
mistaken for a defect the release ships. Every one was established by a
repo-wide search for callers.

| id | item | source | verdict | evidence | justification |
|---|---|---|---|---|---|
| DE-1 | `EmploymentEventStore` — nine `EmploymentEvent` variants, no operation emits one | Employment 10 | **UNREACHABLE** | defined `crates/storage/src/employment_store.rs:675`, exposed `:739`; no executor reference | `EMPLOYMENT_SYSTEM_EVENTS` is never written by execution |
| DE-2 | `LegalEventStore` | Legal 10 | **UNREACHABLE** | defined `crates/storage/src/legal_store.rs:758`, exposed `:843`; noted in-repo at `crates/state/src/legal_view.rs:51`; asserted empty by `published_rows_satisfy_the_committed_scans` | the legal journal is empty on every chain |
| DE-3 | `AgreementEventStore` | Agreement §missing history | **UNREACHABLE** | defined `crates/storage/src/agreement_store.rs:781`, exposed `:875`; pinned by `the_agreement_event_journal_is_never_written` | no undo history, no audit trail: a terminated agreement retains no record of who terminated it |
| DE-4 | `PropertyEventStore` | Property §missing history | **UNREACHABLE** | defined `crates/storage/src/property_store.rs:935`, exposed `:1017`; pinned by `the_property_event_journal_is_never_written` | the twelfth column family; the eleven the migration moved are the ones anything writes |
| DE-5 | `HealthcareEventStore` | Healthcare §missing history | **UNREACHABLE** | defined `crates/storage/src/healthcare_store.rs:958`, exposed `:1035`; pinned by `the_healthcare_event_journal_is_never_written` | compounds AU-2: anyone may fill a prescription and nothing records who |
| DE-6 | `HEALTHCARE_MEMBER_ADDRESS_INDEX`, `HEALTHCARE_SUBJECT_ADDRESS_INDEX`, `HEALTHCARE_PATIENT_ADDRESS_INDEX` — declared, never written | Healthcare §missing history | **UNREACHABLE** | declared and registered at `crates/storage/src/db.rs:502, 504, 506, 723-725`; no `put` in `crates/state/src` or `crates/storage/src` | three column families carried for nothing |
| DE-7 | `AssetStore::add_related_asset` — the one writer that could record a merge or subdivision | Property §invalid transition | **UNREACHABLE** | defined `crates/storage/src/property_store.rs:293`; no caller repo-wide | this is *why* OV-22 is true |
| DE-8 | `DocClassStore::verify_credential` (= PR-12) | DocClass §corruption handling | **UNREACHABLE** | `crates/storage/src/docclass_store.rs:899`; no caller | — |
| DE-9 | `PropertyProofStore::is_valid` (= PR-11) | Property §corruption handling | **UNREACHABLE** | `crates/storage/src/property_store.rs:922-927`; no dispatch caller | — |
| DE-10 | `PrescriptionStore::record_fill`'s own `InvalidData("No refills remaining")` guard | Healthcare §corruption handling | **UNREACHABLE through dispatch** | guard `crates/storage/src/healthcare_store.rs:765` and its view twin `crates/state/src/healthcare_view.rs:675-683`; the executor reads the same row first and refuses at `crates/state/src/healthcare_executor.rs:790` | the blocker document's own reading, confirmed: reproduced verbatim so the candidate side is not the laxer of the two |
| DE-11 | `execute_tx_v2` and its entire payload match (= TS-12) | the "both dispatch arms" half of eight entries | **UNREACHABLE** | `crates/state/src/executor.rs:2081`; no caller outside `crates/state/tests/` | — |
| DE-12 | The five Healthcare `get_by_*` readers, the non-jurisdiction Property `get_by_*` readers, and DocClass `get_active`, issuer `get_by_subcode` and `get_by_revoker` | Healthcare / Property / DocClass §unbounded reads | **UNREACHABLE from RPC**, and unchanged — still no `#[method(...)]` reaches any of them | `crates/storage/src/healthcare_store.rs:307, 564, 708, 905, 915`; `crates/storage/src/docclass_store.rs:961, 995, 811`; `crates/storage/src/property_store.rs` (title/encumbrance/coverage/claim `get_by_*`); no `#[method(...)]` in `crates/rpc/src/api.rs` reaches any of them | the sub-rows of SC-5, SC-6 and SC-7 that the release RPC surface does not expose. Their pinning tests — `the_committed_healthcare_readers_return_two_thousand_rows_whole`, `the_committed_property_readers_return_two_thousand_rows_whole` — exercise readers production cannot call, which is the clearest small example of a test proving behaviour without proving reachability. **The Class 7 pass bounded them anyway and kept the distinction explicit:** each has a `_paged` sibling, tested through the store by `the_unreachable_property_readers_are_bounded_at_the_store` and `the_unreachable_healthcare_readers_are_bounded_at_the_store` rather than through an RPC method, because there is no method to test it through. Bounding an unreachable reader means a future `#[method]` cannot expose an unbounded one; it is not the closing of a live vector, and SC-5, SC-6 and SC-7 each say which half is which |
| DE-13 | `DOCCLASS_EVENTS` is written by every operation and read by nothing block execution can reach | DocClass §missing history | **written but UNREAD** | writes at `crates/state/src/docclass_executor.rs:300` and throughout; no execution-path reader | the inverse of DE-1..5: an append-only journal with no reader, which TS-10 then reduces to one row per block |

## Counts

137 rows, each carrying exactly one verdict. Cross-referenced rows are counted
once: PR-1 to PR-7 and PR-10 restate AU-20, AU-29, AU-17, AU-26, AU-12, AU-6,
AU-32 and AU-33 and are not counted twice; TS-12, PR-11 and PR-12 are the same
rows as DE-11, DE-9 and DE-8.

Two rows are reading-dependent, and they swap, so the totals are identical under
both readings of the release configuration:

| verdict | Reading A (live mainnet) | Reading B (committed `genesis.json`) |
|---|---|---|
| **REACHABLE** | **118** (117 + GATED-1) | **118** (117 + D-19a) |
| **GATED OFF** | **3** (JR-2, GATED-2, D-19a) | **3** (JR-2, GATED-2, GATED-1) |
| **UNREACHABLE** | **13** | **13** |
| **UNDETERMINED** | **3** | **3** |
| total | 137 | 137 |

**Blocking = REACHABLE + UNDETERMINED = 121 of 137, under both readings.** That
is the figure AT THE AUDIT; see the two corrections below, which take it to
120 and then to 114.

### The count after the remediation pass, derived rather than asserted

| | at the audit | after remediation | after the integration pass | after the census pass |
|---|---|---|---|---|
| REACHABLE | 118 | **118** | **117** | **111** |
| GATED OFF | 3 | **3** | **3** | **3** |
| UNREACHABLE | 13 | **13** | **13** | **15** |
| CLOSED | 0 | **0** | **1** | **5** |
| UNDETERMINED | 3 | **3** | **3** | **3** |
| **blocking (REACHABLE + UNDETERMINED)** | **121** | **121** | **120** | **114** |

The last column is the correction the integration pass owes this table. OC-2 was
CLOSED — `ImportRegisteredKeys` no longer has a reachable mutating shape — and
its row was marked closed without the count being moved. One row leaving
REACHABLE is one row leaving the blocking set, so the number after that pass is
120 and not 121. The census pass then took six more out, for 114; that
derivation is the section after this one.

Both figures were re-derived from the table rather than carried: excluding the
eleven cross-references named above leaves exactly 137 rows, of which 117 carry
a plain REACHABLE verdict today, one of the two reading-dependent rows is
REACHABLE under either reading, and three are UNDETERMINED. 117 + 1 + 3 = 121 at
the audit, when OC-2 was still among the 117; 120 now that it is not.

### The last column, derived the same way

Six rows moved in the census pass, and nothing else did. **Not one line of
executing code changed, so the behaviour a release-configured node ships is
byte-for-byte what it was**; what changed is which of it this document calls
release-blocking.

  * **AU-24 and AU-28: REACHABLE to UNREACHABLE.** Both name the branch body of
    `issuer.issuer_address != *sender` in `UpdateIssuer`. The read is at the
    sender's key; every write into either issuer family keys by the value's own
    `issuer_address` or by the address it just read; nothing rewrites that
    field; and `issuer_key` is injective. So no input reaches the branch, which
    is this document's own definition of UNREACHABLE. It is now held by
    `no_write_path_can_make_an_issuer_row_whose_key_is_not_its_own_address`,
    which fails if a route is ever added rather than restating today's paths.
  * **OV-4, OV-5, OV-7 and OV-8: REACHABLE to CLOSED.** Each had its stated
    CONSEQUENCE tested and withdrawn by an earlier pass, which then left them
    blocking on the rule "a withdrawn consequence is a finding, not a closure".
    That rule conflates two questions. A finding they remain: the rows are kept
    in place, in full, with the mechanism still pinned. Blocking they are not.
    The remedy field of all four reads "none, and none is wanted", and a row
    nobody should act on cannot be what a release is waiting for. Each now also
    names what its withdrawal test would catch if the row became a defect
    again, so the retirement is falsifiable rather than asserted.

Plain-REACHABLE therefore goes 116 to 110, and 110 + 1 reading-dependent row + 3
UNDETERMINED = 114. The verdict totals still sum to 137: 111 + 3 + 15 + 5 + 3.

**What did NOT move matters more than what did.** Nothing was retired for being
hard, narrow or unlikely. OV-4, OV-5 and OV-7 describe behaviour that is real,
permissionless, and happens on every revocation; they are retired because that
behaviour is the subsystem WORKING, evidenced by readers that depend on it, and
because the remedy the rows imply would introduce a worse defect than the one
they name. OV-8's first clause is still true and still recorded; only the clause
that made it a defect is gone. AU-24's and AU-28's comparisons stay in the
source, because an unreachable guard that would hold if the family were ever
written by something new is worth more than a tidy diff.

**Otherwise unchanged, and the reason is the whole point.** Thirty-five rows now carry a
remedy that is implemented, reachable through a named seam and covered by tests
that show an ungated node and a gated node disagreeing, and two more carry
half of one. Every one of those
remedies sits behind an activation height whose `ChainParams` field does not
exist, because `crates/genesis` belongs to another track. An absent
`#[serde(default)] Option<u64>` resolves to `None`; `None` closes the gate;
a closed gate means a release-configured node executes exactly the code it
executed before. Nothing became unreachable, so nothing stops blocking.

The arithmetic that WOULD move, stated so the next pass can check it: the
seventeen remediation fields now exist, so the remaining half of the
precondition is that they are SET to a height in the deployed runtime
`genesis.json`. When they are, forty-eight rows move from REACHABLE to GATED OFF
— the remediated behaviour becomes the behaviour — and the blocking count falls
from 114 to 66. (It was 120 to 72 before the census pass retired six rows;
the forty-eight that would move are unchanged, because none of the six is
among them.)

The forty-eight were re-derived from this table rather than carried forward, and
the figure has moved twice as later passes landed: thirty-five after the
remediation pass, forty-eight now that Class 4 bounded three allocation rows and
Class 8 closed ten. The rows that are both fully REMEDIED, PENDING ACTIVATION
and currently blocking are AL-9, AL-10, AL-11, AU-1, AU-2, AU-4, AU-5,
AU-13..AU-16, AU-19, AU-22, AU-23, AU-25, AU-27, AU-30, AU-31, AU-36,
BD-1..BD-6, OV-1, OV-2, OV-3, OV-12, OV-13, OV-14, OV-17, OV-18, OV-20, OV-26,
OV-28, OV-29 and TS-1..TS-11. That is forty-eight rows, none of them among the
two partial ones and none of them OC-2, which is closed rather than pending.
AU-3 and AU-34 do NOT move, because only part of each is remedied and the rest
is still reachable; a row is GATED OFF only when the whole of it is. Until the
fields land and an operator sets them the count is 114, and reporting 66 before
then would be the exact failure this document was written to prevent.

Six further rows are **BLOCKED, STRUCTURAL** (AU-9, AU-10, AU-11, AU-18, AU-21,
AU-32): no guard can close them, because the subsystem records no address, no
registry and no signature to authorize against. They need wire or registry
changes in `crates/sumchain-wire` and `ChainParams`, and they are REACHABLE and
blocking with or without the ten fields.

Only three rows in the entire inventory are decided by a gate, and only two of
those are gated under both readings. The eleven subsystems the blocker document
covers have no activation gate of any kind: there is no `nft_enabled_from_height`,
`docclass_…`, `healthcare_…`, `property_…`, `agreement_…`, `legal_…`,
`finance_…`, `employment_…`, `tax_…`, `messaging_…` or `policy_account_…` field
in `ChainParams` (`crates/genesis/src/lib.rs:191-600`), and no gate check in any
of their dispatch arms (`crates/state/src/executor.rs:494, 692, 755, 795, 868,
907, 943, 982, 1021, 1060, 1099`).

**That is the finding.** This release does not gate these subsystems off. It
ships them.

The remediation pass changes what is available, not what is shipped: twelve
activation gates now exist in the executors, dormant, each reading the
`ChainParams` field it names. Until an operator sets them, the
sentence above is still true word for word.

## Prioritised blocking list

REACHABLE and UNDETERMINED together, most severe first. Severity is ordered by
what one ordinary transaction costs the network, then by what it costs a person.

### Tier 1 — one cheap transaction, network-wide effect

  1. **BD-1 to BD-5, NFT block-level denial.** 21 `?`-propagated
     `StateError::BlockValidation` sites, no gate, `min_fee: 1000`. Any sender
     halts block production. BD-4 (undecodable payload) needs no prior state at
     all.
  2. **BD-6, DocClass subject-index collision.** A second block-denial vector
     from a different subsystem, armed by two transactions and detonated by a
     third, with the colliding key chosen freely by the attacker (AU-35).
  3. **OC-2, operator key import diverges consensus.** Not a transaction — a
     supported operator command that writes a family the executor reads, whose
     effect reaches the state root through receipts. **CLOSED**: the command
     refuses above genesis height and into a non-empty registry, and a node that
     seeded says so at every startup and on `chain_getSyncCapability`, with a
     digest of the set it was seeded from.

### Tier 2 — authorization absent where it is least tolerable

  4. **AU-1, `SupersedeConsent` checks nothing.** Complete bypass of the consent
     lifecycle; the replacement's subject, recipient, scope and issuer all come
     from the attacker's payload.
  5. **AU-2 + OV-18 + OV-19 + TS-8, prescriptions.** Anyone fills any
     prescription; a zero-refill `Active` prescription is filled once more; the
     controlled-substance guard covers one status value; and because the
     timestamp is zero, an expired prescription is fillable forever. Four
     reachable defects that compose into one.
  6. **AU-9 + AU-10, agreements.** Any sender signs on behalf of any party and
     carries a two-party agreement to `Executed` alone, and no signature is ever
     verified.
  7. **AU-33 + AU-35 + AU-36, DocClass identity.** No signature is verified
     anywhere; nothing binds a subject commitment to anybody; the revocation
     family never consults the registry.
  8. **AU-34, issuer self-elevation.** A suspended DocClass issuer restores
     itself to `Active` with one `UpdateIssuer`, and grants itself any subcode
     and any stake while it is there.
  9. **AU-18 + AU-21, self-registration as an authority.** A key generated a
     second ago registers as `TaxAuthority` or `CentralBank` and issues.
 10. **AU-3, the subject of a consent can neither grant nor revoke it.**
 11. **AU-11 + AU-13 + AU-14 + AU-15 + AU-16 + AU-30 + AU-31 + AU-4,** the
     remaining "any sender may" operations across agreement, legal, property and
     healthcare.
 12. **AU-23 + AU-27, revoked and suspended issuers keep control** of everything
     they ever issued, in finance and employment.

### Tier 3 — value destroyed or misreported

 13. **OV-26, the DocClass registration stake is destroyed.** Deducted from the
     sender, credited to nobody, never returned, and `UpdateIssuer` can raise
     the recorded figure afterwards without moving balance. Silent, unbounded
     supply destruction on a normal user action.
 14. **PR-1 to PR-10, nothing verifies any proof.** Seven `VerifyProof`
     operations that charge and succeed unconditionally, plus DocClass verifying
     no signature at all.
 15. **OV-9, the NFT receipt and the state disagree on every failed
     transaction** — the fee is taken and the receipt reports zero.
 16. **RY-1 to RY-3, royalties are recorded, publicly reported over RPC, and
     never paid**; and a royalty can never be changed after creation.
 17. **OV-10, `max_metadata_bytes` and `storage_fee_per_byte` are configured in
     the release genesis and bypassed on two of three write paths.**

### Tier 4 — attacker-controlled growth, unbounded cost

 18. **AL-13 (UNDETERMINED) and AL-1 to AL-12.** Thirty-plus accumulating
     structures, with the release ceiling at 1 GiB rather than the 4,096/8,192 B
     the measurements used. AL-10 is the worst: `CreateIdentityRoot` seeds a row
     from a single 2 MB payload, and every later `AddKey` re-decodes and
     re-encodes it.
 19. **AL-7, the property jurisdiction index key** is unvalidated payload UTF-8,
     so the attacker chooses the key width and the key count.
 20. **SC-1 to SC-7 and SC-8 (UNDETERMINED).** Fourteen unpaginated whole-family
     scans reachable from public RPC methods, on a server with authentication
     built and never wired in.
 21. **OC-1, the startup backfill** — an ungated full-family rewrite outside the
     candidate, proportional to an unbounded family, on every boot.

### Tier 5 — correctness, data loss, and reachable-but-narrow

 22. **TS-1 to TS-11**, every executor-written timestamp is zero, and **TS-10**
     and **TS-11**, where `tx_index = 0` reduces the DocClass event family, and a
     recipient's messaging inbox, to one row per block.
 23. **OV-23 + OV-24 + OV-25**, revocation is reversible, two revocations at one
     height are one row, and `UpdateCredential` writes nothing.
 24. **OV-1 to OV-3, OV-6, OV-11 to OV-17, OV-20 to OV-22, OV-27 to OV-30,
     CI-1, MD-1, MD-2, D-19b, JR-1, PA-1** — the remaining reachable rows.
     **OV-4, OV-5, OV-7 and OV-8 have left this list**, retired by the census
     pass: each had its stated consequence withdrawn and the withdrawal
     pinned, so none of them is what stands between this tree and a release.
     AU-24 and AU-28 were never in this list and are now UNREACHABLE.
 25. **CO-1**, the `contains`-not-`get` guards. Reachable, and the one row where
     **the fix is more dangerous than the defect**: upgrading it converts
     today's refusals into block-level errors of the Tier 1 class. It should be
     fixed only together with BD-1 to BD-6, never before them.
 26. **OC-3 (UNDETERMINED).**

## Every UNDETERMINED, and what would settle it

Three rows. Each blocks, and each names its missing evidence.

  * **AL-13 — that arbitrary input never reaches an allocator abort.** The eight
    measurements in the blocker document are each one point, taken at 4,096 or
    8,192 bytes; the release ceiling is `1 << 30`
    (`crates/state/src/executor.rs:269`). **What would settle it:** the maximum
    row size reachable under `max_block_bytes: 2000000` and a 1 GiB write-set
    ceiling; the 2× (index) and 3× (in-row) allocation factors these
    measurements already establish, applied to it; and a validator memory
    specification to compare against. The third number does not exist anywhere
    in this tree. The bincode measurement run for this audit closes the decode
    half (bounded at ~1 MiB per attempt) and not the row-growth half.
  * **SC-8 — whether the release RPC surface is publicly exposed.**
    Authentication is built (`crates/rpc/src/auth.rs`) and never called on the
    request path (`crates/rpc/src/server.rs:181, 296, 399`); the default bind is
    loopback (`crates/node/src/config.rs:201`). **What would settle it:** the
    deployed operator configuration — whether validators bind loopback behind a
    proxy or set `addr = "0.0.0.0:8545"`, which
    `crates/node/src/config.rs:380-385` shows is supported. Under loopback the
    fourteen scans are operator-facing; under a public bind they are an
    unauthenticated, unrate-limited denial surface.
  * **OC-3 — the rest of the designated out-of-consensus inventory.** The
    designated count is roughly seven operator, two genesis, one snapshot and
    three raw reorg sites. This worktree at `b6f4f6a` contains raw
    `put`/`delete` into `MESSAGING_*` in exactly two files
    (`crates/storage/src/messaging_store.rs`, 8; `crates/state/src/messaging_view.rs`,
    4) and exactly two non-test callers of any writing store method
    (`crates/node/src/node.rs:149`, `crates/node/src/main.rs:1082`).
    `crates/state/src/state.rs`, `crates/state/src/snapshot.rs` and
    `crates/consensus/src/` contain no `MESSAGING` reference at all. **What
    would settle it:** the tree, branch or commit the count of thirteen was
    taken against, or an enumeration of those sites with file and line. I am not
    willing to close the gap between two and thirteen by counting statements
    inside the store as call sites, so it stays open and it blocks.

## What in the blocker document could not be classified, and why

  * **The document is structurally damaged between lines 664 and 1058.** Three
    subsystem headings are present but their bodies are interleaved: `## Property`
    opens at line 664 and its `### Missing authorization and proof verification`
    is cut off mid-list at line 710; `## Healthcare` opens at 711 and its
    `### Unrestricted allocation from untrusted input` is cut off after five
    lines at 722; `## NFT` opens at 723, and the ~330 lines that follow are a
    mixture — the NFT block-denial section is genuinely NFT's, but lines 754-826
    are Healthcare's allocation and authorization content, 828-866 Property's,
    867-934 Healthcare's and Property's alternating, and 935-978 both again,
    before NFT's own fee-accounting section resumes at 980 with its measurement
    table missing a heading. One bullet ends mid-sentence at line 847
    ("`PropertyTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and").
    **Every bullet in that range was still classified**, attributed to its
    subsystem by its named pinning test and by the executor its subject matter
    names, and verified against source in each case. No bullet was dropped. But
    the attribution is this audit's reconstruction, not the document's, and the
    document should be repaired before it is relied on for anything else.
  * **PolicyAccount and messaging carry no deferred-defect inventory at all.**
    The blocker document says so and this audit confirms it: the only two items
    of substance are PA-1 (classified) and the messaging replay-guard property
    below. There is nothing else to classify there.
  * **The messaging replay-guard property** — "this dispatch arm does NOT advance
    the account nonce for most messaging operations; the messaging sender nonce
    is this subsystem's own replay guard" (`e293b03a`) — is **not classified**,
    because the source states it as a property that surprised its author and not
    as a defect, and this audit does not invent a defect in order to have
    something to classify. It is recorded here so its absence is deliberate. If
    it is meant as a defect claim, it needs one first.
  * **The three `sumchain-rpc` lib-test build sites** (`server.rs` 9805, 9906,
    10512), named by all six earlier commit messages as pre-existing, are a
    build-status item and fall in none of the seven audited classes. Not
    classified, and named here so the omission is visible.
  * **The 166 / 140 remaining committed manifest rows** and the "application
    journal gated on that reaching zero" measurements are migration-progress
    counts, not defects. Not classified.

## One observation outside the seven classes

Recorded because it bears on how every verdict above should be read, and because
no entry in the blocker document says it.
`compute_block_state_root` (`crates/state/src/executor.rs:3610-3687`) folds no
application column family into the block state root. Below the contracts, supply,
compute-pool and beacon gates it hashes only block header fields, receipt
outcomes and the previous root. So for all eleven subsystems, **what reaches
consensus is the receipt, not the row.** That is what makes JR-1 benign and OC-1
survivable; it is also why OC-2 is dangerous, since a divergent row changes a
receipt. It is not in the audited classes and is not counted, but a reader of
this table should know it.

## Appendix — where each remediation lives, and the test that governs it

Every row below is REACHABLE in the release configuration and stays blocking.
This table says only what exists in the tree to close it once its field lands.

| row(s) | change | test |
|---|---|---|
| BD-1..BD-5 | `NftExecutor::execute_with_gate` converts `BlockValidation` and `InsufficientBalance` into a `Failed` receipt at the entry boundary; every error site in `nft_executor.rs` fires strictly before its own function's first write, checked site by site, so nothing is half-applied. Storage and encoding errors are deliberately not converted | `an_absent_collection_aborts_the_block_below_the_gate_and_is_a_receipt_above_it`, `every_block_denial_shape_becomes_a_receipt_at_the_gate_and_only_at_the_gate`, `an_in_block_insufficient_balance_aborts_below_the_gate_and_advances_the_nonce_above_it`, `an_ungated_node_cannot_execute_the_block_a_gated_node_roots` |
| BD-6 | the identity subject index moves to a tagged 33-byte key no 32-byte legacy key can equal (`subject_identity_index_key`, `crates/storage/src/docclass_store.rs`); reads try the tagged key and fall back to the legacy one, so pre-activation rows are still found | `a_colliding_subject_commitment_ends_the_block_below_the_gate_and_is_harmless_above_it`, `an_identity_indexed_before_the_split_is_still_found_after_it` |
| OV-26 | the stake is credited to `docclass_stake_escrow_address()`, a keyless account derived the way `gov_escrow_address` is; `DeactivateIssuer` returns it exactly once; `UpdateIssuer` may no longer restate the recorded amount | `a_registration_stake_is_destroyed_below_the_gate_and_escrowed_above_it`, `deactivation_refunds_the_escrowed_stake_once_and_only_at_the_gate`, `an_update_cannot_inflate_the_recorded_stake_at_the_gate` |
| AU-1, AU-3 (revoke), AU-2, AU-4, AU-5, OV-18 | the Healthcare authorization rules, in `HealthcareGates` | `any_sender_can_supersede_any_consent_below_the_gate_and_none_can_above_it`, `the_issuer_may_still_supersede_but_cannot_move_the_subject_at_the_gate`, `the_subject_can_revoke_its_own_consent_only_at_the_gate`, `a_stranger_can_fill_any_prescription_below_the_gate_and_none_above_it`, `a_stranger_can_change_network_affiliations_only_below_the_gate`, `a_prescription_naming_another_issuers_prescriber_is_refused_only_at_the_gate`, `a_prescription_with_no_refills_is_filled_once_more_below_the_gate_only` |
| AU-13..AU-16 | the Legal authority checks, in `LegalGates`; supersession also requires the sender to issue the replacement and the replacement's id to be free | `consolidate_and_transfer_lose_their_authority_gap_at_the_gate`, `a_supersession_cannot_overwrite_another_live_order_at_the_gate`, `a_superseded_event_must_name_a_case_that_exists_at_the_gate` |
| AU-22, AU-23, AU-25 | the Finance issuer-standing rules, in `FinanceGates` | `a_suspended_finance_issuer_keeps_control_below_the_gate_and_loses_it_above`, `update_issuer_cannot_walk_around_reactivate_at_the_gate`, `submit_proof_requires_a_registered_active_issuer_at_the_gate` |
| AU-27 | the Employment issuer-standing rule, in `EmploymentGates` | `a_suspended_employment_issuer_loses_its_mutations_only_at_the_gate`, `an_active_employment_issuer_is_unaffected_by_the_standing_rule` |
| AU-30, AU-31 | the Property authority checks, in `PropertyGates` | `a_stranger_can_merge_assets_it_did_not_issue_only_below_the_gate`, `a_stranger_cannot_rewrite_a_title_history_at_the_gate` |
| AU-19 | the Tax claim-type authority check, in `TaxGates` | `the_claim_type_registry_is_writable_by_anyone_only_below_the_gate` |
| TS-1..TS-9, TS-10 (timestamp half) | every dispatch arm for the eight subsystems now passes `block.header.timestamp`, and each executor substitutes `0` while the gate is closed, through one shared `effective_block_timestamp` so the eight cannot drift apart | `prescription_validity_is_evaluated_at_time_zero_until_the_gate` (TS-8, both directions: expired-forever and never-fillable), `a_consent_revocation_stamps_a_real_time_only_at_the_gate`, and `every_status_update_records_a_zero_timestamp_through_dispatch`, whose discriminator moved from the call site to the gate |
| AU-36 | `check_revoke_auth` consults the issuer registry — the status question only, so an issuer whose authorization was narrowed can still withdraw what it validly issued | `a_suspended_issuer_keeps_the_revocation_family_only_below_the_gate` |
| TS-10 (`tx_index` half), TS-11 | `execute_tx_with_validators` and `execute_tx_v2` take the transaction's index; `execute_block` passes the same `idx` its receipts are built from; both arms reduce it once through `effective_tx_index`, which yields the literal `0` while `subsystem_tx_index_enabled_from_height` is closed. The Messaging arm additionally stopped passing `0` for the block timestamp and now reduces it through `effective_block_timestamp` like the other eight | `two_docclass_events_in_a_block_land_at_two_keys_at_the_gate` and `the_same_two_events_still_collide_below_the_gate` (the discriminator: REAL indices go in below the gate and one row still comes out), `execute_block_keys_each_docclass_event_by_its_own_transaction_index` (both directions, through a published block), `two_messages_to_one_recipient_in_a_block_land_at_two_keys_at_the_gate`, `the_same_two_messages_still_collide_below_the_gate`, `a_messaging_event_stamps_a_real_time_only_at_the_gate` |
| OV-1, OV-2, OV-3 | the Tax proof lifecycle, in `TaxGates::proof_lifecycle`. `IssueClaim` refuses a proof id already present (before the fee, like every other duplicate guard in the file); `RevokeClaim` resolves its 32-byte payload through `TAX_SUBJECT_INDEX`, which is what a subject nullifier is a key for, instead of handing it to a store keyed by proof id; `v_delete_subject_proofs` removes every proof the subject has AND the index row, so the deletion stops leaving a pointer to rows that are gone. `v_delete_proof` is untouched, so the closed gate writes exactly what it wrote | `issuing_a_claim_overwrites_an_existing_proof_only_below_the_gate`, `revocation_resolves_the_subject_and_clears_its_index_only_above_the_gate`; the two pinning tests `deleting_a_proof_leaves_the_subject_index_entry_behind` and `revoke_claim_keys_the_proof_store_by_nullifier` are unchanged and still pass, which is the dormant-side proof |
| OV-12, OV-13, OV-14 | the NFT token-authority rules, in the new `NftGates::token_authority`. `UpdateMetadata` requires the current OWNER (the creator is stamped at mint and never changes); both `Approve` and `UpdateMetadata` refuse a `locked` token; `Approve` reads the collection and refuses a non-transferable one, which is the guard `execute_transfer` already has. `NftGates` also carries the pre-existing receipt-failure decision, and `execute_with_gate` survives as a wrapper that leaves token authority closed, so every existing caller is bit-identical | `the_creator_rewrites_a_token_it_sold_only_below_the_gate`, `a_locked_token_is_approvable_and_rewritable_only_below_the_gate`, `an_approval_is_recorded_on_a_soulbound_token_only_below_the_gate`; the pinning tests `the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns`, `a_locked_token_can_still_be_approved_and_rewritten` and `approve_never_reads_the_collection` are unchanged and still pass |
| OV-28, OV-29 | the Agreement signature-integrity rules, in `AgreementGates::signature_integrity`. `SignAgreement` requires the signature's `party_ref` to hash to a party the agreement actually binds; `RevokeSignature` clears that party's `signed` flag and `signed_at` through the new `v_unmark_party_signed`, and walks an agreement back from `Executed` to `PendingSignatures` when it is no longer fully signed — reversing exactly the promotion `v_mark_party_signed` performs and no other status, so `Active`, `Terminated`, `Superseded` and `Voided` are not dragged backwards | `a_signature_from_a_stranger_to_the_agreement_is_stored_only_below_the_gate`, `revoking_a_signature_leaves_the_agreement_executed_only_below_the_gate`; the pinning test `a_signature_for_a_party_outside_the_agreement_is_still_recorded` is unchanged and still passes |
| OV-17, OV-20 | the Healthcare state preconditions, in `HealthcareGates::state_precondition`. `RenewMembership` refuses a `Suspended`, `Terminated` or `Cancelled` membership — the three statuses reached only by an explicit operation whose purpose is to stop the membership being active, and which renewal otherwise undoes while walking around `ReinstateMembership`, the operation that DOES carry a status guard. `v_remove_network_affiliation` and `v_remove_dependent` become the exact negation of their `contains`-guarded add mirrors: nothing to remove, nothing written, so a removal stops CREATING an empty index row at a plan the provider was never in | `a_terminated_membership_is_renewed_back_to_active_only_below_the_gate`, `removing_what_was_never_there_writes_a_row_only_below_the_gate`, and `an_active_membership_renews_under_either_gate` as the discriminator that the gate narrows renewal rather than disabling it; the pinning tests `renewing_a_terminated_membership_makes_it_active_again` and `removing_an_affiliation_that_was_never_there_still_stages_an_empty_index` are unchanged and still pass |
| AL-2, AL-4 (unbounded half) | the Employment and Finance accumulating-index bounds, in `EmploymentGates::row_limit` and `FinanceGates::row_limit`. Five Employment rows (`credential_indexes_within_bound`, `attestation_indexes_within_bound`) and four Finance rows (`index_row_within_bound`) are refused by their STORED LENGTH against `MAX_ACCUMULATING_ROW_BYTES`, before any decode and before `v_deduct`. No new field and no new constant: a fourth and fifth reader of `subsystem_allocation_bound_enabled_from_height` | `employment_employee_index_stops_growing_an_unbounded_accumulating_row` and eight more, `a_short_jurisdiction_code_naming_an_over_long_row_is_still_refused`, `an_open_gate_over_small_rows_refuses_nothing`, `a_corrupt_index_row_behaves_the_same_below_the_gate_and_is_length_refused_above` (`sumchain-state --test employment_finance_allocation_bound_gate`) |

### Rows this pass looked at and did not close

| row(s) | why |
|---|---|
| AU-9, AU-10, AU-11 | `AgreementCommitment` carries no address at all, and `PartyRef` is a 32-byte commitment or a 32-byte subject id. There is nothing in the subsystem to compare a sender to, so no guard can be written. Needs an `Address` on the commitment (or an address-bearing `PartyRef` variant) in `crates/sumchain-wire/src/agreement.rs`; AU-10 additionally needs a canonical signing input the subsystem does not define |
| AU-3 (grant half) | a consent's subject cannot participate in GRANTING without a signature `ConsentEnvelope` does not carry. The revocation half is remediated; the grant half is a wire change |
| AU-18, AU-21 | the tax and finance registries authorize nothing they do not take from the applicant, and no `ChainParams` field names a registrar for either. Inventing one inside an executor would be a rule nobody set |
| AU-32 | `PropertyProofEnvelope` carries no issuer address and Property has no issuer registry at all |
| AU-24, AU-28 | **NOW UNREACHABLE AND RETIRED; this entry is the history.** Dead checks, not holes: the row is fetched BY the sender key and registration forces the equality the comparison later tests, so neither can fire. Removing them would be tidier and would close nothing. **Re-tested rather than inherited, and the finding is unchanged with one refinement:** the comparison is live code that fires on a row no transaction can write, so "dead" means unreachable-by-any-input rather than eliminated, and the invariant that keeps it so is now asserted by `the_issuer_sender_check_fires_only_on_a_row_no_transaction_can_write` instead of being read off the source. Removing the checks would still close nothing, and would remove the only guard that holds if the family is ever written by something new. **The census pass then did the remaining half: unreachability PROVED rather than observed, by `no_write_path_can_make_an_issuer_row_whose_key_is_not_its_own_address`, which fails if a route is ever added. Both rows moved from REACHABLE to UNREACHABLE and left the blocking set; see their rows in Class 3.** |
| TS-12 | the dead `execute_tx_v2` arm, which was changed with the live one — a fix must change both, because `pub` means a future caller can appear. It took the `tx_index` parameter and the same `effective_tx_index` reduction as the live arm |
| Class 5 (PR-1..PR-8, = AU-6, AU-12, AU-17, AU-20, AU-26, AU-29, AU-32) | **BLOCKED, and looked at rather than skipped.** All seven `VerifyProof` arms are character-for-character the same three statements: deduct, credit, increment, return success. None reads a payload, because there is no wire type for a verification REQUEST — `data` is free bytes and no struct in `crates/sumchain-wire` describes what a `VerifyProof` payload contains. More to the point, **no proof verifier exists anywhere in this tree**: nothing consumes `proof_data` against `public_inputs`, in any subsystem. A presence check ("the named proof exists") could be added and would stop these succeeding for proofs that do not exist, but it would not verify anything, and shipping it under the name `VerifyProof` would invite exactly the misreading this class is about. It was left alone on that reasoning. **A later pass disagreed and closed the false-positive half behind `subsystem_proof_presence_enabled_from_height`, and the reasoning above is kept rather than deleted because the disagreement is the point.** The argument against was that a presence check does not make the sentence "verifies nothing" false; that is accepted and the six rows stay open on that half, which is why they are marked PARTLY REMEDIED and why the gate is named for PRESENCE rather than for verification. The argument for is that below the gate a `VerifyProof` receipt cannot be distinguished from a receipt for four bytes that are not a proof id, so a relying party reading receipts is told a proof verified for a proof the chain has never held -- and removing a false positive is worth doing even when the true positive is still absent. Defining the payload as the proof id is a CHOICE, recorded here as one and made the same way OV-2's payload reading was: `crates/sumchain-wire` declares no request type, so `data` is free bytes, and naming the proof is the only reading under which the operation names anything. PR-7 (= AU-32) is NOT in this: it is Property `SubmitProof`, which has no `VerifyProof` arm to gate, and it stays BLOCKED, STRUCTURAL for the reason its own row gives. **A THIRD pass disagreed with the second and retired the presence gate.** Both earlier paragraphs are kept rather than deleted, for the same reason the first was kept. The finding that decided it is the one the first paragraph already reached and the second did not act on: above the presence gate, a payload naming a proof the subsystem happens to hold still returned SUCCESS -- and a success receipt from an operation called `VerifyProof` IS "exactly the misreading this class is about", in the first paragraph's own words. Presence is not verification, so presence must not be reported as verification, and a gate that can still produce that receipt is a narrower false positive rather than a fix. So `subsystem_proof_unsupported_enabled_from_height` replaces it: at and above the height every arm returns a FAILED receipt saying the operation is UNSUPPORTED, for every payload, without consulting the proof family at all -- consulting it would put back the implication that a present proof was checked. The presence field, its accessor and its rows in every gate table survive, because deleting a declared `ChainParams` field would change the activation digest's field set for a gate no chain has ever opened; no execution path reads them, which `the_retired_presence_gate_decides_nothing` pins, so there are not two gates here disagreeing about what `VerifyProof` returns. **The "could a verifier be written instead" question was re-opened from source rather than inherited, and the answer is still no, on four independent grounds:** no proof system is in the workspace dependency graph -- the risc0/sp1 crates exist only under `tools/`, which the root `Cargo.toml` EXCLUDES precisely so it has no dependency edge into production; no verifying key, circuit or trusted-setup artefact exists in source, `configs/`, `genesis.json` or `deploy/` (`b0::verifier_material` holds labels, lengths and HASHES of material that lives elsewhere, and `ProductionProofEnvelopeV1` carries a `proof_artifact_digest` rather than proof bytes -- neither is reachable from `crates/state`); no verification-REQUEST type is declared anywhere, so a payload carries no expected public inputs to check against; and the `Groth16`/`Plonk` discriminants on the per-subsystem `ProofType` enums are matched on nowhere, while `proof_data` and `public_inputs` are read in exactly four non-test places, every one of which hashes them into an identifier. **And the seventh arm was found in the process:** `PropertyOperation::VerifyProof = 51` exists at `crates/state/src/property_executor.rs:1197`, is reachable, and is the arm PR-7 says is not there -- so the presence gate covered six of seven, and this one covers seven of seven |
| Class 4 (AL-1..AL-13), Class 6 (RY-1..RY-3) and the rest of Class 8 | untouched by this pass. They are ordered below Class 3 in severity and the pass ran out of runway before them, which is recorded here rather than left to be inferred from silence. AL-13 is the UNDETERMINED row remaining in these classes and remains so: it was not investigated, so it did not move. **Class 7 has since been closed by its own track** (SC-1..SC-7 bounded; SC-8 still UNDETERMINED and explicitly not moved) and has left this list |
| OV-7..OV-9, OV-11, OV-15, OV-16, OV-19, OV-21..OV-24, OV-27, CI-1, CO-1, MD-1, MD-2, PA-1 | untouched by the Class 8 pass that closed the ten rows above, and still untouched. (OV-6, OV-10, OV-25 and OV-30 have since been closed and have left this list; OV-11 and the transfer half of OV-22 are BLOCKED, STRUCTURAL in the row below.) The pass chose depth over breadth: four gates, ten rows, each with a mixed-version test that shows an ungated and a gated node disagreeing and a closed-gate test that reproduces today's behaviour exactly. Nothing about these rows changed, and none of them was investigated far enough to move a verdict |
| OV-22 (transfer half), OV-11 | **BLOCKED, STRUCTURAL.** `TransferAsset` moves no ownership because a Property asset row has no owner field to move — the fix is a wire change to `PropertyAsset`, not an executor change. `SetApprovalForAll` is unimplemented because operator approvals have no storage: there is no column family keyed by `(owner, operator)` anywhere in `crates/storage`, and inventing one behind an activation height would be a new state family rather than a behaviour change. Both were looked at and left, with the reason recorded rather than the row quietly skipped |
| Class 4 (AL-1..AL-13), Class 6 (RY-1..RY-3), Class 7 (SC-1..SC-8), and the rest of Class 8 | untouched by this pass. They are ordered below Class 3 in severity and the pass ran out of runway before them, which is recorded here rather than left to be inferred from silence. AL-13 and SC-8 are the two UNDETERMINED rows in these classes and remain so: neither was investigated, so neither moved |
| OV-7..OV-9, OV-11, OV-15, OV-16, OV-19, OV-21..OV-24, OV-27, CI-1, CO-1, MD-1, MD-2, PA-1 | untouched by the Class 8 pass that closed the ten rows above, and still untouched. (OV-6, OV-10, OV-25 and OV-30 have since been closed and have left this list; OV-11 and the transfer half of OV-22 are BLOCKED, STRUCTURAL in the row below.) The pass chose depth over breadth: four gates, ten rows, each with a mixed-version test that shows an ungated and a gated node disagreeing and a closed-gate test that reproduces today's behaviour exactly. Nothing about these rows changed, and none of them was investigated far enough to move a verdict. **A later NFT-and-Agreement pass has since moved five of them and left this list: OV-9, OV-15 and CI-1 are REMEDIED, PENDING ACTIVATION behind three new heights; OV-16's stated CONSEQUENCE was tested against source and withdrawn -- the mechanism it names does not hold, and the opposite one does; and OV-11 was re-tested rather than inherited and stays BLOCKED, STRUCTURAL with a second leg. AL-5 moved in the same pass, on the shared allocation-bound height. An Employment-and-Finance pass has since moved two more, both by OV-16's route rather than by a gate: OV-7's and OV-8's stated CONSEQUENCES were tested against source and WITHDRAWN, and the rows say what replaced them. **The census pass has since RETIRED both: OV-7 and OV-8 have left this list and the blocking set, because a row whose consequence is withdrawn and whose withdrawal is pinned by a test is a finding and not a blocker.** AL-2 and AL-4 moved in that pass on the shared allocation-bound height, which now has five readers. OV-19, OV-21..OV-24, OV-27, CO-1, MD-1, MD-2 and PA-1 are still untouched** |
| OV-22 (transfer half), OV-11 | **BLOCKED, STRUCTURAL.** `TransferAsset` moves no ownership because a Property asset row has no owner field to move — the fix is a wire change to `PropertyAsset`, not an executor change. `SetApprovalForAll` is unimplemented because operator approvals have no storage: there is no column family keyed by `(owner, operator)` anywhere in `crates/storage`, and inventing one behind an activation height would be a new state family rather than a behaviour change. Both were looked at and left, with the reason recorded rather than the row quietly skipped. **A later pass RE-TESTED the OV-11 half against source rather than inheriting it. The claim holds and gains a second leg: there is also no WIRE type — `crates/nft/src/ops.rs` declares no payload struct for the operation and nothing in `NftTxData` names an operator — so the arm has neither a place to write nor anything to write. The suggested alternative, making it REFUSE, was examined and rejected on the facts: it already returns a failure and changes no family, so there is no silent success to remove, and refusing EARLIER (ahead of `deduct_fee`) would make the one operation that can never succeed the cheapest transaction on the chain. The row carries the file:line evidence.** |
| OV-4, OV-5 | looked at and deliberately NOT closed. Both describe index entries that survive a revocation — but the credential and the attestation they name still EXIST; only their status changed. So the entry is not a dangling pointer the way OV-3's is, and removing it would be a decision about what the index MEANS ("all credentials ever issued" against "credentials still live"), which nothing in the subsystem or its specification states. Closing it would be inventing the semantics rather than restoring them, so the rows stay open and the reason is recorded here. **A later pass TESTED that reasoning instead of inheriting it, and half of it is wrong — which is why the original is kept rather than deleted.** The first half holds exactly: the entry is not a dangling pointer. The second half does not. The subsystem DOES state the meaning, in three places, and it states the OPPOSITE of removal: `summarize_by_employee` computes `employment_getSummary`'s `ended` count by walking the employee index, which a live-only index cannot produce at all; every index reader is paired with a filtering sibling and both halves reach the RPC as separate methods; and `UpdateEmployment` can restore an ended credential while no execution path ever re-adds an index entry, so removal would be irreversible. So the decision "stay open" was right and the reason given for it was not: the rows are now WITHDRAWN as defects rather than left open for want of a semantics. OV-7 is the same question in Finance and was answered the same way in the same pass, on `list_active` against `get_by_jurisdiction`. **The census pass then RETIRED all three, and OV-8 with them: a withdrawn consequence whose withdrawal is pinned by a test is not a blocker, and the previous pass's reason for keeping them -- "the way OV-16 does" -- was bookkeeping rather than evidence.** |
| PR-8, PR-9, and the remaining half of AU-26 and AU-29 | **OWNED ELSEWHERE, and deliberately not touched.** Every `VerifyProof` arm and every proof-family read in Employment and Finance belongs to a concurrent track, so the Employment-and-Finance pass left all four alone rather than write into a file another pass is holding. On the merits they would not have moved anyway: PR-8 and PR-9 say the proof families are read only through a `contains` that never decodes, which is the SAFE direction their own rows record, and the remaining half of AU-26 and AU-29 is that `VerifyProof` still verifies nothing — which needs a proof verifier, and there is none anywhere in this tree, in any subsystem. Reported rather than attempted |
| OV-2 (naming half) | the gated fix treats the payload's 32 bytes as the SUBJECT NULLIFIER the field is named for and resolves them through the index. The alternative reading — that the field is misnamed and the store is right — would have been a rename with no consensus effect and therefore no gate, and it would have left `TAX_SUBJECT_INDEX` with no way to be read by a revocation at all. The choice is recorded here because the source message that reported OV-2 named neither behaviour as intended |
