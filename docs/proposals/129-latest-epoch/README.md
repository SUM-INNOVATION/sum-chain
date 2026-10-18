# PROPOSED AMENDMENT — not ratified; #129 text (union) unchanged

**#129 retention: the latest-epoch reading ("L") and its cross-repository prerequisites.**

This is a proposal for owner ratification. It does not change #129, which still says the replica count is "unioned across `file_epochs`".

Nothing here is implemented or activated, and nothing is consensus. The compute-pool gate stays refused at genesis load. The parts of #129 already ratified (2026-10-07) are restated, not changed:
- values are injected, with strict relational validation;
- relations 1–5 hold;
- activation is refused until the values exist.

Base: sum-chain `main` 2c275242. SNIP references are to `main` b4786c0b. OmniNode references are to `main` bcf6c019.

**Two labels are used throughout:**
- **LIMIT**: a committed value or a deterministic count that every node checks identically.
- **OBSERVATION**: a measured performance figure. It informs how a value is chosen. It is never a bound, never a consensus input, and no node measures it.

---

## 1. Definitions

| Symbol | Meaning |
|---|---|
| `F` | the file a tracker covers (by root) |
| `e_last(F)` | `F`'s latest assignment epoch: the last element of its epoch list (`assignment_height`, then each `ReassignChunksV2` height) |
| `S(e)` | the active-archive snapshot at height `e` (`v_get_active_archive_nodes_at_height`) |
| `assigned(c, S)` | the archives the deterministic assignment function gives chunk `c` over `S` with factor `R` |
| `bit(e, a, c)` | archive `a` attested chunk `c` in epoch `e`: the epoch-aware attestation bitmap that `AcceptAssignmentV2` writes for `e` |
| `R_job` | the job's snapshotted replication requirement |

## 2. Rules

### Counting
- **R-E1.** count(c) = |{ a : a ∈ assigned(c, S(e_last)), a is currently Active, bit(e_last, a, c) = 1 }|, de-duplicated by address.
  - Attestations from earlier epochs are not counted.
  - `coverage_ok(counts, R_job)` (`storage_metadata.rs:2711`) is unchanged, and already refuses `R_job = 0` and empty counts.
- **R-E2.** The dependency set is D(F) = every archive assigned at least one chunk of F under S(e_last). It is the `recomputed_dependencies` argument of `retention_tracker_dirty` (`compute_pool.rs:639`), so |D| ≤ R × chunk_count.
- **R-E3. A third Dirty clause.** A tracker is Dirty if the file's current `e_last` differs from the `e_last` recorded at the tracker's last recompute. This sits beside the two existing clauses:
  - a dependency's status generation changed;
  - the dependency set changed.
- **R-E4. E_max = 1.** A tracker is indexed under exactly one epoch, its `e_last`.
  - A reassignment moves the tracker's file and archive reverse-index entries to the new epoch in the same block.
  - The reverse index already refuses a tracker indexed under more epochs than its bound (`RetentionTrackerOutOfBounds{"indexed epochs"}`).
- **R-E5. Unchanged by this proposal:**
  - activation's union predicate (a file becomes Active on union coverage);
  - PoR targeting (latest epoch, `storage_metadata.rs:1190-1230`);
  - `reassignment_needed` (`:2902`);
  - `AcceptAssignmentV2` (latest epoch while the reassignment gate is open, `:1866-1876`).

  So a file can be Active without being retention-covered.

### `since` (coverage-satisfied-since)
- **R-S1.** Any event that makes a tracker Dirty forces the next recompute to set `since` afresh. Those events are:
  - a generation change;
  - a dependency-set change;
  - an `e_last` change.

  The recompute in block H sets `since := H` if `coverage_ok` holds at the recompute point, and `since := None` otherwise. An earlier `since` never survives.
- **R-S2.** Under the existing recompute bound (`RecomputeCursor::select`, `compute_pool.rs:1141`), the per-block recompute selects trackers that are Dirty **or** have `since = None`.
  - Selection is in tracker-key order, wraps, and takes at most `max_retention_updates_per_block` per block.
  - Overflow defers the rest; it never clears Dirty.
  - Without the `since = None` clause, a tracker that lacked coverage would never be revisited once attestations arrived.
- `RetentionSatisfied := not Dirty ∧ since.is_some() ∧ head ≥ since + output_availability_blocks` (`retention_satisfied`, `compute_pool.rs:611`). This is unchanged.

### Status generation (needed by the Dirty clauses)
- **R-G1.** A separate per-archive row, `generation(archive) → u64`. It is not a field of the node record, because changing the node record would change both node-row and snapshot-row encodings. An absent row reads as 0.
- **R-G2.** From the pool gate onwards, every step that changes an archive's stored status writes `gen + 1`, once per step. Overflow fails the transaction.
- **R-G3.** Below the pool gate nothing is written.
- **R-G4.** The rows are journal-reverted and uncommitted, like the #323 retention rows.
- The status rules that define "currently Active" are those in force at pool activation.

### Height
- **R-H1.** Consensus code takes no height argument. Counts and coverage read the executing block's state at the point of the read.
- **R-H2.** Recompute runs once per block, after the last transaction and before challenge generation.
- **R-H3.** Each consequential read evaluates Dirty at its own position.
- **R-H4.** `pool_getRetentionState(job)` answers at the committed head and returns the head's height and hash.

## 3. Model-test evidence

**Source:** sum-chain local branch `test/129-latest-epoch-model`, commit `1d6277644f543c5c5350195808a52e28d48edc34`, file `crates/state/tests/retention_latest_epoch_model.rs`.
- The file is headed "MODEL OF AN UNRATIFIED PROPOSAL", and it changes no production code.
- It runs over the dormant #319 kernels (`active_replica_counts_from`, `coverage_ok`, `retention_tracker_dirty`, `retention_satisfied`), the #129 reverse index and the cursor.
- Its run on 2026-10-16 gave 8 passed. It was not re-run for this document.

| Test | Shows |
|---|---|
| `l_full_coverage_in_first_epoch_matures_after_the_interval` | Coverage in the first epoch: `since` = 110; satisfied at exactly 110 + OAB. |
| `l_reassignment_drops_the_count_to_latest_epoch_attesters_and_dirties` | After a reassignment the counts are `[0,0,0,0]` although earlier holders still hold the chunks. The epoch clause alone makes the tracker Dirty. |
| `l_partial_reattest_is_not_coverage` | Counts `[2,1,1,2]` with R_job 2: `since` stays None. |
| `l_repair_restores_coverage_and_since_restarts` | Once the replacement attests, `since` = 240 (110 is not kept). A `since = None` tracker stays selectable with no Dirty event. |
| `l_since_never_carries_over_even_with_immediate_full_reattest` | Full re-attestation in the reassignment block gives `since` = 200, not 110. |
| `l_prime_counts_a_chunk_gc_deleted_while_assigned_away` | L′ counts 2 where only 1 archive holds the chunk; L counts 1. |
| `union_comparison_over_the_same_sequence` | U keeps `[2,1,1,2]` through the reassignment, but counts a stale bit from an archive moved off a chunk that deleted it (3 counted, 2 holders). |
| `l_indexes_one_epoch_union_needs_a_larger_epoch_bound` | With E_max = 1, L's re-indexing passes and U's two-epoch index is refused. |

### P5 readiness-window model
**Source:** this branch, `crates/state/tests/retention_p5_grace_model.rs`, headed "MODEL OF AN UNRATIFIED PROPOSAL".
- It changes no production code.
- It chooses no value of G. Each test runs over the test parameters G ∈ {1, 5, 20, 64}, and G = 0 where stated.
- The rule is evaluated over the canonical event log, so a reorg replaces a suffix of that log.

| Test | Pins |
|---|---|
| `p5_attesting_before_g_is_challengeable_from_the_attestation` | A newly assigned archive that attests at h < e + G is challengeable from h, and not before. |
| `p5_an_unattested_archive_becomes_challengeable_exactly_at_e_plus_g` | It is not challengeable at e + G − 1, and is challengeable at e + G and after. |
| `p5_g_zero_is_todays_behaviour` | With G = 0, every archive assigned under the latest epoch is a target at once, and an archive moved off the chunk is not. |
| `p5_an_archive_assigned_before_and_after_is_unaffected` | A continuing assignee has no gap at the reassignment. |
| `p5_a_reorg_across_the_boundary_recomputes_from_the_canonical_log` | Reorging away the reassignment removes the window. A reassignment at another height anchors the window there. |
| `p5_two_reassignments_in_a_row_restart_the_window` | An archive not yet challengeable when a second reassignment keeps it assigned gets a new window from the new epoch. One already challengeable stays so. |
| `p5_results_are_deterministic` | Identical challengeability traces on repeated runs, for each G. |
| `p5_window_ends_saturate_instead_of_wrapping` | At the edges of `u64` (test parameters G ∈ {0, 1, 2, 10⁶, u64::MAX − 1, u64::MAX}, and an epoch starting at u64::MAX − 3), e + G saturates: the window never ends early and evaluation never panics. |
| `p5_an_archive_reassigned_away_and_back_gets_a_fresh_window` | An archive moved off a chunk and later assigned it again is not ready: its earlier-epoch attestation does not carry over, so it waits for a new attestation or e + G. |
| `p5_readiness_is_per_chunk` | Attesting one newly assigned chunk does not open the window for another. |

**Mutation checks (2026-10-17).** Each was applied to the model, run, and reverted; each fails exactly the named test:
- e + G computed with wrapping instead of saturating addition: `p5_window_ends_saturate_instead_of_wrapping`;
- an attestation from any epoch counted: `p5_an_archive_reassigned_away_and_back_gets_a_fresh_window`;
- an attestation of any chunk counted: `p5_readiness_is_per_chunk`.

### Existing chain behaviour the proposal relies on
**Source:** this branch, `crates/state/tests/retention_p5_p7_chain_preconditions.rs`, headed as tests of existing chain code written for an unratified proposal.
- These run the real executor and the committed coverage reader. They change no production code and choose no value of G.
- The gates are the mainnet shape: reassignment open, both PoR targeting gates unset. Unbonding is opened only so an archive leaves by its own `BeginUnstake`.

| Test | Pins |
|---|---|
| `p7_the_coverage_flag_is_exactly_the_executors_acceptance_condition` | At every step, the coverage RPC's `reassignment_needed` equals whether the executor accepts the owner's `ReassignChunksV2` (otherwise it refuses with 334). The flag clears in the reassignment block itself, before the new assignee has attested, so an owner tool gated on it cannot submit twice. It returns when a later assignee leaves. |
| `p7_the_flag_is_set_by_any_snapshot_departure_not_only_the_files_assignees` | The departure of an archive holding no chunk of the file sets the flag, and the executor accepts the reassignment. The assignee is unchanged, but the new latest epoch has no attestation until it attests again. |
| `p5_below_the_targeting_gate_no_v2_file_is_challenged` | Gate unset: no challenge for a V2 file, either through the executor's interval or over 32 selection seeds, even right after a reassignment, so a readiness window would change nothing there. Gate open, same state: the unattested newcomer is the target at once (today's G = 0). |

**Mutation checks (2026-10-17).** Each was applied to production code, run, and reverted with `git checkout`:
- the coverage flag reading the first epoch's snapshot instead of the latest fails both `p7_` tests;
- the targeting gate forced open fails `p5_below_the_targeting_gate_no_v2_file_is_challenged`.

## 4. Comparison

| | L (proposed) | U (the #129 text) | L′ |
|---|---|---|---|
| Counts | attested in `e_last`, assigned in `e_last` | attested in any epoch, assigned in that epoch | assigned in `e_last`, attested in any epoch |
| Sound against real holders | yes (every counted archive is a current PoR target) | **no**: counts archives reassigned away, which are never challenged again and may have deleted the chunk | **no**: counts an archive reassigned away and back after deleting the chunk |
| Indexed epochs (E_max) | 1 | 1 + a reassignment bound (none is enforced for tracked files; `max_reassignments_per_file` feeds only the exposure formula) | 1 |
| Effect of a reassignment | count drops to new-epoch attesters; `since` restarts | count never drops | count keeps stale bits |
| Liveness cost | every reassignment needs the assigned archives to re-attest in the new epoch (§5) | lower | — |
| `since` across a reassignment | never carried | could be carried | — |

## 5. Cross-repository prerequisites

Under L, coverage after any reassignment depends on archives re-fetching and re-attesting in the new epoch. Today that lifecycle does not exist in SNIP. Each stage below is a cross-repository acceptance criterion that must hold before the pool gate opens.

### Current state

| Stage | sum-chain (chain side) | SNIP | OmniNode | Verdict |
|---|---|---|---|---|
| 1. Reassignment trigger | `ReassignChunksV2` is owner-only (code 332) and accepted only when a latest-epoch archive left the active set (`storage_metadata.rs:2902-2915, 2939-2990`). It is gated by `archive_reassignment_enabled_from_height` (`executor.rs:292-300`), dormant by default. There is an unsigned builder RPC, `storage_buildReassignChunksV2` (`rpc/src/api.rs:2339`). | No builder emits it (`sum-node/src/tx_builder.rs:972-994`). The owner tool tells the operator to invoke it externally (`ingest_v2.rs:927-949, 1197, 2116-2136`). The CLI says it is not implemented (`main.rs:1324-1341`). | No reference anywhere. | **Missing**: no SNIP or OmniNode submitter. On mainnet, the consensus configuration read on 2026-10-15 sets `archive_reassignment_enabled_from_height` to 8,900,000, so reassignment is live. |
| 2. Epoch discovery | Coverage RPC exposes `latest_assignment_epoch`, `reassignment_needed` and `per_epoch` (`storage_metadata.rs:570-575`). `getFileInfoV2.assignment_height` stays at the original epoch. | Decoded in `sum-types` but read by nothing outside tests. The archive learns file shape from `assignment_height` (`inbound_v2.rs:205-222`). No watcher exists. | — | **Missing**: an epoch watcher. |
| 3. Re-fetch | — | V2 chunks arrive only by owner Push (`inbound_v2.rs:9-12`).<br>• Pushes are validated against the epoch-0 snapshot (`push_validator.rs:321-338`). New tests show a replacement archive refuses its latest-epoch chunk (`NotInSnapshot` at epoch 0, the latest snapshot never consulted), and a survivor refuses a newly assigned chunk (`NotAssigned`).<br>• The owner tool pushes to the epoch-0 snapshot (`ingest_v2.rs:1446`, resume `:2070`).<br>• `market_sync` fetch is V1-only (`market_sync.rs:1-4, 117-160`).<br>• Downloads route to epoch-0 assignees (`download_v2_routing.rs:99`; `download_private.rs:572, 923`).<br>• There is no archive-to-archive V2 fetch. | — | **Missing**: latest-epoch push validation and routing, and an archive-driven V2 re-fetch. |
| 4. Re-attestation | `AcceptAssignmentV2` targets the latest reassignment epoch while the gate is open (`storage_metadata.rs:1866-1876`). It refuses a signer outside that epoch's snapshot (`:1912-1925`) and any index not assigned to it there (`:1945-1972`). | Attestation fires only on an owner ManifestPush (`inbound_v2.rs:14-20`), against the `assignment_height` snapshot (`:922`). The held set is in memory only; the resume is not implemented (`:22-29`). Tests show a replacement archive submits 0 attestations, and a survivor attests its epoch-0 set (indices the chain now refuses). | — | **Missing**: latest-epoch, watcher-triggered re-attestation, with the held set rebuilt from disk. |
| 5. PoR during the transition | Once the targeting gates are open, challenges go to latest-epoch assigned, currently Active archives (`storage_metadata.rs:1190-1230`; `executor.rs:4577-4606`). Expired challenges slash (`executor.rs:3445-3474, 4434-4520`). | The responder is automatic and epoch-agnostic. It answers only when the manifest and chunk are on disk (`por_worker.rs:98-200`). A newly assigned archive that never fetched the chunk cannot answer, so its challenge expires. | — | **Responder implemented; the transition is unsafe** without stage 3. On mainnet, the consensus configuration read on 2026-10-15 leaves `por_assignment_targeting_enabled_from_height` and `assignment_aware_por_scheduler_enabled_from_height` unset. |
| 6. GC | — | Requirements are in P6. Current V2 GC behaviour is under separate review. | — | **Open** (see P6). |

### Acceptance criteria (proposed; each needs tests in the named repository)
- **P1. Epoch watcher (SNIP).** An archive detects a change of `latest_assignment_epoch` for every non-Abandoned V2 file it holds, or is assigned chunks of, from committed chain state, within a bounded number of polls.
- **P2. Latest-epoch snapshot everywhere (SNIP).** Push validation, attestation and download routing evaluate assignment over S(e_last), not `assignment_height`. Tests:
  - the replacement archive accepts its latest-epoch chunk;
  - the survivor accepts its newly assigned chunk;
  - each refuses chunks no longer assigned to it.
- **P3. V2 re-fetch (SNIP).** A newly assigned archive obtains each missing chunk from a current holder (or the owner), verified against the chain Merkle root and chunk count, with no owner action.
- **P4. Re-attestation (SNIP).** After re-fetch, the archive submits `AcceptAssignmentV2` for exactly held ∩ assigned(c, S(e_last)). On restart it rebuilds the held set from disk and resumes.
- **P5. PoR-safe transition. Recommendation, awaiting ratification: a chain-side readiness window with G committed.**
  - Under the targeting gate, an archive that a reassignment newly assigns a chunk becomes challengeable for that chunk at the first height at which either:
    - it has attested the chunk in the latest epoch; or
    - `h ≥ e + G`, where e is the reassignment height.
  - Archives assigned the chunk both before and after the reassignment, and already challengeable, are unaffected. G = 0 is today's behaviour.
  - It is deterministic, and it uses only committed state.
  - **Alternative:** no chain change, relying on SNIP completing P3 within the PoR response window. Whether an honest archive is penalised would then depend on fetch timing.
  - **Cost:** it amends R-E5 ("PoR targeting unchanged") for newly assigned archives only. It also needs G as a committed field (§6).
  - **Condition:** this works without a new gate only if no network has set the targeting gate. On mainnet that gate is unset.
- **P6. V2-aware GC (SNIP).**
  - The retained set includes every chunk the archive is assigned under the latest epoch of every non-Abandoned V2 file.
  - When ownership or retention is uncertain, data is preserved.
  - This is coordinated with separate SNIP GC work.
- **P7. Reassignment submitter. Recommendation, awaiting ratification: the SNIP owner tool and OmniNode, using the existing owner-authorized builder.**
  - When `reassignment_needed` is true, the file owner's tool builds the transaction with the existing `storage_buildReassignChunksV2` RPC, signs it with the owner's existing key and submits `ReassignChunksV2`. For pool output files, OmniNode does this as their owner.
  - This needs no new signing authority and no consensus or schema change. The owner-only rule already applies on mainnet.
  - A SNIP change for the owner tool is being prepared.
  - **Deferred alternative:** automatic chain-side reassignment, or letting any account submit it once the chain's own condition holds. That needs a gated executor change and a per-block bound.
  - **Finding for this decision (tests in §3).** The chain's condition is snapshot-wide. `reassignment_needed` (`storage_metadata.rs:2902`) is set when any archive in the active snapshot at the file's latest epoch has left, not only an archive assigned a chunk of that file.
    - So, once any archive leaves, an owner tool gated on the flag submits a reassignment for every file whose latest snapshot included that archive, paying a fee per file even where no assignee left.
    - Under L, each such reassignment also restarts the file's count: its assignees, unchanged, must attest again in the new epoch before it counts as covered (and `since` restarts, R-S1).
    - Under P5 with the targeting gate open, those continuing assignees are already ready, so they get no window and stay challengeable. Only archives the reassignment newly assigns get one.
    - Options, for ratification with P7: accept this; have the tool also check that one of the file's own assignees left (a client-side filter, no chain change); or narrow the chain's condition (a gated executor change).
- **P8. Gate state (operations).** The mainnet state of the reassignment and PoR-targeting gates is confirmed before the pool gate opens.

## 6. B, T and G: an explicit schema-evolution proposal

### Finding: no existing approved encoding can carry B, T or G without changing its contract
- **Schema 2 is frozen** (`consensus_config/schema.rs:28-30, 255-262`: "never changes again"). `PRODUCTION` writes it (`:666-668`). Its ten added fields (#299) are:
  - `0x103f`, `0x1042`, `0x1040`;
  - `0x0720`;
  - `0x1041`, `0x0115`;
  - `0x2716`, `0x2717`;
  - `0x0116`;
  - `0x252a`.

  **This proposal does not amend schema 2.** Its registry is fixed by #299, and "unreleased" is not permission to change it.
- **`0x0720` `ComputePoolParamsV1` is fixed-width,** 321 B, with no optional, reserved or extension field (`sumchain-wire/src/compute_pool_params.rs:16-60`).
  - Its golden vectors are append-only.
  - Its upgrade rule is "a change is a V2 type with its own magic, schema version and activation height; V1 bytes are never reinterpreted" (`:81-85`).
  - Schema 2 registers it with `item_width = ComputePoolParamsV1::LEN`.
- **Schema 1 is frozen** (`schema.rs:6`).
- **A genesis-only, uncommitted input is ruled out by design.**
  - `compute_pool_retention_inputs.rs:34-40` declines to read the closest constant because doing so "would make it a genesis-validation input without a commitment".
  - `ChainParams` refuses unknown keys (#318).
  - `fields::build` destructures every parameter struct without `..`, so any new genesis key is a code change that must be classified.

### Proposal (for ratification; no number assumed)
- **Schema.** A later schema, its number allocated at ratification, extends the newest schema with an append-only list of three `AddedField`s. `PRODUCTION` knows it as a draft (start is refused while any of its fields is non-absent) until a reviewed release writes it.
- **Fields.** Three scalar parameters in the `0x0100–0x01ff` range. **Their ids are allocated at ratification;** this proposal reserves none.

| Field | Genesis key | Type | Meaning |
|---|---|---|---|
| B | `retention_per_block_budget_ns` | `Ty::U64`, optional, `Source::Param` | the per-block recompute budget, ns |
| T | `retention_t_recompute_bound_ns` | `Ty::U64`, optional, `Source::Param` | the ratified per-recompute bound, ns |
| G | `por_reassignment_readiness_blocks` | `Ty::U64`, optional, `Source::Param` | P5's readiness window, in blocks |

- **Naming.** No name ends in `_from_height`, so none is an activation gate. The activation digest and the protocol digest (gates plus compiled limits; `crates/genesis/tests/activation_digest.rs` selects `*_from_height` `Option<u64>` fields) do not change, and nor does the peer handshake.
- **Value rules,** checked on every configuration built or decoded in that schema, like `check_metering_relations`:
  - B and T are both present or both absent;
  - present only while `0x0720` is present;
  - each ≥ 1;
  - relation 3: `(max_retention_updates_per_block as u128) × (T as u128) ≤ (B as u128)`, where `max_retention_updates_per_block` is read from `0x0720`. A u64 × u64 product cannot overflow u128, so this is exact. For whole-number m it is equivalent to m ≤ ⌊B/T⌋.
  - **G:**
    - it may be present only while `por_assignment_targeting_enabled_from_height` is declared;
    - when present, G ≥ 1 (absence means G = 0, today's behaviour, so the same behaviour has one encoding);
    - pool activation is refused while G is absent. This presence rule is part of the ratification choice; the alternative is to allow pool activation with G absent, meaning 0.
- **Genesis and activation.** `compute_pool_retention_inputs` sources `PerBlockBudgetNs` from B, and the renamed `TRecomputeBoundNs` from T. The targeting path reads G from the committed configuration at the executing block.
  - Relation 3 is checked at genesis validation whenever both are declared.
  - Activation is refused while either is absent, as today.
  - Execution enforces only the count, through `RecomputeCursor::select`. **No node measures time.**
- **Census.**
  - The three new `ChainParams` fields are classified as COMMITTED through the new schema's `AddedField`s. No exclusion row is needed.
  - `consensus_config_census.rs` gains nothing to exclude.
  - `consensus_constants_census.tsv` is unaffected unless L's single-epoch rule is introduced as a named compiled constant. In that case it needs a row (COMMITTED in `0x2100–0x2fff` under the same schema), or the rule stays structural with no constant.
  - The B0 aggregate-verify constant stays uncommitted and unread.
- **Migration and compatibility.**
  - An existing schema-1 or schema-2 record is carried forward by the stopped-node `acknowledge-consensus-config-schema`, which changes no rule: absent fields mean pre-field behaviour.
  - No state rows and no database migration beyond that record.
  - A chain that declares no `compute_pool_params` and no targeting gate (mainnet today) keeps all three fields absent, so its behaviour is unchanged.
  - Older binaries refuse a genesis that names the new keys (fail-closed).
  - Other draft schemas may claim numbers, so the number is allocated at ratification.
- **Why commit B, T and G.** G changes which archives are challengeable, which is a validity-relevant outcome, so every node must read the same value. Ratified relation 3 is part of the activation condition of a committed gate. Committing B and T makes every node validate the same relation over the same declared values. The alternative, classifying them as excluded genesis-only inputs, contradicts the inclusion rule's intent for activation-gating values and is not recommended.

### Derived values (no field)
- **R_max** := `assignment_replication_factor` (`0x010c`, already committed). Changing it while the pool gate is set is refused.
- **E_max** := 1, by rule R-E4.
- **C_ret** := ⌊(⌊M/F⌋ − 1 − E_max) / (E_max × R_max)⌋, where M = `max_reverse_index_entries` and F = `max_retention_files_per_job`. Activation is refused if C_ret < 1. Relation 4 in its sound form, M ≥ F × (1 + E_max × (1 + R_max × C_ret)), then holds by construction.

## 7. Limits and observations

**LIMITS** (committed or deterministic, identical on every node):
- `max_retention_updates_per_block`;
- `output_availability_blocks`;
- `max_retention_files_per_job`;
- `max_reverse_index_entries`;
- `finality_depth`;
- B;
- T;
- G;
- `assignment_replication_factor` (= R_max);
- E_max = 1;
- C_ret (derived);
- the cursor's per-block selection count.

**OBSERVATIONS** (inform the choice of values only; never read by a node; not guaranteed bounds):
- the measured `t_recompute` p99 on reference hardware, which is still to be measured;
- any per-block or per-call millisecond figure;
- observed re-fetch times for a newly assigned archive;
- block-interval figures used to translate `output_availability_blocks` into wall time (for example, 200 blocks at an observed 1.5 s interval is about 5 min).

T is chosen as a committed value at or above the observed p99. G is chosen as a committed value at or above the observed re-fetch time plus a margin.

Choosing either is a ratification act that is informed by observations; no node measures anything in consensus.

## 8. What this proposal does not decide
- The values of `output_availability_blocks`, F, M, B, T and G.
- The bytes of the status-generation row and the retention namespace (decided with the C-series layouts).
- Ratification of the P5 and P7 recommendations (§5). Both await the owner.
- Activation of anything.
