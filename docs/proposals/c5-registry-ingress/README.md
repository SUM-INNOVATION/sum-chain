# PROPOSED, NOT RATIFIED: C5 registry ingress (#242), byte specification

**This is a proposal for byte review. It is not a byte ratification, and nothing in it is frozen.** It specifies the dormant implementation in this pull request completely enough to be checked against the code and the vectors. Every value marked *fixture* or *synthetic* is a test value, not a proposed parameter.

- **Mechanism:** B of the C5 decision document. Governance-v1 operations 8 (register) and 9 (disable) inside `TxType::Governance = 23`. There is no new transaction type, no `RegistryWireOp` namespace, no new gate and no new receipt code (`Failed(418)` stays unallocated).
- **Not on the wire:** this PR does **not** add the two `GovernanceOperation` variants. A governance transaction naming 8 or 9 is refused at decode exactly as on the base, and a block holding one is rejected (§13). The codecs and the executor logic are reached only through `governance_executor::execute_registry_ingress`, which nothing but the tests calls. Adding the wire variants is part of the separately authorized activation change.
- **Authorization:** a quorum of the active PoA validator set at the execution height, verified by the existing `validator_quorum::verify_validator_quorum`. The threshold source is B2 (§7). `tx.from` only pays the fee.
- **State:** dormant and unwired. Even by direct call, both operations refuse with `302` before reading their payload: all four named parameters are unset (§9), and nothing supplies a genesis block hash.
- **Refs:** #242, #128. Base: `main` `e3b8ff81`.

| File | Contents |
|---|---|
| `crates/sumchain-wire/src/registry_ingress.rs` | codecs, signing preimages, named-parameter type, height rules, commit-side check |
| `crates/state/src/registry_ingress.rs` | validation, record state, `REGISTRY_INGRESS_PARAMS` (UNSET) |
| `crates/state/src/governance_executor.rs` | `execute_registry_ingress`: the governance-v1 gate, parameters and Policy-B settlement for the two operations, reached by no transaction decode |
| `crates/state/tests/registry_ingress.rs` | executor tests and the vector check |
| `docs/proposals/c5-registry-ingress/vectors.txt` | synthetic vectors |

## 1. Conventions

- **Integers:** unsigned and little-endian everywhere in these payloads and preimages (D0). No frozen type used here says otherwise; `RegistryRecordV1` is little-endian too.
- **Byte strings** (MAGIC, domains, ids, pubkeys, hashes, signatures) are copied as they are, with no length prefix: every one has a fixed width.
- **Strict decoding:** a payload decodes only if every rule in §3 holds and it is consumed exactly. There are no optional fields, no defaults and no negotiation. Any failure is `302`.
- **Canonical encoding:** every accepted payload has exactly one encoding. Fixed widths, a fixed schema value, a status byte limited to 0 or 1, and strictly ascending approvals leave no freedom.

## 2. The transaction envelope

**Prospective.** This is the envelope the operations will use once the activation change adds their `GovernanceOperation` variants. On this binary, every such envelope is refused at decode (§13); the tests check this against the vectors.

It is the existing envelope: bincode 1.3.3 with its default (legacy) configuration, meaning fixed-width little-endian integers, a `u32` variant index for an enum, and a `u64` length before a `Vec<u8>`.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | `TxPayload` variant index, u32 | `23` (`Governance`) |
| 4 | 4 | `GovernanceOperation` variant index, u32 | `8` register, `9` disable |
| 8 | 8 | `data` length L, u64 | `173 + 96·k` or `51 + 96·k` |
| 16 | L | `data` | §3 |

The `prospective_governance_tx_data` vectors start at offset 4 of this table. **Correction to the decision document:** it describes `operation` as a `u8`. On the wire it is the bincode `u32` variant index; the Rust discriminant is a `u8`.

## 3. Operation payloads

### 3.1 `RegistryRegisterV1`: operation 8, 173 + 96·k bytes

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 7 | MAGIC | `52 52 47 52 76 31 00` (`"RRGRv1\0"`), else `302` |
| 7 | 2 | schema, u16 | must be `1`, else `302` |
| 9 | 8 | `valid_until`, u64 | any value at decode; §8 |
| 17 | 154 | `RegistryRecordV1` | frozen bytes, §3.3 |
| 171 | 2 | k, u16 | `0..=65535`; the entries must all be present |
| 173 | 96·k | approvals | §3.4 |

### 3.2 `RegistryDisableV1`: operation 9, 51 + 96·k bytes

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 7 | MAGIC | `52 44 49 53 76 31 00` (`"RDISv1\0"`), else `302` |
| 7 | 2 | schema, u16 | must be `1`, else `302` |
| 9 | 8 | `valid_until`, u64 | §8 |
| 17 | 32 | record `id` | any 32 bytes at decode |
| 49 | 2 | k, u16 | as in §3.1 |
| 51 | 96·k | approvals | §3.4 |

### 3.3 The embedded `RegistryRecordV1` (frozen, unchanged)

The offsets are relative to the record, then absolute within the register payload.

| Rel | Abs | Size | Field | Decode rule |
|---|---|---|---|---|
| 0 | 17 | 7 | MAGIC `"RREGv1\0"` (`52 52 45 47 76 31 00`) | else `302` |
| 7 | 24 | 2 | `schema_version`, u16 | must be `1`, else `302` |
| 9 | 26 | 32 | `id` | |
| 41 | 58 | 2 | `proof_system_id`, u16 | semantic, §7 |
| 43 | 60 | 32 | `audit_commitment` | |
| 75 | 92 | 32 | `source_commitment` | |
| 107 | 124 | 32 | `ceremony_commitment` | |
| 139 | 156 | 4 | `verifier_binary_version`, u32 | |
| 143 | 160 | 8 | `activation_height`, u64 | semantic, §8 |
| 151 | 168 | 1 | `status`, u8 | `0` Enabled or `1` Disabled, else `302`; register needs `0` (§7) |
| 152 | 169 | 2 | `approval_threshold_bps`, u16 | semantic, §7 |

### 3.4 Approvals

Each entry is 96 bytes: the approving validator's Ed25519 public key (32 bytes, a compressed Edwards point) followed by its signature (64 bytes, `R ‖ S` as in RFC 8032).

- Entries are in **strictly ascending order of pubkey**, compared as unsigned byte strings from byte 0 (`memcmp` order).
- A pubkey equal to the one before it is a duplicate and is refused. A smaller one is out of order and is refused. Both are decode failures (`302`): the order is part of the §2 layout of the decision document, whose §6 lists them with the other byte-level negatives (Q16).
- k = 0 decodes. No quorum can then be met, so the operation refuses with `303`.
- The decoder checks that all `96·k` bytes are present before allocating for them.
- k has no bound other than `u16` (open question Q11). Every approval must come from an active validator (§6), so a valid k never exceeds the active set's size.

### 3.5 Decode order

Decoding runs in this order: MAGIC, schema, `valid_until`, then the record (or `id`), then k, the presence of all entries, each entry with its order check, and finally the trailing-byte check. Every failure gives the same receipt (`302`, no fee), so the order only decides which error a client sees.

## 4. Signing preimages

Validators sign the preimage itself (PureEdDSA, no prehash).

### 4.1 Register: 232 bytes

| Offset | Size | Field |
|---|---|---|
| 0 | 30 | domain `"SUMCHAIN/REGISTRY/REGISTER/v1\0"` = `53554d434841494e2f52454749535452592f52454749535445522f763100` |
| 30 | 8 | `chain_id`, u64 |
| 38 | 32 | `genesis_block_hash` |
| 70 | 8 | `valid_until`, u64 |
| 78 | 154 | the record's canonical encoding (§3.3), byte for byte as carried at offset 17 |

### 4.2 Disable: 109 bytes

| Offset | Size | Field |
|---|---|---|
| 0 | 29 | domain `"SUMCHAIN/REGISTRY/DISABLE/v1\0"` = `53554d434841494e2f52454749535452592f44495341424c452f763100` |
| 29 | 8 | `chain_id`, u64 |
| 37 | 32 | `genesis_block_hash` |
| 69 | 8 | `valid_until`, u64 |
| 77 | 32 | `id` |

### 4.3 Notes on the preimages

- **`chain_id`** is the executing node's chain id, the same value transactions are checked against.
- **`genesis_block_hash`** is `Genesis::create_genesis_block().hash()`, the value the consensus configuration commits as field `0x0005`. `execute_registry_ingress` receives it in its `RegistryIngressContext`; nothing supplies it in production, and without it both operations refuse (open question Q7).
- **Domain separation:** both domains contain exactly one NUL, which is their last byte. The two domains, the registry KDF tags (`…/VK/v1\0`, `…/TOKENIZER/v1\0`, `…/GRAPHDEF/v1\0`) and the governance and settlement quorum domains (`SRC-GOV-VALQUORUM:…`, `OMNINODE-SETTLE-VALQUORUM:…`) are pairwise prefix-free. A test enforces this.
- **Fixed lengths:** each preimage has a fixed length and fixed field positions, so no two field assignments of one domain produce the same bytes.
- **Re-encoding:** the record's re-encoding equals the carried bytes because the codec is canonical (§1). The implementation re-encodes it.

## 5. Signature verification

This follows the governance-v1 convention. Approvals are verified by `verify_validator_quorum` → `sumchain_crypto::verify_bytes`:

1. The pubkey is parsed with `ed25519_dalek::VerifyingKey::from_bytes` (ed25519-dalek 2.2.0, without `legacy_compatibility`). A key that does not decompress fails.
2. The signature is checked with `Verifier::verify` over the §4 preimage. This is RFC 8032 verification as ed25519-dalek implements it. A non-canonical `S` (`S ≥ ℓ`) is refused; a test checks this with `S + ℓ`.
3. **This is not `verify_strict`.** The further refusals of `verify_strict`, such as small-order public keys and `R`, are not applied. Strict verification (E1) is the approved direction for *new finality and upgrade* signatures. Registry approvals reuse the governance-v1 quorum, so they keep its convention. Whether they should move to E1 is open question Q4. That would need a strict variant of the quorum check.

A failed verification refuses the operation (`303`). Nothing is partially counted.

## 6. Quorum and threshold arithmetic

The active set **V** is the list of validator pubkeys consensus supplies for the block being executed (`active_validator_pubkeys`). Under protocol v1 this is the static genesis set. Let n = |V| and let `t` be the threshold in basis points from §7. `verify_validator_quorum` accepts if and only if:

1. `1 ≤ t ≤ 10000`;
2. n ≥ 1;
3. every approval's pubkey is in V. **An approval from a key outside V refuses the whole operation; it is not ignored** (open question Q15 on the decision document's wording);
4. no pubkey repeats (already excluded by §3.4);
5. every signature verifies (§5);
6. k ≥ `required`, where k is the number of approvals and `required = ceil(n·t / 10000) = (n·t + 9999) div 10000`.

**Arithmetic:** it is computed in `u64`. With n < 2^32 and t ≤ 10000, `n·t + 9999 < 2^46`, so it cannot overflow, and `required ≤ n` fits in a `u32`. The comparison is `≥`. Validators that do not sign stay in the denominator. For t ≥ 1 and n ≥ 1, `required ≥ 1`.

| n \ t | 1 | 3334 | 5000 | 5001 | 6667 | 10000 |
|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| 2 | 1 | 1 | 1 | 2 | 2 | 2 |
| 3 | 1 | 2 | 2 | 2 | 3 | 3 |
| 4 | 1 | 2 | 2 | 3 | 3 | 4 |
| 7 | 1 | 3 | 4 | 4 | 5 | 7 |

The set is the one **at execution**, not at signing. An approval from a validator that has since left refuses the operation (rule 3). The required count follows the current n.

## 7. Operation rules

Every check below is semantic: a refusal is `303`, charges the fee and advances the nonce (Policy-B, §10). The checks are independent, so their order changes no receipt. The implementation verifies signatures last.

### Register, executed at height h

Accepted only if **all** of these hold:

1. **Approval window:** `h ≤ valid_until` and `valid_until − h ≤ W` (§8, §9).
2. **Status:** `record.status = Enabled (0)`.
3. **Record threshold range:** `1 ≤ record.approval_threshold_bps ≤ 10000` (`check_threshold_bps`).
4. **Proof system:** `record.proof_system_id ∈ admitted_proof_systems()`, which is {2, RISC0}, fixed by B0-FINAL. `registry_dryRunAdmit` reads the same function.
5. **Timelock floor:** `activation_height ≥ h + T_min`, in exact arithmetic (§8).
6. **Threshold source B2:** `t = GovernanceParams.validator_authority_threshold_bps` from chain state. Then `record.approval_threshold_bps ≥ t`.
7. **New id:** no record with `record.id` exists, Enabled or Disabled.
8. **Quorum:** §6 over the §4.1 preimage at threshold `t`.

On acceptance, the record is stored exactly as carried.

### Disable, executed at height h

Accepted only if **all** of these hold:

1. **Approval window:** as for register.
2. **Record:** the record `id` exists and is Enabled.
3. **Quorum:** §6 over the §4.2 preimage at `t = stored.approval_threshold_bps` (B2). Neither threshold is ever read from the operation bytes.

On acceptance, the stored record's `status` becomes Disabled; every other byte is unchanged. **Disabled is terminal:** there is no re-enable, and because the row remains, rule 7 refuses any later register of that `id`.

## 8. Heights: expiry, window, timelock and the commit side

- **Expiry:** refused if `h > valid_until`. `h = valid_until` is accepted.
- **Window:** refused if `valid_until − h > W`, computed only after `h ≤ valid_until` holds, so it cannot underflow. W is inclusive. `W = u64::MAX` would express "no bound".
- **Timelock:** `activation_height ≥ h + T_min` is evaluated in 128-bit arithmetic. If `h + T_min` exceeds `u64::MAX`, no `u64` activation height satisfies it, and the register refuses. `activation_height = h + T_min` is accepted.
- **Commit side (#128's runtime check):** a consumer referencing record `id` at height h is accepted only if:
  - the record exists;
  - it is Enabled;
  - `h ≥ activation_height`.

  Otherwise it is refused as `Unknown`, `Disabled` or `BeforeActivation`.

  The check reads registry state **at the consumer's own execution point**. A disable earlier in the same block applies to every later transaction of that block and to later blocks; earlier commits and rewards already paid are never touched. `v_check_commit` implements this. No consumer calls it yet (open question Q8).

## 9. Named parameters (unvalued)

`RegistryIngressParams` holds one `Option` per parameter. Execution obtains values only through `complete()`, which returns `None` unless all four are `Some`. A missing value therefore cannot be defaulted on its way to execution. The binary's value is `REGISTRY_INGRESS_PARAMS = RegistryIngressParams::UNSET`, and no production code reads it.

| Parameter | Type | Read by | While unset |
|---|---|---|---|
| `registry_min_timelock_blocks` (T_min; #217 B6, #212) | `Option<u64>` | register rule 5 | both operations refuse `302` |
| `registry_threshold_source` | `Option<RegistryThresholdSource>` | register rule 6, disable rule 3 | both operations refuse `302` |
| `registry_record_default_approval_threshold_bps` (#212) | `Option<u16>` | nothing (open question Q3) | both operations refuse `302` |
| `registry_max_approval_window` (W) | `Option<u64>` | rule 1 of both | both operations refuse `302` |

The threshold source has a single variant, `GovernanceThenRecord` (B2). B1 is not implemented. Setting the source accepts `GovernanceParams.validator_authority_threshold_bps` as the registry's register threshold, which answers the decision record's "value for registry use" (Q17).

The genesis block hash is a precondition of the same kind: without it, both operations refuse `302`.

## 10. Receipts and fee policy

No code is allocated. On this binary, a transaction naming operation 8 or 9 does not decode, so it has no receipt and a block holding it is rejected, as before. The table below is what `execute_registry_ingress` returns, and so what the operations would return once wired. The order is: gate, then governance parameters, then registry readiness, then decode, then the semantic rules.

| Condition | Status | Fee | Nonce | State |
|---|---|---|---|---|
| governance-v1 gate closed | `Failed(300)` | none | unchanged | none |
| `ChainParams::governance` absent | `Failed(301)` | none | unchanged | none |
| a named parameter unset, or no genesis block hash (Q1) | `Failed(302)` | none | unchanged | none |
| payload does not decode (§3) | `Failed(302)` | none | unchanged | none |
| any §7 refusal, including expiry and window (Q2) | `Failed(303)` | charged if affordable | +1 if charged | none |
| accepted | `Success` | charged | +1 | one `cf::META` row under `registry/record/v1/` |

## 11. Replay protection

| Threat | Rule |
|---|---|
| Another chain | `chain_id` and `genesis_block_hash` are both in the preimage. The genesis hash separates chains that share a `chain_id`. |
| Another operation | Distinct NUL-terminated domains, prefix-free against the registry KDF tags and every quorum domain (§4.3). Register approvals presented on a disable refuse (`303`), and the reverse. |
| The same operation again | State idempotency: a register is refused if the `id` exists; a disable is refused unless the record is Enabled; Disabled is terminal. A replayed operation never changes state. The outer account nonce refuses a verbatim transaction replay. |
| Stale approvals | `valid_until` is in the preimage and is checked against h, together with the window W. Membership and threshold are evaluated against the set at execution (§6). |
| Duplicate or unordered approvals | Decode refusal (`302`, §3.4) |

## 12. State

- **No new column family.** Records are versioned keys in the existing `cf::META`, as #337 stores certificates. `ALL_CFS` is byte-identical to `e3b8ff81`, and a test checks this. A family a binary does not name makes the volume unopenable by that binary, and the 0.2.0-era binary would auto-repair it to empty. Keys in an existing family carry no such hazard.
  - Key: `REGISTRY_RECORD_KEY_PREFIX` `"registry/record/v1/"` (19 bytes) ‖ `id` (32), 51 bytes. The `registry/` namespace is prefix-free with every META key in the repository; a test scans the source to check this, as #337's does.
  - Value: the 154-byte `RegistryRecordV1` encoding.
  - A stored row that does not decode, or names another `id`, is an error, never "no record".
- **No committed digest:** `cf::META` is not folded into any committed digest (Q12).
- **Undo:** rows are staged in the block's candidate. Where the generic application journal is active, it records their pre-images like any other row's.

## 13. Consequences and activation prerequisites

1. **This PR changes no decoding.** `GovernanceOperation` keeps exactly its eight variants (0 to 7). A governance transaction naming 8 or 9 fails to decode with the same error as on the base (`invalid value: integer 8, expected variant index 0 <= i < 8`), and a block holding one is rejected whole. Tests pin this for the payload, the signed transaction and the block (`governance_operations_8_and_9_do_not_decode`), for a synced `SyncResponse::Blocks`, and for `send_raw_transaction`, which leaves the mempool empty. An upgraded and a non-upgraded node therefore agree on every block.

   **Adding the two wire variants belongs to the activation change.** It is a coordinated, same-window upgrade: once a binary decodes operation 8 or 9, an earlier binary rejects any block that holds one. If an operation that refuses before semantics (`300`–`302`, no fee) could be included in a block, it would also take block space for free. The decision document does not state either point (Q14).
2. **Activation needs all of the following:**
   - the two `GovernanceOperation` variants and a dispatch to `execute_registry_ingress`, released as a coordinated upgrade;
   - governance-v1 activation with `ChainParams::governance`;
   - ratified values for all four parameters;
   - their registration in the consensus configuration, under a new schema, because schema 2 is frozen (Q5, Q6);
   - the engines supplying the genesis block hash (Q7);
   - a release.

   None of this is done here.
3. **The validator signing tool must include the genesis hash and `valid_until`.**

## 14. Questions, consolidated

There are three groups: (a) settled by the decision ledger (`DECISION-RECORD-20261016.md`); (b) routine implementation choices, resolved in this PR; (c) protocol decisions for ratification, each with a recommendation. No resolution in (b) changes dormancy.

| Grp | Q | Resolution or recommendation | Consequence or citation |
|---|---|---|---|
| a | Q5 consensus-config registration | Schema 2 is fixed. New committed fields need an explicit schema-evolution proposal, which belongs to the activation change. | Ledger G3, "Placement: CORRECTED", 2026-10-16 |
| a | Q13 storage | Versioned `cf::META` keys, no new column family. Applied: `registry/record/v1/` ‖ id; `ALL_CFS` equals main's (tested). | Ledger 2026-10-19 ("not authorized: a new storage column family") and 2026-10-20 (certificate storage direction, #337) |
| b | Q1 missing parameter | `302`, pre-semantic | Defensive only: the ledger's C5 note (2026-10-21) makes activation with a missing value impossible |
| b | Q2 expiry and window | `303`, fee charged | Height-dependent, like every other authorization refusal |
| b | Q7 genesis hash | The activation change supplies `create_genesis_block().hash()` (config field `0x0005`) | Refuses until then |
| b | Q10 dry-run activation check | Unchanged now; the activation change aligns `registry_dryRunAdmit` to `h + T_min` | Non-consensus RPC |
| b | Q11 bound on k | None beyond `u16` | Every approval must be a distinct active validator, so a valid k ≤ n ≤ 29,127 (VS-6(a)); entries are length-checked before allocation |
| b | Q14 wire decoding | No wire variants. Decoding is unchanged and tested for the payload, transaction, block, sync response and RPC. | Adding the variants is the activation change, a coordinated same-window upgrade |
| b | Q15 departed approvals | The `verify_validator_quorum` rule named by the proposal: the operation is refused | Submitters drop departed approvals |
| b | Q16 approval order | Decode refusal (`302`) | The order is part of the §3 layout |
| b | Q18 `id` derivation | No check | Not checkable: `vk_id` needs the manifest hash, which the record does not carry |
| c | Q3 record default threshold | **Recommend:** a tooling default, not consensus, removed from the activation-required set | Three values to ratify, not four. B2's floor (record ≥ governance) already bounds every record. |
| c | Q4 signature rule | **Recommend:** keep governance-v1 `verify` | One rule for every validator-quorum action. VS-5 already excludes small-order and non-canonical keys from the set. Moving governance to E1 later is one change covering all of them. |
| c | Q6 where values live | **Recommend:** `GovernanceParams` fields in genesis, registered by the Q5 proposal, like `validator_authority_threshold_bps` | The values are committed in the consensus configuration; changing them is a coordinated upgrade |
| c | Q8 commit consumers | **Recommend:** decide with the first proof-verifying consumer (#128). It calls `v_check_commit` and maps a refusal to its own existing invalid-input code. | No new code. Until then, nothing enforces the commit-side timelock. |
| c | Q9 all-zero commitments | **Recommend:** refuse at register (`303`), as `registry_dryRunAdmit` does under #217 B1 | Dry run and execution agree; one more register rule |
| c | Q12 committed digest | **Recommend:** fold registry rows into the block state digest at activation, as compute-pool and beacon state are, and carry them in snapshots | One more digest byte table to ratify. Divergent registry state then shows as a root mismatch, not a silent fork. |
| c | Q17 register threshold | **Recommend:** B2 as proposed (the governance threshold) | Registry admission moves with governance; a record can still require more for its own disable |

## 15. Vectors and tests

**`vectors.txt`.** Synthetic. Chain id 4242, genesis hash `0x47 × 32`, validator seeds `[i; 32]`, fixture governance threshold 6667, fixture `T_min = 10` and `W = 100`. It holds, for k = 1 and k = q(4) = 3:
- the record;
- both preimages;
- each payload, and its prospective `GovernanceTxData` and `TxPayload` envelopes (§2).

`vectors_are_reproduced_and_execute` regenerates the file and requires byte equality (comment lines excluded). It runs every payload through `execute_registry_ingress`: k = 1 against the active set {1}, and k = 3 against {1, 2, 3, 4}. Both must reach `Success`. It also requires every prospective envelope to fail decode on this binary.

**Tests.** The wire unit tests are in `crates/sumchain-wire/src/registry_ingress.rs`. The executor tests are in `crates/state/tests/registry_ingress.rs`. Each required case, with the test that checks it:

| Case | Test |
|---|---|
| Offsets and preimages against an independent construction | `register_offsets_…`, `disable_offsets_…`, `signing_preimages_…` |
| Wrong MAGIC or schema; register and disable bytes confused | `wrong_magic_schema_and_cross_operation_bytes_refused`, `undecodable_payloads_refuse_free` |
| Every truncation, trailing bytes, count larger than the entries | `every_truncation_…`, `a_count_larger_…` |
| Descending or duplicate approvals | `unordered_or_repeated_approvals_refused_both_ways`, `undecodable_payloads_refuse_free` |
| Domain confusion (each operation's approvals on the other) | `register_refusals`, `disable_refusals` |
| Stale `chain_id` or genesis hash | `register_refusals`, `disable_refusals` |
| Expired `valid_until`, window exceeded, and both boundaries accepted | `register_refusals`, `disable_refusals` |
| Departed validator approval | `an_approval_from_a_departed_validator_refuses_the_operation` |
| Below threshold, outsider, no approvals | `register_refusals`, `disable_refusals` |
| Pre-timelock register (`h + T_min − 1`) and the accepted boundary | `register_refusals` |
| Record threshold below the governance threshold; out of range | `register_refusals` |
| Disable at the stored record's threshold | `disable_is_authorized_at_the_stored_record_threshold` |
| Duplicate id; re-register after disable; disable twice; unknown id | `an_id_is_registered_once_and_never_again`, `disable_refusals` |
| Pre-timelock commit; disable-after semantics in one block | `commit_side_timelock_and_disable_after_semantics` |
| Each missing parameter; production defaults; gate and params first | `any_single_missing_named_parameter_refuses_free`, `production_defaults_refuse_…`, `governance_gate_and_params_still_come_first` |
| Non-canonical `S` | `signature_convention_refuses_a_non_canonical_s` |
| Operations 8 and 9 still refused at decode (payload, transaction, block), same error as on the base | `governance_fixtures.rs::governance_operations_8_and_9_do_not_decode`, `vectors_are_reproduced_and_execute` |
| The same through block sync (`SyncCodec::read_response`), with operation 7 as the control | `crates/p2p/tests/governance_ops_8_9_sync.rs` |
| `send_raw_transaction` refuses operations 8 and 9 at decode; the mempool stays empty | `crates/rpc/tests/governance_ops_8_9_rpc.rs` |
| `ALL_CFS` byte-identical to main; a record is one META row under its prefix; the prefix is disjoint from every META key | `the_column_families_are_exactly_mains`, `a_record_is_one_meta_row_under_its_prefix`, `the_record_prefix_is_disjoint_from_every_meta_key_in_the_repository` |
