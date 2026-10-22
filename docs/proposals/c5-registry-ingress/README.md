# PROPOSED, NOT RATIFIED: C5 registry ingress (#242), byte specification

**This is a proposal for byte review. It is not a byte ratification, and nothing in it is frozen.** The owner decided Q3, Q8/Q18, Q9 and Q17 on 2026-10-22 (§14). The byte layouts stay PROPOSED until every C5 decision is settled. It specifies the dormant implementation in this pull request completely enough to be checked against the code and the vectors. Every value marked *fixture* or *synthetic* is a test value, not a proposed parameter.

- **Mechanism:** B of the C5 decision document. Governance-v1 operations 8 (register) and 9 (disable) inside `TxType::Governance = 23`. There is no new transaction type, no `RegistryWireOp` namespace, no new gate and no new receipt code (`Failed(418)` stays unallocated).
- **Not on the wire:** this PR does **not** add the two `GovernanceOperation` variants. A governance transaction naming 8 or 9 is refused at decode exactly as on the base, and a block holding one is rejected (§13). The codecs and the executor logic are reached only through `governance_executor::execute_registry_ingress`, which nothing but the tests calls. Adding the wire variants is part of the separately authorized activation change.
- **Authorization:** a quorum of the active PoA validator set at the execution height, verified by the existing `validator_quorum::verify_validator_quorum`. Register uses the authenticated governance threshold (Q17, decided). The register floor and disable's stored-record threshold are B2, PROPOSED and not owner-decided. `tx.from` only pays the fee.
- **State:** dormant and unwired. Even by direct call, both operations refuse with `302` before reading their payload: both named parameters are unset (§9), and nothing supplies a genesis block hash.
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
3. every approval's pubkey is in V. **An approval from a key outside V refuses the whole operation; it is not ignored** (Q15, resolved in group (b) of §14);
4. no pubkey repeats (already excluded by §3.4);
5. every signature verifies (§5);
6. k ≥ `required`, where k is the number of approvals and `required = ceil(n·t / 10000) = (n·t + 9999) div 10000`.

**The rule, verbatim (Q17, decided 2026-10-22).** Register reuses the existing governance rule unchanged:
- `required_approvals` (`crates/sumchain-wire/src/validator_authority.rs:119-123`):
  `let num = (active_count as u64) * (threshold_bps as u64); ((num + 9999) / 10000) as u32`.
- `verify_validator_quorum` (`crates/state/src/validator_quorum.rs:59-90`) applies it as listed above. `check_threshold_bps` is line 40; `required` is computed at line 70; `if valid < required` at line 86 refuses.

**Arithmetic:** computed in `u64`. With n ≤ `u32::MAX` and t ≤ 10000, `n·t + 9999 < 2^46`, so it cannot overflow, and `required ≤ n` fits in a `u32`. The comparison is `≥`. Validators that do not sign stay in the denominator. For t ≥ 1 and n ≥ 1, `required ≥ 1`. It equals the exact ceiling `⌈n·t / 10000⌉`; a test checks this in `u128`.

**Boundaries.** Each is tested (`quorum_arithmetic_at_its_boundaries`, `register_refuses_one_approval_short_and_accepts_exactly_required`, `the_largest_validator_set_counts_every_member`), and the `prospective_quorum.*` vectors record the counts:

| Case | n | t | required | k = required − 1 | k = required |
|---|---|---|---|---|---|
| smallest set | 1 | 1 or 10000 | 1 | refused (`303`) | accepted |
| four validators | 4 | 1 / 6667 / 10000 | 1 / 3 / 4 | refused | accepted |
| largest set (VS-6(a) cap) | 29,127 | 1 | 3 | refused | accepted |
| largest set | 29,127 | 10000 | 29,127 | refused (tested with k = 3) | n/a |
| type limit, no overflow | `u32::MAX` | 1 / 10000 | 429,497 / `u32::MAX` | arithmetic only | arithmetic only |
| t outside range | any | 0 or 10001 | not computed | refused (`InvalidThreshold`, `303`) | refused |

| n \ t | 1 | 3334 | 5000 | 5001 | 6667 | 10000 |
|---|---|---|---|---|---|---|
| 1 | 1 | 1 | 1 | 1 | 1 | 1 |
| 2 | 1 | 1 | 1 | 2 | 2 | 2 |
| 3 | 1 | 2 | 2 | 2 | 3 | 3 |
| 4 | 1 | 2 | 2 | 3 | 3 | 4 |
| 7 | 1 | 3 | 4 | 4 | 5 | 7 |

The set is the one **at execution**, not at signing. An approval from a validator that has since left refuses the operation (rule 3). The required count follows the current n.

## 7. Operation rules

Every check below is semantic: a refusal is `303`. It charges the fee and advances the nonce when the sender's balance covers the fee; otherwise it is `303` with fee 0 (Policy-B, `governance_executor.rs:353-363`, §10). Codes `300` (gate closed) and `301` (governance unconfigured) come first. The checks are independent, so their order changes no receipt. The implementation verifies signatures last.

### Register, executed at height h

Accepted only if **all** of these hold:

1. **Approval window:** `h ≤ valid_until` and `valid_until − h ≤ W` (§8, §9).
2. **Status:** `record.status = Enabled (0)`.
3. **Record threshold range:** `1 ≤ record.approval_threshold_bps ≤ 10000` (`check_threshold_bps`).
4. **Proof system:** `record.proof_system_id ∈ admitted_proof_systems()`, which is {2, RISC0}, fixed by B0-FINAL. `registry_dryRunAdmit` reads the same function.
4a. **Commitments set (Q9, decided 2026-10-22):** none of `audit_commitment`, `source_commitment` and `ceremony_commitment` is 32 zero bytes (`unset_commitments`). `registry_dryRunAdmit` refuses exactly the same names (`commitment_unset`), and a test checks that they agree.
5. **Timelock floor:** `activation_height ≥ h + T_min`, in exact arithmetic (§8).
6. **Threshold (Q17, decided 2026-10-22):** `t = GovernanceParams.validator_authority_threshold_bps`, the authenticated governance threshold from chain parameters. It is never taken from the operation or from a tooling default. **Floor (B2, PROPOSED, not owner-decided):** `record.approval_threshold_bps ≥ t`. Q17 decides only what t is.
7. **New id:** no record with `record.id` exists, Enabled or Disabled.
8. **Quorum:** §6 over the §4.1 preimage at threshold `t`.

On acceptance, the record is stored exactly as carried.

### Disable, executed at height h

Accepted only if **all** of these hold:

1. **Approval window:** as for register.
2. **Record:** the record `id` exists and is Enabled.
3. **Quorum (B2, PROPOSED, not owner-decided):** §6 over the §4.2 preimage at `t = stored.approval_threshold_bps`. Q17 covers register only. Neither threshold is ever read from the operation bytes.

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

`RegistryIngressParams` holds one `Option` per parameter. Execution obtains values only through `complete()`, which returns `None` unless both are `Some`. A missing value therefore cannot be defaulted on its way to execution. The binary's value is `REGISTRY_INGRESS_PARAMS = RegistryIngressParams::UNSET`, and no production code reads it.

| Parameter | Type | Read by | While unset |
|---|---|---|---|
| `registry_min_timelock_blocks` (T_min; #217 B6, #212) | `Option<u64>` | register rule 5 | both operations refuse `302` |
| `registry_max_approval_window` (W) | `Option<u64>` | rule 1 of both | both operations refuse `302` |

Two items left this set on 2026-10-22:
- **Q17** fixed register's threshold to the authenticated governance threshold, so there is no threshold-source parameter.
- **Q3** made the record default threshold a tooling-only default. No consensus path has or reads one, and `no_consensus_path_reads_a_tooling_default` checks that.

Where the values would live and how they would be committed is §14.1.

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
| all-zero commitment at register (Q9, rule 4a) | `Failed(303)` | charged if affordable (Policy-B) | +1 if charged | none: no record written |
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
- **Recommended placement (§14.1, part 3, not implemented):** `cf::STATE` under `registry/v1/` ‖ id, folded into the block state root behind the registry activation gate.
- **Undo:** rows are staged in the block's candidate. Where the generic application journal is active, it records their pre-images like any other row's.

## 13. Consequences and activation prerequisites

1. **This PR changes no decoding.** `GovernanceOperation` keeps exactly its eight variants (0 to 7). A governance transaction naming 8 or 9 fails to decode with the same error as on the base (`invalid value: integer 8, expected variant index 0 <= i < 8`), and a block holding one is rejected whole. Tests pin this for the payload, the signed transaction and the block (`governance_operations_8_and_9_do_not_decode`), for a synced `SyncResponse::Blocks`, and for `send_raw_transaction`, which leaves the mempool empty. An upgraded and a non-upgraded node therefore agree on every block.

   **Adding the two wire variants belongs to the activation change.** It is a coordinated, same-window upgrade: once a binary decodes operation 8 or 9, an earlier binary rejects any block that holds one. If an operation that refuses before semantics (`300`–`302`, no fee) could be included in a block, it would also take block space for free. The decision document does not state either point (Q14).
2. **Activation needs all of the following:**
   - the two `GovernanceOperation` variants and a dispatch to `execute_registry_ingress`, released as a coordinated upgrade;
   - governance-v1 activation with `ChainParams::governance`;
   - ratified values for both parameters;
   - their registration in the consensus configuration, under a new schema, because schema 2 is frozen (Q5, Q6);
   - the engines supplying the genesis block hash (Q7);
   - a release.

   None of this is done here.
3. **The validator signing tool must include the genesis hash and `valid_until`.**

## 14. Questions, consolidated

There are three groups: (a) settled by the decision ledger (`DECISION-RECORD-20261016.md`, including its appendix "2026-10-22 owner decisions") or by an owner instruction; (b) routine implementation choices, resolved in this PR; (c) protocol decisions still open, each with a recommendation. No resolution in (b) changes dormancy.

| Grp | Q | Resolution or recommendation | Consequence or citation |
|---|---|---|---|
| a | Q3 record default threshold | A tooling-only default. Removed from the parameter set and from every consensus path, which derives thresholds from authenticated state. | Owner 2026-10-22. Guarded by `no_consensus_path_reads_a_tooling_default`. |
| a | Q5 consensus-config registration | Schema 2 is fixed. New committed fields need an explicit schema-evolution proposal (§14.1). | Ledger G3, "Placement: CORRECTED", 2026-10-16 |
| a | Q8 commit consumers | Decided with the first proof consumer (#128). Until then nothing in production calls `v_check_commit`, `check_commit` or `execute_registry_ingress`. | Owner 2026-10-22. Guarded by `no_production_code_calls_the_commit_check_or_the_registry_entry`. |
| a | Q18 `id` derivation | Bound to Q8: the consumer checks that its verifier material derives to the record `id`. Register cannot, because the record does not carry the manifest hash. | Owner 2026-10-22 |
| a | Q9 all-zero commitments | Refused at register: `303`, fee charged per Policy-B, no state change (rule 4a, §10). The dry run refuses the same names. | Owner 2026-10-22. Tests `register_refuses_any_all_zero_commitment` and `registry_dry_run_agrees.rs`. |
| a | Q13 storage | The current dormant placement is `cf::META` under `registry/record/v1/` ‖ id, with no new column family and `ALL_CFS` equal to main's (tested). It is superseded if the §14.1 storage recommendation (STATE plus the fold) is adopted. | Settled by owner instruction plus precedent: the owner's 2026-10-21 instruction "Keep #348 dormant". The certificate-storage entries are precedent only: ledger 2026-10-19 (L508, "not authorized: a new storage column family") and 2026-10-20 (L540, versioned META keys, #337). |
| a | Q17 register threshold | The authenticated governance threshold, `validator_authority_threshold_bps`, under the existing rule verbatim (§6) | Owner 2026-10-22. Boundary tests and `prospective_quorum.*` vectors. |
| b | Q1 missing parameter | `302`, pre-semantic | Defensive only: the ledger's C5 note (2026-10-21) makes activation with a missing value impossible |
| b | Q2 expiry and window | `303`, fee charged | Height-dependent, like every other authorization refusal |
| b | Q7 genesis hash | The activation change supplies `create_genesis_block().hash()` (config field `0x0005`) | Refuses until then |
| b | Q10 dry-run activation check | Unchanged now; the activation change aligns `registry_dryRunAdmit` to `h + T_min` | Non-consensus RPC |
| b | Q11 bound on k | None beyond `u16` | The transaction size limit bounds k. No block may exceed `max_block_bytes`, so no includable payload exceeds it, and k < `max_block_bytes` / 96 (10,416 at the 1,000,000-byte default). Every approval must also be a distinct active validator, so a valid k ≤ n ≤ 29,127 (VS-6(a)). Entries are length-checked before allocation. |
| b | Q14 wire decoding | No wire variants. Decoding is unchanged and tested for the payload, transaction, block, sync response and RPC. | Adding the variants is the activation change, a coordinated same-window upgrade |
| b | Q15 departed approvals | The `verify_validator_quorum` rule named by the proposal: an approval from any key outside the execution-height set refuses the whole operation (`303`); it is not ignored | Submitters must drop departed approvals |
| b | Q16 approval order | Decode refusal (`302`) | The order is part of the §3 layout |
| c | Q4 signature rule | **Recommend:** keep governance-v1 `verify` (§14.1, part 1) | One rule for every governance quorum action. Under VS-5, `verify` and `verify_strict` accept the same signatures from real approvers. Condition: VS-5 is in effect on every node before activation. |
| c | Q6 where values live | **Recommend:** genesis `GovernanceParams` fields, as draft schema-3 entries `0x0609`/`0x060a`, in the range `1..=u32::MAX`, with no defaults, plus the present-only protocol-digest trailer (§14.1, part 2) | Every existing digest and commitment stays byte-identical; changing a value is a coordinated same-window upgrade |
| c | B2 thresholds | **Recommend:** keep B2. Register requires `record.approval_threshold_bps ≥` the governance threshold, and disable is authorized at the stored record's threshold. Both come from authenticated state (chain parameters and a quorum-registered record), as Q3 requires. | A record can demand more for its own disable than governance requires. Neither threshold is read from operation bytes or a tooling default. |
| c | Q12 committed digest | **Recommend:** move the records to `cf::STATE` under `registry/v1/` ‖ id, with a gated registry state fold after the beacon digest. `"state:registry"` joins the fast-sync families at activation (§14.1, part 3). | Roots stay byte-identical while dormant. Divergence becomes a root mismatch, and the registry fold byte table must be ratified. |

### 14.1 Recommendation (PROPOSED)

**PROPOSED.** Nothing here is ratified, and nothing beyond what this PR already contains is implemented. The parameters, signatures and storage parts stay unimplemented until the owner decides. The byte layouts stay PROPOSED until every C5 decision is settled. This section matches the sprint decision record `C5-RECOMMENDATION-20261022.md` (2026-10-22), which consolidates three inputs: the parameters analysis; the signatures and storage/digest analysis, read-only on `e3b8ff81` and this PR at `f9031df8`; and a cross-check of both, with its corrections applied.

Already directed by the owner on 2026-10-22, and implemented in this PR: Q3 (a tooling-only default), Q8/Q18 (decided with the first consumer, unreachable until then), Q9 (all-zero commitments refused, code 303) and Q17 (the governance threshold, with exact rounding).

#### The recommendation: one rule set

The three parts are one design. Register and disable verify approvals exactly as every other governance quorum action does. Their parameters live in the consensus configuration, and are bound across nodes once present. Their records are consensus state, committed in the block state root once activated. While dormant, every byte is identical to today.

##### 1. Signatures: keep governance-v1 `verify` for operations 8 and 9

Approvals go through `verify_validator_quorum` → `crypto::verify_bytes` → ed25519-dalek `verify`, which is not strict, exactly as for existing governance actions. Existing operations are unchanged.

Behaviour on malformed input:

| Input | Result |
|---|---|
| Wrong signature or key length | decode refusal **302**, no fee |
| Non-canonical S | **303**, fee charged*; `verify` and `verify_strict` both refuse |
| Non-canonical R | **303**, fee charged*; both refuse, because R is compared by encoding |
| Signature over the wrong message | **303**, fee charged* |
| Approver outside the execution-height set, or a duplicate approver | **303**, fee charged* |
| Small-order R or A | refused by `verify_strict` only |

\* Charged only when the balance covers the fee; otherwise the result is 303 with fee 0 (`governance_executor.rs:353-363`). Codes that come before these checks are unchanged: 300 when the gate is closed, 301 when governance is unconfigured (`:294-302`).

The small-order case does not matter for approvers. Under VS-5 (#338), every validator key is canonical and of prime order. A small-order R then verifies only by solving a discrete log, so for real approvers the two rules accept exactly the same signatures.

**Condition:** VS-5 genesis validation must be in effect on every node before the registry is activated. #338 enforces it at every node start.

**Consequence:** there is one quorum rule for every governance action. Moving governance to strict verification later is a single, governance-wide, coordinated change. Mixing rules now would split tooling and vectors for no security gain.

##### 2. Parameters: ConsensusConfig schema 3, no defaults, bound once present

- **Fields.** Two genesis `GovernanceParams` fields, placed as `validator_authority_threshold_bps` is: `registry_min_timelock_blocks` (T_min) and `registry_max_approval_window` (W). Each is `Option<u64>` with `#[serde(default)]` and **no default**. Absent means register and disable refuse (302). The Q3 record default is tooling-only, so it is not a consensus parameter.
- **Schema 3.** Schema 2 is frozen. The new fields are 0x0609 T_min (U64) and 0x060a W (U64), plus constants 0x2900–0x2904 (two domains, two magics, the schema version), present only while both values are set. Schema 3 is a **draft** until activation: `knows` includes it, `writes` stays schema 2, and absent draft fields are dropped by `project()`. Schema-2 records and commitments stay byte-identical.
- **Validation in `Genesis::validate`, and in the configuration build:**
  - both values are set, or neither;
  - **1 ≤ T_min ≤ u32::MAX and 1 ≤ W ≤ u32::MAX** (chosen in consolidation; the parameters analysis marked the cap optional). The cap catches misconfiguration and leaves no legitimate value out. It is checked at genesis load, with beacon `epoch_length ≥ 1` (`lib.rs:3701`) as the precedent; the fields stay `Ty::U64`, like 0x0604;
  - setting them without `governance_enabled_from_height` is refused;
  - a partial set is refused.
- **Arithmetic:** h + T_min is computed exactly (u128); a result above u64::MAX is 303. The window check is h ≤ valid_until and valid_until − h ≤ W, via `checked_sub`. Each failure is 303: fee charged, nonce + 1, no state change. T_min and W need no relation to each other, because they constrain different fields (activation_height and valid_until).
- **Binding: the gap, and the fix.** On `e3b8ff81`, the protocol digest covers `chain_id`, the genesis activation digest (validators, allocations, activation heights) and the compiled `consensus_limits`. **No GovernanceParams value is covered**, and neither is the genesis block hash. Today the only binding is each node's local configuration baseline plus operator acknowledgement, the same as for 0x0601. For existing governance actions this is tolerable, because their effects land in the state root. Registry effects do not land there today (see §3), so a T_min mismatch would split silently.
- **Recommended binding:**
  - **(a)** When **both** registry values are set, append one trailer to `protocol_digest_with_limits` that folds T_min, W **and the governance threshold that register uses (0x0601)**. The trigger is the registry values, never 0x0601 alone, so every existing digest stays byte-identical. It cannot go through `activation_heights()`, because an absent value still adds a byte (`lib.rs:4815`), nor through `consensus_limits()`, which holds compiled-in values only. Folding 0x0601 is safe: block validation never reads the digest, and governance reads the threshold directly.
  - **What (a) does and does not give** (cross-check, `peer_compat.rs:33-36`, `:234`; `node.rs:544/1128/1252`): a peer that **declares** a different digest is refused in both phases, meaning its blocks and votes are ignored; it is not disconnected. A binary that declares nothing is refused only from `peer_protocol_declaration_required_from_height`, which mainnet genesis does not set. So (a) catches misconfigured current binaries early, and (b) below is the guarantee.
  - **(b)** The registry state fold in §3 turns any remaining divergence into a state-root mismatch at the block where it occurs.
  - A configuration commitment in block headers would be stronger, but it is a header change beyond C5.
- **Upgrade:** activation is one coordinated same-window release. It carries the wire variants 8/9, schema 3 as `writes` with the schema and configuration acknowledgements, the values, the registry state fold and the dry-run alignment. Older binaries refuse the genesis (unknown fields) and op-8/9 blocks. Changing a value later is another coordinated same-window change, with acknowledgement and a changed digest. Records already accepted are unaffected, because T_min and W are checked only at register and disable.

##### 3. Storage and digest: consensus state, folded at activation

Three of the four requirements already hold for writes through `ExecutionView`:
- **(a) Historical execution:** execution happens only at the head, and import executes each block once. Reorg and rollback unwind, then re-execute forward. No state is served at past heights.
- **(b) Atomic commit:** `ExecutionView` writes, the block, receipts, journals and head pointer go out in one batch. That is stronger than #337's certificate seam.
- **(c) Rollback:** the operator rollback is the reorg unwind. It replays the generic journal, which holds pre-images for every family, so a record written at h is removed by a rollback below h.

The fourth is the gap:
- **(d) Consensus digest:** `compute_block_state_root` folds contracts, supply, compute-pool and beacon state behind their gates, but **not** the registry. Snapshots carry only `state:accounts`.

Recommendation:
- **Placement.** Move the records from META (node-local by convention) to the existing `cf::STATE` under `registry/v1/` ‖ id. There is still no new column family. The analysis confirmed that no production code scans all of STATE: the account root, snapshot export and legacy revert scan only the `acct` prefix, and the pruner reads STATE_DIFFS. The generic journal covers STATE rows. A test pins disjointness from `acct` and from G5's `vset/` prefix.
- **Fold.** Behind the registry activation gate, append after the beacon digest:
  `BLAKE3("SUMCHAIN/REGISTRY/STATE/v1\0" ‖ n ‖ (id ‖ record)* in ascending id)`.
  The integer encoding and record bytes go in the C5 byte table (PROPOSED). The cost is linear in the registry size, which is bounded by governance admission.
- **Fast sync.** Add `"state:registry"` to `REQUIRED_FAST_SYNC_FAMILIES`. Fast sync is already refused today, because snapshots carry only accounts. The entry does change visible output, though: the RPC `chain_getSyncCapability` missing list, the startup log and the restore error text. So it belongs to the **activation change**, not to dormant #348.
- **Consequence.** Roots stay byte-identical while dormant. Divergence becomes a root mismatch at the block, never a silent fork. There is one more digest byte table to ratify (Q12, now concrete).

#### What lands in #348 dormant if the owner accepts this, and what waits for activation

| Dormant in #348 (no active behaviour changes) | Activation change (coordinated, same window) |
|---|---|
| `#[serde(default)]` GovernanceParams fields and their validation; schema 3 as a draft (`knows` only) | Wire variants 8/9; `writes` = schema 3 plus acknowledgements |
| The present-only protocol-digest fold of T_min, W and 0x0601 | The values themselves; the registry activation gate |
| STATE placement `registry/v1/`; the gated registry state fold (gate unset) | The state fold enabled; `"state:registry"` in `REQUIRED_FAST_SYNC_FAMILIES`; snapshots carrying registry rows; dry-run alignment to h + T_min |
| Vectors labelled `prospective_*`; byte tables PROPOSED | VS-5 deployed on every validator (#338) |

#### Decision requested (one)

Adopt §1–§3 as the C5 design:
- governance-v1 `verify`;
- schema-3 optional parameters with no defaults, the range 1..=u32::MAX, and the present-only protocol-digest binding of T_min, W and 0x0601;
- STATE placement with the gated registry state fold.

#348 then implements the dormant column of the table above, and the C5 byte tables (record, approvals, registry fold) become the last C5 item for byte ratification.

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
| Q17 boundaries: arithmetic, k = required − 1 refused and k = required accepted, the largest set | `quorum_arithmetic_at_its_boundaries`, `register_refuses_one_approval_short_and_accepts_exactly_required`, `the_largest_validator_set_counts_every_member` |
| Q9: all-zero commitments refused, and the dry run agrees | `register_refuses_any_all_zero_commitment`, `crates/rpc/tests/registry_dry_run_agrees.rs` |
| Q3 and Q8 guards: no tooling default, no production caller | `no_consensus_path_reads_a_tooling_default`, `no_production_code_calls_the_commit_check_or_the_registry_entry` |
| `ALL_CFS` byte-identical to main; a record is one META row under its prefix; the prefix is disjoint from every META key | `the_column_families_are_exactly_mains`, `a_record_is_one_meta_row_under_its_prefix`, `the_record_prefix_is_disjoint_from_every_meta_key_in_the_repository` |
