# PROPOSED, NOT RATIFIED: C5 registry ingress (#242), byte specification

**This is a proposal for byte review. It is not a byte ratification, and nothing in it is frozen.** The owner decided Q3, Q8/Q18, Q9 and Q17 on 2026-10-22. On 2026-10-23 the owner decided four more points, and replaced the handshake binding with the activation proposal in §16 (§14):
- strict verification for operations 8 and 9;
- the parameter structure;
- STATE storage;
- B2.

The byte layouts stay PROPOSED until every C5 decision is settled. It specifies the dormant implementation in this pull request completely enough to be checked against the code and the vectors. Every value marked *fixture* or *synthetic* is a test value, not a proposed parameter.

- **Mechanism:** B of the C5 decision document. Governance-v1 operations 8 (register) and 9 (disable) inside `TxType::Governance = 23`. There is no new transaction type, no `RegistryWireOp` namespace, no new gate and no new receipt code (`Failed(418)` stays unallocated).
- **Not on the wire:** this PR does **not** add the two `GovernanceOperation` variants. A governance transaction naming 8 or 9 is refused at decode exactly as on the base, and a block holding one is rejected (§13). The codecs and the executor logic are reached only through `governance_executor::execute_registry_ingress`, which nothing but the tests calls. Adding the wire variants is part of the separately authorized activation change.
- **Authorization:** a quorum of the active PoA validator set at the execution height, verified **strictly** by `validator_quorum::verify_validator_quorum_strict` (§5). Register uses the authenticated governance threshold (Q17). Disable uses the stored record's threshold (B2, adopted 2026-10-23). `tx.from` only pays the fee.
- **State:** dormant and unwired. Even by direct call, both operations refuse with `302` before reading their payload: both named parameters are unset (§9), and nothing supplies a genesis block hash. Records live in `cf::STATE` under `registry/v1/` (§12).
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

## 5. Signature verification (strict, owner 2026-10-23)

Operations 8 and 9 verify every approval with **`verify_strict`**. Every existing governance and settlement quorum action keeps governance-v1 `verify`, unchanged.

**The strict path reuses existing, reviewed machinery.** `verify_validator_quorum_strict` (`state/src/validator_quorum.rs`) is the existing quorum rule with one difference: its signature check is `sumchain_crypto::verify_bytes_strict`. That function parses the key with `ed25519_dalek::VerifyingKey::from_bytes` and calls `VerifyingKey::verify_strict` (ed25519-dalek 2.2.0, `legacy_compatibility` off). It is the same call as:
- the ratified E1 path: `finality_foundations::vote::verify_e1`, `finality-foundations/src/vote.rs:277-280`;
- the strict inner-signature checks: `primitives/src/messaging_sponsored.rs:61` and `primitives/src/inference_attestation.rs:45`.

It is a thin wrapper in `crypto`, not new cryptography, because `state` does not depend on `finality-foundations` and should not. The existing `verify_validator_quorum` keeps `verify_bytes`, and both share one private rule (`quorum_with`).

**What the two rules compute** (ed25519-dalek 2.2.0 source):
- `verify` (`verifying.rs:201-217`) decodes `S` canonically (`signature.rs:91-96`) and recomputes `R' = [k](−A) + [s]B`. It accepts iff `compress(R')` equals the signature's `R` bytes.
- `verify_strict` (`verifying.rs:357-380`) additionally refuses when R does not decompress, or when R or A is a small-order point.

**Correction.** The earlier comparison claimed VS-5 makes the two rules agree for real approvers. VS-5 validates public keys, not a signature's R. A key holder can sign with R = identity and s = k·a mod ℓ (where a is the secret scalar). Then `[s]B − [k]A` is the identity, so `verify` accepts. `verify_strict` refuses, because the identity is small-order. So the rules differ even for honest, canonical, prime-order keys. Any other small-order R cannot satisfy the equation with a prime-order A: `[s]B − [k]A` lies in the prime-order subgroup, whose only small-order element is the identity.

| Signature or key | governance-v1 `verify` | `verify_strict` (ops 8, 9) | Through the registry entry |
|---|---|---|---|
| ordinary signature | accepts | accepts | `Success` |
| R = identity, s = k·a (real key holder, canonical prime-order key) | **accepts** | refuses | `303` |
| any other small-order R, prime-order A | refuses (cannot satisfy the equation) | refuses | `303` |
| small-order A (outside VS-5), R = [s]B, any message | **accepts** | refuses | `303` |
| non-canonical S (S + ℓ) | refuses | refuses | `303` |
| non-canonical R (y = p + 1 for the identity) | refuses (R is compared by encoding) | refuses | `303` |
| wrong message | refuses | refuses | `303` |
| public key that does not decompress | refuses | refuses | `303` |
| truncated approval (wrong length) | not reached | not reached | `302` at decode, no fee |

Every row is tested: `the_two_rules_on_each_distinguishing_signature` (both rules) and `operations_8_and_9_refuse_approvals_only_the_old_rule_accepts` (receipts). `existing_governance_operations_keep_the_governance_v1_rule` pins that `RegisterAsset` still accepts the identity-R approval. The vector `prospective_strict_refused.identity_r.register.k1.data` executes as `303`.

**Receipts:** a refused signature is `303`. The fee is charged and the nonce advanced when the balance covers the fee; otherwise it is `303` with fee 0, the nonce unchanged and no state change. Codes `300` (gate closed) and `301` (governance unconfigured) come first, and a malformed encoding is `302` with no fee (§10). Nothing is partially counted.

## 6. Quorum and threshold arithmetic

The active set **V** is the list of validator pubkeys consensus supplies for the block being executed (`active_validator_pubkeys`). Under protocol v1 this is the static genesis set. Let n = |V| and let `t` be the threshold in basis points from §7. `verify_validator_quorum` accepts if and only if:

1. `1 ≤ t ≤ 10000`;
2. n ≥ 1;
3. every approval's pubkey is in V. **An approval from a key outside V refuses the whole operation; it is not ignored** (Q15, resolved in group (b) of §14);
4. no pubkey repeats (already excluded by §3.4);
5. every signature verifies under `verify_strict` (§5);
6. k ≥ `required`, where k is the number of approvals and `required = ceil(n·t / 10000) = (n·t + 9999) div 10000`.

**The rule, verbatim (Q17, decided 2026-10-22).** Register reuses the existing governance rule unchanged:
- `required_approvals` (`crates/sumchain-wire/src/validator_authority.rs:119-123`):
  `let num = (active_count as u64) * (threshold_bps as u64); ((num + 9999) / 10000) as u32`.
- `verify_validator_quorum_strict` (`crates/state/src/validator_quorum.rs:83-96`), through the shared `quorum_with` (`:99-130`), applies it as listed above. `check_threshold_bps` is line 40; `required` is computed at line 111; `if valid < required` at line 126 refuses. `verify_validator_quorum` (`:64-77`) is the same rule under `verify`.

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
6. **Threshold (Q17, decided 2026-10-22):** `t = GovernanceParams.validator_authority_threshold_bps`, the authenticated governance threshold from chain parameters. It is never taken from the operation or from a tooling default. **Floor (B2, adopted 2026-10-23):** `record.approval_threshold_bps ≥ t`.
7. **New id:** no record with `record.id` exists, Enabled or Disabled.
8. **Quorum:** §6 over the §4.1 preimage at threshold `t`.

On acceptance, the record is stored exactly as carried.

### Disable, executed at height h

Accepted only if **all** of these hold:

1. **Approval window:** as for register.
2. **Record:** the record `id` exists and is Enabled.
3. **Quorum (B2, adopted 2026-10-23):** §6 over the §4.2 preimage at `t = stored.approval_threshold_bps`. Neither threshold is ever read from the operation bytes.

**Later governance-threshold changes do not affect existing records.** A record keeps the threshold accepted at its registration, which was then at least the governance threshold. Disable is a safety action and must not get harder over time.

The consequence: after a governance increase, an older record can still be disabled at its lower stored threshold, which is at least the governance threshold of its registration. New registrations must meet the new floor. `a_governance_threshold_change_does_not_move_an_existing_record` tests both. The activation proposal (§16, §2) takes the same position.

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

## 9. Named parameters (structure accepted 2026-10-23; values undecided)

`RegistryIngressParams` holds T_min (`registry_min_timelock_blocks`) and W (`registry_max_approval_window`), each an `Option<u64>` with **no default**. The owner accepted this structure on 2026-10-23:
- **paired presence:** both set or neither;
- **range:** each value in `1..=u32::MAX`;
- **checked arithmetic:** `h + T_min` is exact (§8), and an overflow refuses with `303`.

`validate()` enforces the first two and returns `Partial` or `OutOfRange`; both unset is valid, and is the dormant state. `complete()` yields values only for a valid, fully set pair, so a missing or invalid value can never be defaulted on its way to execution. An unset, partial or out-of-range set refuses both operations with `302` (no fee). `invalid_parameter_sets_refuse_free` and `a_timelock_past_u64_max_refuses_with_303` test this.

The binary's value is `REGISTRY_INGRESS_PARAMS = RegistryIngressParams::UNSET`, and no production code reads it. The values are undecided; the vectors and tests use TEST_ONLY values.

| Parameter | Type | Read by | While unset |
|---|---|---|---|
| `registry_min_timelock_blocks` (T_min; #217 B6, #212) | `Option<u64>`, `1..=u32::MAX` | register rule 5 | both operations refuse `302` |
| `registry_max_approval_window` (W) | `Option<u64>`, `1..=u32::MAX` | rule 1 of both | both operations refuse `302` |

There are no genesis or ConsensusConfig fields, no new schema version and no field ids in this PR. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL. Binding the values across nodes is §16.

Q17 removed the threshold-source parameter, and Q3 made the record default tooling-only (`no_consensus_path_reads_a_tooling_default`). The genesis block hash is a precondition of the same kind: without it, both operations refuse `302`.

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
| an approval `verify_strict` refuses (§5), or any quorum failure (§6) | `Failed(303)` | charged if affordable | +1 if charged | none |
| a partial or out-of-range parameter set (§9) | `Failed(302)` | none | unchanged | none |
| accepted | `Success` | charged | +1 | one `cf::STATE` row under `registry/v1/` |

## 11. Replay protection

| Threat | Rule |
|---|---|
| Another chain | `chain_id` and `genesis_block_hash` are both in the preimage. The genesis hash separates chains that share a `chain_id`. |
| Another operation | Distinct NUL-terminated domains, prefix-free against the registry KDF tags and every quorum domain (§4.3). Register approvals presented on a disable refuse (`303`), and the reverse. |
| The same operation again | State idempotency: a register is refused if the `id` exists; a disable is refused unless the record is Enabled; Disabled is terminal. A replayed operation never changes state. The outer account nonce refuses a verbatim transaction replay. |
| Stale approvals | `valid_until` is in the preimage and is checked against h, together with the window W. Membership and threshold are evaluated against the set at execution (§6). |
| Duplicate or unordered approvals | Decode refusal (`302`, §3.4) |

## 12. State (STATE adopted 2026-10-23)

- **Placement:** the existing `cf::STATE` family. No column family is added: `ALL_CFS` is byte-identical to `e3b8ff81`, and a test checks this. A family a binary does not name makes the volume unopenable by that binary, and the 0.2.0-era binary would auto-repair it to empty.
  - Key: `REGISTRY_RECORD_KEY_PREFIX` `"registry/v1/"` (12 bytes) ‖ `id` (32), 44 bytes.
  - Value: the 154-byte `RegistryRecordV1` encoding.
  - A stored row that does not decode, or names another `id`, is an error, never "no record".
- **Collision checks.** These are every key family of `cf::STATE` on main and in the open PRs (checked 2026-10-23):
  - `acct`: account rows, `storage/src/schema.rs` `ACCOUNT_KEY_PREFIX`. It is the only family any production code scans: the account root, snapshot export and legacy revert.
  - `vset/`: G5's validator-set rows, #342, unmerged.

  No other open PR writes `cf::STATE`, and the retention-tracker layouts are injected, with no production layout. `registry/v1/` is prefix-free with both, in both directions, and the `registry/` namespace appears nowhere else in the repository's byte literals. `the_record_prefix_is_disjoint_from_every_state_key_family` checks this. `prefix_iter` seeks to a prefix, and readers stop where it ends; the account fold does (`account_root.rs` `AccountDigest::fold`). `registry/` sorts after `acct`, so the account scan never reaches a registry row, and `a_record_is_one_state_row_under_its_prefix` checks that too.
- **Writes and rollback.** Rows are written only through `ExecutionView`, so they land in the block's one atomic batch, and the generic application journal unwinds them on a rollback. Disable rewrites the row in place, changing only the status byte.
- **Digest:** while dormant, nothing folds these rows into a root. The registry digest R(h), and what the root does and does not cover, is the activation proposal (§16).

## 13. Consequences and activation prerequisites

1. **This PR changes no decoding.** `GovernanceOperation` keeps exactly its eight variants (0 to 7). A governance transaction naming 8 or 9 fails to decode with the same error as on the base (`invalid value: integer 8, expected variant index 0 <= i < 8`), and a block holding one is rejected whole. Tests pin this for the payload, the signed transaction and the block (`governance_operations_8_and_9_do_not_decode`), for a synced `SyncResponse::Blocks`, and for `send_raw_transaction`, which leaves the mempool empty. An upgraded and a non-upgraded node therefore agree on every block.

   **Adding the two wire variants belongs to the activation change.** It is a coordinated, same-window upgrade: once a binary decodes operation 8 or 9, an earlier binary rejects any block that holds one. If an operation that refuses before semantics (`300`–`302`, no fee) could be included in a block, it would also take block space for free. The decision document does not state either point (Q14).
2. **Activation needs all of the following:**
   - the two `GovernanceOperation` variants and a dispatch to `execute_registry_ingress`, released as a coordinated upgrade;
   - governance-v1 activation with `ChainParams::governance`;
   - ratified values for both parameters;
   - their registration in the consensus configuration, under a new schema, because schema 2 is frozen (Q5, Q6). The allocation is provisional;
   - the consensus binding and the registry digest of §16;
   - the engines supplying the genesis block hash (Q7);
   - a release.

   None of this is done here.
3. **The validator signing tool must include the genesis hash and `valid_until`.**

## 14. Questions, consolidated

There are three groups: (a) settled by the decision ledger (`DECISION-RECORD-20261016.md`, including the appendices "2026-10-22 owner decisions" and "2026-10-23 owner decisions and corrections") or by an owner instruction; (b) routine implementation choices, resolved in this PR; (c) protocol decisions still open, each with a recommendation. No resolution in (b) changes dormancy.

| Grp | Q | Resolution or recommendation | Consequence or citation |
|---|---|---|---|
| a | Q3 record default threshold | A tooling-only default. Removed from the parameter set and from every consensus path, which derives thresholds from authenticated state. | Owner 2026-10-22. Guarded by `no_consensus_path_reads_a_tooling_default`. |
| a | Q4 signature rule | **Strict** (`verify_strict`) for operations 8 and 9 only; existing operations keep `verify` (§5) | Owner 2026-10-23. The earlier comparison is corrected in §5. |
| a | Q5 consensus-config registration | Schema 2 is fixed. New committed fields need a schema-evolution proposal. The schema version is unallocated, and the ids are provisional. | Ledger G3, 2026-10-16; owner 2026-10-23 |
| a | Q6 parameter structure | T_min and W: no defaults, paired presence, `1..=u32::MAX`, checked arithmetic (§9). The values are undecided; no genesis or config fields yet. | Owner 2026-10-23 |
| a | Q8 commit consumers | Decided with the first proof consumer (#128). Until then nothing in production references `v_check_commit`, `check_commit` or `execute_registry_ingress`. | Owner 2026-10-22. Guarded by `no_production_code_calls_the_commit_check_or_the_registry_entry`. |
| a | Q18 `id` derivation | Bound to Q8: the consumer checks that its verifier material derives to the record `id` | Owner 2026-10-22 |
| a | Q9 all-zero commitments | Refused at register: `303`, fee per Policy-B, no state change (§7 rule 4a, §10). The dry run refuses the same names. | Owner 2026-10-22 |
| a | Q13 storage | `cf::STATE` under `registry/v1/` ‖ id. No new column family; `ALL_CFS` equals main's; collision-checked (§12). | Owner 2026-10-23 (STATE adopted), replacing the dormant META placement |
| a | Q17 register threshold | The authenticated governance threshold, under the existing rule verbatim (§6) | Owner 2026-10-22 |
| a | B2 thresholds | Disable is at the stored record's threshold, which register made ≥ the governance threshold. Later governance changes do not affect existing records (§7). | Owner 2026-10-23; consequence in §7 |
| a | Q12 / binding | The handshake-only binding is **rejected**. The consensus-identity binding and the registry digest are the activation proposal (§16). | Owner 2026-10-23 |
| b | Q1 missing parameter | `302`, pre-semantic | Defensive only: activation with a missing value is impossible (ledger C5 note, 2026-10-21) |
| b | Q2 expiry and window | `303`, fee per Policy-B | Height-dependent, like every other authorization refusal |
| b | Q7 genesis hash | The activation change supplies `create_genesis_block().hash()` (config field `0x0005`) | Refuses until then |
| b | Q10 dry-run activation check | Unchanged now; the activation change aligns `registry_dryRunAdmit` to `h + T_min` | Non-consensus RPC |
| b | Q11 bound on k | None beyond `u16` | The transaction size limit bounds k: k < `max_block_bytes` / 96 (10,416 at the 1,000,000-byte default). Every approval must also be a distinct active validator, so a valid k ≤ n ≤ 29,127 (VS-6(a)). |
| b | Q14 wire decoding | No wire variants. Decoding is unchanged and tested for the payload, transaction, block, sync response and RPC. | Adding the variants is the activation change |
| b | Q15 departed approvals | An approval from any key outside the execution-height set refuses the whole operation (`303`); it is not ignored | Submitters must drop departed approvals |
| b | Q16 approval order | Decode refusal (`302`) | The order is part of the §3 layout |
| c | Parameter values | T_min and W are undecided. **Recommend:** decide them with the activation heights. | The vectors use TEST_ONLY values |
| c | Schema and field-id allocation | ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL. | Decided with the activation change |
| c | Activation proposal items | **Recommend** §16: the P/R byte tables, gate A, `registry_param_changes` and the declaration height | Every existing root stays byte-identical below A |

### 14.1 Status of the 2026-10-22 recommendation

The consolidated recommendation of 2026-10-22 (sprint record `C5-RECOMMENDATION-20261022.md`) was decided on 2026-10-23 as follows:
- **Signatures:** its recommendation to keep governance-v1 `verify` was **not adopted**. Its claim that VS-5 makes the two rules agree for real approvers was wrong (corrected in §5). Operations 8 and 9 are strict.
- **Parameters:** the structure was **accepted** (§9). Its handshake digest-trailer binding was **replaced** by the consensus-identity binding of §16; a handshake check may detect mismatches but cannot substitute. Its ids are PROVISIONAL, and the ConsensusConfig schema version is unallocated (assigned when the activation change is planned).
- **Storage and digest:** STATE placement was **adopted** (§12). The registry digest was refined into §16, which corrects where the fold goes: after the account digest.

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
| `ALL_CFS` byte-identical to main; a record is one STATE row under `registry/v1/`, unseen by the account scan; the prefix is disjoint from `acct` and `vset/` | `the_column_families_are_exactly_mains`, `a_record_is_one_state_row_under_its_prefix`, `the_record_prefix_is_disjoint_from_every_state_key_family` |
| Strict for ops 8 and 9: each distinguishing signature under both rules; receipts (`303` with and without fee, `302` at decode); existing operations unchanged | `the_two_rules_on_each_distinguishing_signature`, `operations_8_and_9_refuse_approvals_only_the_old_rule_accepts`, `existing_governance_operations_keep_the_governance_v1_rule` |
| Parameters: paired presence, `1..=u32::MAX`, overflow → `303` | `named_parameters_*` (wire), `invalid_parameter_sets_refuse_free`, `a_timelock_past_u64_max_refuses_with_303` |
| B2: a governance-threshold change does not move an existing record | `a_governance_threshold_change_does_not_move_an_existing_record` |

## 16. Activation proposal: consensus binding and registry digest (PROPOSED)

**PROPOSED, dormant, not ratified, text only.** None of it is implemented in this PR: it is the activation change. **Today's protection against operations 8 and 9 is the decode refusal (§13):** nothing in #348 makes such a block invalid by height. The `R<A>` block-validity rule below belongs to the activation binary. The one part already in this PR is the STATE placement of §12 (the "moves here" in the Placement bullet of its §6 is done).

Gate names and domains are **provisional**. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL.

This section is the sprint record `C5-CONSENSUS-BINDING-PROPOSAL-20261023.md` as amended on 2026-10-23, reproduced as written apart from wording about the schema number and today's #348 behaviour. Its section numbers are local to it. The root-coverage statement in its §6 is verbatim.

Read-only basis: main `e3b8ff81`; #348 `c867eedb`; #342 `13c5c755` (draft); #338 `02508800`. Nothing here is implemented, scheduled or authorized. It replaces the handshake-only binding (owner, 2026-10-23, "2026-10-23 owner decisions and corrections"). Gate names and domains below are **provisional**. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL.

### 0. Summary

- **Mechanism:** from a new registry activation gate A, `compute_block_state_root` appends two components: **P(h)**, a registry-parameters sub-commitment of the consensus-configuration values *effective at h* (T_min, W, 0x0601), and **R(h)**, the registry-state digest. Both go after the account-state fold and before the parent accumulator.
- **Why this binds:** every importer recomputes the root and refuses a mismatch (`storage/src/candidate.rs:459-485`). A node with different effective values computes a different root from block A, whether or not a registry operation occurs. It cannot import honest blocks, and its own blocks are refused.
- **Handshake** (protocol digest) stays as early detection only.

### 1. Commitment encoding and activation boundary

#### 1.1 What the ConsensusConfig commitment is today, and what is missing

- **Encoding:** `MAGIC "CCFGv1\0" ‖ schema:u16 ‖ field_count:u16 ‖ (field_id:u16 ‖ tag:u8 ‖ len:u32 ‖ value)*`, little-endian, every field present and ascending. The commitment is `BLAKE3("SUMCHAIN/CONSENSUS-CONFIG/v1\0" ‖ encoding)` (`consensus/src/consensus_config/codec.rs:8-19`, `:48`, `:405-409`). 0x0601 is `governance.validator_authority_threshold_bps`, U16 (`fields.rs:262-266`, projected at `:1944`).
- **Record:** `cf::META` `consensus_config/v1/record` plus an append-only `transition/<seq>`. Each transition carries `at_height`, the node's head **when the operator acknowledged** (`record.rs:5-31`).
- **Startup check:** `check_at_startup` (`record.rs:366-436`) records a fresh baseline, accepts an exact match, and auto-records a `GateReschedule` for gates still ahead of the chain. It refuses a change to a passed gate (`refuse_retroactive_gates`, `:642`) and any other change without the stopped-node `acknowledge-consensus-config --old --new` (`:457-536`). That acknowledgement refuses chain-identity and rule-code changes (`:450-452`).
- **Missing:**
  - (i) The record is an `UnverifiedLocalBaseline` (`record.rs:71-85`). It is "not signed, exchanged with peers, placed in a block or compared at handshake" (`mod.rs:16-22`), so nothing makes two nodes agree.
  - (ii) Values are not height-keyed. `ChainParams.governance` holds one value, and an acknowledged change applies to every execution after restart, including reorg re-execution of earlier heights. `at_height` is node-local and has no execution meaning.
  - (iii) The protocol digest covers no GovernanceParams value (`state/src/protocol_digest.rs:36-41`, `:372-403`).

#### 1.2 Candidates

| Option | Assessment |
|---|---|
| **(a) fold into `compute_block_state_root` from A** | **Recommended.** It uses the existing gated-fold pattern (`state/src/executor.rs:4346-4413`) and the existing import comparison (`candidate.rs:459-485`). No header, wire or hash-format change. |
| (a′) fold the FULL effective ConsensusConfig commitment | Rejected. It moves on every future-gate reschedule (`GateReschedule`, applied at each node's restart, not at a height) and on every acknowledged change. Nodes restart at different times, so it would split the chain at node-specific heights. It also covers fields that are not effective at h. |
| (b) header field | Rejected as not minimal. It changes the block encoding and the hash for every binary, sync and RPC. |
| (c) handshake | Detection only, per the owner. |

#### 1.3 Preimages (all integers big-endian, like the root's own integers and the account digest, `executor.rs:4333/4342`, `state/src/account_root.rs:25-28`)

```text
P(h) = BLAKE3( "SUMCHAIN/REGISTRY/PARAMS/v1\0"
             ‖ gov_tag:u8   ‖ [ threshold_bps:u16 ]          // 0x0601 effective at h; tag 0 = governance unconfigured, 1 = present
             ‖ reg_tag:u8   ‖ [ T_min:u64 ‖ W:u64 ] )         // paired presence; tag 0 = both absent, 1 = both present
R(h) = BLAKE3( "SUMCHAIN/REGISTRY/STATE/v1\0"
             ‖ for each STATE row with key prefix "registry/v1/", ascending key bytes:
                   id[32] ‖ record[154]                      // RegistryRecordV1 frozen bytes, verbatim; id must equal record.id
             ‖ count:u64 )
root(h ≥ A) = BLAKE3( …unchanged components through the account fold (executor.rs:4331-4413)…
                     ‖ P(h) ‖ R(h)
                     ‖ parent_accumulator )                  // executor.rs:4416
```

R(h) is computed over the block's candidate view (as `v_account_state_digest`, `account_root.rs:449-461`), so it reflects block h's own writes. Correction to the 2026-10-22 recommendation: the fold goes after the **account** digest, which follows the beacon digest at `e3b8ff81`, not directly after the beacon digest.

#### 1.4 Boundary rule (new gate, provisional name `registry_enabled_from_height` = A)

- **h ≤ A−1:** the root is byte-identical to `e3b8ff81`; P and R are not computed. A block holding governance op 8 or 9 must be **invalid**. In #348 today, operations 8 and 9 are not wire variants, so such a block is refused at decode (§13 of this README); that decode refusal is today's only protection. #348's internal entry `execute_registry_ingress` returns `Failed(300/301/302)` receipts keyed on the governance gate. Once the activation binary decodes variants 8/9, that alone would let a block below A be valid to new binaries and undecodable to old ones. The activation binary therefore needs an **explicit height rule**, `R<A>`: a transaction carrying `GovernanceOperation` 8 or 9 is invalid at any height h < A. It is enforced at four points:
  1. **Block validity (authoritative):** in `BlockExecutor::validate_block` (`state/src/executor.rs:4703-4746`), immediately after `check_block_contract_gas` (`:4741`), which is the existing height-gated per-transaction block check. A new `registry_ingress::check_block_registry_ops(&params, block.header.height, &block.transactions)` returns `StateError::BlockValidation` if `height < A` and any `TxType::Governance` transaction names op 8 or 9. `validate_block` runs before execution on both import paths (`consensus/src/poa.rs:1497-1500`, `consensus/src/reorg.rs:476`). So the block is refused whole: no receipt, no fee, no state, as with any invalid block.
  2. **Executor backstop (fail-closed):** the op-8/9 dispatch arm returns an execution **error**, never a receipt, if reached at h < A, so a missed validation cannot yield a valid block. The 300/301/302 receipts apply only from A. A ≥ the governance gate (load rule below), so 300 cannot occur from A.
  3. **Admission:** `Mempool::add` (`state/src/mempool.rs:250`) refuses op 8/9 while `current_height + 1 < A`. It mirrors `EducationAdmission`, which holds `params` and the live height (`:123-133`, check at `:402`), and covers RPC `send_raw_transaction` (`rpc/src/server.rs:1509-1521`) and gossip. Admission is a filter; block validity is authoritative.
  4. **Producer:** `create_block` skips such a transaction for a block at h < A, like its existing contract-gas skip (`poa.rs:767-800`).

  **Interaction with today's decode refusal:** old binaries keep refusing op 8/9 at decode at every height (#348 README §13), so below A old and new binaries reject the same blocks. In the activation binary, decoding succeeds and `R<A>` is the guard. From A, the normal receipt semantics apply: 302 pre-semantic with no fee, 303 semantic with the Policy-B fee.
- **h = A:** ops 8/9 execute. `root(A)` appends P(A) and R(A). With no register in block A, R(A) = R_empty = `BLAKE3(DOMAIN ‖ 0u64)`.
- **h = A+1 and beyond:** the same formula, with values effective at that height.
- **Load-time rules for A** (genesis `validate`, alongside the existing ordering rules, `genesis/src/lib.rs:3570-3633`):
  - T_min and W are both present;
  - `governance_enabled_from_height` ≤ A;
  - `application_journal_enabled_from_height` ≤ A, mirroring `AccountRootWithoutJournalGate` / `JournalGateAfterAccountRoot` (`:108-142`);
  - A > `LEGACY_ROOT_COMPATIBILITY_HEIGHT` = 496,720 (`candidate.rs:607`), because below it an imported root is adopted, not verified (`:470-478`);
  - the gate is added to `REMEDIATION_GATES` (`lib.rs:4133`) and its accessor pin, so `peer_protocol_declaration_required_from_height` ≤ A is enforced at load (`:3615-3633`);
  - `governance` is `Some`.

### 2. Historical execution and replay

- **Effective value:** `effective(params, h)` is a pure function of the configuration and h, never of META history.
  - The base values are the accepted `GovernanceParams` fields (T_min, W) and the existing 0x0601. They are effective from A.
  - Later changes are entries in a new optional config list, `registry_param_changes` (provisional id): `{effective_from: u64, threshold_bps: u16, T_min: u64, W: u64}`, strictly ascending, each `effective_from` > A. `effective(h)` is the last entry with `effective_from` ≤ h, else the base.
- **Import, reorg re-execution, resync:** all call the same executor with the same `ChainParams` (`consensus/src/poa.rs:1472-1550`), so block h always runs with `effective(h)`. A node replaying across a change uses the old values below `effective_from`.
- **Rollback replay:** the operator rollback is the reorg unwind (`node/src/main.rs:953-976`), which restores pre-images from the generic journal. The node then re-imports with `effective(h)`.
- **Immutability, enforced at startup** (a new check beside `refuse_retroactive_gates`, `record.rs:642-670`):
  - once head ≥ A, the base values cannot change;
  - an entry with `effective_from` ≤ head cannot be added, changed or removed;
  - a future entry needs the stopped-node acknowledgement.

  The transition record keeps `at_height` for audit only.
- **Single threshold per height:** from A, every governance reader of 0x0601 must use `effective(h)`. Today there are four (`state/src/governance_executor.rs:451/497/552/1101`). With no change entries this is identical to today; without it, replaying an existing operation across a threshold change would diverge.
- **B2 and later threshold changes:** existing records are unaffected. Disable uses the stored `approval_threshold_bps`, which was ≥ the governance threshold effective at registration (#348 `state/src/registry_ingress.rs:96-101`). New registrations use `effective(h)`.

### 3. Missing or mismatched parameters

- **Absent:** ops 8/9 refuse with 302, no fee, while values or the genesis hash are missing (#348 `governance_executor.rs:301-303`). 300 (gate) and 301 (governance unconfigured) come first. Below A the fold commits nothing, because it is not computed. From A, absence is impossible by the load rule; if reached anyway, P commits tag 0 explicitly and every node refuses with 302 alike.
- **Mismatch** (node X has different effective values at some h ≥ A, or at the first `effective_from` it disagrees on):
  - X's P(h) differs, so X's root differs for every block from that height, with or without registry operations.
  - X's import of an honest block fails with "state root mismatch … discarding the candidate" (`candidate.rs:459-485`). X **stalls**; it does not adopt the block.
  - Honest nodes reject X's blocks the same way.
  - PoA proposers are strictly round-robin `validators[h mod n]` with no skip (`sumchain-wire/src/proposer.rs:61-70`; `poa.rs:2073-2080`). X therefore cannot build a growing fork (the next slot is another validator's block, which X rejects). If X holds a slot, the honest chain also halts at that slot until X is fixed.
  - **Result:** a visible halt (safety kept, liveness lost), never silent divergence.

### 4. Older binaries and undeclared nodes

- **With the new genesis, a binary that includes #318:** refused at load. `ChainParams` and `GovernanceParamsJson` are `deny_unknown_fields` (`genesis/src/lib.rs:475-476`, `:333`).
- **With the new genesis, the deployed mainnet binary `b1f259f6`:** not refused at load. It predates #318: its `GovernanceParamsJson` (`lib.rs:252`) and `ChainParams` (`:320`) carry no `deny_unknown_fields`, so it **silently ignores** the registry gate, T_min, W and the change list, and runs its own rules. What still excludes it:
  - **Before A, digest mismatch.** `b1f259f6`'s activation-name set already lacks two of main's gates (`messaging_timestamp_units_enabled_from_height`, `contract_metering_enabled_from_height`), and will lack the registry gate too. Its activation digest, and so its protocol digest, differs from the activation binary's. It declares that digest (it has `peer_compat.rs` with the same table, `:33-36`, `:234`), so each side marks the other `Incompatible` in both phases, and its blocks are dropped at the network boundary.
  - **From A, root mismatch.** It never appends P‖R, so its root preimage differs at every h ≥ A, and it cannot decode op 8/9.
  - **No equal-root window remains from A.** Below A, roots can be equal only where the two binaries' rules are equal; op 8/9 is refused by both (its decode, `R<A>`). In that band the digest mismatch already keeps it out of consensus.
- A config record of the next ConsensusConfig schema version is refused by any binary whose `reads` lacks that version (`consensus_config/mod.rs:40-46`).
- **With its old genesis:** it runs old rules and computes old roots. It rejects honest block A and every later one, and its blocks from A are rejected by upgraded nodes (§3). It is prevented from participating at block validity, not merely detected.
- **Before A:** the new gate name enters `activation_heights()`, so the activation digest changes even while the gate is `None` (`lib.rs:4800-4815`), and so does the protocol digest. An old binary that declares its digest is `Incompatible` in both phases (`p2p/src/peer_compat.rs:33-36`, `:231-236`). Its blocks are dropped at the network boundary (`node/src/node.rs:544`, `:1128`).
- **Undeclared binaries:** refused from `peer_protocol_declaration_required_from_height` ≤ A, enforced at load.
- **Participation:**
  - Production consensus is PoA, which has no votes; influence is only through imported blocks and fork choice (`peer_compat.rs` module note).
  - BFT is experimental with `propose_block` unimplemented (`consensus/src/bft/mod.rs:3-12`). It is outside this proposal, and the config's PoA rule codes cannot be changed by acknowledgement (`record.rs:450-452`).
  - BFT proposal and vote filters exist at `node.rs:1252/1276/1301`, but are not relied on.

### 5. Same-window upgrade requirements

1. **Ratify:** this binding, the P/R byte tables, the record/approval tables, T_min and W, the schema version and field ids, A, and the declaration height.
2. **Activation binary:**
   - wire variants 8/9, with the `R<A>` rule at block validity, executor, admission and producer (§1.4);
   - the gate and the §1.4 load rules;
   - P/R folds, `effective(h)`, and STATE placement;
   - `"state:registry"` in `REQUIRED_FAST_SYNC_FAMILIES`;
   - dry-run alignment to h + T_min;
   - the next ConsensusConfig schema version as `writes`.
3. **Heights:**
   - Set `peer_protocol_declaration_required_from_height` **strictly below** A, with ≥ 48 h observation (`docs/lane-a/ACTIVATION-PROPOSAL.json:54`).
   - If that height is already set, it stays a single height ≤ A.
   - The lead-time rule applies (`ACTIVATION-PROPOSAL.json` `derivation_rule.lead_time_rule`).
4. **One window, every validator, in this order:**
   - stop;
   - install the binary and the byte-identical `genesis.json` (rollout §3);
   - run `acknowledge_schema_transition` (to the next schema version, rules unchanged);
   - run `acknowledge-consensus-config --old --new` for the values and gate;
   - start.

   Mixed operation is impossible even before A, because the protocol digests differ, so this is a stop-all / start-all window.
5. **Evidence, every validator equal** (rollout §1-§3): binary commit, `genesis.json` sha256, activation digest, protocol digest, ConsensusConfig commitment, and the effective registry values.
6. **Stop conditions:**
   - rollout §4.1 items 1-6;
   - any ConsensusConfig commitment or effective value differs;
   - any "state root mismatch" log line.

   **Stop before the declaration height** (§4, abort rule). Ways out: fix the validator, or postpone with new heights. Never compress the lead time (§4.3). A downgrade must use a binary whose `reads` includes that schema version (`mod.rs:56-72`).

### 6. Registry digest integration

- **Placement:** `cf::STATE`, key `registry/v1/` ‖ id[32] (ADOPTED, subject to collision checks). It is disjoint from `acct` (`storage/src/schema.rs:246`) and from G5's `vset/` (#342 `storage/src/validator_set_g5.rs:148`): neither is a prefix of the other. Tracker layouts are test-only. #348's dormant META prefix `registry/record/v1/` (`state/src/registry_ingress.rs:158`) moves here.
- **Order and encoding:** ascending key bytes (equal to ascending id), as in §1.3. Big-endian count at the end, mirroring the account digest. Records are the frozen 154-byte `RegistryRecordV1` (`sumchain-wire/src/registry_wire.rs:133`), whose fields are little-endian as frozen.
- **Updates:**
  - Register inserts.
  - Disable **updates in place**: only the status byte changes, and the row remains. Recommended over deletion, because deletion would re-allow an id and lose the terminal state (#348 README §7, rule 7).
  - Disabled records stay in R.
- **Rollback:** the generic journal holds pre-images for every family written through `ExecutionView` (`storage/src/journal.rs:21-30`): register undo deletes the row, disable undo restores Enabled. The commit is one atomic batch (`candidate.rs:110`). The load rule requires the journal gate ≤ A.
- **Initialization:** no migration. No production code writes registry rows before A (#348 guard), so R(A) is computed over block A's candidate, and equals R_empty if block A holds no register.
- **Cost:** one ascending scan of n rows, 186 bytes hashed per row, per block from A. That is O(n), against the account-digest reference of about 40 ms per 250,000 rows (`account_root.rs:463-470`). n grows only by quorum-approved, fee-paying registers. No consensus cap is proposed; a warning threshold like the account root's is optional.
- **What `root(h)` commits to for h ≥ A** (`executor.rs:4331-4418`):
  - height, parent hash, timestamp and tx_root;
  - per receipt: tx hash, a success bit and fee_paid. **Not** the failure code: 302 and 303 differ only by fee;
  - the contracts **per-block diff** digest (contracts gate);
  - the supply-ledger digest (once present);
  - compute-pool and beacon digests (their gates);
  - the account digest (account-root gate);
  - P(h) and R(h);
  - the parent accumulator.
- **What it does NOT commit to:** tokens, NFTs, storage metadata, validators, delegations and staking, messaging, docclass, governance proposals, votes and assets, equity, inference state, all of `cf::META` (including the ConsensusConfig record and certified-finality rows), every ConsensusConfig field except P's three values, events and logs, and any gate still closed. It remains a partial commitment, with no Merkle proofs. It is **not** a complete state commitment.

### 7. Open, for the owner

- the P/R byte tables (domains, tags, order);
- gate and field-id allocation. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL.
- whether to adopt `registry_param_changes` now or to freeze values until a later activation;
- T_min and W values;
- A and the declaration height.

Handshake digest trailer: optional detection only.
