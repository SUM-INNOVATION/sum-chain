# PROPOSED, NOT RATIFIED: C5 registry ingress (#242), byte specification

**This is a proposal for byte review. It is not a byte ratification, and nothing in it is frozen.** The owner decided Q3, Q8/Q18, Q9 and Q17 on 2026-10-22. On 2026-10-23 the owner decided four more points, and replaced the handshake binding with the activation proposal in §16 (§14):
- strict verification for operations 8 and 9;
- the parameter structure;
- STATE storage;
- B2.

Later on 2026-10-23 the owner accepted freezing T_min, W and the governance threshold at activation as the design direction (§17; the bytes stay PROPOSED, and no values or heights are selected). Both registry limits stay PROPOSED until the activation change implements and tests them (§12.1).

The byte layouts stay PROPOSED until every C5 decision is settled. It specifies the dormant implementation in this pull request completely enough to be checked against the code and the vectors. Every value marked *fixture* or *synthetic* is a test value, not a proposed parameter.

- **Mechanism:** B of the C5 proposal (#242). Governance-v1 operations 8 (register) and 9 (disable) inside `TxType::Governance = 23`. There is no new transaction type, no `RegistryWireOp` namespace, no new gate and no new receipt code (`Failed(418)` stays unallocated).
- **Not on the wire:** this PR does **not** add the two `GovernanceOperation` variants. A governance transaction naming 8 or 9 is refused at decode exactly as on the base, and a block holding one is rejected (§13). The codecs and the executor logic are reached only through `governance_executor::execute_registry_ingress`, which nothing but the tests calls. Adding the wire variants is part of the separately authorized activation change.
- **Authorization:** a quorum of the active PoA validator set at the execution height, verified **strictly** by `validator_quorum::verify_validator_quorum_strict` (§5). Register uses the authenticated governance threshold (Q17). Disable uses the stored record's threshold (B2, adopted 2026-10-23). `tx.from` only pays the fee.
- **State:** dormant and unwired. Even by direct call, both operations refuse with `302` before reading their payload: both named parameters are unset (§9), and nothing supplies a genesis block hash. Records live in `cf::STATE` under `registry/v1/` (§12).
- **Refs:** #242, #128. Base: `main` `df502b53`.

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

The `prospective_governance_tx_data` vectors start at offset 4 of this table. **Correction to the earlier proposal text:** it describes `operation` as a `u8`. On the wire it is the bincode `u32` variant index; the Rust discriminant is a `u8`.

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
- A pubkey equal to the one before it is a duplicate and is refused. A smaller one is out of order and is refused. Both are decode failures (`302`): the order is part of the proposed layout, which lists them with the other byte-level negatives (Q16).
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

It is a thin wrapper in `crypto`, not new cryptography, because `state` does not depend on `finality-foundations` and should not. The existing `verify_validator_quorum` keeps `verify_bytes`, and both share one internal rule (`quorum_with`).

**What the two rules compute** (ed25519-dalek 2.2.0 source):
- `verify` (`verifying.rs:201-217`) decodes `S` canonically (`signature.rs:91-96`) and recomputes `R' = [k](−A) + [s]B`. It accepts iff `compress(R')` equals the signature's `R` bytes.
- `verify_strict` (`verifying.rs:357-380`) additionally refuses when R does not decompress, or when R or A is a small-order point.

**Correction.** The earlier comparison claimed VS-5 makes the two rules agree for real approvers. VS-5 validates public keys, not a signature's R. A key holder can sign with R = identity and s = k·a mod ℓ (where a is the secret scalar). Then `[s]B − [k]A` is the identity, so `verify` accepts. `verify_strict` refuses, because the identity is small-order. So the rules differ even for honest, canonical, prime-order keys. Any other small-order R cannot satisfy the equation with a prime-order A: `[s]B − [k]A` lies in the prime-order subgroup, whose only small-order element is the identity.

| Signature or key | governance-v1 `verify` | `verify_strict` (ops 8, 9) | Through the registry entry |
|---|---|---|---|
| ordinary signature | accepts | accepts | `Success` |
| R = identity, s = k·a (real key holder, canonical prime-order key) | **accepts** | refuses | `303` |
| any other small-order R, prime-order A | refuses (cannot satisfy the equation) | refuses | `303` |
| A = identity (small-order, outside VS-5), R = [s]B, any message | **accepts** | refuses | `303` |
| non-canonical S (S + ℓ) | refuses | refuses | `303` |
| non-canonical R: y = p + 1 for the identity, s recomputed over those bytes | refuses: the recomputed point is the identity, whose canonical encoding `01 00…00` differs from R | refuses earlier: R decodes (high bit masked, canonicity unchecked) to the identity, a small-order point | `303` |
| wrong message | refuses | refuses | `303` |
| public key that does not decompress | refuses | refuses | `303` |
| truncated approval (wrong length) | not reached | not reached | `302` at decode, no fee |

For a small-order A of order 2, 4 or 8, `verify` accepts R = [s]B only when that order divides k (so that `[k]A` is the identity). `verify_strict` refuses every small-order A.

Every row is tested: `the_two_rules_on_each_distinguishing_signature` (both rules) and `operations_8_and_9_refuse_approvals_only_the_old_rule_accepts` (receipts). `existing_governance_operations_keep_the_governance_v1_rule` pins that `RegisterAsset` still accepts the identity-R approval. The vectors `prospective_strict_refused.identity_r.register.k1.data` and `prospective_both_refuse.noncanonical_r.register.k1.data` execute as `303`.

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
7a. **Size bound (required by the owner 2026-10-23; rule and value PROPOSED):** fewer than `MAX_REGISTRY_RECORDS` records are stored, Enabled and Disabled together (§12.1). It is checked **last**, after the quorum (rule 8), so only an otherwise valid register pays for the scan.
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

- **Placement:** the existing `cf::STATE` family. No column family is added: `ALL_CFS` is byte-identical to `main` (`df502b53`; unchanged since `e3b8ff81`), and a test checks this. A family a binary does not name makes the volume unopenable by that binary, and the 0.2.0-era binary would auto-repair it to empty.
  - Key: `REGISTRY_RECORD_KEY_PREFIX` `"registry/v1/"` (12 bytes) ‖ `id` (32), 44 bytes.
  - Value: the 154-byte `RegistryRecordV1` encoding.
  - A stored row that does not decode, or names another `id`, is an error, never "no record".
- **Collision checks.** These are every key family of `cf::STATE` on main and in the open PRs (checked 2026-10-23):
  - `acct`: account rows, `storage/src/schema.rs` `ACCOUNT_KEY_PREFIX`. It is the only family any production code scans: the account root, snapshot export and legacy revert.
  - `vset/`: G5's validator-set rows, #342, unmerged.

  No other open PR writes `cf::STATE`, and the retention-tracker layouts are injected, with no production layout. `registry/v1/` is prefix-free with both, in both directions, and the `registry/` namespace appears nowhere else in the repository's byte literals. `the_record_prefix_is_disjoint_from_every_state_key_family` checks this. `prefix_iter` seeks to a prefix, and readers stop where it ends; the account fold does (`account_root.rs` `AccountDigest::fold`). `registry/` sorts after `acct`, so the account scan never reaches a registry row, and `a_record_is_one_state_row_under_its_prefix` checks that too.
- **Writes and rollback.** Rows are written only through `ExecutionView`, so they land in the block's one atomic batch, and the generic application journal unwinds them on a rollback. Disable rewrites the row in place, changing only the status byte.
- **Digest:** while dormant, nothing folds these rows into a root. The registry digest R(h), and what the root does and does not cover, is the activation proposal (§16).

### 12.1 Registry limits (required by the owner 2026-10-23; rules and values PROPOSED)

There are two limits. Both stay **PROPOSED** until the activation change implements and tests them:
- **(a)** `MAX_REGISTRY_RECORDS = 4096` records: a transaction-level `303`. It is implemented dormant in this PR and tested through the internal entry.
- **(b)** `MAX_REGISTRY_OPS_PER_BLOCK = 8` registry operations per block: a block-validity rule of the activation change. It is specified here and not implemented in this PR.

#### (a) Size bound: 4,096 records (rule and value PROPOSED)

**The bound.** A deterministic consensus bound on the per-block registry scan, in place of a warning threshold.
- `MAX_REGISTRY_RECORDS = 4096` records, Enabled and Disabled together (`state/src/registry_ingress.rs`).
- The most the proposed fold R(h) hashes per block is `MAX_REGISTRY_FOLDED_BYTES` = 4,096 × (32 + 154) + 27 + 8 = **761,891 bytes**:
  - 32 bytes of id and 154 bytes of record per row;
  - the 27-byte fold domain, provisional with §16;
  - the `u64` count.

**Refusal point (rule PROPOSED).** A register that would store record 4,097 is refused with `303` (rule 7a), as the last check after the quorum:
- the fee is charged when the balance covers it, otherwise fee 0;
- the nonce follows the same rule as every other `303`;
- nothing is stored.

**Behaviour at the limit:**
- **Every stored record counts (rule PROPOSED).** That includes disabled records, because R(h) folds them all, so a disabled record never frees capacity.
- **Disable adds no record** and stays allowed at the limit.
- **A disabled id stays present,** so re-registering it is refused with `303` at any count (rule 7).
- **Raising the bound** after A is a new coordinated activation that height-keys the old and new values (§17 (c)). Every binary keeps the old value and applies it below the change height on replay, reorg and resync, so historical roots and outcomes still reproduce.

**Tested in this PR (dormant, through the internal entry):**
- **The limit:** with 4,095 records stored, a register is accepted; with 4,096 it is `303` (fee charged, and fee 0 when underfunded), and nothing is stored. Disable stays allowed at the limit, a disabled id cannot be registered again, and staged registers are counted (`the_size_bound_refuses_the_register_that_would_exceed_it`, `rolling_back_a_register_restores_the_count`).
- **The order:** a register refused at its quorum is a `303` receipt even when the scan would fail, and the same register with a valid quorum reaches the scan (`the_size_bound_scan_runs_only_after_the_quorum`).
- **Storage errors:** a malformed row or key, and a real RocksDB read failure on the point read and on the scan, are execution errors with no receipt, fee, nonce or write (`a_failing_registry_read_is_an_execution_error_not_a_receipt`, `a_real_registry_read_failure_is_an_execution_error_with_no_fee_nonce_or_write`).
  - They propagate exactly as the governance-v1 operations' storage errors do since #349. In `execute`, a read failure is `Stop::Storage` and returns the error before settlement. In `execute_registry_ingress`, the validators return the error, and the entry propagates it before `settle`.
  - Both reach the executor's block-transaction failure path, and neither becomes a receipt.

**Counting.** A bounded prefix scan over `registry/v1/` through the block's `ExecutionView` (`v_count_records_up_to`). It stops after `MAX_REGISTRY_RECORDS` rows, so a register reads at most 4,096 rows, and it sees the block's own earlier registers.
- Every counted row must pass `checked_registry_row`, the one row rule the proposed R(h) also uses: a key of exactly 12 + 32 bytes, a value that decodes, and a record id equal to the key's.
- A row that breaks the rule, or a read error, is an **execution error**, never a short count and never a receipt.
- **Why a scan, not a count row:** the scan reads exactly the rows R(h) would fold, so the two cannot drift. It adds no key and no collision surface. The candidate overlay, the one atomic batch and the generic journal already cover the rows it counts, so a rollback below a register restores the count with nothing else to undo.

**The value.** 4,096 is PROPOSED, with this rationale:
- One proof system is admitted today.
- Records name verifier keys, program images, tokenizers and models, and each needs a validator quorum and a fee. The expected count is tens to low hundreds over years, so 4,096 leaves at least 16× headroom.
- At the limit the fold costs about 0.6 ms of BLAKE3 on one core (761,891 bytes, measured on an arm64 workstation), once per block.
- One 4,096-row scan costs about 0.7 ms at the account root's reference of 40 ms per 250,000 rows.

**The dry run.** `registry_dryRunAdmit` checks the record alone. It reads no registry state, neither id uniqueness nor the count. At the limit it therefore reports an otherwise valid record as admissible, while execution refuses the register with `303`. A test pins that difference.

#### (b) Per-block cap: 8 registry operations (rule and value PROPOSED; activation change, not this PR)

**Why the bound needs a cap.**
- Only a register that has passed every other check reaches the scan. That includes a strict validator-quorum signature over that exact record and window, so unsigned or wrongly signed registers stop before it.
- A validator quorum could still put many validly signed registers in one block, and each would scan, so the quorum alone is not a bound. With about 1,000 transactions per block, the scans alone could cost about 0.7 s.

**What counts.** A transaction counts if its `TxType::Governance` payload names operation 8 or operation 9:
- registers and disables count together;
- the outcome does not matter: a transaction that would end in `Success`, `302` or `303` counts the same, because the rule is decided from the block's bytes before execution.

**Refusal: block validity (authoritative).**
- `validate_block` checks the cap immediately after `R<A>` (§16 §1.4).
- A block at h ≥ A carrying more than 8 counted transactions is **invalid as a whole**, like any invalid block: no receipts, no fees, no nonces and no state change.
- `validate_block` runs before execution on both import paths and on reorg re-execution, so all three refuse it the same way.

**Boundary at A.**
- **h < A:** no registry operation is allowed at all, because `R<A>` already makes a block with any operation 8 or 9 invalid. The cap is not reached.
- **h ≥ A:** at most 8 per block, from h = A inclusive. Block A itself may carry 8.

**Executor backstop (fail-closed).** Block execution counts again before it executes the first transaction. A block above the cap is an execution error: no transaction runs and no receipt exists, so a missed validation cannot yield a valid block.

**Producer.** `create_block` includes at most 8 counted transactions, in its selection order.
- A further registry operation is skipped for that block, and so is every later transaction of the same sender (nonce order), as with the `R<A>` skip.
- Skipped transactions stay in the mempool for later blocks.

**Mempool.** Admission does not apply the cap.
- It refuses no transaction because of the count. Extras stay pending until a later block includes them.
- They remain subject to every other admission rule, including `R<A>`.

**Cost with the cap.** A block costs at most 8 scans plus one fold: about 8 × 0.7 + 0.6 ≈ 6 ms, about 0.4% of the 1,506 ms block interval. Each approval's strict signature check comes on top, bounded by the approvals' bytes within the block size.

**Not in this PR.** The internal entry runs per transaction and has no block context. Operations 8 and 9 do not decode, so no block can carry one.

**LOCAL PROTOTYPE evidence (not the activation change's tests).** An unpublished local activation prototype, at a test-only A, exercised the rule as specified here. These are not tests of this PR or of the activation change, which must run its own:
- `the_per_block_cap_accepts_8_and_refuses_9_on_poa_import`: 8 registry operations at A accepted; 9 refused whole on the PoA import, with no state change.
- `reorg_import_and_replay_refuse_9_registry_ops_at_a_and_adopt_8`: 9 at A refused on a reorg ("reorg refused before unwinding"); a branch with 8 replayed across A and adopted.
- `the_producer_includes_8_and_the_mempool_keeps_the_rest_pending`: the producer included 8 of 10 admitted operations, the mempool held the other 2 pending, and the next block included them.
- `the_producer_selection_keeps_8_and_skips_the_rest_with_the_sender_tail`: the selection skips the 9th with its sender's later transaction.

#### (c) How both limits are authenticated (PROPOSED)

`MAX_REGISTRY_RECORDS = 4096` and `MAX_REGISTRY_OPS_PER_BLOCK = 8` are compiled constants, derived from the one definition `REGISTRY_LIMITS` (`sumchain-wire/src/registry_ingress.rs`, re-exported by `state/src/registry_ingress.rs`). No configuration file carries them, so no acknowledgement can change them. Two binaries agree on them only if they were built from the same values. *[Amended 2026-10-26]* The authoritative binding is now the state root: both limits are committed in P(h) from A (§16 §1.3), so a node with a different value of either limit computes a different root at every block from A, even with an empty registry and no registry operation. Three mechanisms bind nodes to the same values once the activation change wires them (items 1-3), and item 4 is the rule their readers follow. While dormant only the pins of item 5 and the P(h) encoding exist.

1. **The handshake (detection and exclusion of declaring peers).**
   - The activation change adds both names to `protocol_digest::consensus_limits` (`state/src/protocol_digest.rs:141`).
   - `protocol_digest_with_limits` (`:372`) folds every limit's name, type tag and value into the protocol digest each node declares through `GetProtocolId` (`p2p/src/sync.rs:44`).
   - A peer that declares a different digest is `PeerCompat::Incompatible` in both phases. It may not propose, vote or move fork choice (`p2p/src/peer_compat.rs:231-236`, checked at `node/src/node.rs:1128`).
   - A peer that declares nothing is refused only from `peer_protocol_declaration_required_from_height`, which the §16 §1.4 load rules put at or below A.
   - This excludes a declaring peer that was built with another value. It checks no block.
   - Tested dormant: `once_folded_a_different_compiled_registry_limit_changes_the_protocol_digest` shows that a value one step away, in either limit, changes the digest.
2. **Both limits, through P(h) in the state root (authoritative; amended 2026-10-26).**
   - P(h) commits `max_records` and `max_ops_per_block` from `REGISTRY_LIMITS`, the constant the size bound reads (§16 §1.3); the cap readers must read it too (item 4). The committed and enforced values are then one constant.
   - Two nodes differing only in one limit compute different roots at A and at every later block, whatever the block carries. Import refuses on the root mismatch (`storage/src/candidate.rs:481`). Tested in the local activation prototype: `nodes_with_different_registry_limits_refuse_each_others_block_at_a` (not the activation change's test).
   - Below A, P(h) is not folded, and the roots are equal.
   - **Also, through R(h):** a register at the boundary is accepted under one value and refused under another, so the two nodes store different rows.
   - R(h) folds every row and the count (§16 §1.3), so from that block their roots differ.
   - Import refuses a block whose computed root differs from its header ("state root mismatch", `storage/src/candidate.rs:481`); only an exact root is accepted (`:468`). A > 496,720 keeps this out of the legacy window.
   - Without P(h), nothing would diverge until a register reached the boundary. With P(h), the root differs from A.
3. **The per-block cap, through block validity.**
   - A node built with a larger cap accepts, and may produce, a block with more than 8 registry operations. A node with the proposed 8 refuses that block whole in `BlockExecutor::validate_block` (`state/src/executor.rs:4704`, beside the contract-gas check at `:4741`), on both import paths and on reorg.
   - A node built with a smaller cap refuses honest blocks that carry more than its own cap.
   - Either way the disagreement is a refused block, never a silently different state.
   - Which chain advances then depends on proposer order. The local prototype observed a stall at the mismatched proposer's slot for value mismatches; that is not established for long runs, or for this specific mismatch.
4. **Readers of the cap (activation change).** `validate_block`, the executor backstop and the producer cap **must** read `REGISTRY_LIMITS` (through its derived `MAX_REGISTRY_OPS_PER_BLOCK` or directly), never a literal or another value, so that the cap enforced and the value P(h) commits are the same constant. The activation change adds a test showing that the root fold and the cap read the same value.
5. **Pins in this PR (dormant).**
   - `the_compiled_registry_limits_are_pinned_with_their_census_rows` asserts both values. It also asserts their `EXCLUDE unwired` census rows (`consensus/tests/data/consensus_constants_census.tsv`), their classification in `state/tests/protocol_digest_census.rs`, and that neither is in `consensus_limits()` yet.
   - Changing a value, or wiring one without classifying it, fails a test first.

**What is not established.** No test runs two binaries with different compiled limits. (i) is modelled through `protocol_digest_with_limits`, and (ii) and (iii) follow from the root and the validity rule, which the activation change must test with the real code.

#### Activation of both limits

**Activation.** While dormant the bound is in neither `consensus_limits` nor the protocol digest, because no transaction reaches it. The activation change:
- folds P(h) through `registry_params_digest_for`, committing both limits from `REGISTRY_LIMITS` (§16 §1.3);
- makes every cap reader (`validate_block`, the executor backstop, the producer cap) read `REGISTRY_LIMITS`, with a test that the root fold and the cap read the same value;
- adds `MAX_REGISTRY_RECORDS` to `protocol_digest::consensus_limits`, so every node declares it in the protocol digest at the handshake;
- adds the per-block cap `MAX_REGISTRY_OPS_PER_BLOCK` (defined, unwired, in this PR) as a block-validity rule, with its producer cap and executor backstop ((b) above), and to `consensus_limits` beside the bound;
- moves both names out of `EXCLUDED` in `state/tests/protocol_digest_census.rs`, changes their census rows (`consensus_constants_census.tsv`) from `EXCLUDE unwired`, and updates `the_compiled_registry_limits_are_pinned_with_their_census_rows`, which fails until it does;
- runs the tests of both limits again against the activation binary, including the handshake, root and validity mismatches of (c).

ConsensusConfig id: unallocated.

The fold's byte bound follows from it and is not a separate parameter.

## 13. Consequences and activation prerequisites

1. **This PR changes no decoding.** `GovernanceOperation` keeps exactly its eight variants (0 to 7). A governance transaction naming 8 or 9 fails to decode with the same error as on the base (`invalid value: integer 8, expected variant index 0 <= i < 8`), and a block holding one is rejected whole. Tests pin this for the payload, the signed transaction and the block (`governance_operations_8_and_9_do_not_decode`), for a synced `SyncResponse::Blocks`, and for `send_raw_transaction`, which leaves the mempool empty. An upgraded and a non-upgraded node therefore agree on every block.

   **Adding the two wire variants belongs to the activation change.** It is a coordinated, same-window upgrade: once a binary decodes operation 8 or 9, an earlier binary rejects any block that holds one. If an operation that refuses before semantics (`300`–`302`, no fee) could be included in a block, it would also take block space for free. The earlier proposal text did not state either point (Q14).
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

There are three groups: (a) settled by an owner decision (2026-10-16 to 2026-10-23) or owner instruction; (b) routine implementation choices, resolved in this PR; (c) protocol decisions still open, each with a recommendation. No resolution in (b) changes dormancy.

| Grp | Q | Resolution or recommendation | Consequence or citation |
|---|---|---|---|
| a | Q3 record default threshold | A tooling-only default. Removed from the parameter set and from every consensus path, which derives thresholds from authenticated state. | Owner 2026-10-22. Guarded by `no_consensus_path_reads_a_tooling_default`. |
| a | Q4 signature rule | **Strict** (`verify_strict`) for operations 8 and 9 only; existing operations keep `verify` (§5) | Owner 2026-10-23. The earlier comparison is corrected in §5. |
| a | Q5 consensus-config registration | Schema 2 is fixed. New committed fields need a schema-evolution proposal. The schema version is unallocated, and the ids are provisional. | Owner decision, 2026-10-16; owner decision, 2026-10-23 |
| a | Q6 parameter structure | T_min and W: no defaults, paired presence, `1..=u32::MAX`, checked arithmetic (§9). The values are undecided; no genesis or config fields yet. | Owner 2026-10-23 |
| a | Q8 commit consumers | Decided with the first proof consumer (#128). Until then nothing in production references `v_check_commit`, `check_commit` or `execute_registry_ingress`. | Owner 2026-10-22. Guarded by `no_production_code_calls_the_commit_check_or_the_registry_entry`. |
| a | Q18 `id` derivation | Bound to Q8: the consumer checks that its verifier material derives to the record `id` | Owner 2026-10-22 |
| a | Q9 all-zero commitments | Refused at register: `303`, fee per Policy-B, no state change (§7 rule 4a, §10). The dry run refuses the same names. | Owner 2026-10-22 |
| a | Q13 storage | `cf::STATE` under `registry/v1/` ‖ id. No new column family; `ALL_CFS` equals main's; collision-checked (§12). | Owner 2026-10-23 (STATE adopted), replacing the dormant META placement |
| a | Q17 register threshold | The authenticated governance threshold, under the existing rule verbatim (§6) | Owner 2026-10-22 |
| a | B2 thresholds | Disable is at the stored record's threshold, which register made ≥ the governance threshold. Later governance changes do not affect existing records (§7). | Owner 2026-10-23; consequence in §7 |
| a | Q12 / binding | The handshake-only binding is **rejected**. The consensus-identity binding and the registry digest are the activation proposal (§16). | Owner 2026-10-23 |
| a | Freeze | T_min, W and the governance threshold are frozen at activation. This is the accepted design direction; the bytes are PROPOSED (§17), and no values or heights are selected. | Owner 2026-10-23 |
| a | Registry limits | 4,096 records and 8 registry operations per block stay PROPOSED until the activation change implements and tests them. Their exact refusal behaviour is in §12.1. | Owner 2026-10-23 |
| b | Q1 missing parameter | `302`, pre-semantic | Defensive only: activation with a missing value is impossible (owner decision, 2026-10-21) |
| b | Q2 expiry and window | `303`, fee per Policy-B | Height-dependent, like every other authorization refusal |
| b | Q7 genesis hash | The activation change supplies `create_genesis_block().hash()` (config field `0x0005`) | Refuses until then |
| b | Q10 dry-run activation check | Unchanged now; the activation change aligns `registry_dryRunAdmit` to `h + T_min` | Non-consensus RPC |
| b | Q11 bound on k | None beyond `u16` | The transaction size limit bounds k: k < `max_block_bytes` / 96 (10,416 at the 1,000,000-byte default). Every approval must also be a distinct active validator, so a valid k ≤ n ≤ 29,127 (VS-6(a)). |
| b | Q14 wire decoding | No wire variants. Decoding is unchanged and tested for the payload, transaction, block, sync response and RPC. | Adding the variants is the activation change |
| b | Q15 departed approvals | An approval from any key outside the execution-height set refuses the whole operation (`303`); it is not ignored | Submitters must drop departed approvals |
| b | Q16 approval order | Decode refusal (`302`) | The order is part of the §3 layout |
| c | Parameter values | T_min and W are undecided. **Recommend:** decide them with the activation heights. | The vectors use TEST_ONLY values |
| c | Schema and field-id allocation | ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL. | Decided with the activation change |
| c | Activation proposal items | **Recommend** §16: the P/R byte tables, gate A, the freeze bytes (§17) and the declaration height | Every existing root stays byte-identical below A |

### 14.1 Status of the 2026-10-22 recommendation

The consolidated recommendation of 2026-10-22 was decided by the owner on 2026-10-23 as follows:
- **Signatures:** its recommendation to keep governance-v1 `verify` was **not adopted**. Its claim that VS-5 makes the two rules agree for real approvers was wrong (corrected in §5). Operations 8 and 9 are strict.
- **Parameters:** the structure was **accepted** (§9). Its handshake digest-trailer binding was **replaced** by the consensus-identity binding of §16; a handshake check may detect mismatches but cannot substitute. Its ids are PROVISIONAL, and the ConsensusConfig schema version is unallocated (assigned when the activation change is planned).
- **Storage and digest:** STATE placement was **adopted** (§12). The registry digest was refined into §16, which corrects where the fold goes: after the account digest.

## 15. Vectors and tests

**`vectors.txt`.** Synthetic. Chain id 4242, genesis hash `0x47 × 32`, validator seeds `[i; 32]`, fixture governance threshold 6667, fixture `T_min = 10` and `W = 100`. It holds, for k = 1 and k = q(4) = 3:
- the record;
- both preimages;
- each payload, and its prospective `GovernanceTxData` and `TxPayload` envelopes (§2).

`vectors_are_reproduced_and_execute` regenerates the file and requires byte equality (comment lines excluded). It runs every payload through `execute_registry_ingress`: k = 1 against the active set {1}, and k = 3 against {1, 2, 3, 4}. Both must reach `Success`. It also requires every prospective envelope to fail decode on this binary. The `prospective_registry_bound.*` lines record the size bound (§12.1). The k = 1 register executes as `Success` with `MAX − 1` records stored and as `303` with `MAX` stored.

**Activation-change encodings (PROPOSED; dormant codecs, no caller).** The file also holds, at a TEST_ONLY A = 500,000:
- `prospective_registry_limit.max_ops_per_block`: the per-block cap, 8.
- `prospective_registry_params.{none,governance_only,both}.{preimage,digest}`: P(h) with both tags absent, with only the governance threshold, and with the threshold, T_min and W (§16 §1.3, big-endian).
- `prospective_registry_state.{empty,one_record}.{preimage,digest}`: R_empty, and R over the fixture record (§16 §1.3, big-endian).
- `prospective_registry_freeze.record`: the 41-byte freeze record of the fixture values with `first_height = A` (§17, little-endian).
- `prospective_registry_freeze.gate_pin`: the 15-byte gate pin of A (§17, little-endian).

The test also checks:
- that `v_registry_state_digest` over an empty registry, and over one stored fixture record, reproduces the R vectors;
- that the freeze record and the pin decode back to their fields.

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
| Size bound: `MAX − 1` stored → register accepted; at `MAX` → `303` (fee charged; fee 0 when underfunded), nothing stored; disable allowed at the limit; a disabled id not re-registrable; staged registers counted | `the_size_bound_refuses_the_register_that_would_exceed_it` |
| A failing registry read (undecodable row, record under another id, malformed key met by the count) is an execution error, never a receipt | `a_failing_registry_read_is_an_execution_error_not_a_receipt` |
| A real storage read failure: RocksDB refuses a damaged table block, on the point read (register, disable) and on the size-bound scan. Each is an execution error with no receipt, fee, nonce or write | `a_real_registry_read_failure_is_an_execution_error_with_no_fee_nonce_or_write` |
| Size bound: the scan runs only after the quorum (a quorum refusal is a `303` receipt even when the scan would fail) | `the_size_bound_scan_runs_only_after_the_quorum` |
| Size bound: rolling back a published register (generic journal) restores the count | `rolling_back_a_register_restores_the_count` |
| Size bound: the dry run reports the record alone at the limit, while execution refuses `303` | `crates/rpc/tests/registry_dry_run_agrees.rs` (`at_the_size_bound_the_dry_run_reports_the_record_alone`) |
| Size bound: constants and folded bytes; the boundary vectors execute | `the_size_bound_constants`, `vectors_are_reproduced_and_execute` |
| P(h): preimage layout; a different limit, threshold, T_min, W, order or presence gives a different digest | wire `params_digest_preimage_layout_and_every_field_matters`; `the_registry_params_digest_separates_every_mismatch` |
| P(h) commits both limits at fixed offsets; either limit one step away changes P(h) with an empty registry and no registry operations; zero limits refused | `either_limit_changes_p_h_with_an_empty_registry_and_no_registry_operations`; wire `registry_limits_refuse_zero` |
| One source: the size bound and P(h) read the one compiled `REGISTRY_LIMITS`; a line heuristic flags either value spelled on a registry-limit line elsewhere (§16 §1.3); the wire builders refuse invalid limits and the constant is asserted valid at compile time | `the_size_bound_and_p_h_read_the_one_compiled_source`; `registry_limit_values_are_defined_once`; wire `registry_limits_refuse_zero` |
| P(h) commits the threshold and values execution applies: `gov_tag = 0` without governance (`301`), `reg_tag = 0` whenever execution refuses `302` | `p_h_commits_the_threshold_and_values_execution_applies` |
| R(h): preimage layout; ascending key order; disabled records folded; any byte change moves it | wire `state_digest_preimage_layout`; `the_registry_state_digest_is_ordered_and_covers_every_record` |
| R(h) never folds around a bad row (short key, undecodable value, record under another id) | `the_registry_state_digest_refuses_every_malformed_row` |
| Freeze record and gate pin: exact LE layout, round trip, refusal of short, long and cross-magic bytes; the META keys disjoint and prefix-free | wire `freeze_record_and_gate_pin_encode_decode_and_refuse`; `the_freeze_record_and_gate_pin_refuse_malformed_bytes`; `the_record_prefix_is_disjoint_from_every_state_key_family` (the `registry/` namespace, META keys included, is this module's alone) |
| The P and R domains are prefix-free with every registry and validator domain, one NUL each | wire `domains_are_prefix_free_against_every_registry_and_validator_domain` |
| Both compiled limits pinned: values, census rows, protocol-digest classification, not yet in `consensus_limits` | `the_compiled_registry_limits_are_pinned_with_their_census_rows` |
| Once folded, a different compiled value of either limit changes the protocol digest (§12.1 (c)) | `once_folded_a_different_compiled_registry_limit_changes_the_protocol_digest` |

## 16. Activation proposal: consensus binding and registry digest (PROPOSED)

**PROPOSED, dormant, not ratified, text only.** None of it is implemented in this PR: it is the activation change. **Today's protection against operations 8 and 9 is the decode refusal (§13):** nothing in #348 makes such a block invalid by height. The `R<A>` block-validity rule below belongs to the activation binary. The one part already in this PR is the STATE placement of §12 (the "moves here" in the Placement bullet of its §6 is done).

Gate names and domains are **provisional**. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL.

This section is the activation proposal as amended on 2026-10-23, reproduced as written apart from wording about the schema number and today's #348 behaviour. Later amendments of 2026-10-23 are marked *[Amended 2026-10-23]*: the freeze direction (§17), both registry limits (§12.1) and the R(h) row rule. Its section numbers are local to it. The root-coverage statement in its §6 is verbatim.

Read-only basis: main `e3b8ff81`; #348 `c867eedb`; #342 `13c5c755` (draft); #338 `02508800`. Nothing here is implemented, scheduled or authorized. It replaces the handshake-only binding (owner decision, 2026-10-23). Gate names and domains below are **provisional**. ConsensusConfig schema version: unallocated; assigned when the activation change is planned. Field ids 0x0609/0x060a and constants 0x2900–0x2904 are PROVISIONAL.

### 0. Summary

- **Mechanism:** from a new registry activation gate A, `compute_block_state_root` appends two components: **P(h)**, a registry-parameters sub-commitment of both consensus limits (`REGISTRY_LIMITS`, amended 2026-10-26) and the consensus-configuration values *effective at h* (T_min, W, 0x0601), and **R(h)**, the registry-state digest. Both go after the account-state fold and before the parent accumulator.
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
P(h) = BLAKE3( "SUMCHAIN/REGISTRY/PARAMS/v1\0"           // offset 0, 28 bytes
             ‖ max_records:u32                         // offset 28: REGISTRY_LIMITS.max_records (proposed 4,096), always present
             ‖ max_ops_per_block:u16                   // offset 32: REGISTRY_LIMITS.max_ops_per_block (proposed 8), always present
             ‖ gov_tag:u8   ‖ [ threshold_bps:u16 ]    // offset 34; 0x0601 effective at h; tag 0 = governance unconfigured, 1 = present
             ‖ reg_tag:u8   ‖ [ T_min:u64 ‖ W:u64 ] )  // paired presence; tag 0 = both absent, 1 = both present
R(h) = BLAKE3( "SUMCHAIN/REGISTRY/STATE/v1\0"
             ‖ for each STATE row with key prefix "registry/v1/", ascending key bytes:
                   id[32] ‖ record[154]                      // RegistryRecordV1 frozen bytes, verbatim; id must equal record.id
             ‖ count:u64 )
root(h ≥ A) = BLAKE3( …unchanged components through the account fold (executor.rs:4331-4413)…
                     ‖ P(h) ‖ R(h)
                     ‖ parent_accumulator )                  // executor.rs:4416
```

R(h) is computed over the block's candidate view (as `v_account_state_digest`, `account_root.rs:449-461`), so it reflects block h's own writes.

*[Amended 2026-10-26: both limits in P(h); owner, design direction approved; bytes and values PROPOSED]* P(h) commits the exact limits execution and block validity enforce.

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 28 | `SUMCHAIN/REGISTRY/PARAMS/v1\0` | unchanged; no version bump, because no v1 layout was ever ratified or used |
| 28 | 4 | `max_records` u32 BE | `1..=u32::MAX`; must be the value the size bound enforces |
| 32 | 2 | `max_ops_per_block` u16 BE | `1..=u16::MAX`; must be the value the block-validity cap enforces |
| 34 | 1 | `gov_tag` | 0 or 1 |
| 35 | 2 | `threshold_bps` u16 BE | only when `gov_tag = 1` |
| next | 1 | `reg_tag` | 0 or 1 |
| next | 8 + 8 | `T_min` u64 BE ‖ `W` u64 BE | only when `reg_tag = 1` |

- **Lengths:** 36 bytes (no values), 38 (governance only), 54 (both).
- **Why the limits come first, unconditionally:** they are compiled consensus constants that execution and block validity always apply from A. Fixed offsets keep them independent of the optional fields.
- **Widths:**
  - `max_records` is u32, because the registry count is not bounded by any block field, and 32 bits cover every plausible registry while the fold cost stays computable (`max_records × 186` bytes).
  - `max_ops_per_block` is u16, because a cap above a block's transaction count would be meaningless, and u16 exceeds every configured `max_txs_per_block`.
- **One source, structurally, for the readers in this PR:**
  - Both limits have one definition, `REGISTRY_LIMITS: RegistryLimits` (`sumchain_wire::registry_ingress`, re-exported by `sumchain_state::registry_ingress`). A compile-time assertion checks that it is valid.
  - The size bound in `validate_register` reads the constant directly. `RegistryIngressContext` carries no limits, so no caller can supply one.
  - `registry_params_digest_for(params, ctx)` builds P(h) from the same constant and accepts no limits argument. **Consensus code must build P(h) only through it.** The wire `registry_params_digest(limits, …)` and `registry_params_digest_preimage(limits, …)` keep a limits parameter for vectors and the local prototype only. They are hidden from the crate documentation for that reason, and they refuse invalid limits, so a zero limit is never committed.
  - `MAX_REGISTRY_RECORDS` and `MAX_REGISTRY_OPS_PER_BLOCK` are derived from it.
  - `registry_limit_values_are_defined_once` is a **line heuristic, not a proof**. Outside the definition and its pins, in the workspace's Rust sources, it fails on:
    - the records value spelled as `4096`, `4_096` or `0x1000` on a line naming the registry or `max_records`;
    - `8` on a line naming `ops_per_block` or registry operations.

    A copy spelled on a line that names neither, or a value computed rather than written, escapes it. That is why the cap's future readers are required to name the constant (below) and are reviewed for it.
  - **Not yet established:** the per-block cap has no reader in this PR. Its three future readers (`validate_block`, the executor backstop, the producer cap) **must** read `REGISTRY_LIMITS` (§12.1 (c), activation list).
- **The other P(h) inputs come from the values execution reads:**
  - the threshold is `params.governance`'s `validator_authority_threshold_bps`, the field `validate_register` reads; absent governance (`301`) commits `gov_tag = 0`;
  - T_min and W are committed (`reg_tag = 1`) whenever `ready` holds: both parameters complete and the genesis hash present. Otherwise execution refuses `302`, and P(h) commits `reg_tag = 0`.
  - `ready` does not look at governance. With governance absent, P(h) still commits T_min and W while execution refuses `301` first. §16 §1.4's load rules require governance at or before A, so this cannot occur from A, and from A P(h) commits exactly the values execution applies.
- **Tests:**
  - `either_limit_changes_p_h_with_an_empty_registry_and_no_registry_operations`;
  - `the_size_bound_and_p_h_read_the_one_compiled_source`;
  - `p_h_commits_the_threshold_and_values_execution_applies`;
  - `registry_limit_values_are_defined_once`;
  - `the_registry_params_digest_separates_every_mismatch`;
  - the wire `params_digest_preimage_layout_and_every_field_matters` and `registry_limits_refuse_zero`;
  - the vectors `prospective_registry_params.*`, including the four `*_plus_1` cases.
- **The freeze record (§17) does not carry the limits:** they are compiled constants, not configuration, so no acknowledgement can change them. P(h) and the root bind them: a different value means a different binary, and the root of every block from A shows it.
- **Frozen at A.** Like T_min, W and the threshold, both limits are fixed from A. A later change is a new coordinated activation (§17 (c)). Because the limits are compiled constants, the change is a **compiled, height-keyed schedule in a new binary** under a new gate B, not a ConsensusConfig entry. Every binary keeps the old value and applies it below B on replay, reorg and resync. Handshake detection comes through `consensus_limits` (§12.1 (c)).

*[Amended 2026-10-26]* These preimages have one dormant implementation in this PR. Nothing calls it, and no root folds it:
- `registry_params_digest_preimage` / `registry_params_digest` and `registry_state_digest_preimage` (`sumchain_wire::registry_ingress`);
- `v_registry_state_digest` over a candidate view (`sumchain_state::registry_ingress`).

Each has vectors in §15.

*[Amended 2026-10-23]* Every row R(h) folds must pass `checked_registry_row` (`state/src/registry_ingress.rs`), the one row rule the size-bound count also uses (§12.1 (a)):
- the key is exactly `registry/v1/` ‖ 32 bytes;
- the value decodes as `RegistryRecordV1`;
- the record's id equals the key's.

A row under the prefix that breaks the rule is an error:
- a key of any other length is `registry row key of N bytes`;
- an undecodable value is `registry record: …`;
- an id mismatch is `registry record stored under another id`.

Each of these, like a read error, is an execution error that fails the block. A row is never skipped or folded around. Correction to the 2026-10-22 recommendation: the fold goes after the **account** digest, which follows the beacon digest at `e3b8ff81`, not directly after the beacon digest.

#### 1.4 Boundary rule (new gate, provisional name `registry_enabled_from_height` = A)

- **h ≤ A−1:** the root is byte-identical to the base (`df502b53`); P and R are not computed. A block holding governance op 8 or 9 must be **invalid**. In #348 today, operations 8 and 9 are not wire variants, so such a block is refused at decode (§13 of this README); that decode refusal is today's only protection. #348's internal entry `execute_registry_ingress` returns `Failed(300/301/302)` receipts keyed on the governance gate. Once the activation binary decodes variants 8/9, that alone would let a block below A be valid to new binaries and undecodable to old ones. The activation binary therefore needs an **explicit height rule**, `R<A>`: a transaction carrying `GovernanceOperation` 8 or 9 is invalid at any height h < A. It is enforced at four points:
  1. **Block validity (authoritative):** in `BlockExecutor::validate_block` (`state/src/executor.rs:4703-4746`), immediately after `check_block_contract_gas` (`:4741`), which is the existing height-gated per-transaction block check. A new `registry_ingress::check_block_registry_ops(&params, block.header.height, &block.transactions)` returns `StateError::BlockValidation` if `height < A` and any `TxType::Governance` transaction names op 8 or 9. `validate_block` runs before execution on both import paths (`consensus/src/poa.rs:1497-1500`, `consensus/src/reorg.rs:476`). So the block is refused whole: no receipt, no fee, no state, as with any invalid block.
  2. **Executor backstop (fail-closed):** the op-8/9 dispatch arm returns an execution **error**, never a receipt, if reached at h < A, so a missed validation cannot yield a valid block. The 300/301/302 receipts apply only from A. A ≥ the governance gate (load rule below), so 300 cannot occur from A.
  3. **Admission:** `Mempool::add` (`state/src/mempool.rs:250`) refuses op 8/9 while `current_height + 1 < A`. It mirrors `EducationAdmission`, which holds `params` and the live height (`:123-133`, check at `:402`), and covers RPC `send_raw_transaction` (`rpc/src/server.rs:1509-1521`) and gossip. Admission is a filter; block validity is authoritative.
  4. **Producer:** `create_block` skips such a transaction for a block at h < A, like its existing contract-gas skip (`poa.rs:767-800`).

  *[Amended 2026-10-23]* The per-block cap of §12.1 (b) is checked at the same block-validity point, immediately after `R<A>`, with its own executor backstop and producer cap. Admission does not apply it.

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

*[Amended 2026-10-23]* The owner accepted the freeze (§17) as the design direction. The activation change therefore does not include the change list `registry_param_changes` or its immutability rule, both described below. For every h ≥ A, `effective(h)` is the frozen value, until a later coordinated change introduces a height-keyed entry (§17 (c)).

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

**Parameter changes after activation (design direction accepted 2026-10-23; specified in §17).** T_min, W and the governance threshold `validator_authority_threshold_bps` (0x0601) are frozen at A, instead of adopting the height-keyed `registry_param_changes` list above now. Any change after A then needs a new coordinated activation. Consequences:
- From A, `validator_authority_threshold_bps`, T_min and W cannot be changed by acknowledgement. Startup refuses. *[Amended 2026-10-23]* The refusal is keyed on the freeze row, written in the batch of the first block at or above A that the node publishes, produced or imported, not on the head (§17 (a)).
- Changing any of them requires a new coordinated activation, which introduces the height-keyed form or a gated second value set when it is needed.
- Existing records keep their B2 thresholds.
- Before A nothing changes: 0x0601 stays acknowledgement-changeable, as today, with its existing hazard.
- Other GovernanceParams fields are not frozen.

### 3. Missing or mismatched parameters

- **Absent:** ops 8/9 refuse with 302, no fee, while values or the genesis hash are missing (#348 `governance_executor.rs:301-303`). 300 (gate) and 301 (governance unconfigured) come first. Below A the fold commits nothing, because it is not computed. From A, absence is impossible by the load rule; if reached anyway, P commits tag 0 explicitly and every node refuses with 302 alike.
- **Mismatch** (node X holds different effective values at some h ≥ A, or a binary without the registry fold meets one with it). What is established today, by code reading and by tests of the same mechanism for other gates:
  - From A, X's P(h) or missing P‖R makes its computed root differ from the header root of every honest block. Above `LEGACY_ROOT_COMPATIBILITY_HEIGHT` (496,720) an imported root mismatch is refused and the candidate discarded (`candidate.rs:459-485`; tested for another gate by `activation_multinode.rs::above_the_legacy_window_the_same_disagreement_is_refused`). At or below it the header root is adopted, which is why A must be above it.
  - Binaries that lack the registry gate name (the deployed release, main, this PR) declare a different protocol digest from the activation binary and are refused in both phases at the handshake. A node with the activation binary and different values declares the SAME digest (the digest covers no GovernanceParams value), so the handshake does not exclude it; only the root check from A does.
  - Binaries without operations 8 and 9 refuse any block holding one at decode (tested in this PR).
- *[Amended 2026-10-23]* **Since exercised, as LOCAL PROTOTYPE evidence (not the activation change's tests)** (an unpublished local activation prototype, test-only values):
  - below-A refusal on both import paths, through reorg replay, rollback re-import and sync (`poa_import_refuses_operation_8_below_a_and_accepts_it_at_a`, `reorg_import_refuses_operation_8_below_a_and_adopts_it_at_a`, `reorg_replay_across_a_reproduces_every_root_and_refuses_op_8_below_a`, `rollback_below_a_then_reimport_reproduces_every_root_and_refuses_op_8_below_a`, `a_synced_block_below_a_with_operation_8_is_refused_like_poa_import`);
  - for each of T_min, W and the threshold, the root refusal at A in both directions, and identical blocks and roots below A (`mismatched_{t_min,window,threshold}_from_a_refuses_both_ways_at_a_and_agrees_below_a`);
  - equal protocol digests for those mismatched values (`x_with_mismatched_values_declares_the_honest_protocol_digest_and_is_verified`);
  - a refusing node keeps its head, refuses again identically, and does not halt (the same `mismatched_…` tests);
  - at a mismatched proposer's slot, honest nodes refuse its block and stay below A (`rotation_with_x_holding_the_slot_at_a`).

  Behaviour over time, logs, sync loops and peer reporting were not exercised.
- **Not yet established**, and to be tested with the activation code before any ratification: below-A refusal of operations 8 and 9 on both import paths, through reorg replay, rollback re-import and sync; that every mismatch case produces the root refusal at the first block ≥ A; what a refusing node then does (retry, peer reporting, stall); whether honest nodes stall at a mismatched proposer's slot; whether a mismatched minority can extend a fork; reorg and rollback across A. This section makes no claim that every mismatch can only cause a visible halt.

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
   - the next ConsensusConfig schema version as `writes`;
   - *[Amended 2026-10-23]* the per-block cap (§12.1 (b)), and the freeze record with its startup and acknowledgement checks (§17).
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
- **Cost:** one ascending scan of n rows, 186 bytes hashed per row, per block from A. That is O(n), against the account-digest reference of about 40 ms per 250,000 rows (`account_root.rs:463-470`). n grows only by quorum-approved, fee-paying registers. *[Amended 2026-10-23]* The size bound and the per-block cap of §12.1, both PROPOSED, bound it. (As written, this item proposed no cap.)
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
- the freeze bytes and checks (§17). *[Amended 2026-10-23]* Freezing was accepted as the design direction, replacing the question whether to adopt `registry_param_changes` now;
- T_min and W values;
- A and the declaration height.

Handshake digest trailer: optional detection only.

## 17. Freeze at activation (design direction accepted 2026-10-23; bytes PROPOSED)

**Status.**
- **What is frozen:** at the registry gate A, three values:
  - T_min (`registry_min_timelock_blocks`);
  - W (`registry_max_approval_window`);
  - the governance threshold `validator_authority_threshold_bps` (0x0601).
- **What was decided:** the owner accepted the freeze as the design direction on 2026-10-23, then directed this revision before byte ratification.
- **What is PROPOSED:** the binding rule, the recovery path, the record layouts, the keys, the command and the messages below.
- **What is not selected:** any parameter value or activation height.
- **Implementation:** the behaviour is not in this PR. The freeze is part of the activation change, which must test it.
  - This PR carries only the two **codecs** (`RegistryFreezeRecordV1`, `RegistryGatePinV1`), their META key names, vectors and refusal tests. Nothing writes or reads either row.
  - This PR's dormant behaviour is unchanged: operations 8 and 9 do not decode.

**Scope.**
- The freeze covers those three values and A itself. Other `GovernanceParams` fields are not frozen.
- Existing records keep their B2 thresholds.
- Before A nothing changes. 0x0601 stays changeable by the stopped-node acknowledgement, as today, with today's hazard that it is not height-keyed.

### (a) When a node commits, and how startup enforces it (PROPOSED)

**Load rules first.** The §16 §1.4 load-time rules run at genesis validation, before any check here. T_min and W are present, `governance` is `Some`, and A is above 496,720, so every frozen field has a value.

**The freeze record.** One `cf::META` row, key `registry/freeze/v1` (provisional), 41 bytes. Integers are little-endian, like the ConsensusConfig record:

```text
magic "RFRZv1\0" (7) ‖ gate_a:u64 ‖ threshold_bps:u16 ‖ t_min:u64 ‖ w:u64 ‖ first_height:u64
```

- `gate_a`: A as configured;
- `threshold_bps`, `t_min`, `w`: this node's configured values, which the block at `first_height` executed with;
- `first_height`: the height of the block whose publication wrote the row (≥ A; normally A).

**When the node commits: the first publish at or above A, produced or imported.**
- **Write:** in the atomic publish batch of the first block with height ≥ A that this node publishes, if the row is absent.
  - It does not matter whether the node produced the block or imported it through either import path, a reorg replay included.
- **Outside the journal:**
  - Publication stages its `cf::META` rows after the generic application journal is derived (`storage/src/candidate.rs`), and this row is one of them.
  - So the row and the block become durable together.
  - Neither an automatic reorg unwind nor an ordinary rollback touches the row.
  - No later publish rewrites it.
- **Why a publish, and not only a verified peer import:**
  - The proposer of block A has imported nothing at or above A when it publishes A.
  - Neither have a single validator and a node running without a peer.
  - Waiting for a peer block would leave them unbound. Making production wait for a peer block would deadlock every chain at A.
  - A publish needs no peer, so every node commits at its first block at or above A.
- **What each kind of node does:**
  - **First proposer at A:** commits at its own publish of A.
  - **First importer:** commits at the import that publishes its first block at or above A, normally A.
  - **Single validator, or a node without peers:** commits at its own block A.
  - **Snapshot restore at or above A:** does not commit. The snapshot format carries no `cf::META` row; today it carries the account family only. The first publish after the restore commits.
  - **File-level backup restore:** carries the row as it was, with nothing written by the restore.

**No silent switch.** While the row exists, the node cannot run under values other than those it signed or accepted blocks under:
- **Startup refuses** any configured value that differs from the row. Each field must equal, as an integer, the configuration this node starts with:
  - `gate_a` = `registry_enabled_from_height`;
  - `threshold_bps` = `governance.validator_authority_threshold_bps`;
  - `t_min` = `registry_min_timelock_blocks`;
  - `w` = `registry_max_approval_window`.

  The message names each differing field, with its frozen and its configured value, and `first_height`. It states that the values are frozen at activation and that no acknowledgement can permit the change, and it names the recovery rollback below. The check runs beside `check_at_startup` (ConsensusConfig) and the activation-height check, before consensus, RPC or the network exist. A row of the wrong length or magic is **unreadable, not absent**, and start is refused.
- **The acknowledgement refuses** too. `acknowledge-consensus-config --old --new` refuses any change to 0x0601, T_min (0x0609, provisional), W (0x060a, provisional) or A, as it already refuses chain-identity and rule-code changes. A `GateReschedule` of A is refused the same way.
- **Only the recovery rollback below removes the row.**

**Before the first publish at or above A** (no row): start continues at any head, nothing is frozen yet, and the acknowledgement treats these values as today. This window covers a node that has just restored a snapshot above A, and a node whose values make every import fail its root check. The passed-gate rule still refuses moving A once the head is ≥ A.

**Wrong local values get no lock-in.**
- **An importer with wrong values** never publishes a block at or above A: the root check refuses block A before publication. So it never commits. To recover, correct `genesis.json` (acknowledging if the ConsensusConfig baseline differs) and restart.
- **A proposer with wrong values that published a block at or above A** has committed to those values, and its peers refuse that block (root mismatch). Under PoA round-robin, which has no skip, the chain waits at its slot. Recovery is explicit.

**The recovery rollback** (provisional): `sumchain rollback --to T --release-registry-freeze`, on a stopped node.
1. **Stop the node.**
2. **Run the command** with T < `first_height`. The startup refusal names `first_height`. T ≤ A − 1 always qualifies, because `first_height` ≥ A.
   - **One atomic batch:**
     - the ordinary rollback to T (state restored from the generic journal, blocks above T removed and de-indexed, head reset, finality pulled back);
     - the deletion of the freeze row;
     - the gate pin below.
   - **Logged:** the deleted row's bytes, and the hashes of the removed blocks this node signed.
   - **Refused, changing nothing:**
     - no freeze row (use the ordinary rollback);
     - T ≥ `first_height`;
     - an unreadable row with T ≥ the configured A;
     - any target the ordinary rollback refuses, for example one below the journal floor.
3. **Correct the values** in `genesis.json`, and acknowledge the change if the ConsensusConfig baseline differs. The acknowledgement now permits it, because the row is gone.
4. **Start and re-sync from peers.** The first publish at or above A commits again, to the corrected values.

**Re-signing a height.**
- **Only after this explicit step.** In the wrong-proposer case the chain waits at A − 1 for that proposer's slot, so after the recovery it must produce A again. That signs a height it signed before. No other part of this design makes a node do that: the producer always builds head + 1, and the freeze adds no other rollback.
- **The consequence:** the removed header and the new one are two signatures by one validator at one height. That is the material of `DoubleSignEvidence`, the staking evidence type, which is slashable where staking slashing applies. The command states this before it runs and requires the flag.
- **Checked against the existing protections:**
  - **PoA block signing on `df502b53` has no persisted re-sign guard.** An ordinary operator rollback can already lead a validator to produce again at a height it produced before. This design does not change that.
  - **The durable signer proposed in #340** (dormant, not wired to any node) guards finality votes, not PoA headers. Its record lives outside the chain database, and the recovery rollback never touches it. It keeps refusing any vote at or below its last signed position; only its own recovery procedure moves that floor.

**The gate pin (PROPOSED).** A is pinned after the recovery rollback.

*Layout: 15 bytes, the integer little-endian like the freeze record and the ConsensusConfig record* (`RegistryGatePinV1`, `sumchain_wire::registry_ingress`; codec and vector in this PR, written by nothing):

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 7 | magic | `"RFGTv1\0"` = `52 46 47 54 76 31 00` (`REGISTRY_GATE_PIN_MAGIC`) |
| 7 | 8 | `gate_a`, u64 LE | A: the deleted freeze record's `gate_a`, or the configured A if that record was unreadable |

- **Key:** one `cf::META` row, `registry/freeze/gate/v1` (`REGISTRY_GATE_PIN_META_KEY`, provisional), outside the generic journal like the freeze record, and never hashed into a block. It is under the `registry/` namespace, which no other source file spells (`the_record_prefix_is_disjoint_from_every_state_key_family`), so it cannot meet another META key. It is disjoint from the freeze record's key, and neither key prefixes the other.
- **Written:** only by the explicit recovery rollback, in the **same atomic batch** that rolls back to T and deletes the freeze record.
  - `gate_a` is copied from the deleted record's bytes 7..15 when the record decodes, which is the A the node committed to.
  - For an unreadable record (allowed only with T below the configured A, see the refusals above), it is the configured A.
  - A second recovery rollback (a row written again at A, then removed again) rewrites the pin with the same A, because startup has already refused any other configured A.
- **Read at startup:** after the freeze-record comparison and before the node opens for blocks.
  - **Absent:** no constraint.
  - **Present:** `RegistryGatePinV1::decode_exact` must succeed: exactly 15 bytes and this magic. An unreadable pin **refuses start**, as an unreadable freeze record does; it is never treated as absent. Then the configured `registry_enabled_from_height` must equal `gate_a`.
  - **Refused:** a configured A that differs, or is unset, at any head. The message names the pinned A and the configured value, and says that only T_min, W and the governance threshold may change after a recovery rollback.
- **Removed by:** nothing. No command deletes it and no rollback touches it. It outlives the freeze record it replaced.
- **Interaction with the freeze record:**
  - while both exist (the node re-committed at its next publish at or above A), both hold the same A, because both are compared with the configured A;
  - the record holds the three values and `first_height`; the pin holds only A.
- **Why:** without the pin, a database below A would treat A as a future gate under the existing rules. The startup check would then auto-record a `GateReschedule`, and the activation-height check would permit it.
- **The resulting rule:** the recovery rollback permits a change to the three frozen values only. Every other configuration rule is unchanged.
- **LOCAL PROTOTYPE evidence (not the activation change's tests):** the unpublished prototype writes exactly these 15 bytes in the recovery batch, and its `an_ordinary_rollback_below_a_keeps_the_record_and_the_recovery_rollback_removes_it` checks the pin row in that batch and that a restart with a moved A is refused.

**Rollback below A.**
- **Ordinary operator rollback, or automatic reorg unwind, below A:**
  - the row stays;
  - startup still requires the frozen values;
  - the re-import from below A runs under them and does not rewrite the row.
- **This is the recommended rule; an ordinary rollback below A should not refuse.**
  - It is the tool for repairing state below A, and with the row kept it cannot change a frozen value.
  - Refusing it would remove that tool without adding protection.
  - Changing a value needs the explicit flag.
- **Recovery rollback below `first_height`:** removes the row and pins A, as above.

**Restart.**
- With the same values: the node runs.
- With any changed value: start is refused, and so is the acknowledgement.

**Single validator (n = 1): in scope for the deadlock analysis.**
- It commits at its own block A, with no peer needed, so there is no bootstrap deadlock. It produces on, restarts under the same values, and refuses changed values.
- Its recovery is the same rollback. It then produces again from T itself, re-signing every height the rollback removed. No other node produced those heights. The signed headers it already sent out are still `DoubleSignEvidence` material.
- A rule that committed only at a verified peer import would never commit here. One that also held back production until such an import would deadlock every chain at A.

**What the check does not do.**
- The check is local. It proves that this node keeps running the values it committed to at `first_height`.
- It does not prove that other nodes run the same values. That is P(h), in every root from A (§16 §0).
- Rollout compares the ConsensusConfig commitments and the effective values (§16 §5 item 5).

**Cases checked.**

Every test named in the last column is **LOCAL PROTOTYPE evidence (not the activation change's tests)**: an unpublished local activation prototype, run at a test-only A, with its startup check at engine construction. None of them is a test of this PR or of the activation change, which must run its own.

| Case | Commits | Outcome | LOCAL PROTOTYPE evidence (not the activation change's tests) |
|---|---|---|---|
| First proposer at A | at its own publish of A | bound to its values from A | `the_first_proposer_at_a_binds_at_its_own_publish` |
| First importer | at its first imported block ≥ A | bound to its values from that height | `the_first_importer_binds_at_its_import` |
| Single validator, or no peer | at its own block A | no deadlock; produces on | `a_single_validator_produces_through_a_plus_3_restarts_and_refuses_changed_values` |
| Restart, same values | unchanged | runs | `a_bound_node_restarts_with_the_same_values_and_refuses_changed_ones` |
| Restart or acknowledgement, a changed value | unchanged | refused | the same, and the single-validator test |
| Proposer with wrong values | at its own block A | peers refuse its block; recovery rollback, correct the values, re-sync; A re-signed only after that step | `a_mismatched_proposer_binds_is_rejected_and_recovers_through_the_explicit_rollback` |
| Importer with wrong values | never (root check first) | correct the values and restart | `a_mismatched_importer_never_binds_and_a_config_fix_plus_restart_recovers_it` |
| Snapshot restore at or above A | at the first publish after it | as for a first importer or proposer | not exercised |
| File-level backup restore | as in the backup | compared at start as usual | not exercised |
| Ordinary rollback below A | row stays | frozen values still required | `an_ordinary_rollback_below_a_keeps_the_record_and_the_recovery_rollback_removes_it` |
| Reorg unwind below A | row stays | frozen values still required | not exercised for the row |
| Recovery rollback below `first_height` | row deleted, A pinned | commits again at the next publish ≥ A; a moved A refused | `an_ordinary_rollback_below_a_keeps_the_record_and_the_recovery_rollback_removes_it` |

**Not exercised by the local prototype:** the node-startup wiring itself (the check ran at engine construction), the CLI command, a snapshot or backup restore, the row across a reorg unwind, logs, and behaviour over time.

### (b) How earlier blocks replay

- **Below A, unchanged.**
  - Roots are byte-identical to the base (`df502b53`); P and R are not computed.
  - `R<A>` makes any block with operation 8 or 9 invalid.
  - Existing governance operations read 0x0601 from the configuration, as today.
  - The freeze neither introduces nor removes the existing hazard: an acknowledged threshold change still re-executes earlier blocks with the new value.
- **From A, the frozen values.**
  - Every execution path uses them: import, production, reorg re-execution, resync and rollback re-import.
  - They are the configured values. Once the row exists, startup has proven them equal to it.
  - `effective(h)` is constant for h ≥ A, and so P(h) = P(A).
- **Reorg across A.**
  - The unwind restores the registry rows from the generic journal: register undo deletes the row, and disable undo restores Enabled (§16 §6).
  - The freeze row stays.
  - The new branch executes below A under today's rules, and from A with the frozen values.
- **Ordinary rollback below A.**
  - The row stays, and the configuration cannot change the frozen values ((a)).
  - Re-imported blocks below A run under today's rules, and from A with the frozen values again.
  - The node therefore reproduces the roots it computed before.
- **Recovery rollback below `first_height`** ((a)): it removes the row and pins A. The node then re-syncs with its corrected values, and its next publish at or above A writes the row again.
- **A node that has not reached A** can still change these values by acknowledgement. If its values differ from the network's, its root at A differs, and the root check refuses its blocks and the network's alike (§16 §3). The freeze does not move that detection earlier.

### (c) How a later coordinated change is introduced

A change to any frozen value after A is a new coordinated activation. No single node's acknowledgement can make it.
- **New gate B** (provisional name), with B > A, introduced by a new binary.
- **Configured values (threshold, T_min, W): a height-keyed entry under a new ConsensusConfig schema version** (unallocated):
  - the entry is `{effective_from: B, threshold_bps, T_min, W}`, with provisional ids;
  - `effective(h)` is the frozen value for A ≤ h < B, and the entry for h ≥ B;
  - P(h) folds `effective(h)`, and from that change every reader of 0x0601 routes through `effective(h)`.
- **The limits (amended 2026-10-26): a compiled, height-keyed schedule, never a ConsensusConfig entry.** Both limits are compiled constants (§16 §1.3), frozen at A like the configured values.
  - A change ships in the new binary as a compiled schedule: the old `REGISTRY_LIMITS` for A ≤ h < B, and the new value from B.
  - The size bound, the per-block cap and P(h) all read the schedule's value for h, on replay, reorg and resync. A binary that applied the new value below B would reproduce neither the historical roots nor the historical outcomes.
  - The handshake detects a different schedule through `consensus_limits`.
  - The freeze rows do not carry the limits, because they are compiled, not configured.
- **Freeze rows.**
  - The A row stays as it is: its values remain effective below B, and replay below B uses them.
  - The entry gets its own row of the same kind (provisional key `registry/freeze/v2`), written in the batch of the first publish ≥ B, under the same rules as (a).
  - From then on, startup compares both rows, and the acknowledgement refuses changes to either.
- **Height choice.**
  - B lies above every validator's head, plus the lead time (§16 §5 item 3).
  - An entry at or below a node's head, or at or below the `first_height` of its B row once that row exists, is refused at that node's start, as the passed-gate rule refuses a passed gate today.
- **The same-window upgrade rules** (§16 §5) apply unchanged:
  - ratify the entry and B;
  - set the declaration height strictly below B;
  - hold one stop-all / start-all window, with `acknowledge_schema_transition` to the new schema version, and `acknowledge-consensus-config` for the entry and gate B;
  - require equal evidence on every validator, including the effective values below B and from B;
  - keep the same stop conditions.

  The gate name B enters `activation_heights()`. Binaries with and without it therefore declare different protocol digests, and are refused at the handshake before B.
