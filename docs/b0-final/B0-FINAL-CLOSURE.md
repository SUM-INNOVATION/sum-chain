# B0-FINAL closure record — signed proof-system selection + frozen performance constants

Closure artifact for **SUM-INNOVATION/sum-chain#123** (B0: select proof system and freeze performance constants, or HARD FAIL). Machine-auditable companion: [`b0-final-closure.v1.json`](./b0-final-closure.v1.json), validated in CI by `tools/b0-pre-validator/tests/b0_final_closure.rs`.

This record applies the **frozen** B0-PRE protocol mechanically to the sealed official measurement. No threshold, workload, eligibility, or selection rule was changed after observing results; no new proof was run to produce it.

## Authority (complete, untruncated)

| Field | Value |
|---|---|
| Measurement head (sum-chain main) | `9cccaa5ee6e038fb9dcb45af44ecb3cbdc2f48c6` |
| Measured-source commit | `507281e21e95a6a98e3480e25e12d1baab586e07` |
| Measurement-tooling authority (Commit A) | `be3a5cb151b42689b31574691ec1641bb1278bbf` |
| Tooling path-set BLAKE3 | `e17877e38b5ada83f7d84b81bd25be0c3e1cd53e6a1a94fb555140371397a856` |
| B0-PRE spec hash | `e933e7325c2639a48d8e25f20746d0f8abc822dee9fcfa87c2e6cdec226cf2a2` |
| **Official deterministic seal (BLAKE3)** | `60ace32cc2775fd38c3a4b9ea81f49686121cdd25a38db7a5ca5a0f4580bd600` |
| VEC9 package id (BLAKE3) | `80ab5ecfbe7a24d96d02dad78db2e4aee712ea0b29a071c19893b0d83dd0f11b` |
| Records-derived guest set | `11d059c7dbc37b3d80f0a0c1fcaee96ad5e0ba1916ba08bdb0f37e1a7d76401a` |
| MIA / eligibility / canonical guest | `fe90a56c…6ad8` / `2a2804b0…3fe1` / `d72d98b5…03b2` |
| SP1/x86_64 fragment / RISC0/x86_64 fragment | `113958582e…3a65` / `b6090b05…8900` |

## Mechanical selection (frozen protocol, thresholds unchanged)

- **RISC0 — qualified and SELECTED.** measured verify-p99 = 3.2 ms.
- **SP1 — valid proof/identity/evidence, DISQUALIFIED on gates [3, 4].** measured verify-p99 = 212.1 ms.
- **No HARD FAIL** — exactly one stable candidate qualified.

Frozen gates (`b0-pre-protocol-v1.json` → `qualification_gates`): verify-p99 ≤ `75000000` ns (gate 3); aggregate = worst-arch-p99 × `max_accepted_proofs_per_block`(4) ≤ `300000000` ns/block (gate 4); reference envelope `2` cores / `4294967296` bytes. SP1: 212.1 ms > 75 ms → gate 3; 212.1 ms × 4 = 848.4 ms > 300 ms → gate 4. RISC0: 3.2 ms and 12.8 ms — both within budget. Therefore **RISC0 is the unique qualifier** (proven in `risc0_is_the_unique_qualifier_under_frozen_gates`).

Both cells: full-core proving (16c) + exact 2-core / 4 GiB verification (not inherited). Bilateral verification re-confirmed during closure: validator (`verify_sealed_import` + `verify_evidence`) == independent (`b0-pre-independent-verify`, from-scratch) on guest set and per-candidate verdicts. Negatives refused: VEC8 downgrade, allowlist tamper, and 10 records-authoritative negatives.

## Frozen constants — INCLUDED (the derivable performance subset)

Per the owner scope ruling on #123 (option (a)), B0-FINAL freezes **only** proof-system selection, directly measured performance limits, and capacity constants whose complete derivation is present in the frozen protocol + seal. Each constant, its value, unit, and source appear in [`b0-final-closure.v1.json`](./b0-final-closure.v1.json) `included_constants` (26 entries) and are checked against the committed protocol by the validator. Summary: `proof_system_id` = RISC0; frozen verification limits (`verify_p99_gate_ns`, `aggregate_verify_budget_ns_per_block`, `M`=4, reference 2c/4 GiB); measured `V_verify_cost` (RISC0 p99 = 3.2 ms); workload/model bounds (`max_output_tokens`=8, `max_cycles`=0, `state_object_max_bytes`=2761, `max_manifest_slots`=3, `output_manifest_max_slots`=256, `input_manifest_max_slots`=8, `max_d_model`=8, `max_seq_len`=8); fixed-point (`fixed_point_scale_log2`=8 ⇒ S=256); schema/workload versions (`schema_version`, `algorithm_version`, `softmax_variant_id`, `token_input_scheme_id`, `fixed_point_version`, `workload_arch_id`, `weight_schedule_version`=0 [version only], `output_manifest_schema_version`); model identity.

## Constants — EXCLUDED (not B0-FINAL outputs)

Per the same ruling, the following are **absent from the preregistered measurement output**, require different evidence (network-propagation / economic modeling), and are **assigned to their owners** (see `excluded_constants` + the cross-links on #123): economic schedules + reimbursements (`C_layer`/`C_tok`/`C_sel`/`C_emit`, `B_offer`/`B_commit`/`B_check`, reimbursements) → #130/#132; suspension/invite/reprovision/retention policy limits → #130/#133/#129; availability/ack/finality durations → #133/#129; beacon/DKG windows/caps/message limits → #127; topology/crypto-security/consensus-safety → #127/#126; wire/on-chain-verification limits (`public_input_limit`, `proof_byte_limit`, VK — reported-only, no universal frozen limit) → #125/#131.

**Closing B0 selects RISC0 and freezes only the derivable performance subset. It does not authorize placeholder economic, policy, or safety values, and it lifts no downstream implementation-prohibition gate.** The validator enforces INCLUDED/EXCLUDED disjointness + completeness over #123's full list and refuses any prohibited (economic/policy/safety) parameter as an included constant.

## Scope exclusion (machine-checkable)

`scope_exclusion` records `cryptographic_security` / `topology` / `dkg` / `consensus_safety` = `none_selected`, `security_floors` = `preserved`, and implementation-prohibition gates preserved. The validator refuses the record if any prohibited parameter appears among the frozen constants.

## Durable evidence

Published, content-addressed, read-back-verified GitHub release **`b0-final-evidence-60ace32c`** (tag → `9cccaa5ee6e038fb9dcb45af44ecb3cbdc2f48c6`), URL `https://github.com/SUM-INNOVATION/sum-chain/releases/tag/b0-final-evidence-60ace32c` (release id `380755330`):

| Asset | Size | SHA-256 | BLAKE3 |
|---|---|---|---|
| `b0-final-official-evidence.tar` | 3123200 | `fe18544a…a8b7` | `a904316e…c07f` |
| `b0-final-official-evidence-manifest.v1.json` | 7795 | `bf159c5c…cd03` | `e01a9f3f…2570` |
| `CHECKSUMS.txt` | 5010 | `d162e109…a1b3` | `7ff11b18…5ab8` |

The canonical manifest ([`b0-final-official-evidence-manifest.v1.json`](./b0-final-official-evidence-manifest.v1.json)) + [`CHECKSUMS.txt`](./CHECKSUMS.txt) are committed here; the multi-megabyte archive lives only in the release. The manifest lists all **18** official members (size + SHA-256 + BLAKE3 + type/role/candidate/arch) and the exact seal-derivation rule; the validator recomputes the seal from the committed member digests and requires `60ace32c…`.

## Non-authoritative note

Diagnostic and earlier packages are non-authoritative and are excluded from this record and the manifest. Tracked under sub-issue #194; #123 closes only after this PR merges and the final line-by-line audit passes.
