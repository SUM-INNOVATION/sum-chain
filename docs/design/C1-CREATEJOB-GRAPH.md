# C1 `CreateComputePoolJob` + job-graph codec (#227)

Byte-complete specification for the last C1 op. **DORMANT**: consensus bytes only;
execution stays gate-closed (`compute_pool_enabled_from_height = None`).

Implemented in `crates/sumchain-wire/src/compute_pool_graph.rs` (graph + pool
identifier KDFs) and `compute_pool_wire.rs` (`CreateComputePoolJobV1`, op
`0xC101`). Every rule below is executable — the module's tests re-derive the
limits and reproduce the identifier vectors.

## Owner rulings applied (2026-09-03)

1. **Separate graph-root domains.** Registry graphs and pool execution graphs have
   different semantics and must not be interchangeable, so each has its own
   versioned domain, with domain-confusion negatives.
2. **`retention_slots` lives in the graph**, not the op — it drives retention and
   funding, so the commitment must bind it. There is no second sizing list.
3. **No invented limits.** All bounds derive from the pre-existing 1 MiB C1 decode
   ceiling; the derivation is executable and reproducible.

Earlier rulings still in force: economic amounts are governance/state, never
operands; authorization comes from the transaction sender and state, never from
the op bytes; no numeric receipt codes are allocated.

## `CreateComputePoolJobV1` — op `0xC101`, 77 B

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC = "CPJBv1\0"` |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 32 | `client_job_salt` |
| 41 | 32 | `graph_definition_root` |
| 73 | 4 | `unit_count u32 LE` |

No `q`, no bonds, no sizing list, no requester field — see the rulings above.
`verify_graph()` binds a revealed graph: the root must match and `unit_count` must
equal the graph's (`Inconsistent` otherwise).

## Identifier KDFs (draft §K — adopted verbatim)

```
job_id  = BLAKE3("SUMCHAIN/POOL/JOB/v1\n"(21)  ‖ u64_le(chain_id) ‖ requester[20]
                 ‖ u64_le(requester_nonce) ‖ client_job_salt[32])
unit_id = BLAKE3("SUMCHAIN/POOL/UNIT/v1\n"(22) ‖ job_id[32] ‖ u32_le(unit_index))
graph_definition_root
        = BLAKE3("SUMCHAIN/POOL/GRAPHDEF/v1\n"(26) ‖ canonical_graph_encoding)
```

Neither id is carried on the wire. Execution recomputes `job_id` from the chain
id, the **transaction sender**, the sender's nonce and the salt, so an id cannot be
forged or minted for another requester.

**Tag families are per-domain and deliberate:** POOL is `\n`-terminated (§K, whose
vectors were computed independently with `b3sum 1.8.3`); REGISTRY is
`\0`-terminated (ratified #217 B2). The two `GRAPHDEF` tags are mutually
prefix-free and produce different roots over identical bytes.

**Golden vectors** (§K `TEST_ONLY`: `chain_id=1`, `requester=0x01..0x14`,
`nonce=7`, `salt=32×0xAA`, `unit_index=0`) — reproduced by the unit tests, which
therefore cross-check this implementation against an independent `b3sum`:

| id | value |
|---|---|
| `job_id` | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |

## `DependencyEdgeV1` — draft §F, 101 B (authoritative)

| off | size | field |
|---|---|---|
| 0 | 32 | `predecessor_unit_id` |
| 32 | 32 | `predecessor_output_manifest_identity` |
| 64 | 1 | `required_slot_kind u8` = `SlotKind` (`ResidualStream=0`, `KvCache=1`) |
| 65 | 4 | `required_slot_index u32 LE` |
| 69 | 32 | `required_state_object_identity` |

`required_slot_kind` is a **`SlotKind`, not an `ObjectKind`** (the rev. 4
correction). The implied object kind (`ResidualState=6` / `KvState=7`) is derived,
never encoded. Reserved/unknown discriminants are rejected (`BadEnum`).

The in-memory `RequiredInput` folds in: `predecessor` → `predecessor_unit_id`;
`pred_output_manifest_root` → `predecessor_output_manifest_identity`; the opaque
`SlotId` resolves to `(required_slot_kind, required_slot_index)`;
`required_slot_state_object_root` → `required_state_object_identity`.

## `GraphDefinitionV1` — the root's canonical preimage

```
MAGIC[7]="CPGDv1\0" ‖ schema_version u16 ‖ unit_count u32
  per unit, ascending positional unit_index (the index is NEVER encoded):
    retention_slots u64 ‖ edge_count u32 ‖ edge_count × DependencyEdgeV1(101)
```

`size(N, E) = 13 + 12·N + 101·E`.

### Canonical ordering

- **Units:** position **is** `unit_index`, so gaps, duplicates and reordering are
  structurally impossible.
- **Edges:** strictly ascending and unique under the field tuple
  `(predecessor_unit_id, predecessor_output_manifest_identity, required_slot_kind,
  required_slot_index)` — ids compared lexicographically, kind and index
  **numerically**. The order is defined over *fields*, not the encoded prefix,
  because `required_slot_index` is little-endian and a bytewise comparison would
  place `255` after `256`. Enforced on **both** encode and decode.
- **DAG by construction:** every edge must resolve to `unit_id(job_id, j)` with
  **`j < i`**. Backward-only references make positional order a topological order,
  so cycles are unrepresentable and no cycle search is needed; self, forward and
  dangling references are all `BadValue`.

### Derived limits — nothing invented

From the pre-existing ceiling `C1_DECODE_BYTE_LIMIT = 1 << 20 = 1_048_576`
(`crates/state/src/compute_pool_store.rs`):

| limit | value | derivation |
|---|---|---|
| `MAX_GRAPH_BYTES` | `1_048_576` | **given** — equals the existing ceiling |
| `MAX_UNITS` | `87_380` | largest `N` with `E = 0`: `13 + 12N ≤ CEILING`; `N+1` ⇒ `1_048_585 > CEILING` |
| `MAX_TOTAL_EDGES` | `10_381` | largest `E` at the minimum unit count that can host edges (`N = 2`, since backward-only edges leave unit 0 with none): `13 + 24 + 101E ≤ CEILING`; `E+1` ⇒ `1_048_619 > CEILING` |
| `MAX_EDGES_PER_UNIT` | `10_381` | a single unit may legitimately hold every edge (unit 1 → unit 0 across distinct slot indices), so a smaller cap would be **stricter than the ceiling implies**; set equal to the total |

Each is the exact mathematical maximum and **none is stricter than the ceiling**,
so no DoS benchmark is owed. The **authoritative** guard is the byte ceiling; the
count caps exist solely to reject a declared count *before* any allocation.
`derivation_arithmetic_is_exact` re-computes all four and asserts limit/limit+1,
so the derivation is executable and reproducible rather than asserted prose.

### Resource envelope (proved by tests)

- Input `≤ 1 MiB`, rejected **before** parsing when larger.
- Decode is `O(N + E)`; the decoded structure is bounded by the same ceiling.
- `verify_against_job` builds a `unit_id → index` map so predecessor resolution is
  `O(N + E)` instead of `O(N·E)` re-hashing: `≤ 32·87_380 = 2_796_160 B`
  (2.67 MiB) and `≤ 87_380` BLAKE3 hashes over a 58-byte preimage. Peak ≈ 3.7 MiB
  for a maximal input — a bounded, documented amplification.

## Malformed-input rejection

| condition | error |
|---|---|
| wrong magic | `BadTag` |
| `schema_version ≠ 1` | `BadFixedScalar` |
| short buffer | `Truncated` |
| bytes after the structure | `TrailingBytes` |
| input `> MAX_GRAPH_BYTES` | `LengthExceedsMax` (before parsing) |
| declared `unit_count` / `edge_count` / running total over a cap | `CountExceedsMax` (before allocation) |
| edges not strictly ascending | `NonCanonicalOrder` |
| duplicate edge | `DuplicateEntry` |
| `required_slot_kind ∉ {0,1}` | `BadEnum` |
| predecessor not `unit_id(job_id, j<i)` (self / forward / dangling / wrong job) | `BadValue` |
| revealed `unit_count` ≠ the op's, or root mismatch | `Inconsistent` |
| a registry graph root presented as a pool graph root | different root — the domains are prefix-free |
