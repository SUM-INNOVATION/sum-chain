# C1 ComputePool-27 op family — byte tables (#213)

Byte-offset tables for all eight `TxPayload::ComputePool = 27` ops and the
ordinal-27 routing prefix. This closes #213, which was opened because the ops
existed only as prose/field-sketches with no byte layouts.

**DORMANT**: consensus bytes only; execution stays gate-closed
(`compute_pool_enabled_from_height = None`). Implemented in
`crates/sumchain-wire/src/compute_pool_wire.rs`; `CreateComputePoolJob` and the
job graph are specified separately in [C1-CREATEJOB-GRAPH.md](C1-CREATEJOB-GRAPH.md).

## Shared conventions (frozen, reused verbatim — no invention)

Every carrier follows the `beacon_wire` template: a 7-byte `MAGIC` (`"CPxxvN\0"`),
a `u16 schema_version`, fixed-width **little-endian** fields, and
`encode / try_encode / decode / decode_exact` where `decode_exact` rejects
trailing bytes via `Reader::finish`. Op discriminants OR the namespace `0xC100`
(#217 A2). Dispatch peeks the leading 7-byte magic.

Every carrier is **fixed-width** — there is no length prefix and no variable
field anywhere in the family, so each `LEN` is exact.

| op | magic | type | LEN |
|---|---|---|---|
| `0xC101` | `CPJBv1\0` | `CreateComputePoolJobV1` | 77 |
| `0xC102` | `CPOFv1\0` | `PublishBondedOfferV1` | 53 |
| `0xC103` | `CPACv1\0` | `AcceptWorkUnitV1` | 129 |
| `0xC104` | `CPDCv1\0` | `DeclineWorkUnitV1` | 81 |
| `0xC105` | `CPEXv1\0` | `ExpireWorkUnitV1` | 81 |
| `0xC106` | `CPCNv1\0` | `CancelJobV1` | 41 |
| `0xC107` | `CPASv1\0` | `AssignWorkUnitV1` | 81 |
| `0xC108` | `CPRAv1\0` | `ReassignWorkUnitV1` | 81 |

## The ordinal-27 routing prefix — `WorkItemRef`, 72 B

The work-item coordinate, embedded verbatim at absolute offset **`+9`** (right
after the 9-byte header) in every op that targets a work item — accept, decline,
expire, assign, reassign.

| off (in prefix) | size | field | notes |
|---|---|---|---|
| 0 | 32 | `job_id` | derived (§K); references an existing job |
| 32 | 32 | `unit_id` | derived (§K) from `job_id` + `unit_index` |
| 64 | 8 | `generation` | `u64` **LE**; carried in FULL |

Carrying `generation` in full is what makes a stale reference unambiguous: the
same `(job, unit)` at a different generation is different bytes and cannot be
substituted. `routing_prefix_offsets_are_frozen` pins the three offsets.

## Per-op byte tables

### `0xC101` `CreateComputePoolJobV1` — 77 B
See [C1-CREATEJOB-GRAPH.md](C1-CREATEJOB-GRAPH.md) for the full derivation.

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC = "CPJBv1\0"` |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 32 | `client_job_salt` |
| 41 | 32 | `graph_definition_root` |
| 73 | 4 | `unit_count u32 LE` |

### `0xC102` `PublishBondedOfferV1` — 53 B

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC = "CPOFv1\0"` |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 8 | `offer_seq u64 LE` |
| 17 | 16 | `offered_bytes u128 LE` |
| 33 | 20 | `payment_addr` |

`offer_bond_id` is DERIVED at execution from the chain id, the sender and
`offer_seq` (§K:288) — not carried, so a forged id cannot be presented.
`identity` (= the sender), `bond_locked` (a governance value) and the internal
`active` flag are not encoded.

### `0xC103` `AcceptWorkUnitV1` — 129 B

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC = "CPACv1\0"` |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 72 | `WorkItemRef` (routing prefix) |
| 81 | 32 | `commit_bond_id` |
| 113 | 16 | `accepted_bytes u128 LE` |

The winning `offer_bond_id` is NOT carried — it is derived from the assignment
state at execution, so an accept cannot name a different offer than the one the
assignment selected.

### `0xC104` / `0xC105` / `0xC107` / `0xC108` — work-item ops, 81 B each

`DeclineWorkUnitV1`, `ExpireWorkUnitV1`, `AssignWorkUnitV1`,
`ReassignWorkUnitV1` share one layout, differing only in `MAGIC` and op id:

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC` (`CPDCv1\0` / `CPEXv1\0` / `CPASv1\0` / `CPRAv1\0`) |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 72 | `WorkItemRef` (routing prefix) |

Sharing a layout is safe because the magics are pairwise distinct and each
decoder checks its own: one op's bytes are rejected by a sibling decoder
(`ops_do_not_cross_decode`), so an op can never be reinterpreted as another.

The authorization differences — a worker declines, expiry is permissionless
after timeout, assign/reassign are consensus-driven — are execution-layer rules,
not wire fields. For assign/reassign the winner (`offer_bond_id`, `payment_addr`,
score) is **consensus-computed** from pool state and the RATIFIED v1 (#223)
`beacon_output`, never submitter-provided:

```
score preimage = "OMNINODE-POOL-ASSIGN:v1:" ‖ beacon ‖ job_id ‖ unit_id
                 ‖ generation(u64) ‖ payment_addr ‖ offer_bond_id
```

### `0xC106` `CancelJobV1` — 41 B

| off | size | field |
|---|---|---|
| 0 | 7 | `MAGIC = "CPCNv1\0"` |
| 7 | 2 | `schema_version u16 LE = 1` |
| 9 | 32 | `job_id` |

Actor = the job requester (tx sender); refunds/burns are settlement concerns
applied at execution.

## Encoding rulings applied (owner, 2026-09-02)

- Ids that **reference** an existing entity are carried; **derived or
  assignment-selected** ids are not.
- Work-item identity is carried in FULL (generation included) by every op that
  targets a work item.
- **Economic amounts are governance/state values, not transaction operands**:
  bodies carry 32-byte bond *handles* and per-op operands (`offered_bytes`,
  `accepted_bytes`), never bond/reimbursement *amounts*.
- **Caller authorization** is validated from the transaction sender and state,
  never duplicated in the op bytes.
- **No numeric receipt codes** are allocated yet.

## Golden fixtures

`crates/sumchain-wire/tests/compute_pool_wire_golden.rs` is **append-only**
(the `beacon_wire_golden` convention): never edit an existing `*_HEX` constant,
only add new ones. It freezes all eight encodings, the `0xC101..=0xC108`
discriminants, every `LEN`, the routing-prefix offsets, magic distinctness,
dispatch round-tripping, and trailing-byte/truncation rejection.

**Architecture independence is structural**, not incidental: every field is
fixed-width and explicitly little-endian and no encoder consults host layout, so
the vectors are identical on x86_64 and aarch64. CI proves it by running the
suite on both (`build-test-clippy` and `build-test-clippy-aarch64`).
