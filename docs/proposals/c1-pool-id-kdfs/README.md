# UNRATIFIED DRAFT — NEW PROPOSAL. Not recovered §K bytes; not previously ratified; not consensus; do not implement until ratified

**C1 pool identifier derivations: `offer_bond_id`, `reservation_id`, `entitlement_id`**

- **Status: PROPOSAL, for explicit owner ratification.**
  - Nothing here is implemented, and nothing is consensus.
  - No crate, consensus, wire or storage source changes with this directory.
  - The Rust generator is a standalone package outside the workspace.
- **Base:** sum-chain `main` `2c27524279339ff29b6b8073b8027f1e4d217f60`.
- **Why it exists.** The original draft section §K of `docs/plans/c-series-wire-freeze.md` held these derivations. It was never committed, and an exhaustive search on 2026-10-16 did not recover it. These bytes are a **replacement**, not the lost text. If the lost §K is ever found and differs, nothing has implemented it; the ratified version of this document wins.
- **Frozen and unchanged:**
  - `job_id` and `unit_id`, adopted 2026-09-03 and frozen in `crates/sumchain-wire/src/compute_pool_graph.rs:39-75`, with KATs at `:485-500`;
  - the 72-byte `WorkItemRef` (`docs/design/C1-COMPUTEPOOL-OPS.md:36-48`).

  They appear below only as inputs.
- **`legacy_session_id_hash` is deferred:** its purpose is unknown, so no bytes are proposed for it.

## 1. Conventions

- **Hash:** `id = BLAKE3(tag ‖ fields)`, in plain hash mode with a 32-byte output. This is the shape of `job_id`/`unit_id`.
- **Integers:** little-endian, fixed width. Byte arrays are copied verbatim.
- **Tags:** ASCII `SUMCHAIN/POOL/<NAME>/v1` followed by a single `0x0a`, which is the only newline in the tag. This follows the frozen POOL family.
- **Fields:** every field is fixed-width, so each id has exactly one preimage length and parses uniquely after its tag.

## 2. Tags

| id | tag (ASCII) | tag (hex) | len |
|---|---|---|---|
| `job_id` (FROZEN) | `SUMCHAIN/POOL/JOB/v1\n` | `53554d434841494e2f504f4f4c2f4a4f422f76310a` | 21 |
| `unit_id` (FROZEN) | `SUMCHAIN/POOL/UNIT/v1\n` | `53554d434841494e2f504f4f4c2f554e49542f76310a` | 22 |
| `graph_definition_root` (FROZEN) | `SUMCHAIN/POOL/GRAPHDEF/v1\n` | `53554d434841494e2f504f4f4c2f47524150484445462f76310a` | 26 |
| **`offer_bond_id`** | `SUMCHAIN/POOL/OFFERBOND/v1\n` | `53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a` | 27 |
| **`reservation_id`** | `SUMCHAIN/POOL/RESERVATION/v1\n` | `53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a` | 29 |
| **`entitlement_id`** | `SUMCHAIN/POOL/ENTITLEMENT/v1\n` | `53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a` | 29 |

## 3. Preimage layouts

Offsets are within the preimage; the tag starts at offset 0.

### `offer_bond_id`: 63-byte preimage

| off | width | field | encoding |
|---|---|---|---|
| 0 | 27 | tag | §2 |
| 27 | 8 | `chain_id` | u64 LE |
| 35 | 20 | `sender` | address bytes: the transaction sender of `PublishBondedOfferV1` |
| 55 | 8 | `offer_seq` | u64 LE: the operand at `PublishBondedOfferV1` offset 9 |

- **Already fixed by merged text:** the inputs. `C1-COMPUTEPOOL-OPS.md:73-74` says the id is derived at execution from the chain id, the sender and `offer_seq`, and is never carried on the wire.
- **New:** only the tag and the field order. The order copies `job_id`: chain, then actor, then the actor's counter.
- **Excluded:** `payment_addr`. It is a per-offer operand; the id names the bond, and the bond belongs to the sender.

### `reservation_id`: 133-byte preimage

| off | width | field | encoding |
|---|---|---|---|
| 0 | 29 | tag | §2 |
| 29 | 32 | `job_id` | frozen id |
| 61 | 32 | `unit_id` | frozen id |
| 93 | 8 | `generation` | u64 LE |
| 101 | 32 | `offer_bond_id` | §3 |

- **What it names:** the capacity hold that one work item places on one offer.
- **Field order:** the work item first, in `WorkItemRef` order, then the offer. This is the order of the ratified assignment-score preimage.

### `entitlement_id`: 106-byte preimage

| off | width | field | encoding |
|---|---|---|---|
| 0 | 29 | tag | §2 |
| 29 | 32 | `job_id` | frozen id |
| 61 | 32 | `unit_id` | frozen id |
| 93 | 8 | `generation` | u64 LE |
| 101 | 1 | `entitlement_kind` | u8, §4 |
| 102 | 4 | `occurrence` | u32 LE, §4 |

- `beneficiary` and `amount` are **excluded**: the id names the event, not the payee (§6).

## 4. `entitlement_kind` and `occurrence`

### Allowed kinds

These are the values the dormant store already writes: `crates/state/src/compute_pool_store.rs:311-316`, `entitlement_kind_tag`. `AcceptReimb = 0` is pinned by `FROZEN_ROWS_DIGEST` (`:1602`).

| u8 | kind | occurrence |
|---|---|---|
| 0 | `AcceptReimb` | **must be 0** |
| 1 | `ReassignReimb` | counted, below |
| 2 | `ReprovisionReimb` | **must be 0** |
| 3–255 | reserved | **derivation refused** |

- A derivation with a kind outside {0, 1, 2}, or a nonzero `occurrence` for kind 0 or 2, is an error. Both generators implement the refusal, and `check.py` tests it.
- New kinds are appended only when their issue is ratified. For example, C3's `commit_verify` entitlement takes the next free value.

### What `generation` does and does not distinguish

**From the frozen semantics:**
- A work item is `(job_id, unit_id, generation)` (`compute_pool.rs:164-171`).
- C1 work-unit reassignment `ReassignWorkUnitV1` (`0xC108`) moves a unit `Assigned → Reassignable → Assigned` (`compute_pool.rs:340-349`). It carries the **same** `WorkItemRef` and does not change `generation`.
- **No generation-advance code exists on main.** `generation` is a free field today.
- **Re-provisioning is what creates a new generation.** The ratified retention-file bound counts one file set per generation: `job_max_retention_files = Σ_units (1 + slots) · max_generations + final` (#130 scope; `compute_pool.rs:571-592`). The #129 retention tracker key includes `generation`.
- **`ReassignReimb` is the per-reassignment reimbursement for a *retention file*** (a SNIP storage reassignment, #133 "Owner `ReassignChunksV2` (≤ bound)"). It is **not** a C1 work-unit reassignment. The ratified exposure bound reserves `job_max_retention_files · max_reassignments_per_file · reassign_reimb` (`compute_pool.rs:676-689`).
  - A work item has `1 + slots` retention files.
  - Each file can be reassigned up to `max_reassignments_per_file` times.
  - None of these reassignments changes `generation`.

### Occurrence rules

- **`AcceptReimb` (0): `occurrence = 0`.**
  - The event is the acceptance of the work item.
  - The accepted leaf is write-once per `(job, unit, generation)`: `accept_leaf` refuses a second one with `LeafAlreadyAccepted` (`compute_pool.rs:1074-1080`).
  - So the work item alone identifies the event.
- **`ReprovisionReimb` (2): `occurrence = 0`, with the work item of the generation the re-provisioning creates.**
  - Each re-provisioning creates exactly one new generation, so `generation` alone distinguishes the events.
  - **Prerequisite, not yet in code:** the generation-advance rule must be strictly `+1`, below `max_generations`, so that each `(job, unit, generation)` is created once.
- **`ReassignReimb` (1): `generation` does not distinguish the events, so `occurrence` is counted.**
  - `occurrence` is the 0-based number of `ReassignReimb` entitlements already registered for the same `(job_id, unit_id, generation)`, in execution order.
  - The counter is read and incremented in the same atomic block step that registers the entitlement, and is journal-reverted with it.
  - Overflow past `u32::MAX` fails the step.
  - The count is bounded by `(1 + slots) · max_reassignments_per_file`.
  - **This needs a new stored C1 row:** a per-work-item counter for `ReassignReimb`. No such row exists. Under the #215 rule (the stored encoding is the committed encoding) it must be in the v1 row set **before first activation**, or it needs a `…state.v2` digest. Its key and value bytes are **not** proposed here; they belong with the C2 reassignment executor.
  - **Retention files of the job's final output have no work item.** Their `+ final` term in the bound is job-scoped, so their reassignment reimbursements are out of scope here. They need their own tag later, not a placeholder `unit_id`.

## 5. Chain separation

- **`offer_bond_id`** carries `chain_id` (u64 LE) directly, at offset 27.
- **`job_id`** (frozen) carries `chain_id` at offset 21 (`compute_pool_graph.rs:47-66`). `unit_id` is derived from `job_id`.
- So **`reservation_id`** and **`entitlement_id`** are chain-bound through `job_id`. `reservation_id` is also chain-bound through `offer_bond_id`.
- The same inputs on two chains give unrelated ids. The vector `offer_bond_id/chain_id_2` differs from `offer_bond_id/base` only in `chain_id`.
- **Tags are distinct and prefix-free.**
  - Every POOL tag ends in its only `0x0a`. If tag A were a proper prefix of tag B, B would contain a `0x0a` before its last byte.
  - `check.py` also checks the three new tags against the frozen tags and against every byte-string literal under `crates/`. It found no equal or prefix-related literal.

## 6. Duplicate-payment reasoning

- **One event, one id.**
  - `entitlement_id` is a pure function of `(work item, kind, occurrence)`. It excludes `beneficiary` and `amount`.
  - Registering a second entitlement for the same event therefore produces the same id.
  - `register_entitlement` refuses an existing id with `DuplicateEntitlement` before any mutation (`compute_pool.rs:1088-1096`; test `duplicate_entitlement_id_rejected`, `:2052`).
  - The stored key is `[0x08] ‖ entitlement_id` (`compute_pool_store.rs:224-230`), so two rows for the same id cannot coexist.
- **Why the beneficiary is excluded.** If it were in the preimage, paying the same event to two different addresses would give two different ids, and both would pass the guard.
- **Per kind:**
  - **Kinds 0 and 2:** the id-level guard is complete, because one event maps to one work item and one id.
  - **Kind 1:**
    - The id makes each counted reassignment entitlement unique.
    - That one storage reassignment yields exactly one registration is enforced by the reassignment transition itself: it executes once and registers once, in the same atomic step.
    - The id alone does not enforce this.
    - An owner alternative is in §8.
- **Reorgs.**
  - Entitlement rows are C1 rows, written and undone through the per-block `ComputePoolStateDiff` journal (`compute_pool_store.rs:48-54`, `revert_block` `:1196`).
  - A reverted block's entitlements and counters disappear with it.
  - On the winning branch, the same event derives the same id, and only that branch's rows are canonical.
  - *Not wired yet:* the C1 store is dormant and not connected to the live reorg handler. That wiring is an activation prerequisite.
- **Precondition:** an entitlement row must not be deleted while its event can recur. Settlement should mark rows paid, not delete them. Otherwise the duplicate guard is lost. This is for C4 (#132) to decide.

## 7. PROPOSAL vectors (full inputs, preimages and outputs)

**TEST_ONLY inputs:**
- The `job_id`/`unit_id` inputs are exactly the frozen KAT inputs in `compute_pool_graph.rs:476-500`:
  - `chain_id = 1`;
  - requester/sender = bytes `0x01..0x14`;
  - `requester_nonce = 7`;
  - `client_job_salt = 32 × 0xAA`;
  - `unit_index = 0`.
- Plus `offer_seq = 7` and `generation = 1`.
- Two vectors pin byte order with distinct multi-byte values.

`vectors.json` is the machine-readable form of everything below.

#### `job_id/kat` (FROZEN on main; not part of this proposal)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `chain_id` | 8 | 1 | `0100000000000000` |
| `requester` | 20 | (see hex) | `0102030405060708090a0b0c0d0e0f1011121314` |
| `requester_nonce` | 8 | 7 | `0700000000000000` |
| `client_job_salt` | 32 | (see hex) | `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` |

preimage (89 B):
```
53554d434841494e2f504f4f4c2f4a4f422f76310a0100000000000000010203
0405060708090a0b0c0d0e0f10111213140700000000000000aaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
output (32 B): `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82`

#### `unit_id/kat` (FROZEN on main; not part of this proposal)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_index` | 4 | 0 | `00000000` |

preimage (58 B):
```
53554d434841494e2f504f4f4c2f554e49542f76310a8b974099e58a7005fd25
ef863283958351b785e6bf4fb127cf0de5ca4d5c4f8200000000
```
output (32 B): `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662`

#### `offer_bond_id/base` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `chain_id` | 8 | 1 | `0100000000000000` |
| `sender` | 20 | (see hex) | `0102030405060708090a0b0c0d0e0f1011121314` |
| `offer_seq` | 8 | 7 | `0700000000000000` |

preimage (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a0100000000
0000000102030405060708090a0b0c0d0e0f10111213140700000000000000
```
output (32 B): `98fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea`

#### `offer_bond_id/chain_id_2` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `chain_id` | 8 | 2 | `0200000000000000` |
| `sender` | 20 | (see hex) | `0102030405060708090a0b0c0d0e0f1011121314` |
| `offer_seq` | 8 | 7 | `0700000000000000` |

preimage (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a0200000000
0000000102030405060708090a0b0c0d0e0f10111213140700000000000000
```
output (32 B): `85181c227b1f434961fdbdb1f9a3050871b04c3592149c7c7175d09245d78851`

#### `offer_bond_id/byte_order` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `chain_id` | 8 | 578437695752307201 | `0102030405060708` |
| `sender` | 20 | (see hex) | `ffffffffffffffffffffffffffffffffffffffff` |
| `offer_seq` | 8 | 1234605616436508552 | `8877665544332211` |

preimage (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a0102030405
060708ffffffffffffffffffffffffffffffffffffffff8877665544332211
```
output (32 B): `5826d4c3a89fd1374b06f69b10a9531300786cee60f07a2e73ad1e815cde071e`

#### `reservation_id/base` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | 32 | (see hex) | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |
| `generation` | 8 | 1 | `0100000000000000` |
| `offer_bond_id` | 32 | (see hex) | `98fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea` |

preimage (133 B):
```
53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a8b9740
99e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1c
dd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000
000000000098fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8de
bea7a1a4ea
```
output (32 B): `1b251c9b56949e5b383b618003331f50b19acd98234ca7d73adef5fc66624c4f`

#### `entitlement_id/accept_reimb` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | 32 | (see hex) | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |
| `generation` | 8 | 1 | `0100000000000000` |
| `entitlement_kind` | 1 | 0 (AcceptReimb) | `00` |
| `occurrence` | 4 | 0 | `00000000` |

preimage (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b9740
99e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1c
dd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000
00000000000000000000
```
output (32 B): `7377c94d7668f3347e779acac43a4110951ee9c8423468c3172b6605d302da27`

#### `entitlement_id/reassign_reimb_occurrence_2` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | 32 | (see hex) | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |
| `generation` | 8 | 1 | `0100000000000000` |
| `entitlement_kind` | 1 | 1 (ReassignReimb) | `01` |
| `occurrence` | 4 | 2 | `02000000` |

preimage (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b9740
99e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1c
dd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000
00000000000102000000
```
output (32 B): `f0fc9e68ce981ce200d82502657b195179ba8bee94dc16d82fca4b149aac23c9`

#### `entitlement_id/reprovision_reimb` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | 32 | (see hex) | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |
| `generation` | 8 | 1 | `0100000000000000` |
| `entitlement_kind` | 1 | 2 (ReprovisionReimb) | `02` |
| `occurrence` | 4 | 0 | `00000000` |

preimage (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b9740
99e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1c
dd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000
00000000000200000000
```
output (32 B): `11d1849a4a75b45140cb801fe3d33ffac1d40a2680ebf1d164c1018b23de7b89`

#### `entitlement_id/reassign_reimb_byte_order` (PROPOSAL)

| field | width | value | bytes (hex) |
|---|---|---|---|
| `job_id` | 32 | (see hex) | `8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82` |
| `unit_id` | 32 | (see hex) | `3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662` |
| `generation` | 8 | 72623859790382856 | `0807060504030201` |
| `entitlement_kind` | 1 | 1 (ReassignReimb) | `01` |
| `occurrence` | 4 | 16909060 | `04030201` |

preimage (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b9740
99e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1c
dd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662080706
05040302010104030201
```
output (32 B): `66d885ec3397304cd5bf211e784aa73277d0aeb98baec256c3372f9a80d9105f`

### Refused derivations

- `entitlement_kind` 3: refused, kind not in {0, 1, 2}.
- `entitlement_kind` 255: refused, kind not in {0, 1, 2}.
- `entitlement_kind` 0 with `occurrence` 1: refused; `AcceptReimb` is one-time.
- `entitlement_kind` 2 with `occurrence` 1: refused; `ReprovisionReimb` is one-time.

## 8. Owner decisions this artifact does not make

1. **Ratify, or not, the three tags and layouts in §2–§3, and the kind map and occurrence rules in §4.**
2. **The `ReassignReimb` counter row (§4).** It is required, and it must land in the v1 row set before activation.
   - **Alternative:** bind the storage event itself instead of a counter, for example the retention file's root and its reassignment ordinal from SNIP state.
     - This needs no counter row, and a duplicate trigger for the same reassignment then collides on the id.
     - It needs a kind-1-specific preimage and a defined mapping from retention files to work items (C2 and #129).
3. **`reservation_id` as a storage key.**
   - Ratifying its bytes changes nothing stored today. The dormant ledger is aggregate, keyed `[0x05] ‖ offer_bond_id`.
   - Per-hold rows keyed by `reservation_id` would be a new C1 row type, so the same before-activation rule applies.
   - Decide this together with the open `reservation`/`MARGIN` semantics (#217 B7).
4. **The generation-advance rule** that `ReprovisionReimb` relies on (§4).
5. **The `ReprovisionReimb` amount source.** None of the seven ratified reimbursement fields in `ComputePoolParamsV1` (#215) is a re-provision field. This concerns the amount only; the id does not depend on it.
6. **Job-scoped reimbursements** (settlement, final check, final-output file reassignment) need their own tag once C2/C4 define them.
7. **Rejected alternatives:**
   - Deriving `entitlement_id` from the transaction hash loses the structural duplicate-event guard.
   - Renumbering the kinds to the seven parameter fields would change a frozen storage vector.

**Compatibility.**
- Nothing on sum-chain `main` `2c275242` or OmniNode `main` `bcf6c019` derives these ids. sum-chain has opaque newtypes only, and OmniNode's `pool-client` takes `offer_bond_id` as caller input.
- Ratifying them therefore changes no existing byte or golden vector.

**Unlocks:**
- derivation functions beside `job_id`/`unit_id`, with these vectors as append-only KATs;
- the C1 executor's offer, entitlement and hold steps;
- lookup by id over RPC;
- OmniNode deriving `offer_bond_id` itself.

## 9. Reproduce

```
python3 check.py           # Python checks (stdlib only)
python3 check.py --rust    # plus the Rust generator: cargo run --offline --locked
python3 generate.py > vectors.json   # regenerate (check.py compares byte for byte)
```

**What `check.py` checks.** It exits nonzero on any failure.
- The pure-Python BLAKE3 against the 35 official BLAKE3 test vectors (`test_vectors.json` at BLAKE3 tag 1.8.2).
- The frozen `job_id`/`unit_id` KATs and tag bytes, read from the code.
- Two generator runs are identical, and the output equals `vectors.json`.
- Every tag, field, preimage and output length; each preimage = tag ‖ fields; each output = BLAKE3(preimage).
- Tag prefix-freeness.
- The refusals.
- That every preimage and output appears in this README.
- With `--rust`:
  - byte-for-byte agreement with an independent Rust generator, which uses the workspace-locked `blake3` 1.8.2 crate and the frozen `sumchain_wire` functions;
  - two identical Rust runs.

`rust-generator/` has its own `[workspace]` table and lock file, so the sum-chain workspace and CI never build it.
