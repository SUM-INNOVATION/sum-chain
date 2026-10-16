# C1 pool identifiers: `offer_bond_id`, `reservation_id`, `entitlement_id`

**RATIFIED 2026-10-16 (G1-1..G1-3).** The owner ratified the tags, field widths
and little-endian encoding below, the entitlement kinds 0/1/2 with 3–255
refused, and the occurrence rules, from the proposal at
`docs/proposals/c1-pool-id-kdfs/` (sum-chain `6fde77fa`).

These derivations **replace** the lost draft §K text; they are not a recovery
of it. `job_id` and `unit_id` are frozen separately
([C1-CREATEJOB-GRAPH.md](C1-CREATEJOB-GRAPH.md)) and unchanged; they appear
here only as inputs. `legacy_session_id_hash` is **deferred**: its purpose is
unknown.

Implemented in `crates/sumchain-wire/src/compute_pool_graph.rs`
(`offer_bond_id`, `reservation_id`, `entitlement_id`, `EntitlementKind`), with
append-only KATs in `crates/sumchain-wire/tests/compute_pool_ids_golden.rs`.
**DORMANT**: execution stays gate-closed (`compute_pool_enabled_from_height =
None`).

## Not ratified (decided separately, before anything depends on them)

- **The `ReassignReimb` counter row**: the stored count that determines a
  kind-1 `occurrence`. Its key and value bytes, and the alternative of binding
  the event to the retention file's root and reassignment ordinal instead. It
  must be in the C1 v1 row set before first activation, or it needs a v2 state
  digest. Until then `occurrence` is supplied by the caller.
- **Generation transitions**: the generation-advance rule (`+1`, bounded by
  `max_generations`) that kind 2 relies on. No code advances `generation`.
- **The reservation lifecycle**: whether `reservation_id` keys per-hold rows
  (a new C1 row type), together with the `reservation`/`MARGIN` semantics
  (#217 B7). Today's reservation ledger is aggregate, keyed by
  `offer_bond_id`; nothing uses `reservation_id`.
- **Every amount**, including where the `ReprovisionReimb` amount comes from
  (none of the seven ratified reimbursement fields covers it).
- **Job-scoped reimbursements** (settlement, final check, final-output file
  reassignment): their own tag later, never a placeholder `unit_id`.

## Conventions

- `id = BLAKE3(tag ‖ fields)`, plain hash mode, 32-byte output: the shape of
  `job_id`/`unit_id`.
- Integers are fixed-width little-endian; byte arrays are copied verbatim.
- Tags are ASCII `SUMCHAIN/POOL/<NAME>/v1` plus one `0x0a`, the only newline in
  the tag, so no POOL tag prefixes another. Every field is fixed-width, so each
  id has exactly one preimage length.

## Tags

| id | tag (ASCII) | tag (hex) | len |
|---|---|---|---|
| `offer_bond_id` | `SUMCHAIN/POOL/OFFERBOND/v1\n` | `53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a` | 27 |
| `reservation_id` | `SUMCHAIN/POOL/RESERVATION/v1\n` | `53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a` | 29 |
| `entitlement_id` | `SUMCHAIN/POOL/ENTITLEMENT/v1\n` | `53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a` | 29 |

## Preimage layouts

### `offer_bond_id` (63 B)

| off | width | field | encoding |
|---|---|---|---|
| 0 | 27 | tag | above |
| 27 | 8 | `chain_id` | u64 LE |
| 35 | 20 | `sender` | address bytes: the sender of `PublishBondedOfferV1` |
| 55 | 8 | `offer_seq` | u64 LE: the op's operand at offset 9 |

Never carried on the wire. `payment_addr` is not an input: the id names the
sender's bond.

### `reservation_id` (133 B)

| off | width | field | encoding |
|---|---|---|---|
| 0 | 29 | tag | above |
| 29 | 32 | `job_id` | frozen id |
| 61 | 32 | `unit_id` | frozen id |
| 93 | 8 | `generation` | u64 LE |
| 101 | 32 | `offer_bond_id` | above |

The capacity hold one work item places on one offer: the work item in
`WorkItemRef` order, then the offer.

### `entitlement_id` (106 B)

| off | width | field | encoding |
|---|---|---|---|
| 0 | 29 | tag | above |
| 29 | 32 | `job_id` | frozen id |
| 61 | 32 | `unit_id` | frozen id |
| 93 | 8 | `generation` | u64 LE |
| 101 | 1 | `entitlement_kind` | u8, below |
| 102 | 4 | `occurrence` | u32 LE, below |

`beneficiary` and `amount` are not inputs: the id names the event, not the payee.

## Entitlement kinds and occurrence

| u8 | kind | `occurrence` |
|---|---|---|
| 0 | `AcceptReimb` | **must be 0** |
| 1 | `ReassignReimb` | counted |
| 2 | `ReprovisionReimb` | **must be 0** |
| 3–255 | reserved | **refused** |

The stored entitlement row's kind tag is this same byte. The map is
append-only: a new kind takes the next free value when its issue is ratified.

- **`AcceptReimb` (0): `occurrence = 0`.** The accepted leaf is write-once per
  `(job, unit, generation)` (`accept_leaf` → `LeafAlreadyAccepted`), so the work
  item alone identifies the event.
- **`ReprovisionReimb` (2): `occurrence = 0`**, keyed by the work item of the
  generation the re-provisioning creates.
- **`ReassignReimb` (1): `occurrence` is the 0-based count of `ReassignReimb`
  entitlements already registered for the same `(job_id, unit_id,
  generation)`**, read and incremented in the same atomic block step that
  registers the entitlement and journal-reverted with it; overflow past
  `u32::MAX` fails the step. A C1 work-unit reassignment (`0xC108`) does not
  change `generation`, so `generation` cannot separate these events. The row
  holding the count is not ratified (above).

A nonzero `occurrence` for kind 0 or 2, or a kind outside {0, 1, 2}, is
refused by the derivation and by the strict kind decode.

## Chain separation

- `offer_bond_id` carries `chain_id` directly (offset 27).
- The frozen `job_id` carries `chain_id`, so `reservation_id` and
  `entitlement_id` are chain-bound through `job_id`, and `reservation_id` also
  through `offer_bond_id`.
- No POOL or REGISTRY tag equals or prefixes another (tested).

## Duplicate payment

- One event, one id: `entitlement_id` is a pure function of (work item, kind,
  occurrence). A second entitlement for the same event derives the same id,
  and `register_entitlement` refuses it (`DuplicateEntitlement`) before any
  mutation; rows are keyed `[0x08] ‖ entitlement_id`, so two cannot coexist.
- Leaving out the beneficiary is what makes this work: with it in the
  preimage, paying one event to two addresses would derive two ids.
- For kinds 0 and 2 the id-level guard is complete. For kind 1 the id makes
  each counted occurrence unique; that one storage reassignment registers
  exactly once is the reassignment step's own obligation.
- Reorgs: entitlement rows (and any future counter row) are C1 rows undone by
  the per-block journal. Wiring that journal to the live reorg path is an
  activation prerequisite.
- An entitlement row must not be deleted while its event can recur; settlement
  should mark rows paid, not delete them (C4, #132).

## Known-answer vectors

Inputs: the frozen `job_id`/`unit_id` KAT inputs (`chain_id = 1`, sender
`0x01..0x14`, `requester_nonce = 7`, `client_job_salt = 32 × 0xAA`,
`unit_index = 0`), so `job_id = 8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f82`
and `unit_id = 3adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662`;
plus `offer_seq = 7` and `generation = 1`. The byte-order vectors use distinct
bytes in every position of every multi-byte integer.

| vector | preimage (B) | output |
|---|---|---|
| `offer_bond_id/base` | 63 | `98fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea` |
| `offer_bond_id/chain_id_2` | 63 | `85181c227b1f434961fdbdb1f9a3050871b04c3592149c7c7175d09245d78851` |
| `offer_bond_id/byte_order` | 63 | `5826d4c3a89fd1374b06f69b10a9531300786cee60f07a2e73ad1e815cde071e` |
| `reservation_id/base` | 133 | `1b251c9b56949e5b383b618003331f50b19acd98234ca7d73adef5fc66624c4f` |
| `entitlement_id/accept_reimb` | 106 | `7377c94d7668f3347e779acac43a4110951ee9c8423468c3172b6605d302da27` |
| `entitlement_id/reassign_reimb_occurrence_2` | 106 | `f0fc9e68ce981ce200d82502657b195179ba8bee94dc16d82fca4b149aac23c9` |
| `entitlement_id/reprovision_reimb` | 106 | `11d1849a4a75b45140cb801fe3d33ffac1d40a2680ebf1d164c1018b23de7b89` |
| `entitlement_id/reassign_reimb_byte_order` | 106 | `66d885ec3397304cd5bf211e784aa73277d0aeb98baec256c3372f9a80d9105f` |

Complete preimages:

`offer_bond_id/base` (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a01000000000000000102030405060708090a0b0c0d0e0f10111213140700000000000000
```

`offer_bond_id/chain_id_2` (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a02000000000000000102030405060708090a0b0c0d0e0f10111213140700000000000000
```

`offer_bond_id/byte_order` (63 B):
```
53554d434841494e2f504f4f4c2f4f46464552424f4e442f76310a0102030405060708ffffffffffffffffffffffffffffffffffffffff8877665544332211
```

`reservation_id/base` (133 B):
```
53554d434841494e2f504f4f4c2f5245534552564154494f4e2f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb2662010000000000000098fc8ba3a47488bc5c3941691f57f4ea7915086d4057ade85aa8debea7a1a4ea
```

`entitlement_id/accept_reimb` (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000000000000
```

`entitlement_id/reassign_reimb_occurrence_2` (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000102000000
```

`entitlement_id/reprovision_reimb` (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266201000000000000000200000000
```

`entitlement_id/reassign_reimb_byte_order` (106 B):
```
53554d434841494e2f504f4f4c2f454e5449544c454d454e542f76310a8b974099e58a7005fd25ef863283958351b785e6bf4fb127cf0de5ca4d5c4f823adf1cdd6b0f0f01f89cc627622736537bfcc44564e09b5805cf475490bb266208070605040302010104030201
```

Refused: kind 3; kind 255 (and every value 3–255); kind 0 with occurrence 1;
kind 2 with occurrence 1.
