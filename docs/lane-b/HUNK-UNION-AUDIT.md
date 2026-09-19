# Hunk-level union audit of the eight merged parents

Run: `tools/lane-b/hunk-union-audit.py HEAD <each of the eight track branches>`.
Raw output: `HUNK-UNION-AUDIT.txt`, alongside this file.

**323 lines were added by a parent and are not present at the head.** None is a
loss. Every one is classified below, and the classification is the deliverable —
a count on its own would say nothing, because the correct number here is not
zero.

## Why a symbol audit was not enough

`union-audit.py` resolves to one SYMBOL. Three defects on this branch lived
INSIDE symbols it reported present: two WIRING entries and two dormant-list
entries destroyed when a conflict opened in the middle of a tuple and the halves
were spliced; an `activation_heights` tuple wounded the same way; and two string
literals fused into one unterminated literal. In each case the enclosing item
was present and correctly named.

## A zero this audit produced once, which meant nothing

The first run reported `NOT FOUND 0` for all eight parents. It was vacuous: the
fork point came from `git merge-base HEAD <parent>`, which returns the parent
itself once the parent is an ancestor of the head, so every parent was diffed
against itself — zero files, zero lines, a clean result from measuring nothing.
The fork point now comes from the merge commit (find the merge that introduced
the parent, take its first parent, merge-base that with the parent), and the
tool refuses outright if a fork point resolves to itself rather than reporting a
zero. The bases it now derives — 4c105d8, 6e64dd5, 232ff27 — are the three
commits the tracks were actually branched from.

## Classification

| lines | where | class | evidence |
|---|---|---|---|
| 106 | `docs/lane-a/ACTIVATION-AUDIT.md` | CUMULATIVELY RECONCILED | census prose re-derived twice as tracks landed: 121→120 blocking after OC-2 closed, thirty-five→forty-eight movers after Class 4 and Class 8. The head's numbers are derived from the table and checked against the prose as SETS. |
| 54 | `crates/storage/src/snapshot_meta.rs` | INTENTIONALLY REMOVED | the module was deleted in `f41c50f` when its key was collapsed onto the journal's. `git cat-file -e HEAD:…` confirms absence. Its guarantees moved to `storage/one_row_records_the_history_floor_and_the_retired_key_is_gone`, which additionally scans production source so the retired key cannot return by hand. |
| 52 | `crates/state/tests/remediation_gates.rs` | CUMULATIVELY RECONCILED | two tracks each raised the gate count from twelve; the head is the union, seventeen, not either branch's figure. Both the WIRING table and the dormant list were verified to hold 17 entries over IDENTICAL sets. |
| 33 | `crates/storage/tests/application_journal.rs` | SUPERSEDED | the bridge test was rewritten when the bridge it pinned was deleted; the replacement pins a stronger claim (the retired key absent from all production source, not merely unwritten). |
| 19 | `crates/state/tests/execution_closure.rs` | SUPERSEDED | ledger commentary rewritten when the Snapshot class moved 2→1 and the write moved into `StateStore::import_accounts`. |
| 17 | `crates/state/src/nft_executor.rs` | SUPERSEDED | git kept TWO complete `NftGates` definitions, one per track; they were collapsed into one carrying all three gates. |
| 20 | six `*_executor.rs` + `lib.rs` + `docclass_executor.rs` | INTENTIONALLY REMOVED | `let _ = params;` stub bodies and their "Replace with…" comments, replaced by the real field reads in `18a6e5f`. Pinned by `every_remediation_gate_reads_the_field_it_names`. |
| 4 | `crates/rpc/tests/operator_visible_activation_and_history.rs` | INTENTIONALLY REMOVED | calls into the deleted `snapshot_meta`, repointed to `journal::record_undo_history_floor`. |
| 2 | `crates/state/src/docclass_executor.rs` | SUPERSEDED | `v_get_docclass_issuer` became `v_get_docclass_issuer_bounded(view, sender, gates.row_limit())` — the same read through Class 4's allocation bound. Strictly stronger. |
| 4 | `crates/state/src/lib.rs`, `allocation_bound_gate.rs`, `nft_routing.rs` | SUPERSEDED | the NFT export became a superset (adding `MAX_NFT_BATCH_MINT_REQUESTS`); two gate fixtures moved from field-by-field to `..CLOSED`, which is what stops them breaking each time a gate is added. |
| 12 | `legal_routing.rs`, `docclass_routing.rs`, `healthcare_routing.rs` | PRESENT (reflowed) | the assertions survive; rustfmt reflowed them when the twenty-nine authored formatting offences were corrected. Present as behaviour, not as byte-identical lines. |

| 4 | `crates/genesis/src/lib.rs` (Track A) | SUPERSEDED | two tracks independently found and repaired the same damaged gate declaration. The resolution kept the fuller three-bullet description from one and the scar note from the other, so four lines of the shorter description are absent as TEXT while their substance — the rows named, the subject-index behaviour, and a pointer to the accessor that reads the field — is present in the merged block. |

**DROPPED: 0.**

## Second run, after tracks A, B and C

Re-run against the three new parents: 1671 / 1089 / 2227 lines checked, **4 not
found, all from Track A and all the doc substitution above.** Zero from B and C.

The run also surfaced something the audit itself did not catch and did not need
to: `protocol_digest_census`, a test Track B wrote, FAILED at the merged head
because Track A had added `MAX_INDEX_KEY_TEXT_BYTES` and the census refuses to
pass until a limit-shaped constant is classified in one direction or the other.
It decides validity — it refuses an oversized jurisdiction code in Legal,
Finance and Property before the text becomes a raw column-family key — so it is
folded into the digest rather than excluded. One track's guard catching another
track's constant is the cross-track check working; neither track could have run
it, because neither had the other's code.

## What this audit does not cover

It matches by line content, so a line that survives with different wrapping
reads as absent and must be classified by hand — twelve of the 323 are exactly
that. It cannot tell a deliberate deletion from an accidental one; it can only
force each to be named. And it says nothing about lines a parent did NOT add:
behaviour removed by a merge without any parent having added a replacement line
is outside its reach, which is what the suite runs and the closure ledger are
for.
