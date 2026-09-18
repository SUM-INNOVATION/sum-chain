# The application journal contract

The normative reference for the generic per-block application undo journal. One
document, two implementations: the PRODUCER writes the records
(`crates/storage/src/journal.rs`, `crates/storage/src/overlay.rs`,
`crates/storage/src/candidate.rs` — branch `lane-b/journal`), and the CONSUMER
reads them and unwinds blocks with them (`crates/state/src/state.rs` and the
reorg driver — branch `lane-b/reorg`).

Where this document says MUST, it is binding on both sides. Every clause carries
one of three tags:

* **[PRODUCER, TESTED]** — implemented on the producer side and pinned by a named
  test.
* **[PRODUCER, BY CONSTRUCTION]** — implemented on the producer side and held by
  the shape of the code rather than by a test; the mechanism is named so the
  claim can be checked.
* **[CONSUMER]** — a declared obligation the producer does not implement and
  cannot. Where the producer supplies material for it, the material is named.

A clause tagged CONSUMER is not a claim that it works. It is a claim that the
producer has made it implementable and has not implemented it.

Tests named `producer/<name>` live in
`crates/storage/tests/application_journal.rs`; those named `state/<name>` in
`crates/state/tests/application_journal.rs`; those named `unit/<name>` in the
`#[cfg(test)]` module of `crates/storage/src/journal.rs`.

---

## 0. What the journal is, and what it is not

The journal records, for every key a block wrote, what that key held BEFORE the
block. It is derived from the pre-images `ApplicationOverlay::stage` captures on
the first write to each key, so its coverage is the block's write set by
construction rather than by a maintained list.

It is **node-local**. It is never hashed into a block, never folded into a state
root, never sent over the wire, and never read by consensus. Changing the record
format is a storage-format change. Two nodes holding different journal history
cannot fork on that difference.

It does **not** cover:

* Chain storage — `blocks`, `block_height`, `transactions`, `receipts`,
  `tx_by_sender`, `tx_by_recipient`, `meta`. These are staged by publication
  AFTER the journal is derived, and unwinding them is the reorg driver's own
  business. [PRODUCER, TESTED: `producer/the_journal_carries_execution_writes_only_not_the_blocks_canonical_rows`]
* Genesis. Genesis has no block and no candidate; its rows are committed
  directly and there is nothing to abandon.
* Snapshot restore and fast sync. Those replace state wholesale rather than
  applying a block.
* Blocks published before this database had journal history — see §7.
* The four legacy per-subsystem journals (`state_diffs`,
  `contract_state_diffs`, `compute_pool_state_diffs`, `beacon_state_diffs`).
  They are untouched. This journal is written beside them, not instead of them.

---

## 1. Key, record identity, and activation version

### 1.1 The key

    APPLICATION_JOURNAL[ height.to_be_bytes() (8) || block_hash (32) ] = record

via `sumchain_storage::schema::journal_key(height, block_hash)` — the same
function the legacy journals now use.

The height prefix is load-bearing: `crates/storage/src/pruner.rs` parses
`key[..8]` as a height to prune by range scan, and `JournalActivation` reads the
first key's height as the boundary (§7).

**Keyed by block hash, not height alone.** Issue #253 is open because
`compute_pool_state_diffs` and `beacon_state_diffs` key by
`height.to_be_bytes()` alone: two competing blocks at one height name the same
row, so importing the second destroys the first's undo record, and a later
revert of the first replays the second's mutations.

That class of bug is **not expressible** here, by three independent mechanisms:

* `AcceptedCandidate::publish` takes no key parameter. Both halves come from
  `self.block`, the single `&Block` the candidate was accepted against, which is
  also the block whose pre-images produced the record. There is no expression
  that pairs one block's undo data with another block's key.
  [PRODUCER, BY CONSTRUCTION: `publish` has no `Hash` or `BlockHeight` argument;
  `ApplicationJournal::bind` is `pub(crate)`.]
* `journal_key` requires a `&Hash`. There is no height-only overload to reach
  for.
  [PRODUCER, BY CONSTRUCTION]
* The record repeats its own `(height, block_hash)`, so a mis-keyed record is
  detectable at read time rather than merely improbable at write time (§1.2).
  [PRODUCER, TESTED: `producer/competing_blocks_at_one_height_leave_distinct_non_colliding_journals`]

### 1.2 The record header

Every record begins:

    magic           b"SUMAJ"        5 bytes
    format_version  u16 big-endian  2 bytes
    height          u64 big-endian  8 bytes
    block_hash                     32 bytes
    entry_count     u64 big-endian  8 bytes

Identity is in the RECORD, not only in the key. A reader therefore has fields to
compare, and key/record agreement is checkable rather than structurally
impossible.

Readers MUST validate that agreement.
`ApplicationJournal::decode_for(bytes, height, block_hash)` is the only decode
entry point and performs it: a record whose stored height or hash differs from
the key it was read under is an ERROR, never a journal.
[PRODUCER, TESTED: `unit/a_record_refuses_the_wrong_block`,
`producer/competing_blocks_at_one_height_leave_distinct_non_colliding_journals`]

### 1.3 Format version and activation

`FORMAT_VERSION_V1 = 1` is the only format that exists. A reader that does not
implement a record's version MUST refuse the record; it MUST NOT skip it, treat
it as empty, or guess a parser.
[PRODUCER, TESTED: `unit/an_unimplemented_format_version_is_refused_rather_than_guessed`]

A future `v2` is introduced by writing `format_version = 2` from an agreed
height. Records on both sides of that boundary remain individually
self-describing, so a mixed database needs no external record of where the
change happened — which is the property the version field buys, and the reason
it is in the record rather than only in a release note.

**The height at which a new format begins to be written is a deployment
decision, not a producer-side one.** This document does not invent one. What the
producer guarantees is that the decision is expressible without ambiguity: a
reader dispatches on the record it is holding.

---

## 2. Deterministic record ordering

Entries are serialized in ascending `(column family name bytes, key bytes)`
order, compared lexicographically, family first.

**The order is total.** In the overlay, pre-images live in
`HashMap<String, BTreeMap<Vec<u8>, Option<Vec<u8>>>>`. A family name appears once
— it is a `HashMap` key. Within a family, a key appears once — it is a `BTreeMap`
key. So no two entries of one block share a sort key, the sort has no ties to
break, and its result is a function of the entry SET alone. Nothing about
`HashMap` iteration order, insertion order, thread scheduling or allocation
survives it.
[PRODUCER, TESTED: `unit/the_sort_key_is_total_over_the_entries_of_one_block`,
`unit/insertion_order_does_not_reach_the_bytes`,
`producer/identical_block_content_produces_identical_journal_bytes` — two
independent databases, the same content staged in opposite orders, compared byte
for byte.]

The encoding itself is canonical: fixed-width big-endian length prefixes,
explicit tag bytes, no optional fields, no self-describing container whose
framing could vary.

`decode_for` re-checks the order and rejects a record whose entries are not
strictly increasing. Canonical form is therefore enforced in both directions:
identical content produces identical bytes, and bytes that are not in canonical
form are not a valid record of anything.
[PRODUCER, TESTED: `unit/a_non_canonically_ordered_record_is_refused`]

---

## 3. Absent-before versus value-before

Per entry:

    cf_len     u64 BE, cf bytes (UTF-8)
    key_len    u64 BE, key bytes
    before_tag u8   0 = ABSENT, 1 = VALUE
                    if 1: value_len u64 BE, value bytes
    after_tag  u8   0 = ABSENT, 1 = DIGEST
                    if 1: 8-byte tag

The distinction is a **tag byte on the wire**, not a convention about length. An
empty stored value is a legitimate value in several families here — presence-only
index rows store `&[]` — so "zero bytes" cannot stand in for "no row".

* `before_tag = 0` (ABSENT): the key did not exist. Undo MUST **delete** it.
* `before_tag = 1` with `value_len = 0`: the key held an empty value. Undo MUST
  **write an empty value**.

A consumer that writes a default or zero row where the tag says ABSENT is wrong
even when the difference is invisible through an accessor that returns a default
for a missing key. It is visible on disk, and it becomes a fork the moment
anything hashes stored rows.

Any `before_tag` other than 0 or 1 is an ERROR. There are no other defined
values and none will be added without a format version bump.
[PRODUCER, TESTED: `unit/absent_before_and_empty_value_before_are_different_records`,
`producer/absent_before_and_value_before_are_distinguished_and_each_undoes_exactly`,
`producer/a_deleted_key_records_its_prior_value_and_an_absent_after_image`,
`state/a_published_block_leaves_a_journal_that_restores_its_account_rows`]

The pre-image is the value at the START of the block, not an intermediate: the
overlay captures it on the first write to a key and never overwrites it.
[PRODUCER, TESTED: `producer/repeated_writes_to_one_key_journal_the_value_the_block_started_from`]

---

## 4. Current-value validation before reversal

Each entry carries an 8-byte **after-image tag**: a BLAKE3 digest, truncated,
over

    b"sumchain.application_journal.after.v1"
      || len(cf)    || cf
      || len(key)   || key
      || len(value) || value

or `after_tag = 0` when the block DELETED the key. The family and key are hashed
in, length-prefixed, so a tag cannot be transplanted between entries and still
verify.

The before-image is stored in full because it must be RESTORED exactly. The
after-image is a tag because it only has to be RECOGNISED. Eight bytes is a
consistency check against the node's own state, not a security boundary — these
records are node-local and there is no adversary positioned to construct a
collision.

**What the consumer checks.** Before applying any pre-image from a journal, the
consumer MUST verify that every key the journal names still holds what the block
left: `ApplicationJournal::check_current_matches_after(db)` recomputes each tag
from the committed value and compares.

**What it does when the check fails.** It MUST refuse the WHOLE unwind, apply
nothing, and leave every journal in place for retry. It MUST NOT apply the
subset of entries that still match. A failure means rows this journal describes
have moved on — another block was applied on top, or an earlier unwind half-ran —
and the entries that still match are not a safe subset, they are a partial
rewrite of state the journal knows nothing about.

The producer's implementation returns `Err` naming the first divergent
`(family, key)` rather than a count or a filtered list, so there is no shape in
which a caller could act on a partial result.
[PRODUCER, TESTED: `producer/a_row_that_moved_on_since_the_block_refuses_the_whole_unwind`]
[CONSUMER: calling it before applying, and treating its `Err` as a halt.]

`ApplicationJournal::undo_batch(db)` / `undo_into(batch)` build the restores as
one `WriteBatch` — `Absent` becomes a delete, `Value` becomes a put — and commit
nothing themselves, so the consumer folds them into whatever larger atomic batch
its reorg step needs.
[PRODUCER, TESTED: `producer/absent_before_and_value_before_are_distinguished_and_each_undoes_exactly`,
`state/consecutive_blocks_unwind_in_reverse_through_their_own_journals`]

---

## 5. Partial, missing and corrupt journals

Refusing loudly is a defined behaviour. Silently skipping is not, and is
forbidden at and above the activation boundary.

### 5.1 Corrupt or partial

`decode_for` is strict on every axis, and each failure is an ERROR that names
what was wrong — never a shorter entry list, never an empty journal:

| condition | behaviour |
|---|---|
| bad magic | ERROR at byte 0 |
| unimplemented `format_version` | ERROR (§1.3, §8) |
| stored `(height, hash)` ≠ key | ERROR (§1.2) |
| truncated at any offset | ERROR naming offset and record length |
| trailing bytes after `entry_count` entries | ERROR |
| `before_tag` / `after_tag` not in {0, 1} | ERROR naming the entry index |
| entries not strictly increasing | ERROR (§2) |
| column family name not UTF-8 | ERROR |
| length field exceeding `usize` | ERROR |

[PRODUCER, TESTED: `unit/truncation_at_every_length_is_an_error_not_a_short_journal`
(every prefix length from 0 to `len-1`), `unit/trailing_bytes_are_refused`,
`unit/bad_magic_is_refused_at_byte_zero`,
`unit/an_unimplemented_format_version_is_refused_rather_than_guessed`,
`unit/a_non_canonically_ordered_record_is_refused`,
`unit/a_record_refuses_the_wrong_block`,
`producer/a_corrupt_journal_halts_rather_than_reading_as_no_journal`]

A corrupt record MUST NOT be treated as a missing one. The two mean different
things: missing can be pre-activation history (§7), corrupt is always a fault.

### 5.2 Missing

`JournalActivation::load_for_revert(db, height, block_hash)` is the single
function both sides use, so "what happens when the journal is missing" has one
implementation rather than one per call site:

* **present** — decoded and validated. Returns the journal.
* **absent, height ≥ boundary** — ERROR. The revert halts, naming the block and
  the boundary. There is no defined way to unwind a post-activation block
  without its undo record: proceeding leaves the rows it wrote in place while
  the chain claims they are gone.
* **absent, height < boundary** — `Ok(None)`. Pre-journal history; the consumer
  falls back to the legacy per-subsystem journals (§7).

That third case is the only silence in this contract, and it is bounded by a
height the database itself establishes.
[PRODUCER, TESTED: `producer/a_missing_post_activation_journal_halts_and_a_pre_activation_one_does_not`,
`state/the_boundary_a_real_chain_establishes_is_the_first_height_it_published`]
[CONSUMER: routing every revert through it. `StateManager::revert_block_state_diffs`
today returns `Ok(())` whenever all four legacy journals are absent, at any
height, with no boundary in the decision. That is the silent-skip case this
section forbids post-activation, and closing it is a change to
`crates/state/src/state.rs` on the reorg branch, not here.]

### 5.3 Empty is not missing

A block that wrote no application row still gets a record, with `entry_count =
0`. An empty journal is the positive statement "this block touched nothing"; a
MISSING row cannot be told apart from a block published by a binary that wrote
no journals at all.
[PRODUCER, TESTED: `producer/a_block_that_wrote_nothing_leaves_an_empty_journal_rather_than_no_row`]

---

## 6. Crash markers and the recovery state machine

### 6.1 What the producer guarantees

The journal row is staged through the same `ApplicationOverlay` as every
canonical record and reaches RocksDB in the **same atomic `WriteBatch`** as the
block's state rows, block row, transactions, receipts, indexes and head
metadata. `ApplicationOverlay::into_batch` builds that batch; `publish` commits
it once.

Therefore, for an APPLY, there is exactly one crash-consistent resting state per
block:

> **a block's state rows are committed if and only if its journal is committed.**

There is no window in which a block is applied and its undo record is missing,
and none in which a journal exists for a block that was not applied. The
producer needs no apply-side marker because the atomicity of the batch is the
marker.
[PRODUCER, BY CONSTRUCTION: single `into_batch()?.commit()?` at the end of
`AcceptedCandidate::publish`; every staging failure returns before it.]
[PRODUCER, TESTED: `producer/a_block_whose_journal_exceeds_the_ceiling_publishes_nothing`
— a refusal leaves RocksDB byte-identical across every column family, with
neither canonical rows nor a journal row.]

An abandoned candidate — dropped after execution, or refused at acceptance —
writes nothing at all, journal included. The record is derived inside `publish`,
so no window exists in which undo data describes a block that did not happen.
[PRODUCER, TESTED: `producer/an_abandoned_candidate_writes_no_journal`]

### 6.2 What the consumer owes

The UNWIND is multi-step in a way the apply is not: it reverses N blocks, and
each step both restores rows and consumes the journal that told it how. That
needs a marker protocol, and **this document does not invent one** — the unwind
is the consumer's, and a protocol specified here without its implementation
would be a guess presented as a contract.

What the contract does bind:

1. An interrupted unwind MUST have exactly one defined resting state. On
   restart, the consumer MUST be able to determine, without inspecting
   application rows, whether an unwind was in progress and how far it got.
2. A marker announcing an unwind MUST be committed BEFORE any row that unwind
   restores, and cleared AFTER the last of them, in batches separate from the
   restores — otherwise the marker cannot distinguish "not started" from
   "finished".
3. A journal MUST NOT be deleted in a batch earlier than the one that applies
   its restores. Deleting it first makes the interrupted state unrecoverable:
   the rows are unrestored and the record that says how is gone. Restores and
   the journal's own deletion in ONE batch is the shape the existing revert path
   already uses, and it satisfies this.
4. On restart with a marker present, the consumer MUST resume or refuse
   deterministically. It MUST NOT continue forward from an unknown state.

These are satisfiable against §6.1 with no further producer support: the journals
for every block in the unwind range are present and self-identifying before the
unwind begins, and §4's check tells the consumer, per block, whether that block's
restores have already been applied.
[CONSUMER]

---

## 7. Reorgs before, after, and across the activation boundary

The boundary is `JournalActivation`, resolved from an `ActivationSource`. There
is no variant that disables the journal:

* `ObservedFromChain` (the production rule) — the boundary is the lowest height
  for which this database holds a record. One seek, since the key's first eight
  bytes are the height. A node that upgrades at height H publishes journals from
  H upward, so the lowest stored height IS where its journal history begins.
  This is right across an upgrade without anyone choosing a number; a hardcoded
  height cannot be, because too low demands journals for blocks an older binary
  published and too high leaves a window in which nothing is required.
* `Pinned(h)` — a boundary fixed by configuration, for a deployment that wants
  every node to agree on it rather than each observing its own. Configurable,
  not consensus: the records are node-local, so nodes disagreeing about the
  boundary cannot fork.

[PRODUCER, TESTED: `producer/the_activation_boundary_is_observed_from_the_chains_own_journals`,
`producer/a_pinned_boundary_overrides_the_observed_one`,
`state/the_boundary_a_real_chain_establishes_is_the_first_height_it_published`]

The WRITE side has no gate at all. `publish` writes a record for every block it
publishes; there is no parameter to leave unset, and no configuration under
which the journal is silently never written. This is the specific defect the
backlog census found in the other two journals —
`compute_pool_enabled_from_height` and `beacon_enabled_from_height` are `None`
in production, so neither record is ever written — and it is not reproducible
here.
[PRODUCER, TESTED: `producer/the_write_side_is_ungated_so_no_configuration_can_leave_it_unwritten`]

### 7.1 Entirely below the boundary

Every block in the reverted range is pre-journal history. `load_for_revert`
returns `Ok(None)` for each, and the consumer unwinds using the four legacy
per-subsystem journals exactly as it does today. Behaviour is unchanged; nothing
in this contract makes an old reorg newly fail.
[CONSUMER: the fallback. PRODUCER supplies the `Ok(None)` classification.]

### 7.2 Entirely at or above it

Every block in the range MUST have a journal. A missing one halts the reorg
(§5.2). The generic journal is authoritative for application rows; the legacy
journals may still be present and consumed for whatever they cover, but they are
no longer the only undo record and a family missing from all four is no longer
silently unreverted.
[CONSUMER: ordering the two, and deciding whether to apply both or only this one.
This is a genuine open question that the producer cannot settle: applying both a
legacy diff and the generic journal to the same key is idempotent only because
both restore the same pre-image, and confirming that for every subsystem is the
consumer's audit, not an assertion this document is entitled to make.]

### 7.3 Across it

A reorg whose range spans the boundary is handled **per block**, not per reorg.
`load_for_revert` is asked once per block with that block's own height, so the
classification is per-block and needs no special case: blocks below fall back,
blocks at or above are required. The unwind order — head first, downward — walks
from the required region into the fallback region, never the reverse.
[PRODUCER, BY CONSTRUCTION: `requirement_at` takes a single height and is called
per block.]
[CONSUMER: not batching the classification across a range.]

### 7.4 Pruning

Pruning the journal column family raises the observed boundary, because it
removes the lowest records. That is correct rather than a hazard: a range that
has been pruned cannot be reverted anyway. If pruning empties the family
entirely, the observed boundary becomes unestablished and nothing is required —
stated here because it is the one way the observed rule degrades, and it is an
observation about a database with no journal history rather than a gate left
off.
[PRODUCER, BY CONSTRUCTION]

The pruner does not yet prune this family. It prunes `state_diffs` only. Adding
`application_journal` to it is deliberate future work and is NOT done on this
branch: pruning is a retention-policy change, and this branch is the record
format and its producer.

---

## 8. Downgrade refusal once post-activation history exists

Once a newer binary has written records in a format an older binary does not
implement, that older binary cannot revert those blocks. Discovering this during
a reorg is discovering it with the chain already committed to unwinding.

Two layers:

* **Per record.** `decode_for` refuses a record whose `format_version` is not
  implemented. A downgraded binary meeting a newer record errors; it never skips
  it or reads it as empty.
  [PRODUCER, TESTED: `unit/an_unimplemented_format_version_is_refused_rather_than_guessed`]
* **At startup.** `journal::refuse_downgrade(db)` reads the version field of
  every stored record and returns `Err` if any exceeds this binary's
  `FORMAT_VERSION_V1`. `journal::highest_stored_format_version(db)` exposes the
  watermark directly.
  [PRODUCER, TESTED: `producer/a_binary_refuses_to_start_against_a_newer_record_format`]
  [CONSUMER / node boot: calling it. The producer supplies the check; nothing on
  this branch wires it into `sum-node` startup, because that is the node binary's
  boot sequence and not this package's.]

The watermark needs no separate marker row. It is derived from the journal
column family itself, so there is no state to write, to keep in sync, or to
forge. The cost is one scan of that family at startup, reading seven bytes per
record.

---

## 9. Charging

Journal bytes are part of the candidate's accounted cost. The encoded record is
staged through `ApplicationOverlay::put` inside `publish`, like every other
record publication writes, so `ApplicationOverlay::stage` measures it and checks
it against the candidate's ceiling. A block cannot evade the byte ceiling by
generating enormous undo data.

Staging happens strictly before `into_batch()?.commit()?`, so a journal that does
not fit aborts publication with nothing committed — no canonical row and no
journal row.

The measurement is exact: growing a pre-image by N bytes raises the minimum
publishing ceiling by exactly 2N — N for the overlay's capture of it, N for the
journal's copy. If the journal were staged into a side buffer outside the
accounting, the ceiling would grow by N alone.
[PRODUCER, TESTED: `producer/journal_bytes_are_charged_against_the_candidate_ceiling`,
`producer/a_block_whose_journal_exceeds_the_ceiling_publishes_nothing`]

This does tighten the effective ceiling for a block near it, and this document
says so rather than implying otherwise. The increase is bounded by the pre-image
bytes already charged plus fixed framing, and the ceiling in the tree is the
1 GiB `CANDIDATE_LIMIT_SCAFFOLD`, so no block reachable today is affected. When
that scaffold is replaced by the versioned consensus parameter it stands in for,
the parameter must be derived from write sets measured WITH the journal included.

---

## 10. Coverage

Coverage is derived, not declared. `ApplicationOverlay::journal_entries` walks
the pre-image map, which `stage` populates on the first write to every key
through `ExecutionView` — for whatever family the key lives in. There is no
allowlist, no `match` on a family name, and no place a new family could be
forgotten.

The proof iterates `ALL_CFS`, the registry the database is opened from, writes
one row into each through an `ExecutionView`, publishes, and requires the
journal's family set to equal `ALL_CFS` exactly. Nothing in the test names a
family, so a family added to the schema tomorrow is covered by it on the day it
is added.
[PRODUCER, TESTED: `producer/every_column_family_the_database_opens_is_journalled_when_a_block_writes_it`]

Derivation happens at the top of `publish`, before any canonical record is
staged. At that instant the overlay holds exactly what execution wrote and
nothing else — the only handle execution was ever given is `ExecutionView`,
`finish_execution` consumed the candidate, and neither `ExecutedCandidate` nor
`AcceptedCandidate` exposes the overlay — so separating application rows from
chain-storage rows needs no list: those rows do not exist yet.
[PRODUCER, BY CONSTRUCTION, and TESTED for its observable half:
`producer/the_journal_carries_execution_writes_only_not_the_blocks_canonical_rows`]

---

## 11. Open points the producer cannot settle

Stated rather than closed with an invented answer.

1. **Precedence between the generic journal and the four legacy journals during
   an unwind** (§7.2). Both restore pre-images for overlapping families. Whether
   the consumer applies both, or this one only, depends on an audit of what each
   legacy diff covers — which belongs to the reorg side.
2. **The unwind marker protocol** (§6.2). Specified as requirements, not as a
   design, because the unwind is the consumer's.
3. **The height at which a future record format begins to be written** (§1.3). A
   deployment decision. The format field makes it unambiguous once made; it does
   not make it.
4. **Wiring `refuse_downgrade` into node startup** (§8). The check exists; the
   boot sequence that calls it is the node binary's.
5. **Pruning this family** (§7.4). A retention-policy change, deliberately not
   made here.
6. **Turning on `compute_pool_enabled_from_height` and
   `beacon_enabled_from_height`.** NOT done, and out of scope by design. Those
   are consensus gates for dormant subsystems; opening either changes which
   state a block commits and needs its own coordinated activation. The generic
   journal does not depend on them — it is written for every block regardless of
   whether either subsystem is live — so "the journal is never written in
   production" is answered without touching them.
