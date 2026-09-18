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

A fourth tag appears where the CONSUMER side has since been implemented:

* **[CONSUMER, DONE]** — the obligation is met, and the implementation and its
  test are named. Where a clause was left open because the producer could not
  settle it, the resolution is stated in place rather than in a footnote.

Tests named `producer/<name>` live in
`crates/storage/tests/application_journal.rs`; those named `state/<name>` in
`crates/state/tests/application_journal.rs`; those named `unit/<name>` in the
`#[cfg(test)]` module of `crates/storage/src/journal.rs`; those named
`reorg/<name>` in `crates/consensus/tests/reorg_execution.rs`.

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
* **Its own column family**, `application_journal`. The record is derived at the
  top of `publish`, before its own row is staged, so a journal never describes
  itself. That row is node-local undo data in the same class as the four above —
  not application state a reorg restores, but the record that says how to restore
  application state, which a reorg CONSUMES: the unwind deletes each block's row
  in the same batch that applies its restores. Any comparison of "families a
  block writes" against "families a journal records" must classify it that way or
  it is comparing undo data with state.

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

### 1.4 The activation gate

The journal has its OWN genesis parameter:

    ChainParams::application_journal_enabled_from_height: Option<u64>

It is deliberately not `compute_pool_enabled_from_height` or
`beacon_enabled_from_height`. Those two gate dormant CONSENSUS subsystems,
`Genesis::validate` rejects any `Some(_)` for them, and opening either changes
which state a block commits. Tying node-local undo enforcement to one of them
would have made a storage decision wait on a coordinated consensus activation.

It does **not** gate writing. `publish` writes a record for every block, with no
gate to leave unset (§7). It gates the height from and above which a REVERT must
find one, and above which this journal — not the four legacy diffs — is the
authoritative undo record.

* `None` (the default and the production rule) → `ActivationSource::ObservedFromChain`.
  The boundary is the lowest height for which this database holds a record. Not
  an "off" position: the first block a node publishes establishes it.
* `Some(h)` → `ActivationSource::Pinned(h)`. A uniform, operator-visible
  boundary for a deployment that wants every node to answer with the same number.

`ActivationSource::from_configured_height` is the single translation site; the
storage crate does not depend on the genesis crate, so the field arrives as the
`Option<BlockHeight>` it is.

Not consensus: the records are node-local, so two nodes disagreeing about this
value cannot fork on the difference — one of them refuses a reorg the other
performs.
[CONSUMER, DONE: `reorg/the_journal_activation_gate_is_its_own_and_leaves_the_dormant_gates_closed`.]

### 1.5 The ordering invariant, once the account commitment is open

    application_journal_enabled_from_height <= account_root_enabled_from_height

`ChainParams::account_root_enabled_from_height` folds account balances and
nonces into the authoritative block state root. From that height on, a node that
cannot RESTORE account rows during a reorg cannot agree about the root either:
it holds a state it can neither revert nor justify. The generic journal is the
only record that restores every family a block wrote, so it MUST be authoritative
from at or before the height the commitment starts.

Two rules, both enforced by `ChainParams::validate`:

* `account_root_enabled_from_height = Some(_)` with
  `application_journal_enabled_from_height = None` is **REFUSED**. `None` is not
  "always required" — §1.4 — it means OBSERVED FROM CHAIN, and what each node
  observes is its own first journalled height. That is a node-local number.
  Resting consensus output on it is how two honest validators come to hold
  different boundaries and find out at a reorg. Opening the commitment therefore
  forces the boundary to be CHAIN-DEFINED: written in the same genesis document,
  covered by the same genesis identity, read the same way by everyone, with
  nothing for an operator to interpret.
* A journal gate LATER than the account gate is **REFUSED**, naming the band.
  Heights in `[account_root, journal)` would commit account state to the root
  while their only undo record is the four legacy diffs.

Both `None` remains legal and is the production default: no commitment, no
requirement.

Checked at LOAD, not at the boundary. `Genesis::validate` calls
`ChainParams::validate`, so every genesis admitted through the authoritative
loader is consistent; `sumchain_node::node::Node::new` calls it too, because it
also accepts a `Genesis` built in code, and a node that boots happily on an
inconsistent pair and diverges tens of thousands of blocks later is the failure
this exists to eliminate.
[PRODUCER, TESTED: `genesis/the_account_commitment_cannot_open_over_an_observed_journal_boundary`,
`genesis/a_journal_gate_later_than_the_account_gate_is_refused`,
`genesis/the_legal_gate_orderings_are_admitted`,
`genesis/every_committed_genesis_satisfies_the_gate_ordering`,
`genesis/both_gates_live_in_the_genesis_document_and_round_trip`. Tests named
`genesis/<name>` live in the `#[cfg(test)]` module of `crates/genesis/src/lib.rs`.]

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

### 2.1 The uniqueness invariant, and what it settles

**A journal holds one NET entry per `(cf, key)`**: the value at the START of the
block, and the value the block finally left, however many times execution wrote
that key in between.

This is now VALIDATED rather than inherited from the producing type's shape.
`ApplicationJournal::bind` refuses a duplicate `(cf, key)` on the way in — it
will not merge two entries, because a merge would have to pick one of two
pre-images and neither is knowably the one the block started from — and
`decode_for`'s strictly-increasing check refuses one on the way back out.
[PRODUCER, TESTED: `unit/a_duplicate_cf_key_pair_is_refused_rather_than_merged`,
`unit/a_non_canonically_ordered_record_is_refused`,
`reorg/multiple_writes_to_one_key_produce_one_correct_net_undo_entry`]

It settles a real disagreement between the two sides. The producer proves a
TOTAL SORT over `(cf, key)` and has no application order to offer; the consumer
was written demanding "the order the block applied them", on the reasoning that
two mutations of one key inside a block are distinguishable only by application
order. Neither was wrong about its own producer — the four legacy journals are
append logs and really can hold a key twice per block.

The reconciliation is the invariant, not a choice between the two:

> If a block's records hold at most one entry per `(cf, key)`, then no two
> records of that block can interact, so every order over them replays to the
> same state, and a deterministic `(cf, key)` order is sufficient.

So `BranchJournal` producers DECLARE which case they are in, through
`JournalHeader::ordering`:

* `EntryOrdering::NetByKey` — the generic journal. `stage_branch_unwind`
  VALIDATES the uniqueness before relying on it; a duplicate is
  `UndoRefusal::DuplicateJournalKey`, not a merge. Replay order is then free.
* `EntryOrdering::ApplicationOrder` — the four legacy journals. Replayed
  last-first, because undoing two writes to one key in forward order leaves the
  intermediate value.

"Mutation application order" is therefore not required of this producer and is
not described anywhere in this contract as a property of its records.
[CONSUMER, DONE: `sumchain_state::reorg_undo::EntryOrdering` and the check in
`stage_branch_unwind`.]

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
[CONSUMER, DONE: every revert routes through it.
`sumchain_state::reorg_undo::ApplicationJournalReader` calls `load_for_revert`
per block and surfaces its `Err` as `JournalLookup::Unreadable`, which is a HALT
— never `Absent`, which a tolerant policy could swallow.
`StateManager::revert_pre_activation_block_state_diffs` takes a
`reorg_undo::PreActivationBlock`, a witness constructible only by classifying a
height against a resolved `JournalActivation` and only when that classification
returns `PreActivation`. Its `Ok(())` over four absent journals therefore
survives only below the boundary, and a post-activation block cannot be NAMED to
it at all — there is no refusal because there is no case. `ActivatedJournal` is
the path that governs those heights. Tests:
`state/a_post_activation_block_cannot_be_named_to_the_legacy_revert_path`,
`reorg/every_post_activation_record_fault_halts_the_reorg`,
`reorg/the_activation_boundary_decides_whether_an_absence_halts`.]

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

**The consumer's answer: there is no marker, because the HEAD is the marker.**

`execute_reorg` makes exactly two kinds of durable write, and every one of them
carries the head pointer:

1. ONE batch for the whole unwind — every block's restores, every consumed
   journal's deletion, the de-indexing, and the head reset to the ancestor.
2. One batch per adopted block, which is `publish`'s own single commit,
   carrying that block's head pointer.

A `WriteBatch` has no interior, so a reopened database names a head whose state
is fully applied: the old tip, the ancestor, or some prefix of the new branch.
`resume` reads that head, restores the accumulator from that block's own header —
the only place a chained accumulator is recoverable from — and does whatever
remains. Requirement 1 is met because the head is determined without inspecting
application rows; 2 is met vacuously, since there is no window for a marker to
describe; 3 is met because restores and the journal's own deletion are in the
same batch; 4 is met because the three head values are exhaustive and each maps
to one action.

Proven at four points rather than argued:
[CONSUMER, DONE: `reorg/a_crash_before_publication_leaves_neither_state_nor_journal`,
`reorg/a_crash_after_the_journal_write_finds_the_block_and_its_journal_together`,
`reorg/a_crash_during_reversal_leaves_every_journal_it_was_consuming`,
`reorg/a_crash_before_the_new_head_is_committed_resumes_from_the_ancestor`,
`reorg/an_unwind_interrupted_before_commit_reopens_on_the_old_branch_and_retries_cleanly`,
`reorg/an_apply_interrupted_between_blocks_resumes_on_the_committed_prefix`.]

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
[CONSUMER, DONE: **only this one, and never both.**
`sumchain_state::reorg_undo::ActivatedJournal` classifies each block by height
and consults exactly one record for it — the generic journal at and above the
boundary, the four legacy diffs below it. That needs no audit of what each
legacy diff covers, which is what made the question open: applying both would be
at best redundant, and "at best" is not a proof. Choosing per block needs no
proof.

The generic journal is AUTHORITATIVE and MANDATORY at and above the boundary. It
covers every family the block wrote, including the ones the four legacy journals
never did, so there is no family for which consulting a legacy diff could add
information. Missing, corrupt, mis-keyed, duplicate-keyed and
identity-mismatched records all HALT.

`BranchJournal::rows` still returns BOTH families' rows at every height. That is
deletion of undo data, not application of it: a post-activation block has legacy
rows too, the publisher still writes them, and leaving them behind would leave
undo records for blocks on no chain. Deleting a row that does not exist is a
no-op. Tests: `reorg/a_reorg_crossing_the_journal_activation_boundary_is_refused_whole`
(which keeps the per-block classification assertions the test made under its
former name, `a_reorg_across_the_journal_activation_boundary_decides_per_block`,
because those are still true — see §7.3 for what stopped being true),
`reorg/supply_state_converges_through_the_real_journal`,
`reorg/a_real_reorg_at_the_full_production_depth_survives_the_real_retention_floor`.]

### 7.3 Across it — the boundary is an IRREVERSIBLE CHECKPOINT

**A reorg may not cross the activation boundary.** A branch that reaches below
it while also holding blocks at or above it is refused whole, before a single
row is read or staged, as
`sumchain_state::reorg_undo::UndoRefusal::CrossesActivationCheckpoint`.

This reverses what this document said in an earlier revision, and the reversal
is the point, so it is stated rather than edited away.

The earlier rule was that a crossing range is classified per block — below falls
back, at-or-above is required — and that this needed no special case. The
classification is still exactly that, and `requirement_at` is still asked once
per block with that block's own height. What was wrong was the conclusion drawn
from it. Selecting the record answers *which record governs this block*. It
cannot answer *what restores the families no record covers*, and below the
boundary the only records are the four legacy per-subsystem journals, which
§11.1 records as knowingly incomplete: `cf::SUPPLY` is restorable from none of
them.

So the earlier behaviour unwound the upper blocks completely and the lower
blocks partially, committed both in one batch, moved the head, and returned
success. The rows the lower blocks wrote into uncovered families stayed applied
under a chain that no longer contained the blocks that wrote them — silently.

#### Why a checkpoint and not a backfill

The alternative was to backfill complete generic journals across the supported
pre-activation reorg window. That is not implementable here, and not merely
expensive.

A generic journal is the set of PRE-IMAGES of the keys a block wrote, captured
by the overlay while that block executed (§0, §10). For a block published before
the upgrade they were never captured. Reconstructing one means re-executing that
block from the state that preceded it — which is the state the node would have
to rewind to in order to obtain it, using the undo data the backfill is trying
to manufacture. The only non-circular route is replaying the chain from genesis
into a fresh database, which is a RESYNC; and a resynced node's journal history
starts at the bottom of its chain, so it has no boundary left to cross.
Backfill therefore collapses into either "impossible" or "resync", and shipping
half of it would be shipping the appearance of a guarantee.

#### What the checkpoint costs, and for how long

`plan_reorg` bounds the abandoned branch at `MAX_REORG_WALK = 4_096` blocks. So
once the head is 4,096 blocks past the boundary, no plan the engine will ever
build can name a block below it, and the checkpoint cannot refuse anything. It
is **self-extinguishing**. Finality shortens the window further, because
`plan_reorg` already refuses to walk at or below the finalized height.

Inside that window the cost is real: a deep reorg across the upgrade height is
refused, the node stops following the canonical chain, and the operator's
recovery is a resync. That is a bounded availability cost, and it is the price
of making the unbounded correctness cost unreachable. An operator who does not
want to pay it upgrades from a resynced database, whose boundary is genesis.

A reorg **wholly below** the boundary is NOT a crossing and is untouched (§7.1).
That is the shape an operator gets by pinning a boundary above the current head:
the chain has not activated over that range at all, and refusing there would
refuse every reorg on such a chain — a far larger claim than this one.

[CONSUMER, DONE: `sumchain_state::reorg_undo::crosses_activation_checkpoint`,
called first in `stage_branch_unwind` so no unwind can reach around it. Tests:
`reorg/a_reorg_crossing_the_journal_activation_boundary_is_refused_whole`,
`reorg/a_reorg_crossing_the_checkpoint_is_refused_by_the_real_reorg_driver`
(through `execute_reorg` over a real `plan_reorg` plan, asserting nothing is
written and the head does not move, and that the same switch succeeds once the
boundary sits at the foot of the branch),
`reorg/a_reorg_wholly_below_the_boundary_is_not_a_crossing`,
`reorg/the_checkpoint_stops_binding_once_the_head_outruns_the_engine_walk_limit`,
and through the engine itself —
`crates/consensus/tests/journal_activation_e2e.rs`'s
`a_crossing_reorg_is_refused_through_import_block`, where the branch arrives
over `PoAEngine::import_block`, fork choice picks it, and the switch is refused
with the node still on the branch it was on and the canonical height index still
naming its own block.]

### 7.4 Pruning

Pruning the journal column family raises the observed boundary, because it
removes the lowest records. That is correct rather than a hazard: a range that
has been pruned cannot be reverted anyway. If pruning empties the family
entirely, the observed boundary becomes unestablished and nothing is required —
stated here because it is the one way the observed rule degrades, and it is an
observation about a database with no journal history rather than a gate left
off.
[PRODUCER, BY CONSTRUCTION]

**Pruning is implemented, with a retention FLOOR — and it ships DISABLED.**
Read §12.1 before this paragraph: what follows is a correct retention policy
that nothing in the node currently runs, and §12 carries the disk figures an
operator needs in order to run without it.
`crates/storage/src/pruner.rs` prunes `application_journal` and `state_diffs`
below the SAME height, and that height is never closer to the head than
`UNDO_RETENTION_FLOOR = 4_096`, a copy of `sumchain_consensus::poa::MAX_REORG_WALK`.

The floor exists because `plan_reorg` will name a block within 4,096 of the head
on an abandoned branch, and post-activation that block's unwind HALTS without its
record — correctly, and as a self-inflicted outage. `PrunerConfig` may ask to
keep MORE undo data; it cannot ask to keep less, and a configuration below the
floor is raised to it rather than obeyed.

Both undo families are pruned to one depth on purpose: a reorg crossing the
boundary consumes both, and pruning them to different depths would leave a band
of heights revertible by one record and not the other.
[PRODUCER, TESTED: `the_undo_retention_floor_covers_the_deepest_reorg_the_node_will_plan`,
`a_configuration_below_the_floor_is_raised_to_it_rather_than_obeyed`,
`pruning_keeps_every_journal_whose_block_is_still_revertible`,
`an_unrecognisable_journal_key_is_not_deleted_on_a_guess` (all in
`crates/storage/src/pruner.rs`), `reorg/the_pruning_floor_covers_every_reorg_this_engine_will_plan`,
`reorg/a_branch_inside_the_reorg_horizon_still_unwinds_after_pruning`.]

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
* **At startup.** `journal::validate_startup(db)` is the gate, and
  `journal::refuse_downgrade(db)` is it under its old name. It returns `Err` if
  the effective watermark exceeds this binary's `FORMAT_VERSION_V1`.
  [PRODUCER, TESTED: `producer/a_binary_refuses_to_start_against_a_newer_record_format`]
  [CONSUMER, DONE: called from `sumchain_node::node::Node::new`, immediately
  after `Database::open_default` and before the state manager, consensus, RPC or
  the messaging backfill exist. Failing it fails startup.]

**Two watermarks, and the gate takes the higher.**

* the **scan** — `highest_stored_format_version(db)`, exact over the records
  present, reading seven bytes per record;
* the **stamp** — `persisted_format_high_water(db)`, a two-byte `META` row at
  `FORMAT_HIGH_WATER_META_KEY` written by EVERY publish in the same batch as the
  block.

The stamp exists because of §7.4. Pruning removes records, and a pruned database
can reach a state where the family is empty; the scan then says "nothing", and a
downgrade the records would have refused becomes silently permitted. The stamp
is not pruned, so it still refuses.
[PRODUCER, TESTED: `producer/the_format_watermark_survives_pruning_away_every_record`,
`producer/a_database_with_no_journal_history_starts_and_requires_nothing`]

A database with records but no stamp is not treated as a fault — that is the
legitimate shape of one published before stamping existed, and the scan covers
it.

### 8.1 The operational rule, and the procedure

**Once a node has published a block under a record format, it must not be run
against a binary that implements an older one. Downgrade after activation is
PROHIBITED.**

This is an operational prohibition, not advice, because the failure it prevents
is silent and late. An old binary meeting a new record cannot unwind the blocks
that record describes, and it finds out during a reorg — with the chain already
committed to unwinding, and no recovery but a resync.

Operators: a downgrade that trips this gate reports the stamped version, the
version found in records, and the binary's own, and refuses to start. The
supported responses are to run the newer binary, or to resync the node from an
empty database. There is no supported way to clear the watermark and proceed.

#### The watermark is opaque to the binary it protects against

The stamp is a two-byte big-endian row under one `META` key. There is no
envelope, no magic, and nothing self-describing. A binary that predates the
journal does not know `FORMAT_HIGH_WATER_META_KEY`, does not know
`cf::APPLICATION_JOURNAL`, and will not look for either: **nothing in this format
announces itself to a reader that is not already looking.**

So the refusal only ever fires on a binary new enough to contain this gate and
old enough not to implement the record format it finds. A downgrade that skips
back past the introduction of the journal entirely is outside what any check
here can see. This document says so rather than implying coverage it does not
have. (A partial column-family open may or may not be refused by the RocksDB
binding in use — that is version-dependent and is NOT relied on as a barrier.)
[PRODUCER, TESTED: `producer/the_format_watermark_is_opaque_to_a_binary_that_does_not_look_for_it`]

#### The supported upgrade, and where the rollback window closes

1. **Upgrade onto pre-journal history.** A database with no generic journal at
   all starts, requires nothing, and establishes no boundary. This is what an
   operator upgrading a live node is handed, and it is why the boundary is
   observed rather than hardcoded.
2. **Rollback BEFORE the first publish is SUPPORTED.** The upgrade alone writes
   neither a record nor a stamp. The database an older binary gets back is the
   one it handed over.
3. **The first publish CLOSES the window, permanently.** From that commit the
   database carries a record and a stamp. Rollback is prohibited from here.
4. **Pruning does not re-open it.** The stamp is not pruned, so a database whose
   records have all aged out still refuses.

[PRODUCER, TESTED: `producer/the_supported_upgrade_and_rollback_procedure_walked_in_order`
walks all four on real databases, in order, and requires the refusal to name the
operational rule and the resync.]

#### What an operator is left holding

A node that trips this gate does not start. It has not corrupted anything —
that is the point — but it is down until it is given a binary at or above the
stamped version, or resynced from empty. On a validator, budget for the resync:
there is no in-place repair, and there is deliberately no flag to override.

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

## 11. Points that were open, and where they stand

The first five were stated here rather than closed with an invented answer. They
are closed now, each by the side that owned it, and each is named with the
implementation and its test rather than declared done.

1. **Precedence between the generic journal and the four legacy journals during
   an unwind** (§7.2). CLOSED: only one, never both, chosen per block by height.
   `ActivatedJournal`. The audit the question waited on is not needed, because
   the two records are never both applied.
2. **The unwind marker protocol** (§6.2). CLOSED: there is no marker, because
   every durable write in a switch carries the head pointer, so the head IS the
   marker. Proven at four crash points.
3. **The height at which a future record format begins to be written** (§1.3).
   STILL A DEPLOYMENT DECISION, and correctly so — there is no `v2` yet. What
   changed is that the DEPLOYMENT now has a place to say it:
   `application_journal_enabled_from_height` (§1.4) pins the revert boundary,
   and a future format's write height is the same kind of declaration.
4. **Wiring `refuse_downgrade` into node startup** (§8). CLOSED: called from
   `Node::new`, and the watermark is now persisted as well as scanned so pruning
   cannot erase it. The operational rule is stated in §8.1.
5. **Pruning this family** (§7.4). CLOSED, with a retention floor equal to the
   deepest reorg the engine will plan.
7. **A reorg CROSSING the activation boundary** (§7.3). CLOSED, by reversing the
   earlier answer: the boundary is an irreversible checkpoint and a crossing
   reorg is refused whole. Per-block selection was never wrong about
   classification; it was wrong as a safety argument, because it cannot restore
   families no record covers. Backfilling generic journals across the
   pre-activation window was the alternative and is circular — it needs the undo
   data it is trying to manufacture — so it collapses into "resync".
8. **The ordering between the journal gate and the account-root gate** (§1.5).
   CLOSED: `application_journal_enabled_from_height <=
   account_root_enabled_from_height`, enforced at genesis load and at node
   startup, with `None` on the journal gate refused once the commitment is open.
9. **What reorg depth a node may claim** (§13). CLOSED as a stated requirement
   plus the API to answer it. A snapshot-restored node holds canonical state and
   no undo history and must advertise `0` until it has published blocks itself.
   The snapshot implementation is not this document's to change; §13.2 states
   what it owes.
10. **Pruning in production** (§12.1). CLOSED as a DECISION, not as an
   implementation: pruning ships disabled, and §12 carries the disk figures,
   the retained-set figures it would replace them with, and the monitoring.

6. **Turning on `compute_pool_enabled_from_height` and
   `beacon_enabled_from_height`.** STILL NOT DONE, and still out of scope by
   design. Those are consensus gates for dormant subsystems; opening either
   changes which state a block commits and needs its own coordinated activation.
   The generic journal does not depend on them — it is written for every block
   regardless of whether either subsystem is live — and it now has its own gate
   (§1.4), so neither of theirs was repurposed.

### 11.1 What is still not proven

Stated because a clearly named gap is worth more than a silence.

* **The four legacy journals remain incomplete**, and below the activation
  boundary they are still the only undo record a block has. `cf::SUPPLY` is not
  restorable there by any means this branch adds.
  `reorg/the_subsystem_journals_do_not_cover_every_family_a_block_writes`
  measures exactly that, and is kept for that reason. What changed is the
  BLAST RADIUS: a reorg can no longer carry that incompleteness across the
  boundary (§7.3). A chain running wholly below the boundary still has it, and
  nothing here fixes that.
* **`Pruner` still has no production caller.** Nothing in `crates/node`
  constructs one and `PrunerConfig::enabled` is `false`. This is now a stated
  decision with numbers behind it (§12.1) rather than an omission, but the
  decision is "ship with pruning off", not "pruning is wired". An operator who
  turns it on gets the floor — `Pruner` is constructed and exercised at the real
  constant by `reorg/a_real_reorg_at_the_full_production_depth_survives_the_real_retention_floor`
  — but no loop in the node calls it, and the crash-safety of such a loop is
  neither written nor tested here.
* **`StateManager::revert_pre_activation_block_state_diffs` is DEAD in
  production**, and its unsafe case is now STRUCTURALLY unreachable rather than
  refused at run time. It takes a `reorg_undo::PreActivationBlock`, whose only
  constructor returns `None` for any height the activation calls `Required`, so
  the post-activation case has no expression. The reachability scan
  (`state/the_legacy_revert_path_has_no_production_caller_and_the_rollback_cli_has_its_own`)
  stays as a secondary tripwire, not as the guard.

  What that does NOT close: a caller holding a fabricated `JournalActivation` —
  `JournalActivation::pinned(u64::MAX)`, which the tests themselves use — can
  still classify everything as pre-activation. Closing that would need a
  capability the storage layer does not have. What is closed is the case the API
  was actually exposed to: a caller that did not think about the boundary can no
  longer reach the function at all.
* **`sum-node rollback` is FIXED**, and was the real defect of the two. It used
  to revert account rows from `cf::STATE_DIFFS` with its own open-coded loop,
  consulting neither the contract diff nor the generic application journal and
  never asking where the activation boundary was — so past activation it
  under-reverted, silently, while reporting success. It now runs
  `sumchain_consensus::reorg::plan_rollback` + `execute_rollback`, which is the
  reorg path's own unwind: one atomic batch, the per-block journal
  classification, the missing-record halt, the activation checkpoint, and the
  refusal to go deeper than this node's undo history reaches. Those live in the
  consensus crate rather than in `main.rs` precisely so tests can reach them.
  What remains unproven about it is the CLI GLUE: the tests drive
  `plan_rollback`/`execute_rollback` directly, and nothing executes the
  `sum-node rollback` subcommand end to end. The scan in
  `state/the_legacy_revert_path_has_no_production_caller_and_the_rollback_cli_has_its_own`
  pins that `main.rs` calls them and no longer reads `get_state_diff`.
* **`UndoRefusal::DuplicateJournalKey` and `UndoRefusal::JournalIdentityMismatch`
  are unreachable through the real producer.** `decode_for` refuses a repeated
  `(cf, key)` as non-canonical order, and a transplanted record as another
  block's, before the unwind sees either. Both variants stay, because
  `BranchJournal` is a trait and a producer that does not validate on the way in
  would reach them; but the tests that exercise those conditions against the real
  journal assert the DECODER's refusal, which is what actually fires.
* **The checkpoint is now exercised under real multi-validator fork choice**,
  both halves:
  `crates/consensus/tests/checkpoint_multi_validator.rs` stands up three
  validators taking turns as proposer, builds three DIFFERENT rival chains that
  fork below the boundary, and requires all three switches to be refused with
  byte-identical messages, the head unmoved and the canonical height index still
  naming the honest blocks — then requires the chain to keep advancing, the node
  that refused to produce again, and every block it publishes to still be
  journalled. A second test requires a switch wholly at or above the boundary to
  be PERFORMED, so "refuses crossing branches" and "refuses everything" are
  distinguishable observations.

  What that fixture has to remove to measure anything: **finality**.
  `plan_reorg` refuses to walk at or below the finalized height, and it does so
  BEFORE the checkpoint is consulted, so on a chain with an ordinary finality
  depth finality is what refuses a deep crossing switch and the checkpoint never
  gets a turn. The fixture puts finality out of reach on purpose. The corollary
  is that the checkpoint's practical importance is confined to the window where
  the activation boundary is DEEPER than finality — which is exactly the window
  right after an upgrade, and is the window it was designed for.

  Still not observed: what an OPERATOR does next. The recovery from a refused
  crossing switch is a resync, and that claim rests on the same reasoning as
  §8.1's rather than on a test.
* **Nothing measures the journal against a contract-heavy or NFT-heavy write
  set.** §12's figures come from transfer blocks. A block whose write set is
  dominated by large contract values would journal more per transaction —
  bounded by the same pre-image bytes it already charges, but the multiplier in
  §12.2 is a transfer multiplier and should not be read as a universal one.
* **A clean cherry-pick is not semantic compatibility.** This branch merges the
  journal, reorg and account-root work without conflict. That is a syntactic
  fact. Nothing here establishes that the journal and account-root seams agree
  about anything; §1.5 is the one place they are made to, and it is a load-time
  check on two numbers, not a proof about the state root.

---

## 12. Resource sizing, and the decision not to prune

Every figure here is MEASURED against real published blocks, by
`reorg/journal_bytes_per_block_are_measured_against_real_published_blocks` and
`reorg/a_real_reorg_at_the_full_production_depth_survives_the_real_retention_floor`,
and reproduced by running those tests with `--nocapture`. Nothing below is
derived from the record layout.

### 12.1 The decision: pruning ships DISABLED

`PrunerConfig::enabled` is `false` by default and nothing in `crates/node`
constructs a `Pruner`. That is not an oversight left unstated; it is the shipped
configuration, and it is chosen:

* A pruner that never runs cannot delete a journal a reorg still needs. The
  failure it could cause is a self-inflicted outage at the worst moment — during
  a switch, with the chain already committed to unwinding. The failure it
  prevents is running out of disk, which is visible in advance, has a metric,
  and is recoverable.
* Wiring a crash-safe pruning loop into the node — after canonical commitment,
  with its own interruption story — is a change with its own risk, in a crate
  none of this work's tests cover. Shipping it untested beside a correctness
  change would be worse than shipping neither.
* §7.4's retention policy is therefore a correct policy that nothing currently
  runs. It is not dead: `Pruner` is constructed and exercised at the real
  constant by the depth test, so an operator who enables it gets the floor.

The obligation this decision creates is the rest of this section: the numbers an
operator needs in order to run with pruning off, and the metrics that say when
that stops being viable.

### 12.2 Journal bytes per block, measured

At `ChainParams::default()` — `block_time_ms: 2000`, `max_txs_per_block: 1000`:

| block | journal record | entries |
|---|---|---|
| 0 transactions | **55 bytes** (the header; zero entries) | 0 |
| 1 transaction | **347 bytes** | 5 |
| 8 transactions | **956 bytes** | 12 |
| 32 transactions | **3,044 bytes** | 36 |
| 1,000 transactions (full block, extrapolated) | **~87,260 bytes** | ~3,000 |

The marginal cost is **~87 bytes per transaction**, taken across the 1→32 span
so the fixed cost cancels. A transfer journals five rows at one transaction
(sender, recipient, fee credit, and the rows those share) and about three per
transaction thereafter.

Against the **1 GiB `CANDIDATE_LIMIT_SCAFFOLD`**: a full 1,000-transaction
block's journal is 87 KB, which is **0.008%** of the ceiling — a headroom factor
of roughly 12,000×. §9 notes that journal bytes tighten the effective ceiling;
at these magnitudes no block reachable today is affected, and that is now a
measurement rather than an expectation.

### 12.3 Disk growth with pruning disabled

43,200 blocks/day at a 2-second target; 15.77M blocks/year.

| sustained load | per day | per year |
|---|---|---|
| idle (0 tx/block) | 2.3 MiB | **0.81 GiB** |
| 1 tx/block | 14.3 MiB | **5.1 GiB** |
| 8 tx/block | 39.4 MiB | **14.0 GiB** |
| 32 tx/block | 125.4 MiB | **44.7 GiB** |
| saturated (1,000 tx/block) | 3.51 GiB | **1.25 TiB** |

This is the generic journal family ALONE. It is additive to blocks,
transactions, receipts, indexes and the four legacy diffs, none of which this
work changes.

**Planning rule.** Budget the row for the transaction rate the deployment
actually expects, and treat it as monotonic: with pruning off the family never
shrinks. At 32 tx/block — a busy chain by this tree's standards — the journal
costs about 45 GiB/year, which is a disk line item and not a design problem. At
saturation it is 1.25 TiB/year, and a deployment planning to run there should
enable pruning rather than buy the disk.

### 12.4 What enabling pruning would cost instead

The retained set is bounded by the floor, so it is a CONSTANT, not a rate:

| sustained load | retained undo set at `UNDO_RETENTION_FLOOR = 4_096` |
|---|---|
| idle | 220 KiB |
| 1 tx/block | **1.23 MiB** (measured, not extrapolated) |
| 8 tx/block | 3.7 MiB |
| 32 tx/block | 11.9 MiB |
| saturated | 341 MiB |

The 1.23 MiB figure is read off a real 4,095-record retained set in the
production-depth test. So the whole question an operator is being asked is
"unbounded growth at the table in §12.3, or a fixed ceiling of a few hundred
megabytes at most" — and the reason the answer is not simply "prune" is §12.1:
the loop that would run it is not written or tested here.

### 12.5 Memory: a pre-image is charged twice

§9 states it; this measures it.
`reorg/a_preimage_is_charged_twice_and_the_factor_is_measured` publishes two
blocks whose write sets differ only in size and compares the pre-image bytes the
overlay captured against the journal's copy of them.

A one-transaction block captures 24 pre-image bytes and journals 347; a
sixteen-transaction block captures 384 and journals 1,652. The total a candidate
must have headroom for is **the overlay's capture plus the journal's copy**, and
growing the write set raised the charge by **4.6× the growth in pre-image bytes**
— 2× for the second copy, and the rest per-entry framing (family name, key,
length prefixes, tags), because that write set grew by ENTRIES.

§9's exact "2N" is a statement about growing ONE value by N bytes, where no
framing is added. Both are true and they are not the same measurement; this
document now says which is which rather than letting the smaller number stand
for both.

### 12.6 What to monitor

With pruning disabled, three signals, in the order they matter:

1. **`application_journal` bytes on disk**, against §12.3 for the deployment's
   load. It only ever grows. Alert on the trajectory reaching the volume's
   capacity, not on a fixed size — the rate is the number that predicts.
2. **Usable reorg depth** — `JournalActivation::advertisable_reorg_depth(head,
   MAX_REORG_WALK)`, which the node logs at startup. It should equal
   `MAX_REORG_WALK` on a node that has been running since its own activation, and
   less on one restored from a snapshot (§13). A node below the engine limit is a
   node that will REFUSE deep reorgs; that is safe, and it is also an outage
   waiting for the right fork.
3. **Record count against head height.** Above the boundary these move together:
   `publish` writes one record per block, unconditionally. A gap means records
   were deleted by something, and with pruning disabled nothing should be
   deleting them.

---

## 13. Reorg depth a node may honestly claim

The journal is node-local (§0): never hashed into a block, never folded into a
state root, never sent over the wire. That is what makes the format free to
change without a consensus event. It has a consequence that is easy to miss.

**A node that arrives by snapshot restore or fast sync has canonical state and
NO undo history.** Journals are not transmitted, and a pre-image cannot be
derived from a post-state, so there is no way to ship them alongside a snapshot.
On arrival such a node can revert nothing at all.

**`UNDO_RETENTION_FLOOR = 4_096` says nothing about it.** Retention is a promise
not to DISCARD undo history. It is never a claim to HAVE it. A node 200 blocks
past a restore holds 200 blocks of undo history, and the floor cannot raise that
number.

### 13.1 The rule

**A node MUST NOT advertise, report or configure a reorg depth greater than
`JournalActivation::advertisable_reorg_depth(head, MAX_REORG_WALK)`**, which is
`head - boundary + 1` capped at the engine's walk limit, and `0` on a database
with no journal history.

This is not a second claim to keep in step with the first. It is a READING of
the rule the unwind already enforces: `crosses_activation_checkpoint` (§7.3)
refuses any branch reaching below the boundary, so a reorg deeper than this
number is refused rather than mis-applied. The function exists so a node can SAY
the number before it is asked to prove it.
[CONSUMER, DONE: `JournalActivation::restorable_depth` /
`advertisable_reorg_depth`, logged by `Node::new` at startup. Tests:
`reorg/the_advertised_reorg_depth_is_the_depth_the_checkpoint_actually_allows`,
`reorg/a_node_with_no_journal_history_advertises_zero_until_it_publishes`.]

### 13.2 The restore floor, and the one thing a snapshot must do

A restored database and a genuine pre-journal chain look identical through the
journal family: both are empty. They need OPPOSITE treatment — the pre-journal
chain has the four legacy per-subsystem journals to fall back on, and the
restored node has nothing at all. So the ambiguity is removed by a row rather
than guessed at.

**`journal::record_undo_history_floor(db, height)` is the one call a restore
path must make.** It stamps `META[application_journal/undo_history_floor]` with
the height the snapshot left the database at. It is monotone: a later restore
may raise the floor, never lower it.

`JournalActivation::resolve` then raises the boundary to `floor + 1` — `+ 1`
because the restored block is the last one this node did not journal — and takes
the higher of that and whatever the source said, so a boundary pinned BELOW the
floor cannot claim undo history the restore did not bring. Everything downstream
follows without further plumbing:

* §7.3's checkpoint refuses any branch reaching below it;
* §13.1's advertised depth counts up from it;
* `sumchain_consensus::reorg::plan_reorg_within_undo_history` refuses a switch
  deeper than that at PLAN time, before the plan is acted on.

`crates/state/src/snapshot.rs` belongs to another workstream and is not changed
here. The requirement on it is exactly one line of code and these properties:

1. A restored node MUST NOT report a reorg depth greater than
   `advertisable_reorg_depth`. Immediately after a restore it is **0**.
2. There is no way to import undo history with a snapshot. The only way a
   restored node accumulates it is by PUBLISHING blocks itself, one journal per
   block.
3. A restored node therefore reaches the engine's full horizon exactly
   `MAX_REORG_WALK` blocks after the restore point, and not before.
4. The restore point is a hard floor: nothing below it is revertible by any
   record the node holds — the same statement §7.3 makes about the activation
   height, for the same reason.

**Until something calls `record_undo_history_floor`, a restored node is
indistinguishable from a pre-journal chain and is treated as one.** That is
stated rather than glossed: the enforcement is complete and tested on this side,
and it binds on the day the row is written.
[PRODUCER, TESTED: `producer/a_restore_floor_raises_the_activation_boundary`,
`producer/a_node_that_was_never_restored_is_unaffected_by_the_floor`.]
[CONSUMER, DONE: `reorg/a_snapshot_restored_node_refuses_a_switch_below_its_restore_point`,
`reorg/a_switch_deeper_than_this_nodes_undo_history_is_refused_at_plan_time`,
`reorg/a_long_catch_up_over_a_shallow_fork_is_not_refused`,
`reorg/a_restored_nodes_usable_depth_rebuilds_one_block_at_a_time`.]

### 13.2.1 Why the depth is checked against the ABANDONED branch only

`plan_reorg`'s `max_depth` bounds both walks, so passing the usable depth as
`max_depth` would also refuse a long CATCH-UP over a recent fork — a node coming
back online adopts far more than it reverses, and that is not the restricted
thing. `plan_reorg_within_undo_history` therefore keeps the walk budget at the
engine's limit and checks `ReorgPlan::depth()`, which counts abandoned blocks
alone.

The check applies only where the generic journal GOVERNS the head. Below the
boundary the chain has not activated over that range (§7.1) and the legacy
journals are the record; refusing there would refuse every reorg on a chain
whose boundary is pinned above its head.

### 13.3 The interaction with the ordering invariant

`application_journal_enabled_from_height <= account_root_enabled_from_height`
(§1.4) is what keeps 13.1 from being merely advisory once the account
commitment is open. Above the account gate the block state root covers account
rows; a node that cannot restore those rows cannot agree about the root either.
The ordering makes "the root covers account state here" imply "a generic journal
is authoritative here", and the checkpoint makes the region below it
unreachable by a reorg.

---
