# Lane A: cumulative deployment inventory

Every commit on `lane-a/p1-atomic-state` is marked NOT DEPLOYABLE. This file is
the running list of why, accumulated as each subsystem moves onto the execution
view.

Two things this file is *not*. It is not a list of defects introduced by the
migration: every entry below is inherited behaviour that the routing work
reproduced deliberately and pinned with a test, because fixing any of it changes
which transactions are valid or what bytes reach the state root, and that is
consensus work requiring separate activation. And it is not a bug backlog with
owners or dates — it is the standing answer to "why can this not ship yet".

Each entry names the test that pins it. A future fix must change that test on
purpose.

## Ceilings, and what the measurements below mean

Every allocation measurement in this document was taken with the candidate's
byte ceiling set to **4,096 or 8,192 bytes**. Those are TEST ceilings, chosen
small so that a refusal happens early and the allocation that precedes it can be
observed. They are not production values.

**Production uses a 1 GiB candidate ceiling**: `CANDIDATE_LIMIT_SCAFFOLD =
1 << 30` (`crates/state/src/executor.rs:269`, used at `:3074`).

So the ratios quoted per subsystem -- "3.2 MB allocated against a 4,096 B
ceiling" and similar -- demonstrate ONE thing and must not be read as
demonstrating another. What they demonstrate is **allocation before
accounting**: the whole value is built before `view.put` charges a single byte,
so the ceiling bounds what a block may COMMIT and not what one refused
transaction may ALLOCATE. That property is real at any ceiling.

What they do NOT demonstrate is a production memory ratio. Against 1 GiB the
same transaction is admitted rather than refused, and the risk changes shape:
it is unbounded attacker-controlled decoding and accumulation, not a small
ceiling being overshot by three orders of magnitude. An earlier summary of this
work quoted the test ratio as though it were production behaviour. That was
wrong, and the claim is withdrawn here rather than quietly restated.

Two further configuration values are part of this picture and are not
`ChainParams` fields: the DocClass schema validator activates at height 385,000
(`crates/state/src/schema_validator.rs:56-63`), and the contract gate at
8,900,000 has been open since roughly 2026-07-12 -- a "gated off" answer that
was correct in July is wrong today, and time-dependent gates must be evaluated
at the intended release height rather than at the height the note was written.

## Status by subsystem

| subsystem | commit | inventory |
|---|---|---|
| PolicyAccount | `855ec009` | transcribed in full below |
| Messaging + sponsored registration | `e293b03a` | transcribed in full below |
| Tax | `1c5494c` | transcribed in full below |
| Employment (SRC-88X) | `623e41f` (was `04eb5bc`) | transcribed in full below |
| Legal (SRC-85X) | `ddc4985` (was `026447f`) | transcribed in full below |
| Finance (SRC-89X) | `d570469` (was `0706862`) | transcribed in full below |
| Agreement (SRC-84X) | `2249ca8` | transcribed in full below |
| Property (SRC-86X) | this wave | transcribed in full below |
| Healthcare (SRC-87X) | this wave | transcribed in full below |
| NFT (SUM-721) | this wave | transcribed in full below |
| DocClass (SRC-80X/81X) | this wave | transcribed in full below |

All eleven inventories are transcribed here. The six that lived only inside a
commit message -- PolicyAccount, messaging, tax, employment, legal and finance
-- were copied from those messages and from nothing else. A pointer is not a
transcription, and listing them from memory would be worse than listing them
not at all, so where a message is thin, silent or circular the entry says so
instead of filling the gap.

Every entry in those six sections carries a tag naming its source commit and
its evidence class:

  * PINNING TEST -- the message names a test that pins the claim. The tag also
    records where that test is in this tree, because a name that no longer
    resolves is exactly the drift this file exists to expose.
  * MEASUREMENT -- the message gives measured numbers and no test name.
  * SOURCE-ONLY -- asserted in prose, with neither.

Where a message gives both a test name and measured numbers, the entry is
tagged PINNING TEST and the numbers stay in the claim.

Employment, legal and finance were reviewed to an earlier and weaker bar than
this wave, and their rows above carry the SHA they now have on this branch, not
the SHA of the parallel branch they were authored on. Three gaps in that earlier
review are closed by test-only additions on this branch: employment had no
close/reopen restart-parity test, and none of the three had a publication
byte-contract test of the kind property carries.

A fourth gap was open for most of this branch and is now closed: neither
employment nor legal shipped a per-mutation battery document, so their commit
messages' 52/52 and 56/56 were unauditable. Both batteries were re-run on their
own package trees and are recorded here:

  docs/lane-a/EMPLOYMENT-MUTATION-BATTERY.md    60 declared, 60 killed
  docs/lane-a/LEGAL-MUTATION-BATTERY.md         64 declared, 64 killed
  docs/lane-a/FINANCE-MUTATION-BATTERY.md       49 declared, 49 killed

Neither new count matches its claim, and neither was forced to. Both re-runs
first tried to recover the original evidence and both rejected it for the same
reason: the original drivers computed no hashes, so restoration could not be
proven and the logs could not be tied to any tree. Legal's recovered
specification was still usable for correspondence -- all 56 of its anchors
resolve exactly once in this tree and all 56 covering tests still exist under
their names -- so the claimed battery is reproduced verbatim inside the larger
set and all 56 are killed. Employment's could not be tied to any tree at all, so
its 52/52 is neither confirmed nor refuted; the new 60/60 supersedes rather than
corroborates it.

## PolicyAccount

**Entries: 3** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `855ec009`, "state: move policy accounts onto the execution view". The
byte-identical message is also carried by `cece16c`; `855ec009` itself sits on
no branch in this tree, and both resolve.

The first thing to record is an absence. This message carries NO
deferred-defect inventory. It has no "deferred defects", no "inherited risk"
and no equivalent section; it names no behaviour it reproduced without fixing,
and it pins no inherited semantics with a test. The status row that used to
read "in the commit message" pointed at something that does not exist in that
form. What follows is everything in the message that bears on whether this can
ship. It is not a defect list for policy accounts, and it should not be read as
one.

### The unfinished migration

  * 166 manifest rows remain across ten subsystems -- docclass 46,
    messaging 25 (plus the sponsored-registration row in `executor.rs`),
    nft 17, healthcare 16, property 14, agreement 12, finance 11, legal 10,
    employment 8, tax 6. "The application journal is still gated on that
    reaching zero."
    [`855ec009` | measurement]

### A committed read left in place

  * The submit-proposal RPC helper "derives a proposal id from the account's
    committed nonce while building a transaction for the caller. That was
    committed-only before this commit and is committed-only after it; the
    executor still recomputes the id at execution time against the nonce the
    candidate holds."
    AMBIGUOUS, and left unresolved here: the message names this deliberately
    ("because 'audit the committed twins' should not stop at counting them")
    but does not call it a defect, does not say it is reproduced deliberately,
    and attaches no test to it.
    [`855ec009` | source-only]

### A build that is not clean

  * "Build clean apart from sumchain-rpc's lib-test target, at the same three
    server.rs sites (9805, 9906, 10512) the routing commit left there." All six
    messages transcribed in this group name the same three sites and all six
    call them pre-existing.
    [`855ec009` | source-only]

Two things this commit FIXED rather than deferred, recorded so they are not
mistaken for open entries: the split commit point, where a wrapped policy
action staged into the block's candidate while the nonce increment and the
proposal's `Executed` status went straight to RocksDB, so "an abandoned block
kept the authorisation and lost the effect"; and the committed duplicate and
nonce reads that guarded it, which moved to the candidate in the same commit.

## Messaging + sponsored registration

**Entries: 2** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `e293b03a`, "state: move messaging onto the execution view".

Like PolicyAccount, this message carries NO deferred-defect inventory: no
section names a behaviour reproduced without fixing. It is the only one of the
six that fixes two defects outright inside the migration commit.

### The unfinished migration

  * "140 committed manifest rows remain across nine subsystems: docclass 46,
    nft 17, healthcare 16, property 14, agreement 12, finance 11, legal 10,
    employment 8, tax 6. Every one is a write an unaccepted block can still
    make, and the application journal is still gated on that reaching zero."
    [`e293b03a` | measurement]

### Replay protection that does not rest on the account nonce

  * "this dispatch arm does NOT advance the account nonce for most messaging
    operations -- only the two send paths do. The messaging sender nonce is
    this subsystem's own replay guard, which makes its candidate-correctness
    load-bearing rather than incidental."
    AMBIGUOUS, and left unresolved here: the message states this as a property
    that surprised its author, not as a defect, and attaches no test to it as a
    defect claim.
    [`e293b03a` | source-only]

Fixed here rather than carried forward, recorded so they are not read as open:
`is_admin` returned `bool` around `if let Ok(Some(admin))`, so a decode failure
or a storage error fell through to the GENESIS-configured admin and "no caller
could tell" -- `v_is_admin` returns `Result<bool>` now; and
`execute_sponsored_register_v1` asked `has_public_key` of the database, "so two
sponsored registrations for the same address in one block would both pass the
check and the second would overwrite the first".

## Tax

**Entries: 9** — one per numbered defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `1c5494c`, "state: move tax onto the execution view". The message's own
heading is "Inherited risk, none of it fixed by this commit"; it closes that
section with "Deployment remains blocked on all of it." Nine items: nine
numbered, then two the message calls resource items. The numbering below is the
message's own. None of the nine numbered items names a test.

### Missing authorization and no-op verification

  1. "Anyone can self-register an ACTIVE issuer with an arbitrary class,
     including TaxAuthority, and then issue claims."
     [`1c5494c` | source-only]
  2. "Claim-type registration, update and deprecation have no authority check."
     [`1c5494c` | source-only]
  6. "`VerifyProof` performs no verification: it charges the fee and reports
     success."
     [`1c5494c` | source-only]

### Overwrite and dangling-index paths

  3. "`IssueClaim` can overwrite an existing proof id, leaving the old subject
     index pointing at the replacement."
     [`1c5494c` | source-only]
  4. "`RevokeClaim` uses a subject nullifier as a proof id." Spelled out
     earlier in the same message: it "passes a `subject_nullifier` where the
     proof store expects a `proof_id`. Both are `[u8; 32]`, so it compiles and
     keys the wrong row."
     [`1c5494c` | source-only]
  5. "Proof deletion leaves the subject index dangling and permanently
     growing." Earlier: "`v_delete_proof` removes ONLY the proof row. The
     subject-index entry stays, pointing at a proof that is gone, exactly as
     the committed twin leaves it."
     [`1c5494c` | source-only]

Items 4 and 5 are the two the message separately calls "reproduced
deliberately, not fixed", and says of them: "Each now has a test that asserts
the behaviour in both directions, so changing either is a deliberate act with a
failing test attached rather than a silent correction inside a migration." IT
NAMES NEITHER TEST. The mutation summary likewise counts "2 preserved defects"
and names nothing. Marked rather than resolved: no test name can be attached to
these two from the message, so both stay source-only.

### Untrusted payload metadata

  7. "Disclosure and other variable-length tax payloads bypass the available
     schema validation and have no field-specific bounds."
     [`1c5494c` | source-only]
  8. "Both tax dispatch paths pass block timestamp 0, so status changes persist
     an incorrect `updated_at`."
     [`1c5494c` | source-only]
  9. "`TaxTxData.recipient` is ignored entirely."
     [`1c5494c` | source-only]

### Unrestricted allocation from untrusted input

  * The subject index. "`v_add_to_subject_index` decodes an accumulating
    `Vec<ProofId>`, searches it linearly, appends and reserializes -- per
    claim, unbounded across blocks. That is the committed algorithm, reproduced
    line for line. Routing neither introduces the growth nor bounds it." The
    resource item requires "an activation-gated bound with below/at/above tests
    and compatibility handling for existing oversized rows". Pinned at ONE
    measured size: ~20,000 ids, refused by a 4,096 B ceiling with a limit error
    AFTER reaching the index replacement, the candidate-visible index still
    byte-identical to the committed one, canonical state untouched; with room,
    all 20,000 existing ids preserved in order and one appended. The message
    states its own scope limit: "It cannot show that arbitrary input never
    reaches an allocator abort: the value is built before the ceiling is
    charged."
    -- a_640_kib_subject_index_is_refused_by_the_ceiling_without_canonical_change
    [`1c5494c` | pinning test | present in `crates/state/tests/tax_routing.rs`]

  The same section records a cost of the candidate model rather than of tax,
  and it is transcribed here because it is a deployment-relevant property and
  not a defect: "The candidate also holds both pre-image and replacement, so
  peak memory per row is higher than on the committed path -- a property of the
  candidate model this lane adopted, not of tax."

### Unbounded reads

  * "the tax RPC list methods, which scan whole column families into `Vec`s
    with no pagination."
    [`1c5494c` | source-only]

## Employment (SRC-88X)

**Entries: 11** — one per numbered defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `04eb5bc`, "state: move employment onto the execution view". The same
message, differing only in that its section headings were dropped, is at
`623e41f` on this branch; both resolve. Eleven deferred defects, numbered as
the message numbers them: "Found while migrating, reproduced EXACTLY, pinned by
tests that assert the current behaviour in both directions, and NOT fixed: each
one changes transaction validity, which is a consensus change and belongs in
separate activation-gated work."

### Missing authorization and no-op verification

  4. MISSING AUTHORITY RE-CHECK. "Only `CreateEmployment` and
     `CreateIncomeAttestation` require an active issuer. Every mutation of an
     existing credential or attestation checks only that the sender is the
     recorded issuer, so a suspended or revoked issuer keeps full control of
     everything it ever issued."
     -- a_suspended_issuer_can_still_revoke_but_not_create
     [`04eb5bc` | pinning test | present in
     `crates/state/tests/employment_routing.rs`]
  5. NO-OP VERIFICATION. "`UpdateIssuer`'s `issuer.issuer_address != *sender`
     cannot fire: the row is fetched BY `sender` and the store keys it by
     `issuer_address`, so the two are equal for every row this executor can
     write." The only one of the eleven the message states without a test.
     [`04eb5bc` | source-only]
  6. NO-OP VERIFICATION. "`VerifyProof` charges the fee, advances the nonce and
     verifies nothing -- not even that the proof exists."
     -- verify_proof_charges_a_fee_and_verifies_nothing
     [`04eb5bc` | pinning test | present in
     `crates/state/tests/employment_routing.rs`]

### Lifecycle paths and dangling indexes

  2. DANGLING INDEX ENTRIES. "`update_status` and `revoke` rewrite only the
     credential row; the three indexes built at creation keep pointing at a
     credential that is now `Ended`."
     -- revoking_a_credential_leaves_all_three_index_entries_behind
     -- an_update_and_a_revoke_rewrite_only_the_credential_row
     [`04eb5bc` | pinning test | both present, the first in
     `crates/state/tests/employment_routing.rs` and the second in
     `crates/storage/tests/employment_codec_parity.rs`]
  3. "The same for income attestations: revocation touches neither income
     index."
     -- a_revoked_attestation_keeps_its_key_and_its_two_index_rows
     [`04eb5bc` | pinning test | present in
     `crates/storage/tests/employment_codec_parity.rs`]

The message does not say which suite any of its named tests lives in. Two of
the three above are in the codec-parity suite, which asserts raw key and value
bytes at the storage layer rather than driving a transaction through dispatch.
Recorded, not resolved: the names all resolve, and what they assert is a
different instrument from the routing tests the other items name.

### Untrusted payload metadata

  1. PLACEHOLDER BLOCK TIMESTAMP. "Both dispatch arms pass a literal `0` where
     `block_timestamp` belongs, so every `updated_at` an employment status
     update writes is zero." The test "also shows the executor threads a real
     timestamp when given one -- the defect is in the call, not in the
     routing".
     -- every_status_update_records_a_zero_timestamp_through_dispatch
     [`04eb5bc` | pinning test | present in
     `crates/state/tests/employment_routing.rs`]
  9. "`EmploymentTxData.recipient` is ignored by every employment operation."
     [`04eb5bc` | source-only]

### Unrestricted allocation, and unbounded reads

  8. UNBOUNDED GROWTH. "The five index values are `Vec<[u8; 32]>` lists that
     are decoded, linearly searched, appended to and reserialized on every
     write, and nothing bounds them." Pinned "at one size ... which is a
     measurement of one point, not a bound".
     -- a_640_kib_employee_index_is_refused_by_the_ceiling_without_canonical_change
     [`04eb5bc` | pinning test | present in
     `crates/state/tests/employment_routing.rs`]
 11. UNBOUNDED QUERY COST. "The committed employment RPC query methods are
     unpaginated and take no limit. `employment_list_issuers` scans the whole
     issuer family and collects it; `employment_get_credentials_by_employee`,
     `..._by_employer`, `..._by_employee_address`, their `active` variants,
     `employment_get_income_attestations_by_subject` and `..._by_holder_address`
     each decode an ENTIRE index vector (defect 8) and then collect every
     referenced record into a second vector, and the `active`/`valid` variants
     build the full list before filtering it. Both memory and response size grow
     with the chain, with nothing in the request able to bound them."
     [`04eb5bc` | source-only]

### History and corruption handling

  7. CORRUPTION READ AS PRESENCE. "`SubmitProof`'s only read of the proof
     family is a `contains` that never decodes, so a corrupt row refuses the
     submission instead of erroring. Not 'read as absence', but not a decode
     either." The test "also shows the accessor itself does propagate".
     -- a_corrupt_proof_row_refuses_the_submission_rather_than_erroring
     [`04eb5bc` | pinning test | present in
     `crates/state/tests/employment_routing.rs`]
 10. "The employment event log is dead: `EmploymentEventStore` exists and
     `EmploymentEvent` has nine variants, but no operation emits one, so
     EMPLOYMENT_SYSTEM_EVENTS is never written by execution." The message says
     its row shape "is still routed through a shared builder and codec, and
     pinned by the codec parity suite", naming a suite but no test.
     [`04eb5bc` | source-only]

## Legal (SRC-85X)

**Entries: 10** — one per numbered defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `026447f`, "state: move legal onto the execution view". The message at
`ddc4985` on this branch is byte-identical to it; both resolve. Ten deferred
defects, numbered as the message numbers them: "All pre-existing, reproduced
EXACTLY, and pinned in both directions by tests in `legal_routing.rs`. Fixing
any of them changes transaction validity, which is a consensus change and
belongs in separate activation-gated work." Every one of the ten carries a test
name, which no other message in this group manages.

### Missing authorization and no-op verification

  1. "`ConsolidateCase` has NO authority check. Any funded account can attach
     one stranger's case to another's and move the second to `Consolidated`.
     Every other case operation checks `case.issuer_address == sender`."
     -- consolidate_case_has_no_authority_check
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
  2. "`TransferCase` has NO authority check either. Pinned against `CloseCase`,
     which does check, so the gap is shown to be specific."
     -- transfer_case_has_no_authority_check
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
  5. "`VerifyProof` verifies nothing. It charges the fee, advances the nonce,
     reads no proof and returns success -- for a payload that is not even a
     proof id. The answer is identical with a proof present."
     -- verify_proof_verifies_nothing_and_still_charges_the_fee
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]

### Overwrite and invalid-transition paths

  3. "`SupersedeOrder` has no authority check AND no duplicate guard: a
     stranger can supersede an order and, in the same transaction, OVERWRITE a
     different existing order by reusing its id. Pinned against `IssueOrder`,
     which does refuse a duplicate."
     -- supersede_order_overwrites_an_existing_order_without_a_guard
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
  4. "`SupersedeEvent` does not verify the new event's case exists, so it
     creates a case->event index entry under a case id that was never anchored
     -- a dangling index entry. Pinned against `RecordEvent`, which does
     verify."
     -- supersede_event_indexes_under_a_case_that_need_not_exist
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
  7. "A repeated `ConsolidateCase` is a paid no-op: the append is skipped when
     the relation is already recorded, and `updated_at` is only written inside
     that branch, so the row is byte-identical while the fee and the nonce are
     still charged."
     -- a_repeated_consolidation_is_a_paid_no_op
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]

### Untrusted payload metadata

  6. "Both dispatch arms pass a literal `0` where the executor expects
     `block_timestamp` (and `0` for `tx_index`), so EVERY status transition
     stamps `updated_at = 0`, overwriting the timestamp the anchor stored."
     -- a_status_transition_stamps_a_zero_timestamp
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]

### Unrestricted allocation from untrusted input

  9. "The three index families are unbounded accumulating `Vec<[u8; 32]>`
     values with a linear `contains` on every append. Routing reproduces this
     exactly; it neither introduces the growth nor bounds it." The deferred
     item itself names no test; the same message's coverage section names three
     and gives the measurement -- each index "measured at ~640 KiB (20,000
     ids): under a 4,096-byte ceiling the replacement is refused with a limit
     error WITH the primary row already staged, and both the candidate-visible
     and the canonical index are byte-identical to the seeded value; with room,
     all 20,000 existing ids are preserved in order ... and exactly one is
     appended", with the scope limit stated: "it measures ONE size and cannot
     show that arbitrary input never reaches an allocator abort, because the
     replacement value is built before the ceiling is charged."
     -- a_640_kib_jurisdiction_index_is_refused_by_the_ceiling_then_appended_to
     -- a_640_kib_case_event_index_is_refused_by_the_ceiling_then_appended_to
     -- a_640_kib_case_order_index_is_refused_by_the_ceiling_then_appended_to
     [`026447f` | pinning test | all three present in
     `crates/state/tests/legal_routing.rs`]

### History and corruption handling

  8. "The duplicate guards use `contains`, never `get`, so a CORRUPT row reads
     as present and refuses rather than erroring. Safe direction, and
     preserved: upgrading it would turn today's refusals into block-level
     errors."
     -- a_presence_guard_reads_a_corrupt_row_as_present_not_absent
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
 10. "`LegalEventStore` exists for `cf::LEGAL_SYSTEM_EVENTS` and no executor
     operation ever calls it, so the legal journal is empty on every chain.
     `LegalTxData.recipient`, `_tx_index` and `_tx_hash` are likewise accepted
     and ignored. Asserted empty after publication in
     `published_rows_satisfy_the_committed_scans`."
     -- published_rows_satisfy_the_committed_scans
     [`026447f` | pinning test | present in
     `crates/state/tests/legal_routing.rs`]
     The named test covers the empty-journal half of this item only. The
     message attaches no test to the ignored-field half, and none is assumed
     here.

## Finance (SRC-89X)

**Entries: 14** — one per numbered defect below. This line is the normative count;
the prose beneath it repeats it.

Source: `0706862`, "state: move finance onto the execution view". The same
message, differing only in that its section headings were dropped, is at
`d570469` on this branch; both resolve. "Fourteen. Each changes transaction
validity or RPC response shape, so a fix is a consensus or interface change and
belongs in separate activation-gated work." The numbering below is the
message's own.

NOT ONE OF THE FOURTEEN NAMES A TEST. Finance is the only subsystem in this
file whose deferred-defect list carries no test name at all, even though the
same message reports a 40-test routing suite and a 12-test codec-parity suite.
Every item below is therefore source-only except the one that carries measured
numbers, and not one of them can be checked against this tree by name. That is
not a claim that the tests are absent; it is the record that the message does
not let anyone find them.

### Missing authorization and no-op verification

  1. "Any sender can self-register as any finance issuer class.
     `RegisterIssuer` checks exactly one thing about authority -- that the
     profile names the SENDER. A key generated a second ago can register itself
     as a `CentralBank` and attest KYC in the same block."
     [`0706862` | source-only]
  3. "Update and revoke paths never recheck the issuer. Every `Create*`
     requires REGISTERED + ACTIVE + a permitted CLASS; every `Update*` and
     `Revoke*` checks only that the credential's stored `issuer_address` equals
     the sender. A REVOKED issuer keeps full control of everything it ever
     issued."
     [`0706862` | source-only]
  4. "`UpdateIssuer`'s `issuer.issuer_address != *sender` check is a no-op: the
     row is keyed by `sender`, so the field always equals it."
     [`0706862` | source-only]
  6. "`SubmitProof` has no authority check at all -- no issuer, no credential
     reference validation, no signature. Anyone who pays the fee writes any
     proof envelope."
     [`0706862` | source-only]
  7. "`VerifyProof` charges a fee, advances the nonce, and verifies nothing: it
     succeeds for a proof id that does not exist."
     [`0706862` | source-only]

### Invalid-transition, overwrite and fee-accounting paths

  2. "`UpdateIssuer` accepts any status the sender asks for, including `Active`
     from `Revoked`. That is precisely the guard `ReactivateIssuer` exists to
     enforce (`Suspended` only), walked around."
     [`0706862` | source-only]
  5. "A status change never rewrites the jurisdiction index, so a revoked
     issuer stays listed under its jurisdiction and `get_by_jurisdiction` keeps
     returning it."
     [`0706862` | source-only]
  8. "`UpdateAddressProof` refuses BEFORE the fee and nonce writes, so unlike
     every other refusal in this subsystem it charges nothing."
     [`0706862` | source-only]

### Untrusted payload metadata

 10. "Both finance dispatch arms pass a literal `0` where the block timestamp
     belongs, so every routed update, suspension, revocation and reactivation
     stamps `updated_at = 0`. The block's real timestamp reaches `execute_tx`
     and is thrown away."
     [`0706862` | source-only]
 11. "`registered_at_height`, `created_at`, `valid_from` and `expiry` are
     stored verbatim from the submitted payload and never compared to the
     block."
     [`0706862` | source-only]
 14. "`FinanceTxData::recipient` is read by no finance operation."
     [`0706862` | source-only]

### Unrestricted allocation from untrusted input

 12. "The four index values are unbounded: every entry appends to one bincode
     list that is decoded, linearly searched, appended to and reserialized on
     every write. Nothing ever removes an entry -- revocation rewrites the
     credential in place and the id stays indexed. Measured, not bounded: see
     the four large-index tests above." Those four tests are described in the
     same message and named nowhere in it: "the KYC, address-proof and
     bank-standing subject indexes at 640,008 bytes (20,000 existing ids) and
     the jurisdiction index at 400,008 bytes (20,000 existing addresses)", each
     proving "refusal at the replacement write under a 4,096-byte ceiling WITH
     the primary row already staged", the candidate-visible and canonical index
     byte-identical after the refusal, and with room every existing entry
     surviving in order with exactly one appended. The scope limit is the
     message's own: each test "measures one size and cannot prove arbitrarily
     large input never reaches an allocator abort".
     [`0706862` | measurement]

### Unbounded reads

 13. "`FinanceStore::issuers().list_active()` and `get_by_jurisdiction()` are
     unpaginated and unbounded. Neither takes a limit, an offset or a cursor,
     so neither has any shape in which an RPC caller could ask for less;
     response size and work per call are set by how much the chain has
     accumulated."
     [`0706862` | source-only]

### Corruption handling

  9. "Every `exists` guard is a presence check with no decode, matching
     `Database::contains`. A CORRUPT row therefore reads as PRESENT and refuses
     the transaction as a duplicate -- the exact inverse of the `v_get_*`
     readers. `FINANCE_PROOFS` is read ONLY this way, so nothing on the
     execution path ever decodes a `FinanceProofEnvelope`."
     AMBIGUOUS, and left unresolved here: the message's coverage section says
     "The ninth, FINANCE_PROOFS, is pinned separately -- see the deferred
     defects", and the deferred defect it points at names no test. The pin is a
     forward reference to a backward reference, and nothing in the message
     closes the loop.
     [`0706862` | source-only]

## Agreement (SRC-84X)

**Entries: 15** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Fifteen items, grouped as the reviewer framed them.

### Unrestricted allocation from untrusted input

Both accumulating indexes serialize their entire value before `view.put`
accounts for a single byte, so the candidate's byte ceiling bounds what a block
may COMMIT and not what one refused transaction may ALLOCATE. Measured at
20,000 ids with the ceiling set to 4,096 B:

```
party index     allocated 3,204,756 B, largest single 1,280,000 B, accounted 446 B
executor index  allocated 3,204,956 B, largest single 1,280,000 B, accounted 441 B
```

The 1,280,000-byte single allocation is the `Vec` doubling capacity from 20,000
to 40,000 elements before the encode runs. This is one measured size, not a
bound for arbitrary input. Agreement cannot be described as memory bounded or
OOM safe. A deterministic activated bound, or a bounded storage structure, is
required before deployment.

  -- both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses

Every agreement payload is `bincode::deserialize`d from transaction data with no
size or shape limit ahead of it, so the same unrestricted-allocation exposure
applies at the decode boundary and not only at the index append.

### Missing authorization and signature verification

Outside attestations there is no authorization anywhere in SRC-84X.

  * A signature's party reference comes from the PAYLOAD and is never compared
    to the transaction sender, so any sender may sign on behalf of any party and
    carry a two-party agreement to `Executed` alone.
    -- any_sender_can_sign_on_behalf_of_any_party
  * The `signature` bytes are stored, never verified against `signer_key` or
    anything else. Nothing in the executor checks a signature.
  * Any sender may terminate, void or supersede any agreement, revoke any IP
    action, and activate, pause, resume, terminate or complete any executor link.
    -- any_sender_can_terminate_void_and_revoke_anything
  * `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
    returns success for a proof id that was never submitted, without
    deserializing its payload.
    -- verify_proof_succeeds_for_a_proof_that_does_not_exist
  * `policy_id` is carried on commitments, attestations, IP actions and executor
    links, stored, and never consulted by any guard.

Attestations are the single exception: the packet's issuer must be the sender,
and only the recorded issuer may revoke or update one.
    -- only_the_issuer_may_revoke_or_update_its_own_attestation

### Overwrite and invalid-transition paths

  * A signature naming a party that is not bound to the agreement is stored
    anyway, and rewrites the agreement row while flipping no flag.
    -- a_signature_for_a_party_outside_the_agreement_is_still_recorded
  * `RevokeSignature` deletes the signature row and leaves the party's `signed`
    flag set, so an `Executed` agreement stays executed with one of its
    signatures gone. There is no path that recomputes the status.
    -- revoking_a_signature_leaves_the_party_marked_signed
  * `AddParty` and `RemoveParty` charge a fee, advance the nonce and do nothing.
    -- add_party_and_remove_party_charge_a_fee_and_do_nothing

### Untrusted payload metadata

  * `recorded_at_height`, `created_at`, `updated_at`, `valid_from` and `expiry`
    are taken from the payload as supplied. Nothing reconciles them with the
    block.
  * Both dispatch arms pass a literal `0` where the block timestamp belongs, and
    a literal `0` for the transaction index, so every timestamp the executor
    itself writes is 0 regardless of the block.
    -- the_block_timestamp_reaching_agreement_operations_is_always_zero
  * `AgreementTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and
    ignored.

### Unbounded reads and indexes

  * Both indexes are unbounded accumulating `Vec<[u8; 32]>` values with a linear
    `contains` on every append.
  * The committed readers are unpaginated whole-family scans: `list_active` and
    `get_by_agreement` walk every row in their column family and return one
    `Vec`, with no limit, offset or cursor.
    -- the_committed_agreement_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `AgreementEventStore` exists for `cf::AGREEMENT_EVENTS` and no executor
    operation ever calls it, so the agreement journal is empty on every chain.
    There is no undo history and no audit trail: a terminated agreement retains
    no record of who terminated it or what it held before.
    -- the_agreement_event_journal_is_never_written
  * The duplicate guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into
    block-level errors.
    -- a_corrupt_proof_row_is_read_as_presence_not_as_corruption

## Property (SRC-86X)

**Entries: 18** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Eighteen items, grouped as the reviewer framed them.

### Unrestricted allocation from untrusted input

All five accumulating indexes serialize their entire value before `view.put`
accounts for a single byte, so the candidate's byte ceiling bounds what a block
may COMMIT and not what one refused transaction may ALLOCATE. Measured at
20,000 ids with the ceiling set to 4,096 B:

```
jurisdiction index        allocated 3,204,575 B, largest single 1,280,000 B, accounted 417 B
asset title index         allocated 3,204,820 B, largest single 1,280,000 B, accounted 429 B
asset encumbrance index   allocated 3,205,044 B, largest single 1,280,000 B, accounted 485 B
asset coverage index      allocated 3,205,320 B, largest single 1,280,000 B, accounted 556 B
coverage claim index      allocated 3,205,307 B, largest single 1,280,000 B, accounted 521 B
```

The 1,280,000-byte single allocation is the `Vec` doubling capacity from 20,000
to 40,000 elements before the encode runs. This is one measured size, not a
bound for arbitrary input. Property cannot be described as memory bounded or
OOM safe. A deterministic activated bound, or a bounded storage structure, is
required before deployment.

  -- all_five_indexes_allocate_their_whole_value_before_the_ceiling_refuses

Every property payload is `bincode::deserialize`d from transaction data with no
size or shape limit ahead of it, so the same unrestricted-allocation exposure
applies at the decode boundary and not only at the index append.

The jurisdiction index compounds it in a second way: its KEY is the raw UTF-8 of
`AssetAnchor.jurisdiction_code`, taken from the payload with no length or
character validation, so an attacker chooses both the width of the key and the
number of distinct keys in the family.

### Missing authorization and proof verification

  * `MergeAssets` checks nothing about the sender. Any account may merge two
    assets it did not issue, marking the secondary `Merged`.
    -- three_operations_check_no_authority_at_all
  * `SupersedeTitleEvent` checks nothing about the sender. Any account may
    supersede any title event and record a replacement naming itself.
    -- three_operations_check_no_authority_at_all
  * `SubmitProof` checks nothing about the sender and verifies nothing about the
    proof: the only guard is a duplicate-id check.
    -- three_operations_check_no_authority_at_all
  * `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
    returns success for a proof id that was never submitted, without
    deserializing its payload.
    -- verify_proof_succeeds_for_a_proof_that_does_not_exist
  * Where an authorization check does exist it is `issuer_address == sender`,
    and on every creation path `issuer_address` comes from the PAYLOAD. So the
    check binds a row to whoever created it and to nothing else: any account may
    anchor an asset in any jurisdiction, declaring any `PropertyIssuerClass`,
    and then holds sole authority over it. No issuer registry is consulted.
  * `policy_id` is carried on assets, title events, encumbrances, coverage and
    claims, stored, and never consulted by any guard.

### Overwrite and invalid-transition paths

  * Only three transitions guard on the state they read — `ReinstateCoverage`
    (`Suspended`), `PayClaim` (`Approved` or `PartiallyApproved`) and
    `ReopenClaim` (`Closed` or `Denied`). Every other transition applies from
    any prior status, so a `Deregistered` asset can be set back to `Active`, a
    `Paid` claim moved to any status by `UpdateClaim`, and a `Cancelled`
    coverage reactivated by `UpdateCoverage`.
  * `MergeAssets` records no relationship: `related_assets` stays empty on both
    rows and the primary asset is never written at all. `SubdivideAsset`
    creates no child assets. `TransferAsset` moves no ownership — an asset row
    has no owner field, and `PropertyTxData.recipient` is ignored.
    -- merge_subdivide_and_transfer_record_a_status_and_nothing_else
  * `AssetStore::add_related_asset` is the one writer that could record a merge
    or a subdivision, and no execution path reaches it.

### Untrusted payload metadata

  * `created_at`, `updated_at`, `recorded_at_height`, `anchored_at_height`,
    `effective_from`, `expiry`, `date_of_loss` and `date_filed` are taken from
    the payload as supplied. Nothing reconciles them with the block.
  * Both dispatch arms pass a literal `0` where the block timestamp belongs, and
    a literal `0` for the transaction index, so every timestamp the executor
    itself writes is 0 regardless of the block.
    -- the_block_timestamp_reaching_property_operations_is_always_zero
  * `TitleEvent` has no `updated_at` field, so `update_status` writes the
    transition's timestamp into `created_at` — with the zero above, voiding or
    superseding an event destroys its recorded creation time.
    -- the_block_timestamp_reaching_property_operations_is_always_zero
  * `PropertyTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and
    ignored.

### Unbounded reads and indexes

  * All five indexes are unbounded accumulating `Vec<[u8; 32]>` values with a
    linear `contains` on every append.
  * The committed readers are unpaginated whole-family scans: `list_active`
    walks every row in its column family and returns one `Vec`, and the four
    `get_by_*` readers resolve an index list and then point-read every id in
    it, with no limit, offset or cursor.
    -- the_committed_property_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `PropertyEventStore` exists for `cf::PROPERTY_SYSTEM_EVENTS` and no executor
    operation ever calls it, so the property journal is empty on every chain.
    That is the twelfth column family; the eleven this commit moves are the ones
    anything writes. There is no undo history and no audit trail: a deregistered
    asset retains no record of who deregistered it or what it held before.
    -- the_property_event_journal_is_never_written
  * The duplicate guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into
    block-level errors.
    -- a_corrupt_proof_row_is_read_as_presence_not_as_corruption
  * `PropertyProofStore::is_valid` compares `expires_at` to a caller-supplied
    time and nothing else. No proof in SRC-86X is ever cryptographically
    checked.

## Healthcare (SRC-87X)

**Entries: 21** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Twenty-one items. Healthcare is the subsystem where an authorization defect is
least tolerable, and it has the weakest authorization in the lane so far: the
consent lifecycle can be taken over by any sender, and a prescription can be
filled by anyone at all.

### Unrestricted allocation from untrusted input

SEVEN accumulating structures, not two. Five are index families whose values are
`Vec` lists; two accumulate INSIDE a primary row, so the buffer that gets built
is the entire record. Every one serializes its whole contents before `view.put`
accounts for a single byte, so the candidate's byte ceiling bounds what a block
may COMMIT and not what one refused transaction may ALLOCATE. Measured at 20,000
entries with the ceiling set to 4,096 B:

```
provider network index            allocated 3,204,738 B, largest single 1,280,000 B, accounted 448 B
member index                      allocated 3,205,282 B, largest single 1,280,000 B, accounted 545 B
subject consent index             allocated 3,205,195 B, largest single 1,280,000 B, accounted 572 B
patient prescription index        allocated 3,205,682 B, largest single 1,280,000 B, accounted 644 B
prescriber prescription index     allocated 3,207,096 B, largest single 1,280,000 B, accounted 748 B
membership.dependents   (in row)  allocated 4,483,696 B, largest single 1,280,000 B, accounted 168 B
prescription.fill_history (in row) allocated 4,483,993 B, largest single 1,280,000 B, accounted 168 B
```

The 1,280,000-byte single allocation is the `Vec` doubling capacity from 20,000
to 40,000 elements before the encode runs. The two in-row cases allocate about
40% more than the index cases because the whole record is rebuilt, and
`PartialFillPrescription` rebuilds it TWICE in one transaction -- once to append
the fill and once to stamp the status onto the row it just wrote.

This is one measured size, not a bound for arbitrary input. Healthcare cannot be
described as memory bounded or OOM safe. A deterministic activated bound, or a
bounded storage structure, is required before deployment.

  -- every_healthcare_accumulator_allocates_its_whole_value_before_the_ceiling_refuses

Every healthcare payload is `bincode::deserialize`d from transaction data with
no size or shape limit ahead of it, so the same unrestricted-allocation exposure
applies at the decode boundary and not only at the index append.

### Missing authorization

  * `SupersedeConsent` checks NOTHING about the sender. Every other consent
    operation requires the sender to be the recorded issuer; this one only
    checks that the old consent exists, then marks it `Superseded` and stores a
    replacement whose entire contents come from the payload -- a different
    subject, a different recipient, a wider disclosure scope, a different
    issuer. It is a complete bypass of the consent lifecycle's authorization and
    is the most serious item in this inventory.
    -- any_sender_can_supersede_any_consent_with_one_of_their_own
  * A consent's SUBJECT is never consulted in either direction. `GrantConsent`
    compares the packet's issuer to the sender and compares nothing to
    `subject_address` or `subject_ref`, so the issuer records a disclosure
    authorization about someone else without their participation; and
    `RevokeConsent` requires the issuer, so the subject cannot withdraw it.
    -- the_subject_of_a_consent_can_neither_grant_nor_revoke_it
  * `FillPrescription` and `PartialFillPrescription` check no sender at all --
    not the patient, not the prescriber, not the pharmacy, not the issuer. Every
    other prescription operation checks the issuer. A stranger can fill anyone's
    prescription, including a controlled substance.
    -- any_sender_can_fill_any_prescription
  * `AddNetworkAffiliation` and `RemoveNetworkAffiliation` are the only provider
    operations with no issuer check: they verify the provider exists and write.
    A stranger can move any provider between plan networks.
    -- any_sender_can_change_a_providers_network_affiliations
  * `IssuePrescription` requires the packet's issuer to be the sender and the
    named prescriber provider to EXIST, and never relates the sender to that
    provider or to the patient. Anyone who can register a provider can issue
    prescriptions naming any other registered provider as prescriber.
  * `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
    returns success for a proof id that was never submitted, without
    deserializing its payload.
    -- verify_proof_succeeds_for_a_proof_that_does_not_exist
  * `proof_data` is stored and never checked against anything, and `policy_id`
    is carried on providers, memberships, consents and prescriptions, stored,
    and never consulted by any guard.

The issuer checks that DO exist -- register/update/suspend/revoke/reactivate a
provider, every membership operation, grant/update/revoke a consent, and
update/cancel/hold/release a prescription -- are pinned by the contrast
assertions inside the two `any_sender_*` tests above.

### Invalid-transition and overwrite paths

  * `RenewMembership` sets the status to `Active` unconditionally, with no
    transition check, so a membership terminated a transaction earlier is active
    again by the end of the block.
    -- renewing_a_terminated_membership_makes_it_active_again
  * The fill guard is `refills_remaining == 0 && status != Active`, so a
    prescription authorizing ZERO refills whose status is `Active` passes it and
    is filled once more.
    -- a_prescription_with_no_refills_but_active_status_can_be_filled_once_more
  * `is_controlled` is read in exactly one place, and that guard covers exactly
    one status value: `UpdatePrescription` refuses `TransferRequested`. The same
    prescription can be filled, held, released and cancelled like any other, and
    any other status may be set on it directly.
    -- the_controlled_substance_guard_covers_only_the_transfer_status
  * `RemoveNetworkAffiliation` writes the network index unconditionally, so
    removing an affiliation the provider never had CREATES an empty list row
    where there was none, and rewrites the provider row with a bumped
    `updated_at`.
    -- removing_an_affiliation_that_was_never_there_still_writes_an_empty_index
    -- removing_an_affiliation_that_was_never_there_still_stages_an_empty_index
  * `RemoveDependent` is likewise unconditional: it rewrites the membership row
    and bumps `updated_at` even when the dependent was not in the list.

### Untrusted payload metadata, and a block timestamp that is always zero

  * Both dispatch arms pass a literal `0` where the block timestamp belongs, and
    a literal `0` for the transaction index. Every timestamp the executor itself
    writes is therefore 0 regardless of the block -- and, worse than cosmetic,
    `Prescription::is_valid` is evaluated at time zero. An EXPIRED prescription
    is fillable forever, because `0 >= expiry` is false for every positive
    expiry; a prescription with a non-zero `effective_from` can never be filled
    at all.
    -- the_block_timestamp_reaching_healthcare_operations_is_always_zero
  * `created_at`, `updated_at`, `effective_from`, `expiry`, `date_written` and
    `recorded_at_height` are taken from the payload as supplied. Nothing
    reconciles them with the block.
  * `HealthcareTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and
    ignored.

### Unbounded reads and indexes

  * All five index families are unbounded accumulating `Vec<[u8; 32]>` values
    with a linear `contains` on every append, and two more such lists accumulate
    inside primary rows.
  * The committed readers are unpaginated whole-family scans: `list_active`
    walks every row in its column family and `get_by_network`, `get_by_member`,
    `get_by_subject`, `get_by_patient` and `get_by_prescriber` resolve a whole
    index list row by row, each returning one `Vec` with no limit, offset or
    cursor.
    -- the_committed_healthcare_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `HealthcareEventStore` exists for `cf::HEALTHCARE_SYSTEM_EVENTS` and no
    executor operation ever calls it, so the healthcare journal is empty on
    every chain. There is no undo history and no audit trail: a revoked consent
    retains no record of who revoked it, and a filled prescription none of who
    filled it -- which, given that anyone may fill one, is the pair of defects
    compounding.
    -- the_healthcare_event_journal_is_never_written
  * Three declared column families -- `HEALTHCARE_MEMBER_ADDRESS_INDEX`,
    `HEALTHCARE_SUBJECT_ADDRESS_INDEX` and `HEALTHCARE_PATIENT_ADDRESS_INDEX` --
    are never written by anything, even though every row carries the address
    they would be keyed by. `execution_closure` classifies them dead; the same
    test drives that claim through a real published block.
    -- the_healthcare_event_journal_is_never_written
  * The duplicate guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into
    block-level errors.
    -- a_corrupt_proof_row_is_read_as_presence_not_as_corruption
  * `PrescriptionStore::record_fill` carries its own `InvalidData("No refills
    remaining")` guard, which is unreachable through dispatch because the
    executor reads the same row a moment earlier and refuses first. It is
    reproduced verbatim on the candidate surface anyway -- the store is public,
    and the candidate side must not be the laxer of the two.

## NFT (SUM-721)

**Entries: 51** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Fifty-one items. Every one is inherited, reproduced deliberately, and pinned by
the named test.

### Block-level denial of service: absence is an error, not a failed receipt

Every other guard in `nft_executor.rs` returns
`NftExecutionResult::failure(..)`, which becomes a `Failed(2)` receipt. Four
paths instead use `?` on a `StateError::BlockValidation`, and
`BlockExecutor::execute_block` propagates that with `?` too — so ONE such
transaction makes the whole block unexecutable, for the producer and for every
importer. Any sender can submit one, for the minimum fee, naming a collection id
that does not exist.

  * `Collection not found`, from mint, batch mint, transfer, burn, metadata
    update, collection-ownership transfer and config update.
    -- a_transaction_naming_an_absent_collection_aborts_the_whole_block
  * `Token not found`, from transfer, approve, burn, metadata update, lock and
    unlock. Reachable inside one block by burning a token and then using it.
    -- burning_a_token_and_then_using_it_in_one_block_aborts_the_block
  * `Invalid config`, from a royalty above 2500bps in the payload.
    -- an_invalid_collection_config_aborts_the_whole_block
  * `Invalid collection data` / `Invalid mint data` / `Invalid transfer data` /
    `Invalid approve data` / `Invalid batch data` / `Invalid config data`, from
    any payload bincode cannot decode. Same shape; not separately pinned.

This is the item that most obviously has to be fixed before deployment, and it
cannot be fixed here: turning those into failed receipts changes which blocks
are valid.

### Unrestricted allocation from untrusted input

Both accumulating indexes serialize their entire value before `view.put`
accounts for a single byte, so the candidate's byte ceiling bounds what a block
may COMMIT and not what one refused transaction may ALLOCATE. Measured at 20,000
entries with the ceiling set to 4,096 B:

```
provider network index            allocated 3,204,738 B, largest single 1,280,000 B, accounted 448 B
member index                      allocated 3,205,282 B, largest single 1,280,000 B, accounted 545 B
subject consent index             allocated 3,205,195 B, largest single 1,280,000 B, accounted 572 B
patient prescription index        allocated 3,205,682 B, largest single 1,280,000 B, accounted 644 B
prescriber prescription index     allocated 3,207,096 B, largest single 1,280,000 B, accounted 748 B
membership.dependents   (in row)  allocated 4,483,696 B, largest single 1,280,000 B, accounted 168 B
prescription.fill_history (in row) allocated 4,483,993 B, largest single 1,280,000 B, accounted 168 B
```

The 1,280,000-byte single allocation is the `Vec` doubling capacity from 20,000
to 40,000 elements before the encode runs. The two in-row cases allocate about
40% more than the index cases because the whole record is rebuilt, and
`PartialFillPrescription` rebuilds it TWICE in one transaction -- once to append
the fill and once to stamp the status onto the row it just wrote.

This is one measured size, not a bound for arbitrary input. Healthcare cannot be
described as memory bounded or OOM safe. A deterministic activated bound, or a
bounded storage structure, is required before deployment.

  -- every_healthcare_accumulator_allocates_its_whole_value_before_the_ceiling_refuses

Every healthcare payload is `bincode::deserialize`d from transaction data with
no size or shape limit ahead of it, so the same unrestricted-allocation exposure
applies at the decode boundary and not only at the index append.

### Missing authorization

  * `SupersedeConsent` checks NOTHING about the sender. Every other consent
    operation requires the sender to be the recorded issuer; this one only
    checks that the old consent exists, then marks it `Superseded` and stores a
    replacement whose entire contents come from the payload -- a different
    subject, a different recipient, a wider disclosure scope, a different
    issuer. It is a complete bypass of the consent lifecycle's authorization and
    is the most serious item in this inventory.
    -- any_sender_can_supersede_any_consent_with_one_of_their_own
  * A consent's SUBJECT is never consulted in either direction. `GrantConsent`
    compares the packet's issuer to the sender and compares nothing to
    `subject_address` or `subject_ref`, so the issuer records a disclosure
    authorization about someone else without their participation; and
    `RevokeConsent` requires the issuer, so the subject cannot withdraw it.
    -- the_subject_of_a_consent_can_neither_grant_nor_revoke_it
  * `FillPrescription` and `PartialFillPrescription` check no sender at all --
    not the patient, not the prescriber, not the pharmacy, not the issuer. Every
    other prescription operation checks the issuer. A stranger can fill anyone's
    prescription, including a controlled substance.
    -- any_sender_can_fill_any_prescription
  * `AddNetworkAffiliation` and `RemoveNetworkAffiliation` are the only provider
    operations with no issuer check: they verify the provider exists and write.
    A stranger can move any provider between plan networks.
    -- any_sender_can_change_a_providers_network_affiliations
  * `IssuePrescription` requires the packet's issuer to be the sender and the
    named prescriber provider to EXIST, and never relates the sender to that
    provider or to the patient. Anyone who can register a provider can issue
    prescriptions naming any other registered provider as prescriber.
  * `VerifyProof` verifies nothing: it charges the fee, advances the nonce and
    returns success for a proof id that was never submitted, without
    deserializing its payload.
    -- verify_proof_succeeds_for_a_proof_that_does_not_exist
  * Where an authorization check does exist it is `issuer_address == sender`,
    and on every creation path `issuer_address` comes from the PAYLOAD. So the
    check binds a row to whoever created it and to nothing else: any account may
    anchor an asset in any jurisdiction, declaring any `PropertyIssuerClass`,
    and then holds sole authority over it. No issuer registry is consulted.
  * `policy_id` is carried on assets, title events, encumbrances, coverage and
    claims, stored, and never consulted by any guard.

### Overwrite and invalid-transition paths

  * Only three transitions guard on the state they read — `ReinstateCoverage`
    (`Suspended`), `PayClaim` (`Approved` or `PartiallyApproved`) and
    `ReopenClaim` (`Closed` or `Denied`). Every other transition applies from
    any prior status, so a `Deregistered` asset can be set back to `Active`, a
    `Paid` claim moved to any status by `UpdateClaim`, and a `Cancelled`
    coverage reactivated by `UpdateCoverage`.
  * `MergeAssets` records no relationship: `related_assets` stays empty on both
    rows and the primary asset is never written at all. `SubdivideAsset`
    creates no child assets. `TransferAsset` moves no ownership — an asset row
    has no owner field, and `PropertyTxData.recipient` is ignored.
    -- merge_subdivide_and_transfer_record_a_status_and_nothing_else
  * `AssetStore::add_related_asset` is the one writer that could record a merge
    or a subdivision, and no execution path reaches it.

### Untrusted payload metadata

  * `created_at`, `updated_at`, `recorded_at_height`, `anchored_at_height`,
    `effective_from`, `expiry`, `date_of_loss` and `date_filed` are taken from
    the payload as supplied. Nothing reconciles them with the block.
  * Both dispatch arms pass a literal `0` where the block timestamp belongs, and
    a literal `0` for the transaction index, so every timestamp the executor
    itself writes is 0 regardless of the block.
    -- the_block_timestamp_reaching_property_operations_is_always_zero
  * `TitleEvent` has no `updated_at` field, so `update_status` writes the
    transition's timestamp into `created_at` — with the zero above, voiding or
    superseding an event destroys its recorded creation time.
    -- the_block_timestamp_reaching_property_operations_is_always_zero
  * `PropertyTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and
  * `proof_data` is stored and never checked against anything, and `policy_id`
    is carried on providers, memberships, consents and prescriptions, stored,
    and never consulted by any guard.

The issuer checks that DO exist -- register/update/suspend/revoke/reactivate a
provider, every membership operation, grant/update/revoke a consent, and
update/cancel/hold/release a prescription -- are pinned by the contrast
assertions inside the two `any_sender_*` tests above.

### Invalid-transition and overwrite paths

  * `RenewMembership` sets the status to `Active` unconditionally, with no
    transition check, so a membership terminated a transaction earlier is active
    again by the end of the block.
    -- renewing_a_terminated_membership_makes_it_active_again
  * The fill guard is `refills_remaining == 0 && status != Active`, so a
    prescription authorizing ZERO refills whose status is `Active` passes it and
    is filled once more.
    -- a_prescription_with_no_refills_but_active_status_can_be_filled_once_more
  * `is_controlled` is read in exactly one place, and that guard covers exactly
    one status value: `UpdatePrescription` refuses `TransferRequested`. The same
    prescription can be filled, held, released and cancelled like any other, and
    any other status may be set on it directly.
    -- the_controlled_substance_guard_covers_only_the_transfer_status
  * `RemoveNetworkAffiliation` writes the network index unconditionally, so
    removing an affiliation the provider never had CREATES an empty list row
    where there was none, and rewrites the provider row with a bumped
    `updated_at`.
    -- removing_an_affiliation_that_was_never_there_still_writes_an_empty_index
    -- removing_an_affiliation_that_was_never_there_still_stages_an_empty_index
  * `RemoveDependent` is likewise unconditional: it rewrites the membership row
    and bumps `updated_at` even when the dependent was not in the list.

### Untrusted payload metadata, and a block timestamp that is always zero

  * Both dispatch arms pass a literal `0` where the block timestamp belongs, and
    a literal `0` for the transaction index. Every timestamp the executor itself
    writes is therefore 0 regardless of the block -- and, worse than cosmetic,
    `Prescription::is_valid` is evaluated at time zero. An EXPIRED prescription
    is fillable forever, because `0 >= expiry` is false for every positive
    expiry; a prescription with a non-zero `effective_from` can never be filled
    at all.
    -- the_block_timestamp_reaching_healthcare_operations_is_always_zero
  * `created_at`, `updated_at`, `effective_from`, `expiry`, `date_written` and
    `recorded_at_height` are taken from the payload as supplied. Nothing
    reconciles them with the block.
  * `HealthcareTxData.recipient`, `_tx_index` and `_tx_hash` are accepted and
    ignored.

### Unbounded reads and indexes

  * All five indexes are unbounded accumulating `Vec<[u8; 32]>` values with a
    linear `contains` on every append.
  * The committed readers are unpaginated whole-family scans: `list_active`
    walks every row in its column family and returns one `Vec`, and the four
    `get_by_*` readers resolve an index list and then point-read every id in
    it, with no limit, offset or cursor.
    -- the_committed_property_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `PropertyEventStore` exists for `cf::PROPERTY_SYSTEM_EVENTS` and no executor
    operation ever calls it, so the property journal is empty on every chain.
    That is the twelfth column family; the eleven this commit moves are the ones
    anything writes. There is no undo history and no audit trail: a deregistered
    asset retains no record of who deregistered it or what it held before.
    -- the_property_event_journal_is_never_written
  * All five index families are unbounded accumulating `Vec<[u8; 32]>` values
    with a linear `contains` on every append, and two more such lists accumulate
    inside primary rows.
  * The committed readers are unpaginated whole-family scans: `list_active`
    walks every row in its column family and `get_by_network`, `get_by_member`,
    `get_by_subject`, `get_by_patient` and `get_by_prescriber` resolve a whole
    index list row by row, each returning one `Vec` with no limit, offset or
    cursor.
    -- the_committed_healthcare_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `HealthcareEventStore` exists for `cf::HEALTHCARE_SYSTEM_EVENTS` and no
    executor operation ever calls it, so the healthcare journal is empty on
    every chain. There is no undo history and no audit trail: a revoked consent
    retains no record of who revoked it, and a filled prescription none of who
    filled it -- which, given that anyone may fill one, is the pair of defects
    compounding.
    -- the_healthcare_event_journal_is_never_written
  * Three declared column families -- `HEALTHCARE_MEMBER_ADDRESS_INDEX`,
    `HEALTHCARE_SUBJECT_ADDRESS_INDEX` and `HEALTHCARE_PATIENT_ADDRESS_INDEX` --
    are never written by anything, even though every row carries the address
    they would be keyed by. `execution_closure` classifies them dead; the same
    test drives that claim through a real published block.
    -- the_healthcare_event_journal_is_never_written
  * The duplicate guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into
    block-level errors.
    -- a_corrupt_proof_row_is_read_as_presence_not_as_corruption
  * `PropertyProofStore::is_valid` compares `expires_at` to a caller-supplied
    time and nothing else. No proof in SRC-86X is ever cryptographically
    checked.
  * `PrescriptionStore::record_fill` carries its own `InvalidData("No refills
    remaining")` guard, which is unreachable through dispatch because the
    executor reads the same row a moment earlier and refuses first. It is
    reproduced verbatim on the candidate surface anyway -- the store is public,
    and the candidate side must not be the laxer of the two.
owner index       row 960,008 B, allocated 4,484,318 B, largest single 1,280,000 B, accounted 367 B
collection index  row 160,008 B, allocated   805,676 B, largest single   320,000 B, accounted 463 B
```

The million-byte single allocations are the `Vec` doubling its capacity before
the encode runs. This is one measured size, not a bound for arbitrary input. NFT
cannot be described as memory bounded or OOM safe. A deterministic activated
bound, or a bounded storage structure, is required before deployment.

  -- both_accumulating_indexes_allocate_their_whole_value_before_the_ceiling_refuses

Neither index is ever compacted. The owner index grows by one
`(collection id, token id)` pair per token an address holds; the collection
index grows by one `u64` per token ever minted into a collection. Every NFT
payload is `bincode::deserialize`d from transaction data with no size or shape
limit ahead of it, so the same exposure applies at the decode boundary.

### Fee accounting

  * `deduct_fee` runs BEFORE the dispatch match, so every guard below it refuses
    a transaction whose fee is already spent and whose nonce has already
    advanced — while the receipt reports `fee_paid: 0`. The receipt and the
    state disagree on every failed NFT transaction.
    -- a_refused_nft_operation_has_already_charged_the_fee
  * `SetApprovalForAll` is unimplemented. It charges the fee, advances the nonce
    and returns a failure. Operator approvals do not exist at all.
    -- set_approval_for_all_charges_a_fee_and_does_nothing

### Metadata size and storage pricing are enforced on one path only

`execute_mint` enforces `max_metadata_bytes` and
`calculate_nft_storage_fee`. Two other paths write metadata and enforce neither:

  * `UpdateMetadata` takes the transaction payload VERBATIM as the new metadata,
    undecoded, with no size limit and no per-byte fee. 32 KB — twice the mint
    limit — costs the flat minimum fee.
    -- update_metadata_accepts_any_size_and_charges_no_storage_fee
  * `BatchMint` checks neither, for any number of requests.
    -- batch_mint_ignores_the_metadata_size_limit_and_the_storage_fee

### Authority

  * The CREATOR may rewrite the metadata of a token it no longer owns, for the
    life of the token. `creator` never changes, and the guard is
    `owner == sender || creator == sender`.
    -- the_creator_can_rewrite_metadata_of_a_token_it_no_longer_owns
  * The `locked` flag is consulted by transfer and burn only. A locked token can
    still be approved and have its metadata rewritten.
    -- a_locked_token_can_still_be_approved_and_rewritten
  * `Approve` never reads the collection, so an approval can be recorded on a
    token in a non-transferable collection — an approval that can never be
    exercised.
    -- approve_never_reads_the_collection

### Collection identity

`CollectionId::new(sender, name, block_timestamp)` — the block timestamp is the
only nonce. Two blocks that share a timestamp, which nothing forbids, give the
same sender the same id for the same name, and the later creation is refused as
a duplicate. The id is not unique per creation; it is unique per
`(sender, name, timestamp)`.

  -- the_block_timestamp_is_the_only_nonce_in_a_collection_id

### Royalties and config

  * `royalty_bps` and `royalty_recipient` are stored, returned by the RPC
    readers, and consulted by no execution path. A transfer pays the recipient
    nothing.
    -- royalties_are_recorded_and_never_paid
  * Creation zeroes `royalty_recipient` when `royalty_bps == 0`;
    `UpdateCollectionConfig` has no such rule and sets one anyway, and has no
    field for `royalty_bps` at all, so a royalty can never be changed after
    creation.
    -- a_royalty_recipient_can_be_set_on_a_collection_that_pays_no_royalty
  * Transferring a collection moves no token, and hands the new owner
    `owner_only_minting` rights over every future token in it.
    -- transferring_a_collection_moves_no_token

### Index shape and corruption handling

  * Removal is asymmetric: emptying an owner's list DELETES the row, emptying a
    collection's list WRITES an empty list. Both are reproduced exactly on both
    sides.
    -- removal_is_asymmetric_between_the_two_indexes
    -- burning_the_last_token_deletes_one_index_row_and_writes_the_other_empty
  * The existence guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into the
    block-level errors described at the top of this section.
    -- a_malformed_row_is_an_error_from_every_decoding_reader
  * `next_token_id` never goes back. A burn decrements `total_supply` with
    `saturating_sub` and leaves `next_token_id` where it was, so a collection
    with `max_supply` can be permanently exhausted by minting and burning.
    -- a_burn_after_a_mint_in_one_block_moves_every_mirror_row_together

## DocClass (SRC-80X/81X)

**Entries: 17** — one per bulleted defect below. This line is the normative count;
the prose beneath it repeats it.

Seventeen items, grouped as the reviewer framed them. DocClass is the identity and
credential subsystem — identity roots, eligibility attestations, academic and
professional credentials, revocations and the issuer registry — so the
authorization and lifecycle entries below are the ones that matter most.

### Unrestricted allocation from untrusted input

SEVEN structures grow without bound, and only three of them are indexes. Each is
read-modify-write: the whole value is decoded, one entry is pushed, and the whole
value is re-encoded into a fresh buffer before `view.put` accounts for a single
byte. So the candidate's byte ceiling bounds what a block may COMMIT and not what
one refused transaction may ALLOCATE. Measured at 20,000 entries with the ceiling
set to 8,192 B:

```
subject index, identity shape        allocated 3,484,922 B, largest single 1,360,000 B, accounted 471 B
subject index, credential shape      allocated 3,205,443 B, largest single 1,280,000 B, accounted 527 B
issuer index                         allocated 3,206,847 B, largest single 1,280,000 B, accounted 631 B
IdentityRoot.keys                    allocated 6,415,479 B, largest single 2,097,056 B, accounted 168 B
IdentityRoot.additional_controllers  allocated 2,003,318 B, largest single   800,000 B, accounted 168 B
IdentityRoot.services                allocated 7,475,754 B, largest single 2,097,024 B, accounted 168 B
DocClassIssuer.keys                  allocated 5,955,495 B, largest single 2,097,120 B, accounted 168 B
```

The four row-field cases allocate twice over, because the read decodes the whole
row into owned Rust values before the encode rebuilds it — which is why they cost
more than the index cases despite smaller fixtures. This is one measured size,
not a bound for arbitrary input. DocClass cannot be described as memory bounded
or OOM safe. A deterministic activated bound, or a bounded storage structure, is
required before deployment.

  -- all_seven_accumulating_structures_allocate_their_whole_value_before_the_ceiling_refuses

None of the seven is ever compacted, and `UpdateService` and `RotateIssuerKey`
LINEAR-SCAN their list on every append (`RotateIssuerKey` twice). Every DocClass
payload is `bincode::deserialize`d from transaction data with no size or shape
limit ahead of it, so the same exposure applies at the decode boundary.

### One column family, two incompatible value shapes

`DOCCLASS_SUBJECT_INDEX` is written with two different values at the same key.
`IdentityRootStore` writes `Vec<(CredentialId, DocSubcode)>`; `EligibilityStore`
and `CredentialStore` write `Vec<CredentialId>`. An identity and a credential
that share a subject commitment therefore write over each other:

  * The credential store decodes the identity's pair list as a bare id list.
    bincode allows trailing bytes, so this SUCCEEDS, silently dropping the
    subcode, and rewrites the row in the credential shape.
    -- an_identity_and_a_credential_sharing_a_subject_commitment_collide
  * The identity store then cannot decode its own index, so the next identity
    operation on that subject is a BLOCK-LEVEL ERROR rather than a refusal.
    -- an_identity_and_a_credential_sharing_a_subject_commitment_break_the_block

Nothing prevents the collision: a subject commitment is an arbitrary 32-byte
value supplied in the payload, so it can be chosen. Separating the families, or
tagging the value, changes the bytes at a live key and therefore the state root.

### Missing authorization and signature verification

  * NO SIGNATURE IS EVER VERIFIED. `EligibilityAttestation.issuer_signature`,
    `AcademicCredential.issuer_signature`, `IdentityKey.public_key`,
    `IssuerKey.public_key` and `RevocationRecord.signature` are stored and never
    checked against anything. The revocation record the executor builds sets
    `signature: [0u8; 64]` on every path.
  * A registered issuer may rewrite its OWN registry row wholesale — subcodes,
    jurisdictions, status and the declared stake all come from the payload.
    `min_issuer_stake` is checked at registration only, so an issuer registers
    with the minimum and then declares any stake it likes for free; and a
    SUSPENDED issuer restores itself to `Active` with one `UpdateIssuer`.
    -- an_issuer_can_grant_itself_any_subcode_and_any_stake_by_updating_itself
    -- a_suspended_issuer_can_still_revoke_and_update_itself
  * Nothing binds a `subject_commitment` to anybody. Any funded account may
    anchor an identity root claiming any subject, with any status, any
    timestamps and any schema hash, all taken from the payload verbatim.
    -- an_identity_root_is_stored_exactly_as_the_sender_supplied_it
  * The revocation family never consults the issuer registry. A suspended or
    revoked issuer can still revoke, suspend, reactivate and supersede its
    credentials.
    -- a_suspended_issuer_can_still_revoke_and_update_itself
  * `DocClassParams.require_issuer_stake`, `initial_issuers` and
    `max_credential_validity` are declared, defaulted, and read by no execution
    path at all. The RPC reports `require_issuer_stake: true` and a ten-year
    `max_credential_validity` as hardcoded literals, so an operator querying the
    node is told about rules the chain does not apply.
  * `DocClassTxData.subcode`, `DocClassTxData.recipient` and the transaction
    hash are accepted by the dispatch and never read.

Two checks do bite, and they are the whole of the sender binding in the creation
paths: a registration must name the sender's own address, and an identity root
must name the sender as its controller.
    -- registration_and_identity_creation_are_bound_to_the_sender
So does the revocation authorization: only the credential's recorded issuer may
revoke it.
    -- a_third_party_cannot_revoke_someone_elses_credential

### Revocation lifecycle and replay

  * REVOCATION IS REVERSIBLE. Neither `RevokeCredential` nor `SuspendCredential`
    consults the current status, and `ReactivateCredential` requires only that
    the LATEST record say `Suspended`. Revoke, then suspend, then reactivate
    returns a revoked credential to `Active`, and both the record and the
    mirrored `revocation_status` on the credential row follow.
    -- a_revoked_credential_can_be_suspended_and_then_reactivated
  * Revocation records are keyed by `credential_id || revoked_at_height`, so two
    records for one credential at one height are ONE row and the later write
    silently replaces the earlier. A revoke and a reactivation in the same block
    leave a single record.
    -- two_revocations_at_one_height_are_one_row
  * `UpdateCredential` charges the fee, advances the nonce and writes nothing at
    all — not the credential, not an event.
    -- update_credential_charges_a_fee_and_writes_nothing

### The registration stake

`RegisterIssuer` deducts `fee + stake_amount` from the sender and credits only
`fee` to the proposer. The stake reaches no account: it is destroyed. Nothing
returns it — `DeactivateIssuer` charges another fee and refunds nothing — and
`UpdateIssuer` can raise the recorded `stake_amount` afterwards without moving a
single unit of balance.

  -- the_registration_stake_is_deducted_from_the_sender_and_paid_to_nobody

### Untrusted payload metadata and missing block context

  * Both dispatch arms pass a literal `0` where the block timestamp belongs and
    a literal `0` for the transaction index. Every timestamp the executor itself
    writes is therefore 0: `IdentityRoot.updated_at` after a status change,
    `DocClassIssuer.updated_at` after a deactivation, and
    `RevocationRecord.revoked_at` on every revocation record ever written.
    -- the_block_timestamp_reaching_docclass_operations_is_always_zero
  * Because `tx_index` is also 0, every DocClass event in a block lands at the
    same `height || 0 || 0` key. The family holds ONE row per block: the last
    event. Every earlier event in the block is overwritten.
    -- every_docclass_event_in_a_block_lands_at_one_key
  * `issued_at`, `valid_from`, `expires_at`, `created_at`, `updated_at`,
    `registered_at` and `revocation_status` are taken from the payload as
    supplied. A credential may be issued already expired, already revoked, or
    valid from before the chain existed.

### Schema validation does not run

`SchemaValidator` exists to keep PII off-chain and is the only consensus-level
content check in the subsystem. Its default `activation_height` is 385,000, and
below that height it returns `Valid` for every credential without looking at it.
A credential carrying an attribute named `student_ssn` is accepted.

  -- schema_validation_is_inactive_below_its_activation_height

It also validates only three of the SRC-81X subcodes and nothing in SRC-80X:
eligibility attestations are never schema-checked at any height.

### Family selection by trial decode

`IssueCredential` decides which family a payload belongs to by TRYING to decode
it as an `AcademicCredential` and, on failure, retrying it as an
`EligibilityAttestation`. The first decode error is discarded rather than
reported, so a malformed academic credential is silently refused as "Invalid
credential data" with no indication of which decode failed or why. The two
schemas do not currently cross-decode, and nothing enforces that they never will.

  -- issue_credential_picks_its_family_by_trying_to_decode_and_falling_through

### Unbounded reads

The committed readers are unpaginated whole-family scans. `get_all`,
`get_active` and `get_by_jurisdiction` walk every issuer row; `get_by_controller`
and `get_by_subcode` walk every identity and credential row; `get_by_revoker`
walks every revocation record. Each returns one `Vec` with no limit, offset or
cursor.

  -- the_committed_docclass_readers_return_two_thousand_rows_whole

### Missing history and corruption handling

  * `DOCCLASS_EVENTS` is written by every operation and READ by nothing that
    block execution can reach. It is an append-only journal with no reader, and
    the `tx_index` defect above means it keeps one entry per block regardless.
    -- every_docclass_event_in_a_block_lands_at_one_key
  * The duplicate guards use `contains`, never `get`, so a CORRUPT row reads as
    present and refuses rather than erroring. This is the safe direction and is
    preserved for that reason: upgrading it would turn today's refusals into
    block-level errors.
    -- a_corrupt_issuer_row_is_read_as_presence_not_as_corruption
  * `DocClassStore::verify_credential` checks expiry, validity window,
    revocation status and whether the issuer may still issue. It checks no
    signature and no proof, and no execution path calls it.

## Out-of-consensus writes, and the journal re-key

Two findings that sit outside normal execution and are therefore outside the
zero-closure claim entirely. Both are corrections to earlier statements of mine,
recorded here rather than left to stand.

### The journal re-key is a downgrade hazard, not a state-root consensus change

An earlier note called the compute-pool/beacon journal re-keying
"consensus-relevant" and said it required coordinated activation. That was taken
from the re-keying commit's own message rather than checked.

Checked: `compute_block_state_root` (`crates/state/src/executor.rs:3610-3687`)
folds **no application column family**, so a journal key shape cannot change the
state root. Reads fall back to the legacy key (`crates/storage/src/schema.rs:377,421`)
and deletes remove both spellings (`:394,442`).

The residual risk is real but different: a node that reads new-shaped journals
and is then DOWNGRADED to a binary that only understands the legacy key cannot
interpret them. That is a compatibility and downgrade hazard, not an activation
one, and it is what the existing re-key needs handled.

**The future generic journal is a separate matter and DOES require explicit
activation.** It changes what is written during execution, on every block, and
must be gated so that nodes on either side of the boundary agree.

Both existing journal gates are meanwhile fail-closed at the loader:
`ChainParams::validate` (`crates/genesis/src/lib.rs:941-969`) rejects
`Some(_)` for `compute_pool_enabled_from_height` and `beacon_enabled_from_height`
outright, so no genesis edit can open them and re-exposure requires a code
change. Neither journal is written in production today; every test that
exercises them seeds rows directly.

### Out-of-consensus messaging writes: two reproduced callers, not thirteen

An earlier summary of mine claimed roughly thirteen non-test write sites into
the `MESSAGING_*` families (7 operator, 2 genesis, 1 snapshot, 3 raw reorg).
**That count could not be reproduced.** Two non-test write callers were found;
`state.rs`, `snapshot.rs` and `crates/consensus/` contain no `MESSAGING`
reference at all. The larger figure is withdrawn.

What survives the correction is worse than a stray write:

  * **`ImportRegisteredKeys` mutates consensus-read messaging state.**
    `crates/node/src/main.rs:1073-1084` writes `MESSAGING_PUBLIC_KEYS`, and the
    executor READS that family at `crates/state/src/messaging_executor.rs:321,750`
    and `crates/state/src/executor.rs:2030`. An operator command therefore changes
    what transactions do. Two nodes given different imports produce different
    receipts for identical blocks, and receipts ARE folded into the state root --
    so this is a divergence vector, not merely an untracked write.

    **CLOSED.** The write now goes through
    `MessagingStore::seed_registry_at_genesis`, which refuses unless the
    database has executed no block above genesis, holds no registration of its
    own, and has not already been seeded -- so the mutation shape is
    unreachable, from the command and from any caller written later. The one
    remaining shape is an INITIAL CONDITION, and it commits a permanent
    `cf::META` marker in the same batch as the rows, carrying a blake3 digest of
    the seeded set in address order. That marker outlives the process: it is
    read back by `sumchain_state::sync_capability`, warned at every later
    startup, and served on `chain_getSyncCapability`, so two validators can
    establish whether they were seeded from the same set before the first
    messaging transaction. The residual is stated rather than claimed away --
    nothing REFUSES a node whose digest differs from its peers'; the divergence
    is made visible, not prevented. See `docs/lane-a/ACTIVATION-AUDIT.md`,
    "OC-2: closed, by option (b) with a digest".
  * The startup backfill (`crates/node/src/node.rs:148-150`) runs on every boot
    but writes only indexes the executor does not read.
  * A third class of callers remains **UNDETERMINED**: the reproduced count and
    the earlier claim disagree, and the discrepancy is recorded rather than
    resolved by picking the more convenient number.

## What the integration pass found, and what it left blocking

The eleven subsystem inventories above are inherited defects, pinned and
deliberately unfixed. This section is different: it records what integrating the
journal, reorg, account-root and activation-audit work SURFACED, separated into
what was closed and what still blocks. Each item names how it was established,
so a later reader can re-establish it rather than trust it.

### Closed during integration

  * **Two workspace crates did not compile, and no gate noticed.**
    `sumchain-scripts` had not built since `fd7bb8b` added
    `account_root_enabled_from_height` to `ChainParams` without updating the
    exhaustive struct literal in `scripts/src/setup_local_testnet.rs`;
    `crates/integration-tests` had not built since `NftExecutor::execute` gained
    a `block_height` parameter. Both were invisible because every gate run in
    this lane scoped its build and test invocations to the crates under change.
    Closed by `1e40353` and `8fea224`. The standing consequence is a gating
    rule, not a code change: **`cargo build --workspace --all-targets` is part
    of the gate**, because a scoped build cannot report a crate it never built.
    The literal stays exhaustive on purpose — it caught the very next commit
    that added eleven fields.

  * **A snapshot restore could leave state that did not know its own floor.**
    The restore wrote account rows one at a time and recorded the undo-history
    floor afterwards. A crash between the two leaves restored state at height
    `h` with no floor: the journal family is empty, the activation boundary
    reads as unestablished, and the node offers a reorg horizon over blocks it
    holds no undo records for. Closed by `f41c50f`: `StateStore::import_accounts`
    stages the floor into the FIRST batch of rows, so the caller cannot get the
    order wrong. Pinned by
    `state/the_floor_is_staged_with_the_first_rows_rather_than_written_after_the_last`,
    `state/a_failed_import_leaves_the_floor_that_describes_what_it_wrote` and
    `storage/the_restore_floor_and_the_restored_state_commit_or_fail_together`.

  * **`ImportRegisteredKeys` wrote application state outside consensus.**
    Recorded as OC-2 in the activation audit. The write now goes through
    `MessagingStore::seed_registry_at_genesis`, which refuses unless the
    database has executed no block above genesis, holds no registration of its
    own, and has not already been seeded — so the mutating shape is unreachable
    from the command and from any caller written later. The one remaining shape
    is an INITIAL CONDITION, and it commits a `cf::META` marker in the same
    batch as the rows carrying a blake3 digest of the seeded set in address
    order, read back by `sync_capability`, warned at every later startup and
    served on `chain_getSyncCapability`.

    The residual is real and is NOT closed: nothing refuses a node whose digest
    differs from its peers'. Two validators can now establish that they were
    seeded from different sets before the first messaging transaction, which is
    strictly better than the silence this replaced — but the divergence is made
    visible, not prevented. Preventing it means folding the digest into the
    genesis artefact, a `crates/genesis` consensus surface this did not touch.

  * **The first start of an upgraded node validated no activation heights.**
    `ACTIVATION_META_KEY` does not exist in the deployed binary, so every
    upgrading node's first start has no record to compare against — and that
    branch recorded the configured heights and asked nothing. Closed by
    `6e64dd5`, which refuses a gate this binary introduced when it is dated at
    or below a height the database already holds, grandfathering only the
    eighteen gates that shipped in the binary that produced those blocks.

### Still blocking

  * **Thirty-three audit remedies are implemented and dormant.** The eleven
    `*_enabled_from_height` fields they read now exist, are covered by the
    activation digest and the startup change detection, and are read by the
    eleven accessors (`state/every_remediation_gate_reads_the_field_it_names`).
    None is set anywhere in this branch, and
    `state/every_remediation_gate_is_dormant_by_default` pins that. So a release
    node still runs the defective behaviour and the activation audit's blocking
    count stays 121. This is no longer blocked on code: it is blocked on a
    deployment decision to set eleven heights in every validator's runtime
    `genesis.json` as one coordinated activation. See
    `docs/lane-a/ACTIVATION-AUDIT.md` for the arithmetic and the row list.

  * **Nothing in `crates/node` constructs a `Pruner`.** Established by grep over
    `crates/node/src`: no construction site exists. `CapacityGuard` IS wired —
    `crates/consensus/src/poa.rs:90` holds one, built at `:118`, and
    `sum-node set-disk-budget` writes the row it reads at
    `crates/node/src/main.rs:988` — so a node at its budget refuses to produce
    and says why. That brake DELAYS disk exhaustion; it does not prevent it,
    because nothing deletes anything. The `pruner` module and struct
    documentation used to describe this uncalled type as running behaviour and
    no longer does.

  * **A reorg wholly below the journal activation boundary cannot restore every
    family the block wrote.** Below the boundary the only undo records are the
    four legacy per-subsystem journals, which cover account and contract rows
    plus two dormant subsystems and nothing else; `cf::SUPPLY` is restorable
    from none of them. This is pre-existing behaviour of pre-journal history and
    is left alone deliberately — §7.1 of the contract. What the integration adds
    is that a reorg may not CROSS the boundary:
    `UndoRefusal::CrossesActivationCheckpoint` (`crates/state/src/reorg_undo.rs:548`,
    returned at `:634`) refuses, rather than unwinding half a branch
    from records that cannot restore it and reporting success. The refusal is
    the guarantee; the gap below the boundary remains a gap.

  * **The `tx_index` half of TS-10 destroys data.** Every subsystem event in a
    block is written at a key whose transaction index is a literal `0`, so the
    family holds one row per block — the last event — and every earlier event in
    that block is silently overwritten. The timestamp half is remediated behind
    `subsystem_block_timestamp_enabled_from_height`; this half is not.

  * **Fast sync is structurally unavailable.** The snapshot format carries the
    account family alone of the ten families a sync requires, so
    `restore_snapshot` refuses rather than producing a node that believes it is
    synced. `missing_for_fast_sync` computes the gap from the format's own
    declared family list rather than a hardcoded answer.

## What this file now is

All eleven subsystem inventories are in this file and none of them is a pointer
any more. Fifty-one entries were transcribed above from the six earlier commit
messages -- three from `855ec009`, two from `e293b03a`, eleven from `1c5494c`,
eleven from `04eb5bc`, ten from `026447f` and fourteen from `0706862` -- of
which eighteen are pinned by a named test, three rest on measured numbers with
no test named, and thirty are prose assertions with neither. Twenty-one
distinct test names appear across those entries and all twenty-one still exist
in this tree under the name their message gave them, so nothing in the six
earlier inventories has drifted out from under its pin. Nothing here was
recovered from memory: where a message asserts a test without naming it, names
a measurement without a test, or points at its own pointer, the entry records
that and stays where the evidence leaves it. The two absences are the loudest
part of the record -- PolicyAccount and messaging carry no deferred-defect
inventory at all, and finance's fourteen name no test at all, so for those
three subsystems this file transcribes an assertion and not evidence.
Deployment remains blocked on every entry above.
