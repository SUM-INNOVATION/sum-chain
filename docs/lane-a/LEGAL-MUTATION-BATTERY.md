# Legal routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.

    64 mutations, 64 killed, 0 survived, anchors-not-found 0,
    covering-tests-not-run 0, does-not-compile 0, anchors-unrestored 0,
    residue none. 56 of the 64 are the battery the commit message claims,
    verbatim; the other eight are additions, marked as such throughout.


## Provenance

This battery was RE-RUN against the legal commit's own tree -- 026447f, the
commit this document is added on top of -- rather than recovered from the
original run. The original artefacts do survive: the run's specification, and
per-mutation logs naming every one of the 56 mutations the commit message
claims, each with the libtest line it printed. They were not enough. They
record no hashes -- not of the anchors, not of the replacements, and not of
the mutated files before and after -- so there is no way to prove from them
that every mutation was restored, and a battery whose restoration cannot be
checked is not an audit of anything. They carry no residue scan and no
re-resolution of the anchors either, and they are fragmentary: the run was
split across five batches, two of which end in a `KeyboardInterrupt`
traceback rather than a total.

What the recovered specification is good for is CORRESPONDENCE. All 56 of its
anchors still resolve exactly once in this tree, and all 56 of its covering
tests still exist under those names, so the mutations re-run below are the
same mutations, verbatim, that the commit message counted. The first-pass
survivor the commit message mentions is also recovered from those logs, and
reproduced here deliberately -- see the section at the end.


## Method

Each mutation is applied to the tree that this commit contains, one at a time,
and the NAMED covering test is run BY NAME -- `cargo test -p <pkg> --test
<target> -- --exact <test>` -- so that SURVIVED means that test ran and
passed, rather than that something else in the target passed. A kill requires
that test to appear in libtest's output AND to have failed.

A mutation whose anchor does not resolve exactly once aborts the whole run
before anything is applied. One that does not compile, and one whose covering
test does not appear, are separate categories that never count as kills. No
two mutations share an anchor. Restoration happens in a `finally` and on
SIGINT/SIGTERM, every restore is checked against the pre-run sha256 before the
next mutation is applied, and the whole run is under `CARGO_INCREMENTAL=0`,
because an incremental dep-graph flake produced a spurious does-not-compile
verdict earlier in this lane.

Whole-tree text scanning for leftover replacements is diagnostic only. A
replacement is usable as a residue MARKER only if it does not already occur in
the pristine tree -- a scan that reports `Ok(false)` or `Ok(())` as residue is
reporting ordinary source code, which is how an earlier audit in this lane
produced twelve imaginary findings. The residue pass below classifies every
replacement on that test before scanning; in this battery all 64 turn out to be
specific, so the scan is meaningful for all of them and none the hashes have to
carry alone. The authoritative check is still the pre/post sha256 of every
mutated file, printed at the end of this document.


## Count, and the commit message's 56

64 mutations are declared here. 56 of them are the claimed battery,
verbatim. The other eight are additions, and they are marked as such in the
table below:

* seven repair a preserved inherited defect one at a time -- `ConsolidateCase`
  and `TransferCase` gain the authority check every other case operation has,
  `SupersedeOrder` gains a duplicate guard, `SupersedeEvent` starts verifying
  the case it indexes under, `VerifyProof` starts reading the proof, the live
  dispatch arm stops passing a literal `0` for `block_timestamp`, and a
  repeated consolidation stops being a no-op. The claimed battery reached only
  one of the ten deferred defects (the `contains` presence guard, five times);
  a defect that is deliberately preserved and pinned by a test deserves a
  mutation proving the pin actually holds;
* one files a case under the `:benefit` half of the shared jurisdiction family
  rather than the `:case` half. `LEGAL_JURISDICTION_INDEX` keeps cases and
  benefits apart by that suffix alone; the claimed battery broke the suffix
  only inside the key builder, where it collapses BOTH halves at once. This
  one breaks the separation at the call site, which is the failure the shared
  family actually invites.

Deferred defects 9 (the unbounded accumulating index values) and 10 (the
`LEGAL_SYSTEM_EVENTS` family no executor operation writes) get no mutation.
Both are the ABSENCE of code -- a bound that is not imposed, a call that is
never made -- and there is no single anchor whose replacement expresses them.
They are pinned by `a_640_kib_*_index_is_refused_by_the_ceiling_then_appended_to`
and by `published_rows_satisfy_the_committed_scans` respectively, and this
battery does not add to that.


## Summary by category

| category | mutations | killed | survived | not-run | does-not-compile |
|---|---|---|---|---|---|
| candidate-read-becomes-parent-read | 13 | 13 | 0 | 0 | 0 |
| codec-changed | 7 | 7 | 0 | 0 | 0 |
| decode-error-becomes-absence | 8 | 8 | 0 | 0 | 0 |
| dispatch-surface-short-circuited | 2 | 2 | 0 | 0 | 0 |
| key-builder-broken | 9 | 9 | 0 | 0 | 0 |
| multi-row-write-order-reversed | 4 | 4 | 0 | 0 | 0 |
| presence-guard-upgraded-to-a-decode | 5 | 5 | 0 | 0 | 0 |
| preserved-inherited-defect-repaired | 7 | 7 | 0 | 0 | 0 |
| shared-jurisdiction-family-suffix-swapped | 1 | 1 | 0 | 0 | 0 |
| staged-family-omitted | 8 | 8 | 0 | 0 | 0 |


## Pre-run file hashes

```
  9b49cb47ff9ebed599fbc53ae11604366784cd05c42902e94631a43b08397448  crates/state/src/legal_view.rs
  f4456fd0f7d7da2a5e9c4d4ce3e2fbbe04543f9130638776c827154d487751e8  crates/state/src/legal_executor.rs
  54722e9aceeaaecd1997bfcd007cc4e1f9ee78d6d89f41eab167f4623c1a2133  crates/state/src/executor.rs
  3249d3c0a2e15d118cacd0713d762ccfbc14d1570333ab9523813152b3c289e3  crates/storage/src/legal_store.rs
```


## Mutation -> anchor -> covering test

| # | id | in the claimed 56 | file | anchor sha256/16 | covering test | verdict |
|---|---|---|---|---|---|---|
| 1 | `A01-v_get_case` | yes | `crates/state/src/legal_view.rs` | `669caea054355b7a` | `a_case_update_finds_the_anchor_from_the_same_block` | KILLED |
| 2 | `A02-v_get_process_event` | yes | `crates/state/src/legal_view.rs` | `9bf1a8a5aa31c32e` | `an_event_status_update_finds_the_record_from_the_same_block` | KILLED |
| 3 | `A03-v_get_order` | yes | `crates/state/src/legal_view.rs` | `811c80f3bb822a60` | `an_order_status_update_finds_the_issue_from_the_same_block` | KILLED |
| 4 | `A04-v_get_benefit` | yes | `crates/state/src/legal_view.rs` | `3947e1b0ee010555` | `a_reinstatement_sees_the_suspension_from_the_same_block` | KILLED |
| 5 | `A05-v_get_proof` | yes | `crates/state/src/legal_view.rs` | `57292c77374206e8` | `a_submitted_proof_is_readable_from_the_candidate` | KILLED |
| 6 | `A06-v_get_case_event_ids` | yes | `crates/state/src/legal_view.rs` | `c1272c06d488f285` | `two_events_for_one_case_accumulate_in_the_case_index` | KILLED |
| 7 | `A07-v_get_case_order_ids` | yes | `crates/state/src/legal_view.rs` | `e40073b45c090d80` | `two_orders_for_one_case_accumulate_in_the_case_order_index` | KILLED |
| 8 | `A08-v_get_jurisdiction_ids` | yes | `crates/state/src/legal_view.rs` | `9f7a7cd6da86f84b` | `the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits` | KILLED |
| 9 | `A09-v_case_exists` | yes | `crates/state/src/legal_view.rs` | `5bca2d8704d88771` | `a_duplicate_case_anchor_in_the_same_block_is_refused` | KILLED |
| 10 | `A10-v_proof_exists` | yes | `crates/state/src/legal_view.rs` | `a8d341622a57f7a1` | `a_duplicate_proof_in_the_same_block_is_refused` | KILLED |
| 11 | `A11-v_order_exists` | yes | `crates/state/src/legal_view.rs` | `830ec937e7139016` | `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` | KILLED |
| 12 | `A12-v_benefit_exists` | yes | `crates/state/src/legal_view.rs` | `0aaf34a2a3ba8e80` | `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` | KILLED |
| 13 | `A13-v_process_event_exists` | yes | `crates/state/src/legal_view.rs` | `cf0559f8f94ce1b4` | `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` | KILLED |
| 14 | `B01-omit-LEGAL_CASES` | yes | `crates/state/src/legal_view.rs` | `0913fe95022c866f` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 15 | `B02-omit-LEGAL_JURISDICTION_INDEX` | yes | `crates/state/src/legal_view.rs` | `ed99f9674adeee64` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 16 | `B03-omit-LEGAL_EVENTS` | yes | `crates/state/src/legal_view.rs` | `fb9d2d87a060e005` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 17 | `B04-omit-LEGAL_CASE_EVENT_INDEX` | yes | `crates/state/src/legal_view.rs` | `bafb730a1a3655ce` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 18 | `B05-omit-LEGAL_ORDERS` | yes | `crates/state/src/legal_view.rs` | `bab1d7e62e09b753` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 19 | `B06-omit-LEGAL_CASE_ORDER_INDEX` | yes | `crates/state/src/legal_view.rs` | `8d40d60cf5bb0bc1` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 20 | `B07-omit-LEGAL_BENEFITS` | yes | `crates/state/src/legal_view.rs` | `69933a43935317f9` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 21 | `B08-omit-LEGAL_PROOFS` | yes | `crates/state/src/legal_view.rs` | `7e33c7e2857fe5f1` | `an_abandoned_block_leaves_all_eight_families_untouched` | KILLED |
| 22 | `C01-case_key` | yes | `crates/storage/src/legal_store.rs` | `e495d09a5d9bfdc8` | `a_case_row_is_bincode_at_the_case_id_key` | KILLED |
| 23 | `C02-process_event_key` | yes | `crates/storage/src/legal_store.rs` | `2942b8b876f3b46a` | `a_process_event_row_is_bincode_at_the_event_id_key` | KILLED |
| 24 | `C03-order_key` | yes | `crates/storage/src/legal_store.rs` | `4ad14513d1a31041` | `an_order_row_is_bincode_at_the_order_id_key` | KILLED |
| 25 | `C04-benefit_key` | yes | `crates/storage/src/legal_store.rs` | `3ebd4362d9a68d7b` | `a_benefit_row_is_bincode_at_the_benefit_id_key` | KILLED |
| 26 | `C05-proof_key` | yes | `crates/storage/src/legal_store.rs` | `e945152171c596a0` | `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` | KILLED |
| 27 | `C06-case_event_index_key` | yes | `crates/storage/src/legal_store.rs` | `29323bfdfd121708` | `a_process_event_indexes_itself_under_its_case_id` | KILLED |
| 28 | `C07-case_order_index_key` | yes | `crates/storage/src/legal_store.rs` | `dcd39ad1acacde92` | `an_order_indexes_itself_under_its_case_id_in_its_own_family` | KILLED |
| 29 | `C08-jurisdiction_index_key` | yes | `crates/storage/src/legal_store.rs` | `ca091df7e64278ad` | `a_case_puts_its_id_in_the_jurisdiction_index_under_the_case_suffix` | KILLED |
| 30 | `C09-legal_event_key` | yes | `crates/storage/src/legal_store.rs` | `c681add1a518c4be` | `a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key` | KILLED |
| 31 | `D01-encode_case` | yes | `crates/storage/src/legal_store.rs` | `5d143b7430478909` | `a_case_row_is_bincode_at_the_case_id_key` | KILLED |
| 32 | `D02-encode_process_event` | yes | `crates/storage/src/legal_store.rs` | `1dbe972e23fafe15` | `a_process_event_row_is_bincode_at_the_event_id_key` | KILLED |
| 33 | `D03-encode_order` | yes | `crates/storage/src/legal_store.rs` | `f1ef0ea5f550e93d` | `an_order_row_is_bincode_at_the_order_id_key` | KILLED |
| 34 | `D04-encode_benefit` | yes | `crates/storage/src/legal_store.rs` | `e79766382e9022fe` | `a_benefit_row_is_bincode_at_the_benefit_id_key` | KILLED |
| 35 | `D05-encode_proof` | yes | `crates/storage/src/legal_store.rs` | `e3e33faa705f7907` | `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` | KILLED |
| 36 | `D06-encode_id_list` | yes | `crates/storage/src/legal_store.rs` | `046418dba0a9ce6c` | `a_second_case_in_one_jurisdiction_appends_to_the_same_list` | KILLED |
| 37 | `D07-encode_legal_event` | yes | `crates/storage/src/legal_store.rs` | `5653643e67c21d3a` | `a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key` | KILLED |
| 38 | `E01-swallow-case` | yes | `crates/state/src/legal_view.rs` | `68cbed24b98fc7ab` | `malformed_primary_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 39 | `E02-swallow-order` | yes | `crates/state/src/legal_view.rs` | `409f20574266c6fc` | `malformed_primary_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 40 | `E03-swallow-benefit` | yes | `crates/state/src/legal_view.rs` | `0d26ef96e244f53c` | `malformed_primary_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 41 | `E04-swallow-proof` | yes | `crates/state/src/legal_view.rs` | `2b6387cda89ba421` | `a_corrupt_proof_row_makes_the_candidate_reader_error` | KILLED |
| 42 | `E05-swallow-process-event` | yes | `crates/state/src/legal_view.rs` | `a9fbee71cfb4f572` | `malformed_primary_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 43 | `E06-swallow-case-event-index` | yes | `crates/state/src/legal_view.rs` | `43ef4b2584c7726a` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 44 | `E07-swallow-case-order-index` | yes | `crates/state/src/legal_view.rs` | `1d94f8a8bfc1bc76` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 45 | `E08-swallow-jurisdiction-index` | yes | `crates/state/src/legal_view.rs` | `82930392837d0a26` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 46 | `F01-reverse-put-case-order` | yes | `crates/state/src/legal_view.rs` | `8b4a904a6af3b446` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 47 | `F02-reverse-put-process-event-order` | yes | `crates/state/src/legal_view.rs` | `5764636e67e6a6be` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 48 | `F03-reverse-put-order-order` | yes | `crates/state/src/legal_view.rs` | `c1e2300ec906e531` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 49 | `F04-reverse-put-benefit-order` | yes | `crates/state/src/legal_view.rs` | `0de18883de2c173f` | `a_malformed_index_row_fails_after_its_primary_row_is_staged` | KILLED |
| 50 | `H01-decode-case-duplicate-guard` | yes | `crates/state/src/legal_executor.rs` | `5bdca42361fa5a26` | `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` | KILLED |
| 51 | `H02-decode-event-duplicate-guard` | yes | `crates/state/src/legal_executor.rs` | `7a437541816efd7f` | `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` | KILLED |
| 52 | `H03-decode-order-duplicate-guard` | yes | `crates/state/src/legal_executor.rs` | `4e4ca7f8386a7c69` | `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` | KILLED |
| 53 | `H04-decode-benefit-duplicate-guard` | yes | `crates/state/src/legal_executor.rs` | `f49c2680a43b349e` | `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` | KILLED |
| 54 | `H05-decode-proof-duplicate-guard` | yes | `crates/state/src/legal_executor.rs` | `79c9ae34e6628b19` | `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` | KILLED |
| 55 | `G01-shortcircuit-execute_tx_with_validators` | yes | `crates/state/src/executor.rs` | `118604a665f7bf61` | `without_the_anchor_the_same_case_update_is_refused` | KILLED |
| 56 | `G02-shortcircuit-execute_tx_v2` | yes | `crates/state/src/executor.rs` | `8216b7cfba4c8730` | `the_v2_dispatch_surface_refuses_with_the_legal_code` | KILLED |
| 57 | `I01-repair-consolidate-authority` | NO -- added | `crates/state/src/legal_executor.rs` | `6806537756de1e55` | `consolidate_case_has_no_authority_check` | KILLED |
| 58 | `I02-repair-transfer-authority` | NO -- added | `crates/state/src/legal_executor.rs` | `307439163f6bd3d0` | `transfer_case_has_no_authority_check` | KILLED |
| 59 | `I03-repair-supersede-order-guard` | NO -- added | `crates/state/src/legal_executor.rs` | `4d8784a399574224` | `supersede_order_overwrites_an_existing_order_without_a_guard` | KILLED |
| 60 | `I04-repair-supersede-event-case-check` | NO -- added | `crates/state/src/legal_executor.rs` | `b9fa9fb8cbb6f19c` | `supersede_event_indexes_under_a_case_that_need_not_exist` | KILLED |
| 61 | `I05-repair-verify-proof` | NO -- added | `crates/state/src/legal_executor.rs` | `3085593ee1ecf0ef` | `verify_proof_verifies_nothing_and_still_charges_the_fee` | KILLED |
| 62 | `I06-repair-zero-timestamp-live-arm` | NO -- added | `crates/state/src/executor.rs` | `2fc7ef5dd812e0e0` | `a_status_transition_stamps_a_zero_timestamp` | KILLED |
| 63 | `I07-repair-repeated-consolidation` | NO -- added | `crates/state/src/legal_view.rs` | `dcd23d5302f7ef91` | `a_repeated_consolidation_is_a_paid_no_op` | KILLED |
| 64 | `J01-case-indexed-under-the-benefit-suffix` | NO -- added | `crates/state/src/legal_view.rs` | `a73610ff67475b1e` | `the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits` | KILLED |


## The 64 mutations, verbatim


### `crates/state/src/legal_view.rs`

#### 1. `A01-v_get_case` -- the case read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `669caea054355b7a8771e72494298af7d58f9c2ad02b3b7a74796be7ef6c3a55`
* replacement sha256 `e4cf52c077346d6f0a76d38a3520ed2b85836cc5aec04279760e6d971e54105a`
* covering test: `a_case_update_finds_the_anchor_from_the_same_block` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_CASES, case_key(case_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_CASES, case_key(case_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_CASES, case_key(case_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test a_case_update_finds_the_anchor_from_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```

#### 2. `A02-v_get_process_event` -- the process-event read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `9bf1a8a5aa31c32eb7fade792151e365be990036842adb38f66aa85233f510bc`
* replacement sha256 `a53d02a4dbee7ccad0914c84aadf5ab1e92f5f334e2e4b64d7686711da858ef4`
* covering test: `an_event_status_update_finds_the_record_from_the_same_block` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_EVENTS, process_event_key(event_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_EVENTS, process_event_key(event_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_EVENTS, process_event_key(event_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test an_event_status_update_finds_the_record_from_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 3. `A03-v_get_order` -- the order read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `811c80f3bb822a605eb52e687d90be80ce6995842fec56dbbbde4690c8dd8a18`
* replacement sha256 `5c266af6f7a4d01c755bc3ccc3d44061fa86d368f6f42f30f79c92ea4c5c96f5`
* covering test: `an_order_status_update_finds_the_issue_from_the_same_block` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_ORDERS, order_key(order_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_ORDERS, order_key(order_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_ORDERS, order_key(order_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test an_order_status_update_finds_the_issue_from_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.14s
```

#### 4. `A04-v_get_benefit` -- the benefit read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `3947e1b0ee0105555422df920db92335fc7d5d4261c5fc74158d1549501490bb`
* replacement sha256 `6262d593e9b84ad88c7cdf8948f43a8c03f52578848ba44f789076d71d563c6c`
* covering test: `a_reinstatement_sees_the_suspension_from_the_same_block` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_BENEFITS, benefit_key(benefit_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test a_reinstatement_sees_the_suspension_from_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```

#### 5. `A05-v_get_proof` -- the proof read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `57292c77374206e80e0a579f1050ad3b07b9a904ccebb9cc98b36f4aeacb3a73`
* replacement sha256 `d796621336286146010d970494f5c5eefda52cf140e052784925b140b2463f78`
* covering test: `a_submitted_proof_is_readable_from_the_candidate` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_PROOFS, proof_key(proof_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_PROOFS, proof_key(proof_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test a_submitted_proof_is_readable_from_the_candidate ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.14s
```

#### 6. `A06-v_get_case_event_ids` -- the case->events index read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `c1272c06d488f285e8d3359c9072bfbfd361a36f8101ce0a11f9f9663b1a9c16`
* replacement sha256 `4e774c68a1e93e2e0e12eb925e2f22cd8eb7aca7e006e484da32c7ef63a2ecc3`
* covering test: `two_events_for_one_case_accumulate_in_the_case_index` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test two_events_for_one_case_accumulate_in_the_case_index ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.17s
```

#### 7. `A07-v_get_case_order_ids` -- the case->orders index read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `e40073b45c090d80cd1a83b2cc80803ec3ce9a3cfa9831b0dae76c8b89a343f7`
* replacement sha256 `2979b4f656ced07b3334d8108319954ee9236e4b27920b4d5358dff6ad19aee7`
* covering test: `two_orders_for_one_case_accumulate_in_the_case_order_index` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id)) {
                Some(pre) => pre.clone(),
                None => view
                    .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test two_orders_for_one_case_accumulate_in_the_case_order_index ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.16s
```

#### 8. `A08-v_get_jurisdiction_ids` -- the jurisdiction index read answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `9f7a7cd6da86f84bc3aaa3350923923815c4260979359f3c5fdefee04378932f`
* replacement sha256 `98aff773491f33ab137c3ae0f1fd134d827e7087be64ad4a178a18c38def871b`
* covering test: `the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        match view
            .get(
                cf::LEGAL_JURISDICTION_INDEX,
                &jurisdiction_index_key(jurisdiction, id_type),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:
```rust
        match {
            match view.preimage(
                cf::LEGAL_JURISDICTION_INDEX,
                &jurisdiction_index_key(jurisdiction, id_type),
            ) {
                Some(pre) => pre.clone(),
                None => view
                    .get(
                        cf::LEGAL_JURISDICTION_INDEX,
                        &jurisdiction_index_key(jurisdiction, id_type),
                    )
                    .map_err(StateError::Storage)?,
            }
        } {
```

Printed by libtest while mutated:
```
test the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```

#### 9. `A09-v_case_exists` -- the case `exists` guard answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `5bca2d8704d88771d3baec2732b2426e094385af968373089942cb81089d8e4c`
* replacement sha256 `3ca93fc6819ded94c2671a746c6c465a988bb08546f789e67cac731a690cf29e`
* covering test: `a_duplicate_case_anchor_in_the_same_block_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::LEGAL_CASES, case_key(case_id))
            .map_err(StateError::Storage)
```

Replacement:
```rust
        match view.preimage(cf::LEGAL_CASES, case_key(case_id)) {
            Some(pre) => Ok(pre.is_some()),
            None => view
                .contains(cf::LEGAL_CASES, case_key(case_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:
```
test a_duplicate_case_anchor_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.18s
```

#### 10. `A10-v_proof_exists` -- the proof `exists` guard answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `a8d341622a57f7a1eeee7c6db8f27b98bfaf70c4388cf466add897712dc17cab`
* replacement sha256 `a8542ae5773ba84115210c3967e5661131a75979f4981719ec44cfe1de3a9817`
* covering test: `a_duplicate_proof_in_the_same_block_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::LEGAL_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
```

Replacement:
```rust
        match view.preimage(cf::LEGAL_PROOFS, proof_key(proof_id)) {
            Some(pre) => Ok(pre.is_some()),
            None => view
                .contains(cf::LEGAL_PROOFS, proof_key(proof_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:
```
test a_duplicate_proof_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.17s
```

#### 11. `A11-v_order_exists` -- the order `exists` guard answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `830ec937e71390166d59b11ca455d76d32b65f038baaec25eb763083674dd13d`
* replacement sha256 `2db3915f84476a0e2691de477fdfcf3f1b34743f351b1b5a47b08bcb95483f65`
* covering test: `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::LEGAL_ORDERS, order_key(order_id))
            .map_err(StateError::Storage)
```

Replacement:
```rust
        match view.preimage(cf::LEGAL_ORDERS, order_key(order_id)) {
            Some(pre) => Ok(pre.is_some()),
            None => view
                .contains(cf::LEGAL_ORDERS, order_key(order_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:
```
test a_duplicate_event_order_or_benefit_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.17s
```

#### 12. `A12-v_benefit_exists` -- the benefit `exists` guard answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `0aaf34a2a3ba8e80cd00abb33390ed806ef08bad0641792ddf59455992e1cbe3`
* replacement sha256 `ae5980dac7345126b511446cb706afb959bffc85d31afb1ae002d98d4da1b99a`
* covering test: `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
            .map_err(StateError::Storage)
```

Replacement:
```rust
        match view.preimage(cf::LEGAL_BENEFITS, benefit_key(benefit_id)) {
            Some(pre) => Ok(pre.is_some()),
            None => view
                .contains(cf::LEGAL_BENEFITS, benefit_key(benefit_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:
```
test a_duplicate_event_order_or_benefit_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.16s
```

#### 13. `A13-v_process_event_exists` -- the process-event `exists` guard answers from the parent block

* category: candidate-read-becomes-parent-read
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `cf0559f8f94ce1b4a4c1d5644d2a86a29602e5b6d8578e5911be2c7d40c07474`
* replacement sha256 `1704931fd832873dbc913cbca1963bbe72c2e48e73b286e090c7568ecf4d13f8`
* covering test: `a_duplicate_event_order_or_benefit_in_the_same_block_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.contains(cf::LEGAL_EVENTS, process_event_key(event_id))
            .map_err(StateError::Storage)
```

Replacement:
```rust
        match view.preimage(cf::LEGAL_EVENTS, process_event_key(event_id)) {
            Some(pre) => Ok(pre.is_some()),
            None => view
                .contains(cf::LEGAL_EVENTS, process_event_key(event_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:
```
test a_duplicate_event_order_or_benefit_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.16s
```

#### 14. `B01-omit-LEGAL_CASES` -- the `LEGAL_CASES` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `0913fe95022c866fe1bdeae7cbfde1f698d8d53df80ff67f072889f16ec8cff1`
* replacement sha256 `720eedc4171850ad485c171e3f02e5667996f1adf4e1f9a90f5a56019d278611`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::LEGAL_CASES, case_key(&case.case_id), &bytes)
            .map_err(StateError::Storage)?;
```

Replacement:
```rust
        let _ = (case_key(&case.case_id), &bytes);
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```

#### 15. `B02-omit-LEGAL_JURISDICTION_INDEX` -- the `LEGAL_JURISDICTION_INDEX` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `ed99f9674adeee64bf22c85a45981c7c3fed64bf184d2ee53754ff0e6a3da7d9`
* replacement sha256 `df8b8b618c2064434764bb98c60b68be5f593be4e5753d2132128bdb3f95d734`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::LEGAL_JURISDICTION_INDEX,
            &jurisdiction_index_key(jurisdiction, id_type),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:
```rust
        let _ = (&jurisdiction_index_key(jurisdiction, id_type), &bytes);
        Ok(())
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.17s
```

#### 16. `B03-omit-LEGAL_EVENTS` -- the `LEGAL_EVENTS` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `fb9d2d87a060e0053516e3a60aa3e6517d3479f5eac9d52982adb12e049e92cb`
* replacement sha256 `6b0a92bc32fba5af7deab039fb0090116a95f6a44ba8077055dcd9d652bc377e`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::LEGAL_EVENTS, process_event_key(&event.event_id), &bytes)
            .map_err(StateError::Storage)?;
```

Replacement:
```rust
        let _ = (process_event_key(&event.event_id), &bytes);
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.19s
```

#### 17. `B04-omit-LEGAL_CASE_EVENT_INDEX` -- the `LEGAL_CASE_EVENT_INDEX` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `bafb730a1a3655cebba275bf1bf1d8e8dbf9fab044998b84ebc83735ec575819`
* replacement sha256 `68901039b8cc8261d25a738b06861b7a2b3088ec9ce1bc446bf641b53afb8b17`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::LEGAL_CASE_EVENT_INDEX,
            case_event_index_key(case_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:
```rust
        let _ = (case_event_index_key(case_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.16s
```

#### 18. `B05-omit-LEGAL_ORDERS` -- the `LEGAL_ORDERS` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `bab1d7e62e09b7532ae34ff1470b3fc57ea11283f91ca2904b5a0b3b768c2708`
* replacement sha256 `a148268822264a4464fcaef9936dd6cb12bac962f3ed039d19adf6e8b00c17f5`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::LEGAL_ORDERS, order_key(&order.order_id), &bytes)
            .map_err(StateError::Storage)?;
```

Replacement:
```rust
        let _ = (order_key(&order.order_id), &bytes);
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.19s
```

#### 19. `B06-omit-LEGAL_CASE_ORDER_INDEX` -- the `LEGAL_CASE_ORDER_INDEX` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `8d40d60cf5bb0bc15a4370929f6eb1cfca62305e4b24b0267ff786c3a7fa27f5`
* replacement sha256 `0edabb1f095649efd18c0ad38d1712ad4939553d75a09ec47e8adc5a1e360406`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(
            cf::LEGAL_CASE_ORDER_INDEX,
            case_order_index_key(case_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:
```rust
        let _ = (case_order_index_key(case_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.18s
```

#### 20. `B07-omit-LEGAL_BENEFITS` -- the `LEGAL_BENEFITS` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `69933a43935317f91374b7e9515ef60ef728e2257d27690dec44e6f83587ac37`
* replacement sha256 `07278af2ffb5fcf6e854c5def476e3b2423c97fc585b5c911cb39de07ce0b5b8`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::LEGAL_BENEFITS, benefit_key(&benefit.benefit_id), &bytes)
            .map_err(StateError::Storage)?;
```

Replacement:
```rust
        let _ = (benefit_key(&benefit.benefit_id), &bytes);
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.26s
```

#### 21. `B08-omit-LEGAL_PROOFS` -- the `LEGAL_PROOFS` write is never staged

* category: staged-family-omitted
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `7e33c7e2857fe5f1cf3947435d11c1113e83792ceded833d2f8df80c2f474649`
* replacement sha256 `d575de1a487a34e211fd8e6bb9ef7e1de4e9f388aa3bcf9b984cef27350bbb36`
* covering test: `an_abandoned_block_leaves_all_eight_families_untouched` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        view.put(cf::LEGAL_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
```

Replacement:
```rust
        let _ = (proof_key(&proof.proof_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:
```
test an_abandoned_block_leaves_all_eight_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.20s
```

#### 22. `E01-swallow-case` -- a corrupt case row decodes as ABSENCE instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `68cbed24b98fc7ab03e129c744fb7ddb7aadd9742b59220f5e735470d4111edc`
* replacement sha256 `9e62c9328be0a06985717b7d33883bbb4fd18fa0da8ba7cff87712ddfc3049ab`
* covering test: `malformed_primary_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_case(&bytes).map_err(StateError::Storage)?)),
```

Replacement:
```rust
            Some(bytes) => Ok(decode_case(&bytes).ok()),
```

Printed by libtest while mutated:
```
test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 23. `E02-swallow-order` -- a corrupt order row decodes as ABSENCE instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `409f20574266c6fc3863fa87431833e8bd8ba19d20fc4fdbee703be5ca56c0fe`
* replacement sha256 `7c2f2d1abdd224043aa80aca4efcd71012e14e9b1a472e7514ce5a69c283c149`
* covering test: `malformed_primary_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_order(&bytes).map_err(StateError::Storage)?)),
```

Replacement:
```rust
            Some(bytes) => Ok(decode_order(&bytes).ok()),
```

Printed by libtest while mutated:
```
test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.35s
```

#### 24. `E03-swallow-benefit` -- a corrupt benefit row decodes as ABSENCE instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `0d26ef96e244f53cda57012879c661d5388fcd101d125b155ba4c39c92def705`
* replacement sha256 `4ad59ee35337d122b680cfad59480381f29496d37e0df9f0b37174a9824a0abc`
* covering test: `malformed_primary_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_benefit(&bytes).map_err(StateError::Storage)?)),
```

Replacement:
```rust
            Some(bytes) => Ok(decode_benefit(&bytes).ok()),
```

Printed by libtest while mutated:
```
test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.49s
```

#### 25. `E04-swallow-proof` -- a corrupt proof row decodes as ABSENCE instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `2b6387cda89ba421f3fa08cd7369e0d5346f61ff45a749baf34d0bafac9efbdb`
* replacement sha256 `760d3513a45cb799d3c959c11a411958462128678bbdded2b81cb4356549fac3`
* covering test: `a_corrupt_proof_row_makes_the_candidate_reader_error` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(decode_proof(&bytes).map_err(StateError::Storage)?)),
```

Replacement:
```rust
            Some(bytes) => Ok(decode_proof(&bytes).ok()),
```

Printed by libtest while mutated:
```
test a_corrupt_proof_row_makes_the_candidate_reader_error ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 26. `E05-swallow-process-event` -- a corrupt process-event row decodes as ABSENCE instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `a9fbee71cfb4f572fffd48589486a48281fc301bca2419c6ed72776b408b2615`
* replacement sha256 `c0630b109ce133fe0ab41965dde33fac43a4138adb7445e0c93a24be4c77547c`
* covering test: `malformed_primary_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            Some(bytes) => Ok(Some(
                decode_process_event(&bytes).map_err(StateError::Storage)?,
            )),
```

Replacement:
```rust
            Some(bytes) => Ok(decode_process_event(&bytes).ok()),
```

Printed by libtest while mutated:
```
test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.24s
```

#### 27. `E06-swallow-case-event-index` -- a corrupt case->events index row decodes as an EMPTY list instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `43ef4b2584c7726a1a8f2927812bf75117d46da353f2e3dd5a3f478a96304d0c`
* replacement sha256 `d10a6d377a0f870570354eb54806a84ba8f83ee4c2c49b5bf6605122eb23b964`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
```

Replacement:
```rust
            .get(cf::LEGAL_CASE_EVENT_INDEX, case_event_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.36s
```

#### 28. `E07-swallow-case-order-index` -- a corrupt case->orders index row decodes as an EMPTY list instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `1d94f8a8bfc1bc7661ba94936c50dff7b5a232c8a1a07b3e6a822bf69fe118ab`
* replacement sha256 `b4e3bf9a0d292e1775ad62ca00831570db43552d87d5cb8fab1dcd87445388ea`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
```

Replacement:
```rust
            .get(cf::LEGAL_CASE_ORDER_INDEX, case_order_index_key(case_id))
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.47s
```

#### 29. `E08-swallow-jurisdiction-index` -- a corrupt jurisdiction index row decodes as an EMPTY list instead of erroring

* category: decode-error-becomes-absence
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `82930392837d0a26c16b9470dc86980709c742fa93b5daf15951d8df9dc53891`
* replacement sha256 `ed567b519f56a8af2e3e92d2a667b9966d1fca4d3740ee334adbeca7939287f5`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                &jurisdiction_index_key(jurisdiction, id_type),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
```

Replacement:
```rust
                &jurisdiction_index_key(jurisdiction, id_type),
            )
            .map_err(StateError::Storage)?
        {
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.14s
```

#### 30. `F01-reverse-put-case-order` -- `v_put_case` writes its jurisdiction-index row BEFORE the case row

* category: multi-row-write-order-reversed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `8b4a904a6af3b446009087762fec021c588766455c06532c5dc290469b80eab0`
* replacement sha256 `12a60a5ae153ef9c1472e7e62ef820a8efee115ad04a04e9a69695bd6983dd11`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_case(case).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_CASES, case_key(&case.case_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &case.jurisdiction_code, &case.case_id, "case")
```

Replacement:
```rust
        let bytes = encode_case(case).map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(view, &case.jurisdiction_code, &case.case_id, "case")?;
        view.put(cf::LEGAL_CASES, case_key(&case.case_id), &bytes)
            .map_err(StateError::Storage)
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 31. `F02-reverse-put-process-event-order` -- `v_put_process_event` writes its case index row BEFORE the event row

* category: multi-row-write-order-reversed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `5764636e67e6a6befa862595bd824ad43374732d38dd2de3291c97cddd6b291d`
* replacement sha256 `9d1b15fac50b2149698238089443a7da85a8234dfa863ca019bdb80b3c601058`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_process_event(event).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_EVENTS, process_event_key(&event.event_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_case_event_index(view, &event.case_id, &event.event_id)
```

Replacement:
```rust
        let bytes = encode_process_event(event).map_err(StateError::Storage)?;
        Self::v_add_to_case_event_index(view, &event.case_id, &event.event_id)?;
        view.put(cf::LEGAL_EVENTS, process_event_key(&event.event_id), &bytes)
            .map_err(StateError::Storage)
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.38s
```

#### 32. `F03-reverse-put-order-order` -- `v_put_order` writes its case index row BEFORE the order row

* category: multi-row-write-order-reversed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `c1e2300ec906e531ca4a5f4518bdf2163d720a12bed1ac944464a3c9fa955fc4`
* replacement sha256 `40b8424b5b966ba6235c798eba4303f56674104349150456a1d1fe48c9974490`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_order(order).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_ORDERS, order_key(&order.order_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_case_order_index(view, &order.case_id, &order.order_id)
```

Replacement:
```rust
        let bytes = encode_order(order).map_err(StateError::Storage)?;
        Self::v_add_to_case_order_index(view, &order.case_id, &order.order_id)?;
        view.put(cf::LEGAL_ORDERS, order_key(&order.order_id), &bytes)
            .map_err(StateError::Storage)
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.48s
```

#### 33. `F04-reverse-put-benefit-order` -- `v_put_benefit` writes its jurisdiction-index row BEFORE the benefit row

* category: multi-row-write-order-reversed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `0de18883de2c173fd7274ced348ec12cdfffab909a4ac704dd2c267903ccfa80`
* replacement sha256 `3e1dee5da56bcafb74cbbf55bf0b930ac54d5fd6057eb1d4d0f108fad8d179fe`
* covering test: `a_malformed_index_row_fails_after_its_primary_row_is_staged` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        let bytes = encode_benefit(benefit).map_err(StateError::Storage)?;
        view.put(cf::LEGAL_BENEFITS, benefit_key(&benefit.benefit_id), &bytes)
            .map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(
            view,
            &benefit.jurisdiction_code,
            &benefit.benefit_id,
            "benefit",
        )
```

Replacement:
```rust
        let bytes = encode_benefit(benefit).map_err(StateError::Storage)?;
        Self::v_add_to_jurisdiction_index(
            view,
            &benefit.jurisdiction_code,
            &benefit.benefit_id,
            "benefit",
        )?;
        view.put(cf::LEGAL_BENEFITS, benefit_key(&benefit.benefit_id), &bytes)
            .map_err(StateError::Storage)
```

Printed by libtest while mutated:
```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.26s
```

#### 34. `I07-repair-repeated-consolidation` -- deferred defect 7 REPAIRED: a repeated consolidation stops being a no-op

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `dcd23d5302f7ef91d946ef5624d90292e6c92645f83a8586894b493fb8f8eff3`
* replacement sha256 `dc06cae8dcbd3a664ff13f1c42b262a288dfdc4b0bb6cc1a43af85c36ffdfb3b`
* covering test: `a_repeated_consolidation_is_a_paid_no_op` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if !case.related_cases.contains(related_case_id) {
                    case.related_cases.push(*related_case_id);
                    case.updated_at = timestamp;
```

Replacement:
```rust
                if true {
                    case.related_cases.push(*related_case_id);
                    case.updated_at = timestamp;
```

Printed by libtest while mutated:
```
test a_repeated_consolidation_is_a_paid_no_op ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 35. `J01-case-indexed-under-the-benefit-suffix` -- a case is filed under the `:benefit` half of the shared jurisdiction family

* category: shared-jurisdiction-family-suffix-swapped
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `a73610ff67475b1ee82606814508d970123e1bf74d1e4c50ac2c749cc5aabbaa`
* replacement sha256 `f3d5d8ff95bbac981c89390a8a810377584fb8581e3834153230c8b3fb64bc7b`
* covering test: `the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
        Self::v_add_to_jurisdiction_index(view, &case.jurisdiction_code, &case.case_id, "case")
```

Replacement:
```rust
        Self::v_add_to_jurisdiction_index(
            view,
            &case.jurisdiction_code,
            &case.case_id,
            "benefit",
        )
```

Printed by libtest while mutated:
```
test the_jurisdiction_index_accumulates_and_keeps_cases_apart_from_benefits ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```


### `crates/storage/src/legal_store.rs`

#### 36. `C01-case_key` -- `case_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `e495d09a5d9bfdc8b6a1f9681350a51799392d2a2eff5a72e5772a94f5867adf`
* replacement sha256 `88f5d707ff05a1b3eb3bed3df98f787ee5e3c70facb8e639c23324e08ecae32f`
* covering test: `a_case_row_is_bincode_at_the_case_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn case_key(case_id: &CaseId) -> &[u8] {
    case_id
}
```

Replacement:
```rust
pub fn case_key(case_id: &CaseId) -> &[u8] {
    &case_id[..16]
}
```

Printed by libtest while mutated:
```
test a_case_row_is_bincode_at_the_case_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.19s
```

#### 37. `C02-process_event_key` -- `process_event_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `2942b8b876f3b46adcf2516962446a933c83d947f6497a9d728f64e95afa4c27`
* replacement sha256 `c0d1e7ed31367d8855ebfeb3e4a8951765a705d602e6abe9b8cce7ca443ce4af`
* covering test: `a_process_event_row_is_bincode_at_the_event_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn process_event_key(event_id: &ProcessEventId) -> &[u8] {
    event_id
}
```

Replacement:
```rust
pub fn process_event_key(event_id: &ProcessEventId) -> &[u8] {
    &event_id[..16]
}
```

Printed by libtest while mutated:
```
test a_process_event_row_is_bincode_at_the_event_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.24s
```

#### 38. `C03-order_key` -- `order_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `4ad14513d1a31041f0b0d6a77abf372ae1cd7840bf133b19deee576b6ce4c9fa`
* replacement sha256 `96c524d415625edd9ef3062e458149f50fdff66d27865917d95a3784a8a63914`
* covering test: `an_order_row_is_bincode_at_the_order_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn order_key(order_id: &OrderId) -> &[u8] {
    order_id
}
```

Replacement:
```rust
pub fn order_key(order_id: &OrderId) -> &[u8] {
    &order_id[..16]
}
```

Printed by libtest while mutated:
```
test an_order_row_is_bincode_at_the_order_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.19s
```

#### 39. `C04-benefit_key` -- `benefit_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `3ebd4362d9a68d7beb7b4420699dc6b1b0be32ea4a6ad520617d9bde7041c5bf`
* replacement sha256 `12b7e687ac0ffb96a7db494935fd2fd85f48dfb7e0ff89d0225dc9917e12a891`
* covering test: `a_benefit_row_is_bincode_at_the_benefit_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn benefit_key(benefit_id: &BenefitId) -> &[u8] {
    benefit_id
}
```

Replacement:
```rust
pub fn benefit_key(benefit_id: &BenefitId) -> &[u8] {
    &benefit_id[..16]
}
```

Printed by libtest while mutated:
```
test a_benefit_row_is_bincode_at_the_benefit_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.15s
```

#### 40. `C05-proof_key` -- `proof_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `e945152171c596a02f865af6a382ef6c7df8206d703757871411fcc36323944b`
* replacement sha256 `f14b0124f5fc7288ee2df83ec2440c3073684a9cfb881b7c2ee6ffa6c86ab57d`
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn proof_key(proof_id: &ProofId) -> &[u8] {
    proof_id
}
```

Replacement:
```rust
pub fn proof_key(proof_id: &ProofId) -> &[u8] {
    &proof_id[..16]
}
```

Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.19s
```

#### 41. `C06-case_event_index_key` -- `case_event_index_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `29323bfdfd121708304909d5b7cf6533b047cd0cc198399626c878dc543e223c`
* replacement sha256 `2d46d434fef18a7aaf28888ea829e9a08e114516e08834622462f9e1036bbe68`
* covering test: `a_process_event_indexes_itself_under_its_case_id` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn case_event_index_key(case_id: &CaseId) -> &[u8] {
    case_id
}
```

Replacement:
```rust
pub fn case_event_index_key(case_id: &CaseId) -> &[u8] {
    &case_id[..16]
}
```

Printed by libtest while mutated:
```
test a_process_event_indexes_itself_under_its_case_id ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.17s
```

#### 42. `C07-case_order_index_key` -- `case_order_index_key` builds a truncated key

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `dcd39ad1acacde923976c25eb82f078e315f9aa3856f51e5815cc1825aed85a4`
* replacement sha256 `e93f7bf005a7164d9b8dbda05c6584b045f474243e5bc8ee626936dbcd522846`
* covering test: `an_order_indexes_itself_under_its_case_id_in_its_own_family` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn case_order_index_key(case_id: &CaseId) -> &[u8] {
    case_id
}
```

Replacement:
```rust
pub fn case_order_index_key(case_id: &CaseId) -> &[u8] {
    &case_id[..16]
}
```

Printed by libtest while mutated:
```
test an_order_indexes_itself_under_its_case_id_in_its_own_family ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.16s
```

#### 43. `C08-jurisdiction_index_key` -- `jurisdiction_index_key` drops the `:case`/`:benefit` suffix, merging the two halves of the shared family

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `ca091df7e64278ade09803887fd2c734a5f66d631d504dbee1813017b53e8785`
* replacement sha256 `935788e8a0061b3f7b76ec53ec818a918f83e3af27f743a3b6883bffa939ccff`
* covering test: `a_case_puts_its_id_in_the_jurisdiction_index_under_the_case_suffix` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn jurisdiction_index_key(jurisdiction: &str, id_type: &str) -> Vec<u8> {
    format!("{}:{}", jurisdiction, id_type).into_bytes()
}
```

Replacement:
```rust
pub fn jurisdiction_index_key(jurisdiction: &str, id_type: &str) -> Vec<u8> {
    let _ = id_type;
    jurisdiction.as_bytes().to_vec()
}
```

Printed by libtest while mutated:
```
test a_case_puts_its_id_in_the_jurisdiction_index_under_the_case_suffix ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.15s
```

#### 44. `C09-legal_event_key` -- `legal_event_key` writes the height little-endian

* category: key-builder-broken
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `c681add1a518c4be4b58b488f5f72f7cbcf27297185f8518ce50e3bb85251b17`
* replacement sha256 `7c332c825f0275c90fd8ac3634bf8953f0eec0e6be26913acb339b3f744148fd`
* covering test: `a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
    key[..8].copy_from_slice(&block_height.to_be_bytes());
    key[8..12].copy_from_slice(&tx_index.to_be_bytes());
```

Replacement:
```rust
    key[..8].copy_from_slice(&block_height.to_le_bytes());
    key[8..12].copy_from_slice(&tx_index.to_le_bytes());
```

Printed by libtest while mutated:
```
test a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.13s
```

#### 45. `D01-encode_case` -- `encode_case` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `5d143b7430478909c84011d86c93b7aaf3ad25f37849854a8fa2e985f277dcc9`
* replacement sha256 `b6272063acee66a3a1f41c27b47f57d4c24bc031b6c0d8f784e08fa340742885`
* covering test: `a_case_row_is_bincode_at_the_case_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_case(case: &CaseAnchor) -> Result<Vec<u8>> {
    bincode::serialize(case).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_case(case: &CaseAnchor) -> Result<Vec<u8>> {
    bincode::serialize(&(case, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_case_row_is_bincode_at_the_case_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.13s
```

#### 46. `D02-encode_process_event` -- `encode_process_event` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `1dbe972e23fafe153354389a609b96d8147b7c385a783243078ca807b281fc9f`
* replacement sha256 `af618b3066fb7bdd370afdb2f8d8b7d940195a94f892e86c48531462e12af2b1`
* covering test: `a_process_event_row_is_bincode_at_the_event_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_process_event(event: &ProcessEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_process_event(event: &ProcessEvent) -> Result<Vec<u8>> {
    bincode::serialize(&(event, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_process_event_row_is_bincode_at_the_event_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.13s
```

#### 47. `D03-encode_order` -- `encode_order` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `f1ef0ea5f550e93d8ac3e503303eb629e1253b5877b12de5bf859523e3e03ff5`
* replacement sha256 `1b7da47ddc8a6628345d1fbdc0b32a02c5af31def07c91b530cf44847a5f7fab`
* covering test: `an_order_row_is_bincode_at_the_order_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_order(order: &CourtOrder) -> Result<Vec<u8>> {
    bincode::serialize(order).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_order(order: &CourtOrder) -> Result<Vec<u8>> {
    bincode::serialize(&(order, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test an_order_row_is_bincode_at_the_order_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.13s
```

#### 48. `D04-encode_benefit` -- `encode_benefit` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `e79766382e9022fe72682265f6ca18d15137685ae5ed7bd8d73c469c58a6361d`
* replacement sha256 `fec02b64ae36e3a868b9dd38f998861904585cc40b3beac351ea40fe891ea46d`
* covering test: `a_benefit_row_is_bincode_at_the_benefit_id_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_benefit(benefit: &BenefitDetermination) -> Result<Vec<u8>> {
    bincode::serialize(benefit).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_benefit(benefit: &BenefitDetermination) -> Result<Vec<u8>> {
    bincode::serialize(&(benefit, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_benefit_row_is_bincode_at_the_benefit_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.13s
```

#### 49. `D05-encode_proof` -- `encode_proof` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `e3e33faa705f7907fcae4c4e44e40662d50326af1e25a217e3266a4520a03633`
* replacement sha256 `1647ad443fb3dbc0e48c62e80d94d0b4766e46edf914c74666f9d763da2cc99b`
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_proof(proof: &LegalProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_proof(proof: &LegalProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(&(proof, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_proof_row_is_bincode_at_the_proof_id_key_and_writes_no_index ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.15s
```

#### 50. `D06-encode_id_list` -- `encode_id_list` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `046418dba0a9ce6c79aab136166aeb1e58fa241a6d8d7204ebc33883892fadab`
* replacement sha256 `fd2d47fb6fc7b7d756a3e116bc1391da4a4ef229c2dff136d99aa6fb92b31d96`
* covering test: `a_second_case_in_one_jurisdiction_appends_to_the_same_list` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_id_list(ids: &[[u8; 32]]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_id_list(ids: &[[u8; 32]]) -> Result<Vec<u8>> {
    bincode::serialize(&(ids, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_second_case_in_one_jurisdiction_appends_to_the_same_list ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.15s
```

#### 51. `D07-encode_legal_event` -- `encode_legal_event` writes different bytes

* category: codec-changed
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `5653643e67c21d3a738b44a2f63a3f2334d433c5aa8b5ce8d6c03bd3c200cdb6`
* replacement sha256 `f48a5f5bb37704c2a942ca57b99faf1290148973044f943d69b26e263ce7c658`
* covering test: `a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key` (`sumchain-storage --test legal_codec_parity -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
pub fn encode_legal_event(event: &LegalEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:
```rust
pub fn encode_legal_event(event: &LegalEvent) -> Result<Vec<u8>> {
    bincode::serialize(&(event, 0u8)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:
```
test a_system_event_row_is_bincode_at_a_big_endian_height_and_index_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.14s
```


### `crates/state/src/legal_executor.rs`

#### 52. `H01-decode-case-duplicate-guard` -- the case duplicate guard decodes the row instead of testing presence

* category: presence-guard-upgraded-to-a-decode
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `5bdca42361fa5a26a8e10d3723638e963355cf729e51ca58f6aa98839386aed3`
* replacement sha256 `0e9dfb47de164861ee696df3c5fa08b965371613eccf1456df0e088e85860f6c`
* covering test: `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_case_exists(view, &case.case_id)? {
```

Replacement:
```rust
                if Self::v_get_case(view, &case.case_id)?.is_some() {
```

Printed by libtest while mutated:
```
test a_presence_guard_reads_a_corrupt_row_as_present_not_absent ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.16s
```

#### 53. `H02-decode-event-duplicate-guard` -- the event duplicate guard decodes the row instead of testing presence

* category: presence-guard-upgraded-to-a-decode
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `7a437541816efd7fd12ea639f39733908c7808aef27e8419db4d01cfe88cbc15`
* replacement sha256 `1f3c51dbf41b5b93e93ebe0922d92c22ab618b424b18d0bb59cac34783fff5ff`
* covering test: `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_process_event_exists(view, &event.event_id)? {
```

Replacement:
```rust
                if Self::v_get_process_event(view, &event.event_id)?.is_some() {
```

Printed by libtest while mutated:
```
test a_presence_guard_reads_a_corrupt_row_as_present_not_absent ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.35s
```

#### 54. `H03-decode-order-duplicate-guard` -- the order duplicate guard decodes the row instead of testing presence

* category: presence-guard-upgraded-to-a-decode
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `4e4ca7f8386a7c69e9fe82cee7e184c80f33e01c465a6a143febf279bd29a02d`
* replacement sha256 `0e94e42e3ce19c9e8dc2f8b890570487e4b9d96184504251e7637500f3802c91`
* covering test: `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_order_exists(view, &order.order_id)? {
```

Replacement:
```rust
                if Self::v_get_order(view, &order.order_id)?.is_some() {
```

Printed by libtest while mutated:
```
test a_presence_guard_reads_a_corrupt_row_as_present_not_absent ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.54s
```

#### 55. `H04-decode-benefit-duplicate-guard` -- the benefit duplicate guard decodes the row instead of testing presence

* category: presence-guard-upgraded-to-a-decode
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `f49c2680a43b349e2b59d99935e2686fa53a63ce17f418645e6d7a027295592c`
* replacement sha256 `623e1e7a1ef85354a7b0255a178e546e323ecacd21af04c47f3e0d01edc8c177`
* covering test: `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_benefit_exists(view, &benefit.benefit_id)? {
```

Replacement:
```rust
                if Self::v_get_benefit(view, &benefit.benefit_id)?.is_some() {
```

Printed by libtest while mutated:
```
test a_presence_guard_reads_a_corrupt_row_as_present_not_absent ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.65s
```

#### 56. `H05-decode-proof-duplicate-guard` -- the proof duplicate guard decodes the row instead of testing presence

* category: presence-guard-upgraded-to-a-decode
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `79c9ae34e6628b19b3705703c269b499d1089210715db27613ada76cc413ca2b`
* replacement sha256 `5257dc27cd4bf72a8c2db0ba1932c6ba853993abca37a024290937911f9afffa`
* covering test: `a_presence_guard_reads_a_corrupt_row_as_present_not_absent` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_proof_exists(view, &proof.proof_id)? {
```

Replacement:
```rust
                if Self::v_get_proof(view, &proof.proof_id)?.is_some() {
```

Printed by libtest while mutated:
```
test a_presence_guard_reads_a_corrupt_row_as_present_not_absent ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.27s
```

#### 57. `I01-repair-consolidate-authority` -- deferred defect 1 REPAIRED: `ConsolidateCase` gains an issuer check

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `6806537756de1e553098cac7237666e7b897aa4d177860473596b0d5fe8c3af7`
* replacement sha256 `e4bd69794c9b92c82ff390653c47a5a65e443ecc6d94eab7190bbb1f4000424b`
* covering test: `consolidate_case_has_no_authority_check` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_case(view, &d.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }
                if Self::v_get_case(view, &d.related_case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Related case not found"));
                }
```

Replacement:
```rust
                match Self::v_get_case(view, &d.case_id)? {
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                    Some(c) if c.issuer_address != *sender => {
                        return Ok(LegalExecutionResult::failure("Only issuer can consolidate"));
                    }
                    Some(_) => {}
                }
                if Self::v_get_case(view, &d.related_case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Related case not found"));
                }
```

Printed by libtest while mutated:
```
test consolidate_case_has_no_authority_check ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 58. `I02-repair-transfer-authority` -- deferred defect 2 REPAIRED: `TransferCase` gains an issuer check

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `307439163f6bd3d01fbcbd8873c1b7cdaad3b96705682e11c4dcd65d0768f558`
* replacement sha256 `a1df3ca3381e52d230096dcf2321521546130e3fd1f051c1f320e2fea5e1cb60`
* covering test: `transfer_case_has_no_authority_check` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_case(view, &d.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(
                    view,
                    &d.case_id,
                    CaseStatus::Transferred,
```

Replacement:
```rust
                match Self::v_get_case(view, &d.case_id)? {
                    None => return Ok(LegalExecutionResult::failure("Case not found")),
                    Some(c) if c.issuer_address != *sender => {
                        return Ok(LegalExecutionResult::failure("Only issuer can transfer"));
                    }
                    Some(_) => {}
                }

                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Self::v_update_case_status(
                    view,
                    &d.case_id,
                    CaseStatus::Transferred,
```

Printed by libtest while mutated:
```
test transfer_case_has_no_authority_check ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 59. `I03-repair-supersede-order-guard` -- deferred defect 3 REPAIRED: `SupersedeOrder` gains a duplicate guard

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `4d8784a39957422499b0a08ac585de1d3aa0ede36b36fdd5afffa0c3a38697e7`
* replacement sha256 `776eaf406e002918a43c0b1eea587e80935d813c35033cded8b60745bc428ca5`
* covering test: `supersede_order_overwrites_an_existing_order_without_a_guard` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_order(view, &d.old_order_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old order not found"));
                }
```

Replacement:
```rust
                if Self::v_get_order(view, &d.old_order_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old order not found"));
                }
                if Self::v_order_exists(view, &d.new_order.order_id)? {
                    return Ok(LegalExecutionResult::failure("Order already exists"));
                }
```

Printed by libtest while mutated:
```
test supersede_order_overwrites_an_existing_order_without_a_guard ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 60. `I04-repair-supersede-event-case-check` -- deferred defect 4 REPAIRED: `SupersedeEvent` verifies the new event's case

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `b9fa9fb8cbb6f19ceef3f335541086455fde41d8a1ce5278f8cad762551c4bc4`
* replacement sha256 `f8f5afc76909c3312664d80e4497efe79349d1a3e370f9b465d156ffbdd89294`
* covering test: `supersede_event_indexes_under_a_case_that_need_not_exist` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if Self::v_get_process_event(view, &d.old_event_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old event not found"));
                }
```

Replacement:
```rust
                if Self::v_get_process_event(view, &d.old_event_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Old event not found"));
                }
                if Self::v_get_case(view, &d.new_event.case_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Case not found"));
                }
```

Printed by libtest while mutated:
```
test supersede_event_indexes_under_a_case_that_need_not_exist ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.14s
```

#### 61. `I05-repair-verify-proof` -- deferred defect 5 REPAIRED: `VerifyProof` reads the proof it is asked about

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `3085593ee1ecf0ef97b4bc02848d9a52caaf210c30f8750b8a5d66ff19f3c4ca`
* replacement sha256 `aadd6cb452384ac317001b1bfe4acd01c2e70571005f889f106f7182f63c6313`
* covering test: `verify_proof_verifies_nothing_and_still_charges_the_fee` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
            LegalOperation::VerifyProof => {
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
```

Replacement:
```rust
            LegalOperation::VerifyProof => {
                // Verification is read-only - just record the request
                #[derive(serde::Deserialize)]
                struct VerifyData {
                    proof_id: [u8; 32],
                }
                let vd: VerifyData = match bincode::deserialize(&data.data) {
                    Ok(v) => v,
                    Err(_) => return Ok(LegalExecutionResult::failure("Invalid data")),
                };
                if Self::v_get_proof(view, &vd.proof_id)?.is_none() {
                    return Ok(LegalExecutionResult::failure("Proof not found"));
                }
                StateManager::v_deduct(view, sender, fee)?;
```

Printed by libtest while mutated:
```
test verify_proof_verifies_nothing_and_still_charges_the_fee ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```


### `crates/state/src/executor.rs`

#### 62. `G01-shortcircuit-execute_tx_with_validators` -- the live dispatch arm reports success whatever the executor returned

* category: dispatch-surface-short-circuited
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `118604a665f7bf6178de306bd4f33643044d7c4672fc496df7d6090b06e4fdac`
* replacement sha256 `77581c2e34b60ca4f96168310d51c90e8bfbc57581b1a2de8b62ee3a6e051d43`
* covering test: `without_the_anchor_the_same_case_update_is_refused` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                        if result.success {
                            debug!("V2 Legal {} executed: {:?}", tx_hash, legal_data.operation);
```

Replacement:
```rust
                        if result.success || true {
                            debug!("V2 Legal {} executed: {:?}", tx_hash, legal_data.operation);
```

Printed by libtest while mutated:
```
test without_the_anchor_the_same_case_update_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.14s
```

#### 63. `G02-shortcircuit-execute_tx_v2` -- the `execute_tx_v2` arm reports success whatever the executor returned

* category: dispatch-surface-short-circuited
* in the claimed 56: yes
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `8216b7cfba4c8730bfbaf2d3b9a60ccafd72f37c5d06ee22ea18c929fae6b3cc`
* replacement sha256 `879c567cb6e710d7f780634fa0ec4db8f0f607a8e9b6bb53af6c8e2721dfe499`
* covering test: `the_v2_dispatch_surface_refuses_with_the_legal_code` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                if result.success {
                    debug!("V2 Legal {} executed: {:?}", tx_hash, legal_data.operation);
```

Replacement:
```rust
                if result.success || true {
                    debug!("V2 Legal {} executed: {:?}", tx_hash, legal_data.operation);
```

Printed by libtest while mutated:
```
test the_v2_dispatch_surface_refuses_with_the_legal_code ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.13s
```

#### 64. `I06-repair-zero-timestamp-live-arm` -- deferred defect 6 REPAIRED: the live arm stops passing a literal `0` timestamp

* category: preserved-inherited-defect-repaired
* in the claimed 56: **no -- added by this battery**
* occurrences checked before applying: **1** (expected 1)
* anchor sha256 `2fc7ef5dd812e0e086567043153a0b32673918ffe28768a995f1f31f3bcdeb1b`
* replacement sha256 `35370aaacdb2c422d0b252af68aa61d303c0fb385a2284e3f153f161ff61e333`
* covering test: `a_status_transition_stamps_a_zero_timestamp` (`sumchain-state --test legal_routing -- --exact`)
* verdict: **KILLED**

Anchor:
```rust
                        let result = LegalExecutor::execute(
                            view,
                            &v2_tx.from,
                            &legal_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;
```

Replacement:
```rust
                        let result = LegalExecutor::execute(
                            view,
                            &v2_tx.from,
                            &legal_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            1, // block_timestamp placeholder
                            0, // tx_index placeholder
                            tx_hash,
                        )?;
```

Printed by libtest while mutated:
```
test a_status_transition_stamps_a_zero_timestamp ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.15s
```


## The first-pass survivor

The commit message records one first-pass survivor, and it is real. In the
original run `E06-swallow-case-event-index` -- the mutation that turns a
corrupt `LEGAL_CASE_EVENT_INDEX` row into an empty list rather than an error
-- was pointed at `malformed_primary_rows_error_through_dispatch_and_stage_nothing`,
which seeds corruption in the five PRIMARY families and never reads the
case->events index at all. That test could not have failed, so the mutation
was scored as a survivor rather than being quietly dropped. It was re-pointed
at `a_malformed_index_row_fails_after_its_primary_row_is_staged`, which does
read that family, and killed.

The original log lines, recovered:

```
[E06-swallow-case-event-index] swallow-decode         malformed_primary_rows_error_through_dispatch_and_stage_nothing
            test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... ok  -> SURVIVED
...
  SURVIVED: E06-swallow-case-event-index (swallow-decode) covering malformed_primary_rows_error_through_dispatch_and_stage_nothing

[E06-swallow-case-event-index] swallow-decode         a_malformed_index_row_fails_after_its_primary_row_is_staged
            test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED  -> KILLED
```

Reproduced here rather than taken on trust. The same mutation was run again
under this driver against the mis-pointed test, and survives in exactly the
same way -- so the survivor is a property of this tree, not an accident of the
original run:

* anchor sha256 `43ef4b2584c7726a1a8f2927812bf75117d46da353f2e3dd5a3f478a96304d0c` (occurrences before applying: 1)
* replacement sha256 `d10a6d377a0f870570354eb54806a84ba8f83ee4c2c49b5bf6605122eb23b964`
* mis-pointed covering test: `malformed_primary_rows_error_through_dispatch_and_stage_nothing`
* verdict: **SURVIVED**

```
test malformed_primary_rows_error_through_dispatch_and_stage_nothing ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.47s
```

and, re-pointed at the test that reads the family, in the battery above:

```
test a_malformed_index_row_fails_after_its_primary_row_is_staged ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 38 filtered out; finished in 0.36s
```

Both passes are recorded. The mutation is counted once, as a kill, on the
second.


## Totals and post-run hashes

```
=== totals ===
  killed: 64
  declared: 64   scored: 64

=== post-run hashes (authoritative) ===
  MATCH   9b49cb47ff9ebed599fbc53ae11604366784cd05c42902e94631a43b08397448  crates/state/src/legal_view.rs
  MATCH   f4456fd0f7d7da2a5e9c4d4ce3e2fbbe04543f9130638776c827154d487751e8  crates/state/src/legal_executor.rs
  MATCH   54722e9aceeaaecd1997bfcd007cc4e1f9ee78d6d89f41eab167f4623c1a2133  crates/state/src/executor.rs
  MATCH   3249d3c0a2e15d118cacd0713d762ccfbc14d1570333ab9523813152b3c289e3  crates/storage/src/legal_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  64/64
```


## Residue

```
=== 1. the four mutated files vs the pre-run backups ===
  MATCH   crates/state/src/legal_view.rs  9b49cb47ff9ebed599fbc53ae11604366784cd05c42902e94631a43b08397448
  MATCH   crates/state/src/legal_executor.rs  f4456fd0f7d7da2a5e9c4d4ce3e2fbbe04543f9130638776c827154d487751e8
  MATCH   crates/state/src/executor.rs  54722e9aceeaaecd1997bfcd007cc4e1f9ee78d6d89f41eab167f4623c1a2133
  MATCH   crates/storage/src/legal_store.rs  3249d3c0a2e15d118cacd0713d762ccfbc14d1570333ab9523813152b3c289e3
  all four restored: True

=== 2. whole-crates scan, 64 specific replacements ===
  residue: NONE
  0 replacements are text that already occurs in the pristine tree, so
  every one of them is a usable residue marker and none rests on the
  hashes alone.

=== 3. every anchor still resolves exactly once ===
  anchors resolving exactly once: 64/64; not-once: []
```
