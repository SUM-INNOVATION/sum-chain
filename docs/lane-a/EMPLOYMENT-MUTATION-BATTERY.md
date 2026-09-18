# Employment routing: mutation battery

NOT DEPLOYABLE ON ITS OWN, like the rest of this lane.


The commit that moved SRC-88X onto the block's execution view claimed a
mutation battery in its message and left no per-mutation record in the tree.
This document is that record, re-run against the tree THIS commit contains.
It is not a transcription of the earlier run: the scratch evidence from that
run carried anchors, replacements, covering tests and libtest lines, but no
file hashes of any kind, so nothing in it could be tied to a particular tree
or shown to have been restored. Every number below comes from a fresh run.

Each mutation is applied to the tree that this commit contains, one at a
time, and the NAMED covering test is run BY NAME (`-- --exact <test>`). A
kill requires that test to appear in libtest's output AND to have failed;
`survived` therefore means that named test PASSED with the mutation in the
tree, not that some other test in the target failed. A mutation whose anchor
does not resolve exactly once aborts the whole run before anything is
applied; one that does not compile, and one whose covering test does not
appear, are separate categories that never count as kills. Restoration
happens in a `finally` and on SIGINT/SIGTERM, and every restore is checked
against the pre-run sha256. The run is `CARGO_INCREMENTAL=0`: an incremental
dep-graph flake produced a spurious does-not-compile verdict earlier in this
lane.

    60 mutations, 60 killed, 0 survived, anchors-not-found 0, covering-tests-not-run 0, does-not-compile 0, anchors-unrestored 0, residue none

Whole-tree text scanning for leftover replacements is diagnostic only, and
is reported that way. A replacement is usable as a residue MARKER only if it
does not already occur somewhere in the pristine tree, since a hit on
ordinary source text proves nothing. Every one of these 60 replacements is a
multi-line block that occurs nowhere in the pristine `crates/` tree, so all
60 are scannable and all 60 were scanned -- but the AUTHORITATIVE check is
still the pre/post sha256 of every mutated file, because the driver writes
nowhere else and a text scan cannot see a change it has no marker for.


## Summary by category

| category | mutations | killed |
|---|---|---|
| candidate-read-becomes-parent-read | 13 | 13 |
| codec-changed | 6 | 6 |
| decode-error-becomes-absence | 9 | 9 |
| dispatch-surface-short-circuited | 4 | 4 |
| key-builder-broken | 11 | 11 |
| multi-row-write-order-reversed | 2 | 2 |
| preserved-defect-repaired | 6 | 6 |
| staged-family-omitted | 9 | 9 |


## Pre-run file hashes

```
  293b5d9439ff1345f6c16281001cda3df3c6ee5307c6a954a413bd68746f8905  crates/state/src/employment_view.rs
  37703fad74676511b22e17ebf801f0049f415f95ddd8ae709e1c85513bef216b  crates/state/src/employment_executor.rs
  66b952590fa83da23718f2907fddbf306ae96c9dd60acda47dcf1514fa1b9976  crates/state/src/executor.rs
  18d1847715b21a2c86d5255c6533d12d0e9aed50cbcef5bf00d2564408f4542b  crates/storage/src/employment_store.rs
```


## Mutation -> anchor -> covering test

| # | id | category | file | anchor sha256/16 | covering test | outcome |
|---|---|---|---|---|---|---|
| 1 | `A01-parent-read/v_get_issuer` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `2e9b1676c50343dc` | `a_credential_finds_an_issuer_registered_earlier_in_the_same_block` | KILLED |
| 2 | `A02-parent-read/v_issuer_exists` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `93fc3de55ea87553` | `a_suspension_finds_an_issuer_registered_earlier_in_the_same_block` | KILLED |
| 3 | `A03-parent-read/v_get_credential` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `2e8d6abf92156aaf` | `an_update_finds_the_credential_created_earlier_in_the_same_block` | KILLED |
| 4 | `A04-parent-read/v_credential_exists` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `95957c6782fdf546` | `a_duplicate_employment_id_in_the_same_block_is_refused` | KILLED |
| 5 | `A05-parent-read/v_get_attestation` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `5810536da1266ee6` | `a_revocation_finds_the_attestation_created_earlier_in_the_same_block` | KILLED |
| 6 | `A06-parent-read/v_attestation_exists` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `a7cd5a3d46028e7e` | `a_duplicate_attestation_id_in_the_same_block_is_refused` | KILLED |
| 7 | `A07-parent-read/v_get_proof` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `3ededb28e9a41a12` | `a_duplicate_proof_in_the_same_block_is_refused` | KILLED |
| 8 | `A08-parent-read/v_proof_exists` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `9aeb70959bb21c12` | `a_duplicate_proof_in_the_same_block_is_refused` | KILLED |
| 9 | `A09-parent-read/v_get_employee_credential_ids` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `59b04044caa5f553` | `two_credentials_for_one_employee_accumulate_in_all_three_indexes` | KILLED |
| 10 | `A10-parent-read/v_get_employee_address_credential_ids` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `5e0c24cf65d9d566` | `two_credentials_for_one_employee_accumulate_in_all_three_indexes` | KILLED |
| 11 | `A11-parent-read/v_get_employer_credential_ids` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `7763c0ebce17ca80` | `two_credentials_for_one_employee_accumulate_in_all_three_indexes` | KILLED |
| 12 | `A12-parent-read/v_get_subject_attestation_ids` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `92afb15802c5c67c` | `two_attestations_for_one_subject_accumulate_in_both_indexes` | KILLED |
| 13 | `A13-parent-read/v_get_holder_address_attestation_ids` | candidate-read-becomes-parent-read | `crates/state/src/employment_view.rs` | `6acab58a4b6ccd11` | `two_attestations_for_one_subject_accumulate_in_both_indexes` | KILLED |
| 14 | `B01-omit/EMPLOYMENT_ISSUERS` | staged-family-omitted | `crates/state/src/employment_view.rs` | `433c311b13c19433` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 15 | `B02-omit/EMPLOYMENT_CREDENTIALS` | staged-family-omitted | `crates/state/src/employment_view.rs` | `5394843a6192e18b` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 16 | `B03-omit/EMPLOYMENT_EMPLOYEE_INDEX` | staged-family-omitted | `crates/state/src/employment_view.rs` | `183153f8aca2e1bf` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 17 | `B04-omit/EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX` | staged-family-omitted | `crates/state/src/employment_view.rs` | `f2d0c74540568a62` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 18 | `B05-omit/EMPLOYMENT_EMPLOYER_INDEX` | staged-family-omitted | `crates/state/src/employment_view.rs` | `ff95812ce64f7473` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 19 | `B06-omit/EMPLOYMENT_INCOME_ATTESTATIONS` | staged-family-omitted | `crates/state/src/employment_view.rs` | `fe00500a949ec399` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 20 | `B07-omit/EMPLOYMENT_SUBJECT_INCOME_INDEX` | staged-family-omitted | `crates/state/src/employment_view.rs` | `417e83560e1adc98` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 21 | `B08-omit/EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX` | staged-family-omitted | `crates/state/src/employment_view.rs` | `af3805677c3869cc` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 22 | `B09-omit/EMPLOYMENT_PROOFS` | staged-family-omitted | `crates/state/src/employment_view.rs` | `f3755e20ea095e4f` | `an_abandoned_block_leaves_all_nine_families_untouched` | KILLED |
| 23 | `C01-key/issuer_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `baedb41f78fe3e26` | `an_issuer_row_is_bincode_at_the_address_key` | KILLED |
| 24 | `C02-key/credential_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `2518fa2bee346535` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 25 | `C03-key/employee_index_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `2eb7f6f251907ef8` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 26 | `C04-key/employee_address_index_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `bb4d7cbc82ed10dc` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 27 | `C05-key/employer_index_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `16387d5299e67338` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 28 | `C06-key/income_attestation_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `97ae8859a291f0e1` | `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` | KILLED |
| 29 | `C07-key/subject_income_index_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `9150e012549372c5` | `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` | KILLED |
| 30 | `C08-key/income_holder_address_index_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `d9c4ce8fd3d54d39` | `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` | KILLED |
| 31 | `C09-key/proof_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `5af8daf44557c6e1` | `a_proof_row_is_bincode_at_the_proof_id_key` | KILLED |
| 32 | `C10-key/event_key` | key-builder-broken | `crates/storage/src/employment_store.rs` | `d7b3e3a2b7c36767` | `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` | KILLED |
| 33 | `C11-key/event_height_prefix` | key-builder-broken | `crates/storage/src/employment_store.rs` | `e2d481528321351c` | `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` | KILLED |
| 34 | `D01-codec/encode_issuer` | codec-changed | `crates/storage/src/employment_store.rs` | `26b7b64a34e2f5a8` | `an_issuer_row_is_bincode_at_the_address_key` | KILLED |
| 35 | `D02-codec/encode_credential` | codec-changed | `crates/storage/src/employment_store.rs` | `158dde9405515128` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 36 | `D03-codec/encode_attestation` | codec-changed | `crates/storage/src/employment_store.rs` | `4601ca23a61d81db` | `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` | KILLED |
| 37 | `D04-codec/encode_proof` | codec-changed | `crates/storage/src/employment_store.rs` | `8eab919bd1f275b3` | `a_proof_row_is_bincode_at_the_proof_id_key` | KILLED |
| 38 | `D05-codec/encode_id_list` | codec-changed | `crates/storage/src/employment_store.rs` | `21296920f6908639` | `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` | KILLED |
| 39 | `D06-codec/encode_event` | codec-changed | `crates/storage/src/employment_store.rs` | `31294dd6f1130dda` | `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` | KILLED |
| 40 | `E01-error-to-absence/v_get_issuer` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `6dd5bd164addf217` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 41 | `E02-error-to-absence/v_get_credential` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `29038a02e902005a` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 42 | `E03-error-to-absence/v_get_attestation` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `2fc35e3311d08e8c` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 43 | `E04-error-to-absence/v_get_proof` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `60451fc874a55a0a` | `a_corrupt_proof_row_refuses_the_submission_rather_than_erroring` | KILLED |
| 44 | `E05-error-to-absence/v_get_employee_credential_ids` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `1ae01d92f6e3782b` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 45 | `E06-error-to-absence/v_get_employee_address_credential_ids` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `a50911c4d7395490` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 46 | `E07-error-to-absence/v_get_employer_credential_ids` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `4c946b9f98827a4d` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 47 | `E08-error-to-absence/v_get_subject_attestation_ids` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `47ac89d1ed19ffba` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 48 | `E09-error-to-absence/v_get_holder_address_attestation_ids` | decode-error-becomes-absence | `crates/state/src/employment_view.rs` | `808100d9589fb0fd` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 49 | `F01-order/v_put_credential` | multi-row-write-order-reversed | `crates/state/src/employment_view.rs` | `03d46311178f4d89` | `a_refusal_leaves_canonical_storage_untouched` | KILLED |
| 50 | `F02-order/v_put_attestation` | multi-row-write-order-reversed | `crates/state/src/employment_view.rs` | `700658201fc15dbd` | `malformed_rows_error_through_dispatch_and_stage_nothing` | KILLED |
| 51 | `G01-dispatch/execute_tx_with_validators-short-circuit` | dispatch-surface-short-circuited | `crates/state/src/executor.rs` | `20e859f278117dd5` | `without_the_registration_the_same_credential_is_refused` | KILLED |
| 52 | `G02-dispatch/execute_tx_v2-short-circuit` | dispatch-surface-short-circuited | `crates/state/src/executor.rs` | `379e490c240fbe19` | `the_v2_dispatch_surface_refuses_with_the_employment_status` | KILLED |
| 53 | `G03-dispatch/execute_tx_with_validators-status-code` | dispatch-surface-short-circuited | `crates/state/src/executor.rs` | `8c6c24093fcb2b55` | `without_the_registration_the_same_credential_is_refused` | KILLED |
| 54 | `G04-dispatch/execute_tx_v2-status-code` | dispatch-surface-short-circuited | `crates/state/src/executor.rs` | `d28347c526fdd05e` | `the_v2_dispatch_surface_refuses_with_the_employment_status` | KILLED |
| 55 | `H01-defect/proof-exists-never-decodes` | preserved-defect-repaired | `crates/state/src/employment_view.rs` | `62e29ddbfb9f64b2` | `a_corrupt_proof_row_refuses_the_submission_rather_than_erroring` | KILLED |
| 56 | `H02-defect/revoke-leaves-the-indexes` | preserved-defect-repaired | `crates/state/src/employment_view.rs` | `c8b63e24be5ac759` | `revoking_a_credential_leaves_all_three_index_entries_behind` | KILLED |
| 57 | `H03-defect/suspended-issuer-keeps-control` | preserved-defect-repaired | `crates/state/src/employment_executor.rs` | `ca95970d3f33970e` | `a_suspended_issuer_can_still_revoke_but_not_create` | KILLED |
| 58 | `H04-defect/verify-proof-verifies-nothing` | preserved-defect-repaired | `crates/state/src/employment_executor.rs` | `d2b91d0dc05d91f4` | `verify_proof_charges_a_fee_and_verifies_nothing` | KILLED |
| 59 | `H05-defect/update-attestation-refused-free` | preserved-defect-repaired | `crates/state/src/employment_executor.rs` | `d7f9dffdef78c375` | `update_income_attestation_is_refused_before_any_charge` | KILLED |
| 60 | `H06-defect/dispatch-discards-the-timestamp` | preserved-defect-repaired | `crates/state/src/executor.rs` | `87d2e8ba556676ed` | `every_status_update_records_a_zero_timestamp_through_dispatch` | KILLED |


## The 60 mutations

Each entry carries the verbatim anchor and replacement, the sha256 of both,
the occurrence count checked before the mutation was applied, the covering
test, and the lines libtest printed while that mutation was in the tree.


### `crates/state/src/employment_view.rs`


#### A01-parent-read/v_get_issuer

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_finds_an_issuer_registered_earlier_in_the_same_block` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `2e9b1676c50343dcc63e28c9746036a2547b9eb4dc96b6b361dae6c8f2e49bf0`
* replacement sha256: `ef7fc8eafcb56a2e7b4392f21be0565f835c7cc56f69c56a1959c10c336d57ef`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address)) {
            Some(p) => p.clone(),
            None => view
                .get(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test a_credential_finds_an_issuer_registered_earlier_in_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.14s
```


#### A02-parent-read/v_issuer_exists

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_suspension_finds_an_issuer_registered_earlier_in_the_same_block` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `93fc3de55ea875536aa35d09fc225cf925d0995734b2646e07e7d58336f999b6`
* replacement sha256: `36839c2e25f7406a8a08a00b53e720bb220f24b915659ecc70383db9cce69b74`
* verdict: **KILLED**

Anchor:

```rust
        view.contains(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
            .map_err(StateError::Storage)
```

Replacement:

```rust
        match view.preimage(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address)) {
            Some(p) => Ok(p.is_some()),
            None => view
                .contains(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:

```
test a_suspension_finds_an_issuer_registered_earlier_in_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### A03-parent-read/v_get_credential

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_update_finds_the_credential_created_earlier_in_the_same_block` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `2e8d6abf92156aaf7d42c2271e4c4e9cb857f46d519d2864c20f3c5b4923fd34`
* replacement sha256: `4e4a8d0486e7961869897f46600128f08511b8fff4a4b431076b9da10e75072a`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id)) {
            Some(p) => p.clone(),
            None => view
                .get(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test an_update_finds_the_credential_created_earlier_in_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### A04-parent-read/v_credential_exists

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_employment_id_in_the_same_block_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `95957c6782fdf54628f5944da78917152b5c5f3fdfd57c87d3c3194dc8f604e4`
* replacement sha256: `67086bf788ad1a3543de9b6db166051470b480da6ec1d9c753ce7ca296d302a5`
* verdict: **KILLED**

Anchor:

```rust
        view.contains(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
            .map_err(StateError::Storage)
```

Replacement:

```rust
        match view.preimage(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id)) {
            Some(p) => Ok(p.is_some()),
            None => view
                .contains(cf::EMPLOYMENT_CREDENTIALS, credential_key(employment_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:

```
test a_duplicate_employment_id_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.15s
```


#### A05-parent-read/v_get_attestation

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_revocation_finds_the_attestation_created_earlier_in_the_same_block` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `5810536da1266ee626338a15abede59a9053d74d63d342282c9ad6fae420bfd2`
* replacement sha256: `abef36ed42128af06c439eefcd3d50b75974dbefb521602bb92f639afc06a454`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                income_attestation_key(attestation_id),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_INCOME_ATTESTATIONS, income_attestation_key(attestation_id)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                    income_attestation_key(attestation_id),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test a_revocation_finds_the_attestation_created_earlier_in_the_same_block ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### A06-parent-read/v_attestation_exists

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_attestation_id_in_the_same_block_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `a7cd5a3d46028e7e1f0da2d5243c09157269a19bc01dac402e8de8cbbbc34c1b`
* replacement sha256: `aa0ef4902d4e3b77a18135ca651f49ed109cfbacf4816dba35baba109c4962be`
* verdict: **KILLED**

Anchor:

```rust
        view.contains(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        match view.preimage(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
        ) {
            Some(p) => Ok(p.is_some()),
            None => view
                .contains(
                    cf::EMPLOYMENT_INCOME_ATTESTATIONS,
                    income_attestation_key(attestation_id),
                )
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:

```
test a_duplicate_attestation_id_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### A07-parent-read/v_get_proof

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_proof_in_the_same_block_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `3ededb28e9a41a127b66fb5b1223c4b1f4333c80de339bbca0e2367d2bb0e55f`
* replacement sha256: `9a033a70fbb9fa3e9182e37f3a84c77383e5feacda1f7dc93bce8e9eedf2c21f`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_PROOFS, proof_key(proof_id)) {
            Some(p) => p.clone(),
            None => view
                .get(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test a_duplicate_proof_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### A08-parent-read/v_proof_exists

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_duplicate_proof_in_the_same_block_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `9aeb70959bb21c1270c9e1bf699d8c73f80d5f809fdc8e078838a1f789ce6a29`
* replacement sha256: `0eb6892ad1973e8c1db364c74909eec9473dab247806587ba9c451cf98ce167d`
* verdict: **KILLED**

Anchor:

```rust
        view.contains(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
```

Replacement:

```rust
        match view.preimage(cf::EMPLOYMENT_PROOFS, proof_key(proof_id)) {
            Some(p) => Ok(p.is_some()),
            None => view
                .contains(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
                .map_err(StateError::Storage),
        }
```

Printed by libtest while mutated:

```
test a_duplicate_proof_in_the_same_block_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.17s
```


#### A09-parent-read/v_get_employee_credential_ids

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `two_credentials_for_one_employee_accumulate_in_all_three_indexes` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `59b04044caa5f55315afed6694cf81988f6c01e9c2f6fa79aa8009ec754f349f`
* replacement sha256: `caff208b89a0850766d447afee02a4d6bac9799494927eb4b3ba6d384905a4d0`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYEE_INDEX,
                employee_index_key(employee_ref),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_EMPLOYEE_INDEX, employee_index_key(employee_ref)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_EMPLOYEE_INDEX,
                    employee_index_key(employee_ref),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test two_credentials_for_one_employee_accumulate_in_all_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### A10-parent-read/v_get_employee_address_credential_ids

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `two_credentials_for_one_employee_accumulate_in_all_three_indexes` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `5e0c24cf65d9d566564d9f53a19955b096d74960b0c42257e2a745238af7f5ee`
* replacement sha256: `7ef432e606b5895ff021c15a901f9fc346a787bd0631113053722fb5c8606131`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                employee_address_index_key(employee_address),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX, employee_address_index_key(employee_address)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
                    employee_address_index_key(employee_address),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test two_credentials_for_one_employee_accumulate_in_all_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.15s
```


#### A11-parent-read/v_get_employer_credential_ids

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `two_credentials_for_one_employee_accumulate_in_all_three_indexes` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `7763c0ebce17ca80bd0b203b289acbd655e9a844e55277c9c154724190754b9c`
* replacement sha256: `4260a11c9a15a13a969aa2016de36e47fc1a0d5e27ba27a5831d4de6f1be522c`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_EMPLOYER_INDEX,
                employer_index_key(employer_ref),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_EMPLOYER_INDEX, employer_index_key(employer_ref)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_EMPLOYER_INDEX,
                    employer_index_key(employer_ref),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test two_credentials_for_one_employee_accumulate_in_all_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.15s
```


#### A12-parent-read/v_get_subject_attestation_ids

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `two_attestations_for_one_subject_accumulate_in_both_indexes` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `92afb15802c5c67ccbcfe64be9e18eebc2c46a636c84430f1147e3d7389866b6`
* replacement sha256: `e9a3b1d74133f960d480324e26cbeaf0a5049faf129d962c2d2ae99a7cd2c5d3`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                subject_income_index_key(subject_ref),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_SUBJECT_INCOME_INDEX, subject_income_index_key(subject_ref)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
                    subject_income_index_key(subject_ref),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test two_attestations_for_one_subject_accumulate_in_both_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.17s
```


#### A13-parent-read/v_get_holder_address_attestation_ids

* category: candidate-read-becomes-parent-read
* occurrences checked before applying: **1** (expected 1)
* covering test: `two_attestations_for_one_subject_accumulate_in_both_indexes` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `6acab58a4b6ccd1155312aea3e6653c34e5d1e7cd8a27045d4a07094cbeca239`
* replacement sha256: `0f97e4b62fa787d00c0b2a967b56ed809bb99bfff33cd15847e1021e6aeb2ad5`
* verdict: **KILLED**

Anchor:

```rust
        match view
            .get(
                cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                income_holder_address_index_key(holder_address),
            )
            .map_err(StateError::Storage)?
        {
```

Replacement:

```rust
        match match view.preimage(cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX, income_holder_address_index_key(holder_address)) {
            Some(p) => p.clone(),
            None => view
                .get(
                    cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
                    income_holder_address_index_key(holder_address),
                )
                .map_err(StateError::Storage)?,
        } {
```

Printed by libtest while mutated:

```
test two_attestations_for_one_subject_accumulate_in_both_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### B01-omit/EMPLOYMENT_ISSUERS

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `433c311b13c19433d7c312dd4f1a6263848c5896cedbc586b989eccc345e8dee`
* replacement sha256: `8018a06612c7f6cffc876dd8e39e68f40da7038b84b3fb2c017b7d5b2dc68580`
* verdict: **KILLED**

Anchor:

```rust
        view.put(cf::EMPLOYMENT_ISSUERS, issuer_key(issuer_address), &bytes)
            .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, issuer_key(issuer_address), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.15s
```


#### B02-omit/EMPLOYMENT_CREDENTIALS

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `5394843a6192e18bcf1a88768bbe4266e96908fe16f9cc1442f71a8398e0f4dc`
* replacement sha256: `08eb222adc894f3cb8b97116709b7bf8c84edcf0c148090bdfa11dc6aece1f02`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_CREDENTIALS,
            credential_key(employment_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, credential_key(employment_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### B03-omit/EMPLOYMENT_EMPLOYEE_INDEX

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `183153f8aca2e1bf09d61c19e3b6b5afbc176330b28f477494f9f577cfd3745f`
* replacement sha256: `03784dd81a41ab4626e651ce01dde756c934472217d7403ef43ce997f5b11da2`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_EMPLOYEE_INDEX,
            employee_index_key(employee_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, employee_index_key(employee_ref), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.15s
```


#### B04-omit/EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `f2d0c74540568a625a5f65a63798c87158e447d3091519a7fc0bfbd5537aa67d`
* replacement sha256: `cee0157166f4e93c684c6d4295072ff0d6993a86d11930ffbd9d49ae3014f550`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_EMPLOYEE_ADDRESS_INDEX,
            employee_address_index_key(employee_address),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, employee_address_index_key(employee_address), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### B05-omit/EMPLOYMENT_EMPLOYER_INDEX

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `ff95812ce64f74738f7b2426589ce4776d6448ee59365af901ae94117fa85929`
* replacement sha256: `83bda5dcb5ac4553d2261825612be01554c48f7f2a08e724c4a68a58bffa2f27`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_EMPLOYER_INDEX,
            employer_index_key(employer_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, employer_index_key(employer_ref), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### B06-omit/EMPLOYMENT_INCOME_ATTESTATIONS

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `fe00500a949ec39947f3e78f8eb50a93fcebfb416301b085adc9ec14295f4d4e`
* replacement sha256: `ed52c6b4fe9a08314a1d8aab4f401fb9a0d9d9242995ab6cc44ec8f11adf009c`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_INCOME_ATTESTATIONS,
            income_attestation_key(attestation_id),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, income_attestation_key(attestation_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.17s
```


#### B07-omit/EMPLOYMENT_SUBJECT_INCOME_INDEX

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `417e83560e1adc98fb6e378f7dc357d64327fcd4c4db04a756f5d72f1153428d`
* replacement sha256: `2d84765f38eaa770c6e69ae49abd628accb1f54ae0567b37b834b80a6bb921d0`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_SUBJECT_INCOME_INDEX,
            subject_income_index_key(subject_ref),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, subject_income_index_key(subject_ref), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### B08-omit/EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `af3805677c3869cc76d77a2a6117d434f62b2eeaf83040f2bedc0298e51f41fa`
* replacement sha256: `d4e451766eb0275e9a068c30ea4e667594123b1cf01a75ddf7a8469542a2d781`
* verdict: **KILLED**

Anchor:

```rust
        view.put(
            cf::EMPLOYMENT_INCOME_HOLDER_ADDRESS_INDEX,
            income_holder_address_index_key(holder_address),
            &bytes,
        )
        .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, income_holder_address_index_key(holder_address), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### B09-omit/EMPLOYMENT_PROOFS

* category: staged-family-omitted
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_abandoned_block_leaves_all_nine_families_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `f3755e20ea095e4fffda4d92a1ebb676c95ec9e656aed3c3763b3312ec26a220`
* replacement sha256: `316a9b480e5a816ce891818f8d29feeb83e4aac5782f68593030e271d88cc70b`
* verdict: **KILLED**

Anchor:

```rust
        view.put(cf::EMPLOYMENT_PROOFS, proof_key(&proof.proof_id), &bytes)
            .map_err(StateError::Storage)
```

Replacement:

```rust
        let _ = (&*view, proof_key(&proof.proof_id), &bytes);
        Ok(())
```

Printed by libtest while mutated:

```
test an_abandoned_block_leaves_all_nine_families_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.14s
```


#### E01-error-to-absence/v_get_issuer

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `6dd5bd164addf217589df85fa588c7017bfacbfdf651eb081fa4180a8a10de6c`
* replacement sha256: `c2b21a8c8a41f4b0fefb6abb50aabf9eb022cbeba2bb2160ce95d7231465281b`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => Ok(Some(decode_issuer(&bytes).map_err(StateError::Storage)?)),
```

Replacement:

```rust
            Some(bytes) => Ok(decode_issuer(&bytes).ok()),
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### E02-error-to-absence/v_get_credential

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `29038a02e902005adcb5576b2a7d4ec1fecc97918fd96d7e5e2b0eaca8276210`
* replacement sha256: `7660237678bf52d88299698a73a8fed38fb9963a5f563e3ffdc9870bf0bdb786`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => Ok(Some(
                decode_credential(&bytes).map_err(StateError::Storage)?,
            )),
```

Replacement:

```rust
            Some(bytes) => Ok(decode_credential(&bytes).ok()),
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.24s
```


#### E03-error-to-absence/v_get_attestation

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `2fc35e3311d08e8cdb7355bde53bf729da67dd8619eab96b8f83fc7d65ee6246`
* replacement sha256: `e3ea410d940957c8f8b0fa8c6c0ea849719ab720673e2a24c181a65ce019afe7`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => Ok(Some(
                decode_attestation(&bytes).map_err(StateError::Storage)?,
            )),
```

Replacement:

```rust
            Some(bytes) => Ok(decode_attestation(&bytes).ok()),
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.69s
```


#### E04-error-to-absence/v_get_proof

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_proof_row_refuses_the_submission_rather_than_erroring` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `60451fc874a55a0a1eacd245ca357d11ee4ba28c23f0d7b8059290c0572b0abe`
* replacement sha256: `1de08adc94daa8fa33fa5ab4880f3ae04dcb3c11ff56e5d59904a3f87cb7ed38`
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
test a_corrupt_proof_row_refuses_the_submission_rather_than_erroring ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### E05-error-to-absence/v_get_employee_credential_ids

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `1ae01d92f6e3782b56415dc23e9814d26b285a00a13e69bb97e166c42c10073b`
* replacement sha256: `f40d7a79f426bd5fc7ff4c8da887c449e3133cd3220ca7dc33c38f956012c6b8`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_index(
```

Replacement:

```rust
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_index(
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.36s
```


#### E06-error-to-absence/v_get_employee_address_credential_ids

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `a50911c4d73954903531c36d1a609e2f5c0c514e2e7d280f29540ff12a3b4c81`
* replacement sha256: `8faf65370196e5515b5304812c6707e8c6dca67d0d014d04b0070e1669053882`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_address_index(
```

Replacement:

```rust
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employee_address_index(
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.47s
```


#### E07-error-to-absence/v_get_employer_credential_ids

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `4c946b9f98827a4d067c3e4e6b78bf73c232c29ca346cefca76ff6d47c8d93d6`
* replacement sha256: `ec26dc54748ae66b0c69721556c1dcec8bd4b242f5f45d9b7b1f10ab07df72dc`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employer_index(
```

Replacement:

```rust
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_employer_index(
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.61s
```


#### E08-error-to-absence/v_get_subject_attestation_ids

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `47ac89d1ed19ffbafde15f3b5a53315e4009d49a7c5714b58ce16615c699316f`
* replacement sha256: `163025591b525b71eaaa1ce309326629f7fca56c80d9473387f6ec3e6fe2efae`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_income_index(
```

Replacement:

```rust
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_subject_income_index(
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.94s
```


#### E09-error-to-absence/v_get_holder_address_attestation_ids

* category: decode-error-becomes-absence
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `808100d9589fb0fd7ae688748383cbddc5cdad0837c107c058ebd890e203577c`
* replacement sha256: `39b4bef28c8fd7ab8ef0ca9b5b49773ab0bf29c4904784abae0fccb22f3ee215`
* verdict: **KILLED**

Anchor:

```rust
            Some(bytes) => decode_id_list(&bytes).map_err(StateError::Storage),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_holder_address_index(
```

Replacement:

```rust
            Some(bytes) => Ok(decode_id_list(&bytes).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    fn v_add_to_holder_address_index(
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.98s
```


#### F01-order/v_put_credential

* category: multi-row-write-order-reversed
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_refusal_leaves_canonical_storage_untouched` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `03d46311178f4d89f6431beaab8eabd64be9a3a5610bf4bbe65cfdc439d5d422`
* replacement sha256: `f08a63d9450bfa7c199929d8ab52bc2479050b21c70185d15f6ec5610d706ad7`
* verdict: **KILLED**

Anchor:

```rust
        Self::v_write_credential_row(view, &credential.employment_id, credential)?;
        Self::v_add_to_employee_index(view, &credential.employee_ref, &credential.employment_id)?;
        Self::v_add_to_employee_address_index(
            view,
            &credential.employee_address,
            &credential.employment_id,
        )?;
        Self::v_add_to_employer_index(view, &credential.employer_ref, &credential.employment_id)
```

Replacement:

```rust
        Self::v_add_to_employer_index(view, &credential.employer_ref, &credential.employment_id)?;
        Self::v_add_to_employee_address_index(
            view,
            &credential.employee_address,
            &credential.employment_id,
        )?;
        Self::v_add_to_employee_index(view, &credential.employee_ref, &credential.employment_id)?;
        Self::v_write_credential_row(view, &credential.employment_id, credential)
```

Printed by libtest while mutated:

```
test a_refusal_leaves_canonical_storage_untouched ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.22s
```


#### F02-order/v_put_attestation

* category: multi-row-write-order-reversed
* occurrences checked before applying: **1** (expected 1)
* covering test: `malformed_rows_error_through_dispatch_and_stage_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `700658201fc15dbd134cf9caeaf1e7dfeb24455e966aa552a294e10cfb724ddf`
* replacement sha256: `a0fd2ad2f8d6bee764446104fbd84258926b550ecca3b02743d6221e30a39a99`
* verdict: **KILLED**

Anchor:

```rust
        Self::v_write_attestation_row(view, &attestation.attestation_id, attestation)?;
        Self::v_add_to_subject_income_index(
            view,
            &attestation.subject_ref,
            &attestation.attestation_id,
        )?;
        Self::v_add_to_holder_address_index(
            view,
            &attestation.holder_address,
            &attestation.attestation_id,
        )
```

Replacement:

```rust
        Self::v_add_to_holder_address_index(
            view,
            &attestation.holder_address,
            &attestation.attestation_id,
        )?;
        Self::v_add_to_subject_income_index(
            view,
            &attestation.subject_ref,
            &attestation.attestation_id,
        )?;
        Self::v_write_attestation_row(view, &attestation.attestation_id, attestation)
```

Printed by libtest while mutated:

```
test malformed_rows_error_through_dispatch_and_stage_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.91s
```


#### H01-defect/proof-exists-never-decodes

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_corrupt_proof_row_refuses_the_submission_rather_than_erroring` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `62e29ddbfb9f64b20c4159cf4217bbae8419dc0d42eea1eba121d8fea1eb5bcc`
* replacement sha256: `f68d504fb620be6a3ff214578c70177a84aae853d419730f59ef98ee25ef5fd5`
* verdict: **KILLED**

Anchor:

```rust
    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        view.contains(cf::EMPLOYMENT_PROOFS, proof_key(proof_id))
            .map_err(StateError::Storage)
    }
```

Replacement:

```rust
    pub fn v_proof_exists(view: &ExecutionView<'_, '_>, proof_id: &ProofId) -> Result<bool> {
        Ok(Self::v_get_proof(view, proof_id)?.is_some())
    }
```

Printed by libtest while mutated:

```
test a_corrupt_proof_row_refuses_the_submission_rather_than_erroring ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### H02-defect/revoke-leaves-the-indexes

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `revoking_a_credential_leaves_all_three_index_entries_behind` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `c8b63e24be5ac75994ea3b89914c4e74be335061d479c332197878ee588d0988`
* replacement sha256: `bd9b1a0337c27f4eaafd2efe165bd2ec9cdb0386d7f2f1df82748e615046dc8a`
* verdict: **KILLED**

Anchor:

```rust
            Some(mut credential) => {
                credential.status = EmploymentStatus::Ended;
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                Self::v_write_credential_row(view, employment_id, &credential)
            }
```

Replacement:

```rust
            Some(mut credential) => {
                credential.status = EmploymentStatus::Ended;
                credential.revocation_ref = Some(revocation_ref);
                credential.updated_at = timestamp;
                Self::v_write_credential_row(view, employment_id, &credential)?;
                let pruned = encode_id_list(&[]).map_err(StateError::Storage)?;
                view.put(
                    cf::EMPLOYMENT_EMPLOYEE_INDEX,
                    employee_index_key(&credential.employee_ref),
                    &pruned,
                )
                .map_err(StateError::Storage)
            }
```

Printed by libtest while mutated:

```
test revoking_a_credential_leaves_all_three_index_entries_behind ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


### `crates/state/src/employment_executor.rs`


#### H03-defect/suspended-issuer-keeps-control

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_suspended_issuer_can_still_revoke_but_not_create` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `ca95970d3f33970edf623db18a391546b91cd6c076976ecfc26c1176e243ff41`
* replacement sha256: `6d2d78e6b9c1c262449f191ab0b88de58bbcbdb165bcc05d1b291658a37b0b92`
* verdict: **KILLED**

Anchor:

```rust
                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }
```

Replacement:

```rust
                let credential = match Self::v_get_credential(view, &d.employment_id)? {
                    Some(c) => c,
                    None => return Ok(EmploymentExecutionResult::failure("Employment credential not found")),
                };

                if credential.issuer_address != *sender {
                    return Ok(EmploymentExecutionResult::failure("Only issuer can revoke"));
                }

                if !Self::v_get_issuer(view, sender)?
                    .map(|i| i.status.is_active())
                    .unwrap_or(false)
                {
                    return Ok(EmploymentExecutionResult::failure("Issuer is not active"));
                }
```

Printed by libtest while mutated:

```
test a_suspended_issuer_can_still_revoke_but_not_create ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.14s
```


#### H04-defect/verify-proof-verifies-nothing

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `verify_proof_charges_a_fee_and_verifies_nothing` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `d2b91d0dc05d91f4d24fb4f5f77a111782022ec67de9d7cdf30a5ee08992b982`
* replacement sha256: `a8fb11418276b88c2c9c405bcf6c3855f1367951d41f96cb0e5347a75f753c53`
* verdict: **KILLED**

Anchor:

```rust
            EmploymentOperation::VerifyProof => {
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
```

Replacement:

```rust
            EmploymentOperation::VerifyProof => {
                let subject: EmploymentProofEnvelope = bincode::deserialize(&data.data)
                    .map_err(|e| StateError::NftError(format!("Invalid data: {}", e)))?;
                if !Self::v_proof_exists(view, &subject.proof_id)? {
                    return Ok(EmploymentExecutionResult::failure("Proof not found"));
                }
                // Verification is read-only - just record the request
                StateManager::v_deduct(view, sender, fee)?;
```

Printed by libtest while mutated:

```
test verify_proof_charges_a_fee_and_verifies_nothing ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.18s
```


#### H05-defect/update-attestation-refused-free

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `update_income_attestation_is_refused_before_any_charge` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `d7f9dffdef78c375af8fe90f55368bc626f8468ffa936d04b898c2184046da43`
* replacement sha256: `dda7223c6baea3b9c19e08fc2bbafd4a222e99638277b99580ebb6b41a52ff5e`
* verdict: **KILLED**

Anchor:

```rust
            EmploymentOperation::UpdateIncomeAttestation => {
                // For now, we only support updating via revoke and re-issue
                Ok(EmploymentExecutionResult::failure("Update not supported, use revoke and re-issue"))
            }
```

Replacement:

```rust
            EmploymentOperation::UpdateIncomeAttestation => {
                // For now, we only support updating via revoke and re-issue
                StateManager::v_deduct(view, sender, fee)?;
                StateManager::v_credit(view, proposer, fee)?;
                StateManager::v_increment_nonce(view, sender)?;
                Ok(EmploymentExecutionResult::failure("Update not supported, use revoke and re-issue"))
            }
```

Printed by libtest while mutated:

```
test update_income_attestation_is_refused_before_any_charge ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.17s
```


### `crates/state/src/executor.rs`


#### G01-dispatch/execute_tx_with_validators-short-circuit

* category: dispatch-surface-short-circuited
* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_registration_the_same_credential_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `20e859f278117dd5d951844d19220f301a4ebe16c0914ca94adce8ba54d22d63`
* replacement sha256: `f809d1697d1c4f20fd840d5a68323ccaa7330228659a9cf70b94360e3c6630c2`
* verdict: **KILLED**

Anchor:

```rust
                        if result.success {
                            debug!(
                                "V2 Employment {} executed: {:?}",
```

Replacement:

```rust
                        if result.success || true {
                            debug!(
                                "V2 Employment {} executed: {:?}",
```

Printed by libtest while mutated:

```
test without_the_registration_the_same_credential_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.18s
```


#### G02-dispatch/execute_tx_v2-short-circuit

* category: dispatch-surface-short-circuited
* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_refuses_with_the_employment_status` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `379e490c240fbe19349a958a738cb794132030a1f8c8503f7fc9d19349dc2beb`
* replacement sha256: `59c59dc9f590dadbec85b92fbb784d4c36700212961ac9b7c0f32b12c1f1d7c9`
* verdict: **KILLED**

Anchor:

```rust
                if result.success {
                    debug!(
                        "V2 Employment {} executed: {:?}",
```

Replacement:

```rust
                if result.success || true {
                    debug!(
                        "V2 Employment {} executed: {:?}",
```

Printed by libtest while mutated:

```
test the_v2_dispatch_surface_refuses_with_the_employment_status ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.14s
```


#### G03-dispatch/execute_tx_with_validators-status-code

* category: dispatch-surface-short-circuited
* occurrences checked before applying: **1** (expected 1)
* covering test: `without_the_registration_the_same_credential_is_refused` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `8c6c24093fcb2b55a1d0ec8ac82a6e82f9468928e196db8ba272b983b7771997`
* replacement sha256: `bc2921879361a183e80673fb069037870a5ff3b4f7d0c987bf29d971f8845c7b`
* verdict: **KILLED**

Anchor:

```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(15), // Employment operation failed
```

Replacement:

```rust
                            Ok(TxExecutionResult {
                                tx_hash,
                                status: TxStatus::Failed(16), // Employment operation failed
```

Printed by libtest while mutated:

```
test without_the_registration_the_same_credential_is_refused ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.16s
```


#### G04-dispatch/execute_tx_v2-status-code

* category: dispatch-surface-short-circuited
* occurrences checked before applying: **1** (expected 1)
* covering test: `the_v2_dispatch_surface_refuses_with_the_employment_status` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `d28347c526fdd05e139cb88017a0e6fbca80b833fb0ccf4b935fe1cfbfdd47ac`
* replacement sha256: `0962d9d9dbfaf00f65ab404dceac0c8771909620c7e71ba4543fe0dc867823c7`
* verdict: **KILLED**

Anchor:

```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(15), // Employment operation failed
```

Replacement:

```rust
                    Ok(TxExecutionResult {
                        tx_hash,
                        status: TxStatus::Failed(16), // Employment operation failed
```

Printed by libtest while mutated:

```
test the_v2_dispatch_surface_refuses_with_the_employment_status ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.13s
```


#### H06-defect/dispatch-discards-the-timestamp

* category: preserved-defect-repaired
* occurrences checked before applying: **1** (expected 1)
* covering test: `every_status_update_records_a_zero_timestamp_through_dispatch` (`sumchain-state --test employment_routing -- --exact`)
* anchor sha256: `87d2e8ba556676ed1a6917aea346da4c6a01f4a09a64d84ef6764f173fd7d1e1`
* replacement sha256: `037d8bfad3f6f3aef2104e95e2747b54045288435acb193cab53ef9e6be3d066`
* verdict: **KILLED**

Anchor:

```rust
                            &employment_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            0, // block_timestamp placeholder
```

Replacement:

```rust
                            &employment_data,
                            proposer,
                            v2_tx.fee,
                            block_height,
                            block_timestamp,
```

Printed by libtest while mutated:

```
test every_status_update_records_a_zero_timestamp_through_dispatch ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 28 filtered out; finished in 0.18s
```


### `crates/storage/src/employment_store.rs`


#### C01-key/issuer_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_address_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `baedb41f78fe3e26eb8ce792fa40532929693bf7b093bb639336ba4737f21358`
* replacement sha256: `8d081890f4af9d724665f08c1ea6bfc858c10fa0f5a1a0164680b9de563d1a9d`
* verdict: **KILLED**

Anchor:

```rust
pub fn issuer_key(issuer_address: &Address) -> &[u8] {
    issuer_address.as_bytes()
}
```

Replacement:

```rust
pub fn issuer_key(issuer_address: &Address) -> &[u8] {
    &issuer_address.as_bytes()[..19]
}
```

Printed by libtest while mutated:

```
test an_issuer_row_is_bincode_at_the_address_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### C02-key/credential_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `2518fa2bee346535b1c53b1d83880d267430b3d16795ba83fc3a8eeb73db5c60`
* replacement sha256: `e967164db6f48e970f817b68c49c728366d928e33121b21de11bf4a5117ab83a`
* verdict: **KILLED**

Anchor:

```rust
pub fn credential_key(employment_id: &EmploymentId) -> &[u8] {
    employment_id
}
```

Replacement:

```rust
pub fn credential_key(employment_id: &EmploymentId) -> &[u8] {
    &employment_id[..31]
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.14s
```


#### C03-key/employee_index_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `2eb7f6f251907ef83936a5b07198277f095284779fdc3a5808cb404e800b011e`
* replacement sha256: `74950cab4106812db5fcdb5c1f7c71b5cadbef23869a9e0e5892509f24992176`
* verdict: **KILLED**

Anchor:

```rust
pub fn employee_index_key(employee_ref: &SubjectRef) -> &[u8] {
    employee_ref
}
```

Replacement:

```rust
pub fn employee_index_key(employee_ref: &SubjectRef) -> &[u8] {
    &employee_ref[..31]
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.14s
```


#### C04-key/employee_address_index_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `bb4d7cbc82ed10dc7b67705756365b09476934145495d4568606aeb3ec7eb83b`
* replacement sha256: `b5cefd75986863ff63c86e4abaf7c9ed62f1282bfdeeec9c3d9373eb4ee4a817`
* verdict: **KILLED**

Anchor:

```rust
pub fn employee_address_index_key(employee_address: &Address) -> &[u8] {
    employee_address.as_bytes()
}
```

Replacement:

```rust
pub fn employee_address_index_key(employee_address: &Address) -> &[u8] {
    &employee_address.as_bytes()[..19]
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.16s
```


#### C05-key/employer_index_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `16387d5299e673386e888850abb797139f0750a557bfcd45ae685fb66f54d035`
* replacement sha256: `a258fe9bd9a41b49f5bd4c09a16c07576256b49ec0f5955779b29e30a4c1e875`
* verdict: **KILLED**

Anchor:

```rust
pub fn employer_index_key(employer_ref: &EmployerRef) -> &[u8] {
    employer_ref
}
```

Replacement:

```rust
pub fn employer_index_key(employer_ref: &EmployerRef) -> &[u8] {
    &employer_ref[..31]
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.16s
```


#### C06-key/income_attestation_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `97ae8859a291f0e1f05f9dd0b380055685bd1fd11571f614b1efe26c70957878`
* replacement sha256: `1f88a8a3b637e1286e4aa0d2201c889ed3b995da2acabc93eb531d038afc7018`
* verdict: **KILLED**

Anchor:

```rust
pub fn income_attestation_key(attestation_id: &IncomeAttestationId) -> &[u8] {
    attestation_id
}
```

Replacement:

```rust
pub fn income_attestation_key(attestation_id: &IncomeAttestationId) -> &[u8] {
    &attestation_id[..31]
}
```

Printed by libtest while mutated:

```
test an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.15s
```


#### C07-key/subject_income_index_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `9150e012549372c5489a75664584345720570d2a81b5ec608088692c66f80e64`
* replacement sha256: `9f2c058c3f64b7dd0093decc10bf9248d74b8862c386b65843b48119e00f5bae`
* verdict: **KILLED**

Anchor:

```rust
pub fn subject_income_index_key(subject_ref: &SubjectRef) -> &[u8] {
    subject_ref
}
```

Replacement:

```rust
pub fn subject_income_index_key(subject_ref: &SubjectRef) -> &[u8] {
    &subject_ref[..31]
}
```

Printed by libtest while mutated:

```
test an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.15s
```


#### C08-key/income_holder_address_index_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `d9c4ce8fd3d54d39d5e5b2312c7500a62302371e0ef3c12a057f3c14345a7e8a`
* replacement sha256: `73931c3faf1ac2c3c959b58a6fba9633be51b7a0c233931ac2d7bc3ac5386b0f`
* verdict: **KILLED**

Anchor:

```rust
pub fn income_holder_address_index_key(holder_address: &Address) -> &[u8] {
    holder_address.as_bytes()
}
```

Replacement:

```rust
pub fn income_holder_address_index_key(holder_address: &Address) -> &[u8] {
    &holder_address.as_bytes()[..19]
}
```

Printed by libtest while mutated:

```
test an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### C09-key/proof_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `5af8daf44557c6e1c5a43a5746fb27e13c80306de9d98ba563411e18f99e1c0f`
* replacement sha256: `d2aac6ef88bd84a4edea8de83ceed0a6bde04bb2c7f4c92b8041a70784346d9b`
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
    &proof_id[..31]
}
```

Printed by libtest while mutated:

```
test a_proof_row_is_bincode_at_the_proof_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### C10-key/event_key

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `d7b3e3a2b7c36767a4ad3c02681f6d7c22184a32fa0f4394c411486581ece1ba`
* replacement sha256: `caa965ed7c01844e4f7d1a3aadd8905029ff595b40cc0364add75d9aeb8c7090`
* verdict: **KILLED**

Anchor:

```rust
    let mut key = [0u8; 12];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(&index.to_be_bytes());
    key
```

Replacement:

```rust
    let mut key = [0u8; 12];
    key[..4].copy_from_slice(&index.to_be_bytes());
    key[4..].copy_from_slice(&height.to_be_bytes());
    key
```

Printed by libtest while mutated:

```
test an_event_row_is_bincode_at_a_big_endian_height_and_index_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### C11-key/event_height_prefix

* category: key-builder-broken
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `e2d481528321351c934602c67af3121c6cf441b1671afad60977c26f05b9e93c`
* replacement sha256: `36b881f6def60fa3139e5d7becd52ab5880be590a3d4427f4b0ac0add19ac12b`
* verdict: **KILLED**

Anchor:

```rust
pub fn event_height_prefix(height: BlockHeight) -> [u8; 8] {
    height.to_be_bytes()
}
```

Replacement:

```rust
pub fn event_height_prefix(height: BlockHeight) -> [u8; 8] {
    height.to_le_bytes()
}
```

Printed by libtest while mutated:

```
test an_event_row_is_bincode_at_a_big_endian_height_and_index_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### D01-codec/encode_issuer

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_issuer_row_is_bincode_at_the_address_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `26b7b64a34e2f5a8daea84cbd3980f04967b9b5c97330950708dc0f917dbc1c3`
* replacement sha256: `682a3cd8165c0100bf786bbb9585c117548db875b2b6d6308a322ab6aa94ffbc`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_issuer(issuer: &EmploymentIssuerProfile) -> Result<Vec<u8>> {
    bincode::serialize(issuer).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_issuer(issuer: &EmploymentIssuerProfile) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, issuer)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test an_issuer_row_is_bincode_at_the_address_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### D02-codec/encode_credential

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `158dde9405515128ddb8ff3a41f481b797a6e625c2060550e47c04bc5241126a`
* replacement sha256: `dc6b923e19e0038ae99ece2f2630e66426850a2cc2917b129fae9e587a75a83b`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_credential(credential: &EmploymentCredential) -> Result<Vec<u8>> {
    bincode::serialize(credential).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_credential(credential: &EmploymentCredential) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, credential)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.17s
```


#### D03-codec/encode_attestation

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `4601ca23a61d81dbc4ca9b496a20d79960bf488c7d5021b964f1a36e2db99264`
* replacement sha256: `1bb3edc56ef436b59c98380475b4e688b46d44af1b2ded4fd7cf7a94da506131`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_attestation(attestation: &IncomeAttestation) -> Result<Vec<u8>> {
    bincode::serialize(attestation).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_attestation(attestation: &IncomeAttestation) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, attestation)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test an_attestation_row_is_bincode_at_its_id_and_fills_two_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.15s
```


#### D04-codec/encode_proof

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_proof_row_is_bincode_at_the_proof_id_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `8eab919bd1f275b3323d8042626198ad0a217c097c1b7cd2dc9f53609d1757ab`
* replacement sha256: `75aabc81a9373d3db26ecd9232978b8a5677be519cb59765c502a2ea3e2863f2`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_proof(proof: &EmploymentProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_proof(proof: &EmploymentProofEnvelope) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, proof)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test a_proof_row_is_bincode_at_the_proof_id_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### D05-codec/encode_id_list

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `21296920f69086392c214573c7309843d7c0fe2fa9cc8c05769cc0fc29058e2f`
* replacement sha256: `1202484e33bf5bc2bd2193ecd8c3631810c49a71c7423889ed339196bdc32d4e`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_id_list(ids: &[EmploymentId]) -> Result<Vec<u8>> {
    bincode::serialize(ids).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_id_list(ids: &[EmploymentId]) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, ids)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test a_credential_row_is_bincode_at_the_employment_id_and_fills_three_indexes ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


#### D06-codec/encode_event

* category: codec-changed
* occurrences checked before applying: **1** (expected 1)
* covering test: `an_event_row_is_bincode_at_a_big_endian_height_and_index_key` (`sumchain-storage --test employment_codec_parity -- --exact`)
* anchor sha256: `31294dd6f1130ddaec62bdd567a2781aafb7705a64bbbb88d19d9a0986edd06b`
* replacement sha256: `7d4c222ecaf6b0a1d7c85a0645cbaf70562480f828564713a90a9a949c2b2b47`
* verdict: **KILLED**

Anchor:

```rust
pub fn encode_event(event: &EmploymentEvent) -> Result<Vec<u8>> {
    bincode::serialize(event).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Replacement:

```rust
pub fn encode_event(event: &EmploymentEvent) -> Result<Vec<u8>> {
    bincode::serialize(&(0u8, event)).map_err(|e| StorageError::Serialization(e.to_string()))
}
```

Printed by libtest while mutated:

```
test an_event_row_is_bincode_at_a_big_endian_height_and_index_key ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.13s
```


## Totals, post-run hashes and anchor re-resolution

```
prevalidated 60 anchors against expected count 1; mismatches: 0

=== totals ===
  killed: 60
  declared: 60   scored: 60

=== post-run hashes (authoritative) ===
  MATCH   293b5d9439ff1345f6c16281001cda3df3c6ee5307c6a954a413bd68746f8905  crates/state/src/employment_view.rs
  MATCH   37703fad74676511b22e17ebf801f0049f415f95ddd8ae709e1c85513bef216b  crates/state/src/employment_executor.rs
  MATCH   66b952590fa83da23718f2907fddbf306ae96c9dd60acda47dcf1514fa1b9976  crates/state/src/executor.rs
  MATCH   18d1847715b21a2c86d5255c6533d12d0e9aed50cbcef5bf00d2564408f4542b  crates/storage/src/employment_store.rs
  all four byte-identical to pre-run: True

=== anchors resolve exactly once again ===
  60/60
```


## Residue

```
=== 1. the four mutated files vs the pre-run copies (AUTHORITATIVE) ===
  MATCH   293b5d9439ff1345f6c16281001cda3df3c6ee5307c6a954a413bd68746f8905  crates/state/src/employment_view.rs
  MATCH   37703fad74676511b22e17ebf801f0049f415f95ddd8ae709e1c85513bef216b  crates/state/src/employment_executor.rs
  MATCH   66b952590fa83da23718f2907fddbf306ae96c9dd60acda47dcf1514fa1b9976  crates/state/src/executor.rs
  MATCH   18d1847715b21a2c86d5255c6533d12d0e9aed50cbcef5bf00d2564408f4542b  crates/storage/src/employment_store.rs
  all four restored: True

=== 2. whole-crates scan for the 60 specific replacements ===
  residue: NONE

  generic replacements (text that already occurs in the pristine tree,
  and so cannot serve as a residue marker): 0 of 60 -- every replacement
  in this battery is a multi-line block found nowhere else, so the scan
  above covers all of them. Check 1 remains the authoritative one.

=== 3. every anchor still resolves exactly once ===
  anchors resolving exactly once: 60/60; not-once: []
```
